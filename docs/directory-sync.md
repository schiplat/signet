# Signet 目录同步（Directory Sync）设计

| 项 | 内容 |
|---|---|
| 状态 | **P0 + P1 + P2 + P3 + P4 已实现**（地基 + LDAP 拉取引擎 + bind 直通登录 + 定时调度 + 通用 HTTP JSON 源 + 两种 pull kind 共用的映射 UI，见 §13.1）；P5 SCIM push 待做 |
| 定位 | 把外部目录作为**只读数据源**同步进 Signet 本地用户库；LDAP 用户可直接用目录密码登录 |
| 首选落地 | LDAP（pull） |
| 相关文档 | [设计总览](./design.md) · [安全设计](./security.md) · [集成对接](./integrations.md) · [Dashboard API](./api-v1.md) · [MFA](./mfa.md) |

---

## 1. 目标与非目标

### 1.1 目标

1. 将外部目录作为**只读数据源**，同步用户（及组）到 Signet 本地 `users` 表；
2. 支持三类数据源：**LDAP**、**SCIM**、**通用 HTTP JSON**；
3. 支持两种触发方式：**命令行/API 手动触发** 与 **后台定时同步**，且均可管理、可审计、可观测；
4. LDAP 目录用户可直接用其目录密码登录（**bind 直通**）；
5. 支持上游**主动推送**（push）模式的接入。

### 1.2 非目标（v1 明确不做）

| 不做 | 原因 |
|---|---|
| 回写上游（双向同步） | 单向即可满足需求；回写会引入写冲突与上游权限放大 |
| 同步密码 hash | `users.password_hash` 只认 argon2；改多 hash 支持成本高、风险大 |
| 把上游组映射为 Signet `role` | **提权风险**：上游一改组即可拿到 admin。`role` 恒为本地管理 |
| 替代现有 SSO 联邦 | `upstream_providers`/`user_identities` 是**认证时**联邦，本设计是**供给时**同步，二者互补 |
| AD Deleted Objects 删除检测 | 需额外 tombstone 权限，环境差异大 |
| 嵌套组展开 | 需要 AD `LDAP_MATCHING_RULE_IN_CHAIN` 等特殊能力 |

---

## 2. 已定决策

| # | 决策 | 选择 | 影响 |
|---|---|---|---|
| D1 | push 语义 | **上游 → Signet**（复用并加固现有 `/scim/v2` 服务端） | push 只存在于 SCIM 线；LDAP 纯 pull |
| D2 | 密码策略 | **LDAP bind 直通** | 密码留在 LDAP；登录路径需分叉 |
| D3 | 上游删人 | **默认 disable，不删除** | 保留审计 actor 归属（`audit_logs.actor_user_id` 是 `ON DELETE SET NULL`） |
| D4 | LDAP TLS | **LDAPS(636) 必选 + 强制证书校验**，自签 CA 可导入 | 明文 bind 不可接受；TLS 配置为必填项 |
| D5 | 目录用户编辑权 | **完全只读**：admin 不可改邮箱/姓名/组；仅可改本地 MFA、`role`、直接禁用 | 需要托管语义与属性归属矩阵 |
| D6 | LDAP 不可用时 | **fail closed** | 登录失败，无本地密码兜底 |

---

## 3. 数据源与接入模式

| 数据源 | 模式 | 方向 | 触发 | 说明 |
|---|---|---|---|---|
| **LDAP** | pull | Signet → 目录 | CLI / 定时 | LDAPS + 服务账号搜索；bind 直通用于登录 |
| **通用 HTTP JSON** | pull | Signet → 上游 | CLI / 定时 | 最灵活，需 SSRF 防护 |
| **SCIM** | push | 上游 → Signet | 上游驱动 | 即现有 `/scim/v2`，需加固（见 §14） |

> ⚠️ **LDAP 没有 push 语义**。文档与需求描述必须写成「三类数据源 × 两种接入模式（pull / push）」，避免产生"LDAP 也应支持推送"的误解。

---

## 4. 数据模型

### 4.1 新增表（迁移 `024_directory_sync.sql`）

```sql
-- 数据源配置
CREATE TABLE directory_sources (
    id UUID PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,          -- CLI / URL 标识，如 "corp-ldap"
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ldap', 'scim', 'http_json')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    priority INT NOT NULL DEFAULT 100,  -- 多源属性冲突时的优先级（小者优先）
    config JSONB NOT NULL DEFAULT '{}', -- kind 特有配置（明文，不含密钥）
    credential_enc TEXT,                -- 服务账号密码 / Bearer token，AES-256-GCM
    ca_cert_pem TEXT,                   -- LDAPS 自签 CA（公钥，无需加密）
    sync_groups BOOLEAN NOT NULL DEFAULT TRUE,
    interval_minutes INT,               -- NULL = 仅手动触发
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 每次同步运行（运行历史，供 UI/审计查询）
CREATE TABLE directory_sync_runs (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'cli', 'push')),
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    scanned INT NOT NULL DEFAULT 0,
    created_count INT NOT NULL DEFAULT 0,
    updated_count INT NOT NULL DEFAULT 0,
    disabled_count INT NOT NULL DEFAULT 0,
    skipped_count INT NOT NULL DEFAULT 0,
    conflict_count INT NOT NULL DEFAULT 0,
    error_count INT NOT NULL DEFAULT 0,
    error TEXT,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- 手动触发者
    stats JSONB NOT NULL DEFAULT '{}'   -- 组同步计数等扩展指标
);
CREATE INDEX directory_sync_runs_source_started_idx
    ON directory_sync_runs (source_id, started_at DESC);

-- 外部条目 ↔ 本地用户 的链接
CREATE TABLE directory_entries (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES directory_sources(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,          -- LDAP: entryUUID/objectGUID；SCIM: id
    external_dn TEXT,                   -- LDAP bind 直通所需
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_hash TEXT,                   -- 托管字段指纹，避免无谓 UPDATE
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_synced_at TIMESTAMPTZ,
    UNIQUE (source_id, external_id)
);
CREATE INDEX directory_entries_user_idx ON directory_entries (user_id);
```

> `users.external_id`（迁移 `012`）是**全局唯一**且面向 SCIM 的，**不能**当作多源外部 ID 使用；因此必须新建 `directory_entries`。
> 同一外部身份只允许链接一个本地用户；同一本地用户可被多个源链接（多源场景，见 §17）。

### 4.2 `users` 表变更

```sql
-- 本地禁用意图：与上游 status 分开，避免下次同步把本地禁用覆盖掉
ALTER TABLE users ADD COLUMN local_disabled BOOLEAN NOT NULL DEFAULT FALSE;
-- 目录来源的组，与本地手工组分离（见 §6.5）
ALTER TABLE users ADD COLUMN directory_groups TEXT[] NOT NULL DEFAULT '{}';
```

有效状态计算：

```text
users.status = CASE WHEN local_disabled THEN 'disabled'
                    ELSE <上游 status> END
```

`local_disabled` **只由管理员显式 enable 清除**，同步过程永不改写。

> 同步改造清单：`models.rs` 的 `USER_COLS`、`User` 结构体、`admin` 用户列表/详情返回、以及所有 `SELECT {USER_COLS}` 调用点。

---

## 5. 属性归属与只读语义（D5）

| 字段 | 归属 | 目录可否写 | 本地可否改 |
|---|---|---|---|
| `email` | 目录 | ✅ | ❌ |
| `username` | 目录 | ✅ | ❌ |
| `display_name` | 目录 | ✅ | ❌ |
| `groups`（本地组） | 本地 | ❌ | ✅ |
| `directory_groups` | 目录 | ✅ | ❌ |
| `status` | 目录 + 本地 override | ✅（上游值） | ✅（仅通过 `local_disabled`） |
| `external_id` | 目录 | ✅ | ❌ |
| `password_hash` | 本地 | ❌ | ✅（目录用户恒为空） |
| `mfa_required` / `totp_enabled` / `totp_secret` | 本地 | ❌ | ✅ |
| `role` | **本地** | ❌ | ✅ |
| `phone` | 本地 | ❌（v1） | ✅ |
| `must_change_password` | 本地 | ❌（目录用户恒 `false`） | ✅ |

**判定"目录托管"**：`directory::managing_source(pool, user_id) -> Option<String>` 返回**优先级最高**的源 code（`ORDER BY priority ASC, code ASC`，`code` 用于在同优先级下给出确定结果）。文档原先拟定的 `is_managed(pool, user_id) -> bool` **未单独实现**——`managing_source(..).is_some()` 就是它，而每个强制点都需要 source code 来构造错误信息与审计明细，两个函数只是同一查询的重复。

被拒时返回 `403`，错误信息由 `directory::managed_write_error(source, field)` / `directory::managed_delete_error(source)` 生成（纯函数，见 §5.1）。**所有权字段清单**是代码里的 `directory::DIRECTORY_OWNED_FIELDS`，测试 `tests/directory_policy.rs` 把它与上表钉在一起。

**已实现（P0）**：

| 入口 | 行为 |
|---|---|
| `update_user` | 仅当 `email`/`username`/`display_name` 的**归一化后新值**与现值不同才拒绝；仅改 `role`/`groups`/`phone`/`mfa_required`/`status` 等本地字段照常放行 |
| `delete_user` | 一律拒绝，提示改用 disable（与 D3 一致：上游删人只 disable，本地也不应硬删） |
| `disable_user` / `enable_user` / `batch_disable_users` | **放行**，并写入/清除 `users.local_disabled`（见下） |

> **对文档措辞的一处修正**：§5 原文把 `disable_user` 也列入"必须校验并拒绝"的入口。但同一张 D5 表格写明 `status` 是"目录 + 本地 override，本地可改（仅通过 `local_disabled`）"——若拒绝 disable，文档承诺的本地覆盖机制就无法使用。因此实现为**放行并正确落到 `local_disabled`**，而不是拒绝。`set_status` 现在强制要求调用方传入 `local_disabled`，任何绕过该意图的本地禁用都会在编译期被拦住。

> 拒绝写入会记一条审计事件 `directory.managed_write_blocked`（`detail = { source, field }`）。同步引擎自身的 `directory.sync.*` / `directory.user.*` 事件属于 P1，因为现在还没有同步可审计。

---

### 5.1 拒写策略的可测试性

`managed_write_error` / `managed_delete_error` / `DIRECTORY_OWNED_FIELDS` 都是纯函数/常量，因此上面那张归属表可以用普通单元测试锁定，不需要数据库。`tests/directory_policy.rs` 覆盖：托管字段被拒、本地字段放行、未知字段**默认放行**（调用方写错字段名时不应把管理员锁在无关属性之外）。

---

## 6. 同步算法

### 6.1 主流程（全量对账）

```text
1. 创建 run（status=running，记录 trigger 与 actor）
2. 分页拉取上游全量条目
3. 逐条处理（见 6.2）
4. 对账收尾（见 6.3）
5. 组同步（见 6.5，若 enabled）
6. 关闭 run，写统计；失败则 status=failed + error
```

分页与批量：

- LDAP：RFC 2696 Simple Paged Results，页大小可配（默认 500）；AD 需同时请求分页控件 OID `1.2.840.113556.1.4.319`。
- 建议每 N 条（默认 200）提交一次事务，避免长事务与内存膨胀。

### 6.2 单条处理

```text
按 (source_id, external_id) 查 directory_entries
├─ 命中 link
│   ├─ 计算托管字段指纹，与 source_hash 相同 → 仅更新 last_seen_at（计 skipped）
│   └─ 不同 → UPDATE 托管字段 + source_hash + last_seen_at（计 updated）
└─ 未命中 link
    ├─ 按 email / username 匹配本地用户
    │   ├─ 命中 → 冲突：skip + 计 conflict + 审计 directory.conflict（见 6.4）
    │   └─ 未命中 → INSERT 新用户（role='member'、password_hash=''、
    │                  provisioned_via=<kind>、local_disabled=FALSE）
    │               + 写 link（计 created）
    └─ 写 link
```

新用户字段：`sub` 使用生成的 UUIDv4；`display_name` 缺失时回退为 email 本地部分（与 `federation/link.rs:203` 的 JIT 逻辑一致）。

### 6.3 对账收尾（缺失即 disable）

```text
UPDATE users SET status='disabled'
WHERE id IN (SELECT user_id FROM directory_entries
             WHERE source_id = $1 AND last_seen_at < <本次 run 开始时间>)
```

- **不删除**用户、不删除 link、不清除 `local_disabled`；
- 审计 `directory.user.disabled`，`detail.reason` 有两个取值：

| reason | 何时 |
|---|---|
| `absent_upstream` | 目录不再列出这个条目 |
| `out_of_scope` | 目录仍然列出，但不再属于本源的**作用域**（§7.2.1：调岗、域变更） |

`apply_disables` 逐条带出 planner 给出的原因，而不是硬编码其中一个 —— 一个凌晨三点读到「账号被禁用」的运维必须能分辨「离职」和「调岗」；
- 另有两点与作用域相关的边界：作用域只可能禁用**本源自已 link 的用户**（缺席对账遍历的是 link，没 link 的人动不到）；`--limit` 试跑不做对账，因此作用域在试跑里**不会**禁用任何人；
- 上游重新出现时，`status` 由上游值决定恢复（`local_disabled` 仍生效）；
- link 保留使"消失—复现"不会误建重复账号。

### 6.4 冲突处理

| 冲突 | 处理 |
|---|---|
| 上游 email/username 撞已有本地用户，且该用户无 link | **skip + 报冲突**，不自动接管。审计 `directory.conflict`，由管理员显式确认后手动建立链接 |
| 上游 email/username 撞的用户**已被另一个源 link** | **skip，不计冲突**。按 `priority` 判定归属（§4.1），高优先级源继续拥有该用户的属性；`reason` 里点名是哪个源（见下方说明） |
| 上游同一 email 出现多条 | 取第一条，其余 skip + 告警 |
| 上游 email 变更后撞另一用户 | UPDATE 失败 → 该条 skip + 冲突，其余条目继续，run 置 `partial` |
| 上游删除了某条但本地已 link | 走 6.3 disable |

> **多源重叠的判定**：同一个用户在两个目录里都存在时，两个源会各自 link 到他（`external_id` 是 per-source 的）。计划阶段先看 `managing_source`——若该用户的归属源不是本次运行的源，则**既不写属性、也不在"上游消失"时 disable**，记为 skip 并把归属源写进 `reason`。
>
> 之所以是 skip 而不是 conflict：conflict 的定义是"撞上一个**没人托管**的本地账号"，那才是需要人工裁决的接管风险。两源同时列出一个人是多源部署的正常状态，把它算成冲突会让每个 run 都停在 `partial`，运营商很快就会学会忽略这个状态。归属源的属性优先，正是 `priority` 的语义。
>
> 代价是低优先级源贡献的组会被丢弃。v1 接受这个代价（Q5 仍未定），归属源变更时下一次运行会重新规划。

> **安全考量**：v1 **不做**按 email 自动 claim 现有账号。否则一个恶意/误配的目录条目（例如填了 `admin@corp.com`）就能接管本地管理员账号。宁可让冲突浮出来，也不静默接管。若将来要支持 claim，须同时满足：源配置显式开启、目标用户 `role='member'`、且目标用户无本地密码。

### 6.5 组映射

`users.groups` 会被 OIDC 作为 `groups` claim 发出（`oidc/token.rs`、`oidc/userinfo.rs`），因此不能直接把目录组写进 `groups`——会冲掉本地手工组。采用**分列**方案：

- `users.groups` = 本地组（管理员维护）
- `users.directory_groups` = 目录组（同步全量替换）
- OIDC `groups` claim = 两者的**并集**（去重 + 稳定排序，保证 claim 可重复）

同步时对该源贡献的组做全量替换：

```sql
UPDATE users SET directory_groups = $2 WHERE id = $1
```

> 该方案需改动 OIDC claim 组装处与后台用户列表展示，代价可控，且为多源/本地共存留出空间。

v1 组能力边界：

- 仅同步**直接成员**，不做嵌套组展开；
- LDAP 侧按 `member`（OpenLDAP 组对象）或 `memberOf`（AD 反查）解析，具体取法在源配置里选择；
- SCIM 侧沿用 `scim_groups` + `users.groups` 现有模型，需迁移到 `directory_groups`。

**已实现（P1/P2）**：`users.directory_groups` 由同步全量替换（`update_user` 里用 `COALESCE($5::text[], directory_groups)`，因此 `sync_groups` 关闭的源不会清空已有值）；OIDC 的 `groups` claim 由 `models::effective_groups` 计算两列并集（去重 + 排序，保证同一用户每次拿到的 claim 一致）。测试 `tests/oidc_groups_claim.rs`。

---

## 7. LDAP 接入细则

### 7.1 依赖与 TLS

引入 `ldap3`，**必须**关闭默认特性（默认 `tls` 走 native-tls）：

```toml
ldap3 = { version = "0.12", default-features = false, features = ["tls-rustls-ring"] }
```

要点（已核对 crate 文档）：

- `tls-rustls` 单独启用**不可用**，必须选一个 crypto provider（`tls-rustls-ring` 或 `tls-rustls-aws-lc-rs`）；
- `tls` 与 `tls-rustls` **互斥**，同时启用会编译失败；
- 自签 CA 通过 `RootCertStore` + `LdapConnSettings::set_config(Arc<ClientConfig>)` 注入；
- 禁止使用 `no_tls_verify`（跳过校验）——与 D4「强制证书校验」冲突，代码层不暴露该选项。

### 7.2 连接配置（`config JSONB`）

```json
{
  "url": "ldaps://ldap.corp.example:636",
  "bind_dn": "cn=signet-sync,ou=svc,dc=corp,dc=example",
  "base_dn": "ou=people,dc=corp,dc=example",
  "user_filter": "(&(objectClass=person)(mail=*))",
  "email_domains": ["corp.example", "partner.example"],
  "department_attribute": "department",
  "department_values": ["Engineering", "Platform"],
  "username_attribute": "uid",
  "email_attribute": "mail",
  "display_name_attribute": "displayName",
  "external_id_attribute": "entryUUID",
  "group_base_dn": "ou=groups,dc=corp,dc=example",
  "group_filter": "(objectClass=groupOfNames)",
  "group_membership": "member",
  "page_size": 500
}
```

- `credential_enc` 存服务账号密码（只读权限即可）；
- **要求目录侧授予最小权限**：仅需读取 `base_dn` 与 `group_base_dn` 子树；
- `user_filter` 由服务器执行，是**粗筛**：省流量，但预览无法校验它（§13.1.3）。写域名时注意 `(mail=*corp.example)` 会匹配 `bob@evilcorp.example`，要写成 `(mail=*@corp.example)`；
- `email_domains` / `department_values` 是**细筛**，在本地对规范化后的条目求值，因此预览能报「匹配 0/N 条」。两者是叠加关系（都要通过），不是替代；
- **过滤器必须做转义，禁止把用户输入拼进 filter（防 filter 注入）。** 谓词（`email_domains` 等）走的是本地比较，不插值进 filter，因此`ldap.rs` 里「不插值所以不必转义」的论证依然成立 —— 若要新增任何把配置值拼进 filter 的字段，必须先引入 RFC 4515 转义并补测试。

### 7.2.1 作用域（scope）是「所有权」，不是「查询条件」

这是本节最需要记住的一点。`email_domains` 与 `department_values` 定义的是**这个源拥有谁**，而不是**这次要查谁**。直接后果（§6.3 的「缺失即 disable」）：

- 缩窄作用域 ⇒ 掉出范围的人**被禁用**（并撤销会话），和上游删除同一条路径；
- 因此**改作用域是一次有破坏性的操作**：保存前先用 `--dry-run` 看 `disabled` 计数，或看运行历史的 disable 列表；
- 匹配 0 条不是「同步了 0 人」，而是**把该源已管理的所有人一次性禁用**。预览的 `scope` 行会在这种配置上直接判 `ok: false`（§13.1.3），配置保存时也会拒绝空条目、通配符、以及「有 `department_values` 却没有 `department_attribute`」这类会让筛选恒不匹配的写法；
- **域稳定、部门易变**：域筛选下掉出范围基本只发生在离职/域名变更；部门筛选下**每次内部调动都会掉出范围**。因此禁用原因被刻意分成两个字符串：

| reason | 含义 |
|---|---|
| `absent_upstream` | 目录不再列出这个人（离职/删除） |
| `out_of_scope` | 目录仍然列出，但不再属于这个源的作用域（调岗、域变更） |

两者都会写进运行历史的 `changes[].reason` 与审计 detail 的 `reason` 字段，运维据此区分「离职」与「调岗」。这是本次实现里唯一新增的 reason 值。

域名匹配规则（刻意做得窄）：比较**整个标签边界**，`corp.example` 匹配 `corp.example` 与 `mail.corp.example`，但**不匹配** `evilcorp.example`；大小写不敏感；**没有通配符、没有正则** —— 一个能表达任意条件的模式语言同时也是预览无法校验、一次 typo 就静默缩小或清空作用域的东西。部门值按精确值比较（去空白、忽略大小写），没有前缀匹配。后者是一个已知缺口，记录在 §17 的 Q7：AD 常把部门写成 `Engineering / Platform` 这样的层级路径，此时必须把 `department_attribute` / `department_path` 指到恰好那一层，配成上层名字不会匹配——**且因为作用域即所有权，配错的结果是禁用（`out_of_scope`），不是少同步几条**。因此改动部门筛选前后都应先看 `--dry-run` 的 `disabled` 计数。

### 7.3 外部 ID 的选取

| 目录 | 稳定 ID | 备注 |
|---|---|---|
| OpenLDAP | `entryUUID` | 稳定 |
| AD | `objectGUID` | 二进制，需转为 UUID 字符串 |

不要用 DN 作为 `external_id`：DN 会因 OU 调整而变，会导致重复建号。DN 只存在 `external_dn`，供 bind 使用。

### 7.4 增量同步（仅作优化）

| 目录 | 增量字段 | 坑 |
|---|---|---|
| AD | `uSNChanged` | 每 DC 单调递增、非全局；换 DC 会错乱 |
| AD | `whenChanged` | 秒级精度，同秒内多次修改会漏 |
| OpenLDAP | `modifyTimestamp` | 秒级精度，需向前回溯若干分钟（kludge） |

**结论**：增量只作为降低开销的优化，**必须**保留周期性全量对账兜底（尤其是删除检测）。建议默认按「每小时增量 + 每日全量」；v1 可先只做全量，跑通后再加增量。

---

## 8. LDAP bind 直通认证（D2）

### 8.1 登录路径分叉

现状是 `auth/routes.rs:90` 无条件调用本地校验：

```text
if !verify_password(&body.password, &user.password_hash)? { ... }
```

改为按**托管来源**分派：

```text
1. 加载用户（现状不变）
2. status 校验、锁定校验（现状不变）
3. 查询用户是否被启用的 LDAP 源托管
   ├─ 是 → 走 LDAP bind 校验（8.2）
   └─ 否 → 走本地 argon2 校验（现状）
4. 通过后继续 begin_login_mfa_flow（现状不变，MFA 流程无需改动）
```

这同时修掉了 §15 的空密码缺陷：仅有非托管用户才会走到 argon2 分支，且空 hash 应返回 `401` 而非 `500`。

**已实现（P2）**：

| 组件 | 位置 | 行为 |
|---|---|---|
| 路径选择 | `directory::auth::resolve` | 单条 SQL 选出**最低 `priority` 的启用中 LDAP 源**（与 `managing_source`、同步规划器同一套归属规则）。无 link / 源被停用 / 源非 `ldap` / `external_dn` 缺失或空白 → `Local` |
| bind 校验 | `directory::auth::verify` → `ldap::bind_as` | 用落库的 `external_dn` 一次 bind；连接 5s / 操作 10s；结束必 unbind |
| 结果三态 | `directory::auth::Credential` | `Valid` / `Invalid { counts_toward_lockout }` / `Unavailable { source_code, detail }` |
| 不可用 | 503 `directory unavailable` | 先写 `auth.directory_unavailable` 审计（含 source 与 error）再返回；**不**回退本地密码 |
| 指标 | `metrics.rs` | `signet_directory_login_failures_total`、`signet_directory_unavailable_total`，与本地失败分开计数 |

> **配置损坏的处理**：源 config 解析失败时 `resolve` 返回错误（→500）而不是静默降级到本地。目录用户没有本地密码，伪装成"密码错误"会把人送去重置一个根本不存在的密码。源 config 只在保存时校验，所以这种状态意味着库被外部改坏了。

> **本地密码的写入被拦在 `password::set_user_password`**：该函数现在是唯一的收口点，四个调用方（自助改密、管理员重置、邮件重置、强制改密）都在此被挡住。理由不是"目录用户本地密码无意义"，而是它**有害**——bind 直通会让它永远不被使用，而源一旦被停用/删除它就变成可用凭据。判定用 `directory::enabled_managing_source`（只看启用中的源），这是有意与 `managing_source` 不同的语义：**关闭一个源必须把账号交回本地管理**，否则下线一个目录就等于永久锁死它的用户。`/password-reset/request` 同样对托管账号跳过发信，保持恒 200 防枚举。

### 8.2 bind 校验

- **用同步时落库的 `directory_entries.external_dn`** 直接 bind，避免每次登录都"服务账号搜索 + bind"两步（降低延迟，且不需要给登录路径搜索权限）；
- 连接串使用配置里的 `ldaps://`；LDAPS 是硬要求；
- 密码不落库、不写日志、不缓存；
- 成功后重置本地 `failed_login_attempts` / `locked_until`，然后进入既有 MFA 流程。

### 8.3 失败与故障语义（D6 fail closed）

| 情况 | 行为 |
|---|---|
| bind 返回 invalid credentials | `401 invalid email or password`；累加审计与指标 |
| LDAP 不可达 / 超时 | `503 {"error":"directory unavailable"}` + `tracing::error!`；**不回退**本地密码 |
| DN 缺失（未同步到 `external_dn`） | 视为未托管 → 走本地校验；若同时无本地密码 → `401` |

超时建议：连接 5s、操作 10s（可配）；**必须**设超时，否则 LDAP 挂起会拖垮登录线程池。

### 8.4 锁定策略（需确认，见 §17）

本地 `failed_login_attempts` 与 AD 自身锁定策略会**叠加**，可能把用户锁死且互相掩盖原因。建议 v1：

- LDAP 认证**失败不计入**本地锁定（交由目录侧的锁定策略）；
- 但**仍记录**审计 `auth.login.failed` 与 Prometheus 指标，保留暴力破解可见性。

**已按此实现**：`Credential::Invalid { counts_toward_lockout: false }` 表达这一决定，登录处理器据此跳过 `failed_login_attempts` 自增与本地锁定分支，审计与指标照写（指标走 `signet_directory_login_failures_total`，与本地失败分开）。判定放在返回类型里而不是调用处，是为了让"这个失败该不该记本地账"成为一个必须显式回答的问题。

---

## 9. 命令行

已实现于 `directory/cli.rs`。引入 CLI 对 `main.rs` 是行为变更（此前完全不解析 argv、纯 env 配置），因此**无子命令时保持原行为**（读 env → 起服务），既有容器 command 与部署脚本不受影响。

### 9.1 命令

```bash
signet sync run     --source <code> [--dry-run] [--json] [--limit <n>]
signet sync ldap    --source <code> [--dry-run] [--json] [--limit <n>]   # run 的别名
signet sync runs    --source <code> [--json] [--limit <n>]               # 默认 20 条
signet sync sources [--json]
signet serve                                                             # 等同无子命令
```

`run` 的 connector 由数据源的 `kind` 决定（`ldap` / `http_json`），同一命令驱动两类源。子命令名随 P4 从 `ldap` 改为 `run`，`ldap` 以 `#[command(visible_alias = "ldap")]` 保留为别名，既有脚本无需修改。

`--limit` 语义不只是"少跑几条"：**它同时跳过"上游缺失即 disable"的对账**——只看到一个片段的快照，无法区分"已删除"与"排在 limit 之后"。因此有限跑动的报告会打上 `reconciled: false` 并显式提示，绝不会因为截断而误停用用户。

### 9.2 典型用法

```bash
# 首次接目录：只算差异、不写库，先看会新增/更新/停用哪些人
signet sync run --source corp-ldap --dry-run

# 确认无误后正式跑
signet sync run --source corp-ldap

# 只抽样验证属性映射是否正确（注意：不做缺失对账）
signet sync run --source corp-ldap --limit 50

# 排障：看最近运行历史 / 列出已配置的源
signet sync runs --source corp-ldap
signet sync sources
```

### 9.3 `--dry-run` 的边界

`--dry-run` 是 LDAP 首次上线的安全带，只计算 created/updated/disabled/conflict 的预期结果并输出差异，**不写库**。它同时**不开 run 记录**（`status` CHECK 里没有 `dry_run`，记录一次"什么都没写"的运行会让历史说谎），因此 `runs` 里看不到 dry run。

### 9.4 输出

```bash
$ signet sync sources
code                 kind       enabled  priority interval   credential
corp-ldap            ldap       true          100 30m        set
```

```bash
$ signet sync runs --source corp-ldap
id                                     started (UTC)        status    created updated disabled conflicts
3f6c1e2a-…                             2026-09-20 15:40:02  succeeded       2       1        0         0
```

`run` 的文本报告含 `source / mode / status / scanned + 各计数`，随后逐条列出 noteworthy 变更（每条附 `reason`）；超过 50 条时截断并提示改用 `--json`（`--json` 始终是完整列表）。

`disable` 的 `reason` 有两个取值（§6.3）：`absent_upstream`（目录已不再列出）与 `out_of_scope`（仍在目录里，但掉出该源的作用域，即调岗/域变更）。二者是运维区分「离职」与「调岗」的唯一依据，因此以原样 token 输出，便于 `grep`/告警规则匹配。

`runs` 文本表只列 7 列；`--json` 返回 `RunRow` 全字段（含 `trigger`、`scanned`、`skipped_count`、`error_count`、`stats`），需要区分 `cli` / `schedule` / `manual` 触发时用 `--json`。

`status` 取值：`running` / `succeeded` / `partial`（跑完但有 conflict 或 entry error）/ `failed`。

### 9.5 退出码与失败语义

- 成功 `0`；任何错误 `1`（`main` 返回 `anyhow::Result`），错误摘要同时以 `Error: …` 打到输出，便于 CI 判定。
- 源不存在 / 配置解析失败：`load_source` 在 `open_run` **之前**执行，因此 `Error: directory source not found: <code>` 之类只终止进程，**不落 run 记录、也不写审计**（`source::get_by_code` → `SourceConfig::parse`）。
- 连接失败等规划期错误：发生在 `open_run` **之后**，会把该 run 以 `failed` + `error` 收尾，并写一条 `directory.sync.failed` 审计（dry run 的 `run_id` 为 `null`）。留下失败记录是有意为之——否则进程被杀会永久占住"运行中"。
- **并发保护**：迁移 `025` 的单运行唯一索引保证一个源同一时刻只有一条 `running`。与 dashboard 手动触发或调度器抢跑时，后来者会拿到 `another sync run for this source is already in progress`（HTTP 侧为 409），而不是两次同步交错。超过 `STALE_RUN_MINUTES`（120 分钟）的 `running` 会先被标记为 `abandoned by a previous process` 再开新 run，避免进程被杀后源被永久卡住。

### 9.6 运行前提（重要）

CLI **不是**轻量客户端：它复用 `build_state`，因此启动时会做与 server 完全相同的一套初始化——

- 连接 `SIGNET_DATABASE_URL` 并**执行迁移**；
- 加载或**自动生成** `jwt_private.pem` 与 `encryption.key`；
- 一次性重加密 webhook secret（失败即致命，不会静默降级为不签名）；
- 修剪过期审计日志、按需创建 SCIM token、构造 WebAuthn 依赖方。

由此引出两条运维硬要求：

1. **DB、密钥路径、`SIGNET_WEBAUTHN_RP_ID` / `RP_ORIGIN` 必须与 server 一致**。用不同的 `SIGNET_ENCRYPTION_KEY_PATH` 跑 CLI 会就地生成一份**新**密钥文件，然后因解不开已有密文而失败；即使侥幸跑通，也会留下一份与 server 不一致的密钥产物。建议通过同一份 env（或容器内同 cwd）执行。
2. `dotenvy` 会读取**当前工作目录**的 `.env`。在容器外手工执行时务必 `cd` 到装载 env 的目录，否则会静默退回内置默认值。

生产环境的执行方式（容器内 `exec`）见 [deploy.md §4](./deploy.md#4-容器内执行目录同步-cli)。

### 9.7 日志与管道

日志走 **stdout**（与报告同一流），直接 `| jq` 会被 INFO 行污染。管道消费时显式关日志：

```bash
RUST_LOG=off signet sync sources --json | jq -r '.[].code'
```

日志本身遵循 [日志规范](../.cursor/rules/logging.mdc)：静态消息 + 结构化字段。`APP_ENV=production` 时为单行 JSON。

---

## 10. 定时调度与运行历史

现状：**没有任何**后台/定时任务设施，全仓库只有 `webhooks.rs` 两处 request-scoped `tokio::spawn`。

设计：

- 在 `build_app` 中 `tokio::spawn` 一个调度循环，`tokio::time::interval` 每分钟 tick；
- 每次 tick 寻找 `enabled = TRUE AND interval_minutes IS NOT NULL` 且到期的源；
- **多副本安全**：执行前用 `pg_try_advisory_lock` 抢源级锁（key 由 `source_id` 派生），抢不到就跳过。否则每个副本都会跑一遍同步；
- v1 用 `interval_minutes`（整数）而非 cron 表达式，避免引入 cron 解析依赖；后续需要再升级；
- 运行历史写 `directory_sync_runs`，并提供查询 API：

```text
GET  /api/v1/admin/directory/sources                        # 列表
POST /api/v1/admin/directory/sources                        # 新建（凭据加密入库）
PUT  /api/v1/admin/directory/sources/{code}                 # 更新
POST /api/v1/admin/directory/sources/{code}/enabled         # 启停
POST /api/v1/admin/directory/sources/{code}/sync            # 手动触发（异步，返回 run id）
GET  /api/v1/admin/directory/sources/{code}/runs            # 运行历史
GET  /api/v1/admin/directory/sources/{code}/runs/{id}       # 单次详情
```

权限：全部 `require_admin_role`（凭据属敏感配置）。

**已实现（P3）**：`directory::scheduler`（tick 60s / `MissedTickBehavior::Delay` / 跳过第一个立即 tick）+ `model::due_sources`。「到期」的判定全部落在这一条 SQL 里：`enabled`、`interval_minutes IS NOT NULL`、无**存活的** running run、距最近一次 `started_at` 已满 interval。

> **对 §10 的一处偏离：未使用 `pg_try_advisory_lock`。** 原因是会话级 advisory lock 属于**获取它的那个连接**，而本仓库的连接来自池、按查询借还——"加锁 → spawn 任务 → 解锁"会跨连接，锁根本锁不住，而一把锁不住的锁比没有锁更危险，因为读代码的人会以为有保护。
>
> 真正提供互斥的是迁移 `025` 的部分唯一索引（`directory_sync_runs (source_id) WHERE status = 'running'`）：`begin_run` 在**所有副本、所有触发方式**（schedule/manual/cli）下都只能插入一行、且插入发生在连接目录**之前**。输掉竞争的副本拿到 `Conflict`，不写任何东西。数据库约束不会被忘记。
>
> **另一个偏离（且是修 bug）**：`due_sources` 把"存活"定义为 `started_at` 在 `STALE_RUN_MINUTES` 之内。若把任何 `running` 都当作阻塞，一次崩溃留下的 run 会让该源**永远不再被调度**——恢复逻辑 `fail_stale_runs` 只在 `open_run` 里执行，而 `open_run` 只在有东西调用它时才到达。两个常量因此共享 `engine::STALE_RUN_MINUTES`：一旦漂移，要么永久卡死，要么和正在跑的同步撞车。`tests/directory_scheduler.rs` 用 `a_crashed_run_is_recovered_instead_of_wedging_the_source_forever` 钉住这一点。

---

## 11. 审计与可观测性

### 11.1 审计事件

| 事件 | 粒度 |
|---|---|
| `directory.source.created` / `.updated` / `.deleted` / `.enabled` / `.disabled` | 每次操作 |
| `directory.sync.started` / `.finished` / `.failed` | 每次运行（含 trigger、统计、耗时） |
| `directory.user.created` | **逐条** |
| `directory.user.disabled` | **逐条**（`detail.reason = absent_upstream`） |
| `directory.user.updated` | **仅汇总**（计数），不逐条 |
| `directory.conflict` | **逐条** |

> ⚠️ **必须处理 webhook 扇出**：`audit.rs:107` 对**每条**审计事件无条件调用 `webhooks::dispatch`，且**不重试**。一次 10 万用户的全量同步若逐条审计，会产生 10 万条审计 + 10 万次 webhook 投递。因此：
> - `updated` 只汇总不逐条；
> - 为同步事件增加扇出抑制（如 `directory_sources.config.webhook_events = "summary"`），或按 run 聚合为单条 `directory.sync.finished` 推送。

### 11.2 指标

- `directory_sync_runs_total{source,status}`
- `directory_sync_duration_seconds{source}`
- `directory_sync_entries_total{source,action}`
- `directory_sync_conflicts_total{source}`
- `directory_bind_total{result}`（登录 bind 成功/失败/不可达）

### 11.3 日志

遵循 [日志规范](../.cursor/rules/logging.mdc)：静态消息 + 结构化字段（`source_code`、`run_id`、`scanned`、`created`、`updated`、`disabled`、`conflicts`、`elapsed_ms`）；错误放 `error` 字段。**禁止**记录密码、服务账号凭据、bind 密码。

---

## 12. 安全

| 项 | 要求 |
|---|---|
| LDAP TLS | LDAPS + 强制证书校验（D4）；代码层不提供跳过校验的开关 |
| 凭据存储 | 服务账号密码/Bearer token 一律经 `Encryptor`（AES-256-GCM）落库到 `credential_enc`；**不得**明文 |
| 出站 SSRF | 新建统一出站模块：仅允许 `http(s)`、禁止跟随重定向、连接/整体超时、响应体大小上限、**阻断私网/回环/链路本地地址（含 DNS 解析后二次校验，防 rebinding）**。LDAP 本身不走 HTTP，但 HTTP JSON 源（P4）必须有，故在 P0 一并建立；同时把 `webhooks.rs:80` 与 federation 的 `issuer_url` 校验切到该校验 |
| 目录账号权限 | 只读，最小授权（仅需读取用户与组子树） |
| 提权防护 | 目录数据**永不**写 `users.role`；组只写 `directory_groups` |
| 只读强制 | `admin` 接口按 §5 拒绝修改托管字段，返回 `403` 与明确原因 |
| 冲突不接管 | 按 email 自动 claim 现有账号（尤其 admin/manager）在 v1 被明确禁止 |
| 密码 | 不落库、不落日志、不缓存；bind 直通仅用原始提交密码 |
| 顺带修复 | `webhooks.secret` 目前**明文**存储，而 SSO client secret / TOTP secret 均已加密 —— 应统一到 `Encryptor` |

---

## 13. 通用 HTTP JSON 源（P4）—— 已实现

配置（`kind = 'http_json'`，`config` 全部为显式点号路径，`deny_unknown_fields`）：

```json
{
  "url": "https://directory.corp.example.com/api/users",
  "method": "GET",
  "auth": "bearer",
  "users_path": "data.users",
  "external_id_path": "id",
  "email_path": "email",
  "email_domains": ["corp.example"],
  "department_path": "dept",
  "department_values": ["Engineering"],
  "username_path": "login",
  "display_name_path": "name",
  "groups_path": "groups",
  "pagination": { "mode": "cursor", "param": "cursor", "next_path": "paging.next", "max_pages": 10 }
}
```

- **鉴权**：`auth` 为 `"none"` / `"bearer"` / `{"basic": {"username": "..."}}`；密钥本身走 `credential_enc`（`Encryptor`，AES-256-GCM），**不落在 `config` 里**；`auth: none` 时不再强制要求凭据（`SourceConfig::requires_credential`，创建与更新走同一个判断）；
- **字段映射**：`a.b[0].c` 形式的点号路径（支持 `["带.点的键"]` 与可选 `$.` 根标记）。路径语法错误（空段、未闭合括号/引号）不允许被当作"取不到值"——否则写错的映射会静默变成"目录为空"，而空目录会把该源管理的用户全部 disable（D3）；
- **必须报错的失败**：`users_path` 不存在或不是数组 → 报错并带上路径名与命中值的 JSON 类型，**不返回空列表**；上游非 2xx → 只报状态码与去掉 query 的 URL，不回显 response body（可能是 HTML 错误页）；
- **分页**：`none` / `page`（`?page=N&page_size=M`，起始页与参数名可配）/ `cursor`（从 `next_path` 取下一个游标，取不到即结束）。三者都由 `max_pages` 硬性封顶（配置上限 1000）：一个"永远还有下一页"的上游会让同步在持有服务账号令牌时无限循环；
- **出站校验**：每页请求都重新走 `outbound::ensure_allowed`（DNS rebinding 意味着保存时的检查在抓取时已失效），不跟随重定向，响应体大小上限与连接/整体超时直接复用 P0 的 `outbound` 模块。保存时另做一次（`source::ensure_destination_allowed`），与 webhooks 同层：字面内网地址只有在 `SIGNET_OUTBOUND_ALLOW_PRIVATE` 打开时才允许保存；
- **复用 P1 的映射与对账层**：connector 只负责"取数据"，产出 `Vec<UpstreamUser>` 后进入同一个 planner / apply / 运行历史 / 审计链路；`engine::fetch_and_plan` 是唯一按 kind 分派的位置；
- **明确不做（v1）**：`method` 只支持 `GET`（POST body 没有配置面，故报错而非静默降级），不做通配符/过滤式的通用 JSONPath，不解析"组对象数组"（`{id,name}` 这类无法猜字段，宁可报"无组"也不臆造组名）；
- **作用域**：`email_domains` / `department_path` + `department_values` 与 LDAP 侧语义完全一致（§7.2.1），包括"掉出作用域即 disable"和 `out_of_scope` 原因。区别只在取值来源：部门是一个 JSON 路径而不是目录属性。URL 里自带 query 的上游筛选（`?dept=eng`）属于上游自己的过滤，Signet 看不见也无法校验，因此**不替代**这里的谓词；
- **增量**：仍未实现，退化为全量对账（与 LDAP 一致，见 §7.4）。

Dashboard：新建数据源时可选 kind（创建后不可改，与 API 一致），HTTP JSON 表单覆盖 URL / 鉴权 / 分页；**映射部分现在由两种 pull kind 共用**，见 §13.1。

---

## 13.1 映射 UI 与预览端点（两种 pull kind 共用）

### 13.1.1 为什么不是六个输入框

原先的映射是一组孤立的文本框（`data.users` / `id` / `mail` / `entryUUID`…），它把三件事同时推给运维：要凭记忆知道上游长什么样、要能背出路径语法、写错了要等到**下一次同步**才知道。第四件事更危险：规范化过程（邮箱小写、显示名回落邮箱前缀、组排序去重）在表单里完全不可见，提交完并不知道库里会变成什么。

所以共用形态是：**一张共享的映射表 + 按 kind 换的"样例面板"**。两种 pull kind 回答的是同一组问题，只是答案的语法不同：

| 映射行（`ROW_*`） | LDAP | HTTP JSON |
|---|---|---|
| `scope` | `base_dn` + `user_filter` | `users_path` |
| `external_id` | `external_id_attribute` | `external_id_path` |
| `email` | `email_attribute` | `email_path` |
| `username` | `username_attribute` | `username_path` |
| `display_name` | `display_name_attribute` | `display_name_path` |
| `groups` | `group_base_dn` + `group_filter` + `group_member_attribute` + `group_name_attribute` | `groups_path` |

行定义在前端一处（`dashboard/src/lib/directoryMapping.ts`），加 kind 是改数据而不是再写一个表单。`scim` **不在**这张表里：它是 push 方向（§3），映射由 SCIM schema 固定，所以 UI 上明确它不是待配置的拉取源，而不是给它摆一张假映射表。

### 13.1.2 样例：贴一次，然后点选

不在第一批做"从上游拉取"，因此两个 kind 都用**粘贴**获得样例，各自贴合其数据形状：

- **JSON 是嵌套的 → 两棵树**。第一棵"列表在哪"（只有数组节点可点，数组以外的节点置灰并说明原因）；选定后第二棵"单条记录长什么样"，**以 entry 为根重新挂载**，因此它给出的路径自动是 entry 相对的（`id`，而不是 `data.users[0].id`——后者只对第一页第一条成立，换页即失效）。
- **LDIF 是扁平的 → 属性清单**。`ldapsearch -LLL` 的输出就是 LDIF，正好是 LDAP 侧最常配错的东西（`uid` vs `sAMAccountName`、`entryUUID` vs `objectGUID`）的权威来源。解析在**后端**（`directory::ldif`），前端只渲染返回的 `targets`，避免第二份 LDIF 实现。

`targets` 带出现次数与来源（`user` / `group` / `both`），多值属性标 `N values`。JSON 侧的"某个键在 12 条里有几条有"由前端按 entry 统计并显示为 `12/12` / `3/12` 徽标——存在于少数条目的字段会被高亮，这正是"只看第一条"必然看不出的问题。

**点击落点**：点击样例里的字段会填进**当前获得焦点的输入框**；没有焦点时不响应并显示提示。这样不需要"模态里再套一个选择器"。

### 13.1.3 `POST /admin/directory/sources/preview-mapping`（admin-only，纯函数）

```
{ kind, config, sample?, sync_groups?, offset? }
→ { fields: [{ row, ok, error, resolved, total, fixed }],
    targets: [{ key, count, multi, source, sample_value, user_entries, group_entries }],
    rows: [{ external_id, external_dn, email, username, display_name, groups }],
    warnings: [...], entry_count, offset, page_size, truncated }
```

- **不碰数据库、不发网络请求**：`sample` 只在内存里参与计算，不落库、不写日志（它是一段真实目录数据）；
- **与同步共用同一段代码**，因此预览不可能与真实运行分歧：LDAP 走 `ldap::upstream_from_entry`（`fetch_users` 也调它），HTTP JSON 走 `http_json::to_upstream`，规范化走 `plan::ManagedFields::from_upstream` + `plan::normalize_groups`；
- **按行报错而不是一句"配置无效"**：`ok/resolved/total` 让 UI 把结论挂在出错的那一行上。`scope` 行对 LDAP 检查两件事：样例 DN 是否落在 `base_dn` 之下（`user_filter` 由服务器执行，本地无法判定，响应里明说），以及 §7.2.1 的作用域谓词是否**至少放行一条** —— 谓词是本地求值的，所以这一条能判定，而"匹配 0 条"直接判 `ok: false`（原因写在 `error` 里，并且指出它在真实运行里会禁用该源已管理的所有人）。未配置作用域时该行维持原语义（`resolved` = 落在 `base_dn` 之下的条目数），因此老配置的回显不变；
- **不做的事也要说清**：未提供样例时 `fields` 为空 + 一条 warning，**不假装已校验**；没有组条目时明说组列未验证；`group_base_dn` 已配但 `sync_groups` 关闭时明确警告"组不会写入"；
- **样例体积上限 1 MiB**（路由额外放宽 body limit 到 4 MiB，避免被框架的 413 抢先）；
- **校验全量、回显分页**：`fields` 的 `resolved/total` 与 `targets` 的出现次数一律对**全部**样例条目计算（`total == entry_count`），只有 `rows` 按 `offset` 分页返回，每页 `page_size = 25`。二者刻意不共用同一个数：早期版本把校验也截断在前 50 条，于是同一块面板上同时出现 "120 entries" 和 "10/50" 两个分母，而那个小的分母把稀缺属性说得比实际更普遍（8% 显示成 20%）——这正是该计数要防的误判。分析是一次内存遍历，`MAX_SAMPLE_BYTES` 已封顶，因此"算全量"的代价可以忽略；
- `offset` 超出范围时**回落到最后一页**而不是返回空表（两次防抖之间样例可能变短，空表会被读成"这个源没有用户"）。`page_size` 恒为页宽（容量），**不要用 `rows.len()` 步进**：条目可能因缺少 external id 而不产生行，末页也会短于页宽，用行数步进会与前后的窗口重叠；
- `deny_unknown_fields`：拼错的请求字段（例如 `sample_json`）会 400，而不是静默变成"没样例、校验通过"；
- **不写审计**：它不写库、不读库、不持有凭据，且在编辑映射时会被反复调用；真正需要审计的是配置的保存（`directory.source.*`）。样例同样**不持久化**。

### 13.1.4 一处刻意的近似

LDAP 的组在真实同步里是从**组侧**搜索得到（`fetch_group_membership` 对 `group_base_dn` 做带 `group_filter` 的服务器端搜索）。粘贴的 LDIF 没有服务器可查，只能按"DN 落在 `group_base_dn` 之下且带 `group_member_attribute`"推定成员关系。

因此组列在 LDIF 模式下标注**最佳推定**（`warnings`），其余五列是精确的。精确答案留给"从上游拉取样例"（不做 probe 就不做精确承诺）。

### 13.1.5 预览与保存的一致性

预览请求里的 `config` 直接取自**表单当前值**，而不是保存用的 `buildBody()`，因此输入框里有什么就预览什么，改动即时生效。

之所以能这样做，是因为**后端放宽了校验**：未填写的映射键被报成"尚未设置"（该行 `ok = false`，`error = "… is not set yet"`），而不是"配置非法"。早期的严格校验要求 `display_name_attribute` 这类可选键必须存在，于是直接预览原始表单会因为一个空字符串而 400 —— 那样反而会逼着前端把预览接到 `buildBody()` 上。

一致性靠这一点保证：预览与保存读同一份表单值，而"保存会省略空的可选键"这件事由后端按"空即未设置"来解释，两边就不会出现"预览通过但保存失败"或反之。

---

## 14. SCIM inbound push（P5 概要）

现有 `/scim/v2` 是 SCIM **服务端**，路线正确，但需加固才能真正承接 Okta / Entra 的推送：

| 问题 | 位置 | 待办 | 状态 |
|---|---|---|---|
| `role = 'user'` 违反 CHECK（只允许 admin/manager/member），**建用户必然 500** | `scim.rs` create_user | 改为 `'member'` | ✅ 已修（与 §15 #1 同一处） |
| `PATCH` 请求体的操作列表名是 `operations`，而 RFC 7644 与各 IdP 发的是 `Operations`；serde 大小写敏感 + `#[serde(default)]` ⇒ 列表为空、**整个请求体被丢弃**，却回 200 与未改动的资源 | `scim.rs` `PatchUserBody` / `PatchGroupBody` | 接受两种拼写 | ✅ 已修（`rename = "Operations"`, `alias = "operations"`） |
| 操作未读 `op`/`path`，一律按写入处理 ⇒ 组路由上 `remove` **反而把成员加上**；`{"op":"remove","path":"active"}` 无 `value` ⇒ 静默无效；Entra 的 `{"op":"Replace","path":"active","value":false}`（标量）⇒ 被接受并忽略 | `scim.rs` `patch_user` / `patch_group` | 按 RFC 7644 §3.5.2 解析 `op`/`path`，支持 `active`/`displayName`/`members` | ✅ 已修（语义抽成 `user_attrs_from_patch` / `group_member_changes` 纯函数） |
| `PATCH /Groups` 只能加不能删 | `scim.rs` `patch_group` | 支持 add/remove/replace | ✅ 已修（含 Okta 的 `members[value eq "<id>"]` 过滤器形式） |
| `delete_group` 绑定了未使用的 `$1` | `scim.rs` `delete_group` | 修正绑定 | ✅ 已修（与 §15 #4 同一处） |
| DELETE 返回 200 + Error schema | `scim.rs` `delete_user` / `delete_group` | 改为 `204` | ✅ 已修 |
| `PATCH /Users` 不支持 `userName` / `emails` 写入 | `scim.rs` `patch_user` | 按 op/path 正确解析，支持 `userName`/`emails`/`active` | ⏳ 待做：`emails`/`username` 是 UNIQUE 列，写入需要先决定唯一冲突对推送客户端意味着什么（409 还是合并），属 P5 功能而非缺陷 |
| 无 filter 支持 | `scim.rs:100` | 视上游要求决定是否实现 | ⏳ 待做 |
| 审计缺失（无 `scim.group.*`） | — | 补齐 | ⏳ 待做：`delete_user` 有 `scim.user.delete`，组侧的 create/patch/delete 尚无 |
| 组模型 | — | 从 `users.groups` 迁移到 `directory_groups`，与 §6.5 对齐 | ⏳ 待做 |

> **`Operations` 那一项值得单独说明**：它让上面所有 PATCH 缺陷都变得不可观测——真实客户端的请求体在反序列化阶段就变成了空列表，路由于是"成功"地什么都没做。先前的缺陷分析（"完全忽略 op/path 语义"）是在只有小写拼写的请求体下才成立；对上真实 IdP，症状是"PATCH 一律返回 200 且无任何变化"。回归测试因此走**请求体**这一层（`user_attrs_from_body` / `group_member_changes_from_body`），而不是直接调用解释器——否则这个 bug 依然测不到。

推送写入路径应复用同步的映射与冲突逻辑，并写 `directory_sync_runs`（`trigger = 'push'`）以获得统一的运行历史与审计。

---

## 15. P0 缺陷修复清单（所有阶段的前置）

这些是当前代码里**已经坏掉**、且正好落在本设计要复用的链路上的缺陷：

| # | 位置 | 问题 | 修法 | 状态 |
|---|---|---|---|---|
| 1 | `scim.rs:228` | 插入 `role = 'user'`，违反 `CHECK (role IN ('admin','manager','member'))` → `POST /scim/v2/Users` 必然 500 | 改为 `'member'` | ✅ 已修 |
| 2 | `mfa/mod.rs:341` | `mfa_challenges.purpose = 'change_password'`，违反 `CHECK (purpose IN ('login','enroll'))` → 强制改密流程坏 | 扩展 CHECK 或改用既有值 | ✅ 已修（迁移 `022`，按约束定义查名删除，不依赖自动命名） |
| 3 | `auth/routes.rs:90` | `password_hash = ''` 的用户（SSO JIT / SCIM 创建）会使 `PasswordHash::new("")` 报错，被 `?` 转成 **500** 而非 401 | 按 §8.1 分派；非托管用户的空 hash 返回 401 | ✅ 已修（空 hash → 401；§8.1 的 LDAP 分派待 P2） |
| 4 | `scim.rs:684` | `delete_group` 的 UPDATE 只引用 `$2`，却先绑定了 `group.id` | 修正参数绑定 | ✅ 已修 |
| 5 | `webhooks.rs:80` | 出站 URL 只校验 `http(s)://` 前缀，无 SSRF 防护 | 接入 §12 统一出站校验 | ✅ 已修（新增 `outbound` 模块；创建时 + **每次投递时**校验，禁用重定向） |
| 6 | `webhooks.rs:87` | `webhooks.secret` 明文存储，与其它密钥处理不一致 | 经 `Encryptor` 加解密 | ✅ 已修（迁移 `023` 加 `secret_enc`；`audit::record` 改为接收 `&AppState`，53 处调用点同步更新；`bootstrap::encrypt_webhook_secrets` 在启动时把存量明文一次性搬走） |
| 7 | `federation/provider.rs` | 出站 HTTP 无 timeout（仅 webhook 有 10s） | 统一到出站模块 | ✅ 已修（统一 client：连接 5s / 整体 10s、禁重定向、响应体 1 MiB 上限） |

> **第 6 项的落点**：`audit::record(pool, event)` 已改为 `audit::record(state, event)`，`webhooks::dispatch` / `deliver_one` 同样接收 `&AppState`，因此投递路径能拿到 `Encryptor` 解密 `secret_enc`。`login_alert::track_login` 一并改签名。存量明文通过启动时的 `bootstrap::encrypt_webhook_secrets` 搬迁，且该步骤**故意设为致命错误**：静默失败会让 `secret_enc` 为空，投递直接降级为不签名。

> **出站校验的兼容性提示**：`outbound` 默认拒绝解析到私网/回环/链路本地地址的目标，因此**指向内网地址的既有 webhook 会开始投递失败**（会记录一条 `success = false` 的投递记录）。若内网 webhook 接收方确实需要保留，设 `SIGNET_OUTBOUND_ALLOW_PRIVATE=true`（部署级开关，默认关闭；开启时启动会打一条 WARN，且该开关只放宽**地址**策略，仍拒绝非 http(s) 协议与内嵌凭据）。另：所有出站请求都禁用了重定向，若某 provider 的 endpoint 依赖重定向会受影响。`issuer_url` 与 OIDC discovery 走的是严格模式（仅字面地址检查、不解析 DNS），内网 IdP 用主机名即可正常工作。


---

## 16. 分期与验收

| 阶段 | 内容 | 验收标准 | 状态 |
|---|---|---|
| **P0 地基** | §15 全部缺陷修复；`is_managed`/只读语义；§4 三张表 + `users` 变更；审计事件；统一出站模块；凭据加密 | 现有测试通过；SCIM 建用户不再 500；强制改密可用；空密码用户返回 401；管理员改目录用户被拒 | ✅ 已完成：迁移 `024`（三张表 + `users` 两列）；`directory` 模块 + `tests/directory_policy.rs`；拒写已记审计。同步引擎自身的 `directory.sync.*` 事件推迟到 P1——现在还没有同步可审计 |
| **P1 LDAP 同步引擎** | 连接/LDAPS；全量分页拉取；指纹比对；创建/更新；缺失即 disable；组写入 `directory_groups`；CLI（含 `--dry-run`、`--json`）；手动触发 API；运行历史 | `--dry-run` 输出的差异与真实执行一致；对目标目录跑通全量；上游删人后用户变 disabled 且审计留痕；重复运行第二遍 `updated = 0` | ✅ 已实现：`directory/{source,plan,model,ldap,engine,api,cli}.rs`；迁移 `025` 保证单源单 run；CLI `signet sync`；`/admin/directory/sources` 系列端点。测试：`tests/directory_plan.rs`（纯规划 10 例）、`tests/directory_engine.rs`（真库 7 例，含"第二次运行 `updated = 0`"）。**未对真实目录联调**——需要 Q1 确定 AD/OpenLDAP 后做 |
| **P2 LDAP bind 直通** | 按 §8 分派登录；LDAPS bind；fail closed；指标 | 目录用户能用目录密码登录并正常走 MFA；改密后新密码生效；LDAP 停机时返回 503 且明确不回退 | ✅ 已实现：`directory::auth`（三态结果）+ `ldap::bind_as`（一次性 bind、必 unbind）+ 登录处理器分派 + 两个独立指标 + `set_user_password` 收口。测试：`tests/directory_login.rs`（15 例，含"不可达 → 503 而非 401""复选源按 priority""停用源/删除源回退本地""托管账号拒绝写本地密码"）。**未对真实目录验证**：`改密后新密码生效`、`正常走 MFA` 需 Q1 确定 AD/OpenLDAP 后联调 |
| **P3 定时调度** | §10 调度循环 + advisory lock；运行历史 UI 入口 | 到点自动运行；双副本同时启动只跑一次；失败有审计与指标 | ✅ 已完成：调度（`directory::scheduler` + `model::due_sources`，含崩溃遗留 run 的自动恢复）、运行历史 UI（`DirectoryView.vue` 的 History 面板 + `/admin/directory/sources/{code}/runs`）、调度与同步指标（`signet_directory_sync_runs_total` / `_failures_total` / `_partial_total` / `_conflicts_total` / `_last_success_timestamp_seconds`）。测试：`tests/directory_scheduler.rs` 8 例。**未做**：advisory lock（见 §10 说明，改由迁移 `025` 的部分唯一索引保证） |
| **P4 HTTP JSON 源** | §13 | 完成一次全量同步；SSRF 用例（内网地址、重定向、超大响应）全部被拒 | ✅ 已完成：`directory/http_json.rs`（点号路径映射 + `none`/`page`/`cursor` 分页 + Bearer/Basic 鉴权 + 每页重新走 `outbound` 校验）；`SourceConfig` 按 kind 分派，planner/apply 完全复用；API 与 Dashboard 支持 `kind = http_json`。测试：`tests/http_json_source.rs` 21 例，含**真库端到端**一次全量同步 + 二次运行零变更，以及"严格策略下内网地址在抓取时被拒且请求未发出" |
| **P4.5 共用映射 UI** | §13.1 | 贴一次样例即可点选映射；预览与真实写入（规范化后）一致；样例不落库不写日志 | ✅ 已完成：后端 `directory/{ldif,mapping}.rs` + `POST /admin/directory/sources/preview-mapping`（纯函数，与同步共用 `upstream_from_entry` / `to_upstream` / planner 规范化）；LDAP 侧把 entry→`UpstreamUser` 抽成 `ldap::upstream_from_entry` 供同步与预览共用。前端 `lib/directoryMapping.ts`（共享行定义）+ `components/directory/{MappingPanel,MappingTable,FieldPicker}.vue` + `lib/valueShape.ts`（交互规范见 `docs/directory-mapping-ux.md`）；LDAP 表单把映射键交还给面板（连接/鉴权/分页仍留在表单）。**校验全量、回显分页**：`fields`/`targets` 的计数对全部样例条目计算（`total == entry_count`），`rows` 按 `offset` 每页 25 条返回。测试：`tests/directory_mapping_preview.rs` 52 例（LDIF 折行/`::` base64/二进制 `objectGUID`→GUID/注释与 `version`/畸形行报行号/URL 值拒绝、两种 kind 的逐行判定与规范化行、样例体积上限、请求体契约、分页与完整计数的一致性、作用域行的判定）。**未做**：从上游拉取样例（probe），故 LDAP 组列为最佳推定（§13.1.4） |
| **P4.6 从上游拉取样例（probe）** | §13.1.2 | 不必手工粘贴；LDAP 组列由近似变为精确 | 待做（可独立交付；需新增 admin-only 的 probe 端点，复用 `outbound::ensure_allowed`） |
| **P4.7 源作用域：邮箱域 / 部门** | §7.2.1 | 只同步指定域/部门；配置写错（匹配 0 条）时预览直接判失败而不是静默清空；运行历史能区分「离职」与「调岗」 | ✅ 已完成：`plan::ScopeFilter`（纯谓词，域按标签边界比较、无通配符）+ `UpstreamUser.department` + `PlanOptions.scope`；planner 对掉出作用域的已 link 用户产出 `Disable`，`reason = out_of_scope`（与 `absent_upstream` 区分，并一路带到审计 detail）；`apply_disables` 改为逐条沿用 planner 的原因；两个 kind 的配置字段与保存期校验（空条目、通配符、把地址当域、`department_values` 缺 `department_attribute`/`department_path` 一律拒绝）；预览的 `scope` 行改为可判定（匹配 0 条 ⇒ `ok: false`，且对**全量**样例计数）；Dashboard 在 scope 行加入域/部门输入（列表在表单里是单个字符串，出站时才切分成数组）。测试：`tests/directory_scope.rs` 29 例（谓词边界，含 `evilcorp.example` 不得匹配；planner 的两个 reason 与 `--limit` 下不禁用；配置校验）+ `tests/directory_mapping_preview.rs` 新增 11 例。**刻意未做**：单次运行禁用数超过阈值即中止（本次只要求"可区分"，见 §7.2.1 的安全阀讨论） |
| **P5 SCIM push 加固** | §14 | Okta/Entra 真实推送可完成增删改；组增删正确；审计完整 | ⏳ 进行中：§14 的**缺陷**已修（`Operations` 字段名、`op`/`path` 语义、组成员 remove/replace、DELETE `204`），测试 `tests/scim_patch.rs` 23 例；**剩余为功能**——`userName`/`emails` 写入、filter、`scim.group.*` 审计、组模型迁移 |

> **P1 与 P2 必须紧邻交付**：只做同步不做 bind 直通，目录用户同步进来却登不进去，功能等于没交付。

---

## 17. 未决事项

| # | 待定 | 影响 |
|---|---|---|
| Q1 | 首个联调目标是 **AD** 还是 **OpenLDAP**？ | 决定 `external_id` 字段、成员解析方式、增量字段。建议**先锁死一个**，不要同时兼容 |
| Q2 | 用户量级与期望同步频率？ | 决定 `page_size`、批事务大小、是否需要增量（全量对账在 10 万级下的窗口） |
| Q3 | LDAP 认证失败是否累加本地锁定计数？（§8.4 建议**不累加**） | 双重锁定风险 |
| Q4 | 组是否采用分列方案 `directory_groups`？（§6.5 推荐） | 影响 OIDC claim 组装与后台展示 |
| Q5 | 是否需要多源同时托管一个用户？ | 影响冲突仲裁（`priority`）与 `directory_entries` 是否允许多行同用户 |
| Q6 | 是否需要在 `README.md` / `README.zh-CN.md` 的文档索引中登记本文？ | 文档可达性 |
| Q7 | `department_values` 是否需要**层级/前缀**语义（如"Engineering 下所有子部门都算"）？ | 当前只做精确值比较（§7.2.1），AD 里若把部门写成 `Engineering / Platform` 这类路径，则必须把 `department_attribute` / `department_path` 指到**恰好那一层**，否则配了也不匹配。加前缀语义等于放宽作用域判定，会改变"掉出作用域即禁用"的边界，需要连带决定：是否要在预览的 `scope` 行区分"前缀命中"与"精确命中"，以及前缀是否只按 `/` 分隔符切。**暂不实现**，先只记录 |
