# Signet 设计文档

| 项 | 内容 |
|---|---|
| 项目名 | **Signet**（印鉴） |
| 定位 | 组织内统一身份认证服务（OIDC IdP） |
| 生产入口（未来） | `https://sso.example.com` |
| 开发 Issuer | `http://localhost:8443`（`SIGNET_ISSUER`，不绑生产域名） |
| 协议 | OAuth 2.0 / OIDC **Authorization Code + PKCE** |
| 首个客户端 | Cella（内网部署、可出网） |
| 状态 | Phase 1 MVP 实现中 |

---

## 1. 目标与非目标

### 1.1 目标

- 为多个内部子系统提供**统一登录**（SSO）
- 以标准 **OIDC** 对外，客户端可替换、可并行开发
- 支持：**公网 Signet + 内网业务系统**（业务可出网访问 Signet）
- 提供可撤销的登录会话与（可选）统一登出
- 给出稳定的身份主键（`sub`）与基础用户信息，供业务侧做授权

### 1.2 非目标（首期不做）

- 不替代各业务系统的**细粒度业务权限**（数据集 ACL、操作审计策略等仍在业务侧）
- 不做企业微信/钉钉全量同步（可作为后续 IdP 连接器）
- 不做通用 API 网关、计费、应用商店
- 不与阿里云 OSS（对象存储）混用命名或配置前缀

### 1.3 认证 vs 授权边界

```text
Signet  ──负责──→  认证（你是谁）：登录、会话、id_token、统一登出
业务系统 ──负责──→  授权（你能做什么）：角色、数据集权限、功能开关
```

Signet 可下发可选的 `roles` / `groups` **claims** 作为业务侧的初始映射，但**权威业务授权表在业务系统**（如 Cella 用户角色表）。

---

## 2. 部署拓扑

### 2.1 推荐拓扑

```text
                        公网
              ┌─────────────────────┐
              │  sso.example.com │
              │  Signet (OIDC IdP)     │
              └──────────▲────────────┘
                         │ HTTPS 出站
         ┌───────────────┴────────────────┐
         │ 内网（可访问外网）                │
         │  Cella / 其他子系统              │
         │  用户浏览器（可开内网 + 公网）     │
         └────────────────────────────────┘
```

### 2.2 为何可行

OIDC 授权码模式的关键跳转发生在**用户浏览器**：

1. 浏览器打开内网 Cella  
2. 重定向到公网 Signet 登录  
3. Signet **302 回跳**浏览器到内网 `redirect_uri`（Signet **服务端不必**主动连入内网）  
4. Cella 服务**出站**调用 Signet 的 token / JWKS / userinfo  

### 2.3 约束

| 约束 | 说明 |
|------|------|
| 用户浏览器 | 须能同时访问内网业务与公网 Signet |
| 业务服务器 | 须能出站访问 `sso.example.com` |
| `redirect_uri` | 登记为内网回调即可，无需公网可达 |
| 无 VPN 的外网用户 | 无法完成「回跳内网」，属预期（业务仅内网使用时） |
| 时钟 | 内网机器时间需准确，否则 JWT 校验失败 |

---

## 3. 协议与端点

### 3.1 选用协议

- **OIDC Authorization Code Flow + PKCE**（面向浏览器 SPA / 带前端的服务）  
- 机密客户端（若服务端持有 `client_secret`）与公共客户端（纯 SPA + PKCE）均可；Cella 推荐：**后端持码换票**（BFF 或 Axum 回调处理），避免 token 长期落在纯前端  

### 3.2 Issuer

```text
Issuer: https://sso.example.com
```

Discovery（计划支持）：

```text
GET https://sso.example.com/.well-known/openid-configuration
```

### 3.3 核心端点（首期）

| 端点 | 方法 | 说明 |
|------|------|------|
| `/oauth/authorize` | GET | 授权端点（登录 UI / 同意） |
| `/oauth/token` | POST | 换 token（authorization_code / refresh_token） |
| `/oauth/revoke` | POST | 可选：撤销 refresh / access |
| `/oauth/userinfo` | GET | 用户信息（需 access_token） |
| `/oauth/jwks` | GET | 公钥集，供客户端验 `id_token` |
| `/oauth/logout` 或 OIDC `end_session_endpoint` | GET/POST | 统一登出（二期可完善） |
| `/health` | GET | 探活，公开 |

登录页与管理台同域托管（`/login`、`/activity`、`/overview`、`/users`、`/clients`、`/audit-logs`、`/settings`、`/integrations`）。Dashboard JSON API 统一 **`/api/v1/*`**（见 [api-v1.md](./api-v1.md)）。

### 3.4 Token 类型

| Token | 用途 | 备注 |
|-------|------|------|
| `id_token` | 身份断言（JWT） | 业务用于建立本地登录会话 |
| `access_token` | 调 Signet userinfo 或受保护 API | 不建议业务 API 直接当业务会话长期使用 |
| `refresh_token` | 刷新 | 旋转刷新；可撤销 |

业务系统（Cella）在完成回调后，应签发**自己的会话**（cookie / 本地 JWT），后续 API 鉴权以业务会话为准，并缓存 `sub` 与用户主键映射。

---

## 4. 身份与数据模型（逻辑）

### 4.1 核心实体

```text
User            用户（登录主体）
ClientApp       接入应用（如 cella）
AuthorizationCode / RefreshToken / Session
（可选）Group / Membership   组与成员，用于 claims 映射
（可选）Org                  多租户预留，首期可单租户
```

### 4.2 User（最小字段）

| 字段 | 说明 |
|------|------|
| `id` | 内部 UUID |
| `sub` | OIDC subject（对外稳定主键） |
| `email` | 登录名 |
| `phone` | 可选联系电话（明文，用于联系/找回预留；当前仅作联系信息，**未做短信验证绑定**） |
| `display_name` | 展示名 |
| `password_hash` | Argon2 |
| `status` | `active` / `disabled`（冻结） |
| `role` | `admin` / `manager` / `member` |
| `mfa_required` | 策略：是否强制该用户启用 MFA |
| `totp_enabled` / `totp_secret` | 绑定事实与密钥 |
| `created_at` / `updated_at` | |

### 4.3 ClientApp（接入方）

| 字段 | 说明 |
|------|------|
| `client_id` | 如 `cella` |
| `client_secret_hash` | 机密客户端 |
| `redirect_uris` | 精确白名单 |
| `post_logout_redirect_uris` | 可选 |
| `grant_types` | `authorization_code`, `refresh_token` |
| PKCE | 始终要求 S256（`pkce_required` 字段已移除） |
| `scopes` | `openid`, `profile`, `email` |
| `enabled` | |
| `ip_allowlist_enabled` | 默认新建为 true；可关 |
| `allowed_cidrs` | IP / CIDR 列表 |

### 4.4 Claims（id_token / userinfo）

**必选：**

- `sub`  
- `iss` = `https://sso.example.com`  
- `aud` = `client_id`  
- `exp` / `iat`  
- `email`（若有）  
- `name` 或 `preferred_username`  

**可选（首期可空实现）：**

- `groups` / `roles` — 仅作业务侧初始角色映射，不代替业务 ACL  
- `phone_number` — 联系电话（需请求 `phone` scope）

> 实际下发按 **scope 裁剪**：`email` 需 `email` scope、`name` 需 `profile` scope、`phone_number` 需 `phone` scope、`groups` 需 `groups` scope，`sub` 恒有。见 [client-integration.md](./client-integration.md)。

---

## 5. 登录与登出流程

### 5.1 登录（Cella 示例）

```text
用户 → Cella UI/API（未登录）
     → 302 Signet /oauth/authorize
          ?client_id=cella
          &redirect_uri=https://<cella-host>/auth/callback
          &response_type=code
          &scope=openid profile email
          &state=...
          &code_challenge=...
          &code_challenge_method=S256
     → 用户在 Signet 登录
     → 302 redirect_uri?code=...&state=...
     → Cella 后端：code + code_verifier → Signet /oauth/token
     → 校验 id_token（iss/aud/exp/签名）
     → upsert 本地用户（按 sub）
     → 建立 Cella 会话
     → 进入业务页
```

### 5.2 登出

1. 清除 Cella 本地会话  
2. （可选）重定向 Signet `end_session_endpoint`，并带 `post_logout_redirect_uri`  
3. Signet 清除自身 SSO 会话，使其他已接子系统下次也需重新登录  

首期可只做第 1 步；第 2–3 步作为统一登出增强。

### 5.3 账号生命周期与角色（已定）

Signet **不是**对外账户体系：无公开自助注册。

角色：

| 角色 | 能力 |
|------|------|
| `admin` | 用户/客户端全量管理含删除；全局 Settings（含 MFA 开关）；审计全量；Reset 他人 2FA；**不可删除**审计记录 |
| `manager` | 创建/冻结用户；管理客户端（不含删除）；用户级 `mfa_required`；审计可见非删除类事件 |
| `member` | Home + 账户菜单：资料、密码、自愿/已绑 MFA |

删除类操作（用户删除、客户端删除、MFA reset、全局 Settings）**仅 `admin`**。  
管理台说明见 [dashboard.md](./dashboard.md)；HTTP API 见 [api-v1.md](./api-v1.md)。

### 5.4 首次部署初始化 admin

服务启动迁移完成后：

1. 若已存在 `role = 'admin'` 且 `status = active` 的用户 → 无操作  
2. 若不存在管理员 → 暴露 **`/setup` 页面**：首次访问时在 Web 上创建管理员账户与密码（`POST /api/v1/setup`），创建后即登录  

`/setup` 创建流程有并发保护（Postgres advisory lock），且创建成功后写审计 `setup.complete`。详见 [api-v1.md](./api-v1.md)。

业务系统（Cella）的「第一个业务管理员」由 **Cella** 自己的 bootstrap 解决，不依赖 Signet 把所有人都设成超管。

---

## 6. 与业务客户端的契约

**完整对接步骤、请求字段、token claims、排错**：见 [client-integration.md](./client-integration.md)。

### 6.1 业务客户端 OIDC 配置（摘要）

| 配置项（示例名） | 值 |
|------------------|-----|
| `OIDC_ISSUER` | 开发 `http://localhost:8443`；生产 `https://sso.example.com` |
| `OIDC_CLIENT_ID` | 在 Signet 后台 / 动态注册中登记的 `client_id` |
| `OIDC_CLIENT_SECRET` | 创建客户端时一次性下发的 secret |
| `OIDC_REDIRECT_URI` | 精确白名单，如 `https://<app-host>/auth/callback` |
| `OIDC_SCOPES` | `openid profile email` |

### 6.2 客户端责任

- 授权码 + PKCE S256；后端持 secret 换票  
- 校验 `id_token`；本地用户以 `sub` 唯一映射  
- 业务 ACL 在业务侧；Signet 只做认证  
- 前端未登录跳转 Signet；401 统一处理  
- 遵守客户端 **Source IP 白名单**（若启用）：详见对接文档  

### 6.3 开发期可替换性

只依赖标准 OIDC Discovery；Issuer 可切换，业务代码不绑死 Signet 实现细节。

---

## 7. 安全要求

- 全站 HTTPS（`sso.example.com`）  
- `redirect_uri` **严格白名单**（防开放重定向）  
- 强制或默认 **PKCE S256**  
- `state` / `nonce` 防 CSRF / 重放  
- Token 短 TTL；refresh **旋转**  
- 密码：Argon2；登录审计带 **客户端 IP**  
- **登录防爆破**：连续失败锁定账号（`SIGNET_MAX_LOGIN_ATTEMPTS` / `SIGNET_LOCKOUT_MINUTES`）  
- **密码策略**：最小长度 + 大小写/数字复杂度；历史密码防复用  
- **MFA（TOTP + 恢复码）**：全局 / 用户级强制开关；[mfa.md](./mfa.md)  
- **TOTP 密钥静态加密**：`totp_secret` 使用 AES-256-GCM 应用层加密后落库（密钥 `data/encryption.key` 或 `SIGNET_ENCRYPTION_KEY_PATH`）；旧明文行读取时自动兼容
- **会话管理**：活跃会话列表、单点撤销、管理员强制下线；OIDC `end_session` 统一登出  
- **OIDC Consent**：首次授权需用户同意，记住授权；显式请求的 scope 整体允许/拒绝，客户端允许列表内未显式请求的可选 scope 可由用户勾选单独授予（GitHub 式）  
- **groups claims**：用户组随 `id_token` / `userinfo` 下发，作业务侧初始角色映射  
- **客户端 Source IP 白名单**：新建默认开启（可关）；[client-integration.md](./client-integration.md)  
- 管理后台与 OIDC 端点分权限；Dashboard API 统一 **`/api/v1`**  
- 密钥：JWT RS256；JWKS 暴露公钥  
- 审计：登录、管理操作、MFA/Settings 变更；Overview 展示 24h/7d/30d 登录统计；支持 CSV 导出与保留策略；记录客户端 IP 与浏览器/OS（由 `User-Agent` 解析）  
- 可观测：`/metrics` 暴露登录/token/MFA 计数与 HTTP 指标（Prometheus 文本格式）；请求日志带 `x-request-id` 关联链路  

> 以上安全机制的实现现状（已实现/规划中）与密钥、配置项汇总见 **[security.md](./security.md)**。



---

## 8. 技术选型（建议，可调整）

与现有 Rust 栈对齐，便于同一团队维护：

| 层 | 建议 |
|----|------|
| 语言 | Rust |
| HTTP | Axum |
| DB | PostgreSQL |
| 前端（登录页 / 管理台） | 独立目录 `dashboard/`：Vue 3 + Vite + Tailwind CSS v4 + shadcn-vue 风格；`dist` 嵌入 Rust 二进制 |
| 密码 | Argon2  
| JWT | 非对称签名（RS256 或 EdDSA） |

具体 crate 与模块拆分在实现阶段再定；本文不绑定实现细节。

---

## 9. 分期路线图

### Phase 0 — 契约与骨架

- 本设计定稿  
- 仓库 `signetproject`、域名证书、基础部署清单  

### Phase 1 — 最小可用 IdP（给业务系统用）

- User + ClientApp CRUD（可先配置文件 / 简单管理）  
- authorize / token / jwks / userinfo  
- 登录页 + PKCE  
- Discovery 文档  
- 注册客户端  

### Phase 2 — 会话与运维

- refresh 旋转、revoke  
- 统一登出  
- 管理后台（用户禁用、应用管理、审计查询）  
- 监控与告警  

### Phase 3 — 扩展

- groups/roles claims  
- 外部 IdP 联邦（企业微信等）  
- 多租户 / 多环境隔离  

### Phase 4 — 安全加固（已实施，除短信验证）

按优先级排序：

| 优先级 | 功能 | 状态 | 说明 |
|--------|------|------|------|
| P0 | 密码重置/找回 | ✅ | `/api/v1/password-reset/*`；30 分钟单次 token；SMTP 真实投递（未配置时 503） |
| P0 | **手机号短信验证绑定** | ⏳ | 唯一未实施项：需短信网关；当前 `phone` 仅作联系信息落库，未验证 |
| P0 | RFC 7009 吊销端点 | ✅ | 独立 `/oauth/revoke` |
| P0 | WebAuthn/Passkey + 恢复码 | ✅ | 注册/登录/管理；挑战存内存 |
| P1 | 新设备/IP 登录告警 | ✅ | `login_devices` + `auth.new_device` 审计/告警邮件 |
| P1 | API 全局速率限制 | ✅ | 按 IP 滑动窗口限流，超限 429 |

### Phase 5 — 集成与运维（已实施）

| 优先级 | 功能 | 状态 | 说明 |
|--------|------|------|------|
| P1 | OAuth 客户端动态注册 | ✅ | RFC 7591 `/oauth/register` + 一次性注册 token |
| P2 | SCIM v2 用户/组同步 | ✅ | `/scim/v2/Users`、`/scim/v2/Groups` |
| P2 | Webhooks 事件推送 | ✅ | 审计事件异步推送 + HMAC 签名 |

### Phase 6 — 监控与可观测（部分实施）

| 优先级 | 功能 | 状态 | 说明 |
|--------|------|------|------|
| P1 | HTTP 指标 | ✅ | 请求计数（按状态类）/ 在途 / 延迟直方图导出到 `/metrics` |
| P1 | 健康检查增强 | ✅ | `/health` 探测 Postgres，失败 503 |
| P2 | 告警对接 | ⏳ | 基于 Prometheus 指标接入 Alertmanager |
| P2 | 链路追踪 / 请求 ID | ✅ | `x-request-id` 生成/透传/回显 + tracing span 关联 |

### 组身份迁移（规划中，未排期）

当前组身份以**显示名**为键：`users.groups[]` 与 `users.directory_groups[]` 存名字，
`scim_groups.id` 是唯一真正的组标识符，`docs/integrations.md` 里 SCIM User 的
`groups[].value` 已改为组 id。核实过的边界：SCIM 组**没有改名端点**（PATCH 只处理
成员增删换，创建后 `displayName` 不可变），本地组由用户编辑时按名隐式创建——因此
"改名孤儿化成员"目前不可触发，该迁移是**还技术债**而非修复在逃缺陷。

迁移方向（做时一次性完成，不拆步）：

1. `users.groups` / `users.directory_groups` 改存组 id（text[]→uuid[]，迁移时为
   现有每个名字建组记录并回填 id）；
2. OIDC `groups` claim 与 dashboard 渲染在读取时 join 出名字；
3. 目录同步的组写入（指纹比较含组列表）改按 id；
4. 展示名归组表所有，改名即改一行。

前提：目录同步的组语义（上游组名→本地组）需要先定义"上游组没有本地记录时"的
创建策略，避免迁移把隐式约定变成显式 bug。

> 已实现的可观测基础：`/metrics` 暴露登录/token/MFA 计数与 HTTP 指标；`TraceLayer` 请求日志；`/health` 依赖探测；审计日志保留策略。

---

## 10. 配置与密钥命名

避免再使用 `OSS_*` 前缀。建议：

```text
SIGNET_DATABASE_URL=
SIGNET_HTTP_BIND=0.0.0.0:8443
SIGNET_ISSUER=https://sso.example.com
SIGNET_JWT_PRIVATE_KEY=   # 或 KMS 引用
```

客户端侧（Cella）使用 `OIDC_*` 或 `SIGNET_*` 均可，团队内统一一种即可；**禁止**用 `OSS_` 表示本服务。

---

## 11. 术语对照

| 旧口头说法 | 现标准称呼 |
|------------|------------|
| OSS 单点登录 | **Signet** |
| OSS 登录页 | Signet 登录（`sso.example.com`） |
| 阿里云 OSS | 对象存储（与本项目无关） |

---

## 12. 开放问题

1. 各业务系统的正式域名与 `redirect_uri` 最终值（在 Signet 后台 / 动态注册中登记）  
2. Cookie 会话还是业务侧 JWT 会话（各业务自行决定，Signet 只发 OIDC token）  
3. 生产环境是否单独 issuer / 密钥 / 库（与开发隔离）  

已确认：用户来源为首期本地账号 + 管理员开户；机密客户端 + PKCE；开发不使用生产域名。

---

## 修订记录

| 日期 | 说明 |
|------|------|
| 2026-08-13 | 初稿：Signet 定位、OIDC+PKCE、公网/内网拓扑、与 Cella 边界与分期 |
| 2026-08-13 | 账号模型：管理员开户 + bootstrap admin；开发 issuer 与 `dashboard/` 前端约定 |
| 2026-08-13 | 落地：登录防爆破、密码策略、会话管理、groups claims、OIDC Consent、审计导出/保留、Prometheus metrics |
| 2026-08-13 | 路线图新增 Phase 4/5：密码重置、refresh 轮换/吊销、WebAuthn、登录告警、限流、客户端管理+动态注册、SCIM、Webhooks |
| 2026-08-13 | 实施 Phase 4/5/6（除短信验证、告警对接、链路追踪）：吊销、密码重置、Passkey、登录告警、限流、动态注册、SCIM、Webhooks、HTTP 指标与健康检查 |
| 2026-08-13 | 补齐：MFA 用户自主禁用（非强制时）、Users 表 MFA 状态列、consent 可选 scope 授权、`phone` scope / `phone_number` claim、`x-request-id` 链路追踪 |
