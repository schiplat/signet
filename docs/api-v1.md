# Signet HTTP API（`/api/v1`）

Dashboard / 会话相关管理接口统一挂在 **`/api/v1/...`**。  
OIDC 协议端点仍为 `/oauth/*` 与 `/.well-known/openid-configuration`（见 [client-integration.md](./client-integration.md)）。动态注册 / Webhooks / SCIM 对接示例见 [integrations.md](./integrations.md)。

鉴权：浏览器 Cookie `signet_session`（HttpOnly）。未登录返回 `401`；权限不足返回 `403`。

错误体（JSON）：

```json
{ "error": "message" }
```

---

## 1. 认证与当前用户

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/login` | 密码登录；可能返回 MFA 分支 |
| `POST` | `/api/v1/logout` | 登出 |
| `GET` | `/api/v1/me` | 当前用户 |
| `PATCH` | `/api/v1/me` | 更新 `display_name` / `phone`（手机查重，排除自身） |
| `POST` | `/api/v1/me/password` | 修改密码（校验复杂度 + 历史） |
| `GET` | `/api/v1/me/sessions` | 当前用户的活跃会话列表 |
| `DELETE` | `/api/v1/me/sessions/{id}` | 撤销指定会话（不含当前） |
| `POST` | `/api/v1/me/sessions` | 撤销除当前外的所有会话 |
| `GET` | `/api/v1/me/consents` | 当前用户已授权的应用（OAuth 同意记录） |
| `DELETE` | `/api/v1/me/consents/{client_id}` | 撤销对某应用的授权（连带吊销其 refresh token） |
| `GET` | `/api/v1/me/activity` | 当前用户自己的活动记录（登录 + 账号/安全操作），`?page=&page_size=` 分页；并附 `summary`（上次登录 / 活跃会话 / 2FA·passkey / 已授权应用数） |

### 首次部署初始化（首次登录创建管理员）

无任何 active `admin` 用户时，首次访问会跳转到 `/setup` 页面，在 Web 上创建首位管理员（替代早期由环境变量在启动时创建的方式）。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/setup/status` | 公开：返回 `{ "needs_setup": true/false }`（是否存在 active admin） |
| `POST` | `/api/v1/setup` | 公开：创建首位 admin 并登录。body `{ "email", "password", "display_name"? }`；已存在 admin 时返回 `409` |

- `POST /api/v1/setup` 成功后签发会话（`signet_session` Cookie）并返回 `{ "status": "ok", "user": ... }`。
- 密码校验与普通用户一致（长度 + 大小写 + 数字，见 `SIGNET_PASSWORD_MIN_LENGTH`）。
- 并发保护：使用 Postgres 咨询锁（advisory lock）保证只创建一个 admin。

### `POST /api/v1/login`

请求：`{ "email", "password" }`

响应之一：

| `status` | 含义 |
|----------|------|
| `ok` | 已签发会话；含 `user` |
| `mfa_required` | 需再调 MFA verify（Cookie：`signet_mfa`） |
| `enroll_required` | 需强制绑定 TOTP |

成功登录会写审计 `auth.login`，并记录 **客户端 IP**（`X-Forwarded-For` / `X-Real-IP` / 直连 peer）。

### 登录防爆破与密码策略

- 连续密码错误达到 `SIGNET_MAX_LOGIN_ATTEMPTS`（默认 5）后锁定账号 `SIGNET_LOCKOUT_MINUTES`（默认 15）分钟；失败写审计 `auth.login_failed`。
- 密码强度：`SIGNET_PASSWORD_MIN_LENGTH`（默认 10）且需大小写字母 + 数字。
- 历史复用：新密码不得与最近 `SIGNET_PASSWORD_HISTORY_SIZE`（默认 3）次历史相同。
- 配置项均通过环境变量覆盖，见 `.env.example`。

---

## 2. MFA

详见 [mfa.md](./mfa.md)。

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/mfa/verify` | 登录挑战：TOTP / 恢复码 |
| `POST` | `/api/v1/mfa/enroll/start` | 强制 enroll：生成 secret + otpauth |
| `POST` | `/api/v1/mfa/enroll/confirm` | 强制 enroll 确认；返回 `recovery_codes` |
| `GET` | `/api/v1/me/mfa` | 已登录：MFA 状态 |
| `POST` | `/api/v1/me/mfa/enroll/start\|confirm` | 自愿绑定 |
| `POST` | `/api/v1/me/mfa/recovery/regenerate` | 轮换恢复码（需当前 TOTP） |
| `POST` | `/api/v1/me/mfa/rebind/start\|confirm` | 换绑 |
| `POST` | `/api/v1/me/mfa/disable` | 用户自主禁用 MFA（需当前 TOTP，body `{ code }`；全局或用户级强制时返回 400） |
| `GET/PATCH` | `/api/v1/admin/settings/mfa` | **admin**：全局强制开关 |
| `GET/PATCH` | `/api/v1/admin/settings/sso` | **admin**：SSO JIT 开户开关 `{ "jit_provision": bool }` |
| `GET/PATCH` | `/api/v1/admin/settings/sign-in` | **admin**：登录白名单（邮箱域名），见 §14 |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/runtime` | **admin**：运行时策略（token/会话有效期、登录锁定、密码策略、审计保留、限流）；优先级 **DB > 环境变量 > 默认**，DELETE 清除覆盖 |
| `GET/POST` | `/api/v1/admin/tokens` | **admin**：机器凭据（PAT）列表 / 创建。创建 `{ "name", "expires_in_days"? }` 返回 `{"id","token":"sgn_pat_…（仅此一次）"}`；调用方在 `Authorization: Bearer` 头携带该 token 即可访问本表全部 admin 端点（无需会话 Cookie）。token 本身不携带权限：每次调用按**属主当前**的 role/status/must_change_password 校验，属主降级/冻结/改密即失效。审计 actor 记为属主 |
| `DELETE` | `/api/v1/admin/tokens/{id}` | **admin**：吊销（立即生效） |
| `POST` | `/api/v1/admin/users/{id}/mfa/reset` | **admin**：重置他人 MFA |

---

## 3. 管理：用户

需 staff（admin / manager）；删除与部分操作仅 admin。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/users` | 分页列表。返回 `{ users, total, limit, offset }`；行内含 `mfa_required` / `totp_enabled` / `groups` / `phone` / `provisioned_via` / `has_password` / `sso_identities` / `directory_sources` / `scim_managed` |
| `GET` | `/api/v1/admin/users/email-check?email=` | 邮箱查重，返回 `{ "exists": bool }` |
| `GET` | `/api/v1/admin/users/phone-check?phone=&exclude_id=` | 手机查重，返回 `{ "exists": bool }`（`exclude_id` 可选，编辑时排除自身） |
| `POST` | `/api/v1/admin/users` | 创建（可带 `groups`、`phone`） |
| `PUT` | `/api/v1/admin/users/{id}` | 更新（含 `mfa_required`、status、role、`groups`、`phone`…） |
| `DELETE` | `/api/v1/admin/users/{id}` | **admin** 删除 |
| `POST` | `/api/v1/admin/users/{id}/disable` | 冻结 |
| `POST` | `/api/v1/admin/users/{id}/enable` | 解冻 |
| `POST` | `/api/v1/admin/users/batch-disable` | 批量冻结 `{ "ids": [] }` |
| `POST` | `/api/v1/admin/users/import` | **admin** 批量导入 `{ users: [...], update?: bool, dry_run?: bool }`，≤1000 行；逐行校验、行级错误不中断批次；`update=true` 时更新已存在账号的资料（**不改密码**）；`dry_run=true` 时全量校验并返回与真实执行相同的分类结果（响应多一个 `dry_run: true` 字段），**不写任何数据、不写审计**（响应含 `created/updated/skipped/errors`）；真实导入每行写 `user.create` 审计，另写一条 `user.import` 汇总 |
| `GET` | `/api/v1/admin/users/export` | **staff** 用户 CSV（邮箱/用户名/显示名/角色/状态/组/手机，公式中和） |
| `POST` | `/api/v1/admin/users/{id}/sessions/revoke` | 强制下线该用户全部会话 |

`groups` 为用户组（`TEXT[]`），会作为 `groups` claim 下发到 `id_token` 与 `/oauth/userinfo`，供业务侧做初始角色映射（不替代业务 ACL）。`phone` 为可选的明文联系电话（`TEXT`，空即不填）。创建/更新邮箱时后端会显式查重，重复返回 `400 "email already exists"`；手机同理（非空时唯一，重复返回 `400 "phone already exists"`，DB 有部分唯一索引 `users_phone_key`）。

列表额外字段：`provisioned_via`（如 `sso_jit` 表示第三方 JIT 开户，否则 `null`）、`has_password`、`sso_identities`（`[{ provider_code, display_name, provider_type }]`，已绑定的第三方）。

**`GET /admin/users` 分页契约**：

- `?q=` 服务端搜索，覆盖 email、username、display_name、status、role、`provisioned_via`、SSO 身份（provider 显示名/code/type）。`_` 与 `%` 按字面字符匹配（已转义），非通配符。
- `?sort=` 取值白名单：`created_at`（默认）/ `email` / `display_name` / `role` / `status`；`?dir=` 仅接受 `asc`（其余一律 `desc`）。
- `?limit=` 钳制到 `[1, 200]`（默认 20）；`?offset=` ≥ 0。
- 排序以 `id ASC` 作次级键：同 `created_at`（如目录批量导入）的行在跨页时不会重复或丢失。
- `total` 是命中搜索的行数（非本页行数）；翻页用 `offset`，越界返回空 `users` 数组而非错误。

**`POST /admin/users/batch-disable` 语义**：逐行做权限检查（manager 不能冻结 admin，冻结目标排除自己），返回的 `disabled` 计数包含**所有存在的目标 id**——重复冻结已冻结的账号也计入（操作幂等，重复选择不会少报）；仅不存在的 id 不计入。每个目标账号产生一条审计事件；全部成功后一次性吊销其全部会话。

> `phone` 当前仅作**联系信息**，未做短信验证绑定；验证绑定（SMS OTP）为规划项，见 [design.md](./design.md) Phase 4。

---

## 4. 管理：Clients

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/clients` | 列表 |
| `POST` | `/api/v1/admin/clients` | 注册（secret 仅返回一次） |
| `PUT` | `/api/v1/admin/clients/{id}` | 更新 redirect / scopes / **IP 白名单**（PKCE 已无开关，始终强制 S256） |
| `DELETE` | `/api/v1/admin/clients/{id}` | **admin** 删除 |
| `POST` | `/api/v1/admin/clients/{id}/disable\|enable` | 启停 |
| `POST` | `/api/v1/admin/clients/{id}/rotate-secret` | 轮换 secret |

### IP 白名单字段

| 字段 | 默认（新建） | 说明 |
|------|--------------|------|
| `ip_allowlist_enabled` | `true` | 开启后仅 `allowed_cidrs` 可访问该客户端的 authorize/token |
| `allowed_cidrs` | `[]` | IP 或 CIDR；开启时**至少一条** |

已有客户端迁移后默认为 **关闭**限制。详见 [client-integration.md](./client-integration.md)。

---

## 5. 管理：概览与审计

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/stats` | Overview 统计（登录趋势 24h 小时粒度 + 7d/30d 日粒度；支持按应用筛选与应用/浏览器/OS 分布） |
| `GET` | `/api/v1/admin/audit-logs` | 审计列表（含 `ip` / `browser` / `os` / `client_id`；可按 action / client_id / browser / os / q / sort） |
| `GET` | `/api/v1/admin/audit-logs/export` | 审计导出 CSV（`text/csv`，尊重 staff 权限过滤，含 `client_id` 列） |
| `GET` | `/api/v1/admin/audit-logs/facets` | 审计筛选下拉数据源（近 90 天 browser / os 去重值 + 全部应用） |

### `GET /api/v1/admin/stats`（节选）

- 用户 / 客户端计数  
- `logins_24h` / `logins_7d` / `logins_30d`（当前窗口合计）  
- `unique_users_24h` / `unique_users_7d` / `unique_users_30d`  
- `login_trend[]`：近 30 日每日点，含 `day`、`logins_1d`、滚动 `logins_7d` / `logins_30d`
- `login_trend_24h[]`：近 24 小时逐小时点（UTC 整点，含空桶补零），含 `hour`、`logins`  
- `by_client[]`：近 30 天按应用聚合（Top 10，按 30d 降序），含 `client_id`（`(direct)` 表示无应用归属的直登）、`logins_24h/7d/30d`、`unique_users_30d`  
- `browsers[]` / `oses[]`：近 30 天登录事件的浏览器 / 操作系统分布，含 `name` / `count`  
- `scope`：回显当前筛选（`client_id` 为 `null` 表示全局）  

Query：可选 `client_id`。传入应用标识时，上述登录类字段（合计 / 独立用户 / 趋势 / 最近登录 / 分布）均过滤为该应用；传 `(direct)` 仅统计无归属的直登。用户与客户端计数恒为全局。

### `GET /api/v1/admin/audit-logs`

Query：`q`、`action`、`client_id`、`browser`、`os`、`page`、`page_size`、`sort`（含 `ip`）、`dir`。  
每行含 `ip`、`user_agent`、`browser`、`os`、`client_id`（登录/MFA 等事件有值；`browser`/`os` 由 `User-Agent` 解析；`client_id` 为发起登录的 OAuth 应用，从 2026-09 起的新日志开始记录，历史数据为空）。  
manager 仅见允许的 action 白名单；`user.delete` / `client.delete` / `mfa.reset` / `settings.mfa_update` 等仅 admin。

### `GET /api/v1/admin/audit-logs/facets`

返回 `browsers[]`、`oses[]`（近 90 天日志中的去重值，升序）与 `clients[]`（全部应用，含 `client_id` / `enabled`），供审计页与 Overview 的筛选下拉使用。

### 登录审计的应用归属

登录接口（`POST /auth/login`、`POST /mfa/verify`、`POST /mfa/enroll/confirm`、`POST /passkeys/finish`）接受可选 `return_to` 字段（形如 `/oauth/authorize?...&client_id=xxx`）。服务端解析并在 `client_apps` 校验通过后，将该应用的 `client_id` 写入 `auth.login` / `auth.login_failed` 审计事件；解析失败不影响登录流程。

---

## 6. 与 OIDC 的边界

| 前缀 | 用途 |
|------|------|
| `/api/v1/*` | Signet Dashboard、会话、后台管理 |
| `/oauth/*` | 标准 OIDC（业务客户端对接） |
| `/health` | 探活 |
| `/metrics` | Prometheus 指标（独立监听；默认仅 `127.0.0.1:9464`，`SIGNET_METRICS_BIND` 可改/关） |

### 审计保留策略

小时巡检清理 `created_at` 早于保留窗口的记录（`SIGNET_AUDIT_RETENTION_DAYS`，默认 180；也可在 Settings → Runtime policies 修改，**不得小于 1 天**）。管理台查询与导出不受影响。

### OIDC 附加端点

- `GET/POST /oauth/consent`：同意页提交（`allow` 为 `true`/`false`）。显式请求的 scope 在 `allow` 时整体授予；客户端允许列表内未请求的 scope 作为可选，由用户在授权页勾选，经 body `optional_scopes`（空格分隔）提交。允许则写 `oauth_consents` 并回跳 authorize（回跳只带原本请求的 scope）。
- `GET/POST /oauth/end_session`：统一登出。GET 必须携带 `id_token_hint`（验签、`sub` 与会话一致）；POST 不需要（Lax cookie 不随跨站表单发送）。`post_logout_redirect_uri` 须在该客户端的白名单内才回跳，`client_id` 与 hint 的 `aud` 同时出现时须一致。
- `POST /oauth/revoke`：RFC 7009 吊销端点。表单字段 `token`、可选 `token_type_hint`；客户端须以 Basic 或 `client_id`+`client_secret` 认证。仅吊销 refresh token（access token 为无状态 JWT，无法服务端吊销）。无论 token 是否存在均返回 200。
- `POST /oauth/register`：RFC 7591 动态客户端注册。需 `Authorization: Bearer <token>` 或表单 `initial_access_token`（单次使用，由管理员签发）。返回 `client_id`/`client_secret`。
- `POST /oauth/introspect`：RFC 7662 令牌自省。客户端以 Basic 或 `client_id`+`client_secret` 认证；body `{ token }`。返回 `{ active: bool, ... }`：`active=false` 覆盖签名无效、已过期、**用户已禁用/删除**、客户端已禁用——这是本地验签 JWT 给不了的能力。未知 token 不报错（§2.2）。
- `POST /oauth/token` 的 `grant_type=client_credentials`：机器对机器（M2M）令牌。客户端须在注册时被授予该 grant；无刷新令牌、无用户 claim，`sub` = `client_id`，scope 收敛到客户端登记列表（body `scope` 只能子集）。

**Authorization Code 附加参数**

| 参数 | 说明 |
|------|------|
| `max_age`（秒） | 层次升级（step-up）。会话年龄超过该值时销毁会话并强制重登录；`prompt=none` 下回 `error=login_required`；`max_age=0` 恒需新登录 |
| `code_challenge` / `code_challenge_method` | 恒为 `S256`，强制，无开关 |

`id_token` 附加 claim：`auth_time`（本次认证时间，来自授权码）、`email_verified`。`access_token` 亦携带 `email_verified` 与客户端自定义 claim。

**每客户端额外 claim**（`client_apps.extra_claims`，Dashboard → Clients 编辑）：JSON 对象，值可为字面量（字符串/数字/布尔）或占位符 `$sub` / `$email` / `$username` / `$display_name` / `$phone`；合并进该客户端的 `id_token`、`access_token` 与 `/oauth/userinfo` 响应。占位符无法解析时**中止签发**（不发出缺 claim 的令牌）；M2M（无用户）令牌只保留字面量。

**Back-Channel Logout**（`client_apps.backchannel_logout_uri`）：用户会话被终结（登出 / `end_session` / 管理员强制下线 / 改密或换邮箱）时，向持有该用户授权的每个登记客户端 POST 表单 `logout_token=<签名 JWT>`（含 `events` 成员与 `sub`，`exp` 120 秒）。best-effort：失败只记日志，RP 可另经自省或短 access token TTL 兜底。

> **scope 裁剪**：`id_token` 与 `/oauth/userinfo` 均按已授权 scope 下发 claim——`email` 需 `email` scope、`name` 需 `profile` scope、`phone_number` 需 `phone` scope、`groups` 需 `groups` scope，`sub` 恒有。

## 7. 密码重置

| 方法/路径 | 说明 |
|-----------|------|
| `POST /api/v1/password-reset/request` | body `{ email }`；生成 30 分钟有效的重置 token 并经 SMTP 发送。**未配置 `SIGNET_SMTP_HOST` 时返回 503**（不再假装成功；开发态可开 `SIGNET_DEV_LOG_LINKS` 把链接打到日志）。邮箱不存在仍返回 `{ ok: true }` 防枚举；投递失败返回 502 |
| `POST /api/v1/password-reset/confirm` | body `{ token, new_password }`；校验 token、应用密码策略、吊销全部会话 |

### 自助换邮箱（需已验证当前邮箱）

| 方法/路径 | 说明 |
|-----------|------|
| `POST /api/v1/me/email/change-request` | session；body `{ new_email }`。校验邮箱格式、与当前不同、域名白名单、未被占用；生成 30 分钟单次 token 投递到**新地址**（走 outbox 队列）。当前邮箱 `email_verified=false` 时返回 403 |
| `GET /api/v1/me/email/confirm?token=` | 无需登录（链接即凭证）；单次消费。成功 → `302 /settings?email_changed=1`，过期 → `302 /settings?email_error=expired`，已被占用 → `302 /settings?email_error=taken`。成功时置 `email_verified=TRUE`，吊销全部会话与 refresh token，并触发 back-channel logout |

## 8. Passkeys（WebAuthn）

| 方法/路径 | 认证 | 说明 |
|-----------|------|------|
| `GET /api/v1/me/passkeys` | session | 列出当前用户 passkeys |
| `POST /api/v1/me/passkeys/start` | session | 开始注册：返回 `{ token, challenge }` |
| `POST /api/v1/me/passkeys/finish` | session | 完成注册：body `{ token, name, credential }` |
| `DELETE /api/v1/me/passkeys/{id}` | session | 删除一个 passkey |
| `POST /api/v1/passkeys/start` | 公开 | 开始登录：body `{ email }` |
| `POST /api/v1/passkeys/finish` | 公开 | 完成登录：body `{ token, credential }`；成功后建立会话 |

挑战状态存于服务端内存（单实例、5 分钟有效）。passkey 公钥以 `webauthn-rs` `Passkey` JSON 形式落库，登录成功后更新签名计数器。

## 9. Webhooks

| 方法/路径 | 认证 | 说明 |
|-----------|------|------|
| `GET /api/v1/admin/webhooks` | admin | 列出 webhook（含 `kind`、`secret_set`） |
| `POST /api/v1/admin/webhooks` | admin | body `{ url, secret?, kind? }`，`kind` 为 `generic`（默认）或 `feishu` |
| `DELETE /api/v1/admin/webhooks/{id}` | admin | 删除 |
| `GET /api/v1/admin/webhooks/{id}/deliveries` | admin | 最近 50 条投递结果 |

每条审计事件写入后异步 POST 到所有启用的 webhook。`kind` 决定投递方式：

- **`generic`**：原始审计 JSON 原样 POST，请求头含 `x-signet-event`（事件 id）与 `x-signet-signature`（`sha256=<HMAC>`，用 `secret` 签名）。
- **`feishu`**：渲染为飞书交互卡片（`msg_type: interactive`），`secret` 用于飞书「签名校验」——按 `key = timestamp+"\n"+secret`、空消息做 HMAC-SHA256 后标准 Base64，字段 `sign` 与 `timestamp` 写入 body（非请求头）。

投递结果（状态码/成败/错误）写入 `webhook_deliveries`。

## 10. SCIM v2

`/scim/v2/*`，需 `Authorization: Bearer <token>`（token 未配置则禁用）。token 由后台生成/轮换/吊销，明文仅展示一次、库中只存哈希；`SIGNET_SCIM_BEARER_TOKEN` 仅作首次启动种子。

| 方法/路径 | 说明 |
|-----------|------|
| `GET/POST /scim/v2/Users` | 列表 / 创建（`userName`→email，`active`→status，`externalId`） |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | 按 id / externalId / email 定位 |
| `GET/POST /scim/v2/Groups` | 列表 / 创建 |
| `GET/PATCH/DELETE /scim/v2/Groups/{id}` | 详情 / 增删成员 / 删除 |
| `GET /scim/v2/ServiceProviderConfig` | 能力声明 |

组以 `users.groups[]` 为成员来源（`scim_groups` 表保存组元数据），与 OIDC `groups` claim 保持一致。

## 11. 集成状态

| 方法/路径 | 认证 | 说明 |
|-----------|------|------|
| `GET /api/v1/admin/integrations` | admin | 只读返回 `scim`（是否启用、端点、token 是否配置）与 `webauthn`（`rp_id`/`rp_origin`） |
| `POST /api/v1/admin/scim/token` | admin | 生成/轮换 SCIM bearer token，返回 `{"token":"<明文，仅此一次>"}` |
| `DELETE /api/v1/admin/scim/token` | admin | 吊销 SCIM bearer token（禁用 SCIM 接口） |

## 12. 第三方登录（身份联邦）

管理员在后台配置上游身份源后，用户可用第三方账号登录。配置存于 `upstream_providers`（`client_secret` AES-256-GCM 加密存储），绑定关系存于 `user_identities`（`(provider_code, subject)` 唯一）。

支持类型：`github` / `google` / `feishu` / `wechat` / `oidc`（通用 OIDC discovery，需 `issuer_url`）。

### 登录流程（浏览器重定向）

| 路径 | 说明 |
|------|------|
| `GET /api/v1/auth/sso/{provider}/start?return_to=` | 生成 CSRF state（HttpOnly cookie 存明文、库中仅存 SHA-256，一次性，10 分钟），302 到上游授权页。可选 `return_to`：发起登录的 `/oauth/authorize?...` URL（仅接受同源 OIDC 路径，防开放重定向），登录完成后回跳以续接原流程 |
| `GET /api/v1/auth/sso/{provider}/callback` | 校验 state → 换 token → 拉取归一化 profile → 绑定判定 → 签发会话或暂存待绑定（`auth.login.thirdparty` 审计）。账号仍有本地闸门（强制改密 / TOTP / 强制 MFA 注册）时，重定向 `/login?sso_step=mfa|enroll|password_change` 走与密码登录相同的续接流程 |
| `GET /api/v1/auth/sso/providers` | 公开接口：返回启用中的 provider（登录页按钮用） |

### 绑定策略（防账号接管 + OA JIT）

回调时按以下顺序判定（任一成功即结束）：

1. **已绑定**：`(provider_code, subject)` 已在 `user_identities` → 直接签发会话登录。
2. **已登录会话**：浏览器已有有效 `signet_session` → 把该上游身份绑到当前用户并登录。
3. **邮箱自动绑定**：上游返回的 email **已验证**，且 `lower(email)` 精确匹配本地 `status=active` 用户 → 自动写入 `user_identities` 并登录。
4. **JIT 开户**（默认开启，可关）：上游 email **已验证**且本地尚无该邮箱 → 自动创建 `role=member`、无密码的本地用户，写入绑定并登录。适合公司飞书 / Google / OIDC OA「首次点登录即可进系统、无需管理员预开户」。
5. **否则 → 暂存待绑定**：将身份写入 `identity_link_challenges` + cookie `signet_sso_pending`（**15 分钟**），重定向 `/login?sso_error=no_matching_account`。用户在时限内用密码 / MFA / Passkey 登录已有账号后完成绑定。

注意：

- JIT **不会**在无验证邮箱时开户（微信开放平台通常无邮箱 → 仍需管理员开户或邀请绑定）。
- 飞书需在应用侧开通邮箱相关权限，且 profile 能返回 `email` / `enterprise_email`，否则走第 5 步。对 `GET /open-apis/authen/v1/user_info`：`email` 需 **获取用户邮箱信息**（`contact:user.email:readonly`）；`enterprise_email` 另需 **获取用户受雇信息**（`contact:user.employee:readonly`）且租户已启用飞书邮箱。权限在开放平台开通并发布后生效（授权 URL 不带 `scope=`）。
- 关闭 / 开启 JIT：Dashboard → **Settings → JIT provision on SSO**（`app_settings.sso.jit_provision`），或 `GET/PATCH /api/v1/admin/settings/sso`。环境变量 `SIGNET_SSO_JIT_PROVISION` 仅在该配置行缺失时作为回退（默认 `true`）；跑过迁移 `020` 后以 DB / Settings 为准。
- **Provider 级覆盖**（迁移 `033`）：每个 provider 可配 `jit_mode`（`inherit` 跟随全局 / `on` 全局关也开 / `off` 全局开也关）与 `email_trust`（`inherit` 按 adapter 上报的验证标志 / `any` 有邮箱即视为已验证 / `verified` 要求上游显式验证标志）。各平台差异速查：

  ⚠️ **`any` 的前提是租户管控联系邮箱**：它信任"provider 断言了该邮箱"这件事本身。若上游允许用户自改联系邮箱（飞书个人版、自建 OIDC 等），攻击者可在受害者注册前以 `victim@corp.com` 完成自动绑定 / JIT 开户（预创建劫持）。保存 `email_trust=any` 时服务端会在日志输出警告；仅对管理员统一管控联系邮箱的租户启用。

  | provider_type | 邮箱验证标志 | 建议配置 | 说明 |
  |---------------|--------------|----------|------|
  | `github` | 上游如实返回（primary + verified） | `inherit` | 验证邮箱才自动绑定 / 开户 |
  | `google` | 上游如实返回（`email_verified`） | `inherit` | 同上 |
  | `oidc` | 取决于上游，标准字段 | `inherit`；上游不可信时 `verified` 收紧 | 同上 |
  | `feishu` | **无验证标志**（adapter 如实上报「未验证」） | 自有企业租户 `email_trust=any` + `jit_mode=on`；否则保持 `inherit` | 迁移 033 已把存量飞书 provider 置为 `any` 保持行为；新建默认 `inherit`（只允许绑定，需显式选 `any` 才自动开户） |
  | `wechat` | **无邮箱 API** | 不适用（`email_trust` 无效果） | 依旧豁免邮箱要求，只能绑定已有账号 |

  另：SSO 无法自动绑定 / 开户时暂存的 pending 身份，现在**只会在用户登录后于 Dashboard 显式确认时绑定**（`GET/POST/DELETE /api/v1/auth/sso/pending`，登录后顶部横幅），不再跟随"同一浏览器的下一次登录"自动绑定——共享机器上他人的暂存身份不会再落到你的账号上。确认时会按 provider 当前的邮箱域白名单重新校验。

  典型组合：企业飞书 / Google Workspace 租户 `jit_mode=on`（可信租户自动开户）；开放注册的 GitHub `jit_mode=off`（只允许绑定已有账号）。
- 第三方登录只证明上游身份：本地策略（强制改密、TOTP、全局/用户级强制 MFA）在会话签发前照常生效，与密码登录共用同一套 MFA 挑战（挑战行记录来源 `via=sso`）。

失败时回调重定向回登录页并带 `?sso_error=`：`unknown_provider` / `provider_disabled` / `state_mismatch` / `upstream_error` / `access_denied`（用户在第三方授权页拒绝/取消） / `missing_code` / `no_matching_account` / `email_required`（上游未返回邮箱；微信除外。已绑定过的 `(provider, subject)` 仍可直接登录）。

### 管理端 API（admin）

| 方法/路径 | 说明 |
|-----------|------|
| `GET /api/v1/admin/sso/providers` | 列表（含 `bindings`、`jit_mode`、`email_trust`、每条记录的具体 `callback_url`；`client_secret` 永不回传） |
| `POST /api/v1/admin/sso/providers` | 创建（`code` `[a-zA-Z0-9_-]`，`oidc` 必填 `issuer_url`；可选 `jit_mode` / `email_trust`，缺省 `inherit`） |
| `PUT /api/v1/admin/sso/providers/{code}` | 更新；`client_secret` 留空保持不变，传入即轮换；`jit_mode` / `email_trust` 同创建 |
| `DELETE /api/v1/admin/sso/providers/{code}` | 删除（级联删除绑定关系） |
| `POST /api/v1/admin/sso/providers/{code}/enabled` | 启用/禁用 `{"enabled": bool}` |
| `GET/PATCH /api/v1/admin/settings/sso` | JIT 开户开关 `{"jit_provision": bool}`（写入 `app_settings`） |
| `GET /api/v1/auth/sso/callback-url` | 返回统一 URL 模板：`{base}/api/v1/auth/sso/{provider}/callback` |

**回调地址规范（所有 provider 同一格式）**：  
`{SIGNET_PUBLIC_BASE_URL|/issuer}/api/v1/auth/sso/{code}/callback`  
GitHub / Google / 飞书 / 微信 / OIDC 均使用此路径；平台差异只体现在适配器内部（换 token、拉 profile），**不改变 URL 形态**。管理端列表每行直接给出该 provider 的完整可复制地址。

### 用户侧 API

| 方法/路径 | 说明 |
|-----------|------|
| `GET /api/v1/auth/sso/identities` | 当前用户已绑定的第三方账号列表 |
| `DELETE /api/v1/auth/sso/identities/{provider_code}` | 解绑；若解绑后没有任何登录方式（无密码且无其他绑定）则拒绝 |

## 13. 可观测性

| 端点 | 说明 |
|------|------|
| `GET /health` | 就绪探测：探测 Postgres（`SELECT 1`），失败返回 503 |
| `GET /metrics` | Prometheus 文本格式；登录/token/MFA 计数与 HTTP 请求计数、在途请求、延迟直方图。**独立监听**（默认 `127.0.0.1:9464`，`SIGNET_METRICS_BIND` 配置；公开端口不提供），该监听同时提供 `/health` |

全局速率限制：对 `/api/v1`、`/oauth/*` 等按客户端 IP 限流，默认 `SIGNET_RATE_LIMIT_PER_MINUTE=300`，超限返回 429。

链路追踪：所有响应回显 `x-request-id`（透传请求头或生成 UUID），并写入 tracing span，访问日志按 `request_id` 关联。

旧路径 `/api/...`（无 `v1`）已废弃，不再提供 JSON API。

## 14. 登录白名单（邮箱域名）

限制「谁能进来」：只允许指定邮箱域名下的地址登录、被开通、被同步。配置是**全域名列表**（不是邮箱前缀），匹配按标签边界比较（`corp.example` 匹配 `corp.example` 与 `mail.corp.example`，不匹配 `evilcorp.example`），大小写不敏感，无通配符。空列表 = 不限制。

### 配置与来源

| 来源 | 位置 | 优先级 |
|------|------|--------|
| `app_settings.auth.allowed_email_domains` | Dashboard → Settings → **Email domain allowlist**，或 `GET/PATCH /api/v1/admin/settings/sign-in` | 高于环境变量 |
| `SIGNET_ALLOWED_EMAIL_DOMAINS` | 环境变量（逗号或空白分隔） | 仅在该配置行缺失时作为默认值 |

`GET` 返回 `{ "allowed_email_domains": [...], "origin": "setting" | "environment" | "unrestricted" }`；`PATCH` 的 body 为 `{ "allowed_email_domains": [...] }`。传 `null`（或省略该字段）表示**删除该配置行**、回退到环境变量；传空数组则是显式写入「不限制」（`origin` 仍为 `setting`）—— 两者都放行所有人，但只有前者能被「取消环境变量」撤销。域列表保存前会规范化（去空白、小写、去重）并校验：空条目、含有 `@`（把地址当域名填）、通配符一律 400 拒绝。

服务端拒绝保存「会把当前操作者自己排除在外」的列表（400，提示把自己的域加回去），避免一次配置改动就把所有人锁在门外；如果保存的名单排除了**其他** admin，会在审计 detail 的 `excluded_admins` 里点名，因为被排除的账号没法告诉任何人自己为什么进不来了。环境变量路径没有这个保护，因此在启动时如果名单排除了全部 admin，会打一条 `warn` 日志。

### 语义：拒绝，而不是禁用

名单外的地址**登不进去、开不了户、同步不落地**，但账号本身**不会被禁用**，数据与历史都保留 —— 缩窄名单是「谁可以进来」的声明，不是「谁已经离开」的声明。这是它与目录同步作用域（`docs/directory-sync.md` §7.2.1）的关键区别，后者掉出范围即 disable。

| 位置 | 名单外的行为 |
|------|--------------|
| 登录（密码 / MFA / passkey / SSO 回调） | 统一在会话签发处拒绝：Unauthorized；SSO 回调重定向带 `error=domain_not_allowed` |
| `POST /api/v1/login` | 凭据先行：未知账号、口令错误与「口令正确但域名不允许」返回**同一句** `invalid email or password`；未知账号同样跑一次 dummy Argon2 对齐耗时；`disabled` / `locked` 只在密码验证通过后提示 |
| 管理端建号 / 改邮箱 | 400 拒绝 |
| SCIM `POST`/`PUT` `/scim/v2/Users` | 400 拒绝（IdP 能直接看到原因） |
| SSO JIT 开户 | 拒绝开户（与上面的登录拒绝同一条路径） |
| 目录同步 | 该条目 `skip`，`reason = email_domain_not_allowed`；**不计入 disable**，也不视为上游消失（见 `docs/directory-sync.md` §7.2.1） |
| 密码重置 | 静默：仍返回 `200 {"ok": true}`，但不发信（不泄露账号是否存在） |
| 首次部署 `/setup` | **不受限制**：否则全新部署连第一个管理员都建不出来 |

每个 SSO provider 还可以配一份自己的 `allowed_email_domains`（§12 管理端 API / Dashboard → Integrations），它只会**进一步收窄**全局名单，不能放宽：provider 名单为空 = 不额外限制。

审计：拒绝登录记 `auth.sign_in_blocked`，拒绝开户记 `user.provision_blocked`（`detail.via` 区分 `password`（含 MFA 挑战）/ `passkey` / `sso` / `sso_jit` / `admin` / `scim`），改配置记 `settings.sign_in_allowlist_update`。
