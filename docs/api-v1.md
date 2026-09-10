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
| `POST` | `/api/v1/admin/users/{id}/mfa/reset` | **admin**：重置他人 MFA |

---

## 3. 管理：用户

需 staff（admin / manager）；删除与部分操作仅 admin。

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/users` | 列表（含 `mfa_required` / `totp_enabled` / `groups` / `phone` / `provisioned_via` / `has_password` / `sso_identities`） |
| `GET` | `/api/v1/admin/users/email-check?email=` | 邮箱查重，返回 `{ "exists": bool }` |
| `GET` | `/api/v1/admin/users/phone-check?phone=&exclude_id=` | 手机查重，返回 `{ "exists": bool }`（`exclude_id` 可选，编辑时排除自身） |
| `POST` | `/api/v1/admin/users` | 创建（可带 `groups`、`phone`） |
| `PUT` | `/api/v1/admin/users/{id}` | 更新（含 `mfa_required`、status、role、`groups`、`phone`…） |
| `DELETE` | `/api/v1/admin/users/{id}` | **admin** 删除 |
| `POST` | `/api/v1/admin/users/{id}/disable` | 冻结 |
| `POST` | `/api/v1/admin/users/{id}/enable` | 解冻 |
| `POST` | `/api/v1/admin/users/batch-disable` | 批量冻结 `{ "ids": [] }` |
| `POST` | `/api/v1/admin/users/{id}/sessions/revoke` | 强制下线该用户全部会话 |

`groups` 为用户组（`TEXT[]`），会作为 `groups` claim 下发到 `id_token` 与 `/oauth/userinfo`，供业务侧做初始角色映射（不替代业务 ACL）。`phone` 为可选的明文联系电话（`TEXT`，空即不填）。创建/更新邮箱时后端会显式查重，重复返回 `400 "email already exists"`；手机同理（非空时唯一，重复返回 `400 "phone already exists"`，DB 有部分唯一索引 `users_phone_key`）。

列表额外字段：`provisioned_via`（如 `sso_jit` 表示第三方 JIT 开户，否则 `null`）、`has_password`、`sso_identities`（`[{ provider_code, display_name, provider_type }]`，已绑定的第三方）。

> `phone` 当前仅作**联系信息**，未做短信验证绑定；验证绑定（SMS OTP）为规划项，见 [design.md](./design.md) Phase 4。

---

## 4. 管理：Clients

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/v1/admin/clients` | 列表 |
| `POST` | `/api/v1/admin/clients` | 注册（secret 仅返回一次） |
| `PUT` | `/api/v1/admin/clients/{id}` | 更新 redirect / PKCE / **IP 白名单** |
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
| `/metrics` | Prometheus 指标（公开） |

### 审计保留策略

启动时清理 `created_at` 早于 `SIGNET_AUDIT_RETENTION_DAYS`（默认 180）天的审计记录。管理台查询与导出不受影响。

### OIDC 附加端点

- `GET/POST /oauth/consent`：同意页提交（`allow` 为 `true`/`false`）。显式请求的 scope 在 `allow` 时整体授予；客户端允许列表内未请求的 scope 作为可选，由用户在授权页勾选，经 body `optional_scopes`（空格分隔）提交。允许则写 `oauth_consents` 并回跳 authorize（回跳只带原本请求的 scope）。
- `GET/POST /oauth/end_session`：统一登出；`post_logout_redirect_uri` 须在该客户端的白名单内才回跳。
- `POST /oauth/revoke`：RFC 7009 吊销端点。表单字段 `token`、可选 `token_type_hint`；客户端须以 Basic 或 `client_id`+`client_secret` 认证。仅吊销 refresh token（access token 为无状态 JWT，无法服务端吊销）。无论 token 是否存在均返回 200。
- `POST /oauth/register`：RFC 7591 动态客户端注册。需 `Authorization: Bearer <token>` 或表单 `initial_access_token`（单次使用，由管理员签发）。返回 `client_id`/`client_secret`。

> **scope 裁剪**：`id_token` 与 `/oauth/userinfo` 均按已授权 scope 下发 claim——`email` 需 `email` scope、`name` 需 `profile` scope、`phone_number` 需 `phone` scope、`groups` 需 `groups` scope，`sub` 恒有。

## 7. 密码重置

| 方法/路径 | 说明 |
|-----------|------|
| `POST /api/v1/password-reset/request` | body `{ email }`；生成 30 分钟有效的重置 token，发送重置链接（当前为日志型邮件，接入 SMTP 后真实投递）。无论邮箱是否存在均返回 `{ ok: true }` |
| `POST /api/v1/password-reset/confirm` | body `{ token, new_password }`；校验 token、应用密码策略、吊销全部会话 |

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
| `GET /api/v1/auth/sso/{provider}/start?client_id=` | 生成 CSRF state（HttpOnly cookie 存明文、库中仅存 SHA-256，一次性，10 分钟），302 到上游授权页 |
| `GET /api/v1/auth/sso/{provider}/callback` | 校验 state → 换 token → 拉取归一化 profile → 绑定判定 → 签发会话或暂存待绑定（`auth.login.thirdparty` 审计） |
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

失败时回调重定向回登录页并带 `?sso_error=`：`unknown_provider` / `provider_disabled` / `state_mismatch` / `upstream_error` / `missing_code` / `no_matching_account`。

### 管理端 API（admin）

| 方法/路径 | 说明 |
|-----------|------|
| `GET /api/v1/admin/sso/providers` | 列表（含 `bindings`、每条记录的具体 `callback_url`；`client_secret` 永不回传） |
| `POST /api/v1/admin/sso/providers` | 创建（`code` `[a-zA-Z0-9_-]`，`oidc` 必填 `issuer_url`） |
| `PUT /api/v1/admin/sso/providers/{code}` | 更新；`client_secret` 留空保持不变，传入即轮换 |
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
| `GET /metrics` | Prometheus 文本格式；新增 HTTP 请求计数（按状态类）、在途请求、延迟直方图，以及既有登录/token/MFA 计数 |

全局速率限制：对 `/api/v1`、`/oauth/*` 等按客户端 IP 限流，默认 `SIGNET_RATE_LIMIT_PER_MINUTE=300`，超限返回 429。

链路追踪：所有响应回显 `x-request-id`（透传请求头或生成 UUID），并写入 tracing span，访问日志按 `request_id` 关联。

旧路径 `/api/...`（无 `v1`）已废弃，不再提供 JSON API。
