# Signet 安全设计

本文汇总 Signet 的安全机制与实现现状，作为 [design.md](./design.md) 安全要求的展开。

| 项 | 内容 |
|---|---|
| 状态 | 标注 ✅（已实现）/ ⏳（规划中） |
| 相关文档 | [design.md](./design.md) · [api-v1.md](./api-v1.md) · [mfa.md](./mfa.md) · [client-integration.md](./client-integration.md) · [integrations.md](./integrations.md) |

---

## 1. 凭证与密钥存储

**原则：任何可验证的凭证都只存哈希/密文，不存明文。**

| 数据 | 存储位置 | 方式 | 状态 |
|------|---------|------|------|
| 用户密码 | `users.password_hash` | Argon2（随机盐） | ✅ |
| 密码历史 | `password_history.password_hash` | Argon2 | ✅ |
| MFA 恢复码 | `totp_recovery_codes.code_hash` | Argon2（规范化后哈希） | ✅ |
| OAuth 客户端密钥 | `client_apps.client_secret_hash` | Argon2 | ✅ |
| 会话 token | `sessions.token_hash` | SHA-256 | ✅ |
| 授权码 | `auth_codes.code_hash` | SHA-256 | ✅ |
| Refresh token | `refresh_tokens.token_hash` | SHA-256 | ✅ |
| MFA 挑战 token | `mfa_challenges.token_hash` | SHA-256 | ✅ |
| **TOTP 密钥** | `users.totp_secret` | **AES-256-GCM 应用层加密** | ✅ |

### 1.1 TOTP 密钥应用层加密

`totp_secret` 是验证 TOTP 所必需的**可逆共享密钥**，无法像密码一样只做单向哈希，因此使用**应用层加密**而非明文落库：

- 算法：AES-256-GCM，每次加密生成随机 96-bit nonce，`nonce ‖ ciphertext` base64 后落库。
- 密钥：`data/encryption.key`（32 字节 hex），首次启动自动生成；可用 `SIGNET_ENCRYPTION_KEY_PATH` 覆盖。
- 实现：`crates/signet/src/encryption.rs`（`Encryptor`）。
- 读写点：enroll / rebind 写入时加密；verify / regenerate / rebind 读取时解密。
- **向后兼容**：解密失败时按明文回退，旧明文行无需迁移，下次换绑/重绑自动转为密文。
- 密钥与 JWT 私钥同等敏感，生产环境应纳入备份与权限管控。

> ⚠️ 历史数据迁移：已存在的明文 `totp_secret` 不会主动批量重加密（避免影响在线用户），会在下一次换绑/重绑时自然轮换为密文。如需强制全量迁移，可在维护窗口执行一次性脚本遍历 `users.totp_secret` 重新加密。

---

## 2. 认证安全

### 2.1 登录防爆破 ✅

- 连续密码错误达 `SIGNET_MAX_LOGIN_ATTEMPTS`（默认 5）后锁定账号 `SIGNET_LOCKOUT_MINUTES`（默认 15）分钟。
- 字段：`users.failed_login_attempts`、`users.locked_until`。
- 失败写审计 `auth.login_failed`；锁定期间返回明确提示。
- 登录成功即清零计数。

### 2.2 密码策略 ✅

- 最小长度 `SIGNET_PASSWORD_MIN_LENGTH`（默认 10）。
- 复杂度：必须包含大写、小写字母与数字。
- 历史复用：新密码不得与最近 `SIGNET_PASSWORD_HISTORY_SIZE`（默认 3）次历史相同。
- 实现：`crates/signet/src/password.rs`（`set_user_password` 统一校验）。

### 2.3 邮箱 / 手机唯一性与查重 ✅

- `users.email` 有数据库唯一约束（`users_email_key`）；`users.phone` 有部分唯一索引（`users_phone_key`，仅非空值）。
- 创建/更新用户时后端**显式查重**，重复分别返回 `400 email already exists` / `400 phone already exists`。
- 前端新建/编辑表单对邮箱与手机做防抖实时查重（`email-check` / `phone-check`），命中即提示并禁用提交。
- 自助 profile 编辑（`PATCH /api/v1/me`）支持 `phone`，同样查重（排除自身）。

> ⏳ **手机号绑定验证（规划，暂未实现）**：当前 `phone` 仅作**未验证的联系信息**落库。完整绑定需经短信验证码（SMS OTP）验证后标记为「已验证」，才可用于找回密码/账号恢复/短信登录等敏感场景。需短信网关（如阿里云短信）与发送限流/防重放设计；详情见 [design.md](./design.md) Phase 4。

### 2.4 登录审计 ✅

- 成功/失败登录均写审计，记录客户端 IP（`X-Forwarded-For` → `X-Real-IP` → peer 兜底）与浏览器/OS（由 `User-Agent` 解析，见 §6）。

### 2.5 密码重置 ✅

- `POST /api/v1/password-reset/request` 生成 30 分钟有效、单次使用的重置 token（SHA-256 哈希落库）。
- 链接经邮件发送（当前为日志型 mailer，接入 SMTP 后真实投递）；无论邮箱是否存在均返回成功，防枚举。
- `POST /api/v1/password-reset/confirm` 校验 token、应用密码策略、消费 token 并吊销全部会话。

### 2.6 WebAuthn / Passkey ✅

- 无密码、抗钓鱼的第二因素；passkey 公钥以 `webauthn-rs` `Passkey` JSON 落库，登录成功后更新签名计数器。
- 注册（`/api/v1/me/passkeys/*`）需已登录；登录（`/api/v1/passkeys/*`）成功后建立会话并写 `auth.login`（`mfa: passkey`）。
- 挑战状态存服务端内存（单实例、5 分钟有效、单次使用）。

### 2.7 新设备/IP 登录告警 ✅

- 首次出现的（用户, IP）会写 `auth.new_device` 审计并发送告警邮件（日志型 mailer）。
- 登录源记录在 `login_devices` 表，用于后续异常检测。

---

## 3. 会话管理 ✅

| 能力 | 说明 |
|------|------|
| 会话记录 | `sessions` 表记录 `ip`、`user_agent`、`last_seen_at` |
| 单点撤销 | 用户可撤销自己的指定会话（`/api/v1/me/sessions/{id}`） |
| 撤销其他 | 撤销除当前外的所有会话 |
| 管理员强制下线 | `POST /api/v1/admin/users/{id}/sessions/revoke` 下线该用户全部会话 |
| 统一登出 | OIDC `end_session`（`/oauth/end_session`），`post_logout_redirect_uri` 走客户端白名单 |
| 冻结联动 | 用户被冻结/删除时自动清除其会话 |

会话 Cookie：HttpOnly、SameSite=Lax、可配 Secure（`SIGNET_COOKIE_SECURE`）。

---

## 4. MFA（TOTP + 恢复码）✅

详见 [mfa.md](./mfa.md)。安全要点：

- TOTP 密钥应用层加密（§1.1）。
- 恢复码一次性、Argon2 哈希存储、仅发放时明文展示一次。
- 全局 / 用户级强制开关；管理员可重置他人 MFA。
- 非强制时用户可自主禁用 MFA（需验证当前 TOTP）；全局或用户级强制时不可禁用。
- 恢复码页提供 Copy / Download；Download 生成 `signet-recovery-codes.txt`。

---

## 5. OIDC / OAuth 安全

| 机制 | 状态 |
|------|------|
| Authorization Code + **PKCE S256** | ✅ |
| `redirect_uri` **精确白名单**（防开放重定向） | ✅ |
| `state` **强制必填**（防登录 CSRF） | ✅ |
| `nonce` 防重放 | ✅ |
| **scope 白名单**：请求 scope 必须是客户端登记 scopes 的子集（防越权取 claim） | ✅ |
| **prompt 参数**：`none` / `login` / `consent`（防静默授权） | ✅ |
| 未认证时**不加载 client**（避免枚举 client 是否存在/是否启用） | ✅ |
| 授权/consent 回跳统一 **303**（避免缓存/方法转换） | ✅ |
| Token 短 TTL（access/id 1h，auth code 5min） | ✅ |
| Refresh token **轮换**（每次刷新旧 token 作废） | ✅ |
| RFC 7009 独立吊销端点 `/oauth/revoke` | ✅ |
| RFC 7591 动态客户端注册 `/oauth/register`（需一次性注册 token） | ✅ |
| 客户端 Source IP 白名单（新建默认开启） | ✅ |
| OIDC Consent（首次授权同意 + 记住） | ✅ |
| Consent 可选 scope 授权：请求 scope 整体允许/拒绝，客户端允许列表内未请求的 scope 可勾选单独授予（GitHub 式） | ✅ |
| Consent 用户侧撤销（`/me/consents`，连带吊销 refresh token） | ✅ |
| `groups` claim 下发（id_token / userinfo，按 scope 裁剪） | ✅ |
| `phone` scope 下发 `phone_number` / `phone_number_verified`（按 scope 裁剪） | ✅ |
| `end_session` 统一登出 | ✅ |

客户端密钥 Argon2 哈希存储；授权码/refresh 均 SHA-256 哈希存储。

---

## 6. 审计与可观测

### 6.1 审计 ✅

- 记录：actor（email/role）、action、resource、detail JSON、**IP**、**user_agent / browser / os**、时间。
- 浏览器/OS 由 `User-Agent` 轻量解析（`crates/signet/src/ua.rs`），覆盖 Chrome/Safari/Firefox/Edge/Opera 与 Windows/macOS/Linux/Android/iOS/ChromeOS。
- 删除类事件（`user.delete` / `client.delete` 等）仅 admin 可见；manager 受 action 白名单限制。
- 审计记录**不可删除**（UI 无删除入口）。
- CSV 导出尊重权限过滤；点击行可查看完整详情（含 detail JSON）。

### 6.2 保留策略 ✅

- 启动时清理早于 `SIGNET_AUDIT_RETENTION_DAYS`（默认 180）天的记录。

### 6.3 可观测 ✅

- `/metrics`（公开，Prometheus 文本格式）暴露：
  - 业务计数：登录/登录失败、token 签发、MFA 校验（成功/失败）。
  - HTTP：请求计数（按状态类 2xx/3xx/4xx/5xx）、在途请求、延迟直方图。
- `/health` 就绪探测：探测 Postgres（`SELECT 1`），失败返回 503，供负载均衡/K8s 使用。
- 全局速率限制：按客户端 IP 限流（`SIGNET_RATE_LIMIT_PER_MINUTE`，默认 300），超限返回 429。
- **链路追踪（`x-request-id`）**：请求头透传/生成 UUID，回显到响应头，并写入 tracing span，访问日志与业务日志按 `request_id` 关联。

### 6.4 Webhooks 事件推送 ✅

- 每条审计事件写入后异步 POST 到所有启用的 webhook，投递结果写入 `webhook_deliveries`。
- 两种类型：`generic`（原始 JSON + `x-signet-signature` HMAC 头）与 `feishu`（飞书卡片 + 加签 `timestamp`/`sign` 写入 body）。
- 管理台「Integrations」页可增删 webhook 并查看最近投递状态。

### 6.5 SCIM v2 ✅

- `/scim/v2/Users`、`/scim/v2/Groups` 提供企业目录（Okta/Entra 等）用户与组同步，Bearer token 认证。
- Token 在管理台「Integrations → SCIM v2」生成/轮换/吊销；明文仅展示一次，库中只存哈希（`sha256`）。`SIGNET_SCIM_BEARER_TOKEN` 仅作首次启动的种子。

---

## 7. 密钥与配置

| 配置项 | 默认 | 说明 |
|--------|------|------|
| `SIGNET_JWT_PRIVATE_KEY_PATH` | `./data/jwt_private.pem` | RS256 私钥，首启生成 |
| `SIGNET_ENCRYPTION_KEY_PATH` | `./data/encryption.key` | AES-256-GCM 密钥，首启生成 |
| `SIGNET_COOKIE_SECURE` | `false` | 生产应置 `true` |
| `SIGNET_MAX_LOGIN_ATTEMPTS` | `5` | 登录锁定阈值 |
| `SIGNET_LOCKOUT_MINUTES` | `15` | 锁定时长 |
| `SIGNET_PASSWORD_MIN_LENGTH` | `10` | 密码最小长度 |
| `SIGNET_PASSWORD_HISTORY_SIZE` | `3` | 密码历史复用检查数 |
| `SIGNET_AUDIT_RETENTION_DAYS` | `180` | 审计保留天数 |
| `SIGNET_RATE_LIMIT_PER_MINUTE` | `300` | 每 IP 每分钟请求上限 |
| `SIGNET_PUBLIC_BASE_URL` | — | 邮件/重置链接的公开基址 |
| `SIGNET_SMTP_HOST` / `_PORT` | — | SMTP 服务器（配置后真实投递邮件） |
| `SIGNET_EMAIL_FROM` | — | 邮件发件人 |
| `SIGNET_SCIM_BEARER_TOKEN` | — | SCIM API 认证 token（可选，仅作首次启动种子；后续由后台 UI 管理） |
| `SIGNET_WEBAUTHN_RP_ID` / `_ORIGIN` | 自动 | 依赖方 ID/来源（生产须为真实域名） |

生产容器将 volume `signet_data` 挂到 `/app/data`（JWT / 加密密钥）；`build/` 与 `deploy/` 的 compose 分工见 [deploy.md](./deploy.md)。

---

## 8. 规划中的安全增强

| 优先级 | 功能 | 说明 |
|--------|------|------|
| P0 | 手机号短信验证绑定 | 短信网关；当前 `phone` 未验证（见 §2.3），为唯一未实施的高优先级项 |
| P2 | 告警对接 | 基于 Prometheus 指标接入 Alertmanager |
