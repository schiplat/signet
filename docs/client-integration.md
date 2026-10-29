# Signet 客户端对接指南（OIDC）

面向要接入 Signet SSO 的业务系统（如 Cella）。Signet 作为 **OIDC Identity Provider**，客户端走标准 **Authorization Code + PKCE (S256)**。

相关文档：[设计总览](./design.md) · [MFA](./mfa.md) · [Dashboard API](./api-v1.md) · [管理台](./dashboard.md)

> **可运行的参考实现**：[`examples/axum-oidc-client`](../examples/axum-oidc-client/)（Axum，一个文件覆盖本指南全部要求，复制改 5 个环境变量即可跑通）。非 Rust 子系统参见其 README §4 的标准库配方表。

> 本文描述 **OIDC**（`/oauth/*`）。Signet 管理台 JSON API 在 **`/api/v1/*`**，与业务客户端无关。

---

## 1. 环境与 Issuer

| 环境 | Issuer 示例 |
|------|-------------|
| 本地开发 | `http://localhost:8443`（`SIGNET_ISSUER`） |
| 生产（未来） | `https://sso.example.com` |

客户端配置应只依赖 **Issuer**，通过 Discovery 发现端点，勿写死相对路径以外的主机假设。

```http
GET {issuer}/.well-known/openid-configuration
```

Discovery 返回（节选）：

| 字段 | 值 |
|------|-----|
| `authorization_endpoint` | `{issuer}/oauth/authorize` |
| `token_endpoint` | `{issuer}/oauth/token` |
| `userinfo_endpoint` | `{issuer}/oauth/userinfo` |
| `jwks_uri` | `{issuer}/oauth/jwks` |
| `response_types_supported` | `code` |
| `code_challenge_methods_supported` | `S256` |
| `grant_types_supported` | `authorization_code`, `refresh_token` |
| `id_token_signing_alg_values_supported` | `RS256` |
| `scopes_supported` | `openid`, `profile`, `email`, `phone`, `groups` |
| `token_endpoint_auth_methods_supported` | `client_secret_post`, `client_secret_basic` |

探活：`GET {issuer}/health` → `ok`

---

## 2. 注册客户端

### 2.1 管理后台

管理员 / 经理在 Dashboard → **Clients** 注册 / 编辑：

- `client_id`：稳定标识（如 `cella`）
- `redirect_uris`：精确匹配白名单（一行一个）
- `pkce_required`：默认开启（当前授权端点**始终要求** PKCE S256）
- **Source IP allowlist**（默认开启）：仅允许列出的 IP / CIDR 访问该客户端的 `/oauth/authorize` 与 `/oauth/token`；可关闭为不限制。开启时必须至少配置一条 CIDR/IP。
- 创建后 **client_secret 只展示一次**，同时展示可直接复制给子系统的**对接配置片段**（`.env` / `config.toml` 两种形态，issuer/client/scopes/redirect 全部预填）；可 Rotate（轮换后同样展示）
- **Test drive**：Clients 列表对已启用客户端提供一键联调——用系统自带的 `{issuer}/oauth/test-callback/{client_id}` 回调地址走真实 authorize → 登录 → consent → 回调，结果页展示通过项（认证、scope、redirect 匹配、一次性 code）。token 端点 + secret + PKCE verifier 不在覆盖范围（服务端只存 secret 哈希），需真实集成验证

禁用客户端后无法完成授权 / 换票。

> 换票通常来自业务后端，白名单应包含 BFF / 业务服务器出口 IP。Authorize 经浏览器时，源 IP 为用户侧；若仅希望限制服务端换票，仍需把用户网段一并列入，或临时关闭该客户端的 IP 限制。

### 2.2 动态客户端注册（RFC 7591）

除管理后台外，业务系统也可通过**一次性初始访问 token** 自助登记客户端，见 [integrations.md](./integrations.md) §1。

### 2.3 推荐客户端形态

**机密客户端 + 后端换票（BFF）**：

- 浏览器只拿 `code`，不持有 `client_secret` / 长期 refresh
- 业务服务端用 secret 调 `/oauth/token`，校验 `id_token` 后签发**本系统会话**

纯 SPA 公共客户端暂非首期重点；当前 token 端点仍要求 `client_secret`。

---

## 3. 登录流程

```text
用户访问业务系统（未登录）
  → 302 Signet /oauth/authorize?...
  → 若无 Signet SSO 会话：302 /login?return_to=...
  → 用户登录（及 MFA，若策略要求）
  → Signet 302 回业务 redirect_uri?code=...&state=...
  → 业务后端：code + code_verifier → /oauth/token
  → 校验 id_token（iss / aud / exp / 签名 / nonce）
  → 按 sub upsert 本地用户，建立业务会话
  → 进入业务页
```

**边界**：Signet 负责「你是谁」；业务 ACL / 角色权威仍在业务库。`id_token` / userinfo 中的身份仅作映射主键与展示信息。

若用户在 Signet 已开 MFA 或被强制 MFA，登录页会要求 TOTP / 恢复码；客户端无需改协议，只需保证 `return_to` 能回到原 `/oauth/authorize`。

---

## 4. Authorize

```http
GET {issuer}/oauth/authorize
  ?response_type=code
  &client_id={client_id}
  &redirect_uri={exact_registered_uri}
  &scope=openid%20profile%20email
  &state={csrf_opaque}
  &nonce={oidc_nonce}
  &code_challenge={BASE64URL(SHA256(verifier))}
  &code_challenge_method=S256
```

| 参数 | 要求 |
|------|------|
| `response_type` | 必须 `code` |
| `client_id` | 已注册且 enabled |
| `redirect_uri` | 与登记值**完全一致** |
| `scope` | 必须包含 `openid`，且必须是该客户端登记 scopes 的**子集**（越权 scope 会被拒绝） |
| `state` | **必填**（OIDC Core），防登录 CSRF；回调原样带回 |
| `nonce` | 建议；写入 `id_token` |
| `prompt` | 可选：`none`（不得显示任何 UI，未登录/未授权返回错误）、`login`（强制重新登录）、`consent`（强制重新授权） |
| `code_challenge` | 必填 |
| `code_challenge_method` | 必须 `S256`（不支持 `plain`） |

成功：`303` 到 `redirect_uri?code=...&state=...`  
未登录：`303` 到 `/login?return_to=`（编码后的完整 authorize URL）

### 4.1 Consent（同意）

- 首次授权，或此前已记住的授权不足以覆盖本次请求的全部 scope 时，跳转 `/consent`。
- 授权页中，**显式请求的 scope 整体允许/拒绝**（不可拆分）；客户端允许列表内、但本次未显式请求的 scope 作为**可选**，用户可勾选单独授予（GitHub 式）。
- 已勾选的可选 scope 会与请求 scope 一并记住，供后续隐式授权复用；但**本次**回调/换票只反映原本请求的 scope。
- 用户可在 Signet 账户菜单「Connected apps」撤销对某应用的授权。

授权码短时有效（默认约 **300 秒**），**一次性**。

---

## 5. Token

```http
POST {issuer}/oauth/token
Content-Type: application/x-www-form-urlencoded
```

### 5.1 客户端认证

任选其一：

1. **Body**：`client_id` + `client_secret`（`client_secret_post`）
2. **Header**：`Authorization: Basic base64(client_id:client_secret)`

### 5.2 authorization_code

```text
grant_type=authorization_code
&code=...
&redirect_uri=...          # 与 authorize 时相同
&client_id=...
&client_secret=...
&code_verifier=...         # 原始 PKCE verifier
```

### 5.3 refresh_token

```text
grant_type=refresh_token
&refresh_token=...
&client_id=...
&client_secret=...
```

Refresh **旋转**：旧 refresh 立即作废，响应带新 refresh。

### 5.4 成功响应

```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque>",
  "id_token": "<jwt>",
  "scope": "openid profile email"
}
```

| Token | 默认 TTL | 说明 |
|-------|----------|------|
| `access_token` | 3600s | JWT；含 `token_use=access`；用于 userinfo |
| `id_token` | 3600s | JWT RS256；身份断言 |
| `refresh_token` | 30 天 | 不透明；旋转发放 |

---

## 6. 校验 id_token

1. 从 `{issuer}/oauth/jwks` 取公钥（缓存并按 `kid` 轮换）
2. 算法 **RS256**
3. 校验：
   - `iss` == 配置的 Issuer（无尾斜杠）
   - `aud` == 本应用 `client_id`
   - `exp` / `iat`（注意时钟同步）
   - 若 authorize 带了 `nonce`，则 `nonce` 必须一致
4. 以 **`sub`** 作为稳定用户主键（UUID 字符串），勿用 email 作唯一键（email 可被管理员修改）

`id_token` claims（当前实现）：

| Claim | 说明 |
|-------|------|
| `sub` | 稳定主体 |
| `iss` / `aud` / `exp` / `iat` | 标准 |
| `nonce` | 可选 |
| `email` | 用户邮箱（**仅当 authorize 请求了 `email` scope**） |
| `name` | 展示名（**仅当请求了 `profile` scope**） |
| `phone_number` | 联系电话（**仅当请求了 `phone` scope**） |
| `groups` | 用户组（**仅当请求了 `groups` scope**） |

> **scope 裁剪**：`id_token` 与 userinfo 均按已授权的 scope 裁剪 claim——没请求的 scope 就不会下发对应 claim。请确保在 authorize 请求里带上业务实际需要的 scope（`openid profile email phone groups`）。

业务系统应签发**自己的会话**；不要把 Signet access_token 当作业务 API 长期会话。

---

## 7. UserInfo（可选）

```http
GET {issuer}/oauth/userinfo
Authorization: Bearer {access_token}
```

响应示例（`scope` 含 `openid profile email groups phone` 时）：

```json
{
  "sub": "...",
  "email": "user@example.com",
  "name": "Display Name",
  "preferred_username": "user@example.com",
  "phone_number": "+15550001111",
  "phone_number_verified": false,
  "groups": ["eng", "ops"]
}
```

仅接受 `token_use=access` 的 access JWT。claims 按 access token 内的 `scope` 裁剪：`sub` 恒有；`email` 需 `email` scope；`name` / `preferred_username` 需 `profile` scope；`phone_number` / `phone_number_verified` 需 `phone` scope；`groups` 需 `groups` scope。

用户可在 Signet 账户菜单「Connected apps」查看并**撤销**对某应用的授权；撤销后该应用的 refresh token 也会被吊销，下次登录需重新同意。

---

## 8. 登出

### 8.1 两种登出

1. **仅清除业务本地会话**即可满足多数场景；Signet 会话仍在，下次登录可免重新认证（SSO 单点）。
2. 需要**全局统一登出**时，走 **RP-Initiated Logout**（OIDC RP-Initiated Logout 1.0）：

```http
GET {issuer}/oauth/end_session?client_id=cella&post_logout_redirect_uri={uri}&state=...
```

- Signet 清除 `signet_session` 会话
- 仅当 `post_logout_redirect_uri` 登记在该客户端的 `post_logout_redirect_uris` 白名单内才回跳，可带 `state`
- 用户也可在 Signet 账户菜单「Active sessions」自行撤销单设备会话

### 8.2 完整链路

```text
用户点「登出」
  → 业务后端清除本地会话
  → 浏览器跳转 Signet /oauth/end_session?client_id=...&post_logout_redirect_uri=...
  → Signet 清除 SSO 会话
  → Signet 校验 post_logout_redirect_uri 是否在白名单内
      ├─ 命中 → 302 回跳该地址（可带 state）
      └─ 未命中 → 302 到 Signet 首页（/）
```

### 8.3 两个配置，缺一不可

RP-Initiated Logout 里 `post_logout_redirect_uri` 是**客户端主动发起**的参数，IdP 只负责**校验**，两者职责不同，不能互相替代：

| 位置 | 配置项 | 角色 | 语义 |
|------|--------|------|------|
| Signet（IdP） | 客户端 `post_logout_redirect_uris` 白名单 | **校验方**（被动） | 「允许登出后回跳到哪些地址」 |
| 业务系统（RP） | `OIDC_POST_LOGOUT_REDIRECT_URI` | **发起方**（主动） | 「我登出后想回哪里」 |

- **发起方必须传**：客户端不传 `post_logout_redirect_uri`，Signet 就没有可校验的地址，只能 fallback 到 `/`。
- **校验方必须登记**：Signet 只回跳白名单内的地址。未登记（空数组/NULL）或**与发起值不完全一致**（含尾斜杠、http/https、端口、路径）都会回退到 Signet 首页。
- **两边必须逐字符一致**：例如业务侧配 `http://localhost:8080/signed-out`，Signet 白名单也必须是同一个字符串。

### 8.4 Signet 端不配（或值不一致）的后果

Signet 对回跳是 **fail-closed**：

```text
end_session?post_logout_redirect_uri={未登记/不一致的值}
  → 校验失败 → 302 到 Signet 首页 /
  → 首页路由守卫发现未登录 → 302 /login?return_to=...
  → 用户看到的是 Signet 登录页
```

即：**不会产生开放重定向漏洞**（安全性更严格），但登出后无法回到业务系统，表现为「登出后又弹回 IdP 登录页」。

### 8.5 客户端需提供 public 落地页

业务系统若**所有路由都要求登录**，登出回跳后会被自身路由守卫再次踢回 Signet 登录页（循环体验）。建议提供一个 public 的「已退出登录」落地页（如 `/signed-out`），并把它设为 `OIDC_POST_LOGOUT_REDIRECT_URI`，让登出有一个明确的终点。

---

## 9. 业务侧清单

- [ ] 配置 `OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` / `REDIRECT_URI` / `SCOPES`
- [ ] 需要统一登出时：配置 `OIDC_POST_LOGOUT_REDIRECT_URI`（业务侧），并在 Signet 客户端白名单登记**同一值**
- [ ] 生成 PKCE `code_verifier` / `code_challenge`（S256）与 `state` / `nonce`
- [ ] 未登录跳转 authorize；回调校验 `state`
- [ ] 后端换票；校验 `id_token`
- [ ] 本地用户表以 `sub` 唯一映射；权限表在业务侧
- [ ] API 鉴权看业务会话；公开 `/health`
- [ ] 生产 HTTPS；时钟同步；secret 不进前端仓库

### 客户端示例配置名

| 配置项 | 开发示例 |
|--------|----------|
| `OIDC_ISSUER` | `http://localhost:8443` |
| `OIDC_CLIENT_ID` | 在 Signet 后台 / 动态注册中登记的 `client_id` |
| `OIDC_CLIENT_SECRET` | 创建客户端时一次性下发的 secret |
| `OIDC_REDIRECT_URI` | 在 Signet 登记的精确回调地址 |
| `OIDC_SCOPES` | `openid profile email` |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | 统一登出回跳地址（可选；须在 Signet 客户端白名单登记同一值） |

---

## 10. 错误与排错

| 现象 | 常见原因 |
|------|----------|
| `redirect_uri not allowed` | URI 与 Clients 登记不完全一致（含尾斜杠 / http·https） |
| `scope not allowed for this client` | 请求了该客户端未登记的 scope（如只登记了 `openid` 却请求 `email`） |
| `missing state` | authorize 未携带 `state`（OIDC 要求必填） |
| `code_challenge_method must be S256` | 用了 `plain` 或未传 |
| `invalid code_verifier` | verifier 与 challenge 不匹配或编码错误 |
| `invalid client credentials` | secret 错误或客户端已 disable |
| `client IP not allowed` | 启用了 Source IP 白名单且当前源 IP 不在列表（含代理头） |
| `code expired` / `already used` | 超时或重复换票 |
| authorize 后仍回登录 | SSO 会话未建立（密码/MFA 未完成）或 Cookie 域 / `SameSite` 问题 |
| id_token 验签失败 | Issuer 配置不一致、拿错 JWKS、时钟偏差 |

本地快速自检：

```bash
curl -sS "$ISSUER/.well-known/openid-configuration" | jq .
curl -sS "$ISSUER/oauth/jwks" | jq .
curl -sS "$ISSUER/health"
```

---

## 11. 当前未提供（客户端勿依赖）

- 无 `client_secret` 的公共客户端换票  
- 企业微信 / 钉钉等外部 IdP 联邦（Phase 3）

## 12. 相关接口

- RFC 7009 吊销：`POST /oauth/revoke`（见[集成对接](./integrations.md)或 [api-v1.md](./api-v1.md)）
- 动态注册 RFC 7591 / Webhooks / SCIM v2：见[集成对接指南](./integrations.md)
