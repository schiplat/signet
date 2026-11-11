# Signet 集成对接指南（RFC 7591 · Webhooks · SCIM）

本文给出 Signet 三类「机器对机器」集成接口的对接示例：**动态客户端注册（RFC 7591）**、**Webhooks 事件推送（含飞书）**、**SCIM v2 目录同步**。

相关文档：[设计总览](./design.md) · [OIDC 客户端对接](./client-integration.md) · [Dashboard API](./api-v1.md) · [安全设计](./security.md)

| 接口 | 前缀 | 用途 | 鉴权 |
|------|------|------|------|
| OIDC 动态注册 | `/oauth/register` | 业务系统自助登记客户端 | 一次性注册 token（admin 签发） |
| Webhooks | `/api/v1/admin/webhooks` | 审计事件实时推送到外部系统 | admin session（管理）/ 无（投递） |
| SCIM v2 | `/scim/v2/*` | 企业目录（Okta/Entra）同步用户与组 | `Bearer <SIGNET_SCIM_BEARER_TOKEN>` |

> 约定：下文 `$ISSUER` 为 Signet 基址（开发 `http://localhost:8443`，生产 `https://sso.example.com`）。所有 admin 管理端点均需先登录拿 `signet_session` Cookie，示例用 `-b /tmp/signet_cookies.txt` 表示。

---

## 1. OAuth 动态客户端注册（RFC 7591）

让业务系统**自助**登记一个 OAuth 客户端，无需管理员在后台手动建。设计要点：

- 必须持有一个**一次性 initial access token**（由 admin 签发，24 小时有效、用后即焚）。
- 支持放在 `Authorization: Bearer <token>` 头，或放在 JSON body 的 `initial_access_token` 字段。
- 返回的 `client_secret` **只展示这一次**。

### 1.1 签发注册 token（admin）

```bash
curl -s -b /tmp/signet_cookies.txt \
  -X POST "$ISSUER/api/v1/admin/clients/registration-tokens"
```

```json
{ "token": "9fG3...", "expires_at": "2026-08-14T03:00:00Z" }
```

`token` 只返回一次，服务端仅存其 SHA-256 哈希。

### 1.2 用 token 注册客户端

```bash
curl -s -X POST "$ISSUER/oauth/register" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "cella-web",
    "redirect_uris": ["http://localhost:3000/auth/callback"],
    "initial_access_token": "9fG3..."
  }'
```

成功响应（201）：

```json
{
  "client_id": "cl_abc123...",
  "client_secret": "5k...",
  "client_id_issued_at": 1755057600,
  "client_secret_expires_at": 0,
  "redirect_uris": ["http://localhost:3000/auth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

### 1.3 校验规则

| 字段 | 规则 |
|------|------|
| `redirect_uris` | 必填，至少 1 条；必须 `http(s)://` 开头；**不得含 `#` 片段**；去重排序 |
| `scopes` | 可选；若提供必须包含 `openid` |
| `client_name` | 可选展示名 |
| `grant_types` | 当前忽略，固定 `authorization_code` + `refresh_token` |

响应中**不返回** `registration_access_token` / `registration_client_uri`：本服务没有 RFC 7591 的客户端管理端点（`GET/PUT /oauth/register/{client_id}`），返回它们只会让标准客户端去请求一个 404。注册后的客户端在 Dashboard → Clients 管理。

注册出的客户端默认：`pkce_required=true`、`ip_allowlist_enabled=false`（不限制源 IP）。

### 1.4 错误码

| 场景 | 响应 |
|------|------|
| 缺 token | `401 missing initial access token` |
| token 无效/过期/已用过 | `401 invalid or expired registration token` |
| `redirect_uris` 空或非 http(s) | `400` |
| `scopes` 缺 `openid` | `400 scopes must include openid` |

---

## 2. Webhooks 事件推送

每次审计事件落库后，Signet **异步** POST 到所有启用的 webhook。两种投递类型 `kind`：

| kind | 行为 |
|------|------|
| `generic`（默认） | 原始审计 JSON 原样 POST；签名放请求头 `x-signet-signature` |
| `feishu` | 渲染为飞书交互卡片；签名（加签）写入 body |

### 2.1 管理 API（admin）

```bash
# 列表
curl -s -b /tmp/signet_cookies.txt "$ISSUER/api/v1/admin/webhooks"

# 新建（generic）
curl -s -b /tmp/signet_cookies.txt -X POST "$ISSUER/api/v1/admin/webhooks" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.example.com/audit","secret":"my-hmac-secret","kind":"generic"}'

# 新建（飞书）
curl -s -b /tmp/signet_cookies.txt -X POST "$ISSUER/api/v1/admin/webhooks" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://open.feishu.cn/open-apis/bot/v2/hook/xxx","kind":"feishu","secret":"飞书加签secret"}'

# 删除
curl -s -b /tmp/signet_cookies.txt -X DELETE "$ISSUER/api/v1/admin/webhooks/{id}"

# 最近 50 条投递结果
curl -s -b /tmp/signet_cookies.txt "$ISSUER/api/v1/admin/webhooks/{id}/deliveries"
```

创建请求体：`{ "url": string, "secret"?: string, "kind"?: "generic" | "feishu" }`（`kind` 缺省 `generic`；`secret` 缺省不签名/不加签）。

> 管理台「**Integrations**」页提供同样能力的图形界面（含飞书预设与投递状态），推荐日常用 UI。

### 2.2 事件负载（payload）

两类 webhook 都基于同一份审计事件：

```json
{
  "id": "0f0e...",
  "action": "auth.login",
  "resource_type": "user",
  "resource_id": "0f0e...",
  "actor_user_id": "0f0e...",
  "actor_email": "admin@example.com",
  "actor_role": "admin",
  "detail": { "...": "..." },
  "ip": "203.0.113.7",
  "browser": "Chrome",
  "os": "macOS",
  "created_at": "2026-08-13T03:00:00Z"
}
```

### 2.3 generic：签名头

- 头 `x-signet-event`：事件 `id`。
- 头 `x-signet-signature`：`sha256=<hex>`，其中 `<hex> = HMAC-SHA256(key = secret, msg = 请求体原始字节)`。

接收端验签示例（Python）：

```python
import hashlib, hmac

body = request.data
expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
sig = request.headers.get("x-signet-signature")  # "sha256=..."
assert sig == f"sha256={expected}"
```

### 2.4 feishu：卡片 + 加签

**消息体**为飞书交互卡片（`msg_type: interactive`），标题 `Signet · <action>`，正文含操作者/动作/资源/IP/设备/详情，脚注含时间与事件 id。

**加签**（仅当机器人开启「签名校验」且 webhook 填了 `secret` 时）：

```text
sign = Base64( HMAC-SHA256( key = timestamp + "\n" + secret, msg = "" ) )
```

`timestamp`（秒级）与 `sign` 两个字段**写入 body 顶层**（不是请求头）：

```json
{
  "timestamp": "1755057600",
  "sign": "xxxx",
  "msg_type": "interactive",
  "card": { "...": "..." }
}
```

飞书侧校验：`timestamp` 须在请求时刻 ±3600 秒内；算法见[飞书官方文档](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot?lang=zh-CN)。

### 2.5 投递可靠性

- 投递**异步、尽力而为**；失败只记日志 + 写 `webhook_deliveries`，不重试、不阻塞审计写入。
- 单次超时 10 秒；HTTP 2xx 记为 `success=true`。
- 每个 webhook 单独并发投递，互不影响。

---

## 3. SCIM v2 目录同步

Signet 实现 **SCIM 2.0 Server** 侧，供 Okta / Entra ID / HR 系统**供给**用户与组。与 SSO 互补：SCIM 管「账号在不在、角色对不对」，SSO 管「能不能登录」。

### 3.1 启用

SCIM 的 bearer token 可在**管理后台 → Integrations → SCIM v2** 里生成 / 轮换 / 吊销：

- 点击 **Generate token**（或 **Rotate token**）会返回一段新 token，**明文只显示一次**，请立即复制；库里只存哈希，之后无法回看。
- 点击 **Revoke** 立即禁用 SCIM 接口，直到下次生成。

也可以用环境变量作为**一次性种子**（仅在数据库里还没有 token 时生效）：

```text
SIGNET_SCIM_BEARER_TOKEN=change-me-scim-token
```

一旦数据库里存在 token（无论来自 UI 还是 env 种子），env 就不再干预，后续以 UI 轮换为准。未配置 token 时，整个 `/scim/v2/*` 返回 `401 SCIM is not configured`。

所有请求必须带：

```http
Authorization: Bearer <token>
```

### 3.2 端点一览

| 方法/路径 | 说明 |
|-----------|------|
| `GET/POST /scim/v2/Users` | 列表 / 创建用户 |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | 详情 / 替换 / 部分更新 / 删除 |
| `GET/POST /scim/v2/Groups` | 列表 / 创建组 |
| `GET/PATCH/DELETE /scim/v2/Groups/{id}` | 详情 / 更新成员 / 删除组 |
| `GET /scim/v2/ServiceProviderConfig` | 能力声明（供目录系统探测） |

`{id}` 可用 **UUID**、**`externalId`** 或 **email** 三种任一值定位。

### 3.3 字段映射

| SCIM | Signet | 说明 |
|------|--------|------|
| `userName` | `users.email` | 登录名，必须含 `@` |
| `displayName` | `users.display_name` | 展示名 |
| `active` | `users.status` | `true`→`active`，`false`→`disabled` |
| `externalId` | `users.external_id` | 目录侧唯一 ID，幂等关联 |
| `password` | `users.password_hash` | 可选；缺省随机生成 |
| Group `displayName` | `users.groups[]` | 与 OIDC `groups` claim 同源 |

### 3.4 示例

```bash
T="change-me-scim-token"
AUTH="Authorization: Bearer $T"
JSON="Content-Type: application/json"

# 能力声明
curl -s -H "$AUTH" "$ISSUER/scim/v2/ServiceProviderConfig"

# 创建用户
curl -s -X POST "$ISSUER/scim/v2/Users" -H "$AUTH" -H "$JSON" -d '{
  "userName": "alice@example.com",
  "displayName": "Alice",
  "externalId": "emp-001",
  "active": true
}'

# 列表（分页）
curl -s -H "$AUTH" "$ISSUER/scim/v2/Users?startIndex=1&count=50"

# 按 externalId 取
curl -s -H "$AUTH" "$ISSUER/scim/v2/Users/emp-001"

# 禁用（PATCH active=false）
curl -s -X PATCH "$ISSUER/scim/v2/Users/emp-001" -H "$AUTH" -H "$JSON" \
  -d '{"operations":[{"value":{"active":false}}]}'

# 删除（连带清除其会话）
curl -s -X DELETE "$ISSUER/scim/v2/Users/emp-001" -H "$AUTH"

# 创建组
curl -s -X POST "$ISSUER/scim/v2/Groups" -H "$AUTH" -H "$JSON" \
  -d '{"displayName":"engineering","externalId":"grp-001"}'

# 组加成员（member.value 填用户 UUID）
curl -s -X PATCH "$ISSUER/scim/v2/Groups/grp-001" -H "$AUTH" -H "$JSON" \
  -d '{"operations":[{"value":[{"value":"<user-uuid>"}]}]}'
```

### 3.5 实现说明与限制

- 每次操作均写审计（`scim.user.create` / `scim.user.delete` / `scim.group.*` 等），actor 为空。
- 创建的用户角色固定为 `user`（非 admin/manager）；无公开注册。
- **组 PATCH 目前仅支持「增加成员」**（把用户 UUID 加入组），未实现按 `op` 的 remove/replace 语义；删除组会把成员从 `users.groups[]` 移除。
- `bulk`、`filter`、`sort`、`etag`、`changePassword` 等能力在 `ServiceProviderConfig` 中声明为 `supported: false`，目录系统应避免依赖。
- 未配置 token 时整体禁用；token 明文不落库（只存哈希），生成后仅展示一次。

---

## 4. 排错

| 现象 | 原因 |
|------|------|
| 注册返回 `401 missing initial access token` | 未传 token 头/字段 |
| 注册返回 `401 invalid or expired registration token` | token 过期或已被用掉（一次性） |
| webhook 投递无反应 | 看 `webhook_deliveries` 的 `status_code`/`error`；飞书若开了加签而 secret 没填会 93000 系列错误 |
| SCIM 一律 `401 SCIM is not configured` | 尚未生成 token（后台未生成，且无 env 种子） |
| SCIM `401 invalid SCIM bearer token` | `Authorization: Bearer` 值与已配置 token 不一致（或 token 已轮换/吊销） |
| SCIM 建用户 `400 userName already exists` | `users_email_key` 唯一约束命中 |
