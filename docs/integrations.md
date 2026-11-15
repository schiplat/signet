# Signet integrations guide (RFC 7591 · Webhooks · SCIM)

> English · [简体中文](./zh-CN/integrations.md)

Three machine-to-machine integration surfaces with worked examples: **dynamic
client registration (RFC 7591)**, **webhook event delivery (including Feishu)**
and **SCIM v2 directory sync**.

Related: [design overview](./design.md) · [OIDC client integration](./client-integration.md) · [Dashboard API](./api-v1.md) · [Security design](./security.md)

| Interface | Prefix | Purpose | Authentication |
|------|------|------|------|
| OIDC dynamic registration | `/oauth/register` | Let a subsystem register a client itself | Single-use registration token (issued by an admin) |
| Webhooks | `/api/v1/admin/webhooks` | Push audit events to external systems in real time | Admin session (manage) / none (delivery) |
| SCIM v2 | `/scim/v2/*` | Enterprise directory (Okta/Entra) user and group sync | `Bearer <SIGNET_SCIM_BEARER_TOKEN>` |

> Convention: `$ISSUER` below is the Signet base URL (development
> `http://localhost:8443`, production `https://sso.example.com`). Every admin
> endpoint needs a signed-in `signet_session` cookie; the examples pass
> `-b /tmp/signet_cookies.txt`.

---

## 1. OAuth dynamic client registration (RFC 7591)

Lets a subsystem **register an OAuth client by itself**, without an administrator
creating it in the dashboard. Design points:

- It must present a **single-use initial access token** (issued by an admin, valid
  for 24 hours, consumed on use).
- The token may be sent as `Authorization: Bearer <token>` or as the
  `initial_access_token` field in the JSON body.
- The returned `client_secret` is **shown exactly once**.

### 1.1 Issue a registration token (admin)

```bash
curl -s -b /tmp/signet_cookies.txt \
  -X POST "$ISSUER/api/v1/admin/clients/registration-tokens"
```

```json
{ "token": "sgn_reg_9fG3...", "expires_at": "2026-08-14T03:00:00Z" }
```

`token` is returned once; the server stores only its SHA-256 hash.

### 1.2 Register a client with the token

```bash
curl -s -X POST "$ISSUER/oauth/register" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "cella-web",
    "redirect_uris": ["http://localhost:3000/auth/callback"],
    "initial_access_token": "sgn_reg_9fG3..."
  }'
```

Success (201):

```json
{
  "client_id": "sgn_cl_abc123...",
  "client_secret": "sgn_cs_5kQ...",
  "client_id_issued_at": 1755057600,
  "client_secret_expires_at": 0,
  "redirect_uris": ["http://localhost:3000/auth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

### 1.3 Validation rules

| Field | Rule |
|------|------|
| `redirect_uris` | Required, at least one; must start with `http(s)://`; **no `#` fragment**; deduplicated and sorted |
| `scopes` / `scope` | Optional; when present must include `openid`. `scopes` (array) is this service's native shape; the RFC 7591 space-separated `scope` string is accepted too, and `scopes` wins when both are present |
| `client_name` | Optional display name |
| `grant_types` | Ignored today: `authorization_code` + `refresh_token` are always written; **the stored grant list is enforced at authorize and token** |

The response deliberately **omits** `registration_access_token` /
`registration_client_uri`: this service has no RFC 7591 client-management
endpoints (`GET/PUT /oauth/register/{client_id}`), so returning them would send a
conformant client to a 404. Manage registered clients under Dashboard → Clients.

Defaults for a registered client: `ip_allowlist_enabled=false` (no source-IP
restriction), scopes `openid profile email`. PKCE S256 is enforced for every
client unconditionally (no switch).

### 1.4 Error codes

| Case | Response |
|------|------|
| Missing token | `401 missing initial access token` |
| Invalid / expired / used token | `401 invalid or expired registration token` |
| `redirect_uris` empty or non-http(s) | `400` |
| `scopes` without `openid` | `400 scopes must include openid` |

---

## 2. Webhook event delivery

After each audit event is stored, Signet **asynchronously** POSTs it to every
enabled webhook. Two delivery `kind`s:

| kind | Behaviour |
|------|------|
| `generic` (default) | The raw audit JSON is POSTed as-is; the signature goes in the `x-signet-signature` header |
| `feishu` | Rendered as a Feishu interactive card; the signature (`timestamp`/`sign`) is written into the body |

### 2.1 Admin API

```bash
# List
curl -s -b /tmp/signet_cookies.txt "$ISSUER/api/v1/admin/webhooks"

# Create (generic)
curl -s -b /tmp/signet_cookies.txt -X POST "$ISSUER/api/v1/admin/webhooks" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.example.com/audit","secret":"my-hmac-secret","kind":"generic"}'

# Create (Feishu)
curl -s -b /tmp/signet_cookies.txt -X POST "$ISSUER/api/v1/admin/webhooks" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://open.feishu.cn/open-apis/bot/v2/hook/xxx","kind":"feishu","secret":"<feishu-signing-secret>"}'

# Delete
curl -s -b /tmp/signet_cookies.txt -X DELETE "$ISSUER/api/v1/admin/webhooks/{id}"

# The most recent 50 delivery results
curl -s -b /tmp/signet_cookies.txt "$ISSUER/api/v1/admin/webhooks/{id}/deliveries"
```

Create body: `{ "url": string, "secret"?: string, "kind"?: "generic" | "feishu" }`
(`kind` defaults to `generic`; without `secret` nothing is signed).

> The dashboard's **Integrations** page offers the same capabilities with a UI
> (Feishu preset and delivery status included) — prefer it for daily use.

### 2.2 Event payload

Both webhook kinds share one audit event:

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

### 2.3 generic: the signature header

- Header `x-signet-event`: the event `id`.
- Header `x-signet-signature`: `sha256=<hex>` where
  `<hex> = HMAC-SHA256(key = secret, msg = raw request bytes)`.

Receiver-side verification (Python):

```python
import hashlib, hmac

body = request.data
expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
sig = request.headers.get("x-signet-signature")  # "sha256=..."
assert hmac.compare_digest(sig, f"sha256={expected}")
```

### 2.4 feishu: card plus signing

**Body** is a Feishu interactive card (`msg_type: interactive`) titled
`Signet · <action>`, listing actor/action/resource/IP/device/detail, with time and
event id in the footer.

**Signing** (only when the bot enables signature verification and the webhook has
a `secret`):

```text
sign = Base64( HMAC-SHA256( key = timestamp + "\n" + secret, msg = "" ) )
```

`timestamp` (seconds) and `sign` are written **at the top level of the body**,
not as headers:

```json
{
  "timestamp": "1755057600",
  "sign": "xxxx",
  "msg_type": "interactive",
  "card": { "...": "..." }
}
```

Feishu validates that `timestamp` is within ±3600 seconds of the request; see the
[Feishu documentation](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot).

### 2.5 Delivery reliability

- Delivery is **asynchronous and best-effort**: a failure is logged and recorded in
  `webhook_deliveries`; there is no retry and the audit write is never blocked.
- Each attempt times out after 10 seconds; an HTTP 2xx is stored as
  `success=true`.
- Every webhook is delivered concurrently and independently.

---

## 3. SCIM v2 directory sync

Signet implements the **SCIM 2.0 server** side, letting Okta / Entra ID / HR
systems **provision** users and groups. It complements SSO: SCIM decides "does
the account exist and is the role right", SSO decides "may this person sign in".

### 3.1 Enabling

The SCIM bearer token is generated / rotated / revoked under **Dashboard →
Integrations → SCIM v2**:

- **Generate token** (or **Rotate token**) returns a new token. The **plaintext
  is shown once** — copy it immediately; only the hash is stored and it cannot be
  retrieved later.
- **Revoke** disables the SCIM API at once, until the next generation.

An environment variable can act as a **one-time seed** (only while the database
has no token):

```text
SIGNET_SCIM_BEARER_TOKEN=change-me-scim-token
```

Once a token exists in the database (from the UI or the env seed), the variable
is ignored and rotation happens in the UI. With no token configured, the whole
`/scim/v2/*` surface returns `401 SCIM is not configured`.

Every request must carry:

```http
Authorization: Bearer <token>
```

### 3.2 Endpoints

| Method / path | Notes |
|-----------|------|
| `GET/POST /scim/v2/Users` | List / create users |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | Read / replace / patch / delete |
| `GET/POST /scim/v2/Groups` | List / create groups |
| `GET/PATCH/DELETE /scim/v2/Groups/{id}` | Read / update members / delete |
| `GET /scim/v2/ServiceProviderConfig` | Capability declaration (for the directory to probe) |

`{id}` may be a **UUID**, an **`externalId`** or an **email** address.

### 3.3 Field mapping

| SCIM | Signet | Notes |
|------|--------|------|
| `userName` | `users.email` | Login name; must contain `@` |
| `displayName` | `users.display_name` | Display name |
| `active` | `users.status` | `true` → `active`, `false` → `disabled` |
| `externalId` | `users.external_id` | The directory's stable id; used for idempotent matching |
| `password` | `users.password_hash` | Optional; a random one is generated when absent |
| Group `displayName` | `users.groups[]` | Same source as the OIDC `groups` claim |

> In a SCIM User resource, `groups[].value` is the **Group resource's `id`**
> (`display` carries the name). A local group with no SCIM counterpart does not
> appear in that list.

### 3.4 Examples

```bash
T="change-me-scim-token"
AUTH="Authorization: Bearer $T"
JSON="Content-Type: application/json"

# Capability declaration
curl -s -H "$AUTH" "$ISSUER/scim/v2/ServiceProviderConfig"

# Create a user
curl -s -X POST "$ISSUER/scim/v2/Users" -H "$AUTH" -H "$JSON" -d '{
  "userName": "alice@example.com",
  "displayName": "Alice",
  "externalId": "emp-001",
  "active": true
}'

# List (paged)
curl -s -H "$AUTH" "$ISSUER/scim/v2/Users?startIndex=1&count=50"

# Read by externalId
curl -s -H "$AUTH" "$ISSUER/scim/v2/Users/emp-001"

# Disable (PATCH active=false)
curl -s -X PATCH "$ISSUER/scim/v2/Users/emp-001" -H "$AUTH" -H "$JSON" \
  -d '{"operations":[{"value":{"active":false}}]}'

# Delete (clears the user's sessions too)
curl -s -X DELETE "$ISSUER/scim/v2/Users/emp-001" -H "$AUTH"

# Create a group
curl -s -X POST "$ISSUER/scim/v2/Groups" -H "$AUTH" -H "$JSON" \
  -d '{"displayName":"engineering","externalId":"grp-001"}'

# Add a member (member.value is the user's UUID)
curl -s -X PATCH "$ISSUER/scim/v2/Groups/grp-001" -H "$AUTH" -H "$JSON" \
  -d '{"operations":[{"value":[{"value":"<user-uuid>"}]}]}'
```

### 3.5 Implementation notes and limits

- Every operation is audited (`scim.user.create` / `scim.user.delete` /
  `scim.group.*`, …); the actor is empty (a machine credential).
- Created users are always `member` (not admin/manager); there is no public
  registration.
- **Group PATCH currently supports adding members only** (appending a user UUID);
  the `op`-based remove/replace semantics are not implemented. Deleting a group
  removes its members from `users.groups[]`.
- `bulk`, `filter`, `sort`, `etag` and `changePassword` are declared
  `supported: false` in `ServiceProviderConfig`. A request that still sends
  `filter` gets **400** rather than silently receiving the whole directory.
- With no token the whole surface is disabled; the plaintext token never reaches
  the database (hash only) and is shown once.

---

## 4. Troubleshooting

| Symptom | Cause |
|------|------|
| Registration returns `401 missing initial access token` | No token header or field |
| Registration returns `401 invalid or expired registration token` | The token expired or was already used (single-use) |
| Webhook deliveries do nothing | Inspect `webhook_deliveries.status_code` / `error`; a Feishu bot with signing enabled but no `secret` returns a 93000-series error |
| SCIM always returns `401 SCIM is not configured` | No token has been generated yet (neither in the UI nor via the env seed) |
| SCIM returns `401 invalid SCIM bearer token` | The `Authorization: Bearer` value does not match the configured token (or it was rotated/revoked) |
| SCIM user creation returns `400 userName already exists` | The `users_email_key` unique constraint fired |
