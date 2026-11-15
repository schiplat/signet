# Signet client integration guide (OIDC)

> English · [简体中文](./zh-CN/client-integration.md)

For business systems (such as Cella) connecting to Signet SSO. Signet is an
**OIDC Identity Provider**; clients use the standard **Authorization Code + PKCE
(S256)** flow.

Related: [design overview](./design.md) · [MFA](./mfa.md) · [Dashboard API](./api-v1.md) · [Dashboard](./dashboard.md)

> **Runnable reference implementation**: [`examples/axum-oidc-client`](../examples/axum-oidc-client/)
> (Axum; one file covering every requirement here — copy it, change five
> environment variables, and the round trip works). For non-Rust subsystems, see
> the standard-library recipes in its README §4.

> This guide covers **OIDC** (`/oauth/*`). The dashboard JSON API lives under
> **`/api/v1/*`** and is unrelated to business clients.

---

## 1. Environment and issuer

| Environment | Example issuer |
|------|-------------|
| Local development | `http://localhost:8443` (default; the public value can be set under Dashboard → Settings → Server identity, and `SIGNET_ISSUER` is only an optional override) |
| Production example | `https://sso.example.com` |

Client configuration should depend only on the **issuer** and discover the
endpoints, never on hard-coded host assumptions beyond the relative paths.

```http
GET {issuer}/.well-known/openid-configuration
```

Discovery returns (excerpt):

| Field | Value |
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

Liveness: `GET {issuer}/health` → `ok`

---

## 2. Registering a client

### 2.1 Dashboard

An administrator or manager registers / edits under Dashboard → **Clients**:

- `client_id`: a stable identifier (e.g. `cella`)
- `redirect_uris`: an exact-match allowlist (one per line)
- PKCE S256 is **always enforced**: clients have no `pkce_required` switch any
  more, and both the authorization and token endpoints require a 43–128
  character challenge/verifier
- **Source IP allowlist** (on by default): only the listed IPs / CIDRs may reach
  that client's `/oauth/authorize` and `/oauth/token`; it can be turned off. When
  enabled, at least one CIDR/IP is required
- After creation the **client_secret is shown once**, together with a copyable
  integration snippet (`.env` / `config.toml`, with issuer/client/scopes/redirect
  prefilled); Rotate issues a fresh secret and shows it the same way
- **Test drive**: an enabled client gets a one-click round trip through the
  built-in `{issuer}/oauth/test-callback/{client_id}` redirect URI — real
  authorize → sign-in → consent → callback — and the result page lists what
  passed (authentication, scope, redirect match, single-use code). The token
  endpoint with the secret and PKCE verifier is out of scope (the server stores
  only the secret hash), so a real integration is still the final check

A disabled client cannot complete authorization or token exchange.

> Token exchange usually comes from the business backend, so the allowlist should
> include the BFF / business-server egress IPs. Authorize goes through the
> browser, where the source IP is the user's; to restrict only server-side
> exchange, include the user network ranges too, or turn the client's IP
> restriction off temporarily.

### 2.2 Dynamic client registration (RFC 7591)

Besides the dashboard, a subsystem can register itself with a **single-use
initial access token**; see [integrations.md](./integrations.md) §1.

> There is also a pure-web path: any signed-in user can register and manage their
> own client under Dashboard → **My apps** (`/my-apps`) — no administrator
> action and no initial access token needed. The registered client is equivalent
> to dynamic registration (PKCE, authorization_code + refresh_token).

### 2.3 Recommended client shape

**Confidential client with backend code exchange (BFF)**:

- The browser only receives the `code`; it never holds the `client_secret` or a
  long-lived refresh token
- The business backend exchanges the code with the secret, validates the
  `id_token`, and issues **its own session**

Pure-SPA public clients are not supported: the token endpoint requires a
`client_secret`.

---

## 3. Sign-in flow

```text
User visits the business system (not signed in)
  → 302 Signet /oauth/authorize?...
  → without a Signet SSO session: 302 /login?return_to=...
  → user signs in (and completes MFA when policy requires it)
  → Signet 302s back to the business redirect_uri?code=...&state=...
  → business backend: code + code_verifier → /oauth/token
  → validate id_token (iss / aud / exp / signature / nonce)
  → upsert the local user by sub, create the business session
  → enter the application
```

**Boundary**: Signet answers "who you are"; business ACLs and role authority stay
in the business database. Identity from `id_token` / userinfo is for the mapping
key and display only.

If the user has MFA enabled or enforced at Signet, the sign-in page asks for a
TOTP or recovery code; the client changes nothing in the protocol, it only needs
`return_to` to land back on the original `/oauth/authorize`.

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

| Parameter | Requirement |
|------|------|
| `response_type` | Must be `code` |
| `client_id` | Registered and enabled |
| `redirect_uri` | **Exactly** the registered value |
| `scope` | Must include `openid` and be a **subset** of the client's registered scopes (escalation is refused) |
| `state` | **Required** (OIDC Core) against login CSRF; returned unchanged on the callback |
| `nonce` | Recommended; written into the `id_token` |
| `prompt` | Optional: `none` (no UI; an error when not signed in or not authorized), `login` (force re-authentication), `consent` (force re-consent) |
| `code_challenge` | Required |
| `code_challenge_method` | Must be `S256` (`plain` is not supported) |

Success: `303` to `redirect_uri?code=...&state=...`
Not signed in: `303` to `/login?return_to=` (the encoded full authorize URL)

### 4.1 Consent

- On first authorization, or when a remembered grant does not cover every scope
  in this request, the user is sent to `/consent`.
- On that page the **explicitly requested scopes are granted or refused as a
  whole** (not individually); scopes inside the client's allowlist that were not
  requested are offered as **optional** and can be granted individually
  (GitHub-style).
- Optional scopes the user ticks are remembered alongside the request for later
  silent authorization; the **current** callback/exchange reflects only the
  originally requested scopes.
- Users can revoke an app's authorization under **Connected apps** in the account
  menu.

Authorization codes are short-lived (default about **300 seconds**) and
**single-use**.

---

## 5. Token

```http
POST {issuer}/oauth/token
Content-Type: application/x-www-form-urlencoded
```

### 5.1 Client authentication

Either:

1. **Body**: `client_id` + `client_secret` (`client_secret_post`)
2. **Header**: `Authorization: Basic base64(client_id:client_secret)`

### 5.2 authorization_code

```text
grant_type=authorization_code
&code=...
&redirect_uri=...          # same as the authorize request
&client_id=...
&client_secret=...
&code_verifier=...         # the original PKCE verifier
```

### 5.3 refresh_token

```text
grant_type=refresh_token
&refresh_token=...
&client_id=...
&client_secret=...
```

Refresh **rotates**: the old refresh token is invalidated immediately and the
response carries a new one.

### 5.4 Success response

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

| Token | Default TTL | Notes |
|-------|----------|------|
| `access_token` | 3600s | JWT; carries `token_use=access`; used for userinfo |
| `id_token` | 3600s | JWT RS256; the identity assertion |
| `refresh_token` | 30 days | Opaque; rotated on use |

---

## 6. Validating the id_token

1. Fetch the public keys from `{issuer}/oauth/jwks` (cache and follow `kid`
   rotation)
2. Algorithm **RS256**
3. Verify:
   - `iss` equals the configured issuer (no trailing slash)
   - `aud` equals this app's `client_id`
   - `exp` / `iat` (watch clock skew)
   - if authorize carried a `nonce`, it must match
4. Use **`sub`** as the stable user key (a UUID string); never use email as a
   unique key (an administrator can change it)

`id_token` claims (current implementation):

| Claim | Notes |
|-------|------|
| `sub` | Stable subject |
| `iss` / `aud` / `exp` / `iat` | Standard |
| `nonce` | Optional |
| `email` | The user's email (**only when authorize requested the `email` scope**) |
| `name` | Display name (**only when `profile` was requested**) |
| `phone_number` | Contact number (**only when `phone` was requested**) |
| `groups` | User groups (**only when `groups` was requested**) |

> **Scope trimming**: both `id_token` and userinfo trim claims by the granted
> scopes — a scope that was not requested produces no claim. Make sure the
> authorize request includes the scopes the app actually needs
> (`openid profile email phone groups`).

The business system should issue **its own session**; do not use a Signet
access token as a long-lived business API session.

---

## 7. UserInfo (optional)

```http
GET {issuer}/oauth/userinfo
Authorization: Bearer {access_token}
```

Example response (with `openid profile email groups phone` in `scope`):

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

Only an access JWT with `token_use=access` is accepted. Claims are trimmed by the
`scope` inside the access token: `sub` is always present; `email` needs the
`email` scope; `name` / `preferred_username` need `profile`; `phone_number` /
`phone_number_verified` need `phone`; `groups` needs `groups`.

Users can view and **revoke** an app's authorization under **Connected apps** in
the account menu; revoking also kills that app's refresh tokens, so the next
sign-in asks for consent again.

---

## 8. Logout

### 8.1 Two kinds of logout

1. **Clearing the local business session** is enough for most cases; the Signet
   session survives, so the next sign-in is silent (SSO).
2. For **global unified logout**, use **RP-Initiated Logout** (OIDC
   RP-Initiated Logout 1.0):

```http
GET  {issuer}/oauth/end_session?id_token_hint={id_token}&post_logout_redirect_uri={uri}&state=...
POST {issuer}/oauth/end_session            (form: client_id/post_logout_redirect_uri/state)
```

- **GET must carry `id_token_hint`** (an id_token from a sign-in): a top-level GET
  navigation sends the Lax session cookie, and without a signed hint there is no
  way to tell "the user clicked logout" from "a link on an attacker's page". The
  hint's signature, `iss`/`exp` are checked, and its `sub` must match the current
  session; `client_id` may be omitted, in which case the hint's `aud` is used
- **POST needs no hint**: a cross-site form POST cannot send the Lax cookie, so
  the CSRF surface is already closed. A frontend without the id_token can
  auto-submit a form
- Signet clears the `signet_session`
- A redirect happens only when `post_logout_redirect_uri` is registered in the
  client's `post_logout_redirect_uris` allowlist; `state` is passed through. When
  both the request's `client_id` and the hint's `aud` are present they must match
- Users can also revoke a single device's session under **Active sessions** in
  the account menu

### 8.2 The full path

```text
User clicks "Log out"
  → the business backend clears its local session
  → the browser goes to Signet /oauth/end_session?client_id=...&post_logout_redirect_uri=...
  → Signet clears the SSO session
  → Signet checks post_logout_redirect_uri against the allowlist
      ├─ match → 302 back to that address (state may be included)
      └─ no match → 302 to the Signet home page (/)
```

### 8.3 Two configurations, both required

In RP-Initiated Logout, `post_logout_redirect_uri` is a **client-initiated**
parameter; the IdP only **validates** it. The two roles are different and neither
replaces the other:

| Side | Setting | Role | Meaning |
|------|--------|------|------|
| Signet (IdP) | the client's `post_logout_redirect_uris` allowlist | **validator** (passive) | "which addresses may we redirect back to after logout" |
| Business system (RP) | `OIDC_POST_LOGOUT_REDIRECT_URI` | **initiator** (active) | "where do I want to return after logout" |

- **The initiator must send it**: without `post_logout_redirect_uri`, Signet has
  nothing to validate and falls back to `/`.
- **The validator must register it**: Signet only redirects to allowlisted
  addresses. Unregistered (empty or NULL) or values that are not **exactly**
  equal (trailing slash, http/https, port, path) fall back to the Signet home
  page.
- **Both sides must match character by character**: if the business configures
  `http://localhost:8080/signed-out`, the Signet allowlist must contain the same
  string.

### 8.4 What happens when Signet is not configured (or the values differ)

Signet is **fail-closed** on the redirect:

```text
end_session?post_logout_redirect_uri={unregistered/mismatched value}
  → validation fails → 302 to the Signet home page /
  → the route guard sees no session → 302 /login?return_to=...
  → the user sees the Signet sign-in page
```

That is: **no open-redirect vulnerability** (stricter is safer), but the user
cannot return to the business system — "logging out bounces back to the IdP
sign-in page".

### 8.5 Clients need a public landing page

If **every route** in the business system requires a session, the post-logout
redirect is immediately bounced back to the Signet sign-in page (an endless
loop). Provide a public "signed out" landing page (e.g. `/signed-out`) and point
`OIDC_POST_LOGOUT_REDIRECT_URI` at it, so logout has a clear destination.

---

## 9. Business-side checklist

- [ ] Configure `OIDC_ISSUER` / `CLIENT_ID` / `CLIENT_SECRET` / `REDIRECT_URI` / `SCOPES`
- [ ] For unified logout: configure `OIDC_POST_LOGOUT_REDIRECT_URI` (business side)
      **and** register the **same value** in the Signet client allowlist
- [ ] Generate the PKCE `code_verifier` / `code_challenge` (S256) and `state` /
      `nonce`
- [ ] Redirect unauthenticated users to authorize; validate `state` on the
      callback
- [ ] Exchange the code on the backend; validate the `id_token`
- [ ] Map local users uniquely by `sub`; keep permission tables on the business
      side
- [ ] Authorise APIs against the business session; expose a public `/health`
- [ ] HTTPS in production; synchronised clocks; the secret never enters a
      frontend repository

### Example client settings

| Setting | Development example |
|--------|----------|
| `OIDC_ISSUER` | `http://localhost:8443` |
| `OIDC_CLIENT_ID` | The `client_id` registered in the dashboard / dynamic registration |
| `OIDC_CLIENT_SECRET` | The secret issued once when the client was created |
| `OIDC_REDIRECT_URI` | The exact callback registered in Signet |
| `OIDC_SCOPES` | `openid profile email` |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | Unified-logout return address (optional; the same value must be registered in the client allowlist) |

---

## 10. Errors and troubleshooting

| Symptom | Likely cause |
|------|----------|
| `redirect_uri not allowed` | The URI is not exactly the registered one (trailing slash, http vs https) |
| `scope not allowed for this client` | A scope the client did not register (e.g. requesting `email` when only `openid` was registered) |
| `missing state` | Authorize did not include `state` (OIDC requires it) |
| `code_challenge_method must be S256` | `plain` was used, or it was omitted |
| `invalid code_verifier` | The verifier does not match the challenge, or the encoding is wrong |
| `invalid client credentials` | Wrong secret, or the client is disabled |
| `client IP not allowed` | The Source IP allowlist is on and the current source is not listed (proxy headers included) |
| `code expired` / `already used` | Timeout, or the code was exchanged twice |
| Still returns to sign-in after authorize | No SSO session was created (password/MFA unfinished) or a cookie domain / `SameSite` problem |
| id_token signature failure | Issuer mismatch, wrong JWKS, or clock skew |

Quick local checks:

```bash
curl -sS "$ISSUER/.well-known/openid-configuration" | jq .
curl -sS "$ISSUER/oauth/jwks" | jq .
curl -sS "$ISSUER/health"
```

---

## 10.5 Machine-to-machine (M2M) and introspection

### Client credentials

Tick `client_credentials` when creating/editing a client under Dashboard →
Clients, and it can exchange its own credentials for a token:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$ISSUER/oauth/token" \
  -d 'grant_type=client_credentials&scope=openid'
```

- No user, no `refresh_token`, no `id_token`; `sub` is the `client_id`.
- `scope` narrows to the client's registered list: requests may only be a
  subset; anything beyond returns `400 invalid_scope`.
- Only for system-to-system calls. The token carries no user identity, so the
  business side must treat `sub == client_id` as a service identity and never as
  a user.

### Token introspection (RFC 7662)

For resource servers that do not want to verify JWTs locally, or that need
**revocation to be visible immediately**:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$ISSUER/oauth/introspect" \
  -d "token=$ACCESS_TOKEN"
# {"active":true,"sub":"...","client_id":"...","scope":"...",
#  "token_use":"access","exp":...,"iat":...,"iss":"..."}
```

`active=false` covers: invalid signature, expired, **user disabled or deleted**,
client disabled. That is the semantics local JWT verification cannot provide — a
password change or a frozen account invalidates old access tokens on the next
introspection. An unknown token returns `{"active":false}` rather than an error
(§2.2).

### Step-up authentication

When a sensitive operation requires "recently re-authenticated", add
`max_age=<seconds>` to authorize:

- A session older than that is destroyed and the user must sign in again;
- Combined with `prompt=none` → `error=login_required`, so a silent renewal gives
  up;
- `max_age=0` → always requires a fresh sign-in.

The `id_token`'s `auth_time` is the actual authentication time, so the RP can
apply its own rule (e.g. the admin area requires `auth_time` within 5 minutes
while the frontend only requires a sign-in).

### Client-defined claims

**Extra claims** (a JSON object) under Dashboard → Clients merge into that
client's `id_token`, `access_token` and `/oauth/userinfo`:

```json
{ "team": "infra", "employee_id": "$username" }
```

`$sub` / `$email` / `$username` / `$display_name` / `$phone` resolve per user;
when a value cannot be resolved the **issuance is aborted** (no token with a
missing claim is produced, so the RP never silently receives an empty value).
M2M tokens have no user, so only literals remain.

### Back-channel logout

The **Back-channel logout URL** on the client edit page. When a user's session is
terminated (logout, `end_session`, admin force sign-out, password change or email
change), Signet POSTs:

```
logout_token=<signed JWT>
```

JWT claims: `iss` / `aud` (= that client) / `sub` (the user) / `iat` / `exp`
(120 seconds) / `jti` / `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`.

The RP verifies the signature and `iss`, checks that `aud` is itself, and clears
its local session by `sub`; no browser redirect is needed. Delivery is
best-effort (no retry), so RPs should pair it with a short access-token TTL or
introspection.

---

## 11. Not provided today (clients must not depend on it)

- Token exchange for public clients without a `client_secret`
- WeCom / DingTalk connectors

## 12. Related endpoints

- RFC 7009 revocation: `POST /oauth/revoke` (see [integrations](./integrations.md) or [api-v1.md](./api-v1.md))
- Dynamic registration RFC 7591 / webhooks / SCIM v2: see the [integrations guide](./integrations.md)
