# Signet HTTP API (`/api/v1`)

> English · [简体中文](./zh-CN/api-v1.md)

Dashboard and session-management endpoints live under **`/api/v1/...`**.
OIDC protocol endpoints stay at `/oauth/*` and
`/.well-known/openid-configuration` (see [client-integration.md](./client-integration.md)).
Dynamic registration / webhooks / SCIM examples: [integrations.md](./integrations.md).

Authentication: the browser cookie `signet_session` (HttpOnly). An unauthenticated
call returns `401`; insufficient permission returns `403`.

Error body (JSON):

```json
{ "error": "message" }
```

---

## 1. Authentication and the current user

| Method | Path | Notes |
|------|------|------|
| `POST` | `/api/v1/login` | Password sign-in; may return an MFA branch. With CAPTCHA configured, send `captcha_token` (see `GET /api/v1/captcha`) |
| `GET` | `/api/v1/captcha` | **Public**: the challenge descriptor for the sign-in/reset forms `{"enabled","provider","site_key"}`; `{"enabled": false}` when off; the secret never appears |
| `POST` | `/api/v1/logout` | Sign out |
| `GET` | `/api/v1/me` | The current user |
| `PATCH` | `/api/v1/me` | Update `display_name` / `phone` (phone uniqueness excludes self) |
| `POST` | `/api/v1/me/password` | Change password (complexity + history) |
| `GET` | `/api/v1/me/sessions` | The current user's active sessions |
| `DELETE` | `/api/v1/me/sessions/{id}` | Revoke one session (not the current one) |
| `POST` | `/api/v1/me/sessions` | Revoke every session except the current one |
| `GET` | `/api/v1/me/consents` | Applications the current user has authorized (OAuth consent records) |
| `DELETE` | `/api/v1/me/consents/{client_id}` | Revoke one app's authorization (and its refresh tokens) |
| `GET` | `/api/v1/me/activity` | The current user's own activity (sign-ins + account/security actions), paged by `?page=&page_size=`, with a `summary` (last sign-in / active sessions / 2FA·passkey / authorized apps) |

### Self-service client registration (any signed-in user, GitHub Developer-settings style)

Ownership lives in `client_apps.owner_id`: every operation's SQL is scoped to
`owner_id = current user`, and a miss is a plain 404 (no existence leak). Defaults
match RFC 7591 (`authorization_code` + `refresh_token`, PKCE, no IP allowlist).
Credentials carry the Signet prefix so logs/configs/scanners can recognise them:
`client_id` looks like `sgn_cl_…`, `client_secret` like `sgn_cs_…` (single-use
registration tokens are `sgn_reg_…`). `client_secret` appears only in the
create/rotate response. Administrators keep global visibility and control at
`/api/v1/admin/clients` (`AdminClient` carries `client_name`).

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/me/clients` | Applications owned by the current user |
| `POST` | `/api/v1/me/clients` | Register an app: `{client_name, redirect_uris, scopes?}` (name required, ≤200 chars; scopes default `openid profile email`) → `{client, client_secret}` |
| `PUT` | `/api/v1/me/clients/{id}` | Only `client_name` / `redirect_uris` may change (absent fields keep their value) |
| `POST` | `/api/v1/me/clients/{id}/rotate-secret` | Rotate the secret → `{client, client_secret}` (the old one stops working immediately) |
| `DELETE` | `/api/v1/me/clients/{id}` | Delete the app (cascades that client's consents and tokens) |

### First-deployment setup (create the administrator on first sign-in)

With no active `admin` user, the first visit redirects to `/setup` to create the
first administrator in the browser (replacing the old environment-variable
creation at startup).

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/setup/status` | Public: `{ "needs_setup": true/false }` (whether an active admin exists) |
| `POST` | `/api/v1/setup` | Public: create the first admin and sign in. Body `{ "email", "password", "display_name"? }`; returns `409` when an admin already exists |

- A successful `POST /api/v1/setup` issues a session (`signet_session` cookie) and
  returns `{ "status": "ok", "user": ... }`.
- Password validation matches normal users (length + case + digit, see
  `SIGNET_PASSWORD_MIN_LENGTH`).
- Concurrency is protected by a Postgres advisory lock, so exactly one admin is
  created.

### `POST /api/v1/login`

Request: `{ "email", "password" }`

One of:

| `status` | Meaning |
|----------|------|
| `ok` | Session issued; includes `user` |
| `mfa_required` | Call MFA verify next (cookie: `signet_mfa`) |
| `enroll_required` | Forced TOTP enrollment |

A successful sign-in writes `auth.login` and records the **client IP**
(`X-Forwarded-For` / `X-Real-IP` / the direct peer).

### Brute-force protection and password policy

- After `SIGNET_MAX_LOGIN_ATTEMPTS` consecutive wrong passwords (default 5) the
  account locks for `SIGNET_LOCKOUT_MINUTES` (default 15); failures write
  `auth.login_failed`.
- Strength: `SIGNET_PASSWORD_MIN_LENGTH` (default 10) plus upper/lower case and a
  digit.
- History: a new password may not match the most recent
  `SIGNET_PASSWORD_HISTORY_SIZE` (default 3).
- All of these can be overridden through environment variables; see
  `.env.example`.

---

## 2. MFA

See [mfa.md](./mfa.md).

| Method | Path | Notes |
|------|------|------|
| `POST` | `/api/v1/mfa/verify` | Login challenge: TOTP / recovery code |
| `POST` | `/api/v1/mfa/enroll/start` | Forced enrollment: generate a secret + otpauth |
| `POST` | `/api/v1/mfa/enroll/confirm` | Forced enrollment confirmation; returns `recovery_codes` |
| `GET` | `/api/v1/me/mfa` | Signed in: MFA status |
| `POST` | `/api/v1/me/mfa/enroll/start\|confirm` | Optional enrollment |
| `POST` | `/api/v1/me/mfa/recovery/regenerate` | Rotate recovery codes (needs the current TOTP) |
| `POST` | `/api/v1/me/mfa/rebind/start\|confirm` | Rebind |
| `POST` | `/api/v1/me/mfa/disable` | Self-service disable (needs the current TOTP, body `{ code }`; returns 400 while globally or per-user enforced) |
| `GET/PATCH` | `/api/v1/admin/settings/mfa` | **admin**: the global enforcement switch |
| `GET/PATCH` | `/api/v1/admin/settings/sso` | **admin**: SSO JIT provisioning `{ "jit_provision": bool }` |
| `GET/PATCH` | `/api/v1/admin/settings/sign-in` | **admin**: the sign-in allowlist (email domains), see §14 |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/runtime` | **admin**: runtime policy (token/session lifetimes, lockout, password policy, audit retention, rate limit); precedence **DB > environment > default**; DELETE clears the override |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/smtp` | **admin**: the SMTP relay (host/port/username/password/from), **DB > environment**, effective immediately. PATCH is tri-state per field: omitted = unchanged, `null` = clear the override and fall back to the environment, a value = set. The password is write-only (GET reports `password_set`; the stored value is encrypted with the application key; `from` is validated as a mailbox). Audits `settings.smtp_update` / `settings.smtp_reset` (never the password) |
| `POST` | `/api/v1/admin/settings/smtp/test` | **admin**: send a test message through the effective relay `{ "to": "…" }`; returns `{ ok, error? }`, surfacing transport errors verbatim (the point of the endpoint) |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/captcha` | **admin**: CAPTCHA (Turnstile/hCaptcha) on sign-in/reset, **DB > environment**; PATCH is tri-state like SMTP; `secret_key` is write-only (encrypted); enabled only when provider/site_key/secret are all present — a half-configured row means off. Audits `settings.captcha_update` / `settings.captcha_reset` |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/server` | **admin**: the issuer (the basis of `iss`, discovery and every client config). Precedence **DB > `SIGNET_ISSUER` > default**: a saved value wins, and the variable only seeds it before the first save. PATCH `{issuer?, allow_repeat_changes?}`: the issuer must be a bare origin (http/https + host + optional port, no path/query/fragment); **the first save locks it**, and changing it again needs `allow_repeat_changes = true` first (the unlock is audited separately). **DELETE** (Reset override) clears `server.issuer` and the repeat switch, falling back to the variable/default, audited as `settings.issuer_reset`. A save applies immediately in this process; peer replicas converge within 30 s. Changing the issuer invalidates outstanding tokens and requires clients plus third-party SSO callbacks to be updated. Audits `settings.issuer_update` / `settings.issuer_repeat_policy` |
| `GET/PATCH/DELETE` | `/api/v1/admin/settings/branding` | **admin**: the product name (sign-in/setup/sidebar/tab title), **DB > `SIGNET_BRAND_NAME` > "Signet"**, applied immediately; 1–64 plain-text characters (control characters refused). DELETE clears the logo too. Audits `settings.branding_update` / `settings.branding_reset` |
| `POST/DELETE` | `/api/v1/admin/settings/branding/logo` | **admin**: upload/remove the logo. POST `{"data_url":"data:image/png;base64,…"}`, PNG/JPEG/WebP only (**SVG refused**, to prevent same-origin script execution), magic-byte checked, ≤256 KiB; returns `{logo_set, logo_url}`. Audits `settings.branding_logo_update` / `settings.branding_logo_remove` |
| `GET` | `/api/v1/branding` | **Public**: `{"name": …, "logo_url": …}`; the sign-in/reset/setup/consent pages read the name and logo without authentication |
| `GET` | `/api/v1/branding/logo` | **Public**: the logo image (404 when unset); the versioned query parameter comes with `Cache-Control: immutable` + `nosniff` |
| `GET/POST` | `/api/v1/admin/tokens` | **admin**: machine credentials (PAT) list / create. Create `{ "name", "expires_in_days"? }` returns `{"id","token":"sgn_pat_… (once)"}`; callers send it as `Authorization: Bearer` to any admin endpoint in this table (no session cookie). The token carries no permissions of its own: every call re-checks the **owner's current** role/status/must_change_password, so a demotion, freeze or password change kills it. The audit actor is the owner |
| `DELETE` | `/api/v1/admin/tokens/{id}` | **admin**: revoke (immediate) |
| `POST` | `/api/v1/admin/users/{id}/mfa/reset` | **admin**: reset another user's MFA |

---

## 3. Administration: users

Staff (admin / manager); deletion and some operations are admin-only.

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/admin/users` | Paged list. Returns `{ users, total, limit, offset }`; rows carry `mfa_required` / `totp_enabled` / `groups` / `phone` / `provisioned_via` / `has_password` / `sso_identities` / `directory_sources` / `scim_managed`. Optional `group_id=<uuid\|ungrouped>` returns that group's members (`ungrouped` = both arrays empty); `include_descendants=true` recurses into child departments/groups |
| `GET` | `/api/v1/admin/users/email-check?email=` | Email uniqueness: `{ "exists": bool }` |
| `GET` | `/api/v1/admin/users/phone-check?phone=&exclude_id=` | Phone uniqueness: `{ "exists": bool }` (`exclude_id` excludes self when editing) |
| `POST` | `/api/v1/admin/users` | Create (may include `groups`, `phone`) |
| `PUT` | `/api/v1/admin/users/{id}` | Update (including `mfa_required`, status, role, `groups`, `phone`, …) |
| `DELETE` | `/api/v1/admin/users/{id}` | **admin** delete |
| `POST` | `/api/v1/admin/users/{id}/disable` | Freeze |
| `POST` | `/api/v1/admin/users/{id}/enable` | Unfreeze |
| `POST` | `/api/v1/admin/users/batch-disable` | Batch freeze `{ "ids": [] }` |
| `POST` | `/api/v1/admin/users/import` | **admin** bulk import `{ users: [...], update?: bool, dry_run?: bool }`, ≤1000 rows; per-row validation, row errors do not abort the batch; `update=true` updates existing profiles (**never passwords**); `dry_run=true` validates everything and returns the same classification as a real run (plus `dry_run: true`), **writing nothing and auditing nothing** (response carries `created/updated/skipped/errors`); a real import audits `user.create` per row plus one `user.import` summary |
| `GET` | `/api/v1/admin/users/export` | **staff** user CSV (email/username/display name/role/status/groups/phone, formula-neutralised); supports the same `group_id` / `include_descendants` filters as the list |
| `POST` | `/api/v1/admin/users/{id}/sessions/revoke` | Force all of that user's sessions out |

In the API, `groups` remains an **array of group names** (writes resolve them to
internal ids through `signet_group_ids()`; an unknown name creates a `local`
group, and reads resolve back through `signet_group_names()`). The array is
published as the `groups` claim in `id_token` and `/oauth/userinfo` (direct
membership only, no ancestor inheritance) as starting data for business role
mapping (not a replacement for business ACLs). `phone` is an optional plaintext
contact number (`TEXT`; empty means unset). Creating/updating checks the email
explicitly and returns `400 "email already exists"`; the phone behaves the same
(a non-empty unique value; duplicates return `400 "phone already exists"`, backed
by the partial unique index `users_phone_key`).

Extra list fields: `provisioned_via` (e.g. `sso_jit` for third-party JIT
provisioning, otherwise `null`), `has_password`, `sso_identities`
(`[{ provider_code, display_name, provider_type }]` — the bound third parties).

### Groups and departments (staff; deletion admin-only)

Groups and departments are one tree (`kind = group | department`). `source`
decides editability: `local` may rename/change members/delete; `scim` and
`directory` nodes may be moved, but their name, membership and existence belong
to the source. See [groups.md](./groups.md).

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/admin/groups` | Flat node list: `id, display_name, parent_id, kind, source, member_count, created_at, updated_at` |
| `POST` | `/api/v1/admin/groups` | `{name, kind?, parent_id?}`; a duplicate name returns 409 |
| `PUT` | `/api/v1/admin/groups/{id}` | `{name?, kind?, parent_id?, clear_parent?}`; cycles are refused on move; omitting `parent_id` keeps it, `clear_parent=true` moves to the root; renaming a non-`local` node returns 409 |
| `DELETE` | `/api/v1/admin/groups/{id}` | **admin** and `local` only; children move up, members are released, the row becomes a tombstone |
| `GET` | `/api/v1/admin/groups/{id}/members?q=&limit=&offset=` | Paged direct members (searches email/display_name) |
| `POST` | `/api/v1/admin/groups/{id}/members` | `{user_ids:[uuid]}` to add; non-`local` returns 409 |
| `DELETE` | `/api/v1/admin/groups/{id}/members/{user_id}` | Remove; non-`local` returns 409 |

Audit: `group.create/update/delete/member_add/member_remove`.

**`GET /admin/users` paging contract**:

- `?q=` is a server-side search over email, username, display_name, status, role,
  `provisioned_via` and SSO identities (provider display name/code/type). `_` and
  `%` match literally (escaped), not as wildcards.
- `?sort=` allowlist: `created_at` (default) / `email` / `display_name` / `role` /
  `status`; `?dir=` accepts only `asc` (anything else means `desc`).
- `?limit=` is clamped to `[1, 200]` (default 20); `?offset=` ≥ 0.
- Sorting uses `id ASC` as a secondary key: rows sharing a `created_at` (e.g. a
  bulk directory import) neither duplicate nor disappear across pages.
- `total` counts matching rows (not the page); paging uses `offset`, and an
  out-of-range offset returns an empty `users` array, not an error.

**`POST /admin/users/batch-disable` semantics**: permissions are checked per row
(a manager cannot freeze an admin, and the target list excludes the caller); the
`disabled` count includes **every target id that exists** — freezing an already
frozen account counts too (idempotent, so a repeated selection is never
under-reported); only non-existent ids are excluded. Each target produces its own
audit event; after all succeed, all their sessions are revoked at once.

> `phone` is currently **contact information** only, with no SMS verification.
> SMS OTP binding is planned; see [design.md](./design.md) Phase 4.

---

## 4. Administration: clients

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/admin/clients` | List |
| `POST` | `/api/v1/admin/clients` | Register (the secret is returned once) |
| `PUT` | `/api/v1/admin/clients/{id}` | Update redirect / scopes / **IP allowlist** (PKCE always enforces S256; no switch) |
| `DELETE` | `/api/v1/admin/clients/{id}` | **admin** delete |
| `POST` | `/api/v1/admin/clients/{id}/disable\|enable` | Enable / disable |
| `POST` | `/api/v1/admin/clients/{id}/rotate-secret` | Rotate the secret |

### IP allowlist fields

| Field | Default (new client) | Notes |
|------|--------------|------|
| `ip_allowlist_enabled` | `true` | When on, only `allowed_cidrs` may reach that client's authorize/token |
| `allowed_cidrs` | `[]` | IPs or CIDRs; at least one when enabled |

Existing clients migrate with the restriction **off**. See
[client-integration.md](./client-integration.md).

---

## 5. Administration: overview and audit

| Method | Path | Notes |
|------|------|------|
| `GET` | `/api/v1/admin/stats` | Overview stats (24h hourly + 7d/30d daily login trends; optional per-app filter plus app/browser/OS distributions) |
| `GET` | `/api/v1/admin/audit-logs` | Audit list (with `ip` / `browser` / `os` / `client_id`; filter by action / client_id / browser / os / q / sort) |
| `GET` | `/api/v1/admin/audit-logs/export` | Audit CSV export (`text/csv`, respecting staff permissions, with a `client_id` column) |
| `GET` | `/api/v1/admin/audit-logs/facets` | Filter-dropdown sources (distinct browser/OS over 90 days + all apps) |

### `GET /api/v1/admin/stats` (excerpt)

- User / client counts
- `logins_24h` / `logins_7d` / `logins_30d` (current window totals)
- `unique_users_24h` / `unique_users_7d` / `unique_users_30d`
- `login_trend[]`: daily points for 30 days with `day`, `logins_1d`, and rolling
  `logins_7d` / `logins_30d`
- `login_trend_24h[]`: hourly points for 24 hours (UTC on the hour, empty buckets
  zero-filled) with `hour`, `logins`
- `by_client[]`: 30-day aggregation per app (top 10 by 30d descending), with
  `client_id` (`(direct)` = no app attribution), `logins_24h/7d/30d`,
  `unique_users_30d`
- `browsers[]` / `oses[]`: browser / OS distribution of 30-day sign-ins with
  `name` / `count`
- `scope`: echoes the current filter (`client_id: null` = global)

Query: optional `client_id`. Passing an app id filters the sign-in fields above
(totals / unique users / trend / recent sign-ins / distributions) to that app;
`(direct)` counts only unattributed sign-ins. User and client counts are always
global.

### `GET /api/v1/admin/audit-logs`

Query: `q`, `action`, `client_id`, `browser`, `os`, `page`, `page_size`, `sort`
(including `ip`), `dir`.
Rows carry `ip`, `user_agent`, `browser`, `os`, `client_id` (set for
login/MFA-style events; `browser`/`os` are parsed from `User-Agent`; `client_id`
is the OAuth app that started the sign-in — recorded from September 2026 onwards,
empty in older rows).
Managers see an allowlist of actions only; `user.delete` / `client.delete` /
`mfa.reset` / `settings.mfa_update` and similar are admin-only.

### `GET /api/v1/admin/audit-logs/facets`

Returns `browsers[]`, `oses[]` (distinct values over 90 days, ascending) and
`clients[]` (all apps with `client_id` / `enabled`) for the audit page and the
Overview filter dropdowns.

### App attribution in login audits

The sign-in endpoints (`POST /auth/login`, `POST /mfa/verify`,
`POST /mfa/enroll/confirm`, `POST /passkeys/finish`) accept an optional
`return_to` (a `/oauth/authorize?...&client_id=xxx` URL). When it parses and the
client validates against `client_apps`, that `client_id` is written into the
`auth.login` / `auth.login_failed` audit event; a parse failure never affects the
sign-in itself.

---

## 6. Boundary with OIDC

| Prefix | Purpose |
|------|------|
| `/api/v1/*` | Signet dashboard, sessions, administration |
| `/oauth/*` | Standard OIDC (business-client integration) |
| `/health` | Liveness |
| `/metrics` | Prometheus metrics (separate listener; default `127.0.0.1:9464`, `SIGNET_METRICS_BIND` moves or disables it) |

### Audit retention

An hourly sweep deletes rows whose `created_at` predates the retention window
(`SIGNET_AUDIT_RETENTION_DAYS`, default 180; also editable under Settings →
Runtime policies, **never below 1 day**). Dashboard queries and exports are
unaffected.

### Additional OIDC endpoints

- `GET/POST /oauth/consent`: the consent page submission (`allow` is
  `true`/`false`). Explicitly requested scopes are granted as a whole when
  `allow` is true; unrequested scopes inside the client allowlist are optional
  and submitted as `optional_scopes` (space-separated) in the body. An allow
  writes `oauth_consents` and redirects back to authorize (the redirect carries
  only the originally requested scopes).
- `GET/POST /oauth/end_session`: unified logout. GET must carry
  `id_token_hint` (signature verified, `sub` matching the session); POST needs no
  hint (a Lax cookie is not sent on a cross-site form). A
  `post_logout_redirect_uri` redirects only when registered in that client's
  allowlist, and when both `client_id` and the hint's `aud` are present they must
  agree.
- `POST /oauth/revoke`: RFC 7009 revocation. Form fields `token` and optional
  `token_type_hint`; the client authenticates with Basic or
  `client_id`+`client_secret`. Only refresh tokens are revoked (access tokens are
  stateless JWTs, so they cannot be revoked server-side). Returns 200 whether or
  not the token existed.
- `POST /oauth/register`: RFC 7591 dynamic client registration. Needs
  `Authorization: Bearer <token>` or the form field `initial_access_token`
  (single-use, issued by an administrator). Returns `client_id`/`client_secret`.
- `POST /oauth/introspect`: RFC 7662 token introspection. The client
  authenticates with Basic or `client_id`+`client_secret`; body `{ token }`.
  Returns `{ active: bool, ... }`: `active=false` covers an invalid signature,
  expiry, **a disabled/deleted user** and a disabled client — semantics local JWT
  verification cannot provide. An unknown token is not an error (§2.2).
- `POST /oauth/token` with `grant_type=client_credentials`: machine-to-machine
  (M2M) tokens. The client must have been granted `client_credentials` at
  registration; there is no refresh token and no user claim, `sub` is the
  `client_id`, and scopes narrow to the client's registered list (the body
  `scope` may only be a subset).

**Additional authorization-code parameters**

| Parameter | Notes |
|------|------|
| `max_age` (seconds) | Step-up: a session older than this is destroyed and a fresh sign-in is required; with `prompt=none` it returns `error=login_required`, so silent renewal gives up; `max_age=0` always requires a fresh sign-in |
| `code_challenge` / `code_challenge_method` | Always `S256`, enforced, no switch |

Additional `id_token` claims: `auth_time` (the actual authentication time,
carried from the authorization code) and `email_verified`. The `access_token`
also carries `email_verified` and the client's custom claims.

**Per-client extra claims** (`client_apps.extra_claims`, edited under Dashboard →
Clients): a JSON object whose values may be literals (string/number/boolean) or
the placeholders `$sub` / `$email` / `$username` / `$display_name` / `$phone`;
merged into that client's `id_token`, `access_token` and `/oauth/userinfo`
response. An unresolvable placeholder **aborts issuance** (no token is emitted
with a missing claim); M2M (user-less) tokens keep literals only.

**Back-channel logout** (`client_apps.backchannel_logout_uri`): when a user's
session is terminated (logout / `end_session` / admin force sign-out / password
or email change), Signet POSTs the form field `logout_token=<signed JWT>` to every
registered client holding that user's authorization (with an `events` member and
`sub`, `exp` 120 seconds). Best-effort: failures are only logged, and RPs may
fall back to introspection or a short access-token TTL.

> **Scope trimming**: `id_token` and `/oauth/userinfo` both emit claims by granted
> scope — `email` needs the `email` scope, `name` needs `profile`,
> `phone_number` needs `phone`, `groups` needs `groups`; `sub` is always present.

## 7. Password reset

| Method/path | Notes |
|-----------|------|
| `POST /api/v1/password-reset/request` | body `{ email }`; mints a 30-minute reset token and sends it over SMTP. **Returns 503 when SMTP is not configured** (Settings → Email relay or `SIGNET_SMTP_HOST`; development can set `SIGNET_DEV_LOG_LINKS` to log the link). An unknown email still returns `{ ok: true }` to prevent enumeration; a delivery failure returns 502 |
| `POST /api/v1/password-reset/confirm` | body `{ token, new_password }`; validates the token, applies the password policy, revokes every session |

### Self-service email change (requires a verified current email)

| Method/path | Notes |
|-----------|------|
| `POST /api/v1/me/email/change-request` | session; body `{ new_email }`. Validates the format, that it differs from the current one, the domain allowlist and that it is unused; mints a 30-minute single-use token delivered to the **new address** (through the outbox). When the current email has `email_verified=false` it returns 403 |
| `GET /api/v1/me/email/confirm?token=` | No sign-in needed (the link is the credential); single-use. Success → `302 /settings?email_changed=1`, expired → `302 /settings?email_error=expired`, taken → `302 /settings?email_error=taken`. On success it sets `email_verified=TRUE`, revokes every session and refresh token, and triggers back-channel logout |

## 8. Passkeys (WebAuthn)

| Method/path | Auth | Notes |
|-----------|------|------|
| `GET /api/v1/me/passkeys` | session | List the current user's passkeys |
| `POST /api/v1/me/passkeys/start` | session | Begin registration: `{ token, challenge }` |
| `POST /api/v1/me/passkeys/finish` | session | Finish registration: body `{ token, name, credential }` |
| `DELETE /api/v1/me/passkeys/{id}` | session | Delete a passkey |
| `POST /api/v1/passkeys/start` | public | Begin sign-in: body `{ email }` |
| `POST /api/v1/passkeys/finish` | public | Finish sign-in: body `{ token, credential }`; creates the session on success |

Challenge state lives in server memory (single instance, 5 minutes). The passkey
public key is stored as the `webauthn-rs` `Passkey` JSON, and the signature
counter is updated after a successful sign-in.

## 9. Webhooks

| Method/path | Auth | Notes |
|-----------|------|------|
| `GET /api/v1/admin/webhooks` | admin | List webhooks (with `kind`, `secret_set`) |
| `POST /api/v1/admin/webhooks` | admin | body `{ url, secret?, kind? }`; `kind` is `generic` (default) or `feishu` |
| `DELETE /api/v1/admin/webhooks/{id}` | admin | Delete |
| `GET /api/v1/admin/webhooks/{id}/deliveries` | admin | The latest 50 delivery results |

After each audit event is stored, it is POSTed asynchronously to every enabled
webhook. `kind` selects the delivery shape:

- **`generic`**: the raw audit JSON as-is, with `x-signet-event` (the event id)
  and `x-signet-signature` (`sha256=<HMAC>`, signed with `secret`).
- **`feishu`**: rendered as a Feishu interactive card (`msg_type: interactive`);
  `secret` drives Feishu's signature verification — HMAC-SHA256 over an empty
  message keyed by `timestamp+"\n"+secret`, standard Base64, with `sign` and
  `timestamp` in the body (not headers).

Delivery outcomes (status code / success / error) are stored in
`webhook_deliveries`.

## 10. SCIM v2

`/scim/v2/*` requires `Authorization: Bearer <token>` (disabled when no token is
configured). The token is generated/rotated/revoked in the dashboard; the
plaintext is shown once and only the hash is stored; `SIGNET_SCIM_BEARER_TOKEN`
only seeds the first start.

| Method/path | Notes |
|-----------|------|
| `GET/POST /scim/v2/Users` | List / create (`userName`→email, `active`→status, `externalId`) |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | Look up by id / externalId / email |
| `GET/POST /scim/v2/Groups` | List / create |
| `GET/PATCH/DELETE /scim/v2/Groups/{id}` | Read / add-remove members / delete |
| `GET /scim/v2/ServiceProviderConfig` | Capability declaration |

Groups take `users.groups[]` as the membership source (`scim_groups` stores group
metadata), consistent with the OIDC `groups` claim.

## 11. Integration status

| Method/path | Auth | Notes |
|-----------|------|------|
| `GET /api/v1/admin/integrations` | admin | Read-only `scim` (enabled, endpoint, token configured) and `webauthn` (`rp_id`/`rp_origin`) |
| `POST /api/v1/admin/scim/token` | admin | Generate/rotate the SCIM bearer token, returning `{"token":"<plaintext, once>"}` |
| `DELETE /api/v1/admin/scim/token` | admin | Revoke the SCIM bearer token (disables the SCIM surface) |

## 12. Third-party sign-in (identity federation)

After an administrator configures an upstream identity source, users can sign in
with a third-party account. Configuration lives in `upstream_providers`
(`client_secret` AES-256-GCM encrypted) and bindings in `user_identities` (unique
on `(provider_code, subject)`).

Supported types: `github` / `google` / `feishu` / `wechat` / `oidc` (generic OIDC
discovery, needs `issuer_url`).

### Sign-in flow (browser redirects)

| Path | Notes |
|------|------|
| `GET /api/v1/auth/sso/{provider}/start?return_to=` | Mints a CSRF state (plaintext in an HttpOnly cookie, SHA-256 in the database, single-use, 10 minutes) and 302s to the upstream authorization page. Optional `return_to`: the initiating `/oauth/authorize?...` URL (same-origin OIDC paths only, preventing open redirects), so the flow resumes after sign-in |
| `GET /api/v1/auth/sso/{provider}/callback` | Verifies state → exchanges the token → fetches the normalised profile → decides the binding → issues a session or stashes a pending identity (audited as `auth.login.thirdparty`). When the account still has local gates (forced password change / TOTP / forced MFA enrollment), it redirects to `/login?sso_step=mfa\|enroll\|password_change`, the same continuation as password sign-in |
| `GET /api/v1/auth/sso/providers` | Public: the enabled providers (for the sign-in page buttons) |

### Binding policy (anti-takeover + OA JIT)

The callback decides in this order (first success wins):

1. **Already bound**: `(provider_code, subject)` exists in `user_identities` →
   issue the session immediately.
2. **Existing session**: the browser already holds a valid `signet_session` →
   bind that upstream identity to the current user and sign in.
3. **Email auto-bind**: the upstream email is **verified** and `lower(email)`
   exactly matches a local `status=active` user → write `user_identities` and
   sign in.
4. **JIT provisioning** (on by default, can be turned off): the upstream email is
   **verified** and no local account uses it → create a `role=member`,
   passwordless local user, write the binding and sign in. Suits a company
   Feishu / Google / OIDC OA where "first click signs you in, with no
   administrator pre-provisioning".
5. **Otherwise → pending bind**: store the identity in
   `identity_link_challenges` plus the `signet_sso_pending` cookie (**15
   minutes**) and redirect to `/login?sso_error=no_matching_account`. Within the
   window the user signs in to an existing account with a password / MFA /
   passkey to finish the binding.

Notes:

- JIT **does not** provision without a verified email (WeChat Open Platform
  usually has none → an administrator must create the account or the user binds
  it explicitly).
- Feishu requires the app to enable email permissions and the profile to return
  `email` / `enterprise_email`, otherwise step 5 applies. For
  `GET /open-apis/authen/v1/user_info`: `email` needs **Get user email**
  (`contact:user.email:readonly`); `enterprise_email` additionally needs **Get
  user employment info** (`contact:user.employee:readonly`) and a tenant with
  Feishu mail enabled. Permissions take effect after being granted and published
  in the open platform (the authorization URL carries no `scope=`).
- Toggle JIT under Dashboard → **Settings → JIT provision on SSO**
  (`app_settings.sso.jit_provision`), or `GET/PATCH /api/v1/admin/settings/sso`.
  `SIGNET_SSO_JIT_PROVISION` only backs the setting while the row is absent
  (default `true`); after migration `020` the DB/Settings win.
- **Per-provider overrides** (migration `033`): each provider may set `jit_mode`
  (`inherit` follows the global switch / `on` provisions even when globally off /
  `off` refuses even when globally on) and `email_trust` (`inherit` uses the
  adapter's verification flag / `any` treats any email as verified / `verified`
  requires an explicit upstream verification flag). Platform differences at a
  glance:

  ⚠️ **`any` assumes the tenant controls contact emails**: it trusts "the provider
  asserted this email". If the upstream lets users edit their own contact email
  (personal Feishu, self-hosted OIDC, …), an attacker can bind or JIT-provision
  `victim@corp.com` before the victim registers (pre-registration takeover).
  Saving `email_trust=any` logs a warning server-side; enable it only for tenants
  where administrators control contact emails.

  | provider_type | Email verification flag | Suggested setting | Notes |
  |---------------|--------------|----------|------|
  | `github` | Reported faithfully (primary + verified) | `inherit` | Auto-bind/provision only on a verified email |
  | `google` | Reported faithfully (`email_verified`) | `inherit` | Same |
  | `oidc` | Depends on the upstream, standard field | `inherit`; use `verified` when the upstream cannot be trusted | Same |
  | `feishu` | **No verification flag** (the adapter reports "unverified") | Company tenant: `email_trust=any` + `jit_mode=on`; otherwise keep `inherit` | Migration 033 set existing Feishu providers to `any` to preserve behaviour; new ones default to `inherit` (bind only; auto-provisioning requires choosing `any`) |
  | `wechat` | **No email API** | Not applicable (`email_trust` has no effect) | Still exempt from the email requirement; can only bind an existing account |

  Also: a pending identity stashed when SSO could not auto-bind/provision is now
  bound **only when the user explicitly confirms it in the dashboard after
  signing in** (`GET/POST/DELETE /api/v1/auth/sso/pending`, a banner at the top
  after sign-in) and no longer auto-binds on "the next sign-in from the same
  browser" — so someone else's stashed identity on a shared machine cannot land
  on your account. Confirmation re-checks the provider's current email-domain
  allowlist.

  Typical combinations: company Feishu / Google Workspace tenants use
  `jit_mode=on` (trusted tenant, auto-provision); an open-registration GitHub
  uses `jit_mode=off` (bind only).

- Third-party sign-in proves the upstream identity only: local policy (forced
  password change, TOTP, global/per-user MFA enforcement) still applies before a
  session is issued, sharing the same MFA challenge as password sign-in (the
  challenge row records `via=sso`).

A failure redirects back to the sign-in page with `?sso_error=`:
`unknown_provider` / `provider_disabled` / `state_mismatch` / `upstream_error` /
`access_denied` (the user refused/cancelled on the third-party page) /
`missing_code` / `no_matching_account` / `email_required` (no email from the
upstream, except WeChat; an already-bound `(provider, subject)` can still sign
in).

### Admin API

| Method/path | Notes |
|-----------|------|
| `GET /api/v1/admin/sso/providers` | List (with `bindings`, `jit_mode`, `email_trust`, each record's `callback_url`; `client_secret` is never returned) |
| `POST /api/v1/admin/sso/providers` | Create (`code` `[a-zA-Z0-9_-]`; `oidc` requires `issuer_url`; optional `jit_mode` / `email_trust`, default `inherit`) |
| `PUT /api/v1/admin/sso/providers/{code}` | Update; an empty `client_secret` keeps the current one, a value rotates it; `jit_mode` / `email_trust` as on create |
| `DELETE /api/v1/admin/sso/providers/{code}` | Delete (cascades bindings) |
| `POST /api/v1/admin/sso/providers/{code}/enabled` | Enable/disable `{"enabled": bool}` |
| `GET/PATCH /api/v1/admin/settings/sso` | The JIT switch `{"jit_provision": bool}` (stored in `app_settings`) |
| `GET /api/v1/auth/sso/callback-url` | The unified URL template: `{base}/api/v1/auth/sso/{provider}/callback` |

**Callback URL convention (identical for every provider)**:
`{SIGNET_PUBLIC_BASE_URL|issuer}/api/v1/auth/sso/{code}/callback`
GitHub / Google / Feishu / WeChat / OIDC all use this path; platform differences
live inside the adapter (token exchange, profile fetch) and **never change the
URL shape**. The admin list shows each provider's full copyable address.

### User-side API

| Method/path | Notes |
|-----------|------|
| `GET /api/v1/auth/sso/identities` | The current user's bound third-party accounts |
| `DELETE /api/v1/auth/sso/identities/{provider_code}` | Unbind; refused when no sign-in method would remain (no password and no other binding) |

## 13. Observability

| Endpoint | Notes |
|------|------|
| `GET /health` | Readiness: probes Postgres (`SELECT 1`), 503 on failure |
| `GET /metrics` | Prometheus text format; login/token/MFA counters plus HTTP request counts, in-flight requests and latency histograms. **Separate listener** (default `127.0.0.1:9464`, `SIGNET_METRICS_BIND`; not on the public port), which also serves `/health` |

Global rate limiting: `/api/v1` and `/oauth/*` are limited per client IP, default
`SIGNET_RATE_LIMIT_PER_MINUTE=300`, returning 429 above it.

Request correlation: every response echoes `x-request-id` (passed through or a
generated UUID) and writes it into the tracing span; access logs correlate on
`request_id`.

The legacy `/api/...` paths (without `v1`) are retired and no longer serve JSON.

## 14. Sign-in allowlist (email domains)

Restricts **who may come in**: only addresses under the configured email domains
may sign in, be provisioned or be synced. Configuration is a **full-domain
list** (not prefixes); matching compares on label boundaries (`corp.example`
matches `corp.example` and `mail.corp.example`, not `evilcorp.example`),
case-insensitively, with no wildcards. An empty list means unrestricted.

### Configuration and source

| Source | Location | Precedence |
|------|------|--------|
| `app_settings.auth.allowed_email_domains` | Dashboard → Settings → **Email domain allowlist**, or `GET/PATCH /api/v1/admin/settings/sign-in` | Above the environment |
| `SIGNET_ALLOWED_EMAIL_DOMAINS` | Environment (comma or whitespace separated) | Only as a default while the setting row is absent |

`GET` returns `{ "allowed_email_domains": [...], "origin": "setting" | "environment" | "unrestricted" }`;
`PATCH` takes `{ "allowed_email_domains": [...] }`. Passing `null` (or omitting
the field) **deletes the setting row** and falls back to the environment; an
empty array explicitly writes "unrestricted" (`origin` stays `setting`) — both
admit everyone, but only the former can be undone by "removing the environment
variable". The list is normalised (trim, lowercase, dedupe) and validated before
saving: empty entries, values containing `@` (an address used as a domain) and
wildcards are all rejected with 400.

The server refuses to save a list that would **exclude the acting operator**
(400, suggesting adding their domain back), so one configuration change cannot
lock everyone out; if the saved list excludes **other** admins, they are named in
the audit detail's `excluded_admins`, because an excluded account cannot tell
anyone why it cannot get in. The environment path has no such protection, so at
startup a list excluding every admin logs a `warn`.

### Semantics: refusal, not disablement

An address outside the list **cannot sign in, be provisioned or be synced**, but
the account itself is **not disabled**, and data and history stay — narrowing the
list declares "who may come in", not "who has left". This is the key difference
from directory-sync scope (`docs/directory-sync.md` §7.2.1), which disables
accounts that fall out of scope.

| Surface | Behaviour outside the list |
|------|--------------|
| Sign-in (password / MFA / passkey / SSO callback) | Refused at session issuance: Unauthorized; the SSO callback redirect carries `error=domain_not_allowed` |
| `POST /api/v1/login` | Credentials first: an unknown account, a wrong password and "correct password but disallowed domain" all return the **same** `invalid email or password`; an unknown account also runs a dummy Argon2 to equalise timing; `disabled` / `locked` are only revealed after the password verifies |
| Admin create / email change | 400 |
| SCIM `POST`/`PUT` `/scim/v2/Users` | 400 (the IdP sees the reason directly) |
| SSO JIT provisioning | Provisioning refused (the same path as the sign-in refusal above) |
| Directory sync | The entry is `skip`ped with `reason = email_domain_not_allowed`; it **does not count as disabled** and is not treated as disappearing upstream (see `docs/directory-sync.md` §7.2.1) |
| Password reset | Silent: still returns `200 {"ok": true}` but sends nothing (no account enumeration) |
| First-deployment `/setup` | **Unrestricted**: otherwise a brand-new deployment could not create its first administrator |

Each SSO provider may also carry its own `allowed_email_domains` (§12 admin API /
Dashboard → Integrations); it only **narrows** the global list, never widens it —
an empty provider list means no extra restriction.

Audit: refused sign-ins record `auth.sign_in_blocked`; refused provisioning
records `user.provision_blocked` (`detail.via` distinguishes `password` (including
the MFA challenge) / `passkey` / `sso` / `sso_jit` / `admin` / `scim`); config
changes record `settings.sign_in_allowlist_update`.
