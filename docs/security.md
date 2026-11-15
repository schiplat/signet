# Signet security design

> English · [简体中文](./zh-CN/security.md)

This document summarises Signet's security mechanisms, expanding the security requirements in [design.md](./design.md).

| Item | Detail |
|---|---|
| Related | [design.md](./design.md) · [api-v1.md](./api-v1.md) · [mfa.md](./mfa.md) · [client-integration.md](./client-integration.md) · [integrations.md](./integrations.md) |

---

## 1. Credential and key storage

**Principle: any verifiable credential is stored as a hash or ciphertext, never
as plaintext.**

| Data | Stored in | Method |
|------|---------|------|
| User password | `users.password_hash` | Argon2 (random salt) |
| Password history | `password_history.password_hash` | Argon2 |
| MFA recovery codes | `totp_recovery_codes.code_hash` | Argon2 (normalised before hashing) |
| OAuth client secret | `client_apps.client_secret_hash` | HMAC-SHA256 (application pepper, constant-time comparison; legacy Argon2 rows upgrade on match) |
| Session token | `sessions.token_hash` | SHA-256 |
| Authorization code | `auth_codes.code_hash` | SHA-256 |
| Refresh token | `refresh_tokens.token_hash` | SHA-256 |
| MFA challenge token | `mfa_challenges.token_hash` | SHA-256 |
| **TOTP secret** | `users.totp_secret` | **AES-256-GCM application-layer encryption** |

### 1.1 Application-layer encryption of TOTP secrets

`totp_secret` is a **reversible shared secret** required to verify TOTP, so it
cannot be one-way hashed like a password. It is therefore **encrypted at the
application layer** rather than stored in plaintext:

- Algorithm: AES-256-GCM; each encryption uses a random 96-bit nonce; the value is
  stored as base64 of `nonce ‖ ciphertext`.
- Key: `data/encryption.key` (32 bytes hex), generated on first start; override
  with `SIGNET_ENCRYPTION_KEY_PATH`.
- Implementation: `crates/signet/src/crypto/encryption.rs` (`Encryptor`).
- Read/write points: encryption on enroll / rebind writes; decryption on verify /
  regenerate / rebind reads.
- **Backward compatibility**: a failed decryption falls back to plaintext, so
  legacy plaintext rows need no migration and convert to ciphertext on the next
  rebind.
- The key is as sensitive as the JWT private key and belongs in backups and
  permission controls.
- **Instances sharing one database must share one key**: otherwise they write
  ciphertext the other cannot read (typical symptom: a TOTP enrolled on instance
  A fails verification on instance B). Startup checks the
  `app_settings.crypto.encryption_key_fingerprint` row and refuses to start on a
  mismatch; see [deploy.md §3](./deploy.md#3-key-directory-appdata).

> ⚠️ Legacy data: existing plaintext `totp_secret` rows are not bulk
> re-encrypted (that would disrupt online users); they convert naturally on the
> next rebind. A maintenance-window script can force a full migration by walking
> `users.totp_secret`.

---

## 2. Authentication security

### 2.1 Login brute-force protection
- After `SIGNET_MAX_LOGIN_ATTEMPTS` consecutive wrong passwords (default 5) the
  account locks for `SIGNET_LOCKOUT_MINUTES` (default 15).
- Fields: `users.failed_login_attempts`, `users.locked_until`.
- Failures are audited as `auth.login_failed`; a locked account gets an explicit
  message.
- A successful login resets the counter.

### 2.2 Password policy
- Minimum length `SIGNET_PASSWORD_MIN_LENGTH` (default 10).
- Complexity: must contain uppercase, lowercase and a digit.
- History: a new password may not match the most recent
  `SIGNET_PASSWORD_HISTORY_SIZE` (default 3).
- Implementation: `crates/signet/src/auth/password.rs` (`set_user_password`
  centralises the checks).

### 2.3 Email and phone uniqueness
- `users.email` carries a database unique constraint (`users_email_key`);
  `users.phone` has a partial unique index (`users_phone_key`, non-null values
  only).
- Create/update **checks explicitly** and returns `400 email already exists` /
  `400 phone already exists`.
- The create/edit form debounces a live check (`email-check` / `phone-check`) and
  disables submit on a hit.
- Self-service profile edit (`PATCH /api/v1/me`) accepts `phone` and performs the
  same check (excluding self).

> **Phone verification is not implemented**: `phone` is stored as
> **unverified contact information** only. Full binding requires an SMS OTP
> before the number can be used for password recovery, account recovery or
> SMS sign-in; that needs an SMS gateway (e.g. Alibaba Cloud SMS) plus sending
> rate limits and replay protection. See the documentation index.

### 2.4 Login auditing
- Both successful and failed sign-ins are audited with the client IP and
  browser/OS (parsed from `User-Agent`, see §6).
- **Client IP trusts proxies only when configured** (`SIGNET_TRUSTED_PROXIES`):
  `X-Forwarded-For` / `X-Real-IP` are honoured only when the direct peer is in
  the list, and the value taken is the **first untrusted hop from the right** —
  the leftmost entry is client-controlled. Without the setting the peer address
  is used, so a forged header cannot affect IP allowlists, rate limits or audit.

### 2.5 Password reset
- `POST /api/v1/password-reset/request` mints a 30-minute, single-use reset
  token (SHA-256 hashed at rest).
- The link is delivered over SMTP; without SMTP the request returns 503 (dev can
  use `SIGNET_DEV_LOG_LINKS` to log links). Unknown addresses still report
  success, to prevent enumeration.
- `POST /api/v1/password-reset/confirm` validates the token, applies the password
  policy, consumes it and revokes every session.

### 2.6 WebAuthn / passkeys
- Passwordless, phishing-resistant second factor; the passkey public key is
  stored as the `webauthn-rs` `Passkey` JSON, and the signature counter is
  updated after a successful sign-in.
- Registration (`/api/v1/me/passkeys/*`) requires a session; sign-in
  (`/api/v1/passkeys/*`) creates the session and writes `auth.login`
  (`mfa: passkey`).
- Challenge state lives in server memory (single instance, 5 minutes, single use).

### 2.7 New device/IP alerts
- A previously unseen (user, IP) pair writes `auth.new_device` and sends an alert
  email; without SMTP the alert only reaches the log and never blocks the
  sign-in.
- Sources are recorded in `login_devices` for later anomaly detection.

### 2.8 Sign-in allowlist (email domains)
- Only addresses in the configured domains may sign in, be provisioned or be
  synced; configuration is in `docs/api-v1.md` §14.
- The semantics are **admission**, not **ownership**: an address outside the list
  is refused (`auth.sign_in_blocked` / `user.provision_blocked`) but the account
  is **not disabled** — data and history stay. Narrowing the list is not a bulk
  offboarding.
- Domains are compared on label boundaries, no wildcards; saving validates
  (empty entries, addresses used as domains and wildcards are refused). A list
  that would exclude the acting administrator is refused by the server, avoiding
  self-lockout; at startup a list excluding every admin logs a warning.
- The first-run `/setup` is exempt (otherwise a new deployment could not create
  its first administrator).

### 2.9 Public self-registration
- **Off by default.** The switch lives at `app_settings.auth.public_signup` and
  has no environment fallback, so a deployment cannot be opened up by an
  environment variable an administrator believes is inert. Enabling requires an
  SMTP relay (the link is the proof of address ownership) **and** a CAPTCHA
  provider (the endpoint is unauthenticated). The save path runs a preflight
  against the live configuration — host, a non-zero port and a From that
  parses as a mailbox for the relay; provider, site key and secret for CAPTCHA
  — and refuses with **every** blocking problem listed. The dashboard shows the
  same checklist, plus advisory warnings for an empty domain allowlist and
  localhost/http links. Both prerequisites are re-checked on every request; if
  either is later removed or becomes unusable, sign-up answers 503 and the
  public status reports `enabled: false`. Removing the relay/CAPTCHA does not
  create accounts without the protection the setting was enabled under.
- **No account before verification.** A request writes `signup_requests` only;
  `users` stays untouched. The verification token is random, stored as a SHA-256
  digest, single-use (the row is deleted on confirmation) and expires after 30
  minutes. A repeated request rotates the token, so an older link stops working.
  Confirmation creates a `member` with no groups, `email_verified=TRUE` and
  `provisioned_via='signup'`; it never starts a session (no login-CSRF via the
  email link). The link puts the token in the URL fragment (`#token=…`), which
  browsers do not send to the server, so it stays out of access and proxy logs;
  the confirmation page POSTs it only after an explicit click.
- **Anti-enumeration.** `POST /signup` returns the same `{ "status": "ok" }` for
  a new address, an address with a pending request and an address with an
  existing account. The password is hashed before the existence lookup so timing
  does not answer the question either. An existing account gets a notice email
  (only its owner can read it) instead of a link; repeats are suppressed for a
  minute.
- **Abuse controls.** Per-address 3 requests/hour, per-IP 5/hour and 20/day,
  counted in `signup_attempts` (shared by replicas); CAPTCHA before any
  address-dependent work; the password policy from §2.2; the email-domain
  allowlist from §2.8 applied both when the request is made and when it is
  confirmed. Audit events: `auth.signup_requested`, `auth.signup_confirmed`,
  `auth.signup_blocked` (rate limit), `user.provision_blocked` (domain) and
  `settings.signup_update`. Neither the password nor the link token is ever
  written to an audit row or a log line.

---

## 3. Session management
| Capability | Detail |
|------|------|
| Session records | `sessions` stores `ip`, `user_agent`, `last_seen_at` |
| Revoke one | A user can revoke one of their own sessions (`/api/v1/me/sessions/{id}`) |
| Revoke others | Revoke every session except the current one |
| Admin force sign-out | `POST /api/v1/admin/users/{id}/sessions/revoke` ends all of that user's sessions |
| Unified logout | OIDC `end_session` (`/oauth/end_session`); `post_logout_redirect_uri` follows the client's allowlist |
| Freeze cascade | Freezing or deleting a user clears their sessions |

Session cookie: HttpOnly, SameSite=Lax; forced `Secure` when the **effective
issuer** (including a dashboard change) is `https://`, so an http→https change
takes effect immediately (`SIGNET_COOKIE_SECURE` only forces the flag for http
deployments, where the dashboard refuses to save an http issuer in that
configuration).

### 3.1 Third-party sign-in passes the same local gates
Federated sign-in (GitHub / Google / Feishu / WeChat / generic OIDC) proves the
upstream identity only; local account policy still applies before a session is
created (`finish_sign_in`): forced password change (`must_change_password`), the
TOTP challenge, and enrollment when global or per-user MFA is enforced — sharing
the same challenge and continuation endpoints as password sign-in. The challenge
row records `via=sso`, and `auth.sign_in_blocked` lets audits tell the paths
apart. A user who already holds a session for that account (when binding from the
profile page) is not challenged again.

---

## 4. MFA (TOTP + recovery codes)
See [mfa.md](./mfa.md). Security highlights:

- TOTP secrets are encrypted at the application layer (§1.1).
- Recovery codes are single-use, Argon2-hashed, and shown in plaintext only once.
- Global and per-user enforcement; administrators can reset another user's MFA.
- Users may disable MFA themselves when it is not enforced (current TOTP
  required); enforced accounts cannot.
- The recovery-code page offers Copy / Download; Download produces
  `signet-recovery-codes.txt`.

---

## 5. OIDC / OAuth security

- Authorization Code + **PKCE S256**
- `redirect_uri` **exact allowlist** (prevents open redirects)
- `state` **mandatory** (login CSRF)
- `nonce` replay protection
- **Scope allowlist**: requested scopes must be a subset of the client's registered scopes (no claim escalation)
- **`prompt`** parameter: `none` / `login` / `consent` (no silent authorization)
- **No client load before authentication** (prevents client enumeration)
- Authorize/consent redirects always **303** (no caching or method conversion)
- Short token TTLs (access/id 1h, auth code 5min)
- Refresh token **rotation** (each refresh invalidates the old token)
- Refresh token **reuse detection** (a rotated token reappearing means theft: the whole family is revoked and `oauth.refresh_reuse` is audited)
- RFC 7009 revocation endpoint `/oauth/revoke`
- RFC 7591 dynamic client registration `/oauth/register` (single-use registration token)
- Client Source IP allowlist (on by default for new clients)
- OIDC consent (first authorization + remembered)
- Consent with optional scopes: request scopes are granted or refused as a whole; unrequested scopes inside the client's allowlist can be granted individually (GitHub-style)
- User-side consent revocation (`/me/consents`, which also revokes refresh tokens)
- `groups` claim (id_token / userinfo, trimmed by scope)
- `phone` scope emits `phone_number` / `phone_number_verified` (trimmed by scope)
- `end_session` unified logout; GET requires a valid `id_token_hint` (its `sub` must match the session), POST needs no hint but cross-site forms carry no cookie (logout CSRF)
- Registered `grant_types` enforced on both authorize and token
- `at_hash` in the id_token (binds the access token minted with it)
- Signing key ring: after rotation old public keys still verify; JWKS publishes both

Client secrets are stored as HMAC-SHA256 with an application pepper (constant-time
comparison; legacy Argon2 rows upgrade automatically); authorization codes and
refresh tokens are SHA-256 hashed.

---

## 6. Audit and observability

### 6.1 Audit
- Records: actor (email/role), action, resource, detail JSON, **IP**,
  **user_agent / browser / os**, timestamp.
- Browser/OS is parsed lightly from `User-Agent`
  (`crates/signet/src/http/user_agent.rs`), covering Chrome/Safari/Firefox/Edge/
  Opera and Windows/macOS/Linux/Android/iOS/ChromeOS.
- Deletion events (`user.delete` / `client.delete`, …) are admin-only; managers
  are limited by an action allowlist.
- Audit records **cannot be deleted** (no UI for it).
- CSV export respects the permission filter; clicking a row opens the full detail
  (including the detail JSON).

### 6.2 Retention
- An hourly sweep removes records older than the retention window
  (`SIGNET_AUDIT_RETENTION_DAYS`, default 180; startup refuses values below 1;
  changeable at runtime).

### 6.3 Observability
- `/metrics` is exposed on a **separate listener** (default `127.0.0.1:9464`,
  `SIGNET_METRICS_BIND`) and never on the public port:
  - Business counters: logins/failures, token issuance, MFA verifications
    (success/failure).
  - HTTP: request counts (by 2xx/3xx/4xx/5xx class), in-flight requests, latency
    histograms.
- `/health` is a readiness probe: it runs `SELECT 1` against Postgres and returns
  503 on failure, for load balancers and Kubernetes.
- Global rate limiting per client IP (`SIGNET_RATE_LIMIT_PER_MINUTE`, default
  300); exceeding it returns 429.
- **Request correlation (`x-request-id`)**: a supplied header is passed through,
  otherwise a UUID is generated; it is echoed, written into the tracing span, and
  links access logs to business logs.

### 6.4 Webhook event delivery
- Each audit event is asynchronously POSTed to every enabled webhook; delivery
  outcomes are stored in `webhook_deliveries`.
- Two types: `generic` (raw JSON plus an `x-signet-signature` HMAC header) and
  `feishu` (a Feishu card with `timestamp`/`sign` in the body).
- The dashboard's Integrations page creates, deletes and inspects recent
  deliveries.

### 6.5 SCIM v2
- `/scim/v2/Users` and `/scim/v2/Groups` provide enterprise directory (Okta/Entra,
  …) user and group sync behind a bearer token.
- The token is generated / rotated / revoked under Integrations → SCIM v2; the
  plaintext is shown once and only its SHA-256 hash is stored.
  `SIGNET_SCIM_BEARER_TOKEN` only seeds the first start.

---

## 7. Keys and configuration

| Setting | Default | Notes |
|--------|------|------|
| `SIGNET_JWT_PRIVATE_KEY_PATH` | `./data/jwt_private.pem` | RS256 private key, generated on first start; rotated by `signet keys rotate` |
| `SIGNET_JWT_RETIRED_KEY_DIR` | `./data/retired_keys` | Retired public keys (still verify; JWKS publishes both) |
| `SIGNET_ENCRYPTION_KEY_PATH` | `./data/encryption.key` | AES-256-GCM key, generated on first start |
| `SIGNET_COOKIE_SECURE` | `false` | Automatic when the issuer is https; set explicitly only to force |
| `SIGNET_TRUSTED_PROXIES` | — | Trusted reverse-proxy IP/CIDR list; unset ignores forwarding headers and uses the peer address |
| `SIGNET_MAX_LOGIN_ATTEMPTS` | `5` | Lockout threshold |
| `SIGNET_LOCKOUT_MINUTES` | `15` | Lockout duration |
| `SIGNET_PASSWORD_MIN_LENGTH` | `10` | Minimum password length |
| `SIGNET_PASSWORD_HISTORY_SIZE` | `3` | Password history depth |
| `SIGNET_AUDIT_RETENTION_DAYS` | `180` | Audit retention |
| `SIGNET_RATE_LIMIT_PER_MINUTE` | `300` | Requests per IP per minute |
| `SIGNET_PUBLIC_BASE_URL` | — | Public base for mail and reset links |
| `SIGNET_SMTP_HOST` / `_PORT` | — | SMTP server (without one, password reset returns 503). Configurable under Settings → Email relay (**DB > environment**, password encrypted, test send supported); the environment is a fallback |
| `SIGNET_SMTP_USERNAME` / `_PASSWORD` | — | SMTP AUTH (optional for a trusted relay) |
| `SIGNET_METRICS_BIND` | `127.0.0.1:9464` | Metrics listener; `off` disables it |
| `SIGNET_OTEL_ENDPOINT` | — | OTLP/HTTP trace export (e.g. `http://collector:4318/v1/traces`); unset means **zero-overhead off** |
| `SIGNET_OTEL_SERVICE_NAME` | `signet` | Trace `service.name` resource attribute |
| `SIGNET_OTEL_SAMPLE_RATIO` | `1.0` | Sampling ratio 0.0–1.0 (root spans sampled by trace id; an upstream decision is followed) |
| `SIGNET_EMAIL_FROM` | — | Mail sender |
| `SIGNET_SCIM_BEARER_TOKEN` | — | SCIM API token (optional; seeds the first start only, managed in the UI afterwards) |
| `SIGNET_WEBAUTHN_RP_ID` / `_ORIGIN` | derived | Relying-party ID/origin (a real domain in production) |
| `SIGNET_CAPTCHA_PROVIDER` / `_SITE_KEY` / `_SECRET_KEY` | — | CAPTCHA (Turnstile or hCaptcha) on sign-in/reset; configurable under Settings → CAPTCHA (**DB > environment**, secret encrypted); enabled only when all three are present |
| `SIGNET_CAPTCHA_VERIFY_URL` | — | siteverify endpoint override (self-hosted compatible service / tests) |
| `SIGNET_BRAND_NAME` | `Signet` | Product name (sign-in/sidebar/title); Settings → Branding overrides it (DB > environment). The same page uploads a logo: PNG/JPEG/WebP only (**SVG refused**, to prevent same-origin script execution), magic-byte checked, ≤256 KiB, served from the public read-only `GET /api/v1/branding/logo` (`nosniff` + versioned immutable cache) |

The production container mounts the `signet_data` volume at `/app/data` (JWT and
encryption keys); the `build/` vs `deploy/` split is in
[deploy.md](./deploy.md).

---

## 8. Not implemented

SMS-verified phone binding and the Alertmanager integration are not implemented;
the [documentation index](./README.md#not-implemented-yet) keeps the canonical
list. `phone` is currently unverified contact information (§2.3).
