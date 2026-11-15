# Signet design document

> English · [简体中文](./zh-CN/design.md)

| Item | Detail |
|---|---|
| Project | **Signet** |
| Role | Organisation-wide identity service (OIDC IdP) |
| Production entry (future) | `https://sso.example.com` |
| Development issuer | `http://localhost:8443` (default; a value saved under Dashboard → Settings → Server identity wins, and `SIGNET_ISSUER` only seeds/falls back) |
| Protocol | OAuth 2.0 / OIDC **Authorization Code + PKCE** |
| First client | Cella (intranet deployment with outbound access) |
| Status | Phase 1 MVP implemented |

---

## 1. Goals and non-goals

### 1.1 Goals

- Provide **single sign-on** for multiple internal subsystems
- Speak standard **OIDC** so clients are replaceable and can be built in parallel
- Support **Signet on the public internet + business systems on the intranet**
  (the business side only needs outbound access to Signet)
- Provide revocable sign-in sessions and (optional) unified logout
- Provide a stable identity key (`sub`) and basic user information so the
  business side can authorise

### 1.2 Non-goals (first phase)

- Not a replacement for each system's **fine-grained business permissions**
  (dataset ACLs, operation policies stay in the business system)
- No full WeCom / DingTalk sync (possible future IdP connectors)
- No general API gateway, billing or app store
- No shared naming or config prefix with Alibaba Cloud OSS (object storage)

### 1.3 Authentication vs authorization boundary

```text
Signet        ── owns ──▶  authentication (who you are): sign-in, sessions,
                           id_token, unified logout
Business app  ── owns ──▶  authorization (what you may do): roles, dataset
                           permissions, feature switches
```

Signet may publish optional `roles` / `groups` **claims** as a starting point for
the business side's mapping, but the **authoritative business authorisation table
lives in the business system** (e.g. Cella's user-role table).

---

## 2. Deployment topology

### 2.1 Recommended topology

```text
                        Internet
              ┌─────────────────────┐
              │  sso.example.com    │
              │  Signet (OIDC IdP)  │
              └──────────▲──────────┘
                         │ HTTPS outbound
         ┌───────────────┴────────────────┐
         │ Intranet (internet-reachable)   │
         │  Cella / other subsystems       │
         │  User browser (intranet + web)  │
         └────────────────────────────────┘
```

### 2.2 Why this works

The key hops of the OIDC authorization-code flow happen in the **user's browser**:

1. The browser opens Cella on the intranet
2. It is redirected to Signet on the public internet to sign in
3. Signet **302s the browser back** to the intranet `redirect_uri` (Signet's
   server never needs inbound access to the intranet)
4. The Cella server **calls out** to Signet's token / JWKS / userinfo

### 2.3 Constraints

| Constraint | Detail |
|------|------|
| User browser | Must reach both the intranet app and the public Signet |
| Business server | Must reach `sso.example.com` outbound |
| `redirect_uri` | Registered as an intranet callback; no public reachability needed |
| Off-VPN users | Cannot complete the "back to intranet" hop (expected when the app is intranet-only) |
| Clocks | Intranet machines must keep accurate time, or JWT validation fails |

---

## 3. Protocol and endpoints

### 3.1 Protocol

- **OIDC Authorization Code Flow + PKCE** (for browser SPAs and services with a
  frontend)
- Confidential clients (the server holds a `client_secret`) and public clients
  (pure SPA + PKCE) both work; for Cella the recommendation is **backend code
  exchange** (a BFF or an Axum callback handler) so tokens never live in a pure
  frontend for long

### 3.2 Issuer

```text
Issuer: https://sso.example.com
```

Discovery (supported):

```text
GET https://sso.example.com/.well-known/openid-configuration
```

### 3.3 Core endpoints (first phase)

| Endpoint | Method | Notes |
|------|------|------|
| `/oauth/authorize` | GET | Authorization endpoint (sign-in UI / consent) |
| `/oauth/token` | POST | Token exchange (authorization_code / refresh_token) |
| `/oauth/revoke` | POST | Optional: revoke refresh / access tokens |
| `/oauth/userinfo` | GET | User info (needs an access token) |
| `/oauth/jwks` | GET | Public key set for clients verifying `id_token` |
| `/oauth/logout` or OIDC `end_session_endpoint` | GET/POST | Unified logout (extended in phase 2) |
| `/health` | GET | Liveness, public |

The sign-in page and dashboard are hosted on the same origin (`/login`,
`/activity`, `/overview`, `/directory`, `/clients`, `/audit-logs`, `/settings`,
`/integrations`, `/my-apps`). The dashboard JSON API is unified under
**`/api/v1/*`** (see [api-v1.md](./api-v1.md)).

### 3.4 Token types

| Token | Purpose | Notes |
|-------|------|------|
| `id_token` | Identity assertion (JWT) | The business side uses it to create its own session |
| `access_token` | Calls Signet userinfo or protected APIs | Not recommended as a long-lived business session |
| `refresh_token` | Refresh | Rotating and revocable |

After the callback, the business system (Cella) should issue **its own session**
(cookie or local JWT), use that for subsequent API authorisation, and cache the
mapping from `sub` to its local user key.

---

## 4. Identity and data model (logical)

### 4.1 Core entities

```text
User            A person (the sign-in subject)
ClientApp       A connected application (e.g. cella)
AuthorizationCode / RefreshToken / Session
(optional) Group / Membership   Groups and members, for claim mapping
(optional) Org                  Tenant placeholder; single-tenant for now
```

### 4.2 User (minimum fields)

| Field | Notes |
|------|------|
| `id` | Internal UUID |
| `sub` | OIDC subject (the stable external key) |
| `email` | Login name |
| `phone` | Optional contact number (plaintext; reserved for contact/recovery; **not SMS-verified**) |
| `display_name` | Display name |
| `password_hash` | Argon2 |
| `status` | `active` / `disabled` (frozen) |
| `role` | `admin` / `manager` / `member` |
| `mfa_required` | Policy: force MFA for this user |
| `totp_enabled` / `totp_secret` | Enrollment fact and secret |
| `created_at` / `updated_at` | |

### 4.3 ClientApp (a connected application)

| Field | Notes |
|------|------|
| `client_id` | e.g. `cella` |
| `client_secret_hash` | For confidential clients |
| `redirect_uris` | Exact allowlist |
| `post_logout_redirect_uris` | Optional |
| `grant_types` | `authorization_code`, `refresh_token` |
| PKCE | Always S256 (the `pkce_required` field was removed) |
| `scopes` | `openid`, `profile`, `email` |
| `enabled` | |
| `ip_allowlist_enabled` | True for new clients; can be turned off |
| `allowed_cidrs` | IP / CIDR list |

### 4.4 Claims (id_token / userinfo)

**Required:**

- `sub`
- `iss` = the effective issuer
- `aud` = `client_id`
- `exp` / `iat`
- `email` (when present)
- `name` or `preferred_username`

**Optional (may be empty early on):**

- `groups` / `roles` — starting data for the business side's role mapping, not a
  substitute for business ACLs
- `phone_number` — requires the `phone` scope

> Claims are **trimmed by scope**: `email` needs the `email` scope, `name` needs
> `profile`, `phone_number` needs `phone`, `groups` needs `groups`; `sub` is
> always present. See [client-integration.md](./client-integration.md).

---

## 5. Sign-in and logout flows

### 5.1 Sign-in (Cella example)

```text
User → Cella UI/API (not signed in)
     → 302 Signet /oauth/authorize
          ?client_id=cella
          &redirect_uri=https://<cella-host>/auth/callback
          &response_type=code
          &scope=openid profile email
          &state=...
          &code_challenge=...
          &code_challenge_method=S256
     → user signs in at Signet
     → 302 redirect_uri?code=...&state=...
     → Cella backend: code + code_verifier → Signet /oauth/token
     → validate id_token (iss/aud/exp/signature)
     → upsert the local user (keyed by sub)
     → create the Cella session
     → enter the application
```

### 5.2 Logout

1. Clear the local Cella session
2. (Optional) redirect to Signet's `end_session_endpoint` with
   `post_logout_redirect_uri`
3. Signet clears its own SSO session, so other connected subsystems require a
   fresh sign-in next time

The first phase may implement step 1 only; steps 2–3 are a unified-logout
enhancement.

### 5.3 Account lifecycle and roles (settled)

Signet is **not** an external account system: there is no public self-service
registration.

Roles:

| Role | Capabilities |
|------|------|
| `admin` | Full user/client management including deletion; global Settings (including the MFA switch); full audit; reset another user's 2FA; **cannot delete** audit records |
| `manager` | Create/freeze users; manage clients (no deletion); per-user `mfa_required`; audit visible without deletion events |
| `member` | Home + account menu: profile, password, optional/enrolled MFA |

Deletion-class operations (user delete, client delete, MFA reset, global
Settings) are **admin-only**.
Dashboard guide: [dashboard.md](./dashboard.md); HTTP API:
[api-v1.md](./api-v1.md).

### 5.4 First-deployment administrator

After startup migrations complete:

1. If a user with `role = 'admin'` and `status = active` exists → do nothing
2. Otherwise the **`/setup` page** is exposed: the first visit creates the
   administrator account and password in the browser (`POST /api/v1/setup`) and
   signs in immediately

`/setup` is concurrency-protected (a Postgres advisory lock) and writes the
`setup.complete` audit event on success. See [api-v1.md](./api-v1.md).

The "first business administrator" inside Cella is **Cella's** own bootstrap
problem, not a reason to make every Signet user a superuser.

---

## 6. Contract with business clients

**Full integration steps, request fields, token claims and troubleshooting**:
see [client-integration.md](./client-integration.md).

### 6.1 Business client OIDC configuration (summary)

| Setting (example name) | Value |
|------------------|-----|
| `OIDC_ISSUER` | Development `http://localhost:8443`; production `https://sso.example.com` |
| `OIDC_CLIENT_ID` | The `client_id` registered in the dashboard or through dynamic registration |
| `OIDC_CLIENT_SECRET` | The secret issued once when the client was created |
| `OIDC_REDIRECT_URI` | Exact allowlist entry, e.g. `https://<app-host>/auth/callback` |
| `OIDC_SCOPES` | `openid profile email` |

### 6.2 Client responsibilities

- Authorization code + PKCE S256; the backend exchanges the code with the secret
- Validate `id_token`; map local users uniquely by `sub`
- Business ACLs stay on the business side; Signet only authenticates
- Redirect unauthenticated users to Signet; handle 401 consistently
- Respect the client **Source IP allowlist** when enabled (see the integration
  guide)

### 6.3 Replaceability in development

Depend only on standard OIDC Discovery; the issuer is swappable, and business
code does not bind itself to Signet implementation details.

---

## 7. Security requirements

- Site-wide HTTPS (`sso.example.com`)
- `redirect_uri` **strict allowlist** (open redirects)
- PKCE S256 required
- `state` / `nonce` against CSRF and replay
- Short token TTLs; refresh **rotation**
- Passwords: Argon2; login audit includes the **client IP**
- **Brute-force protection**: consecutive failures lock the account
  (`SIGNET_MAX_LOGIN_ATTEMPTS` / `SIGNET_LOCKOUT_MINUTES`)
- **Password policy**: minimum length plus case/digit complexity; history reuse
  refused
- **MFA (TOTP + recovery codes)**: global and per-user enforcement; [mfa.md](./mfa.md)
- **TOTP secrets encrypted at rest**: `totp_secret` is AES-256-GCM encrypted at
  the application layer (key at `data/encryption.key` or
  `SIGNET_ENCRYPTION_KEY_PATH`); legacy plaintext rows are read transparently
- **Session management**: active-session list, single-session revoke, admin
  force sign-out; OIDC `end_session` unified logout
- **OIDC consent**: first authorization requires consent and is remembered;
  explicitly requested scopes are granted or refused as a whole, and unrequested
  optional scopes inside the client allowlist can be granted individually
  (GitHub-style)
- **groups claims**: user groups travel in `id_token` / `userinfo` as starting
  data for business role mapping
- **Client Source IP allowlist**: on by default for new clients (can be turned
  off); [client-integration.md](./client-integration.md)
- Dashboard and OIDC endpoints have separate permissions; the dashboard API is
  unified under **`/api/v1`**
- Keys: JWT RS256; JWKS publishes the public key
- Audit: sign-ins, admin actions, MFA/settings changes; Overview shows 24h/7d/30d
  login stats; CSV export and retention; client IP and browser/OS (parsed from
  `User-Agent`) are recorded
- Observability: `/metrics` exposes login/token/MFA counters and HTTP metrics
  (Prometheus text format); request logs carry `x-request-id` for correlation

> Implementation status (done/planned) plus the full key and configuration
> inventory: **[security.md](./security.md)**.

---

## 8. Technology choices (suggested, adjustable)

Aligned with the existing Rust stack so one team can maintain it:

| Layer | Choice |
|----|------|
| Language | Rust |
| HTTP | Axum |
| DB | PostgreSQL |
| Frontend (sign-in / dashboard) | Separate `dashboard/` directory: Vue 3 + Vite + Tailwind CSS v4, shadcn-vue-style; `dist` embedded in the Rust binary |
| Password | Argon2 |
| JWT | Asymmetric signing (RS256 or EdDSA) |

Crates and module split are settled during implementation; this document does not
bind implementation details.

---

## 9. Roadmap

### Phase 0 — contract and skeleton

- This design settles
- Repository `signetproject`, DNS certificate, base deployment manifests

### Phase 1 — minimum usable IdP (for business systems)

- User + ClientApp CRUD (config file / simple admin may come first)
- authorize / token / jwks / userinfo
- Sign-in page + PKCE
- Discovery document
- Client registration

### Phase 2 — sessions and operations

- Refresh rotation, revoke
- Unified logout
- Dashboard (user disable, app management, audit search)
- Monitoring and alerting

### Phase 3 — extensions

- groups/roles claims
- External IdP federation (WeCom, …)
- Multi-tenant / multi-environment isolation

### Phase 4 — security hardening (implemented except SMS verification)

Ordered by priority:

| Priority | Feature | Status | Notes |
|--------|------|------|------|
| P0 | Password reset/recovery | ✅ | `/api/v1/password-reset/*`; 30-minute single-use token; real SMTP delivery (503 without one) |
| P0 | **SMS-verified phone binding** | ⏳ | The only unimplemented item: needs an SMS gateway; `phone` is currently unverified contact information |
| P0 | RFC 7009 revocation endpoint | ✅ | Dedicated `/oauth/revoke` |
| P0 | WebAuthn/passkey + recovery codes | ✅ | Register/sign-in/manage; challenges in memory |
| P1 | New device/IP sign-in alerts | ✅ | `login_devices` + `auth.new_device` audit/alert mail |
| P1 | Global API rate limiting | ✅ | Per-IP sliding window, 429 on excess |

### Phase 5 — integrations and operations (implemented)

| Priority | Feature | Status | Notes |
|--------|------|------|------|
| P1 | OAuth dynamic client registration | ✅ | RFC 7591 `/oauth/register` + single-use registration token |
| P2 | SCIM v2 user/group sync | ✅ | `/scim/v2/Users`, `/scim/v2/Groups` |
| P2 | Webhook event delivery | ✅ | Async audit delivery with HMAC signatures |

### Phase 6 — monitoring and observability (partially implemented)

| Priority | Feature | Status | Notes |
|--------|------|------|------|
| P1 | HTTP metrics | ✅ | Request counts (by class) / in-flight / latency histograms on `/metrics` |
| P1 | Health-check hardening | ✅ | `/health` probes Postgres, 503 on failure |
| P2 | Alerting integration | ⏳ | Feed Prometheus metrics into Alertmanager |
| P2 | Tracing / request id | ✅ | `x-request-id` generation/passthrough/echo + tracing span correlation |

### Connectors and SAML (reviewed against peers; scope unchanged, with triggers)

A peer comparison (Keycloak / Authentik / Zitadel) re-examined two gaps, and the
conclusion is to **keep the original scope decision**:

**DingTalk / WeCom connectors — not built; start on demand.**
- The non-goals section already said so (§1.2): "no full WeCom/DingTalk sync
  (possible future IdP connectors)", with federation in Phase 3.
- This organisation's identity source is **Feishu** (its login connector, webhook
  alert format and e2e coverage); the repository has no DingTalk/WeCom consumer.
- Trigger: the first concrete system that needs DingTalk or WeCom sign-in/sync;
  implement then, following the Feishu connector's shape (an S–M each).

**SAML — not built, with technical justification.**
- The repository and every client speak OIDC; there is no SAML SP consumer.
- The Rust ecosystem has no mature SAML toolkit (compare Python's python3-saml or
  Java's OpenSAML): either an immature crate or hand-written XML signatures and
  canonicalisation — precisely the historical home of XML signature-wrapping
  attacks. The security review turns an L into an XL.
- **A bridge already exists**: Signet's generic OIDC upstream connector can sit
  behind a SAML-capable IdP (Keycloak/ADFS), turning "an upstream only speaks
  SAML" into a standard federation integration without Signet implementing SAML.
- Trigger: a downstream SP that cannot move to OIDC and must be connected;
  separate project, including a dedicated XMLDsig security review.

### Group identity and the organisation tree (implemented in 0.6.0)

- `users.groups` / `users.directory_groups` store `UUID[]` (migration `043`);
  reads resolve names through `signet_group_names()`, writes go through
  `signet_group_ids(names, src)`, and an unknown name creates a row for `src`
- `scim_groups` gained `parent_id` / `kind` (department|group) / `source`
  (local|scim|directory) and became the single group entity and tree
- The OIDC `groups` claim still emits names, **direct membership only**, with no
  ancestor inheritance
- Directory sync writes ids into `directory_groups` (`src='directory'`) and, on a
  successful run with `sync_groups` enabled, sweeps empty child-less directory
  groups (tombstones)
- SCIM `/Groups` only sees `source='scim'` groups; on delete, children move up
  and members are released
- The dashboard gained a **Directory** page (tree + members; staff manage, only
  admin deletes; non-local nodes can only be moved)

---

## 10. Configuration and key naming

Stop using the `OSS_*` prefix. Suggested:

```text
SIGNET_DATABASE_URL=
SIGNET_HTTP_BIND=0.0.0.0:8443
# Optional: only the initial value before the first save; after Dashboard ->
# Settings -> Server identity saves one, the database wins
SIGNET_ISSUER=https://sso.example.com
SIGNET_JWT_PRIVATE_KEY=   # or a KMS reference
```

The client side (Cella) may use `OIDC_*` or `SIGNET_*` as long as the team picks
one; **never** use `OSS_` for this service.

---

## 11. Terminology

| Legacy phrasing | Standard term |
|------------|------------|
| OSS single sign-on | **Signet** |
| OSS login page | Signet sign-in (`sso.example.com`) |
| Alibaba Cloud OSS | Object storage (unrelated to this project) |

---

## 12. Open questions

1. Final domains and `redirect_uri` values for each business system (registered
   in the dashboard or through dynamic registration)
2. Cookie session vs business-side JWT session (each business decides; Signet
   only issues OIDC tokens)
3. Whether production uses separate issuer / keys / database (isolated from
   development)

Settled: users are local accounts created by administrators in the first phase;
confidential clients + PKCE; development never uses the production domain.

---

## Revision history

| Date | Change |
|------|------|
| 2026-08-13 | First draft: Signet positioning, OIDC+PKCE, public/intranet topology, Cella boundary and phasing |
| 2026-08-13 | Account model: admin provisioning + bootstrap admin; development issuer and the `dashboard/` frontend convention |
| 2026-08-13 | Implementation: brute-force protection, password policy, session management, groups claims, OIDC consent, audit export/retention, Prometheus metrics |
| 2026-08-13 | Roadmap gained Phase 4/5: password reset, refresh rotation/revocation, WebAuthn, sign-in alerts, rate limiting, client management + dynamic registration, SCIM, webhooks |
| 2026-08-13 | Implemented Phase 4/5/6 (except SMS verification, alerting and tracing): revocation, password reset, passkeys, sign-in alerts, rate limiting, dynamic registration, SCIM, webhooks, HTTP metrics and health checks |
| 2026-08-13 | Added: user self-service MFA disable (when not enforced), the Users MFA status column, optional-scope consent, the `phone` scope / `phone_number` claim, `x-request-id` tracing |
