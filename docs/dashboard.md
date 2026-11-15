# Signet Dashboard

> English · [简体中文](./zh-CN/dashboard.md)

Vue 3 + Vite + Tailwind CSS v4, built output embedded in the Rust binary
(`rust-embed`).
Develop: `pnpm dev` under `dashboard/` (proxies `/api` → `:8443`).

---

## 1. Roles and navigation

| Role | Visible areas |
|------|----------|
| `admin` | Activity, My apps, Overview, Directory, Clients, Audit logs, **Settings** |
| `manager` | Activity, My apps, Overview, Directory, Clients, Audit logs (no Settings; the audit view hides deletion events) |
| `member` | Activity, My apps; the account menu (profile / password / 2FA / sessions) |

`Activity` is visible to every role (`/activity`): non-staff land there by default
after signing in, and it shows the personal security summary plus that user's own
sign-in and account/security events.

Route guards: `meta.staff` / `meta.admin`.

---

## 2. Page capabilities

### Activity (all roles)

- **Personal security summary** at the top: last sign-in (time + browser/OS), active
  sessions, 2FA status + passkey count, authorized applications
- Below it, the current user's own sign-in and account/security events
  (`GET /api/v1/me/activity`, filtered by `actor_user_id`, available to every role,
  and the response includes `summary`)
- Paged, with IP / browser / OS and time; the empty state explains why
- Positioned as the personal view, as opposed to Overview's operational one

### My apps (all roles, `/my-apps`)

GitHub "Developer settings"-style self-service: **any signed-in user** can register
an OAuth client and becomes its owner, with no administrator approval involved.

- **Register an application**: name (required, shown on the consent screen) +
  redirect URIs (required, http(s), no fragment) + optional scopes (default
  `openid profile email`); submitting returns a `client_id`, and the
  `client_secret` is shown exactly once (with ready-to-paste `.env` /
  `config.toml` snippets)
- Defaults match RFC 7591 dynamic registration: `authorization_code` +
  `refresh_token`, PKCE, no IP allowlist
- Owners can **Edit** (name / redirect URIs), **Rotate** (a new secret; the old one
  stops working immediately) and **Delete** (its consents and tokens go with it)
- Only the owner's own clients are visible or operable; administrators keep global
  control on **Clients** (Name and Owner columns)
- Backend: `/api/v1/me/clients*`; audit actions reuse `client.create /
  client.update / client.rotate_secret / client.delete` with
  `detail.via = "self_service"`

### Overview

- User / role / client totals (global stat cards)
- **App filter** (top right): all apps, one connected app, or `Signet (direct)`
  (sign-ins with no app attribution). The filter applies to the login totals, the
  trend chart, recent sign-ins and the distribution charts below
- **Login trend**: 30 days, overlaying daily / 7-day rolling / 30-day rolling
  counts; the 24h · 7d · 30d totals stay in the top right
- **Logins by app**: per-app sign-ins over 30 days (top 10 horizontal bars;
  `(direct)` grouped together)
- **Browsers / OS**: browser and operating-system distribution over 30 days
- **Setup guide**: for administrators on a deployment that has not finished setup — a
  live check panel (issuer reachability/HTTPS, SMTP completeness, first enabled
  client). Required steps cannot be dismissed until they pass; SMTP is optional and
  does not block. Once dismissed it reopens from the header (`Setup guide · n/4`)
- Sign-in detail lives in **Audit logs** (Overview no longer inlines a recent list,
  to avoid duplicating Audit logs / Activity)

### Directory (staff)

Users and the organisation tree on one page (frontend route `/directory`, API
`/api/v1/admin/users` and `/api/v1/admin/groups`). The directory-sync sources have
their own page at `/directory-sync`.

### Clients

- Create / Edit / Enable · Disable / Rotate secret. Delete is administrator-only
- **Disabled** rows are visually marked
- **Test drive**: an enabled client gets a one-click round trip over the built-in
  `{issuer}/oauth/test-callback/{client_id}` redirect URI — real authorize → sign-in
  → consent → callback. The result page lists what passed (authentication,
  scope, redirect match, single-use code). The token exchange with the secret and
  the PKCE verifier is out of scope (the server stores only the secret's digest), so
  a real integration is still the final check
- After rotation the plaintext secret is shown once, together with copyable `.env` /
  `config.toml` snippets prefilled with the issuer, client id, scopes and redirect URI
- **Source IP**: IP allowlists default to on for new clients and can be turned off
  (Unrestricted); Edit changes the CIDR list. Authorize comes from the browser, so the
  allowlist must include user network ranges, not only the BFF's egress

### Audit logs

- Search (including IP), filters for action / app / browser / OS, sortable columns
  (including **Login IP**)
- Shows actor, IP, app (`client_id` badge), browser/OS (**Device** column), action,
  resource
- **Click any row** to see the event detail (app, full detail JSON, User-Agent)
- **Export CSV**: exports the current filtered result (including the `client_id`
  column)

### Settings (admin only)

A left sub-nav groups nine sections (General / Access / Operations / Developer)
and shows one at a time (below `lg` it becomes a horizontally scrolling tab strip).
The active section is kept in `?section=`, so a reload or a shared link lands on the
same pane:

- **Server identity**: the issuer, tagged with its source (`default` /
  `environment` / `saved here`). Precedence is **database > `SIGNET_ISSUER` > default**:
  a saved value wins and applies immediately (peer replicas converge within 30
  seconds). The first save locks the field; changing it again needs an explicit
  **Unlock to change** (a confirm dialog and an audited event). **Reset override** clears
  the saved value and falls back to the environment/default. **Every save asks for
  confirmation first**, listing
  the impact (outstanding tokens stop validating, clients and third-party SSO
  callbacks need updating)
- **Branding**: the product name (the console, the title and mail) and the **logo
  upload** (PNG/JPEG/WebP ≤256 KB, SVG refused; served from the sidebar and every
  sign-in / reset / setup / consent page; without one, the product name's initials). A replaced logo gets a fresh versioned URL, so it applies without a hard
- **Security**: the global **Require MFA for all users**
- **Email domains**: the sign-in / provisioning domain allowlist (warns when saving
  would lock the acting administrator out)
- **SSO / federation**: **JIT provision on SSO** (whether a first third-party sign-in
  with a verified email and no local account creates one)
- **CAPTCHA**: Turnstile / hCaptcha on sign-in and password reset
- **Runtime policies**: session/token lifetimes, login attempts and lockout, password
  length/history, audit retention, the global rate limit. Saved values apply
  immediately; fields nobody saved keep following the environment
- **Email relay (SMTP)**: host / port / username / From, with a test message after
  saving; the password is write-only and never echoed back
- **API tokens**: machine credentials for the admin API (a PAT). The plaintext is shown
  once and only its hash is stored

### Integrations (admin only)

- Webhooks: list / create / delete, type **Feishu** or **Generic**, plus the latest
  delivery status
- **Third-party sign-in**: add, edit, delete and enable/disable via GitHub / Google /
  Feishu / WeChat Open Platform / generic OIDC; each provider shows its **Callback URL**
  and the number of bound accounts; an empty secret on edit means "keep unchanged"
  (secrets are never returned)
- SCIM v2: the enable state and its endpoint, plus **generate / rotate / revoke** of the
  bearer token (the plaintext is shown once; only its hash is stored)
- WebAuthn: RP ID / RP Origin

### Account menu (top right, every role)

- Two-factor auth: enroll / rebind / rotate recovery codes; **Disable MFA** when not
  enforced (a policy hint and no button while enforced)
- Edit profile: display name and **contact phone** (live phone uniqueness excluding self)
- Active sessions: the current sessions (IP, device, time), revoke one or "all except
  the current one"
- Passkeys: list / register (WebAuthn) / delete
- **Linked accounts**: view bound third-party accounts and **Unlink**; below,
  **Link a provider** lists every enabled provider that is not yet bound (GitHub /
  Google / Feishu / WeChat / OIDC), and clicking it jumps to the upstream
  authorization, binding to the **currently signed-in user**. Alternatively start
  from the sign-in page: choosing a third-party provider and, when unmatched,
  signing in with a password within 15 minutes completes the binding (for any
  enabled provider)
- The one-time recovery-code page offers **Copy** and **Download** (both the enroll
  and regenerate entry points)

---

## 3. Sign-in UX

1. Password (or **Passkey**: enter the email, then one click)
2. **Third-party sign-in**: when an administrator has enabled providers, an "or
   continue with" divider and buttons appear below the password form (GitHub /
   Google / Feishu / WeChat / custom OIDC); clicking jumps to the upstream
   authorization
3. **Binding result** (after the callback):
   - Already bound, or the email matches automatically → a session is issued and the
     user enters the system
   - No matching local account → when JIT is on and the upstream supplies a verified
     email, the account is provisioned and signed in; otherwise the user returns to
     the sign-in page with `?sso_error=no_matching_account` (a password sign-in
     within 15 minutes completes the binding)
   - An SSO callback while already signed in → binds the upstream identity to the
     current user
4. If `mfa_required` → TOTP or a recovery code
5. If `enroll_required` → scan to enroll → one-time display of recovery codes
6. After an OIDC `return_to` (`/oauth/...`) completes, redirect back to authorize
7. Other third-party failures also return to the sign-in page with the matching
   `?sso_error=` (`unknown_provider` / `provider_disabled` / `state_mismatch` /
   `upstream_error` / `access_denied` / `missing_code` / `email_required`, …).
   Cancelling on Feishu et al. is `access_denied` (a friendly notice, not a system
   fault). `email_required`: Feishu etc. returning no email refuses the first
   bind/sign-in and suggests enabling the email permission (WeChat excepted;
   already-bound identities can still sign in).
8. Forgot password: the sign-in page link → `/reset-password`, a two-step reset
   (request → confirm)

---

## 4. API prefix

Every dashboard call is a JSON request under **`/api/v1`**: session cookie auth, no CSRF
token (the cookie is `SameSite=Lax`), errors as `{ "error": "..." }`. See
[api-v1.md](./api-v1.md).

