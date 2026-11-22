# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [Unreleased]

## [0.6.5] - 2026-11-22

Client form completion: the dashboard can now set the back-channel logout URI
the API always accepted, and bulk disables no longer leave relying parties
holding a live session.

### Fixed

- **Batch disable now sends OIDC Back-Channel Logout** like the single-user
  path: `POST /admin/users/batch-disable` (and the bulk disable helper behind
  it) revoked sessions silently, leaving a relying party's session alive until
  its access token expired even though a one-account disable would have
  notified it. The delete keeps its single-statement shape and `RETURNING`
  drives the notification, so only subjects that actually lost a session are
  told.
- **The Clients page renders the Back-channel logout URI field** (Dashboard →
  Clients, create and edit): `client_apps.backchannel_logout_uri` was accepted
  and used by the API, but no input existed, so it could not be set from the
  dashboard.

### Added

- **Scopes must include `openid`** is validated before submit in the Clients
  create/edit and My apps create dialogs, matching the backend rule. An empty
  scopes field on create still takes the default trio; clearing it on edit is
  rejected rather than surfacing a distant 400.

### Changed

- **Dialog submit errors render inside the dialog.** The page-level banner sat
  behind the teleported modal, so backend failures (invalid redirect URI,
  duplicate client_id, …) were invisible while the dialog stayed open.

### Security

- **`url` 2.5.8 → 2.5.9** (RUSTSEC-2026-0592): `Url::origin()` could overflow the
  stack on nested `blob:` URLs. Signet parses client-supplied redirect and
  logout URIs, so the dependency is on an input path; the bump is lockfile-only
  because the manifest already required `2`.

## [0.6.4] - 2026-11-20

Dashboard accessibility and polish: every dialog becomes a real dialog,
form fields are announced, and the theme is committed to light.

### Added

- **Dialog accessibility across all 22 dialogs** (Dashboard → Clients,
  My apps, Users, Directory, Integrations, Directory sync, TopNav account
  dialogs): `role="dialog"` + `aria-modal` + accessible names, focus moved
  into the panel on open (first field) and back to the trigger on close,
  Tab containment, and a counted body-scroll lock. Escape stays each
  dialog's own policy: form dialogs close as their backdrop click did
  (busy-guarded), the secret-reveal dialog has no Escape at all — a one-time
  secret must not be lost to a stray keypress — and the confirm dialog
  focuses **Cancel**, never Confirm, so Enter cannot confirm a delete by
  reflex.
- **Label associations for every form field** in those dialogs (`for`/`id`,
  namespaced per dialog with `useId`): clicking a label focuses its field and
  screen readers announce field names. The SCIM-token and directory-source
  close buttons, previously bare, gained accessible names.

### Changed

- **Light theme is the theme.** The stylesheet defines one token set and no
  `.dark` layer, but scattered `dark:` utilities followed the OS preference,
  producing a light dashboard with dark-tinted patches. All removed; the QR
  code's foreground colour key is untouched.
- **Every dialog has a scroll path.** Six dialogs (register/edit client,
  webhook, SCIM token, sign-in provider, secret reveal) kept a
  centre-no-scroll layout whose overflow was unreachable; all use the
  top-aligned scrollable overlay pattern now, and the profile/password
  panels cap at `90vh`.
- **Directory page**: the Organization tree's member counts and the header
  plus button share one centred 28px column.

### Security

- **chrono accepted by audit policy** (`RUSTSEC-2026-0543`, unmaintained,
  informational): recorded in `.cargo/audit.toml` with reason and end
  condition, matching that file's "every entry is a decision" format. No
  known vulnerability; no dependency change.

## [0.6.3] - 2026-11-19

Security dependency bump and public-repo hygiene: the lettre SMTP advisories,
neutral example names in docs and e2e, and a Buz SSO recipe.

### Added

- **Buz SSO recipe** in the client integration guide (en + zh): the client to
  register under Dashboard → Clients (redirect URI, scopes, grant types), the
  source-IP allowlist caveat for a multi-user SSO client, and the
  `[auth.oidc]` block for Buz's `manager.toml`, including the
  issuer-exact-match and JIT provisioning notes.

### Changed

- **Deploy compose** takes `SIGNET_DATABASE_URL` and the startup-only
  `SIGNET_*` settings from the environment, with the database URL required
  rather than falling back to the localhost default. `deploy/docker-compose.env-file.yml`
  keeps dotenv compatibility as an optional overlay, not the primary path.
- **Neutral example names** — an internal subsystem name and an internal host
  name no longer appear in the READMEs, docs, the deploy compose comment or
  test fixtures; the docs' example client is `demo-app`. The `e2e/` suite
  defaults to loopback, derives the repo path from the checkout, and no longer
  ships host names, addresses or credentials — `start_instances.sh` also
  honours the `E2E_*` variables now instead of duplicating hardcoded values.

### Removed

- **OSS config-bundle publishing** — the image workflow now only builds and
  pushes the multi-arch image; `deploy/env.tpl` is gone. Deployment systems
  provide `.env` / environment variables through their own pipeline.

### Security

- **lettre 0.11.24** — picks up six upstream RustSec advisories published
  2026-11-17: STARTTLS response injection, SMTP command injection via missing
  dot-stuffing, unbounded SMTP reply buffering (memory exhaustion),
  denial-of-service panics on malformed `EHLO` replies / mailbox display names,
  and messages misrouted for addresses with a quoted local part. Dependency
  bump only; no API change.

## [0.6.2] - 2026-11-15

Public self-registration with an explicit readiness gate, plus release and
documentation cleanup.

### Added

- **Public self-registration, off by default.** Settings → Public sign-up adds
  `GET/PATCH /api/v1/admin/settings/signup`; enabling runs a preflight against
  the live configuration (relay host/port/From, CAPTCHA provider/site
  key/secret) and refuses with every blocking problem listed. A request writes
  `signup_requests` only and sends a 30-minute, single-use verification link;
  confirmation creates a plain `member` with no groups, marks the address
  verified and does not sign in. Public endpoints:
  `GET /api/v1/signup/status`, `POST /api/v1/signup` and
  `POST /api/v1/signup/confirm`; the dashboard adds `/signup`,
  `/signup/confirm` and a **Create account** link on sign-in. Responses are
  generic for new, pending and existing addresses; per-address/per-IP throttles,
  CAPTCHA, the domain allowlist and audit events cover abuse. The request path
  re-checks both prerequisites (503 if either disappears).

### Changed

- **Public sign-up preflight** is a single checklist with `Ready` /
  `Action needed` / `Advisory` rows, concise copy, one link per fix and a
  **Re-check** action. The settings API returns `ready`, `problems` and
  `warnings`; an unusable relay `From` or port blocks enabling alongside a
  missing CAPTCHA.
- **README quick start** links to the Releases page instead of a versioned
  asset URL, and the release example uses 0.6.2.
- **Dashboard toolchain** moves to Vite 6.4.6 and vue-tsc 3.3.14 (development
  only); `pnpm audit` is clean for both runtime and dev dependencies.
- **Docker images** are published as one multi-arch manifest for `linux/amd64`
  and `linux/arm64`, built from the matching release binaries.

## [0.6.1] - 2026-11-15

### Added

- **Branding logo upload** — Settings → Branding accepts PNG / JPEG / WebP
  (≤256 KiB, SVG rejected because a same-origin navigation could execute
  script) and serves it from the public versioned endpoint
  `GET /api/v1/branding/logo`; every brand surface (sidebar, sign-in, setup,
  reset, consent) renders the logo, falling back to the product name's
  initial when unset. Upload/remove is audited
  (`settings.branding_logo_update` / `_remove`).

A focused release: a redesigned Settings page, an uploadable logo, and the
issuer made genuinely dashboard-first.

### Changed

- **Settings redesign** — the page is now a left sub-nav (General / Access /
  Operations / Developer) showing one section at a time; the active pane is
  kept in `?section=`, so a reload or a shared link lands on the same section.
  A "Reset override" action covers recovery after a saved issuer.
- **Brand name consistency** — the consent prompt and the document title use
  the configured product name instead of the hardcoded "Signet"; a late
  branding load only replaces the brand part of the title.
- **Issuer precedence is now database > environment** — a value saved under
  Dashboard → Settings → Server identity wins over `SIGNET_ISSUER`, so the
  setting stays editable from the web even when the variable is present. The
  variable seeds the value until the first save. Recovery for a wrong saved
  value: the new `DELETE /api/v1/admin/settings/server` ("Reset override",
  audited as `settings.issuer_reset`) clears the override and falls back to
  the variable or the built-in default; the same row can be deleted in SQL.
  `deploy/env.tpl` still ships `SIGNET_ISSUER` as the production default, but
  it no longer locks the dashboard field.

### Documentation

- `docs/` now holds the English documents (the source of truth) and
  `docs/zh-CN/` the Chinese translations; every page links to its counterpart.
  README download commands use `/releases/latest` so they no longer point at a
  tag that may not exist yet.

### Breaking

- `GET /api/v1/admin/settings/server` no longer returns `env_locked`, and
  PATCH is no longer refused with 409 when `SIGNET_ISSUER` is set: the saved
  value wins. Integrations that keyed on `env_locked` should read `source`
  (`environment` / `database` / `default`) and the new `env_fallback` flag.

## [0.6.0] - 2026-11-14

A mid-sized release: self-service clients, a dashboard-managed issuer, a
first-run guide, and a dashboard-wide visual pass — on top of the M2M, outbox,
SMTP, CAPTCHA and branding work landed since 0.5.0.

### Added

- **Groups and departments as one tree** — Dashboard → Directory manages an
  organisational tree (`kind = department | group`), with local membership,
  rename/move (cycles rejected), member search and pagination. The OIDC
  `groups` claim still publishes **direct** group names only.
  `users.groups` / `users.directory_groups` now store group ids (migration
  `043`) and resolve names on read, so renames no longer rewrite every user.
  Nodes carry a `source` (`local` / `scim` / `directory`): SCIM and directory
  nodes appear in the tree and can be moved, while their name, membership and
  existence stay owned by the source. Directory sync sweeps its empty,
  child-less groups after a successful run.
- **Self-service OAuth clients (My apps)** — any signed-in user can register an
  application (name + redirect URIs) and manage it: rotate the secret, edit the
  redirect targets, delete it. Every operation is owner-scoped in SQL; the
  plaintext secret is shown once and only its digest is stored.
- **Client ownership in the admin surface** — `client_apps.client_name` and
  `owner_id` (migration `042`), plus Name / Owner columns on Dashboard →
  Clients; the owner is also shown (read-only) in the edit dialog.
- **Web-managed issuer** — Dashboard → Settings → Server identity. Precedence
  is `SIGNET_ISSUER` > database > built-in default; the environment keeps the
  field read-only (recovery path). The first save locks the value; further
  changes require an explicit, audited unlock. Changes apply immediately to the
  running process and peer replicas converge within 30 seconds.
- **First-run setup guide** — administrators see a live check panel on Overview
  (issuer reachability/HTTPS/origin match, SMTP completeness, first enabled
  client with valid redirect URIs). Required steps must pass before the guide
  can be dismissed; every check is read-only and can be re-run on demand.
- **Prefixed credentials** — generated client ids and secrets now carry
  `sgn_cl_` / `sgn_cs_` prefixes (registration tokens `sgn_reg_`), so they are
  recognisable in logs, configs and secret scanners.
- **Users import dialog** with a downloadable JSON template (only `email` is
  required) and a server-side dry-run preview before anything is written.
- **RFC 7591 interoperability** — dynamic registration accepts the standard
  space-separated `scope` string (alongside the native `scopes` array) and
  persists `client_name`.
- Since 0.5.0: M2M tokens + introspection + step-up auth, JWT claim mapping,
  back-channel logout, self-service email change, durable webhook/email outbox,
  dashboard SMTP relay configuration, CAPTCHA gate (Turnstile / hCaptcha),
  admin API machine credentials (`sgn_pat_…`), runtime branding, optional OTLP
  trace export.

### Changed

- **Users and Groups merged into one Directory page** (`/directory`): an
  organisation tree on the left filters a full user table on the right
  (search/sort/pagination/import/export/create all retained); `/users` and
  `/groups` redirect. Directory sync moved to `/directory-sync`.
- **Dashboard visual system unified** — all page cards share `surface-card`;
  tables use the same container, header, row divider and hover treatment;
  crowded row actions collapse into a vertical `⋮` menu; the sidebar footer is
  a single aligned `brand · version` line.
- **Register Client** shows only the required fields (client id, redirect URIs)
  up front; everything else lives under **Advanced options**, and the IP
  allowlist now defaults to **off** (matching RFC 7591 registration).
- Session/MFA cookie `Secure` is derived from the **effective** issuer on each
  response, so switching the issuer to https from the dashboard secures cookies
  without a restart.
- The `client_name` accepted by RFC 7591 is stored rather than discarded.

### Fixed

- `RUSTSEC-2026-0538` (`quinn-udp` receive loop could spin after a truncated
  datagram) — lockfile updated to the patched 0.5.16.
- Startup logging printed the boot-time issuer even when the dashboard value
  was in force; the effective issuer is now the single one logged.
- Unused leftover in the settings view (`smtpEdit`) that broke `pnpm typecheck`.

### Security

- The issuer endpoints are admin-only, reject non-origin values, refuse to
  override `SIGNET_ISSUER`, lock after the first save and audit both the change
  and the unlock.
- Self-service client endpoints return 404 (not 403) for resources owned by
  another user; deleting a client cascades to its consents and tokens.
- Credential prefixes do not change entropy or storage: secrets remain keyed
  digests, and the prefix is part of the digested material.

### Documentation

- README (EN/ZH) feature list, API reference (`/me/clients`, `/admin/settings/server`),
  dashboard guide, security notes, integration guide and `.env.example` updated
  for the features above.
