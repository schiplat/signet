# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

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
