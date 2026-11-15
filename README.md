# Signet

Unified identity authentication (SSO / OIDC IdP) service.

> Language: English · [简体中文](./README.zh-CN.md)

- **Production entry (future)**: `https://sso.example.com`
- **Issuer**: defaults to `http://localhost:8443`; the public value is set after first sign-in under **Dashboard → Settings → Server identity**. `SIGNET_ISSUER` is optional: it seeds the value until the first dashboard save, after which the saved value wins
- **First integrating app**: Cella (internal subsystem); clients register through the generic channel (Dashboard → Clients, self-service **My apps**, or RFC 7591 dynamic registration), with no built-in presets

> Naming note: this project is an SSO, **not** Alibaba Cloud Object Storage (OSS).

## Quick Start

Three ways to get a server running. **The release binary is the recommended way**: each [GitHub Release](https://github.com/schiplat/signet/releases) ships self-contained `linux-amd64` / `linux-arm64` / `macos-arm64` binaries with the dashboard embedded at compile time — one file plus a PostgreSQL, no Rust or Node toolchain. DB migrations are embedded too and run automatically on startup.

**A. Release binary (recommended)**

Download the asset for your platform from the [Releases page](https://github.com/schiplat/signet/releases) (`linux-amd64`, `linux-arm64` or `macos-arm64`), then:

```bash
# 1. Rename the downloaded asset to `signet`
chmod +x signet-<platform> && mv signet-<platform> signet

# 2. Start a PostgreSQL matching the built-in default connection string
#    (signet/signet@127.0.0.1:5433/signet) — skip if you already run one
docker run -d --name signet-db -p 5433:5432 \
  -e POSTGRES_USER=signet -e POSTGRES_PASSWORD=signet -e POSTGRES_DB=signet \
  postgres:16-alpine

# 3. Run — reads .env from the working directory (see Configuration below)
./signet
```

**B. Docker image**

Each release also publishes a multi-arch runtime image (`linux/amd64`, `linux/arm64`) to Docker Hub + ACR. The pull-only production stack lives in [`deploy/`](./deploy/):

```bash
cd deploy
cp ../.env.example .env   # edit SIGNET_*; set SIGNET_IMAGE=<registry>/signet:<tag>
docker compose up -d
```

Production layout (external Postgres, keys volume): [docs/deploy.md](./docs/deploy.md).

**C. Build from source (development)**

Prerequisites: Rust stable, Node 20+ with pnpm, and Docker (only to run a PostgreSQL).

```bash
# 1. Start Postgres — matches the built-in default connection string; no
#    configuration needed
docker compose -f build/docker-compose.yml --profile dev up -d db

# 2. Build the dashboard — rust-embed bakes dashboard/dist into the binary at
#    compile time, so it must exist before cargo run
cd dashboard && pnpm install && pnpm build && cd ..

# 3. Start the server
cargo run -p signet
```

### Configuration

All three options read the same environment: the binary loads `.env` from its working directory, the compose files inject the same variables. Only the database URL is needed to boot — the issuer can be left unset and configured in the dashboard after the first sign-in. `.env.example` is the full annotated reference.

```dotenv
SIGNET_DATABASE_URL=postgres://signet:signet@127.0.0.1:5433/signet
# Optional override — leave unset to manage the issuer in the dashboard:
# SIGNET_ISSUER=https://sso.example.com
```

| Setting | Notes |
|---------|-------|
| `SIGNET_DATABASE_URL` | PostgreSQL connection string (the value above is the built-in default, matching the dev `db` container) |
| `SIGNET_ISSUER` | **Optional.** Public origin clients use to reach this IdP; must not end with `/`. Precedence is **database > environment > built-in default**: a value saved under **Dashboard → Settings → Server identity** wins (hot-applied, locked after the first change), while the variable only seeds the value until that save. `Reset override` in the same page (or `DELETE /api/v1/admin/settings/server`) clears the saved value and falls back to the variable. An https effective issuer also turns on `Secure` cookies |
| `SIGNET_HTTP_BIND` | HTTP listen address; default `0.0.0.0:8443` |
| `SIGNET_TRUSTED_PROXIES` | Only behind a reverse proxy: comma-separated proxy IPs/CIDRs allowed to assert `X-Forwarded-For` |
| Keys | `./data/jwt_private.pem` and `./data/encryption.key` are auto-generated on first boot — **back them up**: losing or rotating them invalidates issued tokens and stored TOTP secrets |

Operational policy — session and token lifetimes, login attempts and lockout, password length/history, audit retention, the global rate limit — can be changed at runtime under **Dashboard → Settings → Runtime policies**; no restart or `.env` edit. The matching `SIGNET_*` variables are only fallbacks for fields nobody has saved there (the UI marks which ones are still inherited).

The first administrator is **not** configured via the file: on first boot the dashboard redirects to `/setup` to create it.

### First run

Open **http://localhost:8443** — the first visit redirects to **`/setup`**, where you create the first administrator and sign in. On a real deployment, set the public issuer next under **Dashboard → Settings → Server identity** (HTTPS origin, no trailing `/`): it is stored in the database, overrides `SIGNET_ISSUER`, applied immediately, and locked after the first change. The Overview setup panel keeps flagging incomplete steps until the issuer, SMTP and first client are configured.

**Try SSO:** register a client under **Dashboard → Clients** (staff; the secret is shown once, together with ready-to-paste `.env` / `config.toml` snippets); any signed-in user can also register their own under **Dashboard → My apps**. Then click **Test drive** in the Clients row: a new tab walks the real authorize → sign-in → consent → callback round trip.

**(Optional) example client** for the full integration in five minutes:

```bash
cd examples/axum-oidc-client
export OIDC_ISSUER=http://localhost:8443 OIDC_CLIENT_ID=<id above> OIDC_CLIENT_SECRET=<secret above>
cargo run
# open http://127.0.0.1:3000 → Sign in → signed in through SSO
```

For the hot-reload dev server (`:5173` proxying `:8443`), see [docs/local-development.md](./docs/local-development.md). Client integration guide: [docs/client-integration.md](./docs/client-integration.md).

## Features

- OIDC IdP: authorize / token / PKCE / refresh / userinfo / JWKS / end_session / revoke
- Dashboard: a combined **Directory** (users + organisation tree), clients, audit logs, overview stats (client-scoped), MFA, passkeys, webhooks, SCIM
- **Groups & departments as one tree**: Dashboard → Directory manages an organisational tree (`department` / `group`), membership and move/rename with cycle protection; the OIDC `groups` claim publishes direct group names. SCIM- and directory-owned nodes appear in the tree but stay managed by their source
- **Self-service OAuth clients**: any signed-in user can register and manage their own app (name + redirect URIs) under Dashboard → My apps — owner-scoped, secret shown once, admins keep global control (Name / Owner columns)
- **Web-managed issuer**: the public issuer is set in Dashboard → Settings → Server identity (DB > `SIGNET_ISSUER`, audited, locked after the first change; **Reset override** restores the environment/default). **Settings is split into a left sub-nav** (General / Access / Operations / Developer) with the active section in `?section=`, so reloads and shared links land on the same pane
- **Branding**: product name + **logo upload** (PNG/JPEG/WebP ≤256 KiB, SVG rejected), applied to the sidebar, sign-in, setup, reset and consent pages — no redeploy
- **Public sign-up (opt-in)**: Settings → Public sign-up, off by default and only enabled with SMTP + CAPTCHA ready. A request creates no account until a 30-minute single-use email link is confirmed; new accounts are plain `member`s with no groups. Sign-in shows **Create account** only when the switch is on
- **First-run setup guide**: Overview shows administrators a live check panel (issuer reachability/HTTPS, SMTP completeness, first enabled client) until the required steps pass
- **Runtime policies** (token/session lifetimes, lockout, password policy, audit retention, rate limit) edited in the dashboard — DB-backed, no redeploy
- **Signing-key rotation** (`signet keys rotate` / `keys prune`) with a JWKS key ring that keeps outstanding tokens verifiable
- **Third-party sign-in** (identity federation): GitHub · Google · Feishu · WeChat Open Platform · generic OIDC  
  Binding: verified email match → auto-link; else **JIT create** a `member` when Settings → JIT is on (default; also `SIGNET_SSO_JIT_PROVISION` fallback) and the provider returns a verified email; otherwise stash pending identity (15 min) for password bind. Details: [docs/api-v1.md §12](./docs/api-v1.md#12-third-party-sign-in-identity-federation)

![Dashboard overview](./docs/screenshot_overview.png)

## Documentation

| Document | Contents |
|----------|----------|
| [docs/README.md](./docs/README.md) | **Documentation index** — start here |
| [docs/design.md](./docs/design.md) | Overall design, roles, security, deployment topology |
| [docs/security.md](./docs/security.md) | **Security design summary** (credential storage, auth, sessions, MFA, OIDC, audit, keys) |
| [docs/client-integration.md](./docs/client-integration.md) | **Client OIDC integration** (authorize/token/PKCE/IP allowlist) |
| [docs/integrations.md](./docs/integrations.md) | **Integrations** (RFC 7591 dynamic registration · Webhooks/Feishu · SCIM v2) |
| [docs/api-v1.md](./docs/api-v1.md) | **Dashboard HTTP API** (unified `/api/v1/...`, incl. SSO federation) |
| [docs/mfa.md](./docs/mfa.md) | TOTP / recovery codes / global & per-user enforcement |
| [docs/dashboard.md](./docs/dashboard.md) | Dashboard pages & permissions |
| [docs/groups.md](./docs/groups.md) | **Groups & departments** (tree, membership, sources, API, claim semantics) |
| [docs/directory-sync.md](./docs/directory-sync.md) | **Directory sync** (LDAP / HTTP JSON pull, bind-through login, scheduler, `signet sync` CLI) |
| [docs/deploy.md](./docs/deploy.md) | **build/ vs deploy/** (Dockerfiles, local & production compose, `/app/data` keys) |
| [CHANGELOG.md](./CHANGELOG.md) | Release notes and breaking changes |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | Development workflow, commit rules and local checks |
| [SECURITY.md](./SECURITY.md) | Vulnerability reporting and the security model |

These English documents are the source of truth. Chinese translations live in [docs/zh-CN](./docs/zh-CN/) and may lag behind a release.

## Local development

The full development setup — configuration, backend, dashboard hot-reload, the
account model and observability — is in
**[docs/local-development.md](./docs/local-development.md)**.

Short version: start Postgres, build the dashboard (`cd dashboard && pnpm build`;
it is embedded at compile time), then `cargo run -p signet` on `:8443`.

## Interfaces

Signet exposes four surfaces; the full references live in `docs/`:

| Surface | Prefix | Reference |
|---|---|---|
| OIDC protocol | `/oauth/*`, `/.well-known/openid-configuration` | [docs/client-integration.md](./docs/client-integration.md) |
| Dashboard & admin API | `/api/v1/*` — session cookie, or `Authorization: Bearer` admin API token for automation | [docs/api-v1.md](./docs/api-v1.md) |
| SCIM v2 | `/scim/v2/*` — bearer token | [docs/integrations.md](./docs/integrations.md) |
| Operations | `GET /health`; `GET /metrics` on a separate loopback listener | [docs/security.md](./docs/security.md#63-observability) |

## CI & release

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| **CI** | Push / PR on source paths | Dashboard typecheck + build + runtime-dependency audit; Rust `fmt` / `clippy` (tests run locally before pushing) |
| **Release Signet Binary** | `v*` tag (or manual) | Multi-arch release binaries → GitHub Release |
| **Build Signet Image** | After binary release succeeds | Multi-arch runtime image (`linux/amd64`, `linux/arm64`) from prebuilt binaries → **ACR** + **Docker Hub** (`${DOCKERHUB_USERNAME}/signet`) |

Tag a release (example): `git tag -a v0.6.2 -m v0.6.2 && git push origin v0.6.2`.

Deploy layout: [`docs/deploy.md`](./docs/deploy.md). Compose files under [`deploy/`](./deploy/) (`docker-compose.yml`) and [`build/docker-compose.yml`](./build/docker-compose.yml)
(`docker compose -f build/docker-compose.yml --profile dev up -d db`).


## Contributing

Contributions are welcome. [CONTRIBUTING.md](./CONTRIBUTING.md) covers
prerequisites, the branch/PR workflow, commit-message rules and the checks CI
runs.

- Local setup: [docs/local-development.md](./docs/local-development.md).
- Run the checks locally before pushing: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test`, and in
  `dashboard/`: `pnpm typecheck && pnpm build`.
- Update the relevant page under `docs/` when behaviour changes, keeping the
  English book (source of truth) and `docs/zh-CN/` in sync.

## Security

Please **do not open a public issue** for a vulnerability. Report it privately
as described in [SECURITY.md](./SECURITY.md) (email
**info@open.schiplat.com**); we acknowledge within 3 business days. The security
model and implementation notes are in [docs/security.md](./docs/security.md).

## Repository structure

```text
crates/signet/          Axum OIDC IdP + /api/v1 (+ federation/)
dashboard/              Vue 3 + Tailwind CSS v4
migrations/             Postgres migrations (… audit client_id, identity federation, …)
build/                  Dockerfiles + local compose (image build, optional Postgres)
.github/workflows/      ci.yml · release-binary.yml · build-signet-image.yml
deploy/                 Production compose (pull-only image)
docs/                   design · security · client-integration · integrations · api-v1 · mfa · dashboard · groups · directory-sync
docs/zh-CN/             Chinese translations of the documents above
```
