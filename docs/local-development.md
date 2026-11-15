# Local development

> English · [简体中文](./zh-CN/local-development.md)

Set up a development environment and run Signet from source. For the container
path, see the [Quick Start](../README.md#quick-start); for deployment, see
[deploy.md](./deploy.md).

## 1. Configuration

```bash
cp .env.example .env
# Edit SIGNET_DATABASE_URL, etc.
```

On first run with no administrator, open the dashboard in a browser. It redirects
to **`/setup`**, where you create the first administrator account (email, optional
display name and password).

## 2. Backend

```bash
cargo run -p signet
```

> The binary embeds `dashboard/dist` at compile time (rust-embed); a missing
> folder fails the build. Build the dashboard first (step 3), or follow
> [Quick Start](../README.md#quick-start) option C in order.

Health check: `GET http://localhost:8443/health`

Before committing Rust changes:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## 3. Dashboard (Vue)

```bash
cd dashboard
pnpm install
pnpm dev          # http://localhost:5173, proxied to :8443
# or build and embed into the binary:
pnpm build
cd .. && cargo build -p signet
```

In production/staging, Rust serves `dashboard/dist` through `rust-embed` (the
folder must exist before `cargo build`).

## 4. Account model

- **No public registration**; staff accounts are provisioned under
  **Dashboard → Directory** (frontend route `/directory`, API
  `/api/v1/admin/users`)
- Roles: `admin` / `manager` / `member` (see [design.md](./design.md))
- The first-run **`/setup`** page creates the initial `admin`
- Optional **MFA** (global or per-user enforced); users may self-enroll from the
  account menu
- Optional **third-party providers** under **Integrations**; users manage linked
  accounts from the account menu

## 5. Observability

- Every request/response carries **`x-request-id`** (passed through or an
  auto-generated UUIDv4) for trace linking
- Access logs come from `crates/signet/src/http/access_log.rs`: single line,
  structured fields (`request_id` / `method` / `path` / `query` / `ip` / `status` /
  `latency_ms`), with `2xx/3xx` at `INFO`, `4xx` at `WARN`, `5xx` at `ERROR`
- Logging goes through `tracing`; see
  [.cursor/rules/logging.mdc](../.cursor/rules/logging.mdc): static messages plus
  structured fields, errors in an `error` field, single-line JSON in production
  (`APP_ENV=production`)
- `GET /metrics` exposes Prometheus metrics on a **separate listener** (loopback
  by default; `SIGNET_METRICS_BIND`) — never on the public API port
