# Build and deploy layout

> English · [简体中文](./zh-CN/deploy.md)

Signet splits "build the image" and "run production" into two directories so the
repository root does not accumulate compose files.

| Directory | Responsibility |
|------|------|
| [`build/`](../build/) | Dockerfile + **local** compose (optional Postgres) |
| [`deploy/`](../deploy/) | **Production** compose (pull-only); `.env` is provided by the deployment environment |

Day-to-day development still runs on `cargo run` + `pnpm dev`; the two compose
stacks below are for containerised integration and rollout.

---

## 1. `build/` — image and local orchestration

| File | Purpose |
|------|------|
| `Dockerfile` | Multi-stage: build the dashboard → compile `signet` → slim runtime image |
| `Dockerfile.runtime` | Used by CI: copies the released per-architecture binaries into a multi-arch image, no compilation |
| `docker-compose.yml` | Local: builds `signet` from `Dockerfile`; `--profile dev` optionally starts Postgres |

Run from the **repository root**:

```bash
# Local Postgres only (host port 5433; database/user/password all "signet")
docker compose -f build/docker-compose.yml --profile dev up -d db

# Build and start the application image (needs a repo-root .env with SIGNET_DATABASE_URL)
docker compose -f build/docker-compose.yml up -d --build
```

The `signet` service builds from the repository root and points `env_file` at
`../.env`. The `signet_data` volume mounts at `/app/data` (JWT and encryption
keys, see below).

The release pipeline (`build-signet-image.yml`) uses `build/Dockerfile.runtime`
to bake the `linux-amd64` and `linux-arm64` binaries from a GitHub Release into
one multi-arch manifest, then pushes it to ACR / Docker Hub. `docker pull`
selects the matching architecture automatically.

---

## 2. `deploy/` — production orchestration

| File | Purpose |
|------|------|
| `docker-compose.yml` | **Pull-only**, no build; joins the external `manager-net` network |
| `docker-compose.env-file.yml` | Optional overlay: also loads `deploy/.env` into the container |

Production does not start a database in this stack: it connects to an existing
Postgres via `SIGNET_DATABASE_URL`, with `postgres` as the host on `manager-net`.

Environment variables are the primary path — the deployment system injects
them, and `SIGNET_DATABASE_URL` is required (no fallback to the built-in
localhost default):

```bash
cd deploy
export SIGNET_IMAGE="<registry>/<namespace>/signet:<tag>"
export SIGNET_DATABASE_URL="postgres://signet:<password>@postgres:5432/signet"
docker compose pull
docker compose up -d
```

A dotenv file is still supported as an optional compatibility layer:

```bash
cd deploy
cp ../.env.example .env   # set SIGNET_IMAGE and SIGNET_DATABASE_URL
docker compose -f docker-compose.yml -f docker-compose.env-file.yml up -d
```

The base file's `environment:` values win over the same keys in `.env`; use the
overlay when you want the wider settings surface (SMTP, metrics, optional
integrations) from the file. Buz or any other pipeline can provide either form
from its own secret store. The image workflow publishes only the image; no
configuration bundle is uploaded anywhere.

First deployment: open the issuer URL; the dashboard redirects to `/setup` to
create the first administrator.

---

## 3. Key directory `/app/data`

The container (and the default local path `./data/`) persists two key files:

| File | Purpose |
|------|------|
| `jwt_private.pem` | RS256: signs and verifies OIDC JWTs |
| `encryption.key` | AES-256-GCM: encrypts sensitive columns at rest (TOTP secrets, webhook secrets) |

- Generated automatically on first start when absent.
- Production mounts the Docker volume `signet_data` at `/app/data`; **losing or
  rotating them invalidates issued tokens and makes stored TOTP secrets
  unreadable**.
- The repository's `./data/` is a local artifact only and is not shipped in the
  image. See [security.md §7](./security.md#7-keys-and-configuration).

> **Instances sharing one database must share one `encryption.key`**: TOTP and
> webhook secrets are AES-GCM ciphertexts under that key. Two instances on the
> same database with different keys write ciphertext the other cannot read
> (symptom: a TOTP enrolled on instance A fails base32 decoding on instance B).
> The production compose satisfies this through the shared `signet_data` volume;
> a split deployment must point every instance's `SIGNET_ENCRYPTION_KEY_PATH` at
> the same content. Startup records the key fingerprint in `app_settings`
> (`crypto.encryption_key_fingerprint`) and refuses to start on a mismatch; if
> you are deliberately re-keying, delete that row to re-arm the check (old
> ciphertexts still need handling). `jwt_private.pem` has no such constraint:
> instances may sign with their own keys (different issuers), and JWKS is served
> per issuer.

---

## 4. Running the directory-sync CLI inside the container

`signet sync …` reuses the same `build_state` as the server, so it is **not** a
lightweight client: on start it connects to the database, runs migrations, loads
(and if necessary **generates**) `jwt_private.pem` and `encryption.key`,
re-encrypts webhook secrets, and prunes audit logs.

```bash
# Execute inside the target container: same cwd, env and key volume as the server
docker compose -f deploy/docker-compose.yml exec signet \
  signet sync sources

docker compose -f deploy/docker-compose.yml exec signet \
  signet sync run --source corp-ldap --dry-run
```

Points to keep in mind:

- **Run it inside the server container** (or at least ensure
  `SIGNET_DATABASE_URL` and `SIGNET_ENCRYPTION_KEY_PATH` point at the same
  values). Running elsewhere with a different key path creates a **new** key
  file in the current directory and then fails to decrypt existing ciphertext;
  even if it happens to work, it leaves a key artifact inconsistent with the
  server.
- The container's cwd is `/app`, env comes from the compose `env_file` (there is
  no `.env` in the image), and the key volume is at `/app/data` — all three match
  the server, so `exec` is enough; do not hand-assemble environment variables.
- Running the binary on the host makes `dotenvy` read `.env` from the **current
  working directory**; always `cd` to the directory holding the env file, or it
  silently falls back to the built-in defaults (e.g. the default database and
  `./data/` key paths).
- Logs go to stdout; a pipeline consumer needs `RUST_LOG=off`:

```bash
docker compose -f deploy/docker-compose.yml exec -T signet \
  env RUST_LOG=off signet sync sources --json | jq -r '.[].code'
```

- Concurrent runs with the scheduler or a manual trigger are serialised by
  the single-run partial unique index; the later caller gets
  `another sync run for this source is already in progress`.
- Full commands, output, exit codes and `--dry-run` semantics: see
  [directory-sync.md §9](./directory-sync.md#9-command-line).

---

## 4.5 Signing-key rotation

`signet keys rotate` generates a new key, writes the **public** half of the old
one into `SIGNET_JWT_RETIRED_KEY_DIR` (default `./data/retired_keys`), and
atomically replaces `SIGNET_JWT_PRIVATE_KEY_PATH`. Running instances poll the key
file fingerprint every 30 seconds and hot-reload the ring, **no restart needed**:

- Newly issued access/id tokens are signed with the new `kid`;
- Tokens signed by the old key still verify until they expire naturally (JWKS
  publishes both public keys; clients follow `kid`);
- The old private key is not kept (only the public half is written), so rotation
  does not widen private-key exposure;
- If the key file briefly disappears, the watcher does **not** generate a
  replacement; it keeps the current ring and waits for the file to return.

```bash
# Inside the container (the volume persists both paths under /app/data)
docker compose -f deploy/docker-compose.yml exec -T signet signet keys rotate
# No restart; effective within ~30s (or restart to load immediately)
curl -s https://<issuer>/.well-known/jwks.json | jq '.keys[].kid'   # both kids
```

It can be repeated: each run retires the current key and generates a new one; the
retired directory names keys by `kid`, so repeated rotations overwrite idempotently.

The retired directory is not cleaned automatically (public keys carry no
disclosure risk). Once old tokens have expired it can be shrunk:

```bash
signet keys prune --keep 3   # keep only the three most recent retired public keys
```

---

## 4.6 Supported topology: a single active instance

Signet is designed and verified for a **single active instance**. Three pieces of
in-process state — the rate-limit buckets, the passkey challenge store, and the
runtime-settings snapshot (except challenges already persisted) — are not shared
across replicas. Behind a load balancer this shows up as: the rate-limit budget
multiplied by the replica count, passkey sign-in failing without sticky sessions,
and setting changes taking up to 30 seconds to reach other replicas. Everything
else — sessions, SCIM, audit, sync mutual exclusion — lives in the database and
is replica-safe.

Runtime settings and the signing-key ring both re-read every 30 seconds, so that
interval bounds cross-replica propagation (`signet keys rotate` also hot-loads
per replica, no restart). Before scaling horizontally, design a shared store for
challenges and rate limits — do not just attach a load balancer.

The two in-process caches are deliberate trade-offs, not oversights:

- **Passkey ceremony state** stays in memory. Upstream `webauthn-rs` puts
  serialisation of that state behind the `danger-allow-state-serialisation`
  feature and explicitly warns against using it; persisting `CeremonyState`
  would require that "danger" switch and violate fail-closed. Multi-replica
  passkey sign-in needs sticky sessions or an upstream-supported state export.
- **Rate-limit buckets** stay in memory. Shared storage (DB counters, Redis) is
  possible but adds a dependency or per-request write amplification, with no
  benefit for a single instance.

---

## 5. How this relates to daily development

| Scenario | Recommended path |
|------|----------|
| Change Rust / dashboard code | `cargo run -p signet` + `pnpm dev` under `dashboard/` |
| Containerised Postgres | the `db` profile in `build/docker-compose.yml` |
| Verify the full image | `--build` on the `signet` service in `build/docker-compose.yml` |
| Run the directory-sync CLI | locally `cargo run -p signet -- sync …`; production see [§4](#4-running-the-directory-sync-cli-inside-the-container) |
| Rollout / gz4-style environments | `deploy/` + an image tag + the rendered `.env` |
