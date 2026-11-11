# Production .env template for docker-compose.yml (Buz OSS deliver).
#
# Packed with docker-compose.yml → configs.tar.gz →
#   config_tpl/signet/<tag>/configs.tar.gz
#
# Buz: Deliver OSS → Render this file → `.env` (mode 0600).
#
# Syntax (Env Render):
#   ${secrets.NAME}  — Buz Secret (UPPER_SNAKE_CASE); missing → render FAILS
#   ${vars.NAME}     — pipeline env: / trigger inputs; :-default allowed
#   bare value       — copied as-is
#
# Never commit real passwords. Rotate any secret that was ever in git.

# ── Database (external PostgreSQL) ──
# Signet does not start its own DB in production. Reuses super-manager's
# Postgres via the shared `manager-net` Docker network. The connection URL is
# composed in docker-compose.yml from these three vars (host = super-manager's
# `postgres` service name on manager-net).
#
# Security: signet connects as a DEDICATED, least-privilege `signet` role
# scoped to its own `signet` database — NOT the cluster `postgres` superuser.
# The superuser credential must never be placed in signet's config.
SIGNET_POSTGRES_USER=signet
SIGNET_POSTGRES_PASSWORD=${secrets.SIGNET_POSTGRES_PASSWORD}
SIGNET_POSTGRES_DB=signet

# ── Issuer / HTTP ──
# MUST be the public HTTPS origin clients use to reach this IdP.
SIGNET_ISSUER=${vars.SIGNET_ISSUER}
SIGNET_COOKIE_SECURE=true

# Reverse proxy(ies) allowed to assert the client IP via X-Forwarded-For.
# Without this, every request behind a proxy is attributed to the proxy's
# address in audit logs, client IP allowlists and rate-limit buckets. Set it
# to the proxy network (e.g. the Docker bridge) when one is in front.
# SIGNET_TRUSTED_PROXIES=${vars.SIGNET_TRUSTED_PROXIES:-172.17.0.0/16}

# ── First-run admin ──
# No env vars required: the dashboard redirects to /setup on first boot (when
# no admin exists) to create the first administrator.

# ── WebAuthn (override for production) ──
# RP_ID must be a domain suffix of RP_ORIGIN, and production requires HTTPS.
SIGNET_WEBAUTHN_RP_ID=${vars.SIGNET_WEBAUTHN_RP_ID}
SIGNET_WEBAUTHN_RP_ORIGIN=${vars.SIGNET_WEBAUTHN_RP_ORIGIN}

# ── Optional: public base URL / SCIM token ──
# SIGNET_PUBLIC_BASE_URL=${vars.SIGNET_PUBLIC_BASE_URL}
# SIGNET_SCIM_BEARER_TOKEN=${secrets.SIGNET_SCIM_BEARER_TOKEN}
