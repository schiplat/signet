# E2E — real-host end-to-end verification

Drives two live Signet instances and the quickstart client through the whole
protocol with curl: the OIDC chain a real client performs (discovery, PKCE,
state/nonce, exchange, JWKS-verified id_token, local session), the test-drive
endpoint, the MFA enrollment/TOTP gates, and third-party sign-in with a second
Signet instance as the upstream IdP.

## Topology

```
quickstart (127.0.0.1:3000) ── OIDC ──▶ DOWN (:8443, DB signet_verify)
DOWN ── federation (OIDC + PKCE) ──▶ UP (:8444, DB signet_verify_up)
```

Two databases on purpose: the upstream user population is invisible to the
downstream, so first-time federation exercises the real JIT path and
`jit_mode=off` really refuses an identity with no local account. Each instance
has its own JWT and encryption keys (legitimate — separate databases).

## What the suites pin

- `e2e_core.sh` — setup, client registration, the quickstart round trip
  (including id_token validation failures = script failure), test-drive
  endpoint (one-time code, uncovered-parts note), global-MFA enrollment and
  TOTP gates on the password path.
- `e2e_sso.sh` — upstream world bootstrap, JIT creation (`sso_jit`, member, no
  password) landing on the `sso_step=enroll` gate with `via=sso`, enrollment
  continuation, auto-link without duplicate accounts, `jit_mode=off` refusal
  (`no_matching_account`, nothing created), and linked identities under jit-off.

## Running

Needs: a host with the repo built (`cargo build -p signet -p axum-oidc-client`
plus `dashboard/dist`), a reachable Postgres for scratch databases, and `psql`.
Both scratch databases are **dropped and recreated** on every run.

```bash
# on the lab host, from the repo checkout
bash e2e/run_all.sh            # prints PASS/FAIL per assertion + SUMMARY
```

All lab specifics are env-overridable — see `e2e/lib.sh` (`E2E_REPO`, `E2E_DOWN`,
`E2E_UP`, `E2E_PG_*`, `E2E_DB*`). Defaults point at the original lab
(132/130); **do not point the database names at anything you care about.**
