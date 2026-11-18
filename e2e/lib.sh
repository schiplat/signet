# E2E configuration. Override any of these without editing the scripts:
#   E2E_REPO   repo checkout on the host running the instances (default: this checkout)
#   E2E_DOWN / E2E_UP           issuer base URLs of the two instances
#   E2E_PG_HOST / E2E_PG_USER / E2E_PG_PASS  Postgres used for the scratch databases
#   E2E_DB / E2E_DB_UP          scratch database names (dropped and recreated!)
#
# Defaults target loopback and carry no environment specifics — no host names,
# addresses or credentials ship in the tree. Set the E2E_* variables for your
# own environment (instances, Postgres, credentials) when running elsewhere.
#
# WARNING: run_all.sh drops and recreates both databases. Point these at
# anything you care about and you will lose it.
: "${E2E_REPO:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${E2E_DOWN:=http://127.0.0.1:8443}"
: "${E2E_UP:=http://127.0.0.1:8444}"
: "${E2E_PG_HOST:=127.0.0.1}"
: "${E2E_PG_USER:=postgres}"
: "${E2E_PG_PASS:=}"
: "${E2E_DB:=signet_verify}"
: "${E2E_DB_UP:=signet_verify_up}"
