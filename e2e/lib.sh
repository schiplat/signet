# Lab E2E configuration. Override any of these without editing the scripts:
#   E2E_REPO   repo checkout on the host running the instances (default /root/signet)
#   E2E_DOWN / E2E_UP           issuer base URLs of the two instances
#   E2E_PG_HOST / E2E_PG_USER / E2E_PG_PASS  Postgres used for the scratch databases
#   E2E_DB / E2E_DB_UP          scratch database names (dropped and recreated!)
#
# WARNING: run_all.sh drops and recreates both databases. Point these at
# anything you care about and you will lose it.
: "${E2E_REPO:=/root/signet}"
: "${E2E_DOWN:=http://192.168.39.132:8443}"
: "${E2E_UP:=http://192.168.39.132:8444}"
: "${E2E_PG_HOST:=192.168.39.130}"
: "${E2E_PG_USER:=admin}"
: "${E2E_PG_PASS:=123456}"
: "${E2E_DB:=signet_verify}"
: "${E2E_DB_UP:=signet_verify_up}"
