#!/bin/bash
source "$(dirname "$0")/lib.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -u
for p in $(pgrep -f "target/debug/signet"); do kill $p 2>/dev/null; done
pkill -f axum-oidc-client 2>/dev/null
sleep 1
export PGPASSWORD="$E2E_PG_PASS"
psql -h "$E2E_PG_HOST" -U "$E2E_PG_USER" -d postgres \
  -c "DROP DATABASE IF EXISTS $E2E_DB WITH (FORCE)" -c "CREATE DATABASE $E2E_DB OWNER admin" \
  -c "DROP DATABASE IF EXISTS $E2E_DB_UP WITH (FORCE)" -c "CREATE DATABASE $E2E_DB_UP OWNER admin" >/dev/null
bash "$SCRIPT_DIR/start_instances.sh"
bash "$SCRIPT_DIR/e2e_core.sh"; CORE=$?
bash "$SCRIPT_DIR/e2e_sso.sh"; SSO=$?
echo "SUMMARY core=$CORE sso=$SSO"
