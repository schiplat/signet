#!/bin/bash
source "$(dirname "$0")/lib.sh"
# E2E part 3 — operational surface on a throwaway instance:
# security/cache headers, the separate metrics listener, RP-initiated logout,
# and signing-key rotation/prune against a real process.
#
# Runs on its own port (8445), database and data directory, so it neither
# disturbs the other two suites nor touches /root/signet/data. Everything it
# creates is removed on exit.
set -u

OPS="${E2E_OPS:-http://127.0.0.1:8445}"
OPS_METRICS_PORT="${E2E_OPS_METRICS_PORT:-9465}"
DB="${E2E_DB_OPS:-signet_verify_ops}"
BIN="$E2E_REPO/target/debug/signet"
DATA="$E2E_REPO/data-e2e-ops"
LOG=/tmp/e2e_ops.log
PIDFILE=/tmp/e2e_ops.pid
J=/tmp/jars_ops; rm -rf "$J"; mkdir -p "$J"

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS: $1"; }
bad() { fail=$((fail+1)); echo "FAIL: $1 — got: $(echo "${2:-}" | head -c 300)"; }
check() {
  if [ -z "${3:-}" ]; then bad "$1" "empty pattern"; 
  elif echo "${2:-}" | grep -q "$3"; then ok "$1"; else bad "$1" "${2:-}"; fi
}

export PGPASSWORD="$E2E_PG_PASS"

stop_instance() {
  if [ -f "$PIDFILE" ]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break; sleep 0.2; done
    rm -f "$PIDFILE"
  fi
}

cleanup() {
  stop_instance
  psql -h "$E2E_PG_HOST" -U "$E2E_PG_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1
  rm -rf "$DATA" "$J" "$LOG"
}
trap cleanup EXIT

start_instance() {
  nohup env \
    SIGNET_DATABASE_URL="postgres://admin:123456@$E2E_PG_HOST:5432/$DB" \
    SIGNET_HTTP_BIND="0.0.0.0:8445" \
    SIGNET_ISSUER="$OPS" \
    SIGNET_JWT_PRIVATE_KEY_PATH="$DATA/jwt_private.pem" \
    SIGNET_JWT_RETIRED_KEY_DIR="$DATA/retired_keys" \
    SIGNET_ENCRYPTION_KEY_PATH="$DATA/encryption.key" \
    SIGNET_METRICS_BIND="127.0.0.1:$OPS_METRICS_PORT" \
    "$BIN" >> "$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  for _ in $(seq 1 40); do
    if curl -fsS "$OPS/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "instance did not become healthy; log:"; tail -20 "$LOG"
  return 1
}

jwks_field() { # $1 = python expression over `keys`
  curl -s "$OPS/oauth/jwks" \
    | python3 -c "import json,sys; keys=json.load(sys.stdin)['keys']; print($1)"
}

echo "== 0. fresh throwaway instance =="
rm -rf "$DATA"; mkdir -p "$DATA"
psql -h "$E2E_PG_HOST" -U "$E2E_PG_USER" -d postgres \
  -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" \
  -c "CREATE DATABASE $DB OWNER admin" >/dev/null
start_instance || { echo "FAIL: instance start"; exit 1; }
ok "throwaway instance started"

R=$(curl -s -X POST "$OPS/api/v1/setup" -H 'Content-Type: application/json' \
  -d '{"email":"ops-admin@example.com","password":"OpsPassw0rdX","display_name":"Ops Admin"}')
check "admin created" "$R" '"status":"ok"'
# Session cookie jar for the logout checks below.
curl -s -c "$J/admin" -X POST "$OPS/api/v1/login" -H 'Content-Type: application/json' \
  -d '{"email":"ops-admin@example.com","password":"OpsPassw0rdX"}' >/dev/null

echo "== 1. browser hardening headers =="
H=$(curl -sI "$OPS/")
check "nosniff" "$H" "x-content-type-options: nosniff"
check "frame denied" "$H" "x-frame-options: DENY"
check "no-referrer" "$H" "referrer-policy: no-referrer"
check "CSP present" "$H" "content-security-policy: default-src 'self'"
check "permissions policy" "$H" "permissions-policy: camera=()"

echo "== 2. cache policy =="
check "index.html revalidates" "$H" "cache-control: no-cache"
ASSET=$(curl -s "$OPS/" | grep -o '/assets/[A-Za-z0-9._-]*\.js' | head -1)
if [ -n "$ASSET" ]; then
  AH=$(curl -sI "$OPS$ASSET")
  check "hashed asset is immutable" "$AH" "cache-control: public, max-age=31536000, immutable"
else
  bad "index.html names an asset bundle" "(no /assets/*.js found)"
fi

echo "== 3. metrics live on their own listener =="
MH=$(curl -sI "$OPS/metrics")
check "public /metrics is not the metrics payload" "$MH" "content-type: text/html"
PUB=$(curl -s "$OPS/metrics")
if echo "$PUB" | grep -q "signet_logins_total"; then
  bad "public /metrics leaks counters" "signet_logins_total present"
else
  ok "public /metrics does not expose counters"
fi
M=$(curl -s "http://127.0.0.1:$OPS_METRICS_PORT/metrics")
check "dedicated listener serves counters" "$M" "signet_logins_total"
check "dedicated listener has health" "$(curl -s "http://127.0.0.1:$OPS_METRICS_PORT/health")" "ok"

echo "== 4. RP-initiated logout =="
R=$(curl -s -o /dev/null -w '%{http_code}' "$OPS/oauth/end_session")
check "GET without id_token_hint is refused" "$R" "400"
R=$(curl -s -o /dev/null -w '%{http_code}' "$OPS/oauth/end_session?id_token_hint=not-a-jwt")
check "forged hint is refused" "$R" "400"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$J/admin" -c "$J/admin" \
  -X POST -d '' "$OPS/oauth/end_session")
check "POST signs out without a hint" "$LOC" "$OPS/"
R=$(curl -s -b "$J/admin" "$OPS/api/v1/me")
check "session is gone after logout" "$R" "not authenticated"

echo "== 5. signing-key rotation =="
OLD_KID=$(jwks_field "keys[0]['kid']")
COUNT=$(jwks_field "len(keys)")
check "one key before rotation" "$COUNT" "1"

NEW_KID=$(env \
  SIGNET_DATABASE_URL="postgres://admin:123456@$E2E_PG_HOST:5432/$DB" \
  SIGNET_JWT_PRIVATE_KEY_PATH="$DATA/jwt_private.pem" \
  SIGNET_JWT_RETIRED_KEY_DIR="$DATA/retired_keys" \
  SIGNET_ENCRYPTION_KEY_PATH="$DATA/encryption.key" \
  "$BIN" keys rotate 2>&1 | sed -n 's/^new signing key: //p')
if [ -n "$NEW_KID" ] && [ "$NEW_KID" != "$OLD_KID" ]; then
  ok "rotate produced a new kid"
else
  bad "rotate produced a new kid" "new='$NEW_KID' old='$OLD_KID'"
fi
check "retired public key written" "$(ls "$DATA/retired_keys" 2>/dev/null | wc -l)" "1"

stop_instance
start_instance || { echo "FAIL: restart after rotation"; exit 1; }
COUNT=$(jwks_field "len(keys)")
check "JWKS publishes active + retired" "$COUNT" "2"
KIDS=$(jwks_field "','.join(k['kid'] for k in keys)")
check "new kid is active" "$KIDS" "$NEW_KID"
check "old kid still published" "$KIDS" "$OLD_KID"
R=$(curl -s -c "$J/admin2" -X POST "$OPS/api/v1/login" -H 'Content-Type: application/json' \
  -d '{"email":"ops-admin@example.com","password":"OpsPassw0rdX"}')
check "login still works after rotation" "$R" '"status":"ok"'

echo "== 6. retired-key prune =="
env \
  SIGNET_DATABASE_URL="postgres://admin:123456@$E2E_PG_HOST:5432/$DB" \
  SIGNET_JWT_PRIVATE_KEY_PATH="$DATA/jwt_private.pem" \
  SIGNET_JWT_RETIRED_KEY_DIR="$DATA/retired_keys" \
  SIGNET_ENCRYPTION_KEY_PATH="$DATA/encryption.key" \
  "$BIN" keys prune --keep 0 >/dev/null 2>&1
check "prune removed the retired key" "$(ls "$DATA/retired_keys" 2>/dev/null | wc -l)" "0"
stop_instance
start_instance || { echo "FAIL: restart after prune"; exit 1; }
check "ring loads with only the active key" "$(jwks_field "len(keys)")" "1"
check "login still works after prune" \
  "$(curl -s -X POST "$OPS/api/v1/login" -H 'Content-Type: application/json' \
     -d '{"email":"ops-admin@example.com","password":"OpsPassw0rdX"}')" '"status":"ok"'

echo
echo "ops: $pass passed, $fail failed"
exit $fail
