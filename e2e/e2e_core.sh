#!/bin/bash
source "$(dirname "$0")/lib.sh"
# E2E part 1 — core OIDC chain against the quickstart example, test drive,
# and the MFA gates on the password path. Assumes a FRESH signet_verify DB
# (see reset below) and the quickstart example NOT yet running.
set -u
DOWN="$E2E_DOWN"
J=/tmp/jars; mkdir -p $J; rm -f $J/*
B=/tmp/e2e; mkdir -p $B
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS: $1"; }
bad() { fail=$((fail+1)); echo "FAIL: $1 — got: $(echo "${2:-}" | head -c 300)"; }
check() { if echo "${2:-}" | grep -q "$3"; then ok "$1"; else bad "$1" "${2:-}"; fi }

EMAIL=e2e-admin@example.com
PW=E2ePassw0rdX

# do_consent <jar> <authorize_or_consent_url> -> echoes the callback URL with code
do_consent() {
  local body
  body=$(python3 - "$2" <<'PYEOF'
import sys, urllib.parse, json
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
print(json.dumps({"client_id": q["client_id"][0], "redirect_uri": q["redirect_uri"][0],
  "scope": q["scope"][0], "state": q["state"][0], "nonce": q.get("nonce",[""])[0],
  "code_challenge": q["code_challenge"][0], "code_challenge_method": "S256", "allow": True}))
PYEOF
)
  local redir
  redir=$(curl -s -b "$1" -X POST "$DOWN/oauth/consent" -H 'Content-Type: application/json' -d "$body" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["redirect"])')
  # Consent stores the grant and hands back an /oauth/authorize URL (the SPA
  # follows it); following it here is what actually issues the code.
  curl -s -b "$1" -o /dev/null -w '%{redirect_url}' "$DOWN$redir"
}

totp() {
python3 - "$1" <<'PYEOF'
import hmac,hashlib,base64,struct,time,sys
sec=sys.argv[1].replace(" ","")
key=base64.b32decode(sec+"="*((8-len(sec)%8)%8), casefold=True)
c=int(time.time())//30
mac=hmac.new(key,struct.pack(">Q",c),hashlib.sha1).digest()
o=mac[-1]&15
print(f"{((struct.unpack('>I',mac[o:o+4])[0]&0x7fffffff)%1000000):06d}")
PYEOF
}

echo "== 1. setup =="
R=$(curl -s $DOWN/api/v1/setup/status)
check "fresh instance needs setup" "$R" '"needs_setup":true'
R=$(curl -s -c $J/admin -X POST $DOWN/api/v1/setup -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"display_name\":\"E2E Admin\"}")
check "setup creates admin" "$R" '"status":"ok"'

echo "== 2. create client =="
CREATE=$(curl -s -b $J/admin -X POST $DOWN/api/v1/admin/clients -H 'Content-Type: application/json' \
  -d '{"client_id":"e2e-app","redirect_uris":["http://127.0.0.1:3000/auth/callback"],"post_logout_redirect_uris":["http://127.0.0.1:3000/signed-out"],"ip_allowlist_enabled":false}')
check "client created" "$CREATE" '"client_id":"e2e-app"'
echo "$CREATE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_secret"])' > $B/secret

echo "== 3. quickstart OIDC round trip =="
pkill -f axum-oidc-client 2>/dev/null; sleep 1
nohup env OIDC_ISSUER="$DOWN" OIDC_CLIENT_ID=e2e-app OIDC_CLIENT_SECRET="$(cat $B/secret)" \
  /root/signet/target/debug/axum-oidc-client > /tmp/qs.log 2>&1 &
sleep 2
AUTH=$(curl -s -c $J/cl -o /dev/null -w '%{redirect_url}' http://127.0.0.1:3000/auth/login)
check "client login redirects to authorize" "$AUTH" "/oauth/authorize"
check "authorize URL carries PKCE S256" "$AUTH" "code_challenge_method=S256"
LOGIN_LOC=$(curl -s -b $J/u1 -c $J/u1 -o /dev/null -w '%{redirect_url}' "$AUTH")
check "unauthenticated authorize redirects to login with return_to" "$LOGIN_LOC" "/login?return_to=%2Foauth%2Fauthorize"
RETURN_TO=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.parse_qs(urllib.parse.urlparse(open("/dev/stdin").read().strip()).query)["return_to"][0])' <<<"$LOGIN_LOC")
R=$(curl -s -c $J/u1 -X POST $DOWN/api/v1/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"return_to\":\"$RETURN_TO\"}")
check "password login ok" "$R" '"status":"ok"'
CONS_LOC=$(curl -s -b $J/u1 -o /dev/null -w '%{redirect_url}' "$AUTH")
check "authorize resumes after login" "$CONS_LOC" "/consent"
CB=$(do_consent $J/u1 "$CONS_LOC")
check "consent issues code to callback" "$CB" "code="
FINAL=$(curl -s -b $J/cl -c $J/cl -o /dev/null -w '%{http_code} %{redirect_url}' "$CB")
check "client callback lands on home" "$FINAL" "303 http://127.0.0.1:3000/"
HOME_HTML=$(curl -s -b $J/cl http://127.0.0.1:3000/)
check "quickstart session shows identity" "$HOME_HTML" "Hello, E2E Admin"
check "quickstart validated id_token (sub shown)" "$HOME_HTML" "sub = <code>"

echo "== 4. test drive =="
PAIR=$(python3 -c 'import hashlib,base64,os
v=base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
c=base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
print(v,c)')
TD_ENC=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("'$DOWN'/oauth/test-callback/e2e-app",safe=""))')
TD_AUTH="$DOWN/oauth/authorize?response_type=code&client_id=e2e-app&redirect_uri=$TD_ENC&scope=openid%20profile%20email&state=td123&code_challenge=${PAIR#* }&code_challenge_method=S256"
TD_LOC=$(curl -s -b $J/u1 -o /dev/null -w '%{redirect_url}' "$TD_AUTH")
case "$TD_LOC" in
  */consent*) TD_CB=$(do_consent $J/u1 "$TD_LOC") ;;
  *)          TD_CB=$TD_LOC ;;
esac
check "test-drive authorize redirects to built-in callback" "$TD_CB" "/oauth/test-callback/e2e-app"
R=$(curl -s -b $J/u1 "$TD_CB")
check "test drive page passes" "$R" "Test drive passed"
check "test drive page names uncovered parts" "$R" "Not covered"
R=$(curl -s -b $J/u1 "$TD_CB")
check "test drive code is one-time" "$R" "already used"

echo "== 5. MFA gates on password path =="
R=$(curl -s -b $J/admin -X PATCH $DOWN/api/v1/admin/settings/mfa -H 'Content-Type: application/json' -d '{"required_globally":true}')
check "global MFA enabled" "$R" '"required_globally":true'
R=$(curl -s -c $J/u2 -X POST $DOWN/api/v1/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")
check "login now requires enrollment" "$R" '"status":"enroll_required"'
R=$(curl -s -b $J/u2 -c $J/u2 -X POST $DOWN/api/v1/mfa/enroll/start)
SECRET32=$(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')
check "enroll start returns secret" "$R" "otpauth_uri"
R=$(curl -s -b $J/u2 -c $J/u2 -X POST $DOWN/api/v1/mfa/enroll/confirm -H 'Content-Type: application/json' -d "{\"code\":\"$(totp "$SECRET32")\"}")
check "enroll confirm issues session" "$R" '"status":"ok"'
R=$(curl -s -b $J/u2 $DOWN/api/v1/me)
check "session works after enrollment" "$R" "e2e-admin@example.com"
R=$(curl -s -c $J/u3 -X POST $DOWN/api/v1/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}")
check "subsequent login requires TOTP" "$R" '"status":"mfa_required"'
R=$(curl -s -b $J/u3 -X POST $DOWN/api/v1/mfa/verify -H 'Content-Type: application/json' -d "{\"code\":\"$(totp "$SECRET32")\"}")
check "TOTP verify issues session" "$R" '"status":"ok"'

echo
echo "core: $pass passed, $fail failed"
exit $fail
