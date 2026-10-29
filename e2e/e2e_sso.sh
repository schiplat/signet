#!/bin/bash
source "$(dirname "$0")/lib.sh"
# E2E part 2 — federated sign-in across TWO Signet instances on SEPARATE
# databases: the upstream user population is invisible to the downstream, so
# first-time federation exercises the real JIT path, and jit_mode=off really
# refuses an identity with no local account.
#
#   UP   http://192.168.39.132:8444  DB signet_verify_up  (own keys)
#   DOWN http://192.168.39.132:8443  DB signet_verify    (global MFA ON, set by core)
set -u
DOWN="$E2E_DOWN"
UP="$E2E_UP"
J=/tmp/jars2; mkdir -p $J; rm -f $J/*
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "PASS: $1"; }
bad() { fail=$((fail+1)); echo "FAIL: $1 — got: $(echo "${2:-}" | head -c 300)"; }
check() { if echo "${2:-}" | grep -q "$3"; then ok "$1"; else bad "$1" "${2:-}"; fi }

export PGPASSWORD="$E2E_PG_PASS"; PSQL="psql -h $E2E_PG_HOST -U $E2E_PG_USER -d $E2E_DB -tA -c"
UPSQL="psql -h $E2E_PG_HOST -U $E2E_PG_USER -d $E2E_DB_UP -tA -c"

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

consent_step() { # consent_step <jar> <authorize_url> -> callback URL with code
  local loc="$2" body redir
  case "$loc" in
    */consent*)
      body=$(python3 - "$loc" <<'PYEOF'
import sys, urllib.parse, json
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
print(json.dumps({"client_id": q["client_id"][0], "redirect_uri": q["redirect_uri"][0],
  "scope": q["scope"][0], "state": q["state"][0], "nonce": q.get("nonce",[""])[0],
  "code_challenge": q["code_challenge"][0], "code_challenge_method": "S256", "allow": True}))
PYEOF
)
      redir=$(curl -s -b "$1" -X POST $UP/oauth/consent -H 'Content-Type: application/json' -d "$body" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["redirect"])')
      curl -s -b "$1" -o /dev/null -w '%{redirect_url}' "$UP$redir" ;;
    *) echo "$loc" ;;
  esac
}

echo "== 1. upstream instance: its own admin, client, users (separate DB) =="
R=$(curl -s $UP/api/v1/setup/status)
check "upstream instance is a fresh world" "$R" '"needs_setup":true'
R=$(curl -s -c $J/upadmin -X POST $UP/api/v1/setup -H 'Content-Type: application/json' \
  -d '{"email":"up-admin@up.example","password":"UpsidePassw1","display_name":"Up Admin"}')
check "upstream admin created" "$R" '"status":"ok"'
R=$(curl -s -b $J/upadmin -X POST $UP/api/v1/admin/clients -H 'Content-Type: application/json' \
  -d '{"client_id":"fed-ds","redirect_uris":["'$DOWN'/api/v1/auth/sso/ups/callback"],"ip_allowlist_enabled":false}')
check "upstream client created" "$R" '"client_id":"fed-ds"'
UP_SECRET=$(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["client_secret"])')
R=$(curl -s -b $J/upadmin -X POST $UP/api/v1/admin/users -H 'Content-Type: application/json' \
  -d '{"email":"ups-one@example.com","password":"UpsOne1Passw","display_name":"ups-one","must_change_password":false,"role":"member"}')
check "upstream user ups-one created" "$R" "ups-one@example.com"
R=$(curl -s -b $J/upadmin -X POST $UP/api/v1/admin/users -H 'Content-Type: application/json' \
  -d '{"email":"ups-two@example.com","password":"UpsTwo2Passw","display_name":"ups-two","must_change_password":false,"role":"member"}')
check "upstream user ups-two created" "$R" "ups-two@example.com"

echo "== 2. downstream provider: jit on, trust any email =="
R=$(curl -s -b /tmp/jars/admin -X POST $DOWN/api/v1/admin/sso/providers -H 'Content-Type: application/json' \
  -d '{"code":"ups","provider_type":"oidc","display_name":"Upstream Signet","client_id":"fed-ds","client_secret":"'$UP_SECRET'","issuer_url":"'$UP'","jit_mode":"on","email_trust":"any"}')
check "federation provider created" "$R" '"ok":true'
echo "DEBUG provider row: $($PSQL \"SELECT jit_mode || '/' || email_trust FROM upstream_providers WHERE code='ups'\")"

echo "== 3. JIT: brand-new upstream identity creates a local member =="
START=$(curl -s -c $J/ds -o /dev/null -w '%{redirect_url}' "$DOWN/api/v1/auth/sso/ups/start")
check "sso start redirects to upstream authorize" "$START" "$UP/oauth/authorize"
LOGIN_LOC=$(curl -s -c $J/up1 -o /dev/null -w '%{redirect_url}' "$START")
check "upstream demands login" "$LOGIN_LOC" "/login?return_to=%2Foauth%2Fauthorize"
RETURN_TO=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.parse_qs(urllib.parse.urlparse(open("/dev/stdin").read().strip()).query)["return_to"][0])' <<<"$LOGIN_LOC")
R=$(curl -s -c $J/up1 -X POST $UP/api/v1/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"ups-one@example.com\",\"password\":\"UpsOne1Passw\",\"return_to\":\"$RETURN_TO\"}")
check "upstream login ok (no local MFA on UP)" "$R" '"status":"ok"'
CONS_LOC=$(curl -s -b $J/up1 -o /dev/null -w '%{redirect_url}' "$START")
check "upstream authorize resumes to consent" "$CONS_LOC" "/consent"
CB=$(consent_step $J/up1 "$CONS_LOC")
check "upstream consent returns to downstream callback" "$CB" "$DOWN/api/v1/auth/sso/ups/callback"
FINAL=$(curl -s -b $J/ds -c $J/ds -o /dev/null -w '%{redirect_url}' "$CB")
check "JIT user lands on the SSO enrollment gate" "$FINAL" "/login?sso_step=enroll"
VIA=$($PSQL "SELECT via || '/' || purpose FROM mfa_challenges ORDER BY created_at DESC LIMIT 1")
check "challenge carries via=sso purpose=enroll" "$VIA" "sso/enroll"
PROV=$($PSQL "SELECT role || '/' || provisioned_via FROM users WHERE email='ups-one@example.com'")
check "JIT created a provisioned member" "$PROV" "member/sso_jit"
NOPW=$($PSQL "SELECT password_hash = '' FROM users WHERE email='ups-one@example.com'")
check "JIT account has no password" "$NOPW" "t"

echo "== 4. finish the gate: enrollment continues the SSO sign-in =="
S32=$(curl -s -b $J/ds -c $J/ds -X POST $DOWN/api/v1/mfa/enroll/start | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')
R=$(curl -s -b $J/ds -c $J/ds -X POST $DOWN/api/v1/mfa/enroll/confirm -H 'Content-Type: application/json' -d "{\"code\":\"$(totp "$S32")\"}")
check "enroll confirm issues the federated session" "$R" '"status":"ok"'
R=$(curl -s -b $J/ds $DOWN/api/v1/me)
check "JIT user session works" "$R" "ups-one@example.com"

echo "== 5. auto-link: a local account with the same email links, no JIT dup =="
R=$(curl -s -b /tmp/jars/admin -X POST $DOWN/api/v1/admin/users -H 'Content-Type: application/json' \
  -d '{"email":"ups-link@example.com","password":"LinkLocal1P","display_name":"Link Local","must_change_password":false,"role":"member"}')
check "local twin account created" "$R" "ups-link@example.com"
R=$(curl -s -b $J/upadmin -X POST $UP/api/v1/admin/users -H 'Content-Type: application/json' \
  -d '{"email":"ups-link@example.com","password":"LinkUp1Passw","display_name":"Link Up","must_change_password":false,"role":"member"}')
check "upstream twin account created" "$R" "ups-link@example.com"
START=$(curl -s -c $J/ds2 -o /dev/null -w '%{redirect_url}' "$DOWN/api/v1/auth/sso/ups/start")
LOGIN_LOC=$(curl -s -c $J/up2 -o /dev/null -w '%{redirect_url}' "$START")
RETURN_TO=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.parse_qs(urllib.parse.urlparse(open("/dev/stdin").read().strip()).query)["return_to"][0])' <<<"$LOGIN_LOC")
R=$(curl -s -c $J/up2 -X POST $UP/api/v1/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"ups-link@example.com\",\"password\":\"LinkUp1Passw\",\"return_to\":\"$RETURN_TO\"}")
check "upstream twin login ok" "$R" '"status":"ok"'
CONS_LOC=$(curl -s -b $J/up2 -o /dev/null -w '%{redirect_url}' "$START")
CB=$(consent_step $J/up2 "$CONS_LOC")
FINAL=$(curl -s -b $J/ds2 -c $J/ds2 -o /dev/null -w '%{redirect_url}' "$CB")
check "auto-linked user reaches the enrollment gate" "$FINAL" "/login?sso_step=enroll"
S33=$(curl -s -b $J/ds2 -c $J/ds2 -X POST $DOWN/api/v1/mfa/enroll/start | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')
R=$(curl -s -b $J/ds2 -c $J/ds2 -X POST $DOWN/api/v1/mfa/enroll/confirm -H 'Content-Type: application/json' -d "{\"code\":\"$(totp "$S33")\"}")
check "auto-linked enrollment issues the session" "$R" '"status":"ok"'
N=$($PSQL "SELECT COUNT(*) FROM users WHERE email='ups-link@example.com'")
check "auto-link did not duplicate the account" "$N" "^1$"
PROV=$($PSQL "SELECT COALESCE(provisioned_via,'-') FROM users WHERE email='ups-link@example.com'")
check "pre-existing account not marked sso_jit" "$PROV" "^-$"

echo "== 6. jit_mode=off refuses an identity with no local account =="
R=$(curl -s -b /tmp/jars/admin -X PUT $DOWN/api/v1/admin/sso/providers/ups -H 'Content-Type: application/json' \
  -d '{"code":"ups","provider_type":"oidc","display_name":"Upstream Signet","client_id":"fed-ds","issuer_url":"'$UP'","jit_mode":"off","email_trust":"any"}')
check "provider updated to jit off" "$R" '"ok":true'
START=$(curl -s -c $J/ds3 -o /dev/null -w '%{redirect_url}' "$DOWN/api/v1/auth/sso/ups/start")
LOGIN_LOC=$(curl -s -c $J/up3 -o /dev/null -w '%{redirect_url}' "$START")
RETURN_TO=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.parse_qs(urllib.parse.urlparse(open("/dev/stdin").read().strip()).query)["return_to"][0])' <<<"$LOGIN_LOC")
R=$(curl -s -c $J/up3 -X POST $UP/api/v1/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"ups-two@example.com\",\"password\":\"UpsTwo2Passw\",\"return_to\":\"$RETURN_TO\"}")
check "upstream login ok" "$R" '"status":"ok"'
CONS_LOC=$(curl -s -b $J/up3 -o /dev/null -w '%{redirect_url}' "$START")
CB=$(consent_step $J/up3 "$CONS_LOC")
FINAL=$(curl -s -b $J/ds3 -o /dev/null -w '%{redirect_url}' "$CB")
check "jit-off lands on no_matching_account" "$FINAL" "sso_error=no_matching_account"
N=$($PSQL "SELECT COUNT(*) FROM users WHERE email='ups-two@example.com'")
check "no local account was created" "$N" "^0$"

echo "== 7. linked identities keep working under jit off =="
START=$(curl -s -c $J/ds4 -o /dev/null -w '%{redirect_url}' "$DOWN/api/v1/auth/sso/ups/start")
LOGIN_LOC=$(curl -s -c $J/up4 -o /dev/null -w '%{redirect_url}' "$START")
RETURN_TO=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.parse_qs(urllib.parse.urlparse(open("/dev/stdin").read().strip()).query)["return_to"][0])' <<<"$LOGIN_LOC")
R=$(curl -s -c $J/up4 -X POST $UP/api/v1/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"ups-one@example.com\",\"password\":\"UpsOne1Passw\",\"return_to\":\"$RETURN_TO\"}")
check "upstream login ok" "$R" '"status":"ok"'
CONS_LOC=$(curl -s -b $J/up4 -o /dev/null -w '%{redirect_url}' "$START")
CB=$(consent_step $J/up4 "$CONS_LOC")
FINAL=$(curl -s -b $J/ds4 -c $J/ds4 -o /dev/null -w '%{redirect_url}' "$CB")
check "linked user reaches the TOTP gate under jit off" "$FINAL" "/login?sso_step=mfa"
R=$(curl -s -b $J/ds4 -c $J/ds4 -X POST $DOWN/api/v1/mfa/verify -H 'Content-Type: application/json' -d "{\"code\":\"$(totp "$S32")\"}")
check "jit-off federated session issued for the linked user" "$R" '"status":"ok"'

echo
echo "sso: $pass passed, $fail failed"
exit $fail
