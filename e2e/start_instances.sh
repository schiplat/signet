#!/bin/bash
source "$(dirname "$0")/lib.sh"
for p in $(pgrep -f "target/debug/signet"); do kill $p 2>/dev/null; done
sleep 1
cd "$E2E_REPO"
# DOWN: signet_verify (DB A). UP: signet_verify_up (DB B) - separate user
# populations, its own JWT and encryption keys (legitimate: separate DBs).
setsid nohup env SIGNET_OUTBOUND_ALLOW_PRIVATE=true SIGNET_DATABASE_URL="postgres://admin:123456@192.168.39.130:5432/$E2E_DB" SIGNET_HTTP_BIND="0.0.0.0:8443" SIGNET_ISSUER="http://192.168.39.132:8443" /root/signet/target/debug/signet > /tmp/down.log 2>&1 &
setsid nohup env SIGNET_OUTBOUND_ALLOW_PRIVATE=true SIGNET_DATABASE_URL="postgres://admin:123456@192.168.39.130:5432/$E2E_DB_UP" SIGNET_HTTP_BIND="0.0.0.0:8444" SIGNET_ISSUER="http://192.168.39.132:8444" SIGNET_JWT_PRIVATE_KEY_PATH=/root/signet/data-up/jwt_private.pem SIGNET_ENCRYPTION_KEY_PATH=/root/signet/data-up/encryption.key /root/signet/target/debug/signet > /tmp/up.log 2>&1 &
sleep 5
echo "down: $(curl -s -m 3 http://127.0.0.1:8443/health)"
echo "up:   $(curl -s -m 3 http://127.0.0.1:8444/health)"
