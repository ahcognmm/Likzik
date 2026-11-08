#!/usr/bin/env bash
# End-to-end tests for the API gateway (likzik-gw). Needs: curl, python3
# with PyJWT and cryptography. Run from the repo root:
#
#   zig build -Doptimize=safe && tests/integration/gateway.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
GW=${LIKZIK_GW:-$ROOT/zig-out/bin/likzik-gw}
CORE=${LIKZIK:-$ROOT/zig-out/bin/likzik}
WORK=$(mktemp -d /tmp/likzik-gw-it.XXXXXX)
export NO_PROXY='*' no_proxy='*'
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { if [ "$2" == "$3" ]; then ok "$1"; else bad "$1 (want '$3', got '$2')"; fi; }
has()   { if echo "$2" | grep -qi -- "$3"; then ok "$1"; else bad "$1 (missing '$3')"; fi; }
hasnt() { if echo "$2" | grep -qi -- "$3"; then bad "$1 (unexpected '$3')"; else ok "$1"; fi; }
cleanup() {
  [ -n "${LPID:-}" ] && kill -9 "$LPID" 2>/dev/null
  [ -n "${EPID:-}" ] && kill "$EPID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

python3 "$ROOT/tests/integration/echo_server.py" 19103 >/dev/null 2>&1 & EPID=$!

# Keys and tokens.
python3 - "$WORK" <<'PY'
import json, sys, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
d = sys.argv[1]
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
j = json.loads(RSAAlgorithm.to_jwk(k.public_key())); j["kid"] = "k1"
json.dump({"keys": [j]}, open(f"{d}/jwks.json", "w"))
base = {"iss": "https://issuer.test", "aud": "api", "sub": "alice", "tenant": "acme", "exp": 4102444800}
t = {
  "good": jwt.encode(base, k, algorithm="RS256", headers={"kid": "k1"}),
  "expired": jwt.encode({**base, "exp": 1000000000}, k, algorithm="RS256", headers={"kid": "k1"}),
  "wrong_aud": jwt.encode({**base, "aud": "other"}, k, algorithm="RS256", headers={"kid": "k1"}),
  "none": jwt.encode(base, None, algorithm="none"),
}
for n, v in t.items(): open(f"{d}/{n}.jwt", "w").write(v)
PY
KEY_HASH=$(printf 'bob-key-123' | sha256sum | cut -d' ' -f1)

cat > "$WORK/gw.json" <<JSON
{ "workers": 2, "admin": { "address": "127.0.0.1:19911" },
  "listeners": [
    { "name": "api", "address": "127.0.0.1:18180", "route_config": "core" },
    { "name": "plain", "address": "127.0.0.1:18181", "route_config": "core" } ],
  "route_configs": [ { "name": "core", "virtual_hosts": [ { "name": "all", "domains": ["*"],
    "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "echo" } } ] } ] } ],
  "clusters": [ { "name": "echo", "endpoints": [ { "address": "127.0.0.1:19103" } ] } ],
  "extensions": { "gateway": {
    "listeners": ["api"],
    "api_keys": [ { "name": "keys", "query": "api_key",
      "keys": [ { "consumer": "alice", "key": "alice-key-123" }, { "consumer": "bob", "sha256": "$KEY_HASH" } ] } ],
    "jwt": [ { "name": "idp", "algorithms": ["RS256"], "issuer": "https://issuer.test", "audiences": ["api"],
      "jwks_file": "$WORK/jwks.json",
      "claims_to_headers": [ { "claim": "sub", "header": "X-User-Id" }, { "claim": "tenant", "header": "X-Tenant" } ] } ],
    "rate_limits": [ { "name": "five", "requests": 5, "per": "second", "burst": 5 } ],
    "routes": [
      { "name": "me", "path": "/v1/users/me", "cluster": "echo", "rewrite": "/self" },
      { "name": "user", "path": "/v1/users/:id", "methods": ["GET"], "cluster": "echo",
        "rewrite": "/users/{id}", "request_headers": { "set": [ { "name": "X-Gw-Route", "value": "user:{id}" } ] },
        "response_headers": { "set": [ { "name": "X-Frame-Options", "value": "DENY" } ] } },
      { "name": "v2", "path": "/v1/things", "headers": [ { "name": "X-Version", "value": "2" } ], "cluster": "echo", "rewrite": "/v2/things" },
      { "name": "v1", "path": "/v1/things", "cluster": "echo", "rewrite": "/v1/things" },
      { "name": "keyed", "path": "/keyed/*rest", "auth": ["keys"], "cluster": "echo", "rewrite": "/{rest}" },
      { "name": "jwt", "path": "/jwt", "auth": ["idp"], "cluster": "echo" },
      { "name": "either", "path": "/either", "auth": ["keys", "idp"], "cluster": "echo" },
      { "name": "optional", "path": "/optional", "auth": ["keys"], "auth_optional": true, "cluster": "echo" },
      { "name": "limited", "path": "/limited", "rate_limits": ["five"], "cluster": "echo" },
      { "name": "old", "path": "/old/:id", "redirect": { "status": 301, "location": "{scheme}://{host}/new/{id}" } },
      { "name": "health", "path": "/health", "respond": { "status": 200, "body": "ok\n" } }
    ] } } }
JSON

check "plain likzik refuses an extensions section" "$("$CORE" -c "$WORK/gw.json" --check 2>&1 | grep -c 'use likzik-gw')" "1"
check "likzik-gw --check accepts the config" "$("$GW" -c "$WORK/gw.json" --check >/dev/null 2>&1; echo $?)" "0"
"$GW" -c "$WORK/gw.json" --no-pin ${LIKZIK_ARGS:-} > "$WORK/gw.log" 2>&1 & LPID=$!
for _ in $(seq 50); do curl -s -o /dev/null 127.0.0.1:19911/ready && break; sleep 0.1; done
P=127.0.0.1:18180
first() { curl -s "$@" | head -1 | tr -d '\r'; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "routing"
check "param route + rewrite" "$(first $P/v1/users/42)" "GET /users/42 HTTP/1.1"
check "static beats param" "$(first $P/v1/users/me)" "GET /self HTTP/1.1"
check "header matcher picks v2" "$(first -H 'X-Version: 2' $P/v1/things)" "GET /v2/things HTTP/1.1"
check "without header -> v1" "$(first $P/v1/things)" "GET /v1/things HTTP/1.1"
check "query string kept on rewrite" "$(first "$P/v1/users/7?x=1&y=2")" "GET /users/7?x=1&y=2 HTTP/1.1"
check "dot segments normalized for matching" "$(first $P/v1/admin/../users/9)" "GET /users/9 HTTP/1.1"
check "method mismatch -> 404" "$(code -X DELETE $P/v1/users/42)" "404"
check "no route -> 404 json" "$(curl -s $P/nope)" '{"error":"no_route"}'
check "listener outside the gateway uses core routes" "$(first 127.0.0.1:18181/anything)" "GET /anything HTTP/1.1"

echo "transforms"
H=$(curl -s $P/v1/users/42)
has "request header set from template" "$H" "X-Gw-Route: user:42"
check "response header added" "$(curl -s -D - -o /dev/null $P/v1/users/1 | grep -i '^X-Frame-Options' | tr -d '\r')" "X-Frame-Options: DENY"
check "redirect with template" "$(curl -s -D - -o /dev/null -H 'Host: api.test' $P/old/42 | grep -iE '^(HTTP|Location)' | tr -d '\r' | tr '\n' ' ')" "HTTP/1.1 301 Moved Permanently Location: http://api.test/new/42 "
check "fixed response" "$(curl -s $P/health)" "ok"

echo "api keys"
check "missing key -> 401" "$(code $P/keyed/x)" "401"
check "WWW-Authenticate on 401" "$(curl -s -D - -o /dev/null $P/keyed/x | grep -ci '^WWW-Authenticate: ApiKey')" "1"
check "wrong key -> 401" "$(code -H 'X-API-Key: nope' $P/keyed/x)" "401"
H=$(curl -s -H 'X-API-Key: alice-key-123' -H 'X-Consumer: mallory' $P/keyed/a/b)
has "valid key forwards" "$H" "GET /a/b HTTP/1.1"
has "consumer header set" "$H" "X-Consumer: alice"
hasnt "client-supplied consumer header removed" "$H" "X-Consumer: mallory"
hasnt "key header stripped" "$H" "X-API-Key"
H=$(curl -s "$P/keyed/q?api_key=bob-key-123&keep=1")
has "key by sha256, from query" "$H" "X-Consumer: bob"
has "key removed from query" "$H" "GET /q?keep=1 HTTP/1.1"

echo "jwt"
J() { cat "$WORK/$1.jwt"; }
check "missing token -> 401" "$(code $P/jwt)" "401"
H=$(curl -s -H "Authorization: Bearer $(J good)" -H 'X-User-Id: mallory' $P/jwt)
has "valid RS256 token forwards" "$H" "GET /jwt HTTP/1.1"
has "sub claim -> X-User-Id" "$H" "X-User-Id: alice"
hasnt "spoofed claim header removed" "$H" "X-User-Id: mallory"
has "tenant claim -> X-Tenant" "$H" "X-Tenant: acme"
check "expired -> 401" "$(code -H "Authorization: Bearer $(J expired)" $P/jwt)" "401"
check "wrong audience -> 401" "$(code -H "Authorization: Bearer $(J wrong_aud)" $P/jwt)" "401"
check "alg none -> 401" "$(code -H "Authorization: Bearer $(J none)" $P/jwt)" "401"
check "invalid_token hint" "$(curl -s -D - -o /dev/null -H "Authorization: Bearer $(J expired)" $P/jwt | grep -ci 'error=\"invalid_token\"')" "1"
check "either: api key accepted" "$(code -H 'X-API-Key: alice-key-123' $P/either)" "200"
check "either: jwt accepted" "$(code -H "Authorization: Bearer $(J good)" $P/either)" "200"
check "optional auth: anonymous allowed" "$(code $P/optional)" "200"
check "optional auth: bad key still rejected" "$(code -H 'X-API-Key: nope' $P/optional)" "401"

echo "rate limiting"
codes=$(for i in $(seq 7); do code $P/limited; echo; done)
check "5 allowed, 2 limited" "$(echo "$codes" | grep -c 200) $(echo "$codes" | grep -c 429)" "5 2"
check "Retry-After on 429" "$(curl -s -D - -o /dev/null $P/limited | grep -ci '^Retry-After: ')" "1"
sleep 1.1
check "refilled after a second" "$(code $P/limited)" "200"

echo "operations"
check "gateway metrics exported" "$(curl -s 127.0.0.1:19911/metrics | grep -c '^likzik_gateway_rate_limited_total [1-9]')" "1"
sed 's/"rewrite": "\/self"/"rewrite": "\/self-v2"/' "$WORK/gw.json" > "$WORK/gw.json.tmp" && mv "$WORK/gw.json.tmp" "$WORK/gw.json"
sleep 0.5
check "route change hot-reloaded" "$(first $P/v1/users/me)" "GET /self-v2 HTTP/1.1"
sed 's/"cluster": "echo", "rewrite": "\/self-v2"/"cluster": "nope", "rewrite": "\/self-v2"/' "$WORK/gw.json" > "$WORK/gw.json.tmp" && mv "$WORK/gw.json.tmp" "$WORK/gw.json"
check "bad gateway config rejected on reload" "$(curl -s -X POST 127.0.0.1:19911/reload | grep -c "unknown cluster 'nope'")" "1"
check "old gateway config keeps serving" "$(first $P/v1/users/me)" "GET /self-v2 HTTP/1.1"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
