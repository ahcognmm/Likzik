#!/usr/bin/env bash
# Gateway overhead: the same request through likzik (core routing) and
# through likzik-gw with each gateway feature, keep-alive, peak (wrk).
#
#   zig build -Doptimize=fast
#   bench/gateway.sh [workers=2] [duration_s=10] [connections=64]
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=${1:-2}; DUR=${2:-10}; CONNS=${3:-64}
WORK=$(mktemp -d /tmp/likzik-gwbench.XXXXXX); chmod 755 "$WORK"
cleanup() {
  [ -f "$WORK/up.pid" ] && kill "$(cat "$WORK/up.pid")" 2>/dev/null || true
  [ -n "${LPID:-}" ] && kill "$LPID" 2>/dev/null || true
  sleep 0.3; rm -rf "$WORK"
}
trap cleanup EXIT
export NO_PROXY='*' no_proxy='*'
temps="client_body_temp_path $WORK/b; proxy_temp_path $WORK/p; fastcgi_temp_path $WORK/f; uwsgi_temp_path $WORK/u; scgi_temp_path $WORK/s;"
cat > "$WORK/up.conf" <<NGX
worker_processes $W; daemon on; pid $WORK/up.pid; error_log $WORK/up.err;
events { worker_connections 16384; }
http { access_log off; keepalive_requests 10000000; $temps
  server { listen 127.0.0.1:29001 reuseport backlog=4096; location / { return 200 "hello world\n"; } } }
NGX
nginx -c "$WORK/up.conf" -p "$WORK"

python3 - "$WORK" <<'PY'
import json, sys, jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from jwt.algorithms import RSAAlgorithm, ECAlgorithm
d = sys.argv[1]
rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ek = ec.generate_private_key(ec.SECP256R1())
r = json.loads(RSAAlgorithm.to_jwk(rk.public_key())); r["kid"] = "r"
e = json.loads(ECAlgorithm.to_jwk(ek.public_key())); e["kid"] = "e"
json.dump({"keys": [r, e]}, open(f"{d}/jwks.json", "w"))
c = {"iss": "i", "aud": "api", "sub": "alice", "exp": 4102444800}
open(f"{d}/rs256.jwt", "w").write(jwt.encode(c, rk, algorithm="RS256", headers={"kid": "r"}))
open(f"{d}/es256.jwt", "w").write(jwt.encode(c, ek, algorithm="ES256", headers={"kid": "e"}))
open(f"{d}/hs256.jwt", "w").write(jwt.encode(c, "x" * 32, algorithm="HS256"))
PY

cat > "$WORK/cfg.json" <<JSON
{ "workers": $W, "limits": { "max_requests_per_connection": 10000000 },
  "listeners": [ { "name": "web", "address": "127.0.0.1:28080", "route_config": "r" } ],
  "route_configs": [ { "name": "r", "virtual_hosts": [ { "name": "v", "domains": ["*"],
     "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "up" } } ] } ] } ],
  "clusters": [ { "name": "up", "max_idle_per_endpoint": 256, "endpoints": [ { "address": "127.0.0.1:29001" } ] } ],
  "extensions": { "gateway": {
    "api_keys": [ { "name": "keys", "keys": [ { "consumer": "alice", "key": "bench-key" } ] } ],
    "jwt": [ { "name": "idp", "algorithms": ["RS256", "ES256", "HS256"], "audiences": ["api"], "jwks_file": "$WORK/jwks.json", "hs_secret": "$(printf 'x%.0s' $(seq 32))" } ],
    "rate_limits": [ { "name": "big", "requests": 100000000, "per": "second" } ],
    "routes": [
      { "name": "route", "path": "/route", "cluster": "up" },
      { "name": "params", "path": "/users/:id/orders/:order", "cluster": "up", "rewrite": "/o/{order}",
        "request_headers": { "set": [ { "name": "X-User", "value": "{id}" } ] },
        "response_headers": { "remove": ["Server"] } },
      { "name": "apikey", "path": "/apikey", "auth": ["keys"], "cluster": "up" },
      { "name": "jwt", "path": "/jwt", "auth": ["idp"], "cluster": "up" },
      { "name": "limited", "path": "/limited", "rate_limits": ["big"], "cluster": "up" } ] } } }
JSON
# Plain likzik has no extension: the same config minus the gateway section.
python3 -c "import json,sys; c=json.load(open(sys.argv[1])); c.pop('extensions'); json.dump(c, open(sys.argv[2],'w'))" "$WORK/cfg.json" "$WORK/core.json"

HZ=$(getconf CLK_TCK)
cpu() { awk '{print $14 + $15}' "/proc/$LPID/stat"; }
start() { "$@" > "$WORK/l.log" 2>&1 & LPID=$!; sleep 1; }
stop() { kill "$LPID"; wait "$LPID" 2>/dev/null || true; LPID=; }
run() { # name path extra-args...
  local name=$1 path=$2; shift 2
  local c0 c1 out rps p99
  c0=$(cpu)
  out=$(wrk -t2 -c"$CONNS" -d"${DUR}s" --latency "$@" "http://127.0.0.1:28080$path" 2>&1)
  c1=$(cpu)
  rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
  p99=$(echo "$out" | awk '$1=="99%" {print $2}')
  printf "| %-36s | %10s | %9s | %7s | %s\n" "$name" "$rps" "$p99" \
    "$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" -v r="$rps" 'BEGIN {printf "%.2f", (t / hz) * 1e6 / (r * d)}')" \
    "$(echo "$out" | grep -E 'Non-2xx|Socket errors' | tr -d '\n')"
}
echo "kernel $(uname -r), $(nproc) CPUs ($(uname -m)), $W workers, $CONNS connections, ${DUR}s, keep-alive"
printf "| %-36s | %10s | %9s | %7s | %s\n" "workload" "req/s" "p99" "cpu/req" "errors"
printf "| %-36s | %10s | %9s | %7s | %s\n" "---" "---:" "---:" "---:" "---"
start "$ROOT/zig-out/bin/likzik" -c "$WORK/core.json"
run "likzik (core routing)" /route
stop
start "$ROOT/zig-out/bin/likzik-gw" -c "$WORK/cfg.json"
run "likzik-gw: route" /route
run "likzik-gw: params + rewrite + headers" /users/42/orders/7
run "likzik-gw: api key" /apikey -H "X-API-Key: bench-key"
run "likzik-gw: jwt HS256" /jwt -H "Authorization: Bearer $(cat "$WORK/hs256.jwt")"
run "likzik-gw: jwt ES256" /jwt -H "Authorization: Bearer $(cat "$WORK/es256.jwt")"
run "likzik-gw: jwt RS256" /jwt -H "Authorization: Bearer $(cat "$WORK/rs256.jwt")"
run "likzik-gw: rate limit" /limited
stop
