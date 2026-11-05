#!/usr/bin/env bash
# Benchmark likzik against nginx as a reverse proxy, same box, same
# upstreams, same worker count. Needs nginx and wrk; uses wrk2 (fixed-rate,
# latency-corrected) when it is on PATH.
#
#   zig build -Doptimize=fast
#   bench/vs_nginx.sh [workers] [duration_s] [connections]
#
# This is the quick, single-host harness. For numbers worth publishing,
# follow docs/benchmarking.md: separate load-generator hosts, IRQ/RSS
# pinning, performance governor, and fixed offered load (wrk2/vegeta).
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIKZIK=${LIKZIK:-$ROOT/zig-out/bin/likzik}
W=${1:-2}; DUR=${2:-10}; CONNS=${3:-64}
WORK=$(mktemp -d /tmp/likzik-bench.XXXXXX); chmod 755 "$WORK"
mkdir -p "$WORK/www"; chmod 755 "$WORK/www"
head -c 1048576 /dev/urandom > "$WORK/www/1m.bin"; chmod 644 "$WORK/www/1m.bin"
cleanup() {
  for p in up px; do [ -f "$WORK/$p.pid" ] && kill "$(cat "$WORK/$p.pid")" 2>/dev/null || true; done
  [ -n "${LPID:-}" ] && kill "$LPID" 2>/dev/null || true
  sleep 0.3; rm -rf "$WORK"
}
trap cleanup EXIT
STREAM_MOD=""
[ -f /usr/lib/nginx/modules/ngx_stream_module.so ] && STREAM_MOD="load_module /usr/lib/nginx/modules/ngx_stream_module.so;"

temps="client_body_temp_path $WORK/b; proxy_temp_path $WORK/p; fastcgi_temp_path $WORK/f; uwsgi_temp_path $WORK/u; scgi_temp_path $WORK/s;"
cat > "$WORK/up.conf" <<NGX
worker_processes $W; daemon on; pid $WORK/up.pid; error_log $WORK/up.err;
events { worker_connections 16384; }
http { access_log off; keepalive_requests 10000000; $temps
  server { listen 127.0.0.1:29001 reuseport backlog=4096; root $WORK/www; location = / { return 200 "hello world\n"; } }
}
NGX
cat > "$WORK/px.conf" <<NGX
$STREAM_MOD
worker_processes $W; daemon on; pid $WORK/px.pid; error_log $WORK/px.err;
events { worker_connections 16384; }
http { access_log off; keepalive_requests 10000000; $temps
  upstream backend { server 127.0.0.1:29001; keepalive 256; }
  server { listen 127.0.0.1:28081 reuseport backlog=4096;
    location / { proxy_pass http://backend; proxy_http_version 1.1; proxy_set_header Connection "";
                 proxy_set_header X-Forwarded-For \$remote_addr; } }
}
$( [ -n "$STREAM_MOD" ] && echo "stream { server { listen 127.0.0.1:28444 reuseport; proxy_pass 127.0.0.1:29001; } }" )
NGX
cat > "$WORK/likzik.json" <<JSON
{ "workers": $W, "limits": { "max_connections_per_worker": 32768 },
  "listeners": [ { "name": "web", "address": "127.0.0.1:28080", "route_config": "r" },
                 { "name": "tcp", "address": "127.0.0.1:28443", "protocol": "tcp", "cluster": "up" } ],
  "route_configs": [ { "name": "r", "virtual_hosts": [ { "name": "v", "domains": ["*"],
     "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "up" } } ] } ] } ],
  "clusters": [ { "name": "up", "max_idle_per_endpoint": 256, "endpoints": [ { "address": "127.0.0.1:29001" } ] } ] }
JSON
nginx -c "$WORK/up.conf" -p "$WORK"; nginx -c "$WORK/px.conf" -p "$WORK"
"$LIKZIK" -c "$WORK/likzik.json" > "$WORK/likzik.log" 2>&1 & LPID=$!
sleep 1

TOOL=wrk; command -v wrk2 >/dev/null && TOOL=wrk2
run() { # name url extra-args...
  local name=$1 url=$2; shift 2
  local out; out=$($TOOL -t2 -c"$CONNS" -d"${DUR}s" --latency "$@" "$url" 2>&1)
  local rps p50 p99 err
  rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
  p50=$(echo "$out" | awk '$1=="50%" {print $2}')
  p99=$(echo "$out" | awk '$1=="99%" {print $2}')
  err=$(echo "$out" | grep -E "Non-2xx|Socket errors" | tr '\n' ' ')
  printf "| %-28s | %12s | %9s | %9s | %s\n" "$name" "$rps" "$p50" "$p99" "${err:-}"
}
echo "kernel $(uname -r), $(nproc) CPUs, $W workers each, $CONNS connections, ${DUR}s, tool: $TOOL"
printf "| %-28s | %12s | %9s | %9s | %s\n" "workload" "req/s" "p50" "p99" "errors"
for target in likzik:28080 nginx:28081; do
  n=${target%%:*}; p=${target##*:}
  run "$n keep-alive" "http://127.0.0.1:$p/"
  run "$n new connection" "http://127.0.0.1:$p/" -H "Connection: close"
  run "$n 1 MiB body" "http://127.0.0.1:$p/1m.bin"
done
run "likzik tcp passthrough" "http://127.0.0.1:28443/"
[ -n "$STREAM_MOD" ] && run "nginx tcp passthrough" "http://127.0.0.1:28444/"
run "upstream direct (baseline)" "http://127.0.0.1:29001/"
