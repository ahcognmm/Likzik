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
"$LIKZIK" -c "$WORK/likzik.json" ${LIKZIK_ARGS:-} > "$WORK/likzik.log" 2>&1 & LPID=$!
sleep 1

TOOL=wrk; command -v wrk2 >/dev/null && TOOL=wrk2
HZ=$(getconf CLK_TCK)

# Resource accounting from /proc, for the proxy processes only (not wrk,
# not the upstream). CPU is utime+stime of every thread; memory is PSS
# (proportional set size), which splits shared pages fairly between
# nginx's master and workers instead of counting them once per process.
pids_of() { # name
  case $1 in
    likzik) echo "$LPID" ;;
    nginx)  local m; m=$(cat "$WORK/px.pid"); echo "$m $(pgrep -P "$m" | tr '\n' ' ')" ;;
  esac
}
cpu_ticks() { local t=0 p; for p in $1; do t=$((t + $(awk '{print $14 + $15}' "/proc/$p/stat"))); done; echo $t; }
pss_kb() { local t=0 p; for p in $1; do t=$((t + $(awk '/^Pss:/ {print $2}' "/proc/$p/smaps_rollup"))); done; echo $t; }
peak_kb() { local t=0 p; for p in $1; do t=$((t + $(awk '/^VmHWM:/ {print $2}' "/proc/$p/status"))); done; echo $t; }

run() { # proxy name url extra-args...
  local proxy=$1 name=$2 url=$3; shift 3
  local pids c0 c1 out rps p50 p99 err cores us_per_req pss
  pids=$(pids_of "$proxy")
  c0=$(cpu_ticks "$pids")
  out=$($TOOL -t2 -c"$CONNS" -d"${DUR}s" --latency "$@" "$url" 2>&1)
  c1=$(cpu_ticks "$pids")
  pss=$(pss_kb "$pids")
  rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
  p50=$(echo "$out" | awk '$1=="50%" {print $2}')
  p99=$(echo "$out" | awk '$1=="99%" {print $2}')
  err=$(echo "$out" | grep -E "Non-2xx|Socket errors" | sed 's/^ *//' | tr '\n' ' ')
  cores=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" 'BEGIN {printf "%.2f", t / hz / d}')
  us_per_req=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" -v r="$rps" 'BEGIN {if (r > 0) printf "%.2f", (t / hz) * 1e6 / (r * d); else print "-"}')
  printf "| %-28s | %10s | %9s | %9s | %5s | %7s | %7.1f | %s\n" "$name" "$rps" "$p50" "$p99" "$cores" "$us_per_req" "$(awk -v k="$pss" 'BEGIN {print k / 1024}')" "${err:-}"
}
echo "kernel $(uname -r), $(nproc) CPUs ($(uname -m)), $W workers each, $CONNS connections, ${DUR}s, tool: $TOOL"
echo "cpu = proxy CPU cores used on average; cpu/req = proxy CPU time per request; pss = proxy memory after the run"
printf "| %-28s | %10s | %9s | %9s | %5s | %7s | %7s | %s\n" "workload" "req/s" "p50" "p99" "cpu" "cpu/req" "pss MB" "errors"
printf "| %-28s | %10s | %9s | %9s | %5s | %7s | %7s | %s\n" "---" "---:" "---:" "---:" "---:" "---:" "---:" "---"
for proxy in likzik:28080 nginx:28081; do
  n=${proxy%%:*}; p=${proxy##*:}
  run "$n" "$n keep-alive" "http://127.0.0.1:$p/"
  run "$n" "$n new connection" "http://127.0.0.1:$p/" -H "Connection: close"
  run "$n" "$n 1 MiB body" "http://127.0.0.1:$p/1m.bin"
done
run likzik "likzik tcp passthrough" "http://127.0.0.1:28443/"
[ -n "$STREAM_MOD" ] && run nginx "nginx tcp passthrough" "http://127.0.0.1:28444/"
echo
echo "peak memory (sum of VmHWM, counts shared pages per process): likzik $(( $(peak_kb "$(pids_of likzik)") / 1024 )) MB, nginx $(( $(peak_kb "$(pids_of nginx)") / 1024 )) MB"
