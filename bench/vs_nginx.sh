#!/usr/bin/env bash
# Benchmark likzik against nginx as a reverse proxy, same box, same
# upstreams, same worker count, same certificates and TLS settings.
#
#   zig build -Doptimize=fast
#   bench/vs_nginx.sh [workers=2] [duration_s=10] [connections=64]
#
# Environment:
#   SECTIONS     which sections to run (default "http https rate")
#   LIKZIK_ARGS  extra likzik flags (e.g. "--no-pin")
#   RATE         fixed request rate for the "rate" section (default: 70%
#                of the slower proxy's peak keep-alive rate)
#   WRK2         path to wrk2 (default: `wrk2` on PATH); the rate section
#                needs it, the peak sections use wrk
#
#   LOADGEN      run wrk/wrk2 on another host over ssh (e.g. "bench@10.0.0.5"),
#                as docs/benchmarking.md asks; that host needs wrk and wrk2
#   TARGET       address the load generator uses to reach this host
#                (default 127.0.0.1; set it with LOADGEN)
#   BIND         address the proxies listen on (default 127.0.0.1, or
#                0.0.0.0 when LOADGEN is set)
#
# Without LOADGEN this is the quick, single-host harness. For numbers worth publishing,
# follow docs/benchmarking.md: separate load-generator hosts, IRQ/RSS
# pinning, performance governor, fixed offered load.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIKZIK=${LIKZIK:-$ROOT/zig-out/bin/likzik}
W=${1:-2}; DUR=${2:-10}; CONNS=${3:-64}
SECTIONS=${SECTIONS:-"http https rate"}
LOADGEN=${LOADGEN:-}
if [ -n "$LOADGEN" ]; then
  BIND=${BIND:-0.0.0.0}
  TARGET=${TARGET:?set TARGET to the address of this host as seen from the load generator}
  WRK2=${WRK2:-$(ssh "$LOADGEN" 'command -v wrk2' || true)}
  ssh "$LOADGEN" 'command -v wrk' >/dev/null || { echo "wrk not found on $LOADGEN"; exit 1; }
else
  BIND=${BIND:-127.0.0.1}; TARGET=${TARGET:-127.0.0.1}
  WRK2=${WRK2:-$(command -v wrk2 || true)}
fi
# Run the load generator locally, or on $LOADGEN.
lg() { if [ -n "$LOADGEN" ]; then ssh "$LOADGEN" "$(printf '%q ' "$@")"; else "$@"; fi; }
has() { [[ " $SECTIONS " == *" $1 "* ]]; }

WORK=$(mktemp -d /tmp/likzik-bench.XXXXXX); chmod 755 "$WORK"
mkdir -p "$WORK/www"; chmod 755 "$WORK/www"
head -c 1048576 /dev/urandom > "$WORK/www/1m.bin"; chmod 644 "$WORK/www/1m.bin"
cleanup() {
  for p in up px; do [ -f "$WORK/$p.pid" ] && kill "$(cat "$WORK/$p.pid")" 2>/dev/null || true; done
  [ -n "${LPID:-}" ] && kill "$LPID" 2>/dev/null || true
  sleep 0.3; rm -rf "$WORK"
}
trap cleanup EXIT

# One self-signed ECDSA P-256 certificate, used by both proxies and by the
# TLS upstream (which both proxies verify against it).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=bench.test" \
  -addext "subjectAltName=DNS:bench.test" 2>/dev/null
chmod 644 "$WORK"/*.pem

KTLS=no; [ -r /proc/net/tls_stat ] && KTLS=yes
REQUIRE_KTLS=false; [ "$KTLS" = yes ] && REQUIRE_KTLS=true

STREAM_MOD=""
[ -f /usr/lib/nginx/modules/ngx_stream_module.so ] && STREAM_MOD="load_module /usr/lib/nginx/modules/ngx_stream_module.so;"
temps="client_body_temp_path $WORK/b; proxy_temp_path $WORK/p; fastcgi_temp_path $WORK/f; uwsgi_temp_path $WORK/u; scgi_temp_path $WORK/s;"
# Same TLS policy on both proxies: TLS 1.2/1.3, AEAD suites, kTLS on.
nginx_tls="ssl_certificate $WORK/cert.pem; ssl_certificate_key $WORK/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_cache shared:S:10m; ssl_conf_command Options KTLS;"

cat > "$WORK/up.conf" <<NGX
worker_processes $W; daemon on; pid $WORK/up.pid; error_log $WORK/up.err;
events { worker_connections 16384; }
http { access_log off; keepalive_requests 10000000; $temps
  server { listen 127.0.0.1:29001 reuseport backlog=4096; root $WORK/www; location = / { return 200 "hello world\n"; } }
  server { listen 127.0.0.1:29002 ssl reuseport backlog=4096; $nginx_tls
           root $WORK/www; location = / { return 200 "hello world\n"; } }
}
NGX
cat > "$WORK/px.conf" <<NGX
$STREAM_MOD
worker_processes $W; daemon on; pid $WORK/px.pid; error_log $WORK/px.err;
events { worker_connections 16384; }
http { access_log off; keepalive_requests 10000000; $temps
  # Same keep-alive limits as likzik: no recycling of downstream or
  # upstream connections during a run.
  upstream backend { server 127.0.0.1:29001; keepalive 256; keepalive_requests 10000000; }
  upstream backend_tls { server 127.0.0.1:29002; keepalive 256; keepalive_requests 10000000; }
  proxy_http_version 1.1; proxy_set_header Connection ""; proxy_set_header X-Forwarded-For \$remote_addr;
  server { listen $BIND:28081 reuseport backlog=4096; location / { proxy_pass http://backend; } }
  server { listen $BIND:28082 ssl reuseport backlog=4096; $nginx_tls
           location / { proxy_pass http://backend; } }
  server { listen $BIND:28083 ssl reuseport backlog=4096; $nginx_tls
           location / { proxy_pass https://backend_tls; proxy_ssl_verify on; proxy_ssl_trusted_certificate $WORK/cert.pem;
                        proxy_ssl_name bench.test; proxy_ssl_server_name on; proxy_ssl_session_reuse on; } }
}
$( [ -n "$STREAM_MOD" ] && echo "stream { server { listen $BIND:28444 reuseport; proxy_pass 127.0.0.1:29001; } }" )
NGX
cert='{ "certificates": [ { "certificate_chain": "'$WORK'/cert.pem", "private_key": "'$WORK'/key.pem" } ] }'
cat > "$WORK/likzik.json" <<JSON
{ "workers": $W, "admin": { "address": "127.0.0.1:28901" },
  "limits": { "max_connections_per_worker": 32768, "max_requests_per_connection": 10000000 },
  "tls": { "require_ktls": $REQUIRE_KTLS },
  "listeners": [
    { "name": "web", "address": "$BIND:28080", "route_config": "r" },
    { "name": "tcp", "address": "$BIND:28443", "protocol": "tcp", "cluster": "up" },
    { "name": "https", "address": "$BIND:28084", "route_config": "r", "tls": $cert },
    { "name": "https_tls_up", "address": "$BIND:28085", "route_config": "rt", "tls": $cert } ],
  "route_configs": [
    { "name": "r", "virtual_hosts": [ { "name": "v", "domains": ["*"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "up" } } ] } ] },
    { "name": "rt", "virtual_hosts": [ { "name": "v", "domains": ["*"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "up_tls" } } ] } ] } ],
  "clusters": [
    { "name": "up", "max_idle_per_endpoint": 256, "endpoints": [ { "address": "127.0.0.1:29001" } ] },
    { "name": "up_tls", "max_idle_per_endpoint": 256, "tls": { "sni": "bench.test", "ca_file": "$WORK/cert.pem" },
      "endpoints": [ { "address": "127.0.0.1:29002" } ] } ] }
JSON
nginx -c "$WORK/up.conf" -p "$WORK"; nginx -c "$WORK/px.conf" -p "$WORK"
"$LIKZIK" -c "$WORK/likzik.json" ${LIKZIK_ARGS:-} > "$WORK/likzik.log" 2>&1 & LPID=$!
for _ in $(seq 50); do curl -s -o /dev/null --noproxy '*' http://127.0.0.1:28901/ready && break; sleep 0.1; done

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
# Kernel TLS sessions set up (TX direction; software kTLS), system-wide.
ktls_tx() { if [ "$KTLS" = yes ]; then awk '/^TlsTxSw / {print $2}' /proc/net/tls_stat; else echo 0; fi; }

hdr() {
  printf "| %-34s | %10s | %9s | %9s | %5s | %7s | %6s | %6s | %s\n" "workload" "req/s" "p50" "p99" "cpu" "cpu/req" "pss MB" "kTLS" "errors"
  printf "| %-34s | %10s | %9s | %9s | %5s | %7s | %6s | %6s | %s\n" "---" "---:" "---:" "---:" "---:" "---:" "---:" "---:" "---"
}

LAST_RPS=0
# run proxy name tls(yes/no) url extra-args...   (peak throughput, wrk)
run() {
  local proxy=$1 name=$2 tls=$3 url=$4; shift 4
  local pids c0 c1 k0 k1 out rps p50 p99 err cores us pss kt
  pids=$(pids_of "$proxy")
  c0=$(cpu_ticks "$pids"); k0=$(ktls_tx)
  out=$(lg wrk -t2 -c"$CONNS" -d"${DUR}s" --latency "$@" "$url" 2>&1)
  c1=$(cpu_ticks "$pids"); k1=$(ktls_tx)
  pss=$(pss_kb "$pids")
  rps=$(echo "$out" | awk '/Requests\/sec/ {print $2}'); LAST_RPS=${rps%.*}
  p50=$(echo "$out" | awk '$1=="50%" {print $2}')
  p99=$(echo "$out" | awk '$1=="99%" {print $2}')
  err=$(echo "$out" | grep -E "Non-2xx|Socket errors" | sed 's/^ *//' | tr '\n' ' ')
  cores=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" 'BEGIN {printf "%.2f", t / hz / d}')
  us=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" -v r="$rps" 'BEGIN {if (r > 0) printf "%.2f", (t / hz) * 1e6 / (r * d); else print "-"}')
  kt="-"; [ "$tls" = yes ] && { [ "$KTLS" = yes ] && kt=$((k1 - k0)) || kt="n/a"; }
  printf "| %-34s | %10s | %9s | %9s | %5s | %7s | %6.1f | %6s | %s\n" "$name" "$rps" "$p50" "$p99" "$cores" "$us" "$(awk -v k="$pss" 'BEGIN {print k / 1024}')" "$kt" "${err:-}"
}

# rate proxy name url rate extra-args...   (fixed offered load, wrk2)
rate() {
  local proxy=$1 name=$2 url=$3 r=$4; shift 4
  local pids c0 c1 out p50 p99 p999 p9999 got cores us
  pids=$(pids_of "$proxy")
  c0=$(cpu_ticks "$pids")
  out=$(lg "$WRK2" -t2 -c"$CONNS" -d"${DUR}s" -R"$r" --latency "$@" "$url" 2>&1)
  c1=$(cpu_ticks "$pids")
  got=$(echo "$out" | awk '/Requests\/sec/ {print $2}')
  p50=$(echo "$out" | awk '$1=="50.000%" {print $2}')
  p99=$(echo "$out" | awk '$1=="99.000%" {print $2}')
  p999=$(echo "$out" | awk '$1=="99.900%" {print $2}')
  p9999=$(echo "$out" | awk '$1=="99.990%" {print $2}')
  cores=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" 'BEGIN {printf "%.2f", t / hz / d}')
  us=$(awk -v t=$((c1 - c0)) -v hz="$HZ" -v d="$DUR" -v r="$got" 'BEGIN {if (r > 0) printf "%.2f", (t / hz) * 1e6 / (r * d); else print "-"}')
  printf "| %-34s | %10s | %9s | %9s | %9s | %9s | %5s | %7s\n" "$name" "$got" "$p50" "$p99" "$p999" "$p9999" "$cores" "$us"
}

echo "kernel $(uname -r), $(nproc) CPUs ($(uname -m)), $W workers each, $CONNS connections, ${DUR}s"
echo "kernel TLS module: $KTLS (likzik require_ktls=$REQUIRE_KTLS; nginx: ssl_conf_command Options KTLS)"
echo "cpu = proxy CPU cores used on average; cpu/req = proxy CPU time per request (us); pss = proxy memory after the run;"
echo "kTLS = kernel TLS sessions set up during the run (TlsTxSw delta), n/a when the tls module is not loaded"
echo

declare -A PEAK
if has http; then
  echo "## HTTP (wrk, peak)"; hdr
  for proxy in likzik:28080 nginx:28081; do
    n=${proxy%%:*}; p=${proxy##*:}
    run "$n" "$n keep-alive" no "http://$TARGET:$p/"; PEAK[$n-http]=$LAST_RPS
    run "$n" "$n new connection" no "http://$TARGET:$p/" -H "Connection: close"
    run "$n" "$n 1 MiB body" no "http://$TARGET:$p/1m.bin"
  done
  run likzik "likzik tcp passthrough" no "http://$TARGET:28443/"
  [ -n "$STREAM_MOD" ] && run nginx "nginx tcp passthrough" no "http://$TARGET:28444/"
  echo
fi

if has https; then
  echo "## HTTPS (wrk, peak; TLS 1.3, ECDSA P-256)"; hdr
  for proxy in likzik:28084:28085 nginx:28082:28083; do
    IFS=: read -r n p pt <<< "$proxy"
    run "$n" "$n https keep-alive" yes "https://$TARGET:$p/"; PEAK[$n-https]=$LAST_RPS
    run "$n" "$n https new connection" yes "https://$TARGET:$p/" -H "Connection: close"
    run "$n" "$n https 1 MiB body" yes "https://$TARGET:$p/1m.bin"
    run "$n" "$n https -> https upstream" yes "https://$TARGET:$pt/"
  done
  if [ "$KTLS" = yes ]; then
    echo; echo "likzik connection modes: $(curl -s --noproxy '*' http://127.0.0.1:28901/stats | grep -E '^tls_(ktls|userspace):' | tr '\n' ' ')"
  fi
  echo
fi

if has rate; then
  if [ -z "$WRK2" ]; then
    echo "## Fixed rate: skipped (install wrk2 or set WRK2=path for p99 at equal offered load)"
  else
    echo "## Fixed offered load (wrk2, latency corrected for coordinated omission)"
    printf "| %-34s | %10s | %9s | %9s | %9s | %9s | %5s | %7s\n" "workload @ rate" "req/s" "p50" "p99" "p99.9" "p99.99" "cpu" "cpu/req"
    printf "| %-34s | %10s | %9s | %9s | %9s | %9s | %5s | %7s\n" "---" "---:" "---:" "---:" "---:" "---:" "---:" "---:"
    for kind in http https; do
      a=${PEAK[likzik-$kind]:-0}; b=${PEAK[nginx-$kind]:-0}
      r=${RATE:-$(( (a < b ? a : b) * 7 / 10 ))}
      [ "$r" -gt 0 ] || { [ "$kind" = http ] && r=50000 || r=30000; }
      if [ "$kind" = http ]; then
        rate likzik "likzik keep-alive @ $r" "http://$TARGET:28080/" "$r"
        rate nginx "nginx keep-alive @ $r" "http://$TARGET:28081/" "$r"
      else
        rate likzik "likzik https keep-alive @ $r" "https://$TARGET:28084/" "$r"
        rate nginx "nginx https keep-alive @ $r" "https://$TARGET:28082/" "$r"
      fi
    done
  fi
  echo
fi

echo "peak memory (sum of VmHWM, counts shared pages per process): likzik $(( $(peak_kb "$(pids_of likzik)") / 1024 )) MB, nginx $(( $(peak_kb "$(pids_of nginx)") / 1024 )) MB"
