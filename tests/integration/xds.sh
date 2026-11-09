#!/usr/bin/env bash
# End-to-end tests for the xDS client (ADS, state of the world) against a
# small Python control plane built on Envoy's protos. Needs: curl, python3
# with grpcio and xds-protos. Run from the repo root:
#
#   zig build -Doptimize=safe && tests/integration/xds.sh
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LIKZIK=${LIKZIK:-$ROOT/zig-out/bin/likzik}
WORK=$(mktemp -d /tmp/likzik-xds-it.XXXXXX)
export NO_PROXY='*' no_proxy='*'
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { if [ "$2" == "$3" ]; then ok "$1"; else bad "$1 (want '$3', got '$2')"; fi; }
pids=()
cleanup() {
  [ -n "${LPID:-}" ] && kill -9 "$LPID" 2>/dev/null
  [ -n "${XPID:-}" ] && kill "$XPID" 2>/dev/null
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  [ "$FAIL" -gt 0 ] && { echo "--- likzik log"; tail -40 "$WORK/likzik.log"; }
  rm -rf "$WORK"
}
trap cleanup EXIT

python3 -c 'import grpc, envoy' 2>/dev/null || { echo "needs python3 grpcio and xds-protos (pip install grpcio xds-protos)"; exit 1; }

# Two upstreams that answer "a" and "b".
for n in a b; do mkdir -p "$WORK/$n"; echo "$n" > "$WORK/$n/index.html"; done
python3 -m http.server 19301 --bind 127.0.0.1 --directory "$WORK/a" >/dev/null 2>&1 & pids+=($!)
python3 -m http.server 19302 --bind 127.0.0.1 --directory "$WORK/b" >/dev/null 2>&1 & pids+=($!)

start_cp() { python3 "$ROOT/tests/integration/xds_server.py" 18700 18701 > "$WORK/cp.log" 2>&1 & XPID=$!; sleep 1.5; }
put() { curl -s -X PUT --data "$1" 127.0.0.1:18701/state; sleep 1.2; }
reqs() { curl -s 127.0.0.1:18701/requests; }
get() { curl -s -m 2 "http://127.0.0.1:$1$2"; }
stat() { curl -s 127.0.0.1:18702/stats | grep "^$1:" | awk '{print $2}'; }

state() { # version endpoint route-cluster
  cat <<JSON
{"version":"$1",
 "clusters":[{"name":"web","eds":true},{"name":"static","endpoints":["127.0.0.1:19302"]}],
 "endpoints":{"web":["$2"]},
 "listeners":[{"name":"xweb","port":18790,"rds":"main"},{"name":"xtcp","port":18791,"tcp_cluster":"static"}],
 "routes":[{"name":"main","vhosts":[{"name":"all","domains":["*"],"routes":[{"prefix":"/","cluster":"$3"}]}]}]}
JSON
}

start_cp
put "$(state 1 127.0.0.1:19301 web)"

# The file defines no listeners: everything comes from xDS. A file
# listener and cluster still work next to them.
cat > "$WORK/likzik.json" <<JSON
{ "version": "file-1", "workers": 2, "admin": { "address": "127.0.0.1:18702" },
  "xds": { "address": "127.0.0.1:18700", "node_id": "it-node" },
  "listeners": [ { "name": "file", "address": "127.0.0.1:18792", "protocol": "tcp", "cluster": "file_up" } ],
  "clusters": [ { "name": "file_up", "endpoints": [ { "address": "127.0.0.1:19301" } ] } ] }
JSON
"$LIKZIK" -c "$WORK/likzik.json" --no-pin ${LIKZIK_ARGS:-} > "$WORK/likzik.log" 2>&1 & LPID=$!
for _ in $(seq 50); do [ "$(stat xds_updates_accepted)" -ge 4 ] 2>/dev/null && break; sleep 0.1; done

echo "subscribe and serve"
check "HTTP listener from LDS, routes from RDS, endpoints from EDS" "$(get 18790 /)" "a"
check "TCP listener from LDS to a static cluster" "$(get 18791 /)" "b"
check "file listener next to xDS ones" "$(get 18792 /)" "a"
check "node id sent" "$(reqs | head -1 | grep -c '"node": "it-node"')" "1"
check "every type ACKed with version 1" "$(reqs | grep '"version": "1"' | grep '"error": null' | python3 -c 'import sys,json; print(" ".join(sorted({json.loads(l)["type"] for l in sys.stdin})))')" "Cluster ClusterLoadAssignment Listener RouteConfiguration"
check "EDS subscribed by cluster name" "$(reqs | grep ClusterLoadAssignment | tail -1 | grep -c '"names": \["web"\]')" "1"

echo "updates"
put "$(state 2 127.0.0.1:19302 web)"
check "EDS update moves traffic" "$(get 18790 /)" "b"
put "$(state 3 127.0.0.1:19302 static)"
check "RDS update changes the route" "$(get 18790 /)" "b"

echo "rejections (NACK)"
put "$(state 4 127.0.0.1:19302 nope)"
check "route to an unknown cluster is NACKed with the validator's message" "$(reqs | grep RouteConfiguration | tail -1 | grep -c "unknown cluster 'nope'")" "1"
check "NACK keeps the accepted version" "$(reqs | grep RouteConfiguration | tail -1 | grep -c '"version": "3"')" "1"
check "old routes keep serving" "$(get 18790 /)" "b"
check "rejection counted" "$(stat xds_updates_rejected)" "1"
put "$(state 5 127.0.0.1:19301 web)"
check "a good update after a NACK applies" "$(get 18790 /)" "a"

echo "config file reload keeps xDS resources"
sed -i 's/"file-1"/"file-2"/' "$WORK/likzik.json"; sleep 0.8
check "file change applied" "$(curl -s 127.0.0.1:18702/server_info | grep -c '"version":"file-2"')" "1"
check "xDS listener still serving" "$(get 18790 /)" "a"

echo "control plane restart"
kill "$XPID"; wait "$XPID" 2>/dev/null; sleep 0.5
check "stream down is reported" "$(stat xds_connected)" "0"
check "last config keeps serving without the control plane" "$(get 18790 /)" "a"
start_cp
put "$(state 6 127.0.0.1:19302 web)"
for _ in $(seq 40); do [ "$(stat xds_connected)" = 1 ] && [ "$(get 18790 /)" = b ] && break; sleep 0.25; done
check "reconnects and applies new versions" "$(get 18790 /)" "b"
check "resubscribes to every type from the accepted versions" "$(reqs | grep '"nonce": ""' | grep '"version": "5"' | python3 -c 'import sys,json; print(len({json.loads(l)["type"] for l in sys.stdin}))')" "4"

echo "listener removal"
put '{"version":"7","clusters":[{"name":"web","eds":true}],"endpoints":{"web":["127.0.0.1:19302"]},"listeners":[],"routes":[]}'
check "listener removed from LDS stops" "$(curl -s -m 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:18790/)" "000"
# Version 7 removes cluster "static" before listener "xtcp" (which used it):
# the cluster update only fits after the listener update, and is retried.
check "out-of-order update applied once it fits" "$(reqs | grep '"type": "Cluster"' | tail -1 | grep '"error": null' | grep -c '"version": "7"')" "1"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
