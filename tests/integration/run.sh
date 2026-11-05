#!/usr/bin/env bash
# End-to-end tests: real likzik binary, nginx + a Python echo server as
# upstreams. Needs: nginx, curl, nc, python3, openssl. Run from the repo root:
#
#   zig build -Doptimize=safe && tests/integration/run.sh
#   LIKZIK=path/to/likzik tests/integration/run.sh   (e.g. a Debug build)
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LIKZIK=${LIKZIK:-$ROOT/zig-out/bin/likzik}
WORK=$(mktemp -d /tmp/likzik-it.XXXXXX)
WWW=$WORK/www
mkdir -p "$WWW"; chmod 755 "$WORK" "$WWW"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
check() { if [ "$2" == "$3" ]; then ok "$1"; else bad "$1 (want '$3', got '$2')"; fi; }

cleanup() {
  [ -n "${LPID:-}" ] && kill -9 "$LPID" 2>/dev/null
  [ -n "${EPID:-}" ] && kill "$EPID" 2>/dev/null
  [ -f "$WORK/up.pid" ] && kill "$(cat "$WORK/up.pid")" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

head -c 3000000 /dev/urandom > "$WWW/big.bin"; chmod 644 "$WWW/big.bin"
BIG_MD5=$(md5sum < "$WWW/big.bin")
export NO_PROXY='*' no_proxy='*'

# Test PKI: a CA, two server certificates (SNI), one upstream certificate.
PKI=$WORK/pki; mkdir -p "$PKI"; chmod 755 "$PKI"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$PKI/ca.key" -out "$PKI/ca.crt" -days 2 -subj "/CN=it CA" 2>/dev/null
mkcert() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$PKI/$1.key" -out "$PKI/$1.csr" -subj "/CN=$2" 2>/dev/null
  printf "subjectAltName=%s\n" "$3" > "$PKI/$1.ext"
  openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" -CAcreateserial -out "$PKI/$1.crt" -days 2 -extfile "$PKI/$1.ext" 2>/dev/null
}
mkcert a a.test "DNS:a.test,DNS:*.wild.test"; mkcert b b.test "DNS:b.test"; mkcert up upstream.test "DNS:upstream.test"
chmod 644 "$PKI"/*

cat > "$WORK/up.conf" <<NGX
worker_processes 1; daemon on; pid $WORK/up.pid; error_log $WORK/up_error.log;
events { worker_connections 1024; }
http { access_log off;
  client_body_temp_path $WORK/body; proxy_temp_path $WORK/proxy; fastcgi_temp_path $WORK/fcgi;
  uwsgi_temp_path $WORK/uwsgi; scgi_temp_path $WORK/scgi;
  server { listen 127.0.0.1:19001; root $WWW; location = / { return 200 "a\n"; } location = /slow { return 200 "a\n"; } }
  server { listen 127.0.0.1:19002; root $WWW; location = / { return 200 "b\n"; } }
  server { listen 127.0.0.1:19004 ssl; ssl_certificate $PKI/up.crt; ssl_certificate_key $PKI/up.key;
           root $WWW; location = / { return 200 "tls upstream\n"; } }
}
NGX
nginx -c "$WORK/up.conf" -p "$WORK" || { echo "nginx failed"; exit 1; }
python3 "$ROOT/tests/integration/echo_server.py" 19003 >/dev/null 2>&1 & EPID=$!

cat > "$WORK/likzik.json" <<JSON
{ "version": "it-1", "workers": 2, "admin": { "address": "127.0.0.1:19901" },
  "tls": { "require_ktls": false },
  "limits": { "header_timeout_ms": 1000 },
  "listeners": [
    { "name": "web", "address": "127.0.0.1:18080", "route_config": "main" },
    { "name": "tcp", "address": "127.0.0.1:18443", "protocol": "tcp", "cluster": "web" },
    { "name": "https", "address": "127.0.0.1:18444", "route_config": "main",
      "tls": { "certificates": [
        { "certificate_chain": "$PKI/a.crt", "private_key": "$PKI/a.key", "server_names": ["a.test", "*.wild.test"] },
        { "certificate_chain": "$PKI/b.crt", "private_key": "$PKI/b.key", "server_names": ["b.test"] } ] } } ],
  "route_configs": [ { "name": "main", "virtual_hosts": [
    { "name": "echo", "domains": ["echo.test"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "echo" } } ] },
    { "name": "api", "domains": ["api.test", "*.api.test"], "routes": [
      { "match": { "prefix": "/v1/", "methods": ["GET"] }, "route": { "cluster": "echo", "prefix_rewrite": "/" } } ] },
    { "name": "dead", "domains": ["dead.test"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "dead" } } ] },
    { "name": "tlsup", "domains": ["tlsup.test"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "tlsup" } } ] },
    { "name": "badtls", "domains": ["badtls.test"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "badtls" } } ] },
    { "name": "default", "domains": ["*"], "routes": [ { "match": { "prefix": "/" }, "route": { "cluster": "web" } } ] } ] } ],
  "clusters": [
    { "name": "web", "lb_policy": "round_robin", "endpoints": [ { "address": "127.0.0.1:19001" }, { "address": "127.0.0.1:19002" } ] },
    { "name": "echo", "endpoints": [ { "address": "127.0.0.1:19003" } ] },
    { "name": "dead", "connect_timeout_ms": 300, "endpoints": [ { "address": "127.0.0.1:1" } ] },
    { "name": "tlsup", "tls": { "sni": "upstream.test", "ca_file": "$PKI/ca.crt" }, "endpoints": [ { "address": "127.0.0.1:19004" } ] },
    { "name": "badtls", "tls": { "sni": "wrong.test", "ca_file": "$PKI/ca.crt" }, "endpoints": [ { "address": "127.0.0.1:19004" } ] } ] }
JSON

"$LIKZIK" -c "$WORK/likzik.json" --check >/dev/null 2>&1 && ok "--check accepts the config" || bad "--check"
"$LIKZIK" -c "$WORK/likzik.json" --no-pin > "$WORK/likzik.log" 2>&1 & LPID=$!
for _ in $(seq 50); do curl -s -o /dev/null 127.0.0.1:19901/ready && break; sleep 0.1; done
P=127.0.0.1:18080
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
raw()  { printf "$1" | timeout 3 nc -q 2 127.0.0.1 18080 2>/dev/null; }

echo "routing and load balancing"
# Round robin state is per worker, so look at the set over many requests.
check "round robin reaches both endpoints" "$(for i in $(seq 20); do curl -s $P/; done | sort -u | tr -d '\n')" "ab"
check "unknown host -> default vhost" "$(code -H 'Host: other' $P/)" "200"
check "prefix rewrite" "$(curl -s -H 'Host: api.test' $P/v1/x/y | head -1 | tr -d '\r')" "GET /x/y HTTP/1.1"
check "wildcard domain" "$(curl -s -H 'Host: eu.api.test' $P/v1/z | head -1 | tr -d '\r')" "GET /z HTTP/1.1"
check "method mismatch -> 404" "$(code -X POST -H 'Host: api.test' $P/v1/x)" "404"
check "no route -> 404" "$(code -H 'Host: api.test' $P/nope)" "404"
check "connect refused -> 503" "$(code -H 'Host: dead.test' $P/)" "503"

echo "headers"
H=$(curl -s -H 'Host: echo.test' -H 'X-Forwarded-For: 6.6.6.6' -H 'Connection: x-secret' -H 'X-Secret: 1' -H 'Keep-Alive: 9' -H 'TE: trailers' $P/h)
echo "$H" | grep -q '^X-Forwarded-For: 127.0.0.1' && ok "XFF replaced for untrusted client" || bad "XFF"
echo "$H" | grep -qi '^X-Secret' && bad "connection-nominated header stripped" || ok "connection-nominated header stripped"
echo "$H" | grep -qiE '^(Keep-Alive|TE):' && bad "hop-by-hop stripped" || ok "hop-by-hop stripped"
echo "$H" | grep -q '^X-Forwarded-Proto: http' && ok "X-Forwarded-Proto added" || bad "X-Forwarded-Proto"

echo "bodies and framing"
check "content-length upload" "$(curl -s -H 'Host: echo.test' --data-binary 'hello' $P/u | grep -ao 'BODY:.*')" "BODY:hello"
head -c 200000 /dev/urandom | base64 -w0 > "$WORK/up.txt"
check "chunked upload 270KB" "$(curl -s -H 'Host: echo.test' -H 'Transfer-Encoding: chunked' --data-binary @"$WORK/up.txt" $P/u | grep -ao 'BODY:.*' | md5sum)" "$( (printf 'BODY:'; cat "$WORK/up.txt"; echo) | md5sum)"
check "chunked response" "$(curl -s -H 'Host: echo.test' $P/chunked)" "hello world"
check "HTTP/1.0 client gets de-chunked body" "$(curl -s -0 -H 'Host: echo.test' $P/chunked)" "hello world"
check "close-delimited response" "$(curl -s -H 'Host: echo.test' $P/close)" "close-delimited body"
check "3MB download intact" "$(curl -s $P/big.bin | md5sum)" "$BIG_MD5"
check "HEAD keeps Content-Length" "$(curl -s -I $P/big.bin | grep -i '^content-length' | tr -d '\r')" "Content-Length: 3000000"

echo "keep-alive and pipelining"
# num_connects is 0 for a request that reused a connection (stable across
# curl versions, unlike the wording of -v output).
check "client keep-alive" "$(curl -s -w '%{num_connects} ' -o /dev/null $P/ -o /dev/null $P/ -o /dev/null $P/)" "1 0 0 "
check "3 pipelined requests in order" "$(raw 'GET /1 HTTP/1.1\r\nHost: echo.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: echo.test\r\n\r\nGET /3 HTTP/1.1\r\nHost: echo.test\r\nConnection: close\r\n\r\n' | grep -ao 'GET /[0-9]' | tr '\n' ' ')" "GET /1 GET /2 GET /3 "

echo "request smuggling and malformed input"
first() { raw "$1" | head -1 | tr -d '\r'; }
check "CL + TE" "$(first 'POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "duplicate CL" "$(first 'POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "TE not chunked" "$(first 'POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n')" "HTTP/1.1 501 Not Implemented"
check "space before colon" "$(first 'GET / HTTP/1.1\r\nHost : a\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "obs-fold" "$(first 'GET / HTTP/1.1\r\nHost: a\r\nX: 1\r\n 2\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "missing Host" "$(first 'GET / HTTP/1.1\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "two Hosts" "$(first 'GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n')" "HTTP/1.1 400 Bad Request"
check "bad chunk size" "$(raw 'POST / HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n' | head -1 | tr -d '\r')" "HTTP/1.1 400 Bad Request"
check "101 headers -> 431" "$(curl -s -o /dev/null -w '%{http_code}' $(for i in $(seq 101); do printf -- "-H X-$i:1 "; done) $P/)" "431"
check "head timeout -> 408" "$( (printf 'GET / HTTP/1.1\r\nHost: a\r\n'; sleep 2) | timeout 3 nc 127.0.0.1 18080 | head -1 | tr -d '\r')" "HTTP/1.1 408 Request Timeout"

echo "tcp proxy"
check "tcp passthrough" "$(curl -s 127.0.0.1:18443/ | grep -cE '^(a|b)$')" "1"
check "tcp 3MB intact" "$(curl -s 127.0.0.1:18443/big.bin | md5sum)" "$BIG_MD5"

echo "tls"
S() { curl -s --cacert "$PKI/ca.crt" --resolve "$1:18444:127.0.0.1" "${@:3}" "https://$1:18444$2"; }
certcn() { echo | openssl s_client -connect 127.0.0.1:18444 -servername "$1" 2>/dev/null | openssl x509 -noout -subject | sed 's/.*CN *= *//'; }
fp() { echo | openssl s_client -connect 127.0.0.1:18444 -servername a.test 2>/dev/null | openssl x509 -noout -fingerprint; }
code200() { S "$@" -o /dev/null -w '%{http_code}'; }
check "https termination" "$(code200 a.test /)" "200"
check "SNI selects certificate b" "$(certcn b.test)" "b.test"
check "SNI wildcard -> certificate a" "$(certcn x.wild.test)" "a.test"
check "unknown SNI -> default certificate" "$(certcn other.test)" "a.test"
check "TLS 1.2" "$(code200 a.test / --tlsv1.2 --tls-max 1.2)" "200"
check "ALPN http/1.1" "$(S a.test / -v -o /dev/null 2>&1 | grep -c 'server accepted http/1.1')" "1"
check "X-Forwarded-Proto https" "$(S a.test /h -H 'Host: echo.test' | grep -i '^X-Forwarded-Proto' | tr -d '\r')" "X-Forwarded-Proto: https"
check "3MB over https intact" "$(S a.test /big.bin | md5sum)" "$BIG_MD5"
check "270KB upload over https" "$(S a.test /u -H 'Host: echo.test' --data-binary @"$WORK/up.txt" | grep -ao 'BODY:.*' | md5sum)" "$( (printf 'BODY:'; cat "$WORK/up.txt"; echo) | md5sum)"
check "upstream TLS, verified" "$(S a.test / -H 'Host: tlsup.test')" "tls upstream"
check "3MB via TLS upstream intact" "$(S a.test /big.bin -H 'Host: tlsup.test' | md5sum)" "$BIG_MD5"
check "upstream cert name mismatch -> 503" "$(S a.test / -H 'Host: badtls.test' -o /dev/null -w '%{http_code}')" "503"
check "plaintext on TLS port is dropped" "$(printf 'GET / HTTP/1.1\r\nHost: a\r\n\r\n' | timeout 3 nc 127.0.0.1 18444 | head -c 4)" ""
mkcert a a.test "DNS:a.test,DNS:*.wild.test"; chmod 644 "$PKI"/*
kill -HUP "$LPID"; sleep 0.5
check "certificate hot reload on SIGHUP" "$(fp)" "$(openssl x509 -in "$PKI/a.crt" -noout -fingerprint)"
cp "$PKI/a.crt" "$PKI/a.crt.good"; echo junk > "$PKI/a.crt"
check "broken certificate rejected on reload" "$(curl -s -o /dev/null -w '%{http_code}' -X POST 127.0.0.1:19901/reload)" "400"
check "old certificate keeps serving" "$(code200 a.test /)" "200"
cp "$PKI/a.crt.good" "$PKI/a.crt"
check "tls metrics" "$(curl -s 127.0.0.1:19901/metrics | grep -c '^likzik_tls_handshakes_total ')" "1"

echo "config reload"
cp "$WORK/likzik.json" "$WORK/good.json"
sed 's/"it-1"/"it-2"/' "$WORK/good.json" > "$WORK/likzik.json.tmp" && mv "$WORK/likzik.json.tmp" "$WORK/likzik.json"
sleep 0.5
curl -s 127.0.0.1:19901/server_info | grep -q '"version":"it-2"' && ok "file change applied" || bad "file change applied"
echo '{"listeners": []}' > "$WORK/likzik.json"
check "invalid config rejected by /reload" "$(curl -s -o /dev/null -w '%{http_code}' -X POST 127.0.0.1:19901/reload)" "400"
check "old config keeps serving" "$(code $P/)" "200"
cp "$WORK/good.json" "$WORK/likzik.json"; sleep 0.3
check "metrics endpoint" "$(curl -s 127.0.0.1:19901/metrics | grep -c '^likzik_downstream_rq_total ')" "1"

echo "graceful drain"
(curl -s --limit-rate 1M $P/big.bin | md5sum > "$WORK/drain.md5") &
CP=$!
sleep 0.3
kill -TERM "$LPID"
wait "$CP"
check "in-flight download completes during drain" "$(cat "$WORK/drain.md5")" "$BIG_MD5"
for _ in $(seq 50); do kill -0 "$LPID" 2>/dev/null || break; sleep 0.1; done
kill -0 "$LPID" 2>/dev/null && bad "process exits after drain" || ok "process exits after drain"
LPID=

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
