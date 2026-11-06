# likzik

A Linux-only reverse proxy written in Zig on io_uring, the base for an API gateway.
The target is nginx-level throughput and tail latency at the same core count.

**Status: Phase 1 core (pre-release).** HTTP/1.1, HTTPS (termination and
upstream TLS, kTLS-first) and TCP/L4 proxying, file-based config with hot
reload, graceful drain, metrics. xDS and the gateway filters are not built
yet; see [docs/status.md](docs/status.md) for the plan-by-plan breakdown.

## Build

Requires Zig 0.17.x, OpenSSL 3.x development files (`libssl-dev`), and
Linux 6.14+ (6.18 LTS in production).

```sh
zig build -Doptimize=safe      # binary in zig-out/bin/likzik
zig build test                        # unit tests + parser fuzz corpus + mutation fuzzer
tests/integration/run.sh              # end-to-end tests (needs nginx, curl, nc, python3)
bench/vs_nginx.sh                     # side-by-side with nginx (needs nginx, wrk)
```

Early production builds should use the `safe` mode (`-Doptimize=safe`).

## API gateway

`likzik-gw` is the same proxy with the API gateway: a radix-trie router
with path params, API-key and JWT authentication, rate limiting, header
and path transforms, redirects. It is configured in the config's
`extensions.gateway` section; see [docs/gateway.md](docs/gateway.md) and
[config/gateway.example.json](config/gateway.example.json).

## Run

```sh
likzik -c config/likzik.example.json --check   # validate, like nginx -t
likzik -c config/likzik.example.json
```

| Signal / endpoint | Effect |
| --- | --- |
| edit the config file | Reloaded automatically (inotify); a config that fails validation is rejected and the old one keeps serving |
| `SIGHUP` or `POST /reload` | Reload now |
| `SIGTERM` / `SIGINT` or `POST /drain` | Graceful drain: stop accepting, finish in-flight requests (up to `drain_timeout_ms`), exit. A second signal exits immediately. |
| `GET /metrics` | Prometheus metrics |
| `GET /stats`, `/server_info`, `/ready` | Counters, applied config version + last reload error, readiness |

The admin endpoint has no authentication yet. Bind it to localhost.

## Configuration

JSON, shaped like xDS (listeners → route configs → virtual hosts → routes →
clusters → endpoints), so a future xDS adapter is a translation layer. Unknown
fields are rejected. See [config/likzik.example.json](config/likzik.example.json).

- **Routing**: exact, `*.suffix` and `*` domains; prefix or exact path; method filter; `prefix_rewrite`.
- **Load balancing**: `least_request` (P2C, default), `round_robin` (smooth weighted), `random`.
- **Upstream health**: passive. After N consecutive connect failures an endpoint is ejected with exponential backoff, and connect failures retry on another endpoint.
- **Upstream pooling**: per-worker keep-alive pools with idle caps and timeouts. Idle connections closed by the upstream are noticed immediately.
- **TLS termination**: several certificates per listener, chosen by SNI (exact names, then `*.suffix` wildcards, then the first certificate); TLS 1.2 and 1.3; ALPN `http/1.1`; certificates reload with the config, and a broken certificate is rejected while the old one keeps serving.
- **Upstream TLS**: per-cluster `tls` with SNI, certificate and hostname verification (system CA store or `ca_file`); pooled per cluster.

## Architecture

```
supervisor (main thread)   signals -> commands
control thread             config file + inotify, validate, build snapshot,
                           RCU publish, MSG_RING wake, admin endpoint
worker x N (1 per core)    own io_uring (SINGLE_ISSUER|DEFER_TASKRUN), own
                           SO_REUSEPORT listeners, own buffers and pools
```

- **I/O**: multishot accept, multishot recv into a provided buffer ring, `sendmsg` with gathered iovecs, connects with linked timeouts, a multishot timeout driving a per-worker timer wheel.
- **Zero-copy forwarding**: body bytes go from the provided buffer straight into the peer's send queue. The buffer returns to the kernel only when the send that reads it completes (refcounts plus generation checks). When the ring runs low, bytes are copied out so a slow peer cannot starve the worker.
- **HTTP/1.1**: in-house parser with a resumable head scanner, SIMD (`@Vector`) scanning, comptime byte-class tables and a comptime perfect hash for well-known headers. Strict anti-smuggling rules; requests are re-serialized, never forwarded raw.
- **TCP/L4**: `splice(2)` through a pipe pair, so bytes never enter userspace; ring-driven readiness; independent half-close per direction.
- **TLS**: OpenSSL 3 behind a compile-time `TlsBackend` interface. The handshake runs on the socket, driven by ring readiness, with `SSL_OP_ENABLE_KTLS`. When the kernel `tls` module is loaded, the keys go into the socket and the zero-copy plaintext path above carries HTTPS unchanged. Otherwise the connection falls back to userspace TLS, which is allowed only when `"tls": {"require_ktls": false}` and is counted in `tls_userspace`. Only kTLS-capable suites are offered (AES-GCM, ChaCha20-Poly1305).
- **Config**: immutable snapshots in one arena each, swapped with an atomic pointer; epoch-based reclamation once every worker has moved past.
- **Memory**: no malloc on the request path. Pools are sized up front, but pages are only committed when first used (about 10 MB PSS idle with 2 workers).
- **Send path**: output is flushed once per completion, so a response head and a small body (≤ 2 KiB, copied after the head) go out as a single plain `send`; larger bodies are forwarded zero-copy with `sendmsg`.
- **CPU pinning**: worker N is pinned to CPU N by default (`--no-pin` disables it). Measured on the dev VM, pinning gives lower p50/p99 even when the load generator shares the host.

Source layout: `src/runtime` (loop, buffer ring, timer wheel, worker),
`src/http1` (parser, framing rules, codec), `src/proxy` (HTTP state
machine), `src/upstream` (pool, LB, health), `src/l4`, `src/config`,
`src/control`, `src/observe`, `src/net`, `src/mem`.

## Deployment

io_uring is often disabled by default (RHEL sysctl, Docker's default seccomp
profile). likzik checks at startup and fails with a clear message instead of
degrading. See [docs/deployment.md](docs/deployment.md).
