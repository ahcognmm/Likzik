# likzik

A Linux-only reverse proxy written in Zig on io_uring, the base for an API gateway.
The target is nginx-level throughput and tail latency at the same core count.

**Status: Phase 1 core (pre-release).** HTTP/1.1 and TCP/L4 proxying,
file-based config with hot reload, graceful drain, metrics. TLS, xDS and
the gateway filters are not built yet; see [docs/status.md](docs/status.md)
for the plan-by-plan breakdown.

## Build

Requires Zig 0.16.x and Linux 6.14+ (6.18 LTS in production).

```sh
zig build -Doptimize=ReleaseSafe      # binary in zig-out/bin/likzik
zig build test                        # unit tests + parser fuzz corpus + mutation fuzzer
tests/integration/run.sh              # end-to-end tests (needs nginx, curl, nc, python3)
bench/vs_nginx.sh                     # side-by-side with nginx (needs nginx, wrk)
```

Early production builds should use `ReleaseSafe`.

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
- **Config**: immutable snapshots in one arena each, swapped with an atomic pointer; epoch-based reclamation once every worker has moved past.
- **Memory**: no malloc on the request path. Pools are sized up front, but pages are only committed when first used (RSS is about 5 MB idle).

Source layout: `src/runtime` (loop, buffer ring, timer wheel, worker),
`src/http1` (parser, framing rules, codec), `src/proxy` (HTTP state
machine), `src/upstream` (pool, LB, health), `src/l4`, `src/config`,
`src/control`, `src/observe`, `src/net`, `src/mem`.

## Deployment

io_uring is often disabled by default (RHEL sysctl, Docker's default seccomp
profile). likzik checks at startup and fails with a clear message instead of
degrading. See [docs/deployment.md](docs/deployment.md).
