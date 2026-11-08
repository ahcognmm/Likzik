# Implementation status against the plan

Plan: *Zig Proxy & API Gateway — Final Plan* (Nov 5, 2026). This page
tracks what exists in the code, what doesn't yet, and where the code
deliberately departs from the plan (with the reason).

Legend: **done**, **partial**, **not started**.

## Decisions

| Decision | Status | Notes |
| --- | --- | --- |
| io_uring primary backend, Linux 6.18 LTS / 6.14+ dev | done | Startup check enforces 6.14+ (`--allow-old-kernel` for 6.1+). |
| OpenSSL 3 with full kTLS | done | See TLS below. |
| Thread-per-core, shared-nothing, SO_REUSEPORT per worker | done | Workers pinned to CPUs (`--no-pin` to disable). |
| Immutable snapshots swapped RCU-style | done | `config/rcu.zig`, epoch-based reclamation. |
| Zig pinned, `std.os.linux.IoUring` directly | done | Pinned to 0.17.x (upgraded from 0.16.0; the plan named 0.16.x). The core uses only `std.os.linux` and `std.mem`, not `std.Io`. |

## Requirements (day one)

| Area | Status | Notes |
| --- | --- | --- |
| HTTP/1.1 proxying | done | Keep-alive, pipelining (in order), chunked and Content-Length bodies, close-delimited responses, 1xx forwarding, de-chunking for HTTP/1.0 clients. |
| HTTPS termination + upstream TLS | done | See TLS below. |
| TCP/L4 proxying | done | splice, half-close, idle timeout, connect retry, SNI passthrough routing, PROXY protocol (accept v1/v2 on any listener; send v1/v2 from TCP listeners). |
| File + inotify reload, RCU core | done | Rename-into-place handled; invalid config keeps the old snapshot. |
| Routing, upstream pools, LB | done | Linear first-match routing for now; the radix trie is gateway-phase. |
| Within 10% of nginx p99 | on track | Single-host smoke test is at or better than nginx p99 in all workloads. The harness now runs the load generator on another host (`LOADGEN=`); the multi-host run itself is still to do (docs/benchmarking.md). |

## I/O layer

| Item | Status | Notes |
| --- | --- | --- |
| `SINGLE_ISSUER` + `DEFER_TASKRUN` + `COOP_TASKRUN` | done | Plus `SUBMIT_ALL`, larger CQ. |
| Multishot accept | done | Regular fds, not direct descriptors: L4 uses `splice(2)`, `shutdown(2)` and `setsockopt(2)`, which need real fds. Revisit if accept becomes a bottleneck. |
| Provided buffer ring | done | 1024 × 16 KiB per worker (`--buffers`). No incremental mode: one CQE = one buffer keeps ownership simple. |
| Multishot recv, re-arm on `-ENOBUFS` | done | Re-armed once buffers return; ENOBUFS is a metric. |
| `MSG_RING` wakeups | done | Config swap and drain. |
| `SPLICE` for L4 | done, different mechanism | Ring-driven readiness plus inline non-blocking `splice(2)`. The kernel always punts `IORING_OP_SPLICE` to io-wq, which costs a thread hop per op and one blocked io-wq thread per idle tunnel. |
| `SEND_ZC` for large bodies | not started | Bodies are already forwarded from provided buffers without copies; zero-copy send is the next step. |
| Linked timeout on every connect | done | |
| Linked timeout on every recv | different mechanism | Multishot recv cannot carry a linked timeout without being cancelled by it, so header, idle, response and linger timeouts run on the per-worker timer wheel. |
| Buffer ownership: generations, never recycle before send completes | done | Refcount + generation per buffer and per block. Copy-on-pressure added: when the ring is >75% lent out, queued bytes are copied into blocks so slow peers cannot pin the shared ring. Stress-tested (tests/integration/stress.py), including a 16-buffer ring. |
| Thin `Loop` interface; simulated loop for tests | partial | `runtime/loop.zig` owns user_data encoding and SQE helpers. The simulated loop (`tests/sim`) is not written. |
| Startup checks (kernel, sysctl, seccomp) | done | Probes ring creation and maps EPERM/ENOSYS/ENOMEM to actionable messages. |
| Deployment docs | done | docs/deployment.md. |

## TLS and kTLS

| Item | Status | Notes |
| --- | --- | --- |
| OpenSSL 3.x with kTLS both directions | done, kTLS verified on Linux 7.0 aarch64 | Linked against the system OpenSSL 3 (fetching `allyourcodebase/openssl` was not possible from the build environment). The dev VM's kernel lacks `CONFIG_TLS`; the kTLS path was first exercised by the benchmark on Linux 7.0.0 (Ubuntu 26.04, aarch64): 93,606 connections on kTLS, 0 userspace fallbacks, no errors. Body integrity over kTLS still needs `tests/integration/run.sh` on such a kernel (with `require_ktls` true). |
| Comptime `TlsBackend` interface | done | `tls/backend.zig` checks the backend's declarations at compile time. |
| Handshake sans-I/O over memory BIOs | different mechanism | OpenSSL can only switch kTLS on through a socket BIO, so the handshake runs on the socket and ring readiness polls drive it. The goal (kTLS keys installed by `SSL_OP_ENABLE_KTLS`, no record copying) is unchanged. |
| Only kTLS-capable suites | done | TLS 1.3: AES-128/256-GCM, ChaCha20-Poly1305. TLS 1.2: ECDHE with the same AEADs. Min TLS 1.2. |
| Userspace fallback, guarded | done | Refused unless `"tls": {"require_ktls": false}`; startup warning; `tls_userspace` metric. |
| Control records (EIO + `TLS_GET_RECORD_TYPE`) | written, untested | On EIO/EKEYEXPIRED from a kTLS socket, `SSL_read` handles the record (OpenSSL's kTLS code does the cmsg read), then the multishot recv is re-armed. |
| TLS 1.3 KeyUpdate with kTLS | partly answered | Tested in `tests/integration/run.sh`. Userspace TLS: both directions pass. kTLS on Linux below 6.14 with OpenSSL 3.0 (GitHub's runner): a client KeyUpdate works, but a KeyUpdate the client *requests* from the server breaks the connection (the kernel cannot rekey sending), which confirms the 6.14 minimum. Still to run: kTLS on 6.14+ with OpenSSL 3.2+ (e.g. Ubuntu 26.04), which settles whether OpenSSL installs the new keys itself. |
| SNI certificate selection | done | Exact, `*.suffix`, default. |
| ALPN | done | `http/1.1` only; h2 later. |
| Session tickets: shared key set, rotated by the control plane | partial | Tickets work (one per handshake), with keys per SSL_CTX, which is shared by all workers. Keys change on every reload; explicit key distribution and rotation are not done. |
| Cert hot reload, refcounted old SSL_CTX | done | Tested: new connections get the new cert, in-flight ones finish, broken certs are rejected. |
| Startup check `/proc/net/tls_stat` | done | Also enforced on reload. |
| kTLS share metric | done | `tls_ktls` vs `tls_userspace` (both downstream and upstream connections). |
| Upstream TLS | done | SNI, verification (hostname + CA), pooled per cluster. |
| TLS on TCP listeners, SNI passthrough | SNI passthrough done | TCP listeners route by the ClientHello's server name without terminating TLS (`sni_routes`). Terminating TLS on TCP listeners is not started. |

## Memory

| Item | Status | Notes |
| --- | --- | --- |
| No malloc/mmap on the request path | done | Pools and blocks are preallocated per worker; lazily committed with `mmap(MAP_NORESERVE)`. |
| Per-worker connection slabs | done | `mem/pool.zig`, with generations. |
| Per-request arena | not needed yet | Heads are re-serialized straight into refcounted 16 KiB blocks. |
| Zero-copy header slices, max 100, 431 above | done | |
| Comptime tables, perfect hash, `@Vector` scanning | done | |
| Snapshot arena, freed after all workers pass | done | |
| DebugAllocator / ASan / fuzzer in CI | partial | Tests run under debug-mode safety checks. Zig's coverage-guided fuzzer is not usable yet (0.16.0: the test runner fails to compile; 0.17.0: it runs but aborts with "corrupted coverage file: pcs_len was zero"), so a built-in mutation fuzzer drives the same properties (`zig build fuzz -Dfuzz-iters=N`), covering the HTTP parser, chunked decoder, PROXY protocol and ClientHello parsers. CI (`.github/workflows/ci.yml`) runs it with 2M iterations, plus unit and integration tests. |

## HTTP/1.1

| Item | Status |
| --- | --- |
| Own parser, resumable, allocation-free | done |
| Header split across buffers | done, slightly different: the partial head is accumulated in a per-connection block and parsed there (the whole head, not just the split header). |
| Request line / headers / chunked / response parser on one byte-class core | done |
| Differential fuzzing vs picohttpparser and llhttp | not started (property fuzzing done) |
| Smuggling corpus + every rejection rule as a regression test | done (unit tests + `tests/fuzz`) |
| Parse benchmark in CI | partial: `zig build bench-parse` exists; no CI, no picohttpparser baseline |
| All listed anti-smuggling rules | done. TE accepts exactly `chunked` (501 otherwise). Absolute-form request targets are rejected (400). |
| Strip hop-by-hop and `Connection`-named headers, replace XFF unless trusted | done (`trust_forwarded_headers` per listener) |
| Keep-alive idle timeout, max requests per connection | done |
| Normalize path for routing only | done: core routes and gateway routes match on the same normalized path (unreserved %XX decoded, dot and empty segments removed); the request is forwarded unchanged |

## Upstream management

| Component | Phase | Status |
| --- | --- | --- |
| Per-worker pool keyed by endpoint, idle caps, liveness | 1 | done (keyed by endpoint; TLS/SNI/ALPN key parts come with TLS) |
| Round robin / weighted RR / P2C least-request | 1 | done (+ weighted random) |
| Passive health | 1 | done (connect failures → ejection with backoff; 5xx counted) |
| Outlier detection (consecutive 5xx, max ejection %) | 2 | done (per worker; docs/upstreams.md) |
| Retries: budgeted, idempotent only, different host | 2 | done: `retry_on` gateway_error / 5xx / reset, budget % of active requests, `max_retries`. Per-try timeouts not started. |
| Circuit breaking (connections, requests, retries) | 2 | done, per-worker shares of process-wide limits. No pending queue (HTTP/1.1 connects at once). |
| Cross-worker handoff, active health, mirroring | 2+ | not started |
| Ring hash / Maglev | 3 | not started |

## Dynamic configuration

| Item | Status |
| --- | --- |
| Hot-swap core steps 1–4 | done |
| Listener add/remove | done. Workers bind their own SO_REUSEPORT sockets for new listeners (the plan binds on the control thread and hands them over). Removed listeners stop accepting; idle connections close, in-flight ones finish with `Connection: close`. |
| Binary upgrade via SCM_RIGHTS | not started |
| xDS (ADS SotW, delta) | not started (model is xDS-shaped) |
| Local admin endpoint | done: `/ready`, `/stats`, `/metrics`, `/server_info`, `POST /reload`, `POST /drain`. Auth model is still an open question. |

## Gateway layer

`likzik-gw` (see docs/gateway.md): the core binary plus an extension behind
the generic filter interface `src/proxy/filter.zig`; gateway code is in
`src/gateway/`.

| Item | Status | Notes |
| --- | --- | --- |
| Radix-trie router (static > param > wildcard, header/method/query matchers) | done | Segment trie with backtracking; host is checked per candidate rather than one trie per host. Regex matchers not started. |
| Lookups allocate nothing | done | Params are slices of a per-worker normalized path buffer. |
| API keys (hashed set in the snapshot) | done | SHA-256; key may be given only as its hash. |
| JWT (JWKS, alg allow-list, exp/nbf/aud/iss) | done | std.crypto (RSA PKCS#1/PSS, ECDSA P-256/384, Ed25519, HMAC) with a per-worker verification cache. JWKS from file/inline; fetching JWKS URLs on the control thread is not started. |
| mTLS identity, OAuth2 introspection | not started | |
| Local rate limiting | done, different mechanism | One table shared by all workers (per-bucket spinlocks) instead of per-worker rate÷N, which under-limits single-connection clients. |
| Global rate limiting (Envoy RLS) | not started | |
| Transforms (headers, path rewrite, redirect) | done | Plus fixed responses. Body transforms not started. |
| Plugins (comptime registry, WASM) | not started | The filter interface is the attachment point. |
| Mirroring rules | not started | |

## Observability

| Item | Status |
| --- | --- |
| Per-worker non-atomic counters, summed on scrape | done |
| Prometheus `/metrics` | done |
| Access logs (ring buffer + flusher) | done: per-worker SPSC rings drained by the control thread; text or JSON; drops counted (`access_log_dropped`); reopened on reload (docs/deployment.md) |
| Tracing (traceparent, OTLP) | not started |
| Must-have metrics | ENOBUFS, pool hit rate, snapshot generation per worker, drain state: done. kTLS share: with TLS. |

## Benchmarking

Harness: `bench/vs_nginx.sh` (single host), `zig build bench-parse`, and
docs/benchmarking.md with the methodology. The multi-host, fixed-rate run is
still to do.

## Console and tooling (beyond the plan)

| Item | Status | Notes |
| --- | --- | --- |
| Config console (`likzik-ui`) | done | React + Vite app embedded in a Zig server: draft editing of listeners, routes, clusters, certificates and auth; validation with the proxy's own `--check`; change history and roll back. See docs/dashboard.md. |
| One-command stack | done | `make run` / `likzik-stack` start the gateway and the console together and stop both together. |
