# Implementation status against the plan

Plan: *Zig Proxy & API Gateway — Final Plan* (Nov 5, 2026). This page
tracks what exists in the code, what doesn't yet, and where the code
deliberately departs from the plan (with the reason).

Legend: **done**, **partial**, **not started**.

## Decisions

| Decision | Status | Notes |
| --- | --- | --- |
| io_uring primary backend, Linux 6.18 LTS / 6.14+ dev | done | Startup check enforces 6.14+ (`--allow-old-kernel` for 6.1+). |
| OpenSSL 3 with full kTLS | not started | See TLS below. |
| Thread-per-core, shared-nothing, SO_REUSEPORT per worker | done | Workers pinned to CPUs (`--no-pin` to disable). |
| Immutable snapshots swapped RCU-style | done | `config/rcu.zig`, epoch-based reclamation. |
| Zig 0.16.x, `std.os.linux.IoUring` directly | done | The core uses only `std.os.linux` and `std.mem`, not `std.Io`. |

## Requirements (day one)

| Area | Status | Notes |
| --- | --- | --- |
| HTTP/1.1 proxying | done | Keep-alive, pipelining (in order), chunked and Content-Length bodies, close-delimited responses, 1xx forwarding, de-chunking for HTTP/1.0 clients. |
| HTTPS termination + upstream TLS | not started | Config with `tls` is rejected with a clear message. |
| TCP/L4 proxying | done | splice, half-close, idle timeout, connect retry. SNI passthrough and PROXY protocol not started. |
| File + inotify reload, RCU core | done | Rename-into-place handled; invalid config keeps the old snapshot. |
| Routing, upstream pools, LB | done | Linear first-match routing for now; the radix trie is gateway-phase. |
| Within 10% of nginx p99 | on track | Single-host smoke test is at or better than nginx p99 in all workloads; a rigorous multi-host run is still to do (docs/benchmarking.md). |

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

## TLS and kTLS — not started

Blocked in this environment only by testing: the development VM's kernel is
built without `CONFIG_TLS`, so kTLS cannot be exercised here. Planned shape
is unchanged (sans-I/O handshake over memory BIOs, kTLS for both directions,
`TLS_GET_RECORD_TYPE` control-record handling, KeyUpdate, SNI cert
selection, ticket keys in the snapshot, kTLS share metric). The open
question about OpenSSL performing KeyUpdate with kTLS is still open.

## Memory

| Item | Status | Notes |
| --- | --- | --- |
| No malloc/mmap on the request path | done | Pools and blocks are preallocated per worker; lazily committed with `mmap(MAP_NORESERVE)`. |
| Per-worker connection slabs | done | `mem/pool.zig`, with generations. |
| Per-request arena | not needed yet | Heads are re-serialized straight into refcounted 16 KiB blocks. |
| Zero-copy header slices, max 100, 431 above | done | |
| Comptime tables, perfect hash, `@Vector` scanning | done | |
| Snapshot arena, freed after all workers pass | done | |
| DebugAllocator / ASan / fuzzer in CI | partial | Tests run under Debug safety checks. Zig 0.16.0's `-ffuzz` test runner fails to compile (std bug), so a built-in mutation fuzzer drives the same properties (`zig build fuzz -Dfuzz-iters=N`). No CI configured yet. |

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
| Normalize path for routing only | partial: query string is stripped for matching; no percent-decoding/dot-segment normalization yet |

## Upstream management

| Component | Phase | Status |
| --- | --- | --- |
| Per-worker pool keyed by endpoint, idle caps, liveness | 1 | done (keyed by endpoint; TLS/SNI/ALPN key parts come with TLS) |
| Round robin / weighted RR / P2C least-request | 1 | done (+ weighted random) |
| Passive health | 1 | done (connect failures → ejection with backoff; 5xx counted) |
| Cross-worker handoff, active health, outlier detection, retries budget, circuit breaking, mirroring | 2+ | not started. Safe retries exist: connect failures retry on another endpoint; a request on a pooled connection the upstream just closed is replayed once if idempotent and bodiless. |
| Ring hash / Maglev | 3 | not started |

## Dynamic configuration

| Item | Status |
| --- | --- |
| Hot-swap core steps 1–4 | done |
| Listener add/remove | done. Workers bind their own SO_REUSEPORT sockets for new listeners (the plan binds on the control thread and hands them over). Removed listeners stop accepting; idle connections close, in-flight ones finish with `Connection: close`. |
| Binary upgrade via SCM_RIGHTS | not started |
| xDS (ADS SotW, delta) | not started (model is xDS-shaped) |
| Local admin endpoint | done: `/ready`, `/stats`, `/metrics`, `/server_info`, `POST /reload`, `POST /drain`. Auth model is still an open question. |

## Gateway layer, plugins

Not started (Phase 3+).

## Observability

| Item | Status |
| --- | --- |
| Per-worker non-atomic counters, summed on scrape | done |
| Prometheus `/metrics` | done |
| Access logs (ring buffer + flusher) | not started |
| Tracing (traceparent, OTLP) | not started |
| Must-have metrics | ENOBUFS, pool hit rate, snapshot generation per worker, drain state: done. kTLS share: with TLS. |

## Benchmarking

Harness: `bench/vs_nginx.sh` (single host), `zig build bench-parse`, and
docs/benchmarking.md with the methodology. The multi-host, fixed-rate run is
still to do.
