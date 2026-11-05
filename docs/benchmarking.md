# Benchmarking against nginx

Goal (Phase 1 gate): within 10% of nginx p99 at equal offered load, with the
same core count.

## Quick, single host

```sh
zig build -Doptimize=fast
bench/vs_nginx.sh [workers=2] [seconds=10] [connections=64]
zig build bench-parse -Doptimize=fast   # parser throughput
```

The script runs keep-alive, new-connection, 1 MiB body and TCP passthrough
workloads against likzik and against nginx configured as an equivalent
reverse proxy (same upstream, upstream keepalive, `reuseport`, access log
off, same worker count). It uses wrk2 when available, otherwise wrk.
Extra likzik flags can be passed with `LIKZIK_ARGS`. To find which part
of the send/close path matters on a given machine, A/B these one at a time:

```sh
LIKZIK_ARGS="--no-pin"         bench/vs_nginx.sh   # workers float (nginx's default)
LIKZIK_ARGS="--buffers 1024"   bench/vs_nginx.sh   # larger provided-buffer ring
LIKZIK_ARGS="--no-coalesce"    bench/vs_nginx.sh   # head and small body as separate segments
LIKZIK_ARGS="--always-linger"  bench/vs_nginx.sh   # wait for the client FIN before closing
```

Besides req/s and latency it reports, for the proxy processes only (not wrk,
not the upstream):

- **cpu**: average CPU cores used during the run (utime+stime of all threads).
- **cpu/req**: CPU time per request in µs. This is the efficiency number;
  on a shared host, req/s also depends on how the scheduler shares cores
  between wrk, the upstream and the proxy.
- **pss MB**: proportional set size after the run. Shared pages are split
  between processes, so nginx's master and workers are counted fairly.
- **peak memory** (last line): sum of VmHWM, which counts shared pages once
  per process.

Single-host numbers are only a smoke test: the load generator, both proxies
and the upstream share CPUs. Example from the development VM (4 vCPUs,
Linux 6.18, 2 workers each, 64 connections, wrk, `-Doptimize=fast`):

| workload | likzik req/s | nginx req/s | likzik cpu/req | nginx cpu/req | likzik p99 | nginx p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| keep-alive | 127–128k | 93–100k | 10.8–11.0 µs | 18.4–19.1 µs | 2.4–3.4 ms | 3.1–3.7 ms |
| new connection per request | 40–44k | 35k | 21–23 µs | 36–37 µs | 3.7–3.9 ms | 5.9 ms+ |
| 1 MiB body | 3.2–3.5k | 2.1–2.3k | 490–520 µs | 760–860 µs | 37–41 ms | 60–71 ms |

likzik memory: about 10 MB PSS idle, 21 MB after the 1 MiB run (2 workers).
nginx: about 16–17 MB.

Parser: about 3.7 M requests/s per core (1.1 GB/s) on mixed realistic heads.

HTTPS on the same VM. Its kernel has no `CONFIG_TLS`, so both proxies run
userspace TLS; this is not the kTLS comparison the plan targets. ECDSA
P-256, TLS 1.3, 2 workers each, 64 connections:

| workload | likzik req/s | nginx req/s | likzik p99 | nginx p99 |
| --- | ---: | ---: | ---: | ---: |
| keep-alive | 77–79k | 78–79k | 4.1–4.4 ms | 3.8–4.2 ms |
| new TLS connection per request | 4.6–5.6k | 4.2–4.7k | 16–21 ms | 6–8 ms |

On new connections, wrk's latency covers only the request after the
handshake. likzik finishes more handshakes per second, so requests queue
behind them, while nginx delays handshakes instead. Measured end to end
(handshake plus request, curl probes during the run), likzik was
equal or faster: 5–25 ms to first byte vs 12–28 ms for nginx. A fixed-rate
run with handshake time included is the right way to judge this.

## Numbers worth publishing

- Separate load-generator hosts; same NIC and kernel on the proxy host.
- Same worker cores for both proxies; pin IRQs/RSS queues away from or onto
  those cores consistently; `performance` governor; record SMT/turbo state.
- Fixed offered load with wrk2 or vegeta at several rates. Report
  p50/p99/p99.9/p99.99 and the rate at which p99 crosses the SLO, not just
  peak RPS.
- Same upstream pool, LB policy and logging on both sides. For HTTPS, the
  same TLS library and cipher suite, with nginx also on kTLS + `reuseport`.
- Tune `somaxconn`, SYN backlog, the local port range and fd limits; check
  NUMA locality.
- Reference: zoxy-io/benchmark runs nightly comparisons of a Zig io_uring
  proxy against nginx, HAProxy, Envoy and Pingora.
