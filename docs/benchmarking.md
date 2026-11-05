# Benchmarking against nginx

Goal (Phase 1 gate): within 10% of nginx p99 at equal offered load, with the
same core count.

## Quick, single host

```sh
zig build -Doptimize=ReleaseFast
bench/vs_nginx.sh [workers=2] [seconds=10] [connections=64]
zig build bench-parse -Doptimize=ReleaseFast   # parser throughput
```

The script runs keep-alive, new-connection, 1 MiB body and TCP passthrough
workloads against likzik and against nginx configured as an equivalent
reverse proxy (same upstream, upstream keepalive, `reuseport`, access log
off, same worker count). It uses wrk2 when available, otherwise wrk.

Single-host numbers are only a smoke test: the load generator, both proxies
and the upstream share CPUs. Example from the development VM (4 vCPUs,
Linux 6.18, 2 workers each, 64 connections, wrk, ReleaseFast):

| workload | likzik req/s | nginx req/s | likzik p99 | nginx p99 |
| --- | ---: | ---: | ---: | ---: |
| keep-alive | 90.5k | 78.1k | 2.72 ms | 3.46 ms |
| new connection per request | 33.8k | 37.1k | 4.57 ms | 5.55 ms |
| 1 MiB body | 2.67k | 2.08k | 51.7 ms | 78.1 ms |
| TCP passthrough (likzik) | 110.3k | n/a | 4.09 ms | n/a |

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
