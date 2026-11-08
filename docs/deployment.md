# Deployment

likzik needs io_uring. At startup it checks the kernel version,
`kernel.io_uring_disabled` and whether `io_uring_setup` is allowed (seccomp).
If any check fails it exits with an explicit message rather than running
degraded.

## Kernel

- Production: Linux 6.18 LTS. Development: 6.14 or newer (the first kernel with
  kTLS TLS 1.3 rekey, needed once TLS lands). `--allow-old-kernel` permits
  6.1+ for development only.
- `kernel.io_uring_disabled` must be `0`, or `1` with the service user in
  `kernel.io_uring_group`.

RHEL 9.3+ and derivatives ship with io_uring disabled:

```sh
echo 'kernel.io_uring_disabled = 0' > /etc/sysctl.d/90-likzik.conf
sysctl --system
```

## Kernel TLS

HTTPS is designed to run on kTLS. Load the module and make it persistent:

```sh
modprobe tls
echo tls > /etc/modules-load.d/tls.conf
```

With `"tls": {"require_ktls": true}` (the default), likzik refuses to start,
or to apply a config, that uses TLS while `/proc/net/tls_stat` is missing.
Set it to `false` to allow the userspace fallback, which is slower. Watch
`likzik_tls_ktls_total` against `likzik_tls_userspace_total` in production:
a rising userspace share means kTLS is not engaging (check the module, the
OpenSSL build and the negotiated cipher).

OpenSSL must be built with kTLS (Ubuntu and Debian packages are; when
building from source, configure with `enable-ktls`).

## Containers (Docker, containerd, Kubernetes)

Docker's and containerd's default seccomp profiles block `io_uring_setup`,
`io_uring_enter` and `io_uring_register`. Run with a profile that allows
them. Start from the default profile and add:

```json
{
  "names": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
  "action": "SCMP_ACT_ALLOW"
}
```

```sh
docker run --security-opt seccomp=/etc/likzik/seccomp.json ...
```

On Kubernetes, set `securityContext.seccompProfile` to a `Localhost` profile
containing the same rule.

## Limits

- `RLIMIT_NOFILE`: each connection uses one fd (two for a proxied request,
  four for a TCP tunnel with its pipes). likzik raises the soft limit to the
  hard limit at startup and warns below 65536. Set `LimitNOFILE=1048576` in
  systemd.
- `RLIMIT_MEMLOCK`: since Linux 5.12 io_uring memory is charged to the
  cgroup rather than to memlock, so the default is fine on supported
  kernels. If startup reports "out of locked memory", raise it
  (`LimitMEMLOCK=infinity`).
- `net.core.somaxconn` and `net.ipv4.tcp_max_syn_backlog`: listeners use a
  backlog of 4096. Raise both to at least that.

## Behind a load balancer: PROXY protocol

When an L4 load balancer (AWS NLB, HAProxy, ...) sits in front, likzik
sees the balancer's address. Enable the PROXY protocol on both sides and
likzik takes the client address from the header instead:

```json
{ "name": "web", "address": "0.0.0.0:443", "route_config": "main", "proxy_protocol": true, "tls": { ... } }
```

v1 and v2 are both accepted; v2 `LOCAL` (balancer health checks) keeps
the peer address. A connection that does not start with a valid header
is closed and counted in `proxy_protocol_rejected`, so only enable it
when every client goes through the balancer. The client address is used
for `X-Forwarded-For` and the access log.

TCP listeners can also *send* the header to their upstreams, so a backend
behind a passthrough tunnel still sees the client:

```json
{ "name": "pg", "proxy_protocol": "v2", "endpoints": [ { "address": "10.0.0.4:5432" } ] }
```

(Only TCP listeners can use such a cluster: pooled HTTP upstream
connections are shared between clients.)

## TLS passthrough by server name (SNI)

A TCP listener can route TLS connections by the server name in the
ClientHello without terminating TLS: the backend does the handshake and
sees the client's bytes unchanged.

```json
{ "name": "tls-in", "address": "0.0.0.0:443", "protocol": "tcp", "cluster": "fallback",
  "sni_routes": [
    { "server_names": ["db.example.com"], "cluster": "db" },
    { "server_names": ["*.apps.example.com"], "cluster": "apps" } ] }
```

Exact names win over `*.suffix` patterns, and the longest suffix wins.
`cluster` is optional; it takes connections with no SNI, an unknown name,
or no TLS at all. Without it such connections are closed
(`tcp_sni_unmatched`). The ClientHello must arrive within
`limits.header_timeout_ms`.

## Access logs

```json
"access_log": { "path": "/var/log/likzik/access.log", "format": "text" }
```

One line per request, written when the response finishes (or the
connection ends). `format` is `text` (default) or `json`:

```
2026-11-08T17:40:00.123Z 10.0.0.1 web "GET /v1/users/42 HTTP/1.1" 200 1234 12ms users 10.0.1.10:8000
```

Fields: start time (UTC), client address, listener, request line (`"-"`
when it could not be parsed; targets over 512 bytes are cut), status
(`-` when the client left before a response), bytes sent to the client
(head and body), duration, cluster and the last endpoint tried. JSON lines
carry the same fields plus `tls`.

Workers never wait on the disk: each buffers lines in its own 4 MiB
ring, and the control thread appends them to the file about four times a
second. If a ring fills up, lines are dropped and counted in
`access_log_dropped`. The file is reopened on every reload, so to rotate:
rename the file, then send `SIGHUP` (logrotate: `postrotate kill -HUP
$(pidof likzik-gw)`; no `copytruncate`).

## systemd unit

```ini
[Service]
ExecStart=/usr/local/bin/likzik -c /etc/likzik/likzik.json
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=30
LimitNOFILE=1048576
Restart=on-failure
```

`systemctl reload` re-reads the config; `systemctl stop` drains gracefully.
