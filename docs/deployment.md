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
