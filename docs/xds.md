# xDS (dynamic configuration)

likzik can take listeners, routes, clusters and endpoints from an
Envoy-compatible control plane (go-control-plane, Istio's istiod, Gloo,
Envoy Gateway, or your own) over the **Aggregated Discovery Service**
(ADS), state-of-the-world variant, gRPC over plaintext HTTP/2.

```json
{ "admin": { "address": "127.0.0.1:9901" },
  "xds": { "address": "10.0.0.2:18000", "node_id": "edge-1", "node_cluster": "edge" } }
```

| Field | Default | |
| --- | --- | --- |
| `address` | required | ADS server, `ip:port` |
| `node_id` | required | `Node.id` sent to the control plane |
| `node_cluster` | `likzik` | `Node.cluster` |
| `authority` | the address | `:authority` of the gRPC stream |
| `connect_timeout_ms` | 5000 | |

The `xds` section is read at startup. The rest of the file still applies:
admin, limits, TLS settings, access log, the gateway extension, and any
listeners, routes and clusters defined in the file sit next to the xDS
ones (a name used by both is rejected).

## How updates are applied

1. likzik subscribes to clusters and listeners (wildcard), then to the
   endpoints of every EDS cluster and the route configurations listeners
   refer to.
2. Each response is translated into likzik's config model, merged with the
   config file, and goes through the same validator as a file reload. A
   valid result becomes a new generation (workers switch atomically) and is
   ACKed. An invalid one is NACKed with the previous version and the
   validator's message; the running generation does not change.
3. A rejected response is retried after another type is accepted: a
   control plane may send a cluster removal before the removal of the
   listener that used it, and the cluster update then fits.
4. Listeners wait until their route configuration has arrived (warming);
   EDS clusters answer 503 until their endpoints arrive.
5. If the stream breaks, likzik keeps serving the last accepted
   configuration and reconnects (0.5 s to 30 s backoff), resubscribing from
   the accepted versions.

`/stats` reports `xds_connected`, `xds_updates_accepted` and
`xds_updates_rejected`; accepted and rejected updates are logged.

## What is supported

| Resource | Supported | Rejected (NACK) |
| --- | --- | --- |
| Cluster | `STATIC`, `EDS` (and DNS types with IP addresses), `ROUND_ROBIN` / `LEAST_REQUEST` / `RANDOM`, `connect_timeout` | other LB policies, DNS names, `ORIGINAL_DST` |
| ClusterLoadAssignment | priority 0 endpoints with weights; `UNHEALTHY`, `DRAINING`, `TIMEOUT` endpoints are skipped | DNS names |
| Listener | one filter chain with `http_connection_manager` (RDS or inline routes) or `tcp_proxy` | several filter chains, other filters, TLS from xDS |
| RouteConfiguration | prefix and exact path matches, `cluster`, `prefix_rewrite`, `timeout` (Envoy's 15 s default; 0 = 1 h) | regex and header matches, weighted clusters, redirects and direct responses |

Not supported yet: the incremental (delta) protocol, TLS to the control
plane, SDS secrets, and per-resource TTLs. Unknown fields in resources are
ignored, as protobuf does; features likzik cannot honour are rejected
rather than silently dropped.

## Implementation notes

- `proto/xds.proto` is a wire-compatible subset of the Envoy v3 API (only
  the fields likzik reads, with Envoy's field numbers). The generated C
  (protobuf-c) is committed; `make proto` regenerates it.
- The client runs on its own thread with nghttp2; the control thread does
  the merge, validation and publication, so xDS and file reloads are
  serialized.
- `tests/integration/xds.sh` runs against a small ADS server built on
  Envoy's own protos (`grpcio`, `xds-protos`).
