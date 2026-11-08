# Upstreams: health, retries and overload

Settings on a cluster that decide which endpoints get traffic, what
happens when one fails, and how much load a cluster may take. Counters are
per worker (no shared atomics on the request path); process-wide limits
are split evenly across workers, rounded up.

```json
{ "name": "users", "lb_policy": "least_request",
  "eject_after_failures": 3, "consecutive_5xx": 5, "eject_ms": 10000, "max_ejection_percent": 50,
  "circuit_breakers": { "max_connections": 1024, "max_requests": 1024, "max_retries": 32 },
  "retry": { "retry_on": ["gateway_error", "reset"], "num_retries": 1, "budget_percent": 20 },
  "endpoints": [ { "address": "10.0.1.10:8000" }, { "address": "10.0.1.11:8000" } ] }
```

## Passive health and outlier detection

- `eject_after_failures` (default 3): consecutive connect failures (refused,
  timeout) before an endpoint is ejected.
- `consecutive_5xx` (default 0, off): consecutive 5xx responses before an
  endpoint is ejected.
- `eject_ms` (default 10 s): ejection time, doubled on each repeated
  ejection up to 32x; reset once the endpoint answers well again.
- `max_ejection_percent` (default 50): never eject more than this share of
  the cluster at once. If every endpoint is ejected anyway (each worker
  decides alone), all are used again (panic mode), as in Envoy.

Ejections are counted in `endpoint_ejections`.

## Retries

With a `retry` policy, a failed attempt is retried on a different endpoint
when all of these hold:

- the request is idempotent (`GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`,
  `TRACE`) and has no body;
- nothing has been sent to the client yet;
- the failure is one listed in `retry_on`: `gateway_error` (502, 503 or
  504 from the upstream), `5xx` (any 5xx), or `reset` (the connection
  broke before a response);
- fewer than `num_retries` (default 1, at most 5) retries were made;
- the **retry budget** allows it: retries in flight stay under
  `budget_percent` (default 20) of the cluster's active requests (at least
  3 per worker), and under `circuit_breakers.max_retries`.

Retries are counted in `upstream_rq_retry`; retries the budget refused in
`upstream_rq_retry_overflow`. Connect failures are always tried on another
endpoint up to `max_connect_attempts` (default 2), with or without a
policy, since nothing reached the upstream.

## Circuit breakers

`circuit_breakers` caps a cluster for the whole process (0 = no limit):

- `max_requests`: requests in flight to the cluster. Over the limit,
  requests get an immediate 503 and count in `upstream_rq_overflow`.
- `max_connections`: upstream connections opened for the cluster
  (idle ones included). New requests that would need another connection
  get 503.
- `max_retries`: retries in flight (see above).

Breakers protect a struggling cluster from a retry storm or a backlog: a
fast 503 is better than queueing until timeouts.
