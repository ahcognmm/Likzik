# API gateway (likzik-gw)

`likzik-gw` is the likzik proxy with the gateway extension. It has the same
binary flags, config file, reload, drain, TLS and metrics as `likzik`; the
gateway is configured in the config's `extensions.gateway` section. Plain
`likzik` refuses a config with an `extensions` section.

```sh
zig build -Doptimize=safe
zig-out/bin/likzik-gw -c config/gateway.example.json --check
zig-out/bin/likzik-gw -c config/gateway.example.json
tests/integration/gateway.sh      # end-to-end tests
bench/gateway.sh                  # per-feature overhead
```

## How it attaches to the core

The core has one generic extension point, `src/proxy/filter.zig`. It knows
nothing about auth or rate limits. On each request, after parsing and the
request-smuggling checks, the extension can pick the upstream cluster,
rewrite the path, add or remove request headers, or answer locally. On the
upstream's response head, it can add or remove response headers. The
gateway's config is compiled into the config snapshot, so it reloads (and
is validated) with the rest of the config. All gateway code is in
`src/gateway/`; the `likzik-gw` entry point is `src/gw_main.zig`.

## Request flow

1. **Route**: the first gateway route whose host, path, method, header and
   query matchers all match. With no match: `fallthrough: true` hands the
   request to the core `route_configs`, otherwise 404.
2. **Authentication**, if the route lists `auth` (any one method suffices).
3. **Rate limits**, in the order listed.
4. **Action**: forward to `cluster` (with `rewrite` and header edits),
   `redirect`, or `respond`.

Gateway errors are JSON: `{"error":"no_route"}` (404),
`{"error":"unauthorized"}` / `{"error":"invalid_credentials"}` (401, with
`WWW-Authenticate`), `{"error":"rate_limited"}` (429, with `Retry-After`
and `X-RateLimit-Limit`).

`listeners` restricts the gateway to some listeners; others use the core
routes only.

## Routes

```json
{ "name": "user", "hosts": ["api.example.com", "*.example.com"],
  "path": "/v1/users/:id", "methods": ["GET"],
  "headers": [ { "name": "X-Version", "value": "2" } ],
  "query": [ { "name": "debug", "present": false } ],
  "cluster": "users", "rewrite": "/users/{id}", "timeout_ms": 5000 }
```

- **path**: static segments, `:name` (one segment) and `*name` (the rest,
  zero or more segments, last only). Priority at each level is static, then
  param, then wildcard, with backtracking; routes on the same path are tried
  in config order. Matching uses a normalized copy of the path (unreserved
  `%XX` decoded, `.`/`..` resolved, empty segments dropped), so
  `/admin/../public` matches as `/public`. The original path is forwarded
  unless `rewrite` is set.
- **hosts**: exact, `*.suffix` or `*` (default: any). The port is ignored.
- **headers** matchers: `value` (exact), `prefix`, `present`.
  **query** matchers: `value`, `present` (raw, not percent-decoded).
- **rewrite**: a template. The original query string is appended unless
  the template contains `?`.
- **redirect**: `{ "status": 301|302|303|307|308, "location": "<template>" }`.
- **respond**: `{ "status", "body" (≤ 8 KiB), "content_type" }`.

Templates take `{param}` (from the path), `{consumer}`, `{client_ip}`,
`{host}`, `{path}`, `{query}` and `{scheme}`. Unknown placeholders are config
errors.

## Header transforms

```json
"request_headers":  { "set": [ { "name": "X-Src", "value": "gw:{id}" } ], "add": [], "remove": ["X-Debug"] },
"response_headers": { "set": [ { "name": "X-Frame-Options", "value": "DENY" } ], "remove": ["Server"] }
```

`set` replaces any existing copies, `add` appends, and `remove` deletes.
Request values are templates; response values are static.

## Authentication

### API keys

```json
"api_keys": [ { "name": "partners", "header": "X-API-Key", "query": "api_key", "strip": true,
  "keys": [ { "consumer": "acme", "sha256": "<hex sha-256 of the key>" },
            { "consumer": "dev", "key": "plain-key" } ] } ]
```

Only SHA-256 hashes are kept in memory; prefer giving `sha256` so the key
itself is never written in the config (`printf '%s' "$KEY" | sha256sum`).
With `strip` (default) the key is removed from the forwarded request,
header or query parameter.

### JWT

```json
"jwt": [ { "name": "idp", "algorithms": ["RS256"],
  "issuer": "https://idp.example.com/", "audiences": ["api"],
  "jwks_file": "/etc/likzik/jwks.json",
  "leeway_s": 30, "consumer_claim": "sub",
  "claims_to_headers": [ { "claim": "sub", "header": "X-User-Id" } ],
  "forward_token": true } ]
```

- Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384,
  EdDSA. Only those listed are accepted; `none` never is. A key only
  verifies its own algorithm family (no RSA/HMAC confusion), and the JWK's
  `alg`, if present, restricts it further.
- Keys: `jwks_file` (a JWKS document), inline `jwks`, and/or `hs_secret`
  (at least 32 bytes). RSA keys of 2048, 3072 or 4096 bits.
- Checks: signature, `exp` (required unless `require_exp: false`), `nbf`,
  `iss`, `aud` (string or array). Tokens with `crit` headers are rejected.
- Token from `Authorization: Bearer …` (or `header`), or the `query`
  parameter.
- Verification uses Zig's std.crypto. Each worker caches verified
  signatures by the token's SHA-256 for up to 5 minutes (claims are still
  checked on every request; a reload clears the cache). Cold asymmetric
  verifications are slow (about 70 µs for RS256 and 185 µs for ES256 on
  the dev VM); cached, they cost about 1 µs.
- JWKS is read when the config loads. Rotate keys by updating the file
  (the config reload picks it up via SIGHUP or POST /reload); remote JWKS
  URLs are not fetched yet.

### Consumer identity

A successful authentication sets `consumer_header` (default `X-Consumer`)
to the API key's consumer or the JWT's `consumer_claim`. Client-supplied
copies of the consumer header and of every `claims_to_headers` header are
always removed, authenticated or not, so they can't be spoofed.

`auth_optional: true` lets requests without credentials through as
anonymous; credentials that are present must still be valid.

## Rate limits

```json
"rate_limits": [ { "name": "per-consumer", "requests": 100, "per": "second", "burst": 200, "key": "consumer" } ]
```

- `per`: `second`, `minute`, `hour`. `burst` defaults to `requests`.
- `key`: `client_ip`, `consumer` (falls back to the client IP for anonymous
  requests), `route` (one bucket for the route), or `header:<name>`.
- Buckets are per (limit, route, key), in one fixed-size table (65,536
  buckets) shared by all workers of the process, so limits are exact per
  process. This differs from the plan's per-worker split, which would give
  a client whose connections land on one worker only rate/N. With more
  distinct keys than buckets, the stalest bucket is reused, making limits
  looser, never stricter. Limits are per process; a global limit across
  instances (Envoy RLS) is future work.

## Metrics

`/metrics` adds `likzik_gateway_{requests,no_route,auth_missing,auth_failed,
rate_limited,redirects,responds}_total` and
`likzik_gateway_jwt_cache_{hits,misses}_total`.

## Not yet

mTLS client identity, OAuth2 token introspection, remote JWKS fetching,
global (RLS) rate limits, body transforms, regex matchers, WASM/native
plugins, request mirroring rules.
