# Dashboard (likzik-ui)

A small web UI for likzik and likzik-gw, laid out like Traefik's dashboard.

```sh
zig build -Doptimize=safe
zig-out/bin/likzik-ui -c /etc/likzik/likzik.json            # http://127.0.0.1:9902/
zig-out/bin/likzik-ui -c cfg.json -l 0.0.0.0:9902 --token "$(openssl rand -hex 24)"
```

| Flag | Default | |
| --- | --- | --- |
| `-c, --config` | required | The proxy's config file |
| `-l, --listen` | `127.0.0.1:9902` | Dashboard address |
| `--admin` | `admin.address` from the config | The proxy's admin endpoint |
| `--proxy` | `likzik-gw` next to `likzik-ui` | Binary used to validate configs (`--check`) |
| `--token` | none | Require `Authorization: Bearer <token>` on the API. Mandatory for non-loopback addresses. |

## Views

- **Overview**: state, workers, uptime, config generation and the last
  rejected reload; requests per second (live, 2-minute chart), active
  connections, 2xx–5xx, upstream pool hit rate, timeouts, connect failures,
  ejections; gateway auth failures, rate limiting, JWT cache; TLS
  handshakes and the kTLS/userspace split.
- **HTTP Routers**: gateway routes and core routes (and TCP listeners)
  with their rule, entrypoints, middlewares and target. A red dot marks a
  router that references an unknown service, auth or rate limit.
- **Services**: clusters, servers and weights, load balancing, upstream
  TLS, and how many routers use each.
- **Middlewares**: API key sets (consumers only, never keys), JWT
  providers, rate limits, and where each is used.
- **Entrypoints**: listeners, TLS, which ones the gateway handles, global
  limits.
- **Config**: the whole file as JSON, with Validate / Apply / Reload.

## Editing

Every row has **Edit** (its JSON in a dialog), and each view has **Add**
with a template. Edits go into a draft; a bar at the bottom counts them.
**Validate & apply**:

1. writes the draft to a temporary file next to the config and runs
   `likzik-gw -c <tmp> --check`, the proxy's own validator (certificates,
   JWKS files and every reference included). On failure nothing is
   written and the proxy's message is shown;
2. saves the current file as `<config>.bak` and atomically renames the new
   one into place;
3. the proxy's file watcher applies it, and the UI waits for the new
   generation to appear on the admin endpoint.

If the file changed on disk since the UI loaded it (another editor, a
deploy), Apply is refused with a conflict instead of overwriting it.

## Security

The config can contain secrets (plain API keys, HMAC secrets). The
structured views hide them, but the Config tab and the API return the
whole file, and the API can change the proxy's configuration. Keep the
default loopback address, or use `--token` and put TLS in front (for
example a likzik listener with TLS routing to the dashboard). The page
sends a strict Content-Security-Policy and `X-Frame-Options: DENY`.

## API

| Method | Path | |
| --- | --- | --- |
| GET | `/api/config` | `{path, etag, text}` |
| POST | `/api/validate` | body: config text → `{ok, message}` |
| PUT | `/api/config` | body: config text, `If-Match: <etag>` → `{ok, applied, generation, etag, message}`; 400 invalid, 409 conflict |
| GET | `/api/admin/{server_info,stats,metrics,ready}` | proxied from the proxy's admin endpoint |
