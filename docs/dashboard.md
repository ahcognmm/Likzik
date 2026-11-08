# Dashboard (likzik-ui)

The config console for likzik and likzik-gw: edit listeners, routes,
clusters, certificates and auth in a draft, review the changes, and
publish them as a new configuration generation. The design is in
`docs/design/console/`; the rules for changing the UI are in
`src/ui/CLAUDE.md`.

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

## Screens

- **Sources and status**: the config file the proxy watches, the
  generation each worker runs, the last rejected reload, draining state,
  runtime checks (kTLS share, buffer exhaustion, pool reuse, connect
  failures, requests per second) and the change history. An xDS control
  plane is shown as not available: likzik reads files only.
- **Routing**
  - *Listeners*: addresses, HTTP or TCP, TLS certificates, and whether
    the API gateway handles the listener.
  - *Routes*: gateway routes in match order, then the core routes that
    catch what they miss. Each route opens in an editor (match, upstream,
    auth, rate limit, headers), with a "How a request travels" diagram.
    **Add route** shows a preview and warns about overlapping routes.
  - *Clusters*: endpoints and weights, load balancing, ejection, pooling
    and upstream TLS. Renaming a cluster updates every route that uses it.
- **Certificates**: certificates served by listeners, how upstreams are
  verified, and the "require kernel TLS" switch.
- **Auth providers**: JWT providers, API key sets and rate limits. New API
  keys are generated in the browser and stored as SHA-256 hashes; the key
  is shown once.
- **Review and publish**: every change with before/after values, the
  proxy's own validation, the apply order, and the workers switching
  generation. After a publish, **Roll back to generation N** publishes the
  previous version again.

## Publishing

Edits stay in a draft in the browser until **Publish generation N**:

1. the draft goes to a temporary file next to the config, checked by
   `likzik-gw -c <tmp> --check`, the proxy's own validator (certificates,
   JWKS files and every reference included). On failure nothing is
   written and the proxy's message is shown;
2. the current file is kept in `<config>.history/` with your note (the
   newest 50 are kept), and as `<config>.bak`;
3. the new file is renamed into place atomically;
4. the proxy's file watcher applies it, and the console waits for the new
   generation to appear on the admin endpoint.

If the file changed on disk since the console loaded it (another editor,
a deploy), publishing is refused with a conflict instead of overwriting it.
Any entry in the change history can be loaded into the draft, reviewed
and published again.

## Security

The config can contain secrets (plain API keys, HMAC secrets). The
screens never show them, but the API returns the whole file, and the API can change the proxy's configuration. Keep the
default loopback address, or use `--token` and put TLS in front (for
example a likzik listener with TLS routing to the dashboard). The page
sends a strict Content-Security-Policy and `X-Frame-Options: DENY`.

## API

| Method | Path | |
| --- | --- | --- |
| GET | `/api/config` | `{path, etag, text}` |
| POST | `/api/validate` | body: config text → `{ok, message}` |
| PUT | `/api/config` | body: config text, `If-Match: <etag>`, optional `X-Likzik-Note` (percent-encoded) → `{ok, applied, generation, previous_generation, etag, message}`; 400 invalid, 409 conflict |
| GET | `/api/history` | entries `{id, time_ms, note, replaced_generation, size}`, newest first |
| GET | `/api/history/<id>` | `{id, text}`: the version that publish replaced |
| GET | `/api/admin/{server_info,stats,metrics,ready}` | proxied from the proxy's admin endpoint |

## Developing the UI

The UI is a React + Vite + TypeScript app in `src/ui/web`. The built files
(`dist/`) and the generated `src/ui/assets.zig` are committed, so
`zig build` needs no Node.

```sh
cd src/ui/web
npm install
npm run dev        # Vite on :5173, /api proxied to likzik-ui (LIKZIK_UI, default 127.0.0.1:9902)
npm test           # model tests (Vitest)
npm run build      # typecheck, build dist/, regenerate ../assets.zig
```
