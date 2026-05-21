# selfdef HTTP API

A small read-only API the daemon exposes so the bundled dashboard (and,
eventually, `selfdefctl`) can pull events and findings out of the hot
store without each tool needing its own SQLite open. Read-only on
purpose — control-plane verbs (rule reload, panic mode, action runs)
will land in a later milestone once the auth/audit story is fleshed
out.

## Transports

| Transport | Auth | Use case |
|-----------|------|----------|
| UNIX socket | Filesystem permissions on the socket | Same-host dashboard, `selfdefctl` IPC |
| TCP        | `Authorization: Bearer <token>`       | Mobile dashboard, remote operator |

Both transports serve the same router. They can run side-by-side.

### UNIX socket

Default `unix_socket = "/run/selfdef.sock"`, mode `0660`. systemd-tmpfiles
and `User=` on the unit set the owner. Add your operator user to the
`adm` group (matching the default mode), or tighten the mode to `0600`
if the daemon and CLI both run as root.

### TCP

Set `tcp_addr` (e.g. `127.0.0.1:8443`) and write a high-entropy token to
`token_file`:

```bash
openssl rand -hex 32 | sudo tee /etc/selfdef/api.token
sudo chown root:root /etc/selfdef/api.token
sudo chmod 0600 /etc/selfdef/api.token
```

Then any client must send `Authorization: Bearer <contents-of-token-file>`.

### TCP + TLS / mTLS

The TCP transport can terminate TLS itself — no reverse proxy required.
Configure `[api.tls]`:

```toml
[api.tls]
cert_path = "/etc/selfdef/api-cert.pem"   # server certificate chain (PEM)
key_path  = "/etc/selfdef/api-key.pem"    # matching private key (PEM)
client_ca = ""                            # optional: enable mTLS
```

- **cert_path + key_path only** → TLS server. Bearer token still
  applies. Use this for LAN-exposed deployments where you want
  confidentiality + integrity but operators authenticate by token.
- **+ client_ca** → mTLS. The listener requires a client certificate
  signed by the CA bundle at `client_ca`. The bearer token still
  applies on top, but issuing per-operator client certs is a stronger
  identity story than a shared token.

Generate a quick self-signed cert for the daemon:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=selfdef" \
    -keyout /etc/selfdef/api-key.pem \
    -out    /etc/selfdef/api-cert.pem
sudo chmod 0600 /etc/selfdef/api-key.pem
```

For real deployments, use your existing CA — the cert bundle format is
standard PEM, so anything `openssl x509` can produce works.

## Endpoints

### Read endpoints

| Method | Path              | Returns |
|--------|-------------------|---------|
| GET    | `/status`         | JSON `{host_tag, schema_version, crate_version, event_count, uptime_secs}` |
| GET    | `/events?n=N`     | JSON array of the last N events (default 50, max 1000) |
| GET    | `/findings?n=N`   | JSON array of the last N events with `category_uid = 2` |
| GET    | `/events/stream`  | `text/event-stream` (SSE); one JSON event per `data:` frame, keepalive every 15s |
| GET    | `/actions`        | JSON `{actions: [...]}` — the registered action names in order |

### Control endpoints

| Method | Path                       | Body                                     | Effect |
|--------|----------------------------|------------------------------------------|--------|
| POST   | `/rules/reload`            | (none)                                   | Re-reads `correlator.rules_dir`. Returns `{rules_loaded: N}` |
| POST   | `/panic`                   | `{confirm: "<host_tag>", message?: "..."}` | Builds a Critical Finding and runs the panic action set. Mismatched `confirm` → 400 |
| POST   | `/actions/{name}/run`      | `{event: <Event>}` or `{event_id: "<uuid>"}` | Runs a single named action against the provided/stored event, bypassing the bus allowlist |

Each control verb emits an audit event onto the bus with
`source = "selfdef.api"`, class `INCIDENT_FINDING`, severity
`Informational`. The bus subscribers (store sink in particular) record
it, so `selfdefctl events tail` shows the audit trail.

**Auth boundary for control verbs.**

- **UNIX socket transport**: trusted via filesystem permissions. Every
  request gets the `Full` capability — anyone who can write to the
  socket can already `systemctl reload selfdefd` via the unit file, so
  `/rules/reload` doesn't widen the attack surface.
- **TCP transport**: two-tier bearer tokens.
  - `[api].token_file` is the *read* token. Grants the read-only API
    (`/status`, `/events`, `/findings`, `/events/stream`, `/actions`).
    Required when `tcp_addr` is set.
  - `[api].control_token_file` is the *control* token. Grants the
    read-only API *plus* the control verbs. Optional. When unset, the
    TCP transport refuses every control verb regardless of which token
    is presented — opting in is explicit.

Requests that authenticate as the read token but hit a control verb
get `403 Forbidden` (identity established, authority insufficient).
Unauthenticated requests on TCP get `401 Unauthorized`. The
`WWW-Authenticate: Bearer realm="selfdef-api"` header is set on 401s.

Mint the tokens with:

```bash
openssl rand -hex 32 | sudo tee /etc/selfdef/api.token
openssl rand -hex 32 | sudo tee /etc/selfdef/api-control.token
sudo chmod 0600 /etc/selfdef/api*.token
```

Rotate either token by replacing its file and `systemctl reload selfdefd`.

Every response is content-typed `application/json` (except the SSE
stream). The event body shape is the [OCSF-aligned envelope](../crates/selfdef-core/src/envelope.rs).

### `/v1` — four-watchdog + modules read surface

The `/v1/*` namespace exposes the per-watchdog state surface (MS044
guardian, MS046 friction-audit, MS047 perimeter, MS048 scheduler) plus
the MS006 modules inventory. Every route is read-only and returns
JSON. The same auth boundary as the read endpoints above applies (UNIX
socket = trusted; TCP = read token).

| Method | Path                                  | Returns |
|--------|---------------------------------------|---------|
| GET    | `/v1/friction-audit`                  | Latest verdict for every shipped MS046 gate |
| GET    | `/v1/friction-audit/history`          | Ring-buffer of historical verdicts |
| GET    | `/v1/perimeter`                       | Active perimeter policy + last 16 verdicts |
| GET    | `/v1/perimeter/history`               | Sigkill verdict log |
| GET    | `/v1/guardian`                        | Guardian state + recent events |
| GET    | `/v1/guardian/history`                | Guardian event log |
| GET    | `/v1/scheduler`                       | Scheduler state + last 16 routing decisions |
| GET    | `/v1/scheduler/history`               | Scheduler decision log |
| GET    | `/v1/scheduler/backpressure`          | Per-route backpressure counters |
| GET    | `/v1/scheduler/weights`               | Active 7-axis weight matrix per profile |
| GET    | `/v1/scheduler/explain/:request_id`   | Single-decision detail (factors + chosen route) |
| GET    | `/v1/modules`                         | All shipped modules with `{slug, summary, active, …}` |
| GET    | `/v1/modules/:name`                   | Single-module detail (404 if unknown, 400 on invalid slug) |
| GET    | `/v1/alerts`                          | MS027 alerts: server-side classification of the 9 alert series. Returns `{worst, alerts: [{name, ms, series, threshold, value, state}]}`. Consumed by both the PWA dashboard "Alerts overview" panel and `selfdefctl alerts`. |

Module `:name` slugs are validated against `[a-z0-9-]{1,64}`. Any
mismatch is `400 Bad Request` — this is the directory-traversal guard
for the manifest-on-disk reader.

The dashboard's four-watchdog panels (and the `selfdefctl trio`
consolidated view) consume these routes. They are stable in the
sense that any breakage is caught by the L1 + integration test
gates in `scripts/test/coherence.sh` before a release tag.

### Prometheus exposition (`/metrics`)

The daemon also exposes `GET /metrics` in standard Prometheus
exposition format. The four-watchdog series (17 gauges as of MS048)
+ the modules series (`selfdef_modules_shipped_total`,
`selfdef_modules_active_total`) are emitted here. The MS027
observability module ships a Grafana dashboard + Prometheus alert
rules that consume these. No authentication is performed on
`/metrics` over the UNIX socket; on TCP, the read token is required.

### SSE live tail

The `/events/stream` endpoint subscribes to a fresh bus subscriber per
client and forwards every event as a `data:` frame. When a subscriber
lags (the broadcast capacity is exceeded by a burst), the stream emits a
single `event: lagged` frame with the missed count and then resumes.
Disconnect a client and the forwarder task on the server exits the next
time it tries to send.

## Dashboard

A vanilla-JS PWA lives in `dashboard/`. Open `index.html` directly to
talk to a local-only API, or set `?api=https://your-host` to point at a
reverse-proxied deployment. The bearer token can be passed in the URL
once (`?token=...`); it's persisted to `sessionStorage` for that tab.

The dashboard surfaces the read endpoints (status, findings, events,
live stream) and a **Control** panel that wires up the write
endpoints:

- **Reload rules** — `POST /rules/reload`.
- **Panic** — `POST /panic`. Requires typing the host tag into the
  confirm box and clicking through a browser confirm dialog. Same
  safety belt as `selfdefctl panic --confirm <host>`.
- **Run action** — `POST /actions/{name}/run`. The action dropdown is
  populated from `GET /actions`. The event-id box defaults to the
  most-recent finding when left blank.

The result of every control call lands in a status bar at the bottom
of the panel — success in green, errors in red. If the token in
`sessionStorage` is the read-only token, calling a control verb shows
`403 control verb requires the control token` inline. Set the
session's token to the control token (via `?token=` in the URL) to
unlock the section.

Service-worker shell caching is enabled when the dashboard is served
over HTTP(S). API responses are never cached — operators need the
freshest data they can get. The worker also passes every non-`GET`
request straight through so control verbs never get intercepted.
