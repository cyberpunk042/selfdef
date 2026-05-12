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

Service-worker shell caching is enabled when the dashboard is served
over HTTP(S). API responses are never cached — operators need the
freshest data they can get.
