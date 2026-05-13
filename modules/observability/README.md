# observability

Prometheus scrape config + Grafana dashboard for the selfdef stack.
Owned outputs:

- `selfdef.yml` — Prometheus scrape job that targets the Tetragon
  metrics endpoint (and any other selfdef-managed endpoint a future
  module declares).
- `selfdef.json` — a Grafana dashboard rendering Tetragon event
  rate, kills-by-policy, process cache utilization, and BPF map
  errors. Hand-tuned to fit on one screen on a normal desktop.

This module does **not** install Prometheus or Grafana. They're
operator-owned services. The module configures them.

## Profiles

| Profile | Use when | What it does |
| --- | --- | --- |
| `bundled` (default) | Prometheus + Grafana run on this host under systemd. | Drops scrape config under `/etc/prometheus/conf.d/` and the dashboard JSON under `/var/lib/grafana/dashboards/selfdef/`. Reloads Prometheus on change. Grafana auto-discovers the dashboard JSON. |
| `external` | Prometheus + Grafana run elsewhere (central host, managed service, k8s). | Renders the same files into a staging dir for the operator to sync out. No services are touched. |

## Config

```toml
profile = "bundled"   # or "external"

# Bundled profile only:
prometheus_conf_dir    = "/etc/prometheus/conf.d"
prometheus_service     = "prometheus.service"
grafana_dashboards_dir = "/var/lib/grafana/dashboards/selfdef"

# External profile only:
staging_dir = "/var/lib/selfdef/observability/staging"

# Both profiles. Comma-separated host:port targets Prometheus
# scrapes. The shipped default covers both endpoints the
# dashboard needs:
#   - localhost:2112 — Tetragon's built-in metrics endpoint
#     (from the `tetragon` module's default profile).
#   - localhost:8443 — selfdef-daemon's `/metrics` endpoint
#     (requires `[api] enabled = true` and `tcp_addr =
#     "127.0.0.1:8443"` in /etc/selfdef/selfdef.toml; bearer
#     token required — see "Scraping the daemon" below).
scrape_targets = "localhost:2112, localhost:8443"

# Both profiles. Dashboard metadata.
dashboard_uid   = "selfdef"
dashboard_title = "selfdef — Host Self-Defense"
```

## Dashboard

The shipped dashboard renders seven panels — four from
Tetragon's built-in metrics, three from the selfdef daemon's
own `/metrics` endpoint:

| Panel | Source | Metric |
| --- | --- | --- |
| Tetragon events / second | tetragon | `rate(tetragon_events_total[5m])` |
| Tetragon kills by policy | tetragon | `rate(tetragon_msg_sigkill_total[5m])` by `policy` |
| Process cache utilization | tetragon | `tetragon_process_cache_size` |
| Map operation errors | tetragon | `rate(tetragon_map_errors_total[5m])` by `map`, `op` |
| selfdef events / sec by class | selfdef-daemon | `sum by (class_uid) (rate(selfdef_events_by_class_total[5m]))` |
| selfdef findings / sec by severity | selfdef-daemon | `sum by (severity_id) (rate(selfdef_findings_by_severity_total[5m]))` |
| selfdef hot-store size | selfdef-daemon | `selfdef_store_events` |

### Tetragon metric-name pin

The four Tetragon panels reference metric names from upstream
Tetragon's built-in Prometheus exporter. The shipped panel
queries are verified against **Tetragon v1.x** (the
[`tetragon-metrics`](https://tetragon.io/docs/reference/metrics/)
reference page is the canonical source). If you run a Tetragon
version that renames any of these series (`tetragon_events_total`,
`tetragon_msg_sigkill_total`, `tetragon_process_cache_size`,
`tetragon_map_errors_total`), the corresponding panel renders
flat. The `tetragon` module's `requires` block doesn't pin a
Tetragon version range today (F-2026-052 in the audit ledger);
Phase-2 follow-up tracked.

### Daemon-side panels gating

The daemon-side panels render flat / empty if the
`scrape_targets` list doesn't include the daemon's `/metrics`
endpoint (or if the daemon isn't running). Both endpoints are
required for full dashboard coverage.

## Scraping the daemon

The selfdef daemon's `/metrics` endpoint is auth-gated:

- **UNIX socket** (`/run/selfdef.sock`): no bearer token; gated
  by filesystem permissions. Easiest if Prometheus runs on the
  same host with read access to the socket.
- **TCP** (`127.0.0.1:8443` or wherever `[api] tcp_addr` binds):
  every request needs `Authorization: Bearer <token>` matching
  the contents of `[api] token_file` (default
  `/etc/selfdef/api.token`).

Prometheus scrape config for the TCP transport with bearer
token:

```yaml
scrape_configs:
  - job_name: "selfdef-daemon"
    scrape_interval: 15s
    metrics_path: /metrics
    bearer_token_file: /etc/selfdef/api.token
    static_configs:
      - targets: ["localhost:8443"]
```

If Prometheus runs as a different user than the daemon, copy
the token to a file Prometheus can read at the right mode
(typically `0600 prometheus:prometheus`). Don't symlink — the
two services should hold their own copies so credential
rotation is a deliberate operator action on each side.

Extend the dashboard by editing
`assets/dashboards/selfdef.json.template` and re-running apply —
the file is template-rendered each time so your edits to the
checked-in template propagate.

## What's NOT here yet

- Alert rules. Grafana's alerting + Prometheus's alertmanager are
  operator-owned. The dashboard makes the data legible; reacting
  to it is the notifier chain's job (which integrity-sentinel +
  detect-host already wire up).
- Loki / OpenTelemetry traces. Out of scope for v0.1 — selfdef's
  hot path is structured events, not generic logs/traces.

## Phase

Ships in `phase = "post"` so every other module's metrics endpoint
is up when Prometheus picks up the new scrape job. Cross-phase
dependency on `tetragon` (which is `pre`) is allowed because deps
to earlier phases are always valid.

## Uninstall

`selfdefctl modules uninstall --confirm <hostname> --only observability`
removes the rendered files. Prometheus + Grafana themselves are not
touched — the operator runs them, the operator removes them.
