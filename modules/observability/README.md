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
# scrapes. Default = Tetragon's metrics endpoint from the `tetragon`
# module.
scrape_targets = "localhost:2112"

# Both profiles. Dashboard metadata.
dashboard_uid   = "selfdef"
dashboard_title = "selfdef — Host Self-Defense"
```

## Dashboard

The shipped dashboard is intentionally narrow — four panels, all
sourced from Tetragon's built-in metrics:

| Panel | Metric | Why |
| --- | --- | --- |
| Tetragon events / second | `rate(tetragon_events_total[5m])` | Sanity check that the substrate is collecting at all. |
| Tetragon kills by policy | `rate(tetragon_msg_sigkill_total[5m])` by `policy` | The "are policies actually firing" signal. Spikes = either an attack or a busted policy; flat = a quiet host. |
| Process cache utilization | `tetragon_process_cache_size` | If this saturates you'll lose short-lived process correlation; bump `process-cache-size` in the `tetragon` module config. |
| Map operation errors | `rate(tetragon_map_errors_total[5m])` by `map`, `op` | Non-zero is a Tetragon-side bug; surface it before it eats events. |

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
