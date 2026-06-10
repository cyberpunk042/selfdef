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

The dashboard opens with seven **core** panels — four from
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

Below the core panels the dashboard adds the rows that grew with the
IPS spine (panel-count floor locked at ≥30 by
`scripts/test/L1-grafana-template.sh`): the **four-watchdog set**
(MS027 friction-audit / perimeter / guardian / scheduler), the
**module catalog** (MS006 shipped/active), the **M060 cross-repo
mirror export** row (6 panels), and the **Daemon health & retention
liveness** row (SD-API uptime · metrics ingest-lag · retention
enabled/sweep-liveness). Each row is described in its own section
below; the full panel set lives in `assets/dashboards/selfdef.json.template`.

### Tetragon metric-name pin

The four Tetragon panels reference metric names from upstream
Tetragon's built-in Prometheus exporter. The shipped panel
queries are verified against **Tetragon v1.x** (the
[`tetragon-metrics`](https://tetragon.io/docs/reference/metrics/)
reference page is the canonical source). If you run a Tetragon
version that renames any of these series (`tetragon_events_total`,
`tetragon_msg_sigkill_total`, `tetragon_process_cache_size`,
`tetragon_map_errors_total`), the corresponding panel renders
flat. These four names are now PINNED in a machine-checkable
contract — [`assets/contracts/tetragon-metrics.toml`](assets/contracts/tetragon-metrics.toml)
(SDD-079, closing F-2026-052) — which the CI contract test
(`tests/observability/test_tetragon_metric_name_contract.py`)
locks against the dashboard in lockstep, and which `check.sh`
probes against the live endpoint (opt-in
`SELFDEF_OBSERVABILITY_PROBE_TETRAGON=1`) so a rename surfaces
as a loud warn instead of a silent flat panel. The contract's
`verified_tetragon_version` field (`>=1.0.0, <2.0.0`) records the
window these names are validated against; fail-closed enforcement
from the `tetragon` module's `requires` block (a binary-version
probe) remains a Phase-3 follow-up (SDD-079 D-1).

### Daemon-side panels gating

The daemon-side panels render flat / empty if the
`scrape_targets` list doesn't include the daemon's `/metrics`
endpoint (or if the daemon isn't running). Both endpoints are
required for full dashboard coverage.

### Policy-data coupling (F-2026-080)

The **Tetragon kills by policy** and **Map operation errors**
panels render data only when *policy modules* are applied and
actually firing — there is no kill/policy stream until something
loads Tetragon TracingPolicies. In practice that means
`agent-guard` (host-level invariants on AI agents) and the
perimeter policies; an empty "kills by policy" panel on a host
with no policy modules is **correct, not a fault**. This is a
deliberate *runtime* coupling, not a module-manifest dependency:
`observability` does not `depends_on` `agent-guard`, because the
dashboard is useful (Tetragon event rate, process cache, the
selfdef-daemon panels) even with zero policy modules. Operators
who want the kill-by-policy view must apply at least one policy
module (`selfdefctl modules apply … --only agent-guard`).

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

## Alert rules

`assets/alerts/selfdef.yml.template` ships 19 Prometheus alert rules
across 4 groups: the MS027 four-watchdog set, the M060 cross-repo
mirror-export loop, the SDD-062 detection-watchdog finding stream, and
the meta-observability warnings (metrics-ingest lag + correlator bus lag
+ responder bus lag).

### MS027 four-watchdog set (MS046 + MS047 + MS044 + MS048)

| Severity | Alert | Triggers when |
|---|---|---|
| critical | SelfdefFrictionAuditFailingGate | hardware-integrity gate Fail, no override |
| warning | SelfdefPerimeterSigkill | sys_execve outside the verbatim allowlist |
| critical | SelfdefPerimeterPolicyMissing | TracingPolicy YAML absent — kernel-fence OFF |
| critical | SelfdefPerimeterChainBroken | OCSF audit chain integrity broken |
| critical | SelfdefGuardianFailedResponse | any 3-step response step Failed |
| warning | SelfdefGuardianTetragonSocketMissing | Guardian can't ingest events |
| critical | SelfdefGuardianChainBroken | OCSF audit chain integrity broken |
| warning | SelfdefSchedulerSustainedBackpressure | resource pressure sustained 10m |
| critical | SelfdefSchedulerChainBroken | scheduler audit chain integrity broken |
| warning | SelfdefStorageMountYellow | MS011 mount used 70-89% sustained 5m |
| critical | SelfdefStorageMountRed | MS011 mount used >=90% sustained 1m |

### M060 cross-repo mirror-export loop

| Severity | Alert | Triggers when |
|---|---|---|
| warning | SelfdefM060PublishFailing | any artifact has a failed publish in last 5m |
| warning | SelfdefM060PublishStale | per-artifact: last publish > 10 min ago |
| critical | SelfdefM060PublishWedged | per-artifact: > 5 failures in 30m (persistent) |

### SDD-062 detection-watchdog routed findings

| Severity | Alert | Triggers when |
|---|---|---|
| warning | SelfdefWatchdogAlertFinding | a host watchdog emitted an alert-tier finding in 10m |

### Meta-observability (F-2026-084)

| Severity | Alert | Triggers when |
|---|---|---|
| warning | SelfdefMetricsIngestLag | `selfdef_ingest_lag_events_total` rises in 10m — the metrics-ingest subscriber dropped bus events, so `/metrics` under-counts and the counter-based alerts above may not fire for events in a dropped batch |
| warning | SelfdefCorrelatorBusLag | `selfdef_correlator_lag_events_total` rises in 10m — the correlator subscriber dropped raw events, so they were never rule-evaluated and produced no finding at all (a detection gap, not just a metrics gap) |
| warning | SelfdefResponderBusLag | `selfdef_responder_lag_events_total` rises in 10m — the responder subscriber dropped findings, so no autonomous block/quarantine/notify action fired for them (a response gap) |

The ingest-lag alert watches the observability path itself: detection still
happens (correlator + responder subscribe to the bus independently), but the
counters degrade. The correlator- and responder-lag alerts are stronger: when
those subscribers lag, the bus overflow degrades the *defense* — raw events
bypass detection entirely (correlator) or findings fire no response
(responder). All three share the `[bus] inproc_capacity` overflow mechanism.
Runbooks: `wiki/runbooks/metrics-ingest-lag.md`,
`wiki/runbooks/metrics-correlator-lag.md`,
`wiki/runbooks/metrics-responder-lag.md`.

Every alert carries `runbook_url` pointing at the matching
remediation procedure. The four-watchdog + detection-watchdog + the
meta-observability ingest-lag alerts link to the operator runbooks
under `~/devops-solutions-information-hub/wiki/runbooks/` (the IPS
spine's runbook set). The M060
alerts link to
`https://github.com/cyberpunk042/sovereign-os/blob/main/docs/operator/m060-deployment-guide.md#troubleshooting`
where each M060 alert has a dedicated `####` runbook section
(diagnosis + fix). Operators using ntfy/pagerduty/signal as
Alertmanager receivers get clickable links into the exact remediation.

The Grafana dashboard ships a matching "M060 cross-repo mirror export"
row with 6 panels visualizing the per-artifact publish counters +
last-publish-time gauges that back the M060 alerts. See
`assets/dashboards/selfdef.json.template` panels 120-126.

Deployment is automatic: `apply.sh` renders + installs the alert
rules alongside the scrape config + Grafana dashboard. In the
`bundled` profile they land at `/etc/prometheus/rules.d/selfdef.yml`
(or operator-supplied `prometheus_rules_dir`); in `external` mode
they land in the staging dir under `prometheus/rules/`.

## What's NOT here yet

- Loki / OpenTelemetry traces. Out of scope for v0.1 — selfdef's
  hot path is structured events, not generic logs/traces.
- Alert receiver wiring (Alertmanager → ntfy/pagerduty/signal).
  Operator-owned; the `selfdef-integration-*` notifier integrations
  (ntfy / signal / pagerduty / etc) are independent of Prometheus
  alerting — operators choose their alert delivery path.

## Phase

Ships in `phase = "post"` so every other module's metrics endpoint
is up when Prometheus picks up the new scrape job. Cross-phase
dependency on `tetragon` (which is `pre`) is allowed because deps
to earlier phases are always valid.

## Uninstall

`selfdefctl modules uninstall --confirm <hostname> --only observability`
removes the rendered files. Prometheus + Grafana themselves are not
touched — the operator runs them, the operator removes them.
