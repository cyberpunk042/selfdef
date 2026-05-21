# SDD-034 — Observability module + four-watchdog dashboards/alerts — MS027

> Status: **draft** — Stage-2 architectural spec retrofitted for the
> shipped `observability` module under `modules/observability/`. The
> module has been EXPANDED beyond its catalog baseline this cycle —
> the original 7-panel + scrape-only contract grew to 20 panels +
> 9 Prometheus alert rules + a runbook-URL ↔ info-hub coherence gate.
> This SDD canonicalizes both the baseline + the expansion.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS027 (catalog `backlog/milestones/MS027-observability-module.md`)
> Builds on: SDD-032 (eBPF substrate — Tetragon metrics endpoint
> consumer) + SDD-027 / SDD-028 / SDD-029 / SDD-031 (four-watchdog
> set — emits the `selfdef_*` series the dashboard + alert rules
> consume)
> Companions: L2 bats suite at `packaging/test/L2-observability.bats`
> (26 tests including dry-run + idempotency smoke), L1 gate at
> `scripts/test/L1-prometheus-alerts.sh` (16 gates including the
> runbook-URL-target-existence check Gate 3b).

## Problem

The four-watchdog set + Tetragon + selfdef-daemon all emit Prometheus
metrics, but operators need:
- A canonical scrape config the daemon ships with (no operator-side
  authoring of scrape YAML)
- A pre-built Grafana dashboard that aggregates the four-watchdog
  signals + Tetragon kernel telemetry + selfdef hot-store stats into
  one screen
- Prometheus alert rules that fire on the documented failure modes
  with `runbook_url` annotations linking directly to the operator
  runbook covering that incident class
- A way to ship this in both "bundled" mode (Prometheus + Grafana on
  the same workstation) and "external" mode (Prometheus + Grafana
  managed centrally / in k8s)

Without this module, operators have to author scrape jobs, write
dashboards, and discover failure runbooks by hand — which means
they don't, and the four-watchdog set ships invisible to anyone who
doesn't read the source.

## Operator directive — verbatim (sacrosanct)

> "there is over 20 dashboards and a main one and everything can be
>  turned on and off and there are also a tons of modes and profiles."

> "when I say UX I obviously mean UX and not some internal AI UX
>  checklist.... NO random trash please... you cannot re-invent
>  what UX mean... obviously i expect dashboards and a good UX"

Translation for MS027: the dashboard + scrape config + alert rules
must be SHIPPED + the operator's profile choice (bundled vs external)
must drive different deployment paths + every alert must link to a
runbook the operator can follow without leaving the Prometheus UI.

## Module inventory (shipped, as of 2026-05-21)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/observability/module.toml` | depends_on=[tetragon], provides=[selfdef-dashboards], consumes=[metrics-endpoint], install.kind=script, profiles=[bundled, external] |
| Profile defaults (bundled) | `modules/observability/profiles/bundled.toml` | Prometheus + Grafana on same host via systemd |
| Profile defaults (external) | `modules/observability/profiles/external.toml` | Renders to `staging_dir`; no services touched |
| Apply | `modules/observability/install/apply.sh` | Renders scrape + dashboard + alert rules; reloads Prometheus when bundled |
| Check | `modules/observability/install/check.sh` | Read-only verifier; emits status JSON |
| Uninstall | `modules/observability/install/uninstall.sh` | Manifest-walked tear-down; does NOT touch Prometheus/Grafana services |
| Helper lib | `modules/observability/install/lib.sh` | Shared+local TOML readers + emitters |
| Scrape template | `modules/observability/assets/scrape/selfdef.yml.template` | Prometheus job targeting Tetragon + selfdef-daemon /metrics |
| Dashboard template | `modules/observability/assets/dashboards/selfdef.json.template` | 20 panels (7 baseline + 9 four-watchdog + 2 modules + 2 rows) |
| Alert rules template | `modules/observability/assets/alerts/selfdef.yml.template` | 9 Prometheus alerts with `runbook_url` → info-hub `wiki/runbooks/` |
| L2 tests | `packaging/test/L2-observability.bats` | 26 tests (module shape + apply.sh contract + dry-run smoke + idempotency + malformed-profile rejection) |
| L1 gate | `scripts/test/L1-prometheus-alerts.sh` | 16 gates including runbook-URL-target-existence check |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Two-profile contract

| Profile | Deployment target | What apply.sh writes | Service reload |
|---|---|---|---|
| `bundled` | Prometheus + Grafana on this host under systemd | `/etc/prometheus/conf.d/selfdef.yml` + `/etc/prometheus/rules.d/selfdef.yml` + `/var/lib/grafana/dashboards/selfdef/selfdef.json` | `systemctl reload prometheus.service` (Grafana auto-discovers dashboard) |
| `external` | Prometheus + Grafana run elsewhere | `${staging_dir}/prometheus/selfdef.yml` + `${staging_dir}/prometheus/rules/selfdef.yml` + `${staging_dir}/grafana/selfdef.json` | None (operator syncs out manually) |

Both profiles use the SAME 3 asset templates. The difference is the
destination dir + whether `systemctl reload` runs at the end.

### Deliverable 2 — 20-panel Grafana dashboard

The baseline shipped 7 panels (4 Tetragon + 3 selfdef-daemon).
This cycle expanded to **20 panels total**:

| Panel band | Count | What it visualizes |
|---|---|---|
| Tetragon kernel telemetry (M10 baseline) | 4 | Events/second, kills by policy, process cache utilization, map operation errors |
| selfdef-daemon hot-store + event flow | 3 | Events/sec by class, findings/sec by severity, hot-store size |
| MS046 friction-audit | 2 | Failing gates total, gate-result distribution |
| MS047 perimeter | 3 | Sigkills total, policy present, audit chain events |
| MS044 guardian | 2 | Failed responses, audit chain events |
| MS048 scheduler | 2 | Backpressured decisions, audit chain events |
| MS006 modules | 2 | Modules shipped total, modules active total |
| Rows (section dividers) | 2 | "Four-watchdog set" and "Modules" |

The L1 gate `scripts/test/L1-grafana-template.sh` asserts ≥ 20 panels
+ every four-watchdog series referenced.

### Deliverable 3 — 9-alert Prometheus rule set

Every alert carries `summary` + `description` + `runbook_url`
annotations. The `runbook_url` points to a real file in the info-hub
`wiki/runbooks/` tree. The L1 gate
`scripts/test/L1-prometheus-alerts.sh` Gate 3 + Gate 3b enforces
both URL-pattern AND target-file existence (when info-hub clone
available locally or in CI).

| Alert | Severity | Watchdog | Series | Runbook |
|---|---|---|---|---|
| SelfdefFrictionAuditFailingGate | critical | friction-audit | `selfdef_friction_audit_failing_total` | `friction-audit-pcie.md` |
| SelfdefPerimeterSigkill | warning | perimeter | `selfdef_perimeter_sigkills_total` | `perimeter-sigkill-investigation.md` |
| SelfdefPerimeterPolicyMissing | critical | perimeter | `selfdef_perimeter_policy_present` | `perimeter-policy-load-failure.md` |
| SelfdefPerimeterChainBroken | critical | perimeter | `selfdef_perimeter_audit_chain_events == -1` | `perimeter-audit-log-corruption.md` |
| SelfdefGuardianFailedResponse | critical | guardian | `selfdef_guardian_failed_responses_total` | `guardian-console-alert-investigation.md` |
| SelfdefGuardianTetragonSocketMissing | warning | guardian | `selfdef_guardian_tetragon_socket_present` | `guardian-socket-unreachable.md` |
| SelfdefGuardianChainBroken | critical | guardian | `selfdef_guardian_audit_chain_events == -1` | `guardian-audit-log-corruption.md` |
| SelfdefSchedulerSustainedBackpressure | warning | scheduler | `selfdef_scheduler_backpressured_decisions_total` | `scheduler-backpressure-stuck-open.md` |
| SelfdefSchedulerChainBroken | critical | scheduler | `selfdef_scheduler_audit_chain_events == -1` | `scheduler-audit-log-corruption.md` |

### Deliverable 4 — Scrape config covers both endpoints

Default `scrape_targets = "localhost:2112, localhost:8443"`:
- `localhost:2112` — Tetragon's built-in Prometheus exporter
- `localhost:8443` — selfdef-daemon `/metrics` endpoint

The daemon endpoint is auth-gated. For UNIX-socket Prometheus
deployments (Prometheus on same host), no token. For TCP, a bearer
token from `/etc/selfdef/api.token` must be configured. See SDD-002
+ `docs/src/ops/api.md` § "Scraping the daemon" for the full
operator config.

### Deliverable 5 — Out-of-scope (honest deferrals)

The catalog row E0279 explicitly defers:
- Alert rules (now shipped this cycle — D3 above)
- Loki / OpenTelemetry traces (still deferred — "Out of scope for
  v0.1 — selfdef's hot path is structured events, not generic
  logs/traces")

Operator-facing extension pattern: edit
`assets/dashboards/selfdef.json.template` (or `assets/alerts/`,
`assets/scrape/`) and re-run `selfdefctl modules apply --only
observability`. Templates are rendered each time so checked-in
edits propagate.

## Production-readiness gates

| Gate | Verification |
|---|---|
| All 3 templates parse cleanly | L2 bats tests 18, 19, 20 |
| Dashboard carries ≥ 20 panels | L2 bats test 23 |
| Alert template carries ≥ 9 rules | L2 bats test 21 |
| Every alert has info-hub `runbook_url` | L2 bats test 22 + L1 Gate 3 |
| Every alert `runbook_url` target file exists | L1 Gate 3b (when info-hub clone available) |
| Both profiles supported by apply.sh | L2 bats test 9 |
| apply.sh runs cleanly in dry-run mode (bundled) | L2 bats test 24 |
| apply.sh dry-run is idempotent | L2 bats test 25 |
| Malformed profile rejected | L2 bats test 26 |
| Daemon `[collectors.eventstream]` + scrape coverage | E0276 — daemon must be live + scrape must target it |
| L1 gates wired into coherence harness | `make coherence` includes L1-prometheus-alerts + L1-grafana-template |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest declaring tetragon dependency + profiles + provides
   contract
2. ✅ `profiles/bundled.toml` + `profiles/external.toml`
3. ✅ `assets/scrape/selfdef.yml.template`
4. ✅ `assets/dashboards/selfdef.json.template` (started at 7 panels,
   grew to 20)
5. ✅ `install/apply.sh` (2-profile dispatch + 3-asset rendering +
   conditional Prometheus reload)
6. ✅ `install/check.sh` read-only verifier
7. ✅ `install/uninstall.sh` (manifest-walked, services-untouched)
8. ✅ `install/lib.sh` shared+local helpers
9. ✅ `assets/alerts/selfdef.yml.template` (this cycle — 9 alerts
   with runbook_url annotations)
10. ✅ Companion runbooks in info-hub `wiki/runbooks/` (5
    friction-audit + 5 perimeter + 5 guardian + 5 scheduler + 1
    ux-coherence-failures = 21 runbooks)
11. ✅ `L2-observability.bats` (26 tests, all PASS)
12. ✅ `L1-prometheus-alerts.sh` (16 gates including runbook-URL
    target-existence)
13. ✅ `L1-grafana-template.sh` (4 gates including ≥ 20 panels)

## Cross-references

- Four-watchdog set SDDs (the metric sources):
  `docs/sdd/027-friction-audit-system.md`,
  `docs/sdd/028-perimeter-engine.md`,
  `docs/sdd/029-guardian-daemon.md`,
  `docs/sdd/031-goldilocks-scheduler.md`
- eBPF substrate (Tetragon metrics endpoint source):
  `docs/sdd/032-ebpf-substrate-and-tetragon-policy-ledger.md`
- API doc § "Scraping the daemon" + `/metrics`:
  `docs/src/ops/api.md`
- Coherence harness (run on every push / PR / release tag):
  `scripts/test/coherence.sh`, `Makefile` target `make coherence`
- Operator cheatsheet (links the daemon-side daily-driver into
  Grafana + Prometheus contexts): `docs/operator-cheatsheet.md`
- 21 operator runbooks in info-hub: `~/devops-solutions-information-hub/wiki/runbooks/`

## Authorization for Stage-3+ work

This SDD authorizes:

- New panels in `selfdef.json.template` — add panel JSON + bump the
  L1 gate's panel-count threshold (currently ≥ 20)
- New alert rules — add to `selfdef.yml.template` with `runbook_url`
  pointing to an existing info-hub runbook; the L1 gate enforces
  target-file existence
- Loki / OpenTelemetry traces — deferred at the catalog level; would
  require its own Stage-2 SDD
- Module-specific alert sub-pack — e.g. an alert pack scoped to one
  module that gets merged in conditionally based on the operator's
  `[modules.<name>]` activation

Mark a Stage-3+ extension DONE only when the corresponding L1/L2
gates pass + the alert/dashboard is reachable via the deployed
Prometheus / Grafana (operator-side verification).

— End of SDD-034 / MS027 Stage-2.
