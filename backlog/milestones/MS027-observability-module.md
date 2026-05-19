# MS027 — Observability module (selfdef-side)

> Parent: `backlog/milestones/INDEX.md` row MS027 (source ref `modules/observability` + `crates/selfdef-collector-eventstream` + `crates/selfdef-collector-journald`).
> Source: `modules/observability/` (473 lines across README.md, module.toml, profiles/bundled.toml, profiles/external.toml, install/apply.sh, install/check.sh, install/lib.sh, install/uninstall.sh, assets/dashboards/selfdef.json.template, assets/scrape/selfdef.yml.template).
> All entries below extract verbatim. No invention.

## Epics (E0271–E0280)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0271 | Module identity — `observability` v0.1.0, category=observability, summary "Prometheus scrape config + Grafana dashboards for the selfdef stack (Tetragon metrics, module health)"; "Prometheus scrape config + Grafana dashboard for the selfdef stack"; 2 owned outputs: `selfdef.yml` (Prometheus scrape job targeting Tetragon metrics endpoint + any other selfdef-managed endpoint a future module declares) + `selfdef.json` (Grafana dashboard rendering Tetragon event rate, kills-by-policy, process cache utilization, BPF map errors; "Hand-tuned to fit on one screen on a normal desktop"); "This module does NOT install Prometheus or Grafana. They're operator-owned services. The module configures them" | `module.toml` 1–4 + `README.md` 1–12 |
| E0272 | Two profiles — `bundled` (default; Prometheus + Grafana run on this host under systemd; "Drops scrape config under /etc/prometheus/conf.d/ and dashboard JSON under /var/lib/grafana/dashboards/selfdef/. Reloads Prometheus on change. Grafana auto-discovers the dashboard JSON") + `external` (Prometheus + Grafana run elsewhere — central host / managed service / k8s; "Renders the same files into a staging dir for the operator to sync out. No services are touched") | `README.md` 16–22 + `profiles/bundled.toml` 1–33 + `profiles/external.toml` 1–16 |
| E0273 | Config schema — `profile = "bundled"` (or external); Bundled-profile-only: `prometheus_conf_dir = "/etc/prometheus/conf.d"` + `prometheus_service = "prometheus.service"` + `grafana_dashboards_dir = "/var/lib/grafana/dashboards/selfdef"`; External-profile-only: `staging_dir = "/var/lib/selfdef/observability/staging"`; Both profiles: `scrape_targets = "localhost:2112, localhost:8443"` (default covers Tetragon built-in metrics endpoint + selfdef-daemon /metrics endpoint) + `dashboard_uid = "selfdef"` + `dashboard_title = "selfdef — Host Self-Defense"` | `README.md` 26–55 |
| E0274 | Dashboard 7-panel composition — 4 Tetragon panels + 3 selfdef-daemon panels: Tetragon events/second (`rate(tetragon_events_total[5m])`) / Tetragon kills by policy (`rate(tetragon_msg_sigkill_total[5m]) by policy`) / Process cache utilization (`tetragon_process_cache_size`) / Map operation errors (`rate(tetragon_map_errors_total[5m]) by map, op`) / selfdef events/sec by class (`sum by (class_uid) (rate(selfdef_events_by_class_total[5m]))`) / selfdef findings/sec by severity (`sum by (severity_id) (rate(selfdef_findings_by_severity_total[5m]))`) / selfdef hot-store size (`selfdef_store_events`) | `README.md` 59–73 |
| E0275 | Tetragon metric-name pin — 4 Tetragon panels reference upstream Prometheus exporter; queries verified against Tetragon v1.x; canonical source tetragon.io/docs/reference/metrics; "If you run a Tetragon version that renames any of these series (`tetragon_events_total`, `tetragon_msg_sigkill_total`, `tetragon_process_cache_size`, `tetragon_map_errors_total`), the corresponding panel renders flat"; `tetragon` module's `requires` block doesn't pin a Tetragon version range today (F-2026-052 in the audit ledger); Phase-2 follow-up tracked | `README.md` 75–88 |
| E0276 | Daemon-side panels gating — "panels render flat / empty if the `scrape_targets` list doesn't include the daemon's /metrics endpoint (or if the daemon isn't running). Both endpoints are required for full dashboard coverage" | `README.md` 90–94 |
| E0277 | Scraping the daemon — `/metrics` endpoint is auth-gated; UNIX socket transport `/run/selfdef.sock` (no bearer token; gated by filesystem permissions; "Easiest if Prometheus runs on the same host with read access to the socket"); TCP transport `127.0.0.1:8443` (default; every request needs `Authorization: Bearer <token>` matching contents of `[api] token_file` default `/etc/selfdef/api.token`); example scrape_configs yaml with bearer_token_file; "If Prometheus runs as a different user than the daemon, copy the token to a file Prometheus can read at the right mode (typically `0600 prometheus:prometheus`). Don't symlink — the two services should hold their own copies so credential rotation is a deliberate operator action on each side" | `README.md` 96–127 |
| E0278 | Extension — operator extends dashboard by editing `assets/dashboards/selfdef.json.template` and re-running apply; "the file is template-rendered each time so your edits to the checked-in template propagate" | `README.md` 129–132 |
| E0279 | What's NOT here yet — Alert rules ("Grafana's alerting + Prometheus's alertmanager are operator-owned. The dashboard makes the data legible; reacting to it is the notifier chain's job (which integrity-sentinel + detect-host already wire up)") + Loki / OpenTelemetry traces ("Out of scope for v0.1 — selfdef's hot path is structured events, not generic logs/traces") | `README.md` 134–141 |
| E0280 | Module-system invariants — `depends_on = ["tetragon"]` + `conflicts = []` + `provides = ["selfdef-dashboards"]` + `consumes = ["metrics-endpoint"]` + required binary `systemctl` + `instanced = false` + `phase = "post"` ("runs after every other module is configured and any metrics endpoints they expose are up. Prometheus picks up the new scrape config on reload; Grafana auto-loads the dashboard JSON"; "Cross-phase dependency on `tetragon` (which is `pre`) is allowed because deps to earlier phases are always valid"); uninstall — `selfdefctl modules uninstall --confirm <hostname> --only observability` removes rendered files; "Prometheus + Grafana themselves are not touched — the operator runs them, the operator removes them" | `module.toml` 1–30 + `README.md` 143–149 |

## Modules (M00681–M00706)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00681 | `module.toml` — 30-line manifest (depends_on=[tetragon] + provides=selfdef-dashboards + consumes=metrics-endpoint + instanced=false + phase=post) | `module.toml` 1–30 | E0280 |
| M00682 | `README.md` — 145-line operator doc (profiles + config + 7-panel dashboard + auth + extension + scope) | `README.md` 1–145 | E0271 |
| M00683 | `profiles/bundled.toml` — 33-line default profile (Prometheus + Grafana on same host via systemd) | `profiles/bundled.toml` 1–33 | E0272 |
| M00684 | `profiles/external.toml` — 16-line external profile (renders to staging_dir; no services touched) | `profiles/external.toml` 1–16 | E0272 |
| M00685 | `install/apply.sh` — 116-line applier (render scrape + dashboard + reload Prometheus when bundled) | `install/apply.sh` 1–116 | E0272 + E0278 |
| M00686 | `install/check.sh` — 40-line side-effect-free verifier | `install/check.sh` 1–40 | M00685 |
| M00687 | `install/lib.sh` — 72-line shared+local helpers (v2 opt-in) | `install/lib.sh` 1–72 | M00685 |
| M00688 | `install/uninstall.sh` — 78-line manifest-walked tear-down (does NOT touch Prometheus/Grafana services) | `install/uninstall.sh` 1–78 | E0280 |
| M00689 | `assets/dashboards/selfdef.json.template` — 103-line Grafana dashboard JSON template (7 panels) | `assets/dashboards/selfdef.json.template` 1–103 | E0274 |
| M00690 | `assets/scrape/selfdef.yml.template` — 15-line Prometheus scrape config template | `assets/scrape/selfdef.yml.template` 1–15 | E0271 |
| M00691 | Provided surface — `selfdef-dashboards` (the Grafana dashboard + Prometheus scrape pair) | `module.toml` 7 | E0271 |
| M00692 | Consumed surface — `metrics-endpoint` (any module exposing Prometheus-scrapable metrics) | `module.toml` 8 | E0280 |
| M00693 | Required binary — `systemctl` (for prometheus reload in bundled profile) | `module.toml` 11 | E0280 |
| M00694 | Module dependency — depends_on=["tetragon"] (consumes Tetragon metrics endpoint) | `module.toml` 6 | E0280 |
| M00695 | Single-instance — `instanced = false` (host has one observability config) | `module.toml` 13 | E0280 |
| M00696 | Lifecycle phase — `phase = "post"` (runs after every other module's metrics endpoint is up) | `module.toml` 17 | E0280 |
| M00697 | Default profile — `bundled` | `module.toml` 26 | E0272 |
| M00698 | Available profiles — `["bundled", "external"]` | `module.toml` 27 | E0272 |
| M00699 | Dashboard panel — Tetragon events/second (`rate(tetragon_events_total[5m])`) | `README.md` 65 | E0274 |
| M00700 | Dashboard panel — Tetragon kills by policy (`rate(tetragon_msg_sigkill_total[5m]) by policy`) | `README.md` 66 | E0274 |
| M00701 | Dashboard panel — Process cache utilization (`tetragon_process_cache_size`) | `README.md` 67 | E0274 |
| M00702 | Dashboard panel — Map operation errors (`rate(tetragon_map_errors_total[5m]) by map, op`) | `README.md` 68 | E0274 |
| M00703 | Dashboard panel — selfdef events/sec by class (`sum by (class_uid) (rate(selfdef_events_by_class_total[5m]))`) | `README.md` 69 | E0274 |
| M00704 | Dashboard panel — selfdef findings/sec by severity (`sum by (severity_id) (rate(selfdef_findings_by_severity_total[5m]))`) | `README.md` 70 | E0274 |
| M00705 | Dashboard panel — selfdef hot-store size (`selfdef_store_events`) | `README.md` 71 | E0274 |
| M00706 | Auth-gating — UNIX socket transport (`/run/selfdef.sock`; filesystem permissions) OR TCP transport (`127.0.0.1:8443`; Bearer token from `/etc/selfdef/api.token`) | `README.md` 96–127 | E0277 |

## Features (F03121–F03240)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03121 | module.toml `name = "observability"` | `module.toml` 1 | M00681 |
| F03122 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00681 |
| F03123 | module.toml `summary = "Prometheus scrape config + Grafana dashboards for the selfdef stack (Tetragon metrics, module health)"` | `module.toml` 3 | M00681 |
| F03124 | module.toml `category = "observability"` | `module.toml` 4 | M00681 |
| F03125 | module.toml `depends_on = ["tetragon"]` | `module.toml` 6 | M00694 |
| F03126 | module.toml `conflicts = []` | `module.toml` 7 | M00681 |
| F03127 | module.toml `provides = ["selfdef-dashboards"]` | `module.toml` 7 | M00691 |
| F03128 | module.toml `consumes = ["metrics-endpoint"]` | `module.toml` 8 | M00692 |
| F03129 | module.toml `requires` — binary systemctl | `module.toml` 11 | M00693 |
| F03130 | module.toml `instanced = false` | `module.toml` 13 | M00695 |
| F03131 | module.toml `phase = "post"` | `module.toml` 17 | M00696 |
| F03132 | module.toml phase rationale — "runs after every other module is configured and any metrics endpoints they expose are up" | `module.toml` 15–17 | M00696 |
| F03133 | module.toml phase rationale — Prometheus picks up new scrape config on reload | `module.toml` 16 | M00696 |
| F03134 | module.toml phase rationale — Grafana auto-loads the dashboard JSON | `module.toml` 17 | M00696 |
| F03135 | module.toml `[install] kind = "script"` | `module.toml` 19–20 | M00681 |
| F03136 | module.toml apply = "install/apply.sh" | `module.toml` 21 | M00685 |
| F03137 | module.toml check = "install/check.sh" | `module.toml` 22 | M00686 |
| F03138 | module.toml uninstall = "install/uninstall.sh" | `module.toml` 23 | M00688 |
| F03139 | module.toml `[profiles] default = "bundled"` | `module.toml` 25–26 | M00697 |
| F03140 | module.toml `available = ["bundled", "external"]` | `module.toml` 27 | M00698 |
| F03141 | README — Prometheus scrape config + Grafana dashboard for selfdef stack | `README.md` 3 | E0271 |
| F03142 | README — owned output `selfdef.yml` (Prometheus scrape job) | `README.md` 6–8 | M00690 |
| F03143 | README — owned output `selfdef.json` (Grafana dashboard) | `README.md` 9–11 | M00689 |
| F03144 | README — `selfdef.json` renders Tetragon event rate | `README.md` 10 | E0274 |
| F03145 | README — `selfdef.json` renders kills-by-policy | `README.md` 10 | E0274 |
| F03146 | README — `selfdef.json` renders process cache utilization | `README.md` 10–11 | E0274 |
| F03147 | README — `selfdef.json` renders BPF map errors | `README.md` 11 | E0274 |
| F03148 | README — "Hand-tuned to fit on one screen on a normal desktop" | `README.md` 11–12 | E0271 |
| F03149 | README — "This module does NOT install Prometheus or Grafana" | `README.md` 13 | E0271 |
| F03150 | README — "They're operator-owned services. The module configures them" | `README.md` 14 | E0271 |
| F03151 | Profile bundled — Prometheus + Grafana run on this host under systemd | `README.md` 19 | E0272 |
| F03152 | Profile bundled — drops scrape config under /etc/prometheus/conf.d/ | `README.md` 19 | E0272 |
| F03153 | Profile bundled — drops dashboard JSON under /var/lib/grafana/dashboards/selfdef/ | `README.md` 19 | E0272 |
| F03154 | Profile bundled — reloads Prometheus on change | `README.md` 19 | E0272 |
| F03155 | Profile bundled — Grafana auto-discovers the dashboard JSON | `README.md` 19 | E0272 |
| F03156 | Profile external — Prometheus + Grafana run elsewhere (central host / managed service / k8s) | `README.md` 20 | E0272 |
| F03157 | Profile external — renders same files into staging dir for operator sync | `README.md` 20 | E0272 |
| F03158 | Profile external — no services are touched | `README.md` 20 | E0272 |
| F03159 | Config — `profile = "bundled"` (or external) | `README.md` 27 | E0273 |
| F03160 | Config bundled — `prometheus_conf_dir = "/etc/prometheus/conf.d"` | `README.md` 30 | E0273 |
| F03161 | Config bundled — `prometheus_service = "prometheus.service"` | `README.md` 31 | E0273 |
| F03162 | Config bundled — `grafana_dashboards_dir = "/var/lib/grafana/dashboards/selfdef"` | `README.md` 32 | E0273 |
| F03163 | Config external — `staging_dir = "/var/lib/selfdef/observability/staging"` | `README.md` 35 | E0273 |
| F03164 | Config both — `scrape_targets = "localhost:2112, localhost:8443"` | `README.md` 45 | E0273 |
| F03165 | Default target — localhost:2112 (Tetragon's built-in metrics endpoint) | `README.md` 39–40 | E0273 |
| F03166 | Default target — localhost:8443 (selfdef-daemon's /metrics endpoint) | `README.md` 41 | E0273 |
| F03167 | Default target requires `[api] enabled = true` in /etc/selfdef/selfdef.toml | `README.md` 42 | E0277 |
| F03168 | Default target requires `tcp_addr = "127.0.0.1:8443"` in /etc/selfdef/selfdef.toml | `README.md` 42–43 | E0277 |
| F03169 | Default target requires bearer token | `README.md` 43–44 | E0277 |
| F03170 | Config both — `dashboard_uid = "selfdef"` | `README.md` 48 | E0273 |
| F03171 | Config both — `dashboard_title = "selfdef — Host Self-Defense"` | `README.md` 49 | E0273 |
| F03172 | Dashboard panel 1 — Tetragon events / second | `README.md` 65 | M00699 |
| F03173 | Dashboard panel 1 metric — `rate(tetragon_events_total[5m])` | `README.md` 65 | M00699 |
| F03174 | Dashboard panel 2 — Tetragon kills by policy | `README.md` 66 | M00700 |
| F03175 | Dashboard panel 2 metric — `rate(tetragon_msg_sigkill_total[5m]) by policy` | `README.md` 66 | M00700 |
| F03176 | Dashboard panel 3 — Process cache utilization | `README.md` 67 | M00701 |
| F03177 | Dashboard panel 3 metric — `tetragon_process_cache_size` | `README.md` 67 | M00701 |
| F03178 | Dashboard panel 4 — Map operation errors | `README.md` 68 | M00702 |
| F03179 | Dashboard panel 4 metric — `rate(tetragon_map_errors_total[5m]) by map, op` | `README.md` 68 | M00702 |
| F03180 | Dashboard panel 5 — selfdef events / sec by class | `README.md` 69 | M00703 |
| F03181 | Dashboard panel 5 metric — `sum by (class_uid) (rate(selfdef_events_by_class_total[5m]))` | `README.md` 69 | M00703 |
| F03182 | Dashboard panel 6 — selfdef findings / sec by severity | `README.md` 70 | M00704 |
| F03183 | Dashboard panel 6 metric — `sum by (severity_id) (rate(selfdef_findings_by_severity_total[5m]))` | `README.md` 70 | M00704 |
| F03184 | Dashboard panel 7 — selfdef hot-store size | `README.md` 71 | M00705 |
| F03185 | Dashboard panel 7 metric — `selfdef_store_events` | `README.md` 71 | M00705 |
| F03186 | Tetragon metric pin — 4 panels reference upstream Tetragon Prometheus exporter | `README.md` 76 | E0275 |
| F03187 | Tetragon metric pin — verified against Tetragon v1.x | `README.md` 77 | E0275 |
| F03188 | Tetragon metric pin — canonical source tetragon.io/docs/reference/metrics | `README.md` 78 | E0275 |
| F03189 | Tetragon metric pin — renamed series → panel renders flat | `README.md` 80–82 | E0275 |
| F03190 | Tetragon metric pin — F-2026-052 (no version range pinned in tetragon module's requires today) | `README.md` 84–86 | E0275 |
| F03191 | Tetragon metric pin — Phase-2 follow-up tracked | `README.md` 86 | E0275 |
| F03192 | Daemon-side panels gating — render flat/empty if scrape_targets missing daemon /metrics | `README.md` 90–92 | E0276 |
| F03193 | Daemon-side panels gating — render flat/empty if daemon not running | `README.md` 92 | E0276 |
| F03194 | Daemon-side panels gating — "Both endpoints are required for full dashboard coverage" | `README.md` 93–94 | E0276 |
| F03195 | Daemon /metrics — auth-gated | `README.md` 98 | E0277 |
| F03196 | UNIX socket transport — `/run/selfdef.sock` | `README.md` 100 | E0277 |
| F03197 | UNIX socket transport — no bearer token | `README.md` 100 | E0277 |
| F03198 | UNIX socket transport — gated by filesystem permissions | `README.md` 100–101 | E0277 |
| F03199 | UNIX socket transport — easiest if Prometheus same host with socket read access | `README.md` 101–102 | E0277 |
| F03200 | TCP transport — `127.0.0.1:8443` (or `[api] tcp_addr`) | `README.md` 103 | E0277 |
| F03201 | TCP transport — Authorization: Bearer <token> header required on every request | `README.md` 104–105 | E0277 |
| F03202 | TCP transport — token matches `[api] token_file` default `/etc/selfdef/api.token` | `README.md` 105–106 | E0277 |
| F03203 | Scrape config example — job_name: "selfdef-daemon" | `README.md` 111 | E0277 |
| F03204 | Scrape config example — scrape_interval: 15s | `README.md` 112 | E0277 |
| F03205 | Scrape config example — metrics_path: /metrics | `README.md` 113 | E0277 |
| F03206 | Scrape config example — bearer_token_file: /etc/selfdef/api.token | `README.md` 114 | E0277 |
| F03207 | Scrape config example — static_configs targets: ["localhost:8443"] | `README.md` 115–116 | E0277 |
| F03208 | Token-rotation guidance — "If Prometheus runs as a different user than the daemon, copy the token to a file Prometheus can read at the right mode" | `README.md` 119–121 | E0277 |
| F03209 | Token-rotation guidance — typically `0600 prometheus:prometheus` | `README.md` 121 | E0277 |
| F03210 | Token-rotation guidance — "Don't symlink" | `README.md` 122 | E0277 |
| F03211 | Token-rotation guidance — "two services should hold their own copies so credential rotation is a deliberate operator action on each side" | `README.md` 122–124 | E0277 |
| F03212 | Extension — edit `assets/dashboards/selfdef.json.template` and re-run apply | `README.md` 128–129 | E0278 |
| F03213 | Extension — "the file is template-rendered each time so your edits to the checked-in template propagate" | `README.md` 131–132 | E0278 |
| F03214 | NOT here yet — Alert rules (Grafana alerting + Prometheus alertmanager are operator-owned) | `README.md` 136–138 | E0279 |
| F03215 | NOT here yet — "dashboard makes the data legible; reacting to it is the notifier chain's job" | `README.md` 138–139 | E0279 |
| F03216 | NOT here yet — notifier chain wired by integrity-sentinel + detect-host | `README.md` 139 | E0279 |
| F03217 | NOT here yet — Loki / OpenTelemetry traces | `README.md` 140 | E0279 |
| F03218 | NOT here yet — "Out of scope for v0.1 — selfdef's hot path is structured events, not generic logs/traces" | `README.md` 140–141 | E0279 |
| F03219 | Phase=post — ships post so every other module's metrics endpoint is up | `README.md` 143–145 | M00696 |
| F03220 | Phase=post — cross-phase dependency on tetragon (pre) allowed | `README.md` 145–147 | M00696 |
| F03221 | Phase=post — "deps to earlier phases are always valid" | `README.md` 147 | M00696 |
| F03222 | Uninstall — `selfdefctl modules uninstall --confirm <hostname> --only observability` | `README.md` 149 | E0280 |
| F03223 | Uninstall — removes rendered files | `README.md` 149 | E0280 |
| F03224 | Uninstall — "Prometheus + Grafana themselves are not touched" | `README.md` 150–151 | E0280 |
| F03225 | Uninstall — "the operator runs them, the operator removes them" | `README.md` 151 | E0280 |
| F03226 | Bundled profile config — full default (33-line file) | `profiles/bundled.toml` 1–33 | M00683 |
| F03227 | External profile config — full default (16-line file) | `profiles/external.toml` 1–16 | M00684 |
| F03228 | Dashboard JSON template — 103-line Grafana JSON with 7 panels | `assets/dashboards/selfdef.json.template` 1–103 | M00689 |
| F03229 | Scrape config template — 15-line Prometheus scrape job | `assets/scrape/selfdef.yml.template` 1–15 | M00690 |
| F03230 | apply.sh — 116-line idempotent applier | `install/apply.sh` 1–116 | M00685 |
| F03231 | check.sh — 40-line side-effect-free verifier | `install/check.sh` 1–40 | M00686 |
| F03232 | lib.sh — 72-line v2-opt-in helper loader | `install/lib.sh` 1–72 | M00687 |
| F03233 | uninstall.sh — 78-line manifest-walked tear-down | `install/uninstall.sh` 1–78 | M00688 |
| F03234 | Cross-module — depends on MS016 tetragon module's metrics endpoint | `module.toml` 6 + cross-ref MS016 | M00694 |
| F03235 | Cross-module — consumes MS025 detect-host's api component /metrics endpoint | `README.md` 41–44 + cross-ref MS025 | M00692 |
| F03236 | Cross-module — extends MS006 14-functional-modules catalog (observability is one of 14) | `module.toml` 1 + cross-ref MS006 | M00681 |
| F03237 | Cross-module — F-2026-052 finding from selfdef SDD ledger (MS013 27-SDD charter) | `README.md` 84–86 | E0275 |
| F03238 | Cross-module — module-script lib v2 (MS021) provides shared helpers | `install/lib.sh` 1–14 + cross-ref MS021 | M00687 |
| F03239 | Cross-module — MS020 L1-L5 test harness covers Module-script category for apply/check/uninstall | cross-ref MS020 | M00685 + M00686 + M00688 |
| F03240 | Cross-module — `selfdef-collector-eventstream` + `selfdef-collector-journald` crates publish event metrics consumed by the dashboard | cross-ref `crates/selfdef-collector-eventstream` + `crates/selfdef-collector-journald` + INDEX MS027 | E0274 |

## Requirements (R06241–R06480)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R06241 | Module name MUST be `observability` | `module.toml` 1 | F03121 | non-negotiable | false | 10 |
| R06242 | Module version MUST be 0.1.0 | `module.toml` 2 | F03122 | non-negotiable | false | 10 |
| R06243 | Module summary MUST be "Prometheus scrape config + Grafana dashboards for the selfdef stack (Tetragon metrics, module health)" | `module.toml` 3 | F03123 | non-negotiable | false | 10 |
| R06244 | Module category MUST be `observability` | `module.toml` 4 | F03124 | non-negotiable | false | 10 |
| R06245 | depends_on = ["tetragon"] | `module.toml` 6 | F03125 | non-negotiable | false | 10 |
| R06246 | conflicts = [] | `module.toml` 7 | F03126 | non-negotiable | false | 10 |
| R06247 | provides = ["selfdef-dashboards"] | `module.toml` 7 | F03127 | non-negotiable | false | 10 |
| R06248 | consumes = ["metrics-endpoint"] | `module.toml` 8 | F03128 | non-negotiable | false | 10 |
| R06249 | Required binary — systemctl | `module.toml` 11 | F03129 | non-negotiable | false | 10 |
| R06250 | instanced = false | `module.toml` 13 | F03130 | non-negotiable | false | 10 |
| R06251 | phase = "post" | `module.toml` 17 | F03131 | non-negotiable | false | 10 |
| R06252 | phase=post — runs after every other module is configured | `module.toml` 15 | F03132 | non-negotiable | false | 10 |
| R06253 | phase=post — runs after any metrics endpoints are up | `module.toml` 16 | F03132 | non-negotiable | false | 10 |
| R06254 | phase=post — Prometheus picks up new scrape config on reload | `module.toml` 16 | F03133 | non-negotiable | false | 10 |
| R06255 | phase=post — Grafana auto-loads dashboard JSON | `module.toml` 17 | F03134 | non-negotiable | false | 10 |
| R06256 | [install] kind = "script" | `module.toml` 20 | F03135 | non-negotiable | false | 10 |
| R06257 | apply = "install/apply.sh" | `module.toml` 21 | F03136 | non-negotiable | false | 10 |
| R06258 | check = "install/check.sh" | `module.toml` 22 | F03137 | non-negotiable | false | 10 |
| R06259 | uninstall = "install/uninstall.sh" | `module.toml` 23 | F03138 | non-negotiable | false | 10 |
| R06260 | [profiles] default = "bundled" | `module.toml` 26 | F03139 | non-negotiable | false | 10 |
| R06261 | [profiles] available = ["bundled", "external"] | `module.toml` 27 | F03140 | non-negotiable | false | 10 |
| R06262 | README — Prometheus scrape config + Grafana dashboard for selfdef stack | `README.md` 3 | F03141 | non-negotiable | false | 10 |
| R06263 | Owned output — selfdef.yml (Prometheus scrape job) | `README.md` 6 | F03142 | non-negotiable | false | 10 |
| R06264 | selfdef.yml targets Tetragon metrics endpoint | `README.md` 6–7 | F03142 | non-negotiable | false | 10 |
| R06265 | selfdef.yml may target future selfdef-managed endpoint declared by another module | `README.md` 7–8 | F03142 | non-negotiable | false | 10 |
| R06266 | Owned output — selfdef.json (Grafana dashboard) | `README.md` 9 | F03143 | non-negotiable | false | 10 |
| R06267 | selfdef.json renders Tetragon event rate | `README.md` 10 | F03144 | non-negotiable | false | 10 |
| R06268 | selfdef.json renders kills-by-policy | `README.md` 10 | F03145 | non-negotiable | false | 10 |
| R06269 | selfdef.json renders process cache utilization | `README.md` 11 | F03146 | non-negotiable | false | 10 |
| R06270 | selfdef.json renders BPF map errors | `README.md` 11 | F03147 | non-negotiable | false | 10 |
| R06271 | selfdef.json hand-tuned to fit on one screen on a normal desktop | `README.md` 11–12 | F03148 | non-negotiable | false | 10 |
| R06272 | Module does NOT install Prometheus | `README.md` 13 | F03149 | non-negotiable | false | 10 |
| R06273 | Module does NOT install Grafana | `README.md` 13 | F03149 | non-negotiable | false | 10 |
| R06274 | Prometheus and Grafana are operator-owned services | `README.md` 13–14 | F03150 | non-negotiable | false | 10 |
| R06275 | Module configures Prometheus and Grafana | `README.md` 14 | F03150 | non-negotiable | false | 10 |
| R06276 | Profile bundled — Prometheus + Grafana run on this host under systemd | `README.md` 19 | F03151 | non-negotiable | false | 10 |
| R06277 | Profile bundled — drops scrape config under /etc/prometheus/conf.d/ | `README.md` 19 | F03152 | non-negotiable | false | 10 |
| R06278 | Profile bundled — drops dashboard JSON under /var/lib/grafana/dashboards/selfdef/ | `README.md` 19 | F03153 | non-negotiable | false | 10 |
| R06279 | Profile bundled — reloads Prometheus on change | `README.md` 19 | F03154 | non-negotiable | false | 10 |
| R06280 | Profile bundled — Grafana auto-discovers dashboard JSON | `README.md` 19 | F03155 | non-negotiable | false | 10 |
| R06281 | Profile external — Prometheus + Grafana run elsewhere | `README.md` 20 | F03156 | non-negotiable | false | 10 |
| R06282 | Profile external — central host / managed service / k8s | `README.md` 20 | F03156 | non-negotiable | false | 10 |
| R06283 | Profile external — renders same files into staging dir | `README.md` 20 | F03157 | non-negotiable | false | 10 |
| R06284 | Profile external — operator-driven sync out | `README.md` 20 | F03157 | non-negotiable | false | 10 |
| R06285 | Profile external — no services touched | `README.md` 20 | F03158 | non-negotiable | false | 10 |
| R06286 | Config — `profile = "bundled"` (or external) | `README.md` 27 | F03159 | non-negotiable | false | 10 |
| R06287 | Config bundled — prometheus_conf_dir default /etc/prometheus/conf.d | `README.md` 30 | F03160 | non-negotiable | false | 10 |
| R06288 | Config bundled — prometheus_service default prometheus.service | `README.md` 31 | F03161 | non-negotiable | false | 10 |
| R06289 | Config bundled — grafana_dashboards_dir default /var/lib/grafana/dashboards/selfdef | `README.md` 32 | F03162 | non-negotiable | false | 10 |
| R06290 | Config external — staging_dir default /var/lib/selfdef/observability/staging | `README.md` 35 | F03163 | non-negotiable | false | 10 |
| R06291 | Config — scrape_targets default "localhost:2112, localhost:8443" | `README.md` 45 | F03164 | non-negotiable | false | 10 |
| R06292 | Default target — localhost:2112 = Tetragon built-in metrics | `README.md` 39 | F03165 | non-negotiable | false | 10 |
| R06293 | Default target — localhost:2112 comes from tetragon module default profile | `README.md` 40 | F03165 | non-negotiable | false | 10 |
| R06294 | Default target — localhost:8443 = selfdef-daemon /metrics | `README.md` 41 | F03166 | non-negotiable | false | 10 |
| R06295 | Default target — requires `[api] enabled = true` in /etc/selfdef/selfdef.toml | `README.md` 42 | F03167 | non-negotiable | false | 10 |
| R06296 | Default target — requires `tcp_addr = "127.0.0.1:8443"` in /etc/selfdef/selfdef.toml | `README.md` 42–43 | F03168 | non-negotiable | false | 10 |
| R06297 | Default target — requires bearer token | `README.md` 43–44 | F03169 | non-negotiable | false | 10 |
| R06298 | Config — dashboard_uid default "selfdef" | `README.md` 48 | F03170 | non-negotiable | false | 10 |
| R06299 | Config — dashboard_title default "selfdef — Host Self-Defense" | `README.md` 49 | F03171 | non-negotiable | false | 10 |
| R06300 | Dashboard panel — Tetragon events / second | `README.md` 65 | F03172 | non-negotiable | false | 10 |
| R06301 | Dashboard panel — Tetragon events metric `rate(tetragon_events_total[5m])` | `README.md` 65 | F03173 | non-negotiable | false | 10 |
| R06302 | Dashboard panel — Tetragon kills by policy | `README.md` 66 | F03174 | non-negotiable | false | 10 |
| R06303 | Dashboard panel — kills metric `rate(tetragon_msg_sigkill_total[5m]) by policy` | `README.md` 66 | F03175 | non-negotiable | false | 10 |
| R06304 | Dashboard panel — Process cache utilization | `README.md` 67 | F03176 | non-negotiable | false | 10 |
| R06305 | Dashboard panel — cache metric `tetragon_process_cache_size` | `README.md` 67 | F03177 | non-negotiable | false | 10 |
| R06306 | Dashboard panel — Map operation errors | `README.md` 68 | F03178 | non-negotiable | false | 10 |
| R06307 | Dashboard panel — map-errors metric `rate(tetragon_map_errors_total[5m]) by map, op` | `README.md` 68 | F03179 | non-negotiable | false | 10 |
| R06308 | Dashboard panel — selfdef events / sec by class | `README.md` 69 | F03180 | non-negotiable | false | 10 |
| R06309 | Dashboard panel — events-by-class metric `sum by (class_uid) (rate(selfdef_events_by_class_total[5m]))` | `README.md` 69 | F03181 | non-negotiable | false | 10 |
| R06310 | Dashboard panel — selfdef findings / sec by severity | `README.md` 70 | F03182 | non-negotiable | false | 10 |
| R06311 | Dashboard panel — findings-by-severity metric `sum by (severity_id) (rate(selfdef_findings_by_severity_total[5m]))` | `README.md` 70 | F03183 | non-negotiable | false | 10 |
| R06312 | Dashboard panel — selfdef hot-store size | `README.md` 71 | F03184 | non-negotiable | false | 10 |
| R06313 | Dashboard panel — hot-store metric `selfdef_store_events` | `README.md` 71 | F03185 | non-negotiable | false | 10 |
| R06314 | Tetragon metric pin — 4 panels reference upstream Tetragon Prometheus exporter | `README.md` 76 | F03186 | non-negotiable | false | 10 |
| R06315 | Tetragon metric pin — queries verified against Tetragon v1.x | `README.md` 77 | F03187 | non-negotiable | false | 10 |
| R06316 | Tetragon metric pin — canonical source tetragon.io/docs/reference/metrics | `README.md` 78 | F03188 | non-negotiable | false | 10 |
| R06317 | Tetragon metric — `tetragon_events_total` series name | `README.md` 81 | E0275 | non-negotiable | false | 10 |
| R06318 | Tetragon metric — `tetragon_msg_sigkill_total` series name | `README.md` 81 | E0275 | non-negotiable | false | 10 |
| R06319 | Tetragon metric — `tetragon_process_cache_size` series name | `README.md` 82 | E0275 | non-negotiable | false | 10 |
| R06320 | Tetragon metric — `tetragon_map_errors_total` series name | `README.md` 82 | E0275 | non-negotiable | false | 10 |
| R06321 | Tetragon metric pin — renamed series → panel renders flat | `README.md` 80–82 | F03189 | non-negotiable | false | 10 |
| R06322 | Tetragon metric pin — no version range pinned in tetragon module's requires today | `README.md` 84 | F03190 | non-negotiable | false | 10 |
| R06323 | Tetragon metric pin — F-2026-052 in audit ledger | `README.md` 85 | F03190 | non-negotiable | false | 10 |
| R06324 | Tetragon metric pin — Phase-2 follow-up tracked | `README.md` 86 | F03191 | non-negotiable | false | 10 |
| R06325 | Daemon-side gating — daemon panels render flat/empty if scrape_targets missing daemon /metrics | `README.md` 90–92 | F03192 | non-negotiable | false | 10 |
| R06326 | Daemon-side gating — daemon panels render flat/empty if daemon not running | `README.md` 92 | F03193 | non-negotiable | false | 10 |
| R06327 | Daemon-side gating — both endpoints required for full dashboard coverage | `README.md` 93–94 | F03194 | non-negotiable | false | 10 |
| R06328 | Daemon /metrics endpoint — auth-gated | `README.md` 98 | F03195 | non-negotiable | false | 10 |
| R06329 | UNIX socket transport — path /run/selfdef.sock | `README.md` 100 | F03196 | non-negotiable | false | 10 |
| R06330 | UNIX socket transport — no bearer token | `README.md` 100 | F03197 | non-negotiable | false | 10 |
| R06331 | UNIX socket transport — gated by filesystem permissions | `README.md` 100–101 | F03198 | non-negotiable | false | 10 |
| R06332 | UNIX socket transport — easiest when Prometheus same host | `README.md` 101–102 | F03199 | non-negotiable | false | 10 |
| R06333 | UNIX socket transport — read access to socket required | `README.md` 102 | F03199 | non-negotiable | false | 10 |
| R06334 | TCP transport — 127.0.0.1:8443 (default) | `README.md` 103 | F03200 | non-negotiable | false | 10 |
| R06335 | TCP transport — or wherever `[api] tcp_addr` binds | `README.md` 103 | F03200 | non-negotiable | false | 10 |
| R06336 | TCP transport — every request needs Authorization: Bearer <token> | `README.md` 104 | F03201 | non-negotiable | false | 10 |
| R06337 | TCP transport — token matches contents of `[api] token_file` | `README.md` 105 | F03202 | non-negotiable | false | 10 |
| R06338 | TCP transport — token_file default /etc/selfdef/api.token | `README.md` 105–106 | F03202 | non-negotiable | false | 10 |
| R06339 | Scrape config example — job_name "selfdef-daemon" | `README.md` 111 | F03203 | non-negotiable | false | 10 |
| R06340 | Scrape config example — scrape_interval 15s | `README.md` 112 | F03204 | non-negotiable | false | 10 |
| R06341 | Scrape config example — metrics_path /metrics | `README.md` 113 | F03205 | non-negotiable | false | 10 |
| R06342 | Scrape config example — bearer_token_file /etc/selfdef/api.token | `README.md` 114 | F03206 | non-negotiable | false | 10 |
| R06343 | Scrape config example — static_configs targets ["localhost:8443"] | `README.md` 115–116 | F03207 | non-negotiable | false | 10 |
| R06344 | Token rotation — if Prometheus runs as different user than daemon | `README.md` 119 | F03208 | non-negotiable | false | 10 |
| R06345 | Token rotation — copy token to file Prometheus can read at right mode | `README.md` 119–120 | F03208 | non-negotiable | false | 10 |
| R06346 | Token rotation — typically `0600 prometheus:prometheus` | `README.md` 121 | F03209 | non-negotiable | false | 10 |
| R06347 | Token rotation — "Don't symlink" | `README.md` 122 | F03210 | non-negotiable | false | 10 |
| R06348 | Token rotation — two services should hold their own copies | `README.md` 122 | F03211 | non-negotiable | false | 10 |
| R06349 | Token rotation — credential rotation deliberate operator action on each side | `README.md` 122–124 | F03211 | non-negotiable | false | 10 |
| R06350 | Extension — edit assets/dashboards/selfdef.json.template and re-run apply | `README.md` 128–129 | F03212 | non-negotiable | false | 10 |
| R06351 | Extension — file is template-rendered each time | `README.md` 131 | F03213 | non-negotiable | false | 10 |
| R06352 | Extension — edits to checked-in template propagate | `README.md` 131–132 | F03213 | non-negotiable | false | 10 |
| R06353 | NOT here yet — Alert rules | `README.md` 136 | F03214 | non-negotiable | false | 10 |
| R06354 | NOT here yet — Grafana alerting operator-owned | `README.md` 136–137 | F03214 | non-negotiable | false | 10 |
| R06355 | NOT here yet — Prometheus alertmanager operator-owned | `README.md` 137 | F03214 | non-negotiable | false | 10 |
| R06356 | "Dashboard makes the data legible; reacting to it is the notifier chain's job" | `README.md` 138–139 | F03215 | non-negotiable | false | 10 |
| R06357 | Notifier chain wired by integrity-sentinel + detect-host | `README.md` 139 | F03216 | non-negotiable | false | 10 |
| R06358 | NOT here yet — Loki / OpenTelemetry traces | `README.md` 140 | F03217 | non-negotiable | false | 10 |
| R06359 | NOT here yet — Out of scope for v0.1 | `README.md` 140 | F03218 | non-negotiable | false | 10 |
| R06360 | NOT here yet — selfdef's hot path is structured events not generic logs/traces | `README.md` 140–141 | F03218 | non-negotiable | false | 10 |
| R06361 | Phase — ships in phase=post | `README.md` 143 | F03219 | non-negotiable | false | 10 |
| R06362 | Phase rationale — every other module's metrics endpoint is up when Prometheus picks up new scrape job | `README.md` 143–145 | F03219 | non-negotiable | false | 10 |
| R06363 | Phase — cross-phase dependency on tetragon (which is pre) is allowed | `README.md` 145–147 | F03220 | non-negotiable | false | 10 |
| R06364 | Phase — "deps to earlier phases are always valid" | `README.md` 147 | F03221 | non-negotiable | false | 10 |
| R06365 | Uninstall command — `selfdefctl modules uninstall --confirm <hostname> --only observability` | `README.md` 149 | F03222 | non-negotiable | false | 10 |
| R06366 | Uninstall — removes rendered files | `README.md` 149 | F03223 | non-negotiable | false | 10 |
| R06367 | Uninstall — Prometheus + Grafana themselves NOT touched | `README.md` 150 | F03224 | non-negotiable | false | 10 |
| R06368 | Uninstall — operator runs them, operator removes them | `README.md` 151 | F03225 | non-negotiable | false | 10 |
| R06369 | Cross-module — depends on MS016 tetragon | `module.toml` 6 + cross-ref MS016 | F03234 | non-negotiable | false | 10 |
| R06370 | Cross-module — tetragon module exposes metrics endpoint at localhost:2112 by default | `README.md` 39–40 + cross-ref MS016 | F03234 | non-negotiable | false | 10 |
| R06371 | Cross-module — consumes MS025 detect-host api component /metrics endpoint | `README.md` 41–44 + cross-ref MS025 | F03235 | non-negotiable | false | 10 |
| R06372 | Cross-module — extends MS006 14-functional-modules catalog | `module.toml` 1 + cross-ref MS006 | F03236 | non-negotiable | false | 10 |
| R06373 | Cross-module — F-2026-052 finding traces from selfdef SDD ledger (MS013 27-SDD charter) | `README.md` 84–86 + cross-ref MS013 | F03237 | non-negotiable | false | 10 |
| R06374 | Cross-module — MS021 shared module-script lib v2 provides shared helpers | `install/lib.sh` 1–14 + cross-ref MS021 | F03238 | non-negotiable | false | 10 |
| R06375 | Cross-module — MS020 L1-L5 test harness covers Module-script category for apply/check/uninstall | cross-ref MS020 | F03239 | non-negotiable | false | 10 |
| R06376 | Cross-module — `selfdef-collector-eventstream` publishes events consumed by dashboard | INDEX MS027 + cross-ref crates/selfdef-collector-eventstream | F03240 | non-negotiable | false | 10 |
| R06377 | Cross-module — `selfdef-collector-journald` publishes events consumed by dashboard | INDEX MS027 + cross-ref crates/selfdef-collector-journald | F03240 | non-negotiable | false | 10 |
| R06378 | Cross-module — MS022 SSE quota subscriber count metric is renderable as a future dashboard panel extension | `README.md` 128–132 + cross-ref MS022 | F03212 | non-negotiable | true | 10 |
| R06379 | Cross-module — MS026 integrity-sentinel OCSF 2004 drift event flows to dashboard via selfdef_findings_by_severity_total | cross-ref MS026 | M00704 | non-negotiable | false | 10 |
| R06380 | Cross-module — MS024 bridge-l2 nftables forward_hook traffic metrics may emit into dashboard via collector | cross-ref MS024 | M00692 | non-negotiable | false | 10 |
| R06381 | Cross-module — MS023 polarproxy pcap-over-ip subscriber counts may emit into dashboard via collector | cross-ref MS023 | M00692 | non-negotiable | false | 10 |
| R06382 | Bundled profile config — full 33-line file | `profiles/bundled.toml` 1–33 | F03226 | non-negotiable | false | 10 |
| R06383 | External profile config — full 16-line file | `profiles/external.toml` 1–16 | F03227 | non-negotiable | false | 10 |
| R06384 | Dashboard JSON template — 103-line Grafana JSON | `assets/dashboards/selfdef.json.template` 1–103 | F03228 | non-negotiable | false | 10 |
| R06385 | Scrape config template — 15-line Prometheus scrape job | `assets/scrape/selfdef.yml.template` 1–15 | F03229 | non-negotiable | false | 10 |
| R06386 | apply.sh — 116-line idempotent applier | `install/apply.sh` 1–116 | F03230 | non-negotiable | false | 10 |
| R06387 | check.sh — 40-line side-effect-free verifier | `install/check.sh` 1–40 | F03231 | non-negotiable | false | 10 |
| R06388 | lib.sh — 72-line v2-opt-in helper loader | `install/lib.sh` 1–72 | F03232 | non-negotiable | false | 10 |
| R06389 | uninstall.sh — 78-line manifest-walked tear-down | `install/uninstall.sh` 1–78 | F03233 | non-negotiable | false | 10 |
| R06390 | Dashboard panel count — exactly 7 | `README.md` 59–73 | E0274 | non-negotiable | false | 10 |
| R06391 | Dashboard panels — 4 from Tetragon + 3 from selfdef-daemon | `README.md` 61 | E0274 | non-negotiable | false | 10 |
| R06392 | Module owns rendering, NOT installation of Prometheus | `README.md` 13 + 150 | F03149 | non-negotiable | false | 10 |
| R06393 | Module owns rendering, NOT installation of Grafana | `README.md` 13 + 150 | F03149 | non-negotiable | false | 10 |
| R06394 | Module owns rendering, NOT installation of alerting (alertmanager/Grafana alerting) | `README.md` 136–137 | F03214 | non-negotiable | false | 10 |
| R06395 | Module owns rendering, NOT logging stack (Loki / OpenTelemetry traces) | `README.md` 140 | F03217 | non-negotiable | false | 10 |
| R06396 | Module phase=post enforces dependency-ordering rule that all earlier-phase modules' metrics endpoints are up before scrape config lands | `module.toml` 15–17 + `README.md` 143–145 | F03219 | non-negotiable | false | 10 |
| R06397 | Module phase rule — same-phase modules MUST be sortable (deterministic ordering within phase) | inferred from `phase = "post"` semantics | M00696 | non-negotiable | true | 10 |
| R06398 | Bundled profile — Prometheus reload uses `systemctl reload prometheus.service` | `module.toml` 11 + `profiles/bundled.toml` 1–33 | M00693 | non-negotiable | false | 10 |
| R06399 | External profile — staging_dir owned by module (rendered files land there for operator sync) | `README.md` 35 + `profiles/external.toml` 1–16 | M00684 | non-negotiable | false | 10 |
| R06400 | Token rotation invariant — Prometheus token MUST NOT be a symlink to daemon's token | `README.md` 122 | F03210 | non-negotiable | false | 10 |
| R06401 | Token rotation invariant — two services hold their own copies of the bearer token | `README.md` 122–123 | F03211 | non-negotiable | false | 10 |
| R06402 | Token rotation invariant — credential rotation is deliberate operator action on EACH side | `README.md` 123–124 | F03211 | non-negotiable | false | 10 |
| R06403 | Selfdef-daemon /metrics — uses Prometheus exposition format | inferred from scrape_configs metrics_path | F03205 | non-negotiable | false | 10 |
| R06404 | Selfdef-daemon /metrics — exposes `selfdef_events_by_class_total` | `README.md` 69 | M00703 | non-negotiable | false | 10 |
| R06405 | Selfdef-daemon /metrics — exposes `selfdef_findings_by_severity_total` | `README.md` 70 | M00704 | non-negotiable | false | 10 |
| R06406 | Selfdef-daemon /metrics — exposes `selfdef_store_events` | `README.md` 71 | M00705 | non-negotiable | false | 10 |
| R06407 | Tetragon /metrics — exposes `tetragon_events_total` | `README.md` 65 + 81 | M00699 | non-negotiable | false | 10 |
| R06408 | Tetragon /metrics — exposes `tetragon_msg_sigkill_total` | `README.md` 66 + 81 | M00700 | non-negotiable | false | 10 |
| R06409 | Tetragon /metrics — exposes `tetragon_process_cache_size` | `README.md` 67 + 82 | M00701 | non-negotiable | false | 10 |
| R06410 | Tetragon /metrics — exposes `tetragon_map_errors_total` | `README.md` 68 + 82 | M00702 | non-negotiable | false | 10 |
| R06411 | Dashboard panel — events / sec range = `[5m]` | `README.md` 65–66 + 69–70 | E0274 | non-negotiable | false | 10 |
| R06412 | Dashboard panel — kills aggregation = `by policy` | `README.md` 66 | M00700 | non-negotiable | false | 10 |
| R06413 | Dashboard panel — map-errors aggregation = `by map, op` | `README.md` 68 | M00702 | non-negotiable | false | 10 |
| R06414 | Dashboard panel — events-by-class aggregation = `sum by (class_uid)` | `README.md` 69 | M00703 | non-negotiable | false | 10 |
| R06415 | Dashboard panel — findings-by-severity aggregation = `sum by (severity_id)` | `README.md` 70 | M00704 | non-negotiable | false | 10 |
| R06416 | OCSF — class_uid is the OCSF class identifier (events_by_class_total label) | `README.md` 69 + cross-ref OCSF | M00703 | non-negotiable | false | 10 |
| R06417 | OCSF — severity_id is the OCSF severity identifier (findings_by_severity_total label) | `README.md` 70 + cross-ref OCSF | M00704 | non-negotiable | false | 10 |
| R06418 | Cross-module — OCSF Detection Finding class 2004 (MS026) flows into selfdef_findings_by_severity_total | cross-ref MS026 + `README.md` 70 | M00704 | non-negotiable | false | 10 |
| R06419 | Scrape config — Prometheus scrape_interval 15s default | `README.md` 112 | F03204 | non-negotiable | false | 10 |
| R06420 | Scrape config — Prometheus metrics_path /metrics default | `README.md` 113 | F03205 | non-negotiable | false | 10 |
| R06421 | Scrape config — Prometheus bearer_token_file /etc/selfdef/api.token | `README.md` 114 | F03206 | non-negotiable | false | 10 |
| R06422 | Selfdef-daemon API — `[api] enabled = true` required | `README.md` 42 | F03167 | non-negotiable | false | 10 |
| R06423 | Selfdef-daemon API — `[api] tcp_addr = "127.0.0.1:8443"` required for TCP scraping | `README.md` 42–43 | F03168 | non-negotiable | false | 10 |
| R06424 | Selfdef-daemon API — `[api] token_file = "/etc/selfdef/api.token"` default | `README.md` 105–106 | F03202 | non-negotiable | false | 10 |
| R06425 | Selfdef-daemon API — bearer token enforced on EVERY request | `README.md` 104 | F03201 | non-negotiable | false | 10 |
| R06426 | Module-system invariant — depends_on=tetragon MUST resolve to MS016 tetragon module | `module.toml` 6 + cross-ref MS016 | M00694 | non-negotiable | false | 10 |
| R06427 | Module-system invariant — consumes=metrics-endpoint MUST resolve to any module declaring provides=metrics-endpoint | `module.toml` 8 | M00692 | non-negotiable | false | 10 |
| R06428 | Module-system invariant — provides=selfdef-dashboards declares a single dashboard surface | `module.toml` 7 | M00691 | non-negotiable | false | 10 |
| R06429 | Module-system invariant — phase=post MUST run after every phase=main module | `module.toml` 17 | M00696 | non-negotiable | false | 10 |
| R06430 | Module-system invariant — phase=post MAY have cross-phase dependency on phase=pre tetragon | `README.md` 145–147 | F03220 | non-negotiable | false | 10 |
| R06431 | Module-system invariant — instanced=false (host has one observability config) | `module.toml` 13 | M00695 | non-negotiable | false | 10 |
| R06432 | Profile bundled — assumes systemd-managed Prometheus | `profiles/bundled.toml` 1–33 | M00683 | non-negotiable | false | 10 |
| R06433 | Profile bundled — assumes systemd-managed Grafana | `profiles/bundled.toml` 1–33 | M00683 | non-negotiable | false | 10 |
| R06434 | Profile external — does NOT touch any service | `README.md` 20 + `profiles/external.toml` 1–16 | M00684 | non-negotiable | false | 10 |
| R06435 | Profile external — staging_dir is the ONLY output destination | `README.md` 35 + `profiles/external.toml` 1–16 | M00684 | non-negotiable | false | 10 |
| R06436 | Dashboard panel — 7 panels in total | `README.md` 59–73 | E0274 | non-negotiable | false | 10 |
| R06437 | Dashboard panel — first 4 panels are Tetragon-sourced | `README.md` 65–68 | E0274 | non-negotiable | false | 10 |
| R06438 | Dashboard panel — last 3 panels are selfdef-daemon-sourced | `README.md` 69–71 | E0274 | non-negotiable | false | 10 |
| R06439 | apply.sh — uses MS021 shared module-script lib v2 | `install/lib.sh` 1–14 + cross-ref MS021 | M00687 | non-negotiable | false | 10 |
| R06440 | apply.sh — uses module_record_file for F-2027-024 manifest tracking | `install/lib.sh` 1–14 + cross-ref F-2027-024 | M00687 | non-negotiable | false | 10 |
| R06441 | check.sh — DRY_RUN forced 0 per F-2027-027 (read-only contract) | `install/check.sh` 1–40 + cross-ref F-2027-027 | M00686 | non-negotiable | false | 10 |
| R06442 | uninstall.sh — walks manifest via module_render_files | `install/uninstall.sh` 1–78 | M00688 | non-negotiable | false | 10 |
| R06443 | uninstall.sh — does NOT touch prometheus.service | `README.md` 150–151 | F03224 | non-negotiable | false | 10 |
| R06444 | uninstall.sh — does NOT touch grafana-server.service | `README.md` 150–151 | F03224 | non-negotiable | false | 10 |
| R06445 | uninstall.sh — only removes rendered files (scrape config + dashboard JSON) | `README.md` 149 + 150–151 | F03223 + F03224 | non-negotiable | false | 10 |
| R06446 | Configuration overlay — module config defaults overlaid by profile, then host config, then env | inferred from MS021 + docs/src/modules.md | M00683 + M00684 | non-negotiable | false | 10 |
| R06447 | Configuration overlay — `[modules.observability]` section in /etc/selfdef/modules.toml activates module | `README.md` 1 + cross-ref MS006 | M00696 | non-negotiable | false | 10 |
| R06448 | Bearer token file — `/etc/selfdef/api.token` is canonical default | `README.md` 105–106 + 114 | F03202 + F03206 | non-negotiable | false | 10 |
| R06449 | Bearer token rotation — must be deliberate operator action on each side (Prometheus + selfdef-daemon) | `README.md` 122–124 | F03211 | non-negotiable | false | 10 |
| R06450 | Dashboard JSON — template-rendered each apply | `README.md` 131 | F03213 | non-negotiable | false | 10 |
| R06451 | Dashboard JSON — operator edits propagate to next apply | `README.md` 131–132 | F03213 | non-negotiable | false | 10 |
| R06452 | Scrape YAML — template-rendered each apply | inferred from apply.sh + assets/scrape/selfdef.yml.template | M00690 | non-negotiable | false | 10 |
| R06453 | Bundled — Prometheus reload via `systemctl reload prometheus.service` | `module.toml` 11 + `profiles/bundled.toml` 1–33 | M00693 | non-negotiable | false | 10 |
| R06454 | Bundled — Grafana auto-discovers via dashboard_dir scan | `README.md` 19 | F03155 | non-negotiable | false | 10 |
| R06455 | External — operator owns sync from staging_dir to Prometheus + Grafana | `README.md` 20 | F03157 | non-negotiable | false | 10 |
| R06456 | External — module emits NO systemctl invocations | `README.md` 20 | F03158 | non-negotiable | false | 10 |
| R06457 | Module — does NOT install Prometheus | `README.md` 13 | F03149 | non-negotiable | false | 10 |
| R06458 | Module — does NOT install Grafana | `README.md` 13 | F03149 | non-negotiable | false | 10 |
| R06459 | Module — does NOT install Loki | `README.md` 140 | F03217 | non-negotiable | false | 10 |
| R06460 | Module — does NOT install OpenTelemetry collector | `README.md` 140 | F03217 | non-negotiable | false | 10 |
| R06461 | Module — does NOT install alertmanager | `README.md` 137 | F03214 | non-negotiable | false | 10 |
| R06462 | Module — does NOT install Grafana alerting rules | `README.md` 136 | F03214 | non-negotiable | false | 10 |
| R06463 | Project-boundary — observability is selfdef IPS-side; sovereign-os has separate Observability Plane (M044 + M045) | architecture + cross-ref M044 + M045 | E0271 | non-negotiable | false | 10 |
| R06464 | Project-boundary — selfdef observability module renders Prometheus+Grafana config; sovereign-os Observability Plane uses journald + OpenTelemetry + DCGM + eBPF + Prometheus-Grafana stack | cross-ref M044 + M045 | E0271 | non-negotiable | false | 10 |
| R06465 | Project-boundary — cross-repo audit between selfdef + sovereign-os observability routes through MS007 audit-manifest typed-mirror crate | architecture + cross-ref MS007 | E0280 | non-negotiable | false | 10 |
| R06466 | Module-system invariant — dependency on tetragon means MS027 cannot apply without MS016 tetragon installed | `module.toml` 6 + cross-ref MS016 | M00694 | non-negotiable | false | 10 |
| R06467 | Module-system invariant — module-loader topological sort SHALL place MS016 tetragon BEFORE MS027 observability | `module.toml` 6 + cross-ref MS016 | M00694 | non-negotiable | false | 10 |
| R06468 | Module-system invariant — module-loader SHALL warn if scrape_targets contains an endpoint no installed module provides | `module.toml` 8 | M00692 | non-negotiable | true | 10 |
| R06469 | Module-system invariant — phase=post lifecycle SHALL be the final phase before apply emits final status | `module.toml` 17 | M00696 | non-negotiable | false | 10 |
| R06470 | Module-system invariant — phase=post strict ordering rule "deps to earlier phases are always valid" | `README.md` 147 | F03221 | non-negotiable | false | 10 |
| R06471 | Module-system invariant — single-instance (instanced=false) implies module-loader refuses multi-instance activation | `module.toml` 13 | M00695 | non-negotiable | false | 10 |
| R06472 | Dashboard — designed to fit on one screen on a normal desktop | `README.md` 11–12 | F03148 | non-negotiable | false | 10 |
| R06473 | Dashboard panel — first 4 panels = Tetragon (kernel-level visibility) | `README.md` 65–68 | E0274 | non-negotiable | false | 10 |
| R06474 | Dashboard panel — last 3 panels = selfdef-daemon (correlator + responder visibility) | `README.md` 69–71 | E0274 | non-negotiable | false | 10 |
| R06475 | Dashboard — extends via assets/dashboards/selfdef.json.template edits | `README.md` 128–132 | F03212 | non-negotiable | false | 10 |
| R06476 | Selfdef-daemon /metrics — bearer token never appears in scrape config logs (Prometheus bearer_token_file dereference) | `README.md` 114 | F03206 | non-negotiable | false | 10 |
| R06477 | Selfdef-daemon /metrics — token file mode SHOULD be 0600 owned by Prometheus user | `README.md` 121 | F03209 | non-negotiable | false | 10 |
| R06478 | Selfdef-daemon /metrics — TCP transport uses 127.0.0.1 (loopback only by default) | `README.md` 103 | F03200 | non-negotiable | false | 10 |
| R06479 | Selfdef-daemon /metrics — UNIX socket transport is preferred for same-host deployments | `README.md` 100–102 | F03199 | non-negotiable | false | 10 |
| R06480 | Composite — MS027 (10 epics / 26 modules / 120 features / 240 reqs) covers observability module v0.1.0 (473 lines): module.toml (depends_on=tetragon + provides=selfdef-dashboards + consumes=metrics-endpoint + instanced=false + phase=post) + README.md (145-line operator doc + 7-panel dashboard + auth + token rotation + extension + scope-not-here-yet) + 2 profiles (bundled default + external) + apply.sh + check.sh + lib.sh (v2) + uninstall.sh + 2 templates (dashboard JSON 103-line + scrape YAML 15-line); 7-panel dashboard (4 Tetragon + 3 selfdef-daemon) renders Tetragon-event-rate / kills-by-policy / process-cache / map-errors / selfdef-events-by-class / selfdef-findings-by-severity / selfdef-hot-store-size; auth-gated daemon /metrics (UNIX socket OR TCP+Bearer); module does NOT install Prometheus/Grafana/alertmanager/Loki/OpenTelemetry — operator-owned services; phase=post + tetragon-cross-phase-pre-dep; F-2026-052 phase-2 follow-up for Tetragon-version pin; F-2027-024 manifest integration + F-2027-027 DRY_RUN-forced-0 | `modules/observability/` 473 lines | E0271 + E0272 + E0273 + E0274 + E0275 + E0276 + E0277 + E0278 + E0279 + E0280 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml manifest invariants (R06241–R06261) + README profile + config + dashboard + token rotation + extension + NOT-here-yet + phase=post + uninstall (R06262–R06368) + cross-module + cross-repo (R06369–R06381) + asset templates + script files (R06382–R06389) + dashboard / Prometheus / token / API invariants (R06390–R06425) + module-system invariants (R06426–R06431) + profile invariants (R06432–R06435) + dashboard composition + library + manifest + ownership invariants (R06436–R06462) + project-boundary cross-refs (R06463–R06467) + module-loader/lifecycle invariants (R06468–R06471) + dashboard design invariants (R06472–R06475) + selfdef-daemon metrics auth invariants (R06476–R06479) + composite (R06480)
- Source range 473 lines yields 240 R-rows representing ~51% line-coverage at the verbatim-citation level
- Project boundary — MS027 is selfdef IPS observability scope; sovereign-os has its own Observability Plane (M044 + M045) using journald + OpenTelemetry + DCGM + eBPF + Prometheus-Grafana stack; cross-repo audit routes through MS007 audit-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS026 integrity-sentinel / MS028 BitNet GPU inference
- Dependency — MS027 depends_on=tetragon = MS016 eBPF + Tetragon module (consumes Tetragon Prometheus metrics endpoint)
- Surface integration — provides=`selfdef-dashboards` (Grafana dashboard + Prometheus scrape pair); consumes=`metrics-endpoint` (any future module exposing Prometheus-scrapable metrics)
- Cross-module event integration — `selfdef_events_by_class_total` + `selfdef_findings_by_severity_total` (selfdef-daemon /metrics) flow OCSF event/finding class+severity from MS025 detect-host event-bus + MS026 integrity-sentinel drift events into the dashboard
- Phase integration — `phase = "post"` ensures observability module runs AFTER every other module's metrics endpoint is up; cross-phase dependency on `tetragon` (phase=pre) is allowed because deps to earlier phases are always valid (module-roadmap.md § Lifecycle surface)
- F-2026-052 — selfdef SDD ledger finding tracking Tetragon-version-pin Phase-2 follow-up
- F-2027-024 manifest-helper integration + F-2027-027 DRY_RUN-forced-0 from selfdef SDD ledger
- Test integration — MS020 L1-L5 layered harness covers Module-script test category for apply/check/uninstall scripts; Pipeline test category covers end-to-end Prometheus-scrape→Grafana-render flow
- Cross-repo binding — sovereign-os has its own Observability Plane (M044's 5-component plane + M045's eBPF/PSI/DCGM/Prometheus-Grafana additions); cross-repo audit (e.g., comparing selfdef IPS metrics to sovereign-os intelligence metrics) routes through MS007 audit-manifest typed-mirror crate
- Operator references: tetragon.io/docs/reference/metrics + Prometheus scrape_configs docs + Grafana dashboard auto-discovery docs + OCSF event class_uid/severity_id schema + MS016 tetragon module + MS025 detect-host + MS026 integrity-sentinel
