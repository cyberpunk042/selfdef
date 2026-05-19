# MS001 — Selfdef daemon core — selfdef-core / selfdef-daemon / selfdef-bus / selfdef-config / selfdef-api / selfdef-cli

> Parent: `backlog/milestones/INDEX.md` row MS001.
> Source: existing repo crates `selfdef-core` + `selfdef-daemon` + `selfdef-bus` + `selfdef-config` + `selfdef-api` + `selfdef-cli`; SDD-000 charter; SDD-001 AI-machine end-to-end; SDD-002 defaults that work.

## Epics (E0001–E0010)

| Epic ID | Phrase | Source |
|---|---|---|
| E0001 | Daemon core — long-lived process, supervises all selfdef-side fabrics | `crates/selfdef-daemon`; SDD-000 charter |
| E0002 | Core types — Event / Verdict / Rule / Action / Identity / Subject domain types | `crates/selfdef-core` |
| E0003 | Event bus — in-process pub/sub for collectors → correlator → responder | `crates/selfdef-bus` |
| E0004 | Configuration loader — `/etc/selfdef/selfdef.toml` + `/etc/selfdef/modules.toml` + overlay layers | `crates/selfdef-config`; SDD-002 defaults |
| E0005 | HTTP API — operator-facing control + telemetry surface | `crates/selfdef-api` |
| E0006 | CLI — `selfdefctl` operator command set (`init` / `doctor` / `modules apply` / `audit` / `notifier` / ...) | `crates/selfdef-cli` |
| E0007 | systemd integration — `selfdefd.service` lifecycle + cgroup slice + AppArmor profile | `packaging/`; `ansible/` |
| E0008 | Daemon supervision tree — collectors / correlator / responder / notifier / dashboard subprocesses | `crates/selfdef-daemon` supervisor logic |
| E0009 | Daemon health + doctor — selfdefctl doctor verifies deployment + emits operator-actionable advisories | SDD-002; `crates/selfdef-cli` doctor |
| E0010 | Daemon shutdown / drain — graceful drain of in-flight events on SIGTERM | SDD-000 charter; `crates/selfdef-daemon` shutdown path |

## Modules (M00001–M00026)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00001 | `Event` domain type — universal event envelope across collectors | `crates/selfdef-core` Event struct | E0002 |
| M00002 | `Verdict` domain type — correlator output (Benign / Suspicious / Malicious) | `crates/selfdef-core` Verdict enum | E0002 |
| M00003 | `Rule` domain type — declarative rule definition (id / pattern / window / action) | `crates/selfdef-core` Rule struct | E0002 |
| M00004 | `Action` domain type — responder commit object (lockdown / freeze / snapshot / notify / honey) | `crates/selfdef-core` Action enum | E0002 |
| M00005 | `Identity` domain type — host / user / process / container identity | `crates/selfdef-core` Identity struct | E0002 |
| M00006 | `Subject` domain type — what an event is about (file path / network endpoint / process / pod) | `crates/selfdef-core` Subject struct | E0002 |
| M00007 | Event bus channel — typed broadcast channel from collectors to correlator | `crates/selfdef-bus` Channel | E0003 |
| M00008 | Event bus backpressure policy — bounded channel with operator-tunable depth | `crates/selfdef-bus` BackpressurePolicy | E0003 |
| M00009 | Event bus drop-on-overflow vs block-on-overflow toggle | `crates/selfdef-bus` OverflowMode | E0003 |
| M00010 | Configuration loader — TOML parse + schema validate | `crates/selfdef-config` Loader | E0004 |
| M00011 | Configuration overlay — `/etc/selfdef/selfdef.toml` + env overrides + CLI flag overrides | `crates/selfdef-config` Overlay | E0004 |
| M00012 | Configuration modules.toml — per-module enable/disable + per-module overlay | `crates/selfdef-config` ModulesConfig | E0004 |
| M00013 | HTTP API — `GET /healthz` | `crates/selfdef-api` healthz handler | E0005 |
| M00014 | HTTP API — `GET /readyz` | `crates/selfdef-api` readyz handler | E0005 |
| M00015 | HTTP API — `GET /metrics` (Prometheus) | `crates/selfdef-api` metrics handler | E0005 |
| M00016 | HTTP API — `GET /v1/events` (SSE stream) | `crates/selfdef-api` events SSE | E0005 |
| M00017 | HTTP API — `GET /v1/verdicts` | `crates/selfdef-api` verdicts handler | E0005 |
| M00018 | HTTP API — `POST /v1/actions/dry-run` (preview-before-apply) | `crates/selfdef-api` actions handler | E0005 |
| M00019 | CLI `selfdefctl init` — bootstrap deployment | `crates/selfdef-cli` init | E0006 |
| M00020 | CLI `selfdefctl doctor` — verify deployment | `crates/selfdef-cli` doctor | E0006 |
| M00021 | CLI `selfdefctl modules apply` — apply modules.toml state | `crates/selfdef-cli` modules apply | E0006 |
| M00022 | CLI `selfdefctl audit` — run audit cycle | `crates/selfdef-cli` audit | E0006 |
| M00023 | systemd unit `selfdefd.service` — long-lived daemon | `packaging/systemd/selfdefd.service` | E0007 |
| M00024 | AppArmor profile for selfdefd — capability restrictions | `packaging/apparmor/` | E0007 |
| M00025 | cgroup v2 slice for selfdefd — memory + CPU isolation | `packaging/systemd/` slice unit | E0007 |
| M00026 | Daemon supervisor — restart-on-fail per subprocess + structured logs | `crates/selfdef-daemon` Supervisor | E0008 |

## Features (F00001–F00120)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00001 | Toggle event-bus overflow mode (drop / block) | `crates/selfdef-bus` | M00009 | mode | true |
| F00002 | Profile knob — `event_bus_overflow = drop \| block` | `crates/selfdef-bus` | M00009 | profile | true |
| F00003 | Env var `SELFDEF_EVENT_BUS_OVERFLOW` | `crates/selfdef-bus` | M00009 | env_var | true |
| F00004 | CLI `--event-bus-overflow <mode>` | `crates/selfdef-cli` | M00009 | cli_verb | true |
| F00005 | Dashboard surface — event-bus depth + drop count | `dashboard/` | M00007 | dashboard | true |
| F00006 | Metric `selfdef_event_bus_depth` | `crates/selfdef-bus` | M00007 | observability_metric | true |
| F00007 | Metric `selfdef_event_bus_drop_total` | `crates/selfdef-bus` | M00009 | observability_metric | true |
| F00008 | Metric `selfdef_event_bus_publish_total{channel}` | `crates/selfdef-bus` | M00007 | observability_metric | true |
| F00009 | Toggle event-bus channel capacity (operator-tunable depth) | `crates/selfdef-bus` | M00008 | mode | true |
| F00010 | Profile knob — `event_bus_capacity` | `crates/selfdef-config` | M00008 | profile | true |
| F00011 | Env var `SELFDEF_EVENT_BUS_CAPACITY` | `crates/selfdef-config` | M00008 | env_var | true |
| F00012 | Test — event-bus drop-on-overflow honors policy when channel is full | tests/ | M00009 | test | false |
| F00013 | Test — event-bus block-on-overflow honors policy when channel is full | tests/ | M00009 | test | false |
| F00014 | Test — `Event` envelope round-trips through JSON serde | tests/ | M00001 | test | false |
| F00015 | Test — `Verdict` enum matches scalar reference for all variants | tests/ | M00002 | test | false |
| F00016 | Test — `Rule` parse from TOML matches expected struct | tests/ | M00003 | test | false |
| F00017 | Test — `Action` enum exhaustive on responder commit path | tests/ | M00004 | test | false |
| F00018 | Test — `Identity` struct covers host / user / process / container | tests/ | M00005 | test | false |
| F00019 | Test — `Subject` struct covers file / endpoint / process / pod | tests/ | M00006 | test | false |
| F00020 | Config loader — TOML parse + schema validate | `crates/selfdef-config` | M00010 | composite | false |
| F00021 | Config loader — operator-discoverable error messages on schema violations | `crates/selfdef-config` | M00010 | composite | true |
| F00022 | Config overlay — `/etc/selfdef/selfdef.toml` is the base layer | `crates/selfdef-config` | M00011 | composite | false |
| F00023 | Config overlay — env vars override base | `crates/selfdef-config` | M00011 | composite | true |
| F00024 | Config overlay — CLI flags override env vars | `crates/selfdef-config` | M00011 | composite | true |
| F00025 | Config overlay — operator-overrideable precedence (CLI > env > file) | `crates/selfdef-config` | M00011 | composite | false |
| F00026 | Config modules.toml — per-module `enabled = bool` toggle | `crates/selfdef-config` | M00012 | composite | true |
| F00027 | Config modules.toml — per-module overlay section | `crates/selfdef-config` | M00012 | composite | true |
| F00028 | Dashboard surface — config diff (current vs default) | `dashboard/` | M00011 | dashboard | true |
| F00029 | API `GET /healthz` returns 200 when daemon supervises all subprocesses | `crates/selfdef-api` | M00013 | api_endpoint | false |
| F00030 | API `GET /healthz` returns 503 when any subprocess is in restart loop | `crates/selfdef-api` | M00013 | api_endpoint | false |
| F00031 | API `GET /readyz` returns 200 when all collectors have produced ≥ 1 event | `crates/selfdef-api` | M00014 | api_endpoint | false |
| F00032 | API `GET /metrics` exposes Prometheus text format | `crates/selfdef-api` | M00015 | api_endpoint | false |
| F00033 | API `GET /v1/events` streams events via SSE | `crates/selfdef-api` | M00016 | api_endpoint | true |
| F00034 | API `GET /v1/events` accepts `?since=<unix-ts>` filter | `crates/selfdef-api` | M00016 | api_endpoint | true |
| F00035 | API `GET /v1/events` accepts `?subject=<glob>` filter | `crates/selfdef-api` | M00016 | api_endpoint | true |
| F00036 | API `GET /v1/verdicts` returns last N verdicts | `crates/selfdef-api` | M00017 | api_endpoint | true |
| F00037 | API `POST /v1/actions/dry-run` previews responder action without committing | `crates/selfdef-api` | M00018 | api_endpoint | true |
| F00038 | API per-token SSE subscriber quota (per SDD-007) | `crates/selfdef-api` | M00016 | mode | true |
| F00039 | Profile knob — `api_listen_addr` | `crates/selfdef-config` | M00013 | profile | true |
| F00040 | Profile knob — `api_token_required` | `crates/selfdef-config` | M00013 | profile | true |
| F00041 | Env var `SELFDEF_API_LISTEN_ADDR` | `crates/selfdef-config` | M00013 | env_var | true |
| F00042 | Env var `SELFDEF_API_TOKEN` | `crates/selfdef-config` | M00013 | env_var | true |
| F00043 | CLI `selfdefctl init config` writes `/etc/selfdef/selfdef.toml` | `crates/selfdef-cli` | M00019 | cli_verb | false |
| F00044 | CLI `selfdefctl init modules` writes `/etc/selfdef/modules.toml` | `crates/selfdef-cli` | M00019 | cli_verb | false |
| F00045 | CLI `selfdefctl init` is idempotent (no-op when files exist + match template) | `crates/selfdef-cli` | M00019 | composite | false |
| F00046 | CLI `selfdefctl doctor` runs every health check + emits operator-readable summary | `crates/selfdef-cli` | M00020 | cli_verb | false |
| F00047 | CLI `selfdefctl doctor` exits non-zero when any blocker check fails | `crates/selfdef-cli` | M00020 | composite | false |
| F00048 | CLI `selfdefctl doctor` per-check operator-actionable next-step hint | `crates/selfdef-cli` | M00020 | composite | true |
| F00049 | CLI `selfdefctl modules apply` reads modules.toml + runs per-module install/uninstall | `crates/selfdef-cli` | M00021 | cli_verb | false |
| F00050 | CLI `selfdefctl modules apply --dry-run` previews changes | `crates/selfdef-cli` | M00021 | cli_verb | true |
| F00051 | CLI `selfdefctl modules apply --diff` shows operator-readable per-module diff | `crates/selfdef-cli` | M00021 | cli_verb | true |
| F00052 | CLI `selfdefctl audit` runs current cycle's audit vectors | `crates/selfdef-cli` | M00022 | cli_verb | false |
| F00053 | CLI `selfdefctl audit --cycle <N>` runs a specific past cycle | `crates/selfdef-cli` | M00022 | cli_verb | true |
| F00054 | systemd unit `selfdefd.service` Type=notify with sd_notify integration | `packaging/systemd/` | M00023 | composite | false |
| F00055 | systemd unit `selfdefd.service` Restart=on-failure | `packaging/systemd/` | M00023 | composite | false |
| F00056 | systemd unit `selfdefd.service` MemoryDenyWriteExecute=true | `packaging/systemd/` | M00023 | composite | true |
| F00057 | systemd unit `selfdefd.service` RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK | `packaging/systemd/` | M00023 | composite | true |
| F00058 | systemd unit `selfdefd.service` NoNewPrivileges=true | `packaging/systemd/` | M00023 | composite | false |
| F00059 | systemd unit `selfdefd.service` ProtectSystem=strict | `packaging/systemd/` | M00023 | composite | false |
| F00060 | systemd unit `selfdefd.service` ProtectHome=true | `packaging/systemd/` | M00023 | composite | false |
| F00061 | systemd unit `selfdefd.service` PrivateTmp=true | `packaging/systemd/` | M00023 | composite | false |
| F00062 | systemd unit `selfdefd.service` ReadWritePaths=/var/lib/selfdef /var/log/selfdef /etc/selfdef | `packaging/systemd/` | M00023 | composite | false |
| F00063 | AppArmor profile for selfdefd — restricts capabilities to required set | `packaging/apparmor/` | M00024 | composite | false |
| F00064 | cgroup v2 slice for selfdefd — `MemoryHigh` + `MemoryMax` + `CPUWeight` | `packaging/systemd/` | M00025 | composite | true |
| F00065 | Daemon supervisor — restart subprocess on crash | `crates/selfdef-daemon` | M00026 | composite | false |
| F00066 | Daemon supervisor — exponential backoff on restart | `crates/selfdef-daemon` | M00026 | composite | false |
| F00067 | Daemon supervisor — refuse to restart after N consecutive crashes (operator-tunable) | `crates/selfdef-daemon` | M00026 | composite | true |
| F00068 | Daemon supervisor — structured logs per subprocess (collector / correlator / responder / notifier) | `crates/selfdef-daemon` | M00026 | composite | false |
| F00069 | Dashboard surface — supervisor tree state (per subprocess: running / restarting / dead) | `dashboard/` | M00026 | dashboard | true |
| F00070 | Metric `selfdef_subprocess_restart_total{subprocess}` | `crates/selfdef-daemon` | M00026 | observability_metric | true |
| F00071 | Metric `selfdef_subprocess_state{subprocess}` | `crates/selfdef-daemon` | M00026 | observability_metric | true |
| F00072 | Daemon shutdown — drain in-flight events on SIGTERM | `crates/selfdef-daemon` | E0010 | composite | false |
| F00073 | Daemon shutdown — drain timeout operator-tunable (default 30s) | `crates/selfdef-daemon` | E0010 | composite | true |
| F00074 | Daemon shutdown — emit final flush metric before exit | `crates/selfdef-daemon` | E0010 | composite | false |
| F00075 | Daemon shutdown — hand off in-progress responder actions to SDD-008 notification orchestrator | `crates/selfdef-daemon` | E0010 | composite | false |
| F00076 | Profile knob — `daemon_shutdown_timeout_s` | `crates/selfdef-config` | E0010 | profile | true |
| F00077 | Env var `SELFDEF_DAEMON_SHUTDOWN_TIMEOUT_S` | `crates/selfdef-config` | E0010 | env_var | true |
| F00078 | CLI `--shutdown-timeout-s <n>` | `crates/selfdef-cli` | E0010 | cli_verb | true |
| F00079 | Test — daemon startup probes succeed within 5s on a clean install | tests/ | M00023 | test | false |
| F00080 | Test — daemon doctor reports green when all checks pass | tests/ | M00020 | test | false |
| F00081 | Test — daemon doctor reports actionable summary on each check failure | tests/ | M00020 | test | false |
| F00082 | Test — `selfdefctl init` is idempotent across consecutive invocations | tests/ | M00019 | test | false |
| F00083 | Test — config overlay precedence (CLI > env > file) | tests/ | M00011 | test | false |
| F00084 | Test — daemon supervisor restarts crashed subprocess within N seconds | tests/ | M00026 | test | false |
| F00085 | Test — daemon supervisor refuses to restart after N consecutive crashes | tests/ | M00026 | test | false |
| F00086 | Test — daemon shutdown drains in-flight events before exit | tests/ | E0010 | test | false |
| F00087 | Test — Prometheus `/metrics` exposes all named metrics | tests/ | M00015 | test | false |
| F00088 | Test — SSE `/v1/events` stream emits ≥ 1 event under load | tests/ | M00016 | test | false |
| F00089 | Test — API per-token SSE subscriber quota enforced (SDD-007) | tests/ | M00016 | test | false |
| F00090 | Test — API rejects requests without token when `api_token_required = true` | tests/ | M00013 | test | false |
| F00091 | Test — API token hot-rotation works without daemon restart (per audit-shipped feature) | tests/ | M00013 | test | false |
| F00092 | Composite — Daemon core integrates with all 7 collectors via event bus | repo `crates/selfdef-collector-*` | M00007 | composite | false |
| F00093 | Composite — Daemon core integrates with correlator + store + responder + signing | repo `crates/selfdef-{correlator,store,responder,signing}` | E0001 | composite | false |
| F00094 | Composite — Daemon core integrates with all 14 notifier integration crates | repo `crates/selfdef-integration-*` | E0001 | composite | false |
| F00095 | Composite — Daemon core integrates with notifier engine + orchestrator (SDD-008) | repo `crates/selfdef-notifier{,-engine,-orchestrator}` | E0001 | composite | false |
| F00096 | Composite — Daemon core integrates with 8 cross-repo typed-mirror crates (SDD-038 doctrine) | repo `crates/selfdef-{auth-tier,bashrc-install,history-sink,dashboard-manifest,surface-manifest,ux-checklist,audit-manifest,doc-manifest}` | E0001 | composite | false |
| F00097 | Composite — Daemon core integrates with SDD-005 L1–L5 test layer | tests/ | E0001 | composite | false |
| F00098 | Composite — Daemon core integrates with selfdef-on-sain01 deployment substrate (SDD-010, SDD-012) | sain01/ | E0001 | composite | false |
| F00099 | Composite — Daemon core integrates with 14 functional modules via modules.toml | `modules/*` | M00012 | composite | false |
| F00100 | Composite — Daemon core integrates with operator dashboard (SDD-026 flex profile) | `dashboard/` | E0001 | composite | false |
| F00101 | UX — `selfdefctl` command groups discoverable from `selfdefctl --help` | `crates/selfdef-cli` | E0006 | composite | true |
| F00102 | UX — `selfdefctl <group> --help` shows per-group verbs | `crates/selfdef-cli` | E0006 | composite | true |
| F00103 | UX — each destructive verb requires `--apply` confirm flag (triple-gate pattern) | `crates/selfdef-cli` | E0006 | composite | false |
| F00104 | UX — each `--apply` verb prints a preview-then-prompt diff by default | `crates/selfdef-cli` | E0006 | composite | true |
| F00105 | UX — `selfdefctl doctor` output ≤ 1 screen on green case | `crates/selfdef-cli` | M00020 | composite | true |
| F00106 | UX — `selfdefctl doctor` output groups failures by severity (blocker / important / advisory) | `crates/selfdef-cli` | M00020 | composite | true |
| F00107 | UX — operator-discoverable next-step on each failure | `crates/selfdef-cli` | M00020 | composite | true |
| F00108 | UX — `selfdefctl` honors `NO_COLOR` env var | `crates/selfdef-cli` | E0006 | composite | true |
| F00109 | UX — `selfdefctl --json` output for every verb that has prose output | `crates/selfdef-cli` | E0006 | composite | true |
| F00110 | UX — `selfdefctl audit` per-cycle report path operator-discoverable | `crates/selfdef-cli` | M00022 | composite | true |
| F00111 | Dashboard surface — daemon supervisor tree (live) | `dashboard/` | M00026 | dashboard | true |
| F00112 | Dashboard surface — config diff (current vs default) | `dashboard/` | M00011 | dashboard | true |
| F00113 | Dashboard surface — event bus depth + drop count | `dashboard/` | M00007 | dashboard | true |
| F00114 | Dashboard surface — last 100 events stream | `dashboard/` | M00016 | dashboard | true |
| F00115 | Dashboard surface — last 100 verdicts | `dashboard/` | M00017 | dashboard | true |
| F00116 | Dashboard surface — recent doctor results | `dashboard/` | M00020 | dashboard | true |
| F00117 | Dashboard surface — audit cycle history | `dashboard/` | M00022 | dashboard | true |
| F00118 | Composite — `selfdefctl` integrates with bashrc autocomplete (SD-R-BASHRC-1 cross-repo binding) | `crates/selfdef-bashrc-install` | E0006 | composite | true |
| F00119 | Composite — daemon emits history events to `/var/log/sovereign-os/modules.jsonl` via SD-R-EVENT-LOG-1 | `crates/selfdef-history-sink` | E0001 | composite | true |
| F00120 | Composite — daemon registers dashboard manifest via SD-R-DASHBOARD-MANIFEST-1 typed mirror | `crates/selfdef-dashboard-manifest` | E0001 | composite | false |

## Requirements (R00001–R00240)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R00001 | selfdef daemon runs as a long-lived process supervising all selfdef-side fabrics | SDD-000 charter | E0001 | non-negotiable | false | 10 |
| R00002 | selfdef daemon is implemented as `selfdef-daemon` Rust crate | repo crate | E0001 | non-negotiable | false | 10 |
| R00003 | Selfdef core domain types live in `selfdef-core` crate | repo crate | E0002 | non-negotiable | false | 10 |
| R00004 | Core type — `Event` envelope carries timestamp, source, identity, subject, payload | `crates/selfdef-core` | M00001 | non-negotiable | false | 10 |
| R00005 | Core type — `Verdict` enum is Benign / Suspicious / Malicious (or operator-extensible) | `crates/selfdef-core` | M00002 | non-negotiable | true | 10 |
| R00006 | Core type — `Rule` carries id / pattern / window / action / signing fields | `crates/selfdef-core` | M00003 | non-negotiable | false | 10 |
| R00007 | Core type — `Action` enum covers lockdown / freeze / snapshot / notify / honey / no-op | `crates/selfdef-core` | M00004 | non-negotiable | true | 10 |
| R00008 | Core type — `Identity` carries host / user / process / container fields | `crates/selfdef-core` | M00005 | non-negotiable | false | 10 |
| R00009 | Core type — `Subject` covers file-path / network-endpoint / process / pod | `crates/selfdef-core` | M00006 | non-negotiable | false | 10 |
| R00010 | Event bus uses typed broadcast channel | `crates/selfdef-bus` | M00007 | non-negotiable | false | 10 |
| R00011 | Event bus has bounded capacity (operator-tunable) | `crates/selfdef-bus` | M00008 | non-negotiable | false | 10 |
| R00012 | Event bus overflow policy is drop-on-overflow OR block-on-overflow (operator-selectable) | `crates/selfdef-bus` | M00009 | non-negotiable | true | 10 |
| R00013 | Event bus emits `selfdef_event_bus_depth` Prometheus metric | `crates/selfdef-bus` | F00006 | non-negotiable | true | 10 |
| R00014 | Event bus emits `selfdef_event_bus_drop_total` Prometheus metric | `crates/selfdef-bus` | F00007 | non-negotiable | true | 10 |
| R00015 | Event bus emits `selfdef_event_bus_publish_total{channel}` Prometheus metric | `crates/selfdef-bus` | F00008 | non-negotiable | true | 10 |
| R00016 | Configuration loader parses TOML | `crates/selfdef-config` | M00010 | non-negotiable | false | 10 |
| R00017 | Configuration loader validates against schema | `crates/selfdef-config` | M00010 | non-negotiable | false | 10 |
| R00018 | Configuration overlay base layer is `/etc/selfdef/selfdef.toml` | `crates/selfdef-config` | M00011 | non-negotiable | false | 10 |
| R00019 | Configuration overlay env-var layer overrides base | `crates/selfdef-config` | M00011 | non-negotiable | false | 10 |
| R00020 | Configuration overlay CLI-flag layer overrides env-var | `crates/selfdef-config` | M00011 | non-negotiable | false | 10 |
| R00021 | Configuration overlay precedence operator-discoverable | `crates/selfdef-config` | M00011 | non-negotiable | true | 10 |
| R00022 | Configuration modules.toml has per-module `enabled = bool` | `crates/selfdef-config` | M00012 | non-negotiable | true | 10 |
| R00023 | Configuration modules.toml has per-module overlay section | `crates/selfdef-config` | M00012 | non-negotiable | true | 10 |
| R00024 | HTTP API exposes `GET /healthz` | `crates/selfdef-api` | M00013 | non-negotiable | false | 10 |
| R00025 | HTTP API exposes `GET /readyz` | `crates/selfdef-api` | M00014 | non-negotiable | false | 10 |
| R00026 | HTTP API exposes `GET /metrics` in Prometheus text format | `crates/selfdef-api` | M00015 | non-negotiable | false | 10 |
| R00027 | HTTP API exposes `GET /v1/events` as SSE stream | `crates/selfdef-api` | M00016 | non-negotiable | true | 10 |
| R00028 | HTTP API `GET /v1/events` accepts `?since=<unix-ts>` filter | `crates/selfdef-api` | M00016 | non-negotiable | true | 10 |
| R00029 | HTTP API `GET /v1/events` accepts `?subject=<glob>` filter | `crates/selfdef-api` | M00016 | non-negotiable | true | 10 |
| R00030 | HTTP API exposes `GET /v1/verdicts` for last-N verdict history | `crates/selfdef-api` | M00017 | non-negotiable | true | 10 |
| R00031 | HTTP API exposes `POST /v1/actions/dry-run` for preview-before-apply | `crates/selfdef-api` | M00018 | non-negotiable | true | 10 |
| R00032 | HTTP API enforces per-token SSE subscriber quota (SDD-007) | SDD-007 | M00016 | non-negotiable | true | 10 |
| R00033 | HTTP API supports token hot-rotation without daemon restart | audit-shipped | M00013 | non-negotiable | true | 10 |
| R00034 | HTTP API listen address operator-overrideable | `crates/selfdef-config` | F00039 | non-negotiable | true | 10 |
| R00035 | HTTP API token required when operator opts-in | `crates/selfdef-config` | F00040 | non-negotiable | true | 10 |
| R00036 | CLI binary is `selfdefctl` | `crates/selfdef-cli` | E0006 | non-negotiable | false | 10 |
| R00037 | CLI `selfdefctl init config` writes `/etc/selfdef/selfdef.toml` | `crates/selfdef-cli` | M00019 | non-negotiable | false | 10 |
| R00038 | CLI `selfdefctl init modules` writes `/etc/selfdef/modules.toml` | `crates/selfdef-cli` | M00019 | non-negotiable | false | 10 |
| R00039 | CLI `selfdefctl init` is idempotent | `crates/selfdef-cli` | F00045 | non-negotiable | false | 10 |
| R00040 | CLI `selfdefctl doctor` runs every health check | `crates/selfdef-cli` | M00020 | non-negotiable | false | 10 |
| R00041 | CLI `selfdefctl doctor` emits operator-readable summary | `crates/selfdef-cli` | M00020 | non-negotiable | false | 10 |
| R00042 | CLI `selfdefctl doctor` exits non-zero on any blocker failure | `crates/selfdef-cli` | F00047 | non-negotiable | false | 10 |
| R00043 | CLI `selfdefctl doctor` emits operator-actionable next-step hint per failure | `crates/selfdef-cli` | F00048 | non-negotiable | true | 10 |
| R00044 | CLI `selfdefctl modules apply` reads modules.toml + runs install/uninstall | `crates/selfdef-cli` | M00021 | non-negotiable | false | 10 |
| R00045 | CLI `selfdefctl modules apply --dry-run` previews without committing | `crates/selfdef-cli` | F00050 | non-negotiable | true | 10 |
| R00046 | CLI `selfdefctl modules apply --diff` shows operator-readable per-module diff | `crates/selfdef-cli` | F00051 | non-negotiable | true | 10 |
| R00047 | CLI `selfdefctl audit` runs current cycle's vectors | `crates/selfdef-cli` | M00022 | non-negotiable | false | 10 |
| R00048 | CLI `selfdefctl audit --cycle <N>` runs specific past cycle | `crates/selfdef-cli` | F00053 | non-negotiable | true | 10 |
| R00049 | CLI `selfdefctl --help` shows all top-level command groups | `crates/selfdef-cli` | F00101 | non-negotiable | false | 10 |
| R00050 | CLI `selfdefctl <group> --help` shows per-group verbs | `crates/selfdef-cli` | F00102 | non-negotiable | false | 10 |
| R00051 | CLI destructive verbs require `--apply` confirm flag | `crates/selfdef-cli` | F00103 | non-negotiable | false | 10 |
| R00052 | CLI destructive verbs print preview-then-prompt diff by default | `crates/selfdef-cli` | F00104 | non-negotiable | true | 10 |
| R00053 | CLI honors `NO_COLOR` env var | `crates/selfdef-cli` | F00108 | non-negotiable | true | 10 |
| R00054 | CLI `--json` output format available for every verb with prose output | `crates/selfdef-cli` | F00109 | non-negotiable | true | 10 |
| R00055 | systemd unit `selfdefd.service` Type=notify | `packaging/systemd/` | F00054 | non-negotiable | false | 10 |
| R00056 | systemd unit `selfdefd.service` Restart=on-failure | `packaging/systemd/` | F00055 | non-negotiable | false | 10 |
| R00057 | systemd unit `selfdefd.service` NoNewPrivileges=true | `packaging/systemd/` | F00058 | non-negotiable | false | 10 |
| R00058 | systemd unit `selfdefd.service` ProtectSystem=strict | `packaging/systemd/` | F00059 | non-negotiable | false | 10 |
| R00059 | systemd unit `selfdefd.service` ProtectHome=true | `packaging/systemd/` | F00060 | non-negotiable | false | 10 |
| R00060 | systemd unit `selfdefd.service` PrivateTmp=true | `packaging/systemd/` | F00061 | non-negotiable | false | 10 |
| R00061 | systemd unit `selfdefd.service` ReadWritePaths includes only `/var/lib/selfdef`, `/var/log/selfdef`, `/etc/selfdef` | `packaging/systemd/` | F00062 | non-negotiable | false | 10 |
| R00062 | systemd unit MemoryDenyWriteExecute=true (opt-in, off by default to avoid breaking eBPF JIT-needing components) | `packaging/systemd/` | F00056 | preferable | true | 10 |
| R00063 | systemd unit RestrictAddressFamilies covers AF_INET AF_INET6 AF_UNIX AF_NETLINK only | `packaging/systemd/` | F00057 | non-negotiable | true | 10 |
| R00064 | AppArmor profile for selfdefd restricts capabilities to required set | `packaging/apparmor/` | F00063 | non-negotiable | false | 10 |
| R00065 | cgroup v2 slice for selfdefd carries `MemoryHigh` + `MemoryMax` + `CPUWeight` | `packaging/systemd/` | F00064 | non-negotiable | true | 10 |
| R00066 | Daemon supervisor restarts crashed subprocess automatically | `crates/selfdef-daemon` | F00065 | non-negotiable | false | 10 |
| R00067 | Daemon supervisor uses exponential backoff on restart | `crates/selfdef-daemon` | F00066 | non-negotiable | false | 10 |
| R00068 | Daemon supervisor refuses to restart after N consecutive crashes (default 5, operator-tunable) | `crates/selfdef-daemon` | F00067 | non-negotiable | true | 10 |
| R00069 | Daemon supervisor emits structured logs per subprocess | `crates/selfdef-daemon` | F00068 | non-negotiable | false | 10 |
| R00070 | Daemon shutdown drains in-flight events on SIGTERM | `crates/selfdef-daemon` | F00072 | non-negotiable | false | 10 |
| R00071 | Daemon shutdown timeout operator-tunable (default 30s) | `crates/selfdef-daemon` | F00073 | non-negotiable | true | 10 |
| R00072 | Daemon shutdown emits final flush metric before exit | `crates/selfdef-daemon` | F00074 | non-negotiable | false | 10 |
| R00073 | Daemon shutdown hands off in-progress responder actions to SDD-008 notification orchestrator | SDD-008 | F00075 | non-negotiable | false | 10 |
| R00074 | Daemon emits `selfdef_subprocess_restart_total{subprocess}` metric | `crates/selfdef-daemon` | F00070 | non-negotiable | true | 10 |
| R00075 | Daemon emits `selfdef_subprocess_state{subprocess}` metric | `crates/selfdef-daemon` | F00071 | non-negotiable | true | 10 |
| R00076 | Daemon healthz returns 200 when all subprocesses are running | `crates/selfdef-api` | F00029 | non-negotiable | false | 10 |
| R00077 | Daemon healthz returns 503 when any subprocess is in restart loop | `crates/selfdef-api` | F00030 | non-negotiable | false | 10 |
| R00078 | Daemon readyz returns 200 when all collectors have produced ≥ 1 event | `crates/selfdef-api` | F00031 | non-negotiable | false | 10 |
| R00079 | Daemon supports `selfdefctl init` bootstrap workflow | `crates/selfdef-cli` | M00019 | non-negotiable | false | 10 |
| R00080 | Daemon supports `selfdefctl doctor` verification workflow | `crates/selfdef-cli` | M00020 | non-negotiable | false | 10 |
| R00081 | Daemon integrates with all 7 collectors via the event bus | `crates/selfdef-collector-*` | F00092 | non-negotiable | false | 10 |
| R00082 | Daemon integrates with `selfdef-correlator` for verdict synthesis | `crates/selfdef-correlator` | F00093 | non-negotiable | false | 10 |
| R00083 | Daemon integrates with `selfdef-store` for event persistence | `crates/selfdef-store` | F00093 | non-negotiable | false | 10 |
| R00084 | Daemon integrates with `selfdef-responder` for action commit | `crates/selfdef-responder` | F00093 | non-negotiable | false | 10 |
| R00085 | Daemon integrates with `selfdef-signing` for rule + TracingPolicy signing | `crates/selfdef-signing` | F00093 | non-negotiable | false | 10 |
| R00086 | Daemon integrates with all 14 notifier integration crates | `crates/selfdef-integration-*` | F00094 | non-negotiable | false | 10 |
| R00087 | Daemon integrates with `selfdef-notifier` + `selfdef-notifier-engine` + `selfdef-notifier-orchestrator` (SDD-008) | SDD-008 | F00095 | non-negotiable | false | 10 |
| R00088 | Daemon integrates with the 8 cross-repo typed-mirror crates per SDD-038 doctrine | SDD-038 | F00096 | non-negotiable | false | 10 |
| R00089 | Daemon integrates with `selfdef-cross-repo-saturation` invariant crate | `crates/selfdef-cross-repo-saturation` | F00096 | non-negotiable | false | 10 |
| R00090 | Daemon integrates with SDD-005 L1–L5 layered test harness | SDD-005 | F00097 | non-negotiable | false | 10 |
| R00091 | Daemon integrates with selfdef-on-sain01 deployment substrate (SDD-010, SDD-012, SDD-017) | SDD-010 / 012 / 017 | F00098 | non-negotiable | false | 10 |
| R00092 | Daemon integrates with 14 functional modules via modules.toml | `modules/*` | F00099 | non-negotiable | false | 10 |
| R00093 | Daemon integrates with operator dashboard (SDD-026 flex profile) | SDD-026 | F00100 | non-negotiable | false | 10 |
| R00094 | Daemon integrates with `selfdef-bashrc-install` for autocomplete + aliases (SD-R-BASHRC-1) | SD-R-BASHRC-1 | F00118 | non-negotiable | true | 10 |
| R00095 | Daemon integrates with `selfdef-history-sink` for global history emission (SD-R-EVENT-LOG-1) | SD-R-EVENT-LOG-1 | F00119 | non-negotiable | true | 10 |
| R00096 | Daemon integrates with `selfdef-dashboard-manifest` for typed dashboard discovery (SD-R-DASHBOARD-MANIFEST-1) | SD-R-DASHBOARD-MANIFEST-1 | F00120 | non-negotiable | false | 10 |
| R00097 | Daemon integrates with `selfdef-auth-tier` for typed 6-variant AuthTier enum (SD-R-AUTH-TIER-1) | SD-R-AUTH-TIER-1 | E0001 | non-negotiable | false | 10 |
| R00098 | Daemon integrates with `selfdef-surface-manifest` for 8-surface taxonomy (SD-R-MULTI-SURFACE-AUDIT-1) | SD-R-MULTI-SURFACE-AUDIT-1 | E0001 | non-negotiable | false | 10 |
| R00099 | Daemon integrates with `selfdef-ux-checklist` for 6-dimension UX catalog (SD-R-UX-CHECKLIST-1) | SD-R-UX-CHECKLIST-1 | E0001 | non-negotiable | false | 10 |
| R00100 | Daemon integrates with `selfdef-audit-manifest` for 8-pattern anti-minimization catalog (SD-R-AUDIT-1) | SD-R-AUDIT-1 | E0001 | non-negotiable | false | 10 |
| R00101 | Daemon integrates with `selfdef-doc-manifest` for 6-kind doc catalog (SD-R-DOC-MANIFEST-1) | SD-R-DOC-MANIFEST-1 | E0001 | non-negotiable | false | 10 |
| R00102 | Cross-repo saturation invariant must remain SATURATED (8/8) — any new sovereign-os compliance instrument requires its selfdef-side mirror | SDD-038 | E0001 | non-negotiable | false | 10 |
| R00103 | Cross-repo saturation invariant enforced by `~/sovereign-os/tests/lint/test_cross_repo_saturation_invariant.py` | sovereign-os test | E0001 | non-negotiable | false | 10 |
| R00104 | Test — daemon startup probes succeed within 5s on clean install | tests/ | F00079 | non-negotiable | false | 10 |
| R00105 | Test — daemon doctor reports green when all checks pass | tests/ | F00080 | non-negotiable | false | 10 |
| R00106 | Test — daemon doctor emits actionable summary on each failure | tests/ | F00081 | non-negotiable | false | 10 |
| R00107 | Test — `selfdefctl init` is idempotent across consecutive invocations | tests/ | F00082 | non-negotiable | false | 10 |
| R00108 | Test — config overlay precedence (CLI > env > file) | tests/ | F00083 | non-negotiable | false | 10 |
| R00109 | Test — daemon supervisor restarts crashed subprocess within N seconds | tests/ | F00084 | non-negotiable | false | 10 |
| R00110 | Test — daemon supervisor refuses to restart after N consecutive crashes | tests/ | F00085 | non-negotiable | false | 10 |
| R00111 | Test — daemon shutdown drains in-flight events before exit | tests/ | F00086 | non-negotiable | false | 10 |
| R00112 | Test — Prometheus `/metrics` exposes all named metrics | tests/ | F00087 | non-negotiable | false | 10 |
| R00113 | Test — SSE `/v1/events` stream emits ≥ 1 event under load | tests/ | F00088 | non-negotiable | false | 10 |
| R00114 | Test — API per-token SSE subscriber quota enforced | tests/ | F00089 | non-negotiable | false | 10 |
| R00115 | Test — API rejects requests without token when `api_token_required = true` | tests/ | F00090 | non-negotiable | false | 10 |
| R00116 | Test — API token hot-rotation works without daemon restart | tests/ | F00091 | non-negotiable | false | 10 |
| R00117 | Test — `Event` envelope round-trips through JSON serde | tests/ | F00014 | non-negotiable | false | 10 |
| R00118 | Test — `Rule` parse from TOML matches expected struct | tests/ | F00016 | non-negotiable | false | 10 |
| R00119 | Test — `Action` enum exhaustive match in responder commit path | tests/ | F00017 | non-negotiable | false | 10 |
| R00120 | Test — event-bus drop-on-overflow honors policy when full | tests/ | F00012 | non-negotiable | false | 10 |
| R00121 | Test — event-bus block-on-overflow honors policy when full | tests/ | F00013 | non-negotiable | false | 10 |
| R00122 | Dashboard surface — daemon supervisor tree live view | `dashboard/` | F00111 | non-negotiable | true | 10 |
| R00123 | Dashboard surface — config diff view | `dashboard/` | F00112 | non-negotiable | true | 10 |
| R00124 | Dashboard surface — event bus depth + drop count view | `dashboard/` | F00113 | non-negotiable | true | 10 |
| R00125 | Dashboard surface — last 100 events stream view | `dashboard/` | F00114 | non-negotiable | true | 10 |
| R00126 | Dashboard surface — last 100 verdicts view | `dashboard/` | F00115 | non-negotiable | true | 10 |
| R00127 | Dashboard surface — recent doctor results view | `dashboard/` | F00116 | non-negotiable | true | 10 |
| R00128 | Dashboard surface — audit cycle history view | `dashboard/` | F00117 | non-negotiable | true | 10 |
| R00129 | UX — `selfdefctl doctor` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00105 | preferable | true | 10 |
| R00130 | UX — `selfdefctl doctor` output groups failures by severity | `crates/selfdef-cli` | F00106 | non-negotiable | true | 10 |
| R00131 | UX — operator-discoverable next-step on each failure | `crates/selfdef-cli` | F00107 | non-negotiable | true | 10 |
| R00132 | UX — `selfdefctl audit` per-cycle report path operator-discoverable | `crates/selfdef-cli` | F00110 | non-negotiable | true | 10 |
| R00133 | Daemon supports Debian 13+ | README | E0001 | non-negotiable | false | 10 |
| R00134 | Daemon supports Ubuntu 24.04+ | README | E0001 | non-negotiable | false | 10 |
| R00135 | Daemon supports personal workstation deployment target | README | E0001 | non-negotiable | false | 10 |
| R00136 | Daemon supports home server deployment target | README | E0001 | non-negotiable | false | 10 |
| R00137 | Daemon supports public VPS deployment target | README | E0001 | non-negotiable | false | 10 |
| R00138 | Daemon supports AI-machine host deployment target (containerised agents) | README | E0001 | non-negotiable | false | 10 |
| R00139 | Daemon explicit non-goal — no offensive action against attackers | README | E0001 | non-negotiable | false | 10 |
| R00140 | Daemon explicit non-goal — no "hack back" capability, ever | README | E0001 | non-negotiable | false | 10 |
| R00141 | Daemon scope — Detect intrusion attempts and post-compromise behavior | README §Goals | E0001 | non-negotiable | false | 10 |
| R00142 | Daemon scope — high signal, low noise across kernel + system + network layers | README §Goals | E0001 | non-negotiable | false | 10 |
| R00143 | Daemon scope — Correlate events across collectors with time-windowed rules | README §Goals | E0001 | non-negotiable | false | 10 |
| R00144 | Daemon scope — Respond actively (lockdown egress / freeze logins / snapshot state / notify / engage deception) | README §Goals | E0001 | non-negotiable | false | 10 |
| R00145 | Daemon scope — Defend the client side too (selfdef-ssh-wrap when YOU are the client) | README §Goals | E0001 | non-negotiable | false | 10 |
| R00146 | Daemon scope — Defend AI-machine hosts via agent-guard Tetragon TracingPolicies | README §Goals | E0001 | non-negotiable | false | 10 |
| R00147 | Daemon scope — active deception (honeytokens, honey services) is IN scope | README | E0001 | non-negotiable | false | 10 |
| R00148 | Daemon scope — Phase 1 architecture audit closeout is complete | README §Status | E0001 | non-negotiable | false | 10 |
| R00149 | Daemon scope — 9 modules ship in catalog with 6 audit-shipped opt-in security features | README §Status | E0001 | non-negotiable | true | 10 |
| R00150 | Daemon scope — rule signing is audit-shipped opt-in feature | README §Status | E0001 | non-negotiable | true | 10 |
| R00151 | Daemon scope — TracingPolicy signing is audit-shipped opt-in feature | README §Status | E0001 | non-negotiable | true | 10 |
| R00152 | Daemon scope — eventstream integrity is audit-shipped opt-in feature | README §Status | E0001 | non-negotiable | true | 10 |
| R00153 | Daemon scope — API token hot-rotation is audit-shipped opt-in feature | README §Status | E0001 | non-negotiable | true | 10 |
| R00154 | Daemon scope — k8s RBAC posture check is audit-shipped opt-in feature | README §Status | E0001 | non-negotiable | true | 10 |
| R00155 | Daemon scope — vpn-bridge multi-instance honesty is audit-shipped opt-in feature | README §Status; SDD-003 | E0001 | non-negotiable | true | 10 |
| R00156 | Profile knob — `event_bus_overflow` | `crates/selfdef-config` | F00002 | non-negotiable | true | 10 |
| R00157 | Profile knob — `event_bus_capacity` | `crates/selfdef-config` | F00010 | non-negotiable | true | 10 |
| R00158 | Profile knob — `api_listen_addr` | `crates/selfdef-config` | F00039 | non-negotiable | true | 10 |
| R00159 | Profile knob — `api_token_required` | `crates/selfdef-config` | F00040 | non-negotiable | true | 10 |
| R00160 | Profile knob — `daemon_shutdown_timeout_s` | `crates/selfdef-config` | F00076 | non-negotiable | true | 10 |
| R00161 | Env var — `SELFDEF_EVENT_BUS_OVERFLOW` | `crates/selfdef-config` | F00003 | non-negotiable | true | 10 |
| R00162 | Env var — `SELFDEF_EVENT_BUS_CAPACITY` | `crates/selfdef-config` | F00011 | non-negotiable | true | 10 |
| R00163 | Env var — `SELFDEF_API_LISTEN_ADDR` | `crates/selfdef-config` | F00041 | non-negotiable | true | 10 |
| R00164 | Env var — `SELFDEF_API_TOKEN` | `crates/selfdef-config` | F00042 | non-negotiable | true | 10 |
| R00165 | Env var — `SELFDEF_DAEMON_SHUTDOWN_TIMEOUT_S` | `crates/selfdef-config` | F00077 | non-negotiable | true | 10 |
| R00166 | CLI flag — `--event-bus-overflow <mode>` | `crates/selfdef-cli` | F00004 | non-negotiable | true | 10 |
| R00167 | CLI flag — `--shutdown-timeout-s <n>` | `crates/selfdef-cli` | F00078 | non-negotiable | true | 10 |
| R00168 | Operator can disable any collector via modules.toml | `crates/selfdef-config` | M00012 | non-negotiable | true | 10 |
| R00169 | Operator can disable any notifier integration via modules.toml | `crates/selfdef-config` | M00012 | non-negotiable | true | 10 |
| R00170 | Operator can disable any responder action via responder allow-list config | `crates/selfdef-responder` | M00012 | non-negotiable | true | 10 |
| R00171 | Operator can disable HTTP API entirely via `api.enabled = false` | `crates/selfdef-config` | E0005 | non-negotiable | true | 10 |
| R00172 | Operator can disable dashboard entirely via `dashboard.enabled = false` | `crates/selfdef-config` | E0005 | non-negotiable | true | 10 |
| R00173 | Operator can run daemon in dry-run mode (no commits) via `daemon.dry_run = true` | `crates/selfdef-config` | E0001 | non-negotiable | true | 10 |
| R00174 | Operator can run daemon in audit-only mode (no responder actions) via `responder.enabled = false` | `crates/selfdef-config` | E0001 | non-negotiable | true | 10 |
| R00175 | Operator can run daemon with custom config path via `--config <path>` | `crates/selfdef-cli` | M00011 | non-negotiable | true | 10 |
| R00176 | Operator can run daemon with custom log path via `daemon.log_path` | `crates/selfdef-config` | E0001 | non-negotiable | true | 10 |
| R00177 | Operator can run daemon with custom store path via `store.path` | `crates/selfdef-config` | E0001 | non-negotiable | true | 10 |
| R00178 | Operator can run daemon with custom metric port via `api.metrics_port` | `crates/selfdef-config` | M00015 | non-negotiable | true | 10 |
| R00179 | Operator can opt-in to API token auth | `crates/selfdef-config` | F00040 | non-negotiable | true | 10 |
| R00180 | Operator can hot-rotate API token without daemon restart | audit-shipped | F00091 | non-negotiable | true | 10 |
| R00181 | Daemon emits to journald by default | `crates/selfdef-daemon` | E0001 | non-negotiable | true | 10 |
| R00182 | Daemon emits to stderr when run with `--foreground` | `crates/selfdef-cli` | E0001 | non-negotiable | true | 10 |
| R00183 | Daemon emits structured JSON logs by default | `crates/selfdef-daemon` | F00068 | non-negotiable | true | 10 |
| R00184 | Daemon emits human-readable logs when `log.format = pretty` | `crates/selfdef-config` | F00068 | non-negotiable | true | 10 |
| R00185 | Daemon log level operator-tunable (`trace` / `debug` / `info` / `warn` / `error`) | `crates/selfdef-config` | E0001 | non-negotiable | true | 10 |
| R00186 | Daemon log level overrideable via `RUST_LOG` env var | `crates/selfdef-daemon` | E0001 | non-negotiable | true | 10 |
| R00187 | Daemon respects `journalctl -u selfdefd` standard semantics | `packaging/systemd/` | M00023 | non-negotiable | false | 10 |
| R00188 | Daemon supports `systemctl restart selfdefd` clean restart | `packaging/systemd/` | M00023 | non-negotiable | false | 10 |
| R00189 | Daemon supports `systemctl reload selfdefd` to re-read config without restart | `packaging/systemd/` | M00023 | preferable | true | 10 |
| R00190 | Daemon emits Prometheus metric for total uptime | `crates/selfdef-daemon` | M00015 | non-negotiable | false | 10 |
| R00191 | Daemon emits Prometheus metric for last config reload timestamp | `crates/selfdef-daemon` | M00015 | non-negotiable | true | 10 |
| R00192 | Daemon emits Prometheus metric for current build version | `crates/selfdef-daemon` | M00015 | non-negotiable | false | 10 |
| R00193 | Daemon emits Prometheus metric for current config version (operator-overlay hash) | `crates/selfdef-daemon` | M00015 | non-negotiable | true | 10 |
| R00194 | Daemon binary is single static-or-mostly-static `selfdefd` executable | `crates/selfdef-daemon` | E0001 | non-negotiable | false | 10 |
| R00195 | CLI binary is single static-or-mostly-static `selfdefctl` executable | `crates/selfdef-cli` | E0006 | non-negotiable | false | 10 |
| R00196 | Daemon respects `XDG_CONFIG_HOME` for per-user config path | `crates/selfdef-config` | M00011 | preferable | true | 10 |
| R00197 | Daemon respects `XDG_STATE_HOME` for per-user state path | `crates/selfdef-config` | M00011 | preferable | true | 10 |
| R00198 | Daemon supports `--version` flag returning build version + commit hash | `crates/selfdef-cli` | E0006 | non-negotiable | false | 10 |
| R00199 | Daemon supports `--config-print` flag dumping effective config | `crates/selfdef-cli` | M00011 | non-negotiable | true | 10 |
| R00200 | Daemon supports `--config-validate` flag returning schema-only validation | `crates/selfdef-cli` | M00010 | non-negotiable | true | 10 |
| R00201 | Operator can opt-in to mTLS for HTTP API via `api.mtls.enabled = true` | `crates/selfdef-config` | M00013 | preferable | true | 10 |
| R00202 | Operator can opt-in to TLS-with-CA-pinning for HTTP API via `api.tls.ca_path = ...` | `crates/selfdef-config` | M00013 | preferable | true | 10 |
| R00203 | Operator can opt-in to UNIX-socket-only API via `api.unix_socket = ...` | `crates/selfdef-config` | M00013 | preferable | true | 10 |
| R00204 | Operator can opt-in to systemd socket activation via systemd `.socket` unit | `packaging/systemd/` | M00023 | preferable | true | 10 |
| R00205 | Operator can opt-in to running daemon as non-root via `User=` / `Group=` capability hand-off (where eBPF/auditd allow) | `packaging/systemd/` | M00023 | preferable | true | 10 |
| R00206 | Daemon supports CAP_BPF + CAP_NET_ADMIN + CAP_AUDIT_READ minimum capability set | `packaging/systemd/` | M00023 | non-negotiable | false | 10 |
| R00207 | Daemon supports running with stricter MemoryDenyWriteExecute=true when no JIT-needing components are enabled | `packaging/systemd/` | F00056 | preferable | true | 10 |
| R00208 | Daemon supports SDD-004 threat-model invariants on every responder action | SDD-004 | F00093 | non-negotiable | false | 10 |
| R00209 | Daemon supports SDD-006 shared module-script lib for all module scripts | SDD-006 | E0001 | non-negotiable | false | 10 |
| R00210 | Daemon supports SDD-008 notification orchestration handoff on shutdown | SDD-008 | F00075 | non-negotiable | false | 10 |
| R00211 | Daemon supports SDD-009 dashboard wiring | SDD-009 | F00100 | non-negotiable | false | 10 |
| R00212 | Daemon supports SDD-014 shared audit summary channel | SDD-014 | F00094 | non-negotiable | false | 10 |
| R00213 | Daemon supports SDD-015 perimeter coexistence | SDD-015 | E0001 | non-negotiable | false | 10 |
| R00214 | Daemon supports SDD-016 metric naming doctrine | SDD-016 | M00015 | non-negotiable | false | 10 |
| R00215 | Daemon supports SDD-023 cross-repo model taxonomy mirror | SDD-023 | F00096 | non-negotiable | false | 10 |
| R00216 | Daemon supports SDD-029 (round ledger doctrine) for traceability of every change | SDD-029 | E0001 | non-negotiable | false | 10 |
| R00217 | Daemon supports SDD-032 helper-library doctrine for any new shared lib | SDD-032 | E0001 | non-negotiable | false | 10 |
| R00218 | Daemon supports SDD-035 workload-mode adopter doctrine when responding to sovereign-os workload-mode changes | SDD-035 | F00096 | non-negotiable | true | 10 |
| R00219 | Daemon supports SDD-036 inference-service stricter posture for inference-adjacent subprocesses (when present) | SDD-036 | F00056 | preferable | true | 10 |
| R00220 | Daemon supports SDD-038 cross-repo binding doctrine | SDD-038 | F00096 | non-negotiable | false | 10 |
| R00221 | Daemon never deletes user data without operator triple-gate | SDD-004 | F00103 | non-negotiable | false | 10 |
| R00222 | Daemon never modifies `/etc/` outside `/etc/selfdef/` without operator triple-gate | SDD-004 | F00103 | non-negotiable | false | 10 |
| R00223 | Daemon never writes to `$HOME` of any user other than its own service user | SDD-004 | F00060 | non-negotiable | false | 10 |
| R00224 | Daemon never opens outbound network connections beyond configured notifier targets | SDD-004 | F00057 | non-negotiable | false | 10 |
| R00225 | Daemon never opens inbound listening ports beyond configured API + metrics + dashboard | SDD-004 | F00057 | non-negotiable | false | 10 |
| R00226 | Daemon never executes user-supplied code without operator triple-gate | SDD-004 | F00103 | non-negotiable | false | 10 |
| R00227 | Daemon never bypasses systemd unit hardening at runtime | SDD-004 | M00023 | non-negotiable | false | 10 |
| R00228 | Daemon never bypasses AppArmor profile at runtime | SDD-004 | M00024 | non-negotiable | false | 10 |
| R00229 | Daemon never bypasses cgroup v2 slice at runtime | SDD-004 | M00025 | non-negotiable | false | 10 |
| R00230 | Daemon never accepts an unsigned Rule from a remote source | SDD-004 | F00093 | non-negotiable | false | 10 |
| R00231 | Daemon never commits an Action without a signed Rule chain | SDD-004 | F00093 | non-negotiable | false | 10 |
| R00232 | Daemon never escalates from Suspicious to Malicious Verdict without a matching signed correlation rule | SDD-004 | E0002 | non-negotiable | false | 10 |
| R00233 | Daemon never disables an opt-in security feature silently | SDD-002 | E0004 | non-negotiable | false | 10 |
| R00234 | Daemon emits an operator-discoverable warning when an opt-in security feature is disabled | SDD-002 | F00046 | non-negotiable | true | 10 |
| R00235 | Daemon supports operator-controlled toggle for every opt-in security feature | SDD-002 | E0004 | non-negotiable | true | 10 |
| R00236 | Daemon documentation states the WHY for every opt-in default off | SDD-002 | E0001 | non-negotiable | false | 10 |
| R00237 | Daemon documentation states the WHY for every non-negotiable default on | SDD-002 | E0001 | non-negotiable | false | 10 |
| R00238 | Daemon test coverage L1 (lint) — every public-API surface has at least one assertion | SDD-005 | F00097 | non-negotiable | false | 10 |
| R00239 | Daemon test coverage L3 (smoke) — daemon starts, doctor green, modules apply, doctor green again | SDD-005 | F00079 | non-negotiable | false | 10 |
| R00240 | Daemon test coverage L5 (real-substrate) — daemon runs on a real Debian 13 VM with all collectors live | SDD-005 | F00098 | non-negotiable | false | 10 |

— End of MS001 milestone file.
