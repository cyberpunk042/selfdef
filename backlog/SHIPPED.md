# selfdef · backlog/SHIPPED.md

> **Production-shipped state tracker against `backlog/INDEX.md`.** Auto-maintained as commits land on the selfdef PR branch. Surfaces, per milestone, which catalogued R-rows have reached production code (with test coverage + Cargo-deb-installed asset) versus which remain catalogued-only.
>
> The catalogue itself is `backlog/INDEX.md` (48 milestones × 240 R-rows = 11,520 R-rows total). This file is the orthogonal "delivery state" view per the operator's standing constraint:
>
> > *"You cannot mark something done if it hasn't reached Prod."*
>
> *Shipped* here means: shipped to a commit on the development branch, with passing tests on the affected crate, with a deb-asset entry where applicable, and (for cross-repo R-rows) with the sovereign-os consumer side wired. *Catalogued-only* means: R-row exists in `backlog/milestones/MS*.md` but the production code path for that row hasn't landed yet.

## Roll-up

| State | R-rows | % of 11,520 |
|---|---:|---:|
| Catalogued (total) | 11,520 | 100% |
| Shipped (production code + tests + packaging) | partial — tracked per-milestone below | — |
| Catalogued-only | balance | — |

Per-milestone shipped surfaces are enumerated below in commit-order so the trajectory across the multi-year project is auditable.

## MS043 — IPS operator surface (CLI + TUI + dashboard-mirror exports)

**Catalogued:** 240 R-rows (R10081..R10320). See `backlog/milestones/MS043-ips-operator-surface-cli-tui-and-dashboard-mirrors.md`.

**Shipped this milestone:**

| R-row range | Surface | Commits (selfdef branch) | Tests | Packaging |
|---|---|---|---|---|
| R10281 + R10297 | `selfdef-cli-mirror` schema crate publishes the live clap-tree via `CliMirrorSnapshot 1.0.0`, doctrine verbatim "Fullstack at the edges" | crate ships in workspace as `selfdef-cli-mirror` | 5 schema tests (in-crate) | linked via workspace dep |
| R10281 (producer wiring) | `selfdefctl cli-mirror snapshot --output PATH` operator-controlled producer with atomic tempfile + rename; `DEFAULT_STATE_PATH` const shared between producer + daemon consumer | `a2fc563` | 7 publisher tests (resident-cache + shell-out fallback + schema-drift refusal) | n/a (verb in shipped binary) |
| R10281 (one-shot trigger) | `selfdef-cli-mirror-emit.service` systemd one-shot kicked from `packaging/debian/postinst`; resident-store at `/var/lib/selfdef/cli-mirror.json` becomes hot at install/upgrade | `1d86857` | 8 unit-file contract tests (User=selfdef, Type=oneshot, hardening posture, Environment= matches crate const) | Cargo.toml deb-assets row → `/lib/systemd/system/` |
| R10281 (lifecycle) | postrm cleanup — `purge` arm disables + stops + removes drop-in dir; `remove` arm stops without disabling (reinstall=upgrade contract) | `e9bfd4a` | 9 postrm contract tests (sibling-template parity + var-lib wipe ordering + reinstall-upgrade preservation) | postrm shipped via existing debian/postrm asset |
| R10281 (triage) | `selfdefctl cli-mirror doctor` — 4 checks (schema-version / resident-store / systemd-unit / published-mirror) + 3-tier severity + json/table modes + cross-cutting `selfdefctl doctor` roll-up with opt-in/opt-out gating | `d49c0b6` + `0ad9fc0` | 11 doctor unit + 11 cli_doctor integration tests | verb in shipped binary |
| R10281 (observability) | `cli-mirror doctor --textfile PATH` emits 4 node_exporter-compatible gauge series; `selfdef-cli-mirror-doctor.{service,timer}` runs every 60s with SuccessExitStatus=0 1 2 | `e9ab056` | 8 textfile render unit + 10 timer/service contract tests | 2 new Cargo.toml deb-assets rows |
| R10281 (docs) | `docs/operator/m060-cockpit-mirror-producers.md` (215-line operator runbook) + README + ARCHITECTURE.md references | `fdbef1b` + `6365fa4` | n/a (markdown) | doc files shipped |

**Cross-milestone observability widening (MS027 × MS043 × M060):**

| R-row family | Surface | Commits | Tests |
|---|---|---|---|
| R10281 (chain-wide observability) | `selfdefctl m060-doctor --textfile PATH` covers all 6 mirror domains (D-02/D-13/D-14/D-15/D-17/D-18) with 6 gauge series each; `selfdef-m060-doctor.{service,timer}` runs every 60s at 70s boot-offset | `ce58154` | 8 m060_doctor unit + 10 chain-doctor unit-contract + 2 added postrm contract tests |

## MS007 — Cross-repo typed-mirror crates

**Catalogued:** 240 R-rows. The 8-of-8 SATURATED set listed in the milestone title pairs with the typed-mirror surface.

**Shipped this milestone:**

| R-row range | Surface | Status |
|---|---|---|
| `selfdef-cli-mirror::DEFAULT_STATE_PATH` const | shared producer/consumer/unit const for the resident-store path — eliminates drift across producer (selfdefctl), consumer (selfdefd publisher), unit Environment=, and Grafana alert thresholds | shipped under commit `a2fc563`; locked by `m060_cli_mirror_emit_unit_contract.rs` test asserting unit Environment matches the const |

## MS027 — Observability module (selfdef-side)

**Catalogued:** 240 R-rows (E0271..E0280 + module rows M00683+).

**Shipped this milestone:**

| R-row range | Surface | Commits |
|---|---|---|
| E0279 (was: "Alert rules out-of-scope for v0.1") | Alert rules NOW shipped on the sovereign-os consumer side — 3 cli-mirror-specific alerts (`M060CliMirrorChainDegraded`, `M060CliMirrorChainBroken`, `M060CliMirrorObserverSilent`) + 5 existing chain-wide alerts. Pairs with the textfile metrics this repo emits. | selfdef commits `e9ab056` + `ce58154` (producers); sovereign-os commit `bf98e2a` (rules) |
| (orthogonal) | Grafana dashboard `sovereign-os-m060-cli-mirror.json` rendering selfdef's `selfdef_cli_mirror_doctor_*` series. Operator imports into Grafana via Settings → JSON Model. | sovereign-os commit `2a44536` |

## Pre-session production state (audit of shipped crates / modules / units)

The codebase carries substantial production state from prior development. This section audits the existing shipped surface per milestone — populated from the actual workspace inventory (543 crates / 188 modules / 65 SDD documents / 12 systemd units / 17 integration-test directories), not invented. Each row references real artifacts a `git ls-files | grep …` confirms.

### MS001 — Selfdef daemon core

| Surface | Shipped artifact |
|---|---|
| `selfdef-core` | `crates/selfdef-core/` — core types |
| `selfdef-daemon` | `crates/selfdef-daemon/` — `selfdefd` binary + integration tests under `crates/selfdef-daemon/tests/` |
| `selfdef-bus` | `crates/selfdef-bus/` — event bus |
| `selfdef-config` | `crates/selfdef-config/` — toml schema + parser |
| `selfdef-api` | `crates/selfdef-api/` — HTTP/UNIX `/v1/*` surface + `/metrics` |
| `selfdef-cli` | `crates/selfdef-cli/` — `selfdefctl` binary |
| `selfdef-store` | `crates/selfdef-store/` — sqlite-backed event store |
| `selfdef-signing` | `crates/selfdef-signing/` — MS003 verify-only |
| Packaging | `packaging/systemd/selfdefd.service` + `packaging/debian/postinst`/`postrm` |

### MS002 — Collector fabric

| Surface | Shipped artifact |
|---|---|
| Collectors (10+) | `crates/selfdef-collector-{auditd,journald,tetragon,suricata,ebpf,eventstream,canary,arming-state,budget-guard,coalescing,jitter-policy,quarantine-ledger}` |
| eBPF common | `crates/selfdef-ebpf-common/` |

### MS003 — Correlator + store + responder + signing

| Surface | Shipped artifact |
|---|---|
| Correlator | `crates/selfdef-correlator/` — time-windowed rules pipeline |
| Store | `crates/selfdef-store/` |
| Responder | `crates/selfdef-responder/` |
| Signing | `crates/selfdef-signing/` — minisign-verify integration |

### MS004 — 14 notifier integrations (saturated 14/14)

| Surface | Shipped artifact |
|---|---|
| Integrations | `crates/selfdef-integration-{discord,loki,ntfy,opensearch,oracle-triage,pagerduty,shared-audit-summary,signal,slack,smtp,thehive,twilio,wall,write}` — 14 crates |

### MS005 — Notifier engine + orchestrator

| Surface | Shipped artifact |
|---|---|
| Engine | `crates/selfdef-notifier-engine/` |
| Orchestrator | `crates/selfdef-notifier-orchestrator/` |

### MS006 — 14 functional modules

| Surface | Shipped artifact |
|---|---|
| Module library | `modules/` (188 modules — superset of the 14 catalogued in MS006) including `agent-guard`, `bitnet-gpu-inference`, `bridge-l2`, `detect-host`, `hardware-tune-cache`, `integrity-sentinel`, `observability`, `polarproxy`, `slm-cpu-loop`, `suricata`, `tensor-parallel-inference`, `tetragon`, `vpn-bridge`, `wasm-aot-cache` |

### MS007 — Cross-repo typed-mirror crates (SATURATED beyond 8 of 8)

| Surface | Shipped artifact |
|---|---|
| Typed-mirror crates (14) | `crates/selfdef-{audit,capability,cli,friction-audit,grants,guardian,perimeter,profile,quarantine,rules,sandbox,scheduler,trust-score,tui}-mirror` |

### MS010 — Hardware-aware modules + tune surface

| Surface | Shipped artifact |
|---|---|
| Hardware probe | `crates/selfdef-hardware/` + `crates/selfdef-hardware-requirements/` |
| Tune modules | `modules/auditd-tune`, `modules/journal-tune`, `modules/sudo-tune`, `modules/hardware-tune-cache` |

### MS016 — eBPF programs + Tetragon TracingPolicies

| Surface | Shipped artifact |
|---|---|
| eBPF collector | `crates/selfdef-collector-ebpf/` + `crates/selfdef-ebpf-common/` |
| TracingPolicies | `packaging/tetragon-policies/sovereign-perimeter.yaml` |

### MS017 — agent-guard

| Surface | Shipped artifact |
|---|---|
| Module | `modules/agent-guard/` — k8s pod-label RBAC + TracingPolicies |

### MS027 — Observability module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/observability/` — Prometheus scrape config + Grafana dashboard renderer |
| Daemon metrics | `crates/selfdef-api/src/metrics.rs` — Prometheus exposition |
| Newly closed E0279 | Alert rules on sovereign-os side (per-session commits — see "Shipped this milestone" above) |

### MS037 — Filesystem boundary

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-filesystem-boundary/` |

### MS038 — Network boundary

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-network-boundary/` |

### MS044 — Guardian Daemon

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-guardian/` + `crates/selfdef-guardian-mirror/` |
| Systemd unit | `packaging/systemd/selfdef-guardian.service` |
| Postinst+postrm | Guardian unit lifecycle handled in `packaging/debian/postinst` + `packaging/debian/postrm` |

### MS046 — Friction Audit System

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-friction-audit/` + `crates/selfdef-friction-audit-mirror/` |
| Systemd unit | `packaging/systemd/sovereign-guard.service` |
| Bash script | `packaging/scripts/friction-audit.sh` |
| SDD | `docs/sdd/027-friction-audit-system.md` |

### MS047 — Real-Time Security Perimeter Engine

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-perimeter/` + `crates/selfdef-perimeter-mirror/` |
| TracingPolicy | `packaging/tetragon-policies/sovereign-perimeter.yaml` |
| SDD | `docs/sdd/028-perimeter-engine.md` |

### MS048 — Goldilocks Scheduler

| Surface | Shipped artifact |
|---|---|
| Crates | `crates/selfdef-scheduler/` + `crates/selfdef-scheduler-mirror/` + `crates/selfdef-fair-share-scheduler/` + `crates/selfdef-recurring-task-scheduler/` |
| Systemd unit | `packaging/systemd/selfdef-scheduler.service` |
| SDD | `docs/sdd/031-goldilocks-scheduler.md` |

## Other catalogued milestones — production-shipped state TBD

MS008, MS009, MS011-MS015, MS018-MS026, MS028-MS036, MS039-MS043 (other rows), MS045 — these milestones have catalogue rows in `backlog/milestones/MS*.md` but the corresponding production-shipped audit hasn't been done yet in this file. The 65 SDD documents in `docs/sdd/` cover most of these (SDDs ship as part of the surface) — future audits append per-milestone rows above.

The above per-milestone shipped audit is a SAMPLED snapshot, not a complete production-state survey. The trajectory: each commit that lands or audit cycle that runs appends rows here so the SHIPPED column converges toward the catalogue total as the multi-year project progresses.

## How this file is maintained

1. **Every production commit** that lands a catalogued R-row appends a row to the relevant milestone section above with: R-row range, surface description, commit hash(es), tests added, packaging delta.
2. **No invention** — every row references real commits + tests + assets. Audits cross-check against `git log` + the Cargo.toml deb-assets array + `tests/` directory.
3. **Never marks done** what isn't in production — the operator's R10081 constraint is sacrosanct. Half-shipped (e.g. code without tests, code without packaging) gets a parenthetical "partial — pending X" note, not a "shipped" row.

This file pairs with sovereign-os's parallel `backlog/SHIPPED.md` for consumer-side surfaces. Both repos' INDEX + SHIPPED files together give the operator the catalogue-vs-shipped delta at any commit.
