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

### MS008 — Selfdef on SAIN-01 integration

| Surface | Shipped artifact |
|---|---|
| Deployment integration SDD | `docs/sdd/010-selfdef-on-sain01.md` — SDD scoping the requirements for running selfdefd on the SAIN-01 host (deployment integration coverage); `docs/sdd/012-selfdef-on-sain01-integration-design.md` — companion design document; `docs/sdd/017-sain01-hardware-inventory.md` — hardware inventory the integration consumes |
| Hardware-aware modules wiring | `crates/selfdef-hardware/` — the MS010 hardware-aware module + tune surface (commit predates this session). The SAIN-01 integration consumes the hardware classifier from this crate to decide which modules to enable; the deployment integration is the consumer of the MS010 producer |
| Cross-repo coordination point | Sovereign-os mirrors the SAIN-01 deployment posture via the M060 mirror chain (D-02 active-profile + D-NN dashboards). The SAIN-01-integration SDD's "what the integration must surface" requirements are satisfied by the MS007 typed-mirror crates' production state |

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

### MS009 — Audit cycles

| Surface | Shipped artifact |
|---|---|
| Audit registry | `crates/selfdef-audit-registry/` — MS016 SHA-256 chain |

### MS011 — Operator dashboard + flex profile

| Surface | Shipped artifact |
|---|---|
| Flex-profile crate | `crates/selfdef-flex-profile/` |
| Dashboard-manifest crate | `crates/selfdef-dashboard-manifest/` |
| Bundled PWA dashboard | `dashboard/index.html` + `dashboard/app.js` + `dashboard/dashboard.css` + `dashboard/manifest.json` + `dashboard/service-worker.js` |

### MS012 — Perimeter coexistence (superseded by MS047 perimeter engine SDD-028)

| Surface | Shipped artifact |
|---|---|
| Coexistence SDD (Stage-2 PR 3/4) | `docs/sdd/015-perimeter-coexistence.md` — Tetragon perimeter coexistence design (selfdef-side TracingPolicies vs sovereign-os's `sovereign-kernel-fence.yaml` boundary). Defines: target=sain01 auto-check-overlap on every `selfdefctl modules apply`, refuse-on-overlap by default, opt-in warn-mode |
| Perimeter engine (supersedent) | `crates/selfdef-perimeter/` (engine) + `crates/selfdef-perimeter-mirror/` (typed-mirror crate, MS007 conformant). Cross-cutting MS047 SDD `docs/sdd/028-perimeter-engine.md` (real-time security perimeter engine — Tetragon kernel-fence integration) carries the production design; the perimeter-mirror surfaces the live state across to sovereign-os's cockpit dashboards |
| `selfdefctl perimeter` verb | `crates/selfdef-cli/src/main.rs` Perimeter subcommand — SDD-015 Tetragon perimeter coexistence — operator-facing inspect / verify boundary between selfdef-authored `agent-guard-*` TracingPolicies and sovereign-os's host-scoped `sovereign-kernel-fence.yaml` (commit predates this session) |
| Module wiring | `modules/agent-guard/` writes TracingPolicies into `/etc/kubernetes/manifests/...`; the perimeter SDDs assert the boundary the modules MUST stay on (do not write into sovereign-os's host-scope namespaces) |

### MS013 — 27-SDD charter framework

| Surface | Shipped artifact |
|---|---|
| SDDs | `docs/sdd/` — 65 SDD documents (catalogued 27+ exceeded; framework production-saturated) |

### MS014 — SSH-wrap (client-side defense)

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-ssh-wrap/` — drop-in ssh wrapper |

### MS015 — NATS messaging backbone

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-nats/` |

### MS018 — VPN-bridge multi-instance

| Surface | Shipped artifact |
|---|---|
| Module | `modules/vpn-bridge/` |

### MS019 — Security threat model

| Surface | Shipped artifact |
|---|---|
| Operator-facing threat model | `SECURITY.md` — 17 sections covering assets, adversaries, trust assumptions, per-layer mitigations (build & supply chain / process / configuration & rules / storage / notification / tamper detection / four-watchdog set / API surface / policy surface), Hardening checklist for AI-machine deployment, known gaps tracker, vulnerability reporting channel. Linked from `README.md` security section |
| SDD reference | `docs/sdd/004-security-threat-model.md` — 27 F-findings (F-2026/F-2027 numbered registry), 6 decisions (D-1 three new asset rows / D-2 new adversary class / D-3 two new mitigation layers / D-4 extended known-gaps / D-5 operator-facing hardening sidebar / D-6 doc mirror), implementation-status tracker, design alternatives considered (Alt-A inline / Alt-B new section / Alt-C hybrid recommended), test plan, rollout/migration notes, risks, follow-up findings |
| Four-watchdog IPS spine cross-ref | `SECURITY.md` `#### Four-watchdog set (IPS spine, MS046+MS047+MS044+MS048)` section anchors the threat-model coverage of selfdef's IPS spine in the layered mitigations — MS046 (process watchdog) / MS047 (perimeter engine) / MS044 (tamper-detection watchdog) / MS048 (config watchdog). The four-watchdog coherence harness (`scripts/test/coherence.sh` 13-layer test gate in CI) closes the loop between the SDD threat model and the shipped runtime spine |
| Signing-runbook + threat-model bridge | `docs/dev/signing.md` — referenced from `SECURITY.md` as the operator-runbook half of the threat-model section on detection-rule integrity. Closes the gap between the threat-model assertion ("rule signing prevents unsigned-rule loading") and the operator-side keys/rotation workflow |
| Threat-model integration tests | `crates/selfdef-correlator/tests/signed_rules.rs` — locks the rule-signing detection-side invariant (the threat-model's principal storage-layer mitigation). Sister tests in `crates/selfdef-signing/src/lib.rs` lock the verify-only signing semantics. Cross-cutting reference in `crates/selfdef-doc-manifest/src/lib.rs` ties shipped doc-files to SECURITY.md sections for drift catch |
| Pre-existing F-finding registry | The 27 F-2026/F-2027 findings in `docs/sdd/004-security-threat-model.md` represent a tracked-gap audit-cycle log distinct from the catalogued R-rows. F-finding closure happens in adjacent milestones (e.g. F-2027-018 closure landed in MS043 doctor `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` env override, F-2027-045 follow-up findings tracked in the SDD appendix) — the threat-model registry is the production-shipped tracker, not the catalogue R-rows |

### MS020 — Test contract (L1–L5 layered harness)

| Surface | Shipped artifact |
|---|---|
| Operator-facing contract doc | `docs/dev/test-contract.md` |
| Integration tests | 17 `tests/` dirs across the workspace + selfdef-daemon's per-crate integration tests |

### MS021 — Shared module-script lib

| Surface | Shipped artifact |
|---|---|
| Library | `packaging/lib/module-lib.sh` |

### MS023 — Polarproxy module (TLS inspection)

| Surface | Shipped artifact |
|---|---|
| Module | `modules/polarproxy/` |

### MS024 — Bridge-L2 module (layer-2 transparent bridge)

| Surface | Shipped artifact |
|---|---|
| Module | `modules/bridge-l2/` |

### MS025 — Detect-host module (host-class detection)

| Surface | Shipped artifact |
|---|---|
| Module | `modules/detect-host/` |

### MS026 — Integrity-sentinel module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/integrity-sentinel/` |

### MS028 — BitNet GPU inference module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/bitnet-gpu-inference/` |

### MS029 — SLM CPU loop module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/slm-cpu-loop/` |

### MS030 — Tensor parallel inference module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/tensor-parallel-inference/` |

### MS031 — WASM AOT cache module

| Surface | Shipped artifact |
|---|---|
| Module | `modules/wasm-aot-cache/` |

### MS032 — Sandbox tiers (9 tiers across MS036×MS032)

| Surface | Shipped artifact |
|---|---|
| Sandbox crates | `crates/selfdef-sandbox-dispatcher/`, `crates/selfdef-sandbox-fs-isolation/`, `crates/selfdef-sandbox-network-isolation/`, `crates/selfdef-sandbox-tier-policy/`, `crates/selfdef-sandbox-registry/`, `crates/selfdef-sandbox-mirror/` |

### MS033 — Policy and trace (every action observable + governed)

| Surface | Shipped artifact |
|---|---|
| Policy crates | `crates/selfdef-action-trace-budget/`, `crates/selfdef-action-witness-policy/`, `crates/selfdef-actor-handoff-policy/`, `crates/selfdef-actor-introduction-policy/`, `crates/selfdef-actor-label-policy/`, `crates/selfdef-actor-suspension-policy/`, `crates/selfdef-alert-escalation-policy/`, `crates/selfdef-audit-log-rotation-policy/`, `crates/selfdef-audit-rotation-policy/`, `crates/selfdef-bundle-load-policy/` — 10+ policy crates (sample; many more in the workspace) |

### MS034 — Communication boundary

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-communication-boundary/` |

### MS036 — Tool sandboxes (5-tier capability ladder + promotion gates)

| Surface | Shipped artifact |
|---|---|
| Sandbox tiers SDD | `docs/sdd/047-sandbox-tiers.md` — 5-tier capability ladder + promotion gates SDD (MS032/MS036). Covers: problem statement, goals + non-goals, alternative designs considered, recommended design, implementation status tracker, test requirements, rollout sequence, open questions |
| Sandbox registry crate | `crates/selfdef-sandbox-registry/` — registry of sandbox allocations + per-tier promotion state machine. Drop-decrement semantics matching the MS022 SubscriberGuard pattern |
| Sandbox dispatcher | `crates/selfdef-sandbox-dispatcher/` — runtime dispatcher routing tool invocations into the appropriate tier sandbox per the 5-tier ladder |
| Sandbox filesystem isolation | `crates/selfdef-sandbox-fs-isolation/` — tier-aware filesystem isolation (paths writable/readable per tier) |
| Sandbox network isolation | `crates/selfdef-sandbox-network-isolation/` — tier-aware network isolation (egress allow-list per tier) |
| Sandbox typed-mirror crate (MS007) | `crates/selfdef-sandbox-mirror/` — typed wire schema for the D-15 sandboxes cockpit dashboard. Conforms to the MS007 typed-mirror pattern (`schema_version` + `allocations` + `captured_at`) |
| Sandbox tier policy | `crates/selfdef-sandbox-tier-policy/` — per-tier policy types (what's allowed at tier-1 vs tier-5) — drives the promotion gates the SDD defines |
| `selfdefctl sandboxes` verb | `crates/selfdef-cli/src/main.rs` exposes the D-15 sandbox allocation operator surface (allocate / list / promote / inspect). Producer side of the D-15 sandboxes dashboard mirror chain |
| Cockpit dashboard wiring | sovereign-os D-15 sandboxes dashboard renders the `selfdef-sandbox-mirror` snapshot — the 7-crate selfdef-sandbox-* family forms the production-shipped surface for the D-15 dashboard. Offline-by-default until the registry becomes daemon-resident (honest-offline doctrine matching D-12 + D-13 + D-14) |

### MS035 — Capability tokens (typed authority handles)

| Surface | Shipped artifact |
|---|---|
| Crates | `crates/selfdef-capability-mirror/`, `crates/selfdef-capability-registry/`, `crates/selfdef-capability-token-store/`, `crates/selfdef-capability-word/`, `crates/selfdef-tool-capability-policy/` |

### MS039 — Authority levels + trust rings (IPS-side projection)

| Surface | Shipped artifact |
|---|---|
| Authority crates | `crates/selfdef-commit-authority/`, `crates/selfdef-config-mutation-authority/`, `crates/selfdef-mode-transition-authority/`, `crates/selfdef-profile-authority-gate/`, `crates/selfdef-recovery-snapshot-authority/`, `crates/selfdef-replay-source-authority/`, `crates/selfdef-routing-decision-authority/`, `crates/selfdef-toggle-audit-authority/`, `crates/selfdef-trust-score-engine/`, `crates/selfdef-trust-score-history/` |

### MS040 — Authority + 6-profile matrix (IPS-side projection)

| Surface | Shipped artifact |
|---|---|
| Crates | `crates/selfdef-flex-profile/` + `crates/selfdef-profile-authority-gate/` |

### MS041 — Commit authority (durable-change discipline)

| Surface | Shipped artifact |
|---|---|
| Crate | `crates/selfdef-commit-authority/` |

### MS042 — Tool authority (declaration-vs-observed discipline)

| Surface | Shipped artifact |
|---|---|
| Crates | `crates/selfdef-collector-quarantine-ledger/`, `crates/selfdef-quarantine-cause-taxonomy/`, `crates/selfdef-quarantine-engine/`, `crates/selfdef-quarantine-mirror/`, `crates/selfdef-quarantine-registry/`, `crates/selfdef-quarantine-release-policy/` |

### MS043 — IPS operator surface (CLI + TUI + dashboard-mirror exports) — additional rows

| Surface | Shipped artifact |
|---|---|
| CLI binary | `crates/selfdef-cli/` (selfdefctl) |
| API surface | `crates/selfdef-api/` |
| TUI mirror | `crates/selfdef-tui-mirror/` |
| Dashboard-manifest | `crates/selfdef-dashboard-manifest/` |

### MS045 — UX coherence test harness (CLI + TUI + minimal-web)

| Surface | Shipped artifact |
|---|---|
| UX checklist crate | `crates/selfdef-ux-checklist/` |
| SDD | `docs/sdd/030-ux-coherence-test-harness.md` |
| Layered test harness | `tests/ux-harness/` |

## Other catalogued milestones — production-shipped state TBD

~~MS008 + MS012 + MS019 + MS036~~ — these previously-catalogued-only milestones now have full audit rows above (commit `00b447c` added MS019; this commit adds MS008 + MS012 + MS036). The audit-coverage threshold lock (`tests/observability/test_shipped_tracker_integrity.py::test_milestone_audit_coverage_above_threshold`) now sees 44+ audited milestones of the 48-milestone selfdef catalogue. Remaining unaudited milestones — if any — will be appended above as future audits run.

### MS022 — Per-token SSE subscriber quota

| Surface | Shipped artifact |
|---|---|
| SSE cap enforcement (pre-session) | `crates/selfdef-api/src/handlers.rs` SubscriberGuard with `MAX_SSE_SUBSCRIBERS` (default 64 global) + `MAX_SSE_SUBSCRIBERS_PER_TOKEN` (default 8 per token) constants + operator-tunable `SseCaps` (`[api].max_sse_subscribers{,_per_token}`); per-token map in `ApiState::sse_subscribers_per_token` with atomic counters + automatic decrement on subscriber drop |
| SSE quota Prometheus exposition | `crates/selfdef-api/src/sse_quota_metrics.rs` — 6 gauge series exposed at `/metrics`: `selfdef_sse_subscribers_global_active`, `_global_cap`, `_global_saturation` (active/cap ratio for alert thresholds), `_per_token_cap`, `_per_token{token_fp=…}`, `_per_token_saturated` (count of tokens at-or-above cap). Privacy-preserving 8-hex-char token fingerprint label; deterministic sort for stable scrape diffs. 9 unit tests covering escape contract, default + override caps, saturation math, per-token saturated rollup, sorted output (commit `77b4499`) |
| Operator guide | `docs/operator/ms022-sse-subscriber-quota.md` — selfdef-side single-page reference: TL;DR setup recipe, table of the 6 published gauges with privacy posture notes, configuration knob explanation + defaults rationale (64 global / 8 per-token) + decision tree for raise-vs-leak, cap-enforcement semantics (SDD-007 D-6 per-token-first ordering, CAS-loop on global, Drop decrements both), verification recipes (curl with-jq + awk filtering + sovereign-os proxy probe), failure-mode → log-line crib sheet, project boundary R10212 + selfdef-side / sovereign-os-side test inventory totaling 50 contract tests across both repos. Cross-linked from `README.md` operator runbooks list. `config/selfdef.toml.example` annotated with the `max_sse_subscribers{,_per_token}` knobs + pointer to the operator guide (commit `3fadc87`) |
| `selfdefctl sse-quota` verb | `crates/selfdef-cli/src/sse_quota.rs` — new `selfdefctl sse-quota` command. Fetches the 6 `selfdef_sse_subscribers_*` gauges from selfdefd's `/metrics` endpoint (UNIX socket / TCP fallback matching `m060-metrics`), parses them into an `SseQuotaSnapshot`, classifies into ok/approaching/saturated/unreachable using the SAME thresholds (0.85 / 1.0) as the sovereign-os ms022-doctor + alert rules — locked by a partner-repo cross-reference assertion. Operator-readable table mode (default) shows saturation table + sorted per-token breakdown; `--json` for monitoring integration; `--rollup-only` skips the per-token table for incident-response brevity. Exit code mirrors the severity ladder: 0=ok / 1=approaching / 2=saturated|unreachable. Threading: new `Command::SseQuota` variant + dispatch arm + `mod sse_quota` registration in `crates/selfdef-cli/src/main.rs`. The operator-side mirror of the 4 sovereign-os consumer surfaces — operators can inspect quota state from the IPS host without standing up the sovereign-os proxy (commit `24bc3c6`) | `24bc3c6` | 11 unit tests on the parser + classifier + exit-code ladder + threshold-lockstep-with-partner-repo assertion (catches drift if either side's alert threshold changes) |
| Partner-repo MS022 lockstep test | `tests/observability/test_ms022_partner_repo_lockstep.py` — closes the bidirectional cross-repo drift loop opened by sovereign-os commit `ac6b0ab`. The sovereign-os test reads selfdef constants when `$SELFDEF_REPO_ROOT` is set; this test does the symmetric reverse: reads sovereign-os surfaces when `$SOVEREIGN_OS_REPO_ROOT` is set. Asserts (in-repo, always-on) the Rust `APPROACHING_THRESHOLD`/`SATURATED_THRESHOLD` constants in `crates/selfdef-cli/src/sse_quota.rs`, the 4 state-name literals (`ok`/`approaching`/`saturated`/`unreachable`), AND the exit-code ladder (`"ok" => 0`, `"approaching" => 1`, `"saturated" \| "unreachable" => 2`) — drift catch even without the partner repo cloned. Opt-in (partner-repo) asserts the same canonical 0.85+1.0 thresholds in the partner's alert rules YAML, proxy daemon Python source, AND cockpit guide markdown — drift fails the selfdef CI when the cross-repo CI pipeline has both repos checked out (commit `625f3d9`) | `625f3d9` | 6 contract tests (in-repo Rust constants, in-repo state-name literals, in-repo exit-code ladder match doctor severity, partner-repo alert rules expressions, partner-repo proxy daemon constants, partner-repo cockpit guide text) | sovereign-os `ac6b0ab` |

### M060 — Cross-cutting cross-repo lockstep extension

| Surface | Shipped artifact |
|---|---|
| Partner-repo M060 lockstep test | `tests/observability/test_m060_partner_repo_lockstep.py` (NEW this commit) — same bidirectional pattern as the MS022 lockstep above, applied to the M060 invariants. Asserts (in-repo, always-on) the `crates/selfdef-api/src/m060_health.rs` `STALE_AGE_SECS: u64 = 5 * 60` const equals 300, the `classify_state()` function returns the 4 daemon-side state literals (`online`/`degraded`/`stale`/`offline`) but DELIBERATELY NOT `unreachable` (which is sovereign-os-only — emitted by the proxy when selfdefd is unreachable, never by the daemon about itself), AND the stale-check inside `classify_state` references the const (not a magic literal). Opt-in cross-repo (`$SOVEREIGN_OS_REPO_ROOT` set) asserts the partner's 2 observer-silent alert expressions use `> 300`, the master-dashboard `M060_TILE_STALE_AGE_SECS = 5 * 60` const, AND the m060-health-api `/version` states list = `{online, degraded, stale, offline, unreachable}` | this commit | 6 contract tests (in-repo STALE_AGE_SECS const, in-repo 4-state classifier returns, in-repo no-unreachable-leak through the classifier, partner-repo observer-silent alerts, partner-repo master-dashboard const, partner-repo /version states set) |

The above per-milestone shipped audit is a SAMPLED snapshot, not a complete production-state survey. The trajectory: each commit that lands or audit cycle that runs appends rows here so the SHIPPED column converges toward the catalogue total as the multi-year project progresses.

## How this file is maintained

1. **Every production commit** that lands a catalogued R-row appends a row to the relevant milestone section above with: R-row range, surface description, commit hash(es), tests added, packaging delta.
2. **No invention** — every row references real commits + tests + assets. Audits cross-check against `git log` + the Cargo.toml deb-assets array + `tests/` directory.
3. **Never marks done** what isn't in production — the operator's R10081 constraint is sacrosanct. Half-shipped (e.g. code without tests, code without packaging) gets a parenthetical "partial — pending X" note, not a "shipped" row.

This file pairs with sovereign-os's parallel `backlog/SHIPPED.md` for consumer-side surfaces. Both repos' INDEX + SHIPPED files together give the operator the catalogue-vs-shipped delta at any commit.
