# Findings ledger

> Master index of every finding raised in Phase 1. Per-area
> findings (`M-`, `C-`, `I-`, `D-`, `T-`, `R-`, `S-`) are
> consolidated here as canonical `F-2026-NNN` ids.
>
> Each row carries the canonical id, the severity, the surface,
> a one-line summary, and a recommended **next phase** label:
>
> - `investigate` — root cause not fully understood yet; Phase
>   2 reads code / runs experiments.
> - `design` — root cause is clear; Phase 2 produces an SDD.
> - `implement` — root cause is clear and the fix is small;
>   Phase 2 implements directly with a short rationale doc.
> - `doc` — pure documentation drift; Phase 2 updates the
>   relevant doc file.
>
> Severity:
> - `blocker` — the artifact's central promise fails for the
>   documented use case.
> - `important` — works but a documented promise isn't honoured.
> - `nice` — polish.
> - `SDD-debt` — undocumented design decision with downstream
>   consequences.

---

## Blocker findings (5)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2026-001 | blocker | `crates/selfdef-collector-tetragon/src/lib.rs` | Every Tetragon event hardcodes `SeverityId::Informational`. Policy `selfdef.io/severity` annotation is ignored. *(was I-007)* | design — **closed** by SDD-001 implementation PR (collector now attaches structured `raw.tetragon.{policy_name,policy_namespace,action,function_name}`; severity stays Informational at the collector layer per the SDD's "collectors are dumb translators" invariant — promotion happens in the sigma rule below) |
| F-2026-002 | blocker | `rules/sigma/` | No correlator rule promotes Tetragon agent-guard events to `category_uid = Findings`. Responder never fires `NotifyAction`. *(was I-008)* | design — **closed** by SDD-001 implementation PR (`rules/sigma/hardening/agent_guard_violation.yml` matches `raw.tetragon.policy_name|startswith "selfdef-agent-"` + `action|in [Sigkill, Override, NotifyKiller]`, promotes to `level: high`; corpus covers Sigkill / NotifyKiller / Post-negative / non-agent-guard-negative / non-tetragon-source-negative) |
| F-2026-003 | blocker | `modules/tetragon/README.md` + default profile comment | README points at the wrong collector (`[collectors.eventstream]` instead of `[collectors.tetragon]`). Events silently dropped. *(was I-006)* | doc — **closed** by SDD-001 implementation PR (`modules/tetragon/README.md` now names `[collectors.tetragon]` and ships a paste-ready snippet; reciprocal note on the eventstream collector being wrong is explicit) |
| F-2026-004 | blocker | `selfdef-config EventstreamConfig::default` + `ApiConfig::default` | Default daemon config disables every collector and the API. Modules' "out of the box" promises (drift→notifier, Prometheus scrape) require manual bridging the documentation doesn't surface. *(was I-002, I-004)* | design — **closed** by SDD-002 implementation PR (the bridge is now a manifest-level contract: every active module's `[daemon_requires]` is checked against `/etc/selfdef/selfdef.toml` before any apply.sh fires; mismatch prints a copy-pasteable snippet and exits 2 unless `--ignore-daemon-requires` is set) |
| F-2026-005 | blocker | `modules/vpn-bridge/install/profiles/*.sh` | `instanced = true` declared in manifest; profile scripts use hard-coded state paths. Multi-instance host silently corrupts state. *(was M-008, S-007)* | design — **closed** by SDD-003 implementation PR (manifest now declares per-profile `instanced` capability via `[profiles.details.<name>]`; resolver refuses `vpn-bridge#<inst>` for singleton profiles before any script runs; `relay-via-server` parameterises iface / nftables table / nftables state-file by `${SELFDEF_INSTANCE_ID}`; `tailscale` + `cloudflare-tunnel` `die` defence-in-depth when the resolver is bypassed) |
| F-2026-006 | blocker | daemon integration tests | No AI-machine end-to-end test (policy fires → operator alert). F-2026-001 + F-2026-002 would have been caught by such a test. *(was T-008)* | implement — **closed** by SDD-001 implementation PR (`crates/selfdef-daemon/tests/m_ai_machine.rs` runs Tetragon JSON through collector + correlator and asserts a Detection Finding lands with severity High; negative-case Post line is rejected) |

---

## Important findings (22)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2026-010 | important | `modules/agent-guard/install/apply.sh` | tetragon `policy_dir` discovery depends on `SELFDEF_TETRAGON_CONFIG`; silent fallback to hard-coded path. *(was M-002)* | design |
| F-2026-011 | important | `modules/tetragon/install/apply.sh` | `event_log_path` alignment with daemon eventstream is operator-managed; no apply-time surface or check. *(was M-004)* | design |
| F-2026-012 | important | `modules/observability/` | Three different defaults for `scrape_targets` across README, both profile files, apply.sh fallback. *(was M-005)* | doc — **closed** by doc-sweep PR |
| F-2026-013 | important | `modules/observability/README.md` | Dashboard depends on selfdef-daemon `/metrics`; README only mentions Tetragon. *(was M-006)* | doc — **closed** by doc-sweep PR |
| F-2026-014 | important | every module using the event bus | No `depends_on = ["detect-host"]` declared; consume-side of detect-host's `provides = ["event-bus"]` is silent. *(was M-009)* | design |
| F-2026-015 | important | `selfdef-config CorrelatorConfig::window_secs / threshold` | Dead config knobs — exposed but never read. Sigma rules carry their own. *(was C-002)* | implement — **closed** by dead-knob cleanup PR (rustdoc-marked vestigial; commented out in `selfdef.toml.example`) |
| F-2026-016 | important | `selfdef-config StoreConfig::hot_retention_days` + `selfdef-store` | Dead knob — retention horizon exposed but no sweeper enforces it. *(was C-003)* | design — **closed** by SDD-081 (hot-store retention sweep): `selfdef-store::SqliteStore::prune_older_than` deletes events past the horizon; `selfdef-daemon::retention_sweep_loop` runs an initial sweep at startup + every 6h, computing `cutoff = now - hot_retention_days` and logging pruned/remaining counts. `hot_retention_days=0` = explicit opt-out (keep forever). Tests: store prune (idempotent) + daemon `sweep_once` (prunes past horizon / keeps fresh). |
| F-2026-017 | important | `selfdef-store/src/sqlite.rs:106` | Duplicate `const SCHEMA_VERSION: u32 = 1` instead of referencing `selfdef_core::SCHEMA_VERSION`. *(was C-005)* | implement — **closed** by dead-knob cleanup PR (now imports `selfdef_core::SCHEMA_VERSION`) |
| F-2026-018 | important | `modules/integrity-sentinel/profiles/*.toml` | `event_stream_path` commented out in shipped profiles. *(was I-001)* | implement — **closed** by SDD-002 implementation PR (both strict.toml and warn-only.toml ship with the path live by default; the manifest's `[daemon_requires]` ensures the daemon-side collector path is set before apply proceeds) |
| F-2026-019 | important | `modules/observability/README.md` | Prometheus bearer-token auth on TCP `/metrics` is undocumented. Scrape will 401. *(was I-005)* | doc — **closed** by doc-sweep PR |
| F-2026-020 | important | repo-wide (packaging + module READMEs) | No bundled `selfdef.toml` template for "three modules with sane defaults". *(was I-009)* | design — **closed** by SDD-002 implementation PR (defaults bridge is now per-module via `[daemon_requires]` + `selfdefctl modules show-requires`; bundled templates can ship later as syntactic sugar over the manifest contract per SDD-002's appendix) |
| F-2026-021 | important | `README.md` line 7 | "Milestone 1 — Scaffolding only" status banner is false. *(was D-001)* | doc — **closed** by doc-sweep PR |
| F-2026-022 | important | `ARCHITECTURE.md` | `/metrics` endpoint and the module catalog (AI-machine track) missing from the architecture description. *(was D-003, D-004)* | doc — **closed** by doc-sweep PR |
| F-2026-023 | important | `SECURITY.md` (and mirror) | `/metrics` endpoint not in threat model. Token rotation lifecycle unspecified. *(was D-005, S-002)* | design — **closed** by SDD-004 implementation PR (`/metrics` row in Assets table; API surface mitigations cover transport / read-cap / token-rotation lifecycle; metrics-token rotation tracked as a Known gap follow-up) |
| F-2026-024 | important | `SECURITY.md` | `/etc/tetragon/tetragon.tp.d/` writable directory not in threat model — eBPF policy injection vector. *(was D-006, S-001)* | design — **closed** by SDD-004 implementation PR (TracingPolicy directory row in Assets table; Policy surface mitigations cover ownership + integrity-sentinel baseline; signing tracked as a Known gap follow-up) |
| F-2026-025 | important | `SECURITY.md` | Pod-label scope reliance on k8s label RBAC not in threat model. *(was D-007, S-003)* | design — **closed** by SDD-004 implementation PR (Adversary class 6 "Cluster-tenant attacker"; Policy surface mitigations document the required RBAC posture; cluster control plane added to Trust assumptions) |
| F-2026-026 | important | `SECURITY.md` | Eventstream JSONL paths are a trust boundary; no documented ownership / mode requirements. *(was S-004)* | design — **closed** by SDD-004 implementation PR (Eventstream JSONL row in Assets table; Policy surface mitigations enumerate the per-path trust posture; daemon-side ownership/mode check at parse time tracked as a Known gap follow-up) |
| F-2026-027 | important | `docs/src/{dev,ops}/*.md` | Five stub pages linked from `SUMMARY.md` are one-line TODOs. *(was D-009)* | doc — **closed** by doc-sweep PR |
| F-2026-028 | important | `docs/api.md`, `docs/ebpf.md`, `docs/nats.md`, `docs/ssh-wrap-install.md` | Real operational guides orphaned from mdbook outline. *(was D-010)* | doc — **closed** by doc-sweep PR (files moved into `docs/src/{ops,dev}/`) |
| F-2026-029 | important | `docs/src/modules.md:202-207` | Stale claim that only `detect-host` ships. *(was D-011)* | doc — **closed** by doc-sweep PR |
| F-2026-030 | important | every `module_*.rs` integration test | Dry-run mode not negatively asserted — a regression making `SELFDEF_DRY_RUN=1` mutate state would pass every existing test. *(was T-003)* | implement — **fully closed** by SDD-005 reference (`module_vpn_bridge.rs`) + the 7-module dry-run-noop migration follow-up PR (agent-guard, bridge-l2, integrity-sentinel, observability, polarproxy, suricata, tetragon all now carry a `dry_run_apply_must_be_a_noop_on_disk` test using the shared `snapshot_tree` + `assert_tree_unchanged` helpers) |
| F-2026-031 | important | `m12_api.rs:469-482` | `/metrics` content-type and exposition body checks too loose. *(was T-005)* | implement — **closed** by SDD-005 implementation PR (new strict `mod prom` parser + `metrics_exposition_passes_format_strict_parse` test) |
| F-2026-032 | important | `m12_api.rs` | No test that `/metrics` is accessible with a Read-only token. *(was T-006)* | implement — **closed** by SDD-005 implementation PR (`metrics_allows_read_capability` test) |
| F-2026-033 | important | `selfdef-correlator/tests/` | No SIGHUP-while-processing test. Hot-reload claim from ARCHITECTURE.md is unverified under traffic. *(was T-007)* | implement — **closed** by SDD-005 implementation PR (`hot_reload.rs::correlator_swaps_rules_atomically_under_live_traffic` + `..._keeps_prior_set_on_parse_failure`) |
| F-2026-034 | important | `selfdef-store` | No concurrent-insert or crash-recovery test. *(was T-009)* | implement — **closed** by SDD-005 implementation PR (`tests/concurrent.rs` × 3 tests covering both contracts) |
| F-2026-035 | important | `selfdef-nats` | No real-broker round-trip test. JetStream durability promises unverified. *(was T-010)* | implement — **closed** by SDD-005 implementation PR (`tests/integration.rs` spawns a real `nats-server`; `#[ignore]`-gated so CI without the binary stays green) |
| F-2026-036 | important | `selfdef-collector-tetragon` | No isolation test; every translation goes through daemon tests only. *(was T-011)* | implement — **closed** by SDD-005 implementation PR (`tests/translation.rs` × 10 tests covering every translation branch plus 3 tolerance branches; new `pub fn translate_line` surface) |
| F-2026-037 | important | CHANGELOG + PR descriptions for #21, #22, #24 | Operator outcomes are described as if end-to-end; audit reveals they aren't. *(was R-003)* | doc — **closed** by doc-sweep PR via a CHANGELOG "Honest correction" entry pointing at SDD-001 |

---

## Nice findings (12)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2026-050 | nice | `modules/agent-guard/install/uninstall.sh` | Hand-enumerated policy list; will drift if a sixth policy is added. *(was M-001)* | implement — **closed** by SDD-006 v2 follow-up PR (`packaging/lib/module-lib.sh` bumped to v2; new `module_record_file` / `module_render_files` / `module_clear_manifest` helpers; agent-guard's apply.sh records every rendered file into a per-module manifest at `/var/lib/selfdef/installed/agent-guard.manifest`; uninstall.sh iterates the manifest and falls back to the legacy enum for pre-v2 installs) |
| F-2026-051 | nice | `modules/agent-guard/install/lib.sh render_pod_scope` | Awk state machine fragile against future policy selectors. *(was M-003)* | implement — **partial close** by SDD-006 implementation PR (shared lib v1 doesn't ship YAML-aware editing; a v2 with `yq`/python helpers would close fully) |
| F-2026-052 | nice | `modules/observability/assets/dashboards/` | Hardcoded Tetragon metric name `tetragon_msg_sigkill_total` without an upstream-version pin. *(was M-007)* | investigate — **closed** by SDD-079 (Tetragon metric-name contract): the four pinned series now live in `modules/observability/assets/contracts/tetragon-metrics.toml` with a `verified_tetragon_version` window; CI test `tests/observability/test_tetragon_metric_name_contract.py` locks dashboard↔contract↔SDD↔README in lockstep; `check.sh` gained an opt-in warn-only live-endpoint series probe turning a silent flat panel into a loud warning. Fail-closed binary-version enforcement from the tetragon `requires` block remains a Phase-3 follow-up (SDD-079 D-1). |
| F-2026-053 | nice | `selfdef-config/src/lib.rs BusConfig::backend` | Dead knob — always "inproc", daemon doesn't branch on it. *(was C-001)* | implement — **closed** by dead-knob cleanup PR (rustdoc-marked vestigial; commented out in `selfdef.toml.example`) |
| F-2026-054 | nice | `selfdef-daemon/src/main.rs build_notifier_chain` | A `[notifier.ntfy]` block with no matching `"ntfy"` in `channels` silently disables ntfy without a startup warning. *(was C-004)* | implement — **closed** by follow-ups cleanup PR (warns at startup for either `ntfy` or `signal` orphan block) |
| F-2026-055 | nice | `selfdefctl events emit` | `--out` has no default. Callers must hard-code the path. *(was I-003)* | design |
| F-2026-056 | nice | `README.md` | No catalog of shipped modules in the repo-root README. *(was D-002)* | doc — **closed** by doc-sweep PR #30 (README now ships a Module catalog table) |
| F-2026-057 | nice | `CHANGELOG.md` PR #22 entry | Observability scope ("we configure, we don't install") implicit; should be explicit. *(was D-008)* | doc — **closed** by doc-sweep PR #30 (CHANGELOG "Honest correction" entry) |
| F-2026-058 | nice | `modules/vpn-bridge/README.md` | No mention of multi-instance corruption risk (F-2026-005). *(was D-012)* | doc — **closed** by nice-cluster PR (README now carries a Multi-instance caveat block referencing SDD-003) |
| F-2026-059 | nice | `panic` subcommand vs `modules uninstall` | Hostname-confirm validation duplicated; could share a helper. *(was R-001)* | implement — **closed** by follow-ups cleanup PR (`check_confirm_hostname` + `ConfirmRefusal` helper extracted; both call sites use it) |
| F-2026-060 | nice | `crates/selfdef-cli/tests/*` | Helper functions duplicated across 9 test files; refactor to `tests/common/mod.rs`. *(was T-001)* | implement — **partial close** by follow-ups cleanup PR (`tests/common/mod.rs` exists with the shared helpers; per-test migration is incremental — adopting the common module in each `module_*.rs` is a follow-up) |
| F-2026-061 | nice | `cli_modules_apply.rs:118` and similar | Substring assertions on `Summary:` lines brittle against cosmetic changes. *(was T-002)* | implement — **partial close** by follow-ups cleanup PR (`m12_api.rs` `/metrics` test now exact-matches the Content-Type, asserts each TYPE line is unique, and validates the exposition-format shape line by line; the `Summary:` substring assertions are still in the module tests and are a follow-up) |
| F-2026-062 | nice | per-module test suites | Idempotent-reapply coverage is tetragon-only. *(was T-004)* | implement — **partial close** by follow-ups cleanup PR (agent-guard now has a byte-stable reapply test; bridge-l2 / suricata / polarproxy / vpn-bridge follow-up) |
| F-2026-063 | nice | `selfdef-responder` | No isolation test for action dispatch / dry-run / unknown action. *(was T-012)* | implement |
| F-2026-064 | nice | `rules/sigma/` + `tests/replay/` | No audit of rule ↔ corpus coverage. *(was T-013)* | implement |
| F-2026-065 | nice | `selfdefctl events emit` (security view) | Event-injection primitive; sub-case of F-2026-026. *(was S-005)* | doc — **closed** by follow-ups cleanup PR (Known gaps entry in SECURITY.md + mirror in `docs/src/security.md`) |
| F-2026-066 | nice | `SECURITY.md` | `/metrics` daemon-uptime gauge enables credential-file timing chains. *(was S-006)* | doc — **closed** by follow-ups cleanup PR (Known gaps entry in SECURITY.md + mirror in `docs/src/security.md`) |

---

## SDD-debt findings (4)

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2026-080 | SDD-debt | `modules/observability/assets/dashboards/` | Dashboard implicitly depends on agent-guard policies firing — no manifest-level coupling captured. *(was M-010)* | design |
| F-2026-081 | SDD-debt | `modules/*/install/lib.sh` | Duplicated helpers (`toml_get`, `run`, `log`, `emit_status`) across every module. *(was M-011)* | design — **closed** by SDD-006 implementation PR (shared `packaging/lib/module-lib.sh`; eight modules migrated byte-stably; dispatcher exports `SELFDEF_MODULE_LIB` with workspace+system fallback; version-pinned at `SELFDEF_MODULE_LIB_VERSION=1` with mismatch refused at source time) |
| F-2026-082 | SDD-debt | PR-author discipline | Tests verify the unit, not the flow. Need a design doc on what "integration-tested" means at the daemon ↔ module seam. *(was R-002)* | design — **closed** by SDD-005 implementation PR (`docs/dev/test-contract.md` runbook documents the four categories + three shared patterns; SDD-005 itself flips to `implemented`) |
| F-2026-083 | SDD-debt | development cadence | Module PRs introducing new event sources should be preceded by collector/correlator prep PRs. *(was R-004)* | design |

---

## Triage suggestion (for Phase 2, not committed)

The four central-promise blockers cluster into two coherent
design tracks:

1. **AI-machine track end-to-end**: F-2026-001, F-2026-002,
   F-2026-003, F-2026-006. Together: make the agent-guard
   policy → operator alert flow real. Phase-2 design SDD: how
   does Tetragon event metadata map to selfdef Event fields, and
   what's the contract between the collector and the rule set?
2. **Defaults that work out of the box**: F-2026-004, F-2026-018,
   F-2026-020. Together: ship a bundled `selfdef.toml` template
   and align module defaults. Phase-2 design SDD: what does the
   "out-of-the-box install with three modules" experience look
   like, and which knobs are operator-required vs.
   operator-optional?

The vpn-bridge blocker (F-2026-005) is independent; small SDD
on its own.

The important findings split roughly:

- **Documentation drift** (F-2026-012, F-2026-013, F-2026-019,
  F-2026-021, F-2026-022, F-2026-027, F-2026-028, F-2026-029,
  F-2026-037): one focused doc-sweep PR.
- **Threat-model updates** (F-2026-023 through F-2026-026):
  one SDD-style SECURITY.md rewrite.
- **Dead config knobs** (F-2026-015, F-2026-016, F-2026-017,
  F-2026-053): a small implementation PR; choose remove or
  implement for each.
- **Test coverage gaps** (F-2026-030 through F-2026-036): one
  test-infrastructure PR establishing the helpers (common/mod.rs,
  Prometheus parser, capability assertions) plus the missing
  integration tests.

All sequencing is Phase-2's call. This ledger is the menu.
