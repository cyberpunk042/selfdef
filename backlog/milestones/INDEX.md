# selfdef milestones — enumerated list

> Each entry is named using a phrase that appears verbatim in the
> selfdef repository state (existing crate / module / SDD / notifier),
> in the operator's standing mandate, or in the raw dump's
> security/sandbox/observability sections. Each carries a source ref.
> The list is ordered by **structural layer**, not implementation order;
> the operator decides implementation order.

## Source authority

| Layer | Source |
|---|---|
| Repo-state | the existing `crates/` (47 crates), `modules/` (14 modules), `docs/sdd/` (27 SDDs), `dashboard/`, `packaging/`, `ansible/`, `rules/`, `bpf/`, `selfdef-ebpf/`, `supply-chain/` directories |
| Standing mandate | `~/sovereign-os/docs/standing-directives/2026-05-17-operator-mandate.md` |
| Raw dump | `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` (18,341 lines) |
| Cross-repo binding doctrine | `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` |

## Enumeration

| ID | Phrase from source | Source ref |
|---|---|---|
| MS001 | Selfdef daemon core — `selfdef-core` / `selfdef-daemon` / `selfdef-bus` / `selfdef-config` / `selfdef-api` / `selfdef-cli` | repo `crates/selfdef-*` core six |
| MS002 | Collector fabric — auditd / journald / eBPF / Tetragon / Suricata / eventstream / canary | repo `crates/selfdef-collector-*` |
| MS003 | Correlator + store + responder + signing — time-windowed rules pipeline | repo `crates/selfdef-correlator,store,responder,signing` |
| MS004 | 14 notifier integrations — Discord / Loki / ntfy / OpenSearch / Oracle-Triage / PagerDuty / Shared-Audit-Summary / Signal / Slack / SMTP / TheHive / Twilio / Wall / Write | repo `crates/selfdef-integration-*` |
| MS005 | Notifier engine + orchestrator | repo `crates/selfdef-notifier{,-engine,-orchestrator}` |
| MS006 | 14 functional modules — `agent-guard` / `bitnet-gpu-inference` / `bridge-l2` / `detect-host` / `hardware-tune-cache` / `integrity-sentinel` / `observability` / `polarproxy` / `slm-cpu-loop` / `suricata` / `tensor-parallel-inference` / `tetragon` / `vpn-bridge` / `wasm-aot-cache` | repo `modules/*` |
| MS007 | 8/8 SATURATED cross-repo typed-mirror crates — auth-tier / bashrc-install / history-sink / dashboard-manifest / surface-manifest / ux-checklist / audit-manifest / doc-manifest | repo `crates/selfdef-{auth-tier,bashrc-install,history-sink,dashboard-manifest,surface-manifest,ux-checklist,audit-manifest,doc-manifest}` + `crates/selfdef-cross-repo-saturation` |
| MS008 | selfdef-on-sain01 integration | SDD-010, SDD-012, SDD-017 |
| MS009 | Audit cycles — Phase 6 / 7 / 8 + cycle3/4/5/6 vectors | SDD-019, SDD-020, SDD-021, SDD-024, SDD-025; `docs/review/` |
| MS010 | Hardware-aware modules + tune surface | SDD-018; `crates/selfdef-hardware`; `modules/hardware-tune-cache` |
| MS011 | Operator dashboard + flex profile | SDD-026; `dashboard/` |
| MS012 | Perimeter coexistence | SDD-015 |
| MS013 | 27-SDD charter framework — `000-charter` through current | `docs/sdd/000-charter.md` and successors |
| MS014 | SSH-wrap — client-side defense when YOU are the client | `crates/selfdef-ssh-wrap` |
| MS015 | NATS messaging backbone | `crates/selfdef-nats` |
| MS016 | eBPF programs + Tetragon TracingPolicies | `bpf/`, `selfdef-ebpf/`, `crates/selfdef-collector-ebpf`, `crates/selfdef-collector-tetragon`, `crates/selfdef-ebpf-common` |
| MS017 | agent-guard — host-level invariants on AI agents in Docker / Podman / containerd | `modules/agent-guard`; README §"Defend AI-machine hosts" |
| MS018 | VPN-bridge multi-instance | SDD-003; `modules/vpn-bridge` |
| MS019 | Security threat model | SDD-004 |
| MS020 | Test contract — L1–L5 layered harness | SDD-005 |
| MS021 | Shared module-script lib | SDD-006 |
| MS022 | Per-token SSE subscriber quota | SDD-007 |
| MS023 | Polarproxy module — TLS inspection | `modules/polarproxy` |
| MS024 | Bridge-L2 module — layer-2 transparent bridge | `modules/bridge-l2` |
| MS025 | Detect-host module — host-class detection | `modules/detect-host` |
| MS026 | Integrity-sentinel module | `modules/integrity-sentinel` |
| MS027 | Observability module (selfdef-side) | `modules/observability`; `crates/selfdef-collector-eventstream`; `crates/selfdef-collector-journald` |
| MS028 | BitNet GPU inference module | `modules/bitnet-gpu-inference`; dump 11187+ "1-bit / ternary ZMM utilization" |
| MS029 | SLM CPU loop module | `modules/slm-cpu-loop`; dump 7445 "SLMs Are Microservices Of Intelligence" |
| MS030 | Tensor parallel inference module | `modules/tensor-parallel-inference` |
| MS031 | WASM AOT cache module | `modules/wasm-aot-cache`; dump 6495 "WASM As Tool ABI" |
| MS032 | Sandbox tiers — read-only / workspace-write / Podman / network-denied / network-allowed / VFIO 3090 / browser-GUI / CRIU / ZFS clone | dump 16252–16277 (Phase 4: Sandbox Execution) |
| MS033 | Policy and trace — every action observable + governed | dump 16210–16250 (Phase 3: Policy And Trace) |
| MS034 | Communication boundary | dump 3450–3488 |
| MS035 | Capability tokens — typed authority handles | dump 3489–3527 |
| MS036 | Tool sandboxes | dump 3528–3549 |
| MS037 | Filesystem boundary | dump 3550–3593 |
| MS038 | Network boundary | dump 3594–3621 |
| MS039 | 7 authority levels + 5 trust rings | dump 17215–17532 |
| MS040 | Authority and profiles — authority threaded through profile resolution | dump 17468–17489 |
| MS041 | Commit authority — only the runtime commits | dump 17389–17421 |
| MS042 | Tool authority — typed authority on every tool intent | dump 17422–17445 |
| MS043 | IPS operator surface — CLI + TUI + dashboard-mirror exports | dump 581, 3290–3325, 15625–15665, 16440–16466, 14760–14780 |
| MS044 | Guardian Daemon — Tetragon eBPF supervisor + SIGKILL + atomic ZFS audit logs | sain-01 dump 513–588, 712–721, 977–981 |
| MS045 | UX coherence test harness (CLI + TUI + minimal-web) — TDD validator for MS043 operator surface | MS043 + operator standing direction 2026-05-19 |
| MS046 | Friction Audit System — boot-time hardware-integrity gate (PCIe / ZFS / memory) | sain-01 dump §5 lines 338–378 |
| MS047 | Real-Time Security Perimeter Engine — Tetragon kernel-fence (sovereign-perimeter.yaml + sys_execve Sigkill) | sain-01 dump §6 lines 380–411 |
| MS048 | Goldilocks Scheduler — hardware-aware resource routing (Blackwell/3090/CPU + KV/Context + Memory + Tool + Backpressure surfaces + 7-axis objective) | avx-plus-plus dump tail lines 18000–18250 |

## Stage 2+ production status (2026-05-21)

> Tracks which milestones have reached Stage 2+ (SDD specification +
> implementation + testing reaching production) per the operator's
> standing directive: *"DO NOT STOP AT DEFINING/REGISTERING THE
> REQUIREMENT and doing the scaffolds, we expect the full production
> progressively through the workflow. You cannot mark something done
> if it hasn't reached Prod."*
>
> **`done`** — every layer shipped: SDD + implementation + tests + L1
> coherence gates + docs + (where applicable) HTTP route + dashboard
> + CLI + operator runbook. SDD status promoted to `implemented`.
>
> **`partial`** — some layers shipped; specific gaps documented in the
> milestone file or its companion SDD's Status header.
>
> **`stage-1`** — catalog identified but no Stage-2 SDD spec OR
> implementation work landed yet.

| ID | Status | Notes |
|---|---|---|
| MS001 | done | core 6 crates shipped pre-session |
| MS002 | partial | collector crates exist; eBPF collector + tetragon collector + eventstream + journald + **auditd collector with AVC + SECCOMP + ANOM_ABEND + ANOM_PROMISCUOUS support** (4 high-signal kernel-emitted record types beyond the M3 USER_AUTH/LOGIN/ACCT baseline; ratified under SDD-059). **New `audit-rules` + `dns-shield` + `usbguard` + `kernel-lockdown` + `chrony-baseline` + `coredumpd-redirect` + `time-skew-watchdog` + `aide-bridge` + `rkhunter-cron` + `lynis-cron` + `unattended-upgrades-config` modules** ship full rule sets / device policies / sysctl hardening baselines / NTP integrity + drift-detection sidecar (5min) / AIDE file integrity baseline (daily 03:30) / rkhunter known-rootkit-signature daily scan (04:30) / Lynis CIS-style weekly compliance audit (Sun 05:30) / coredump redirect with mode 0700 preservation dir / unattended-upgrades baseline (apt-systemd-daily auto-installs security-pocket updates; security-only or security-and-reboot profile; foundational CVE-mitigation layer). `audit-rules` provides `base` + `paranoid` profile rule sets (ld.so.preload watch + credential-file watch + sudo/su exec + kernel-module syscalls + raw-socket creation + loginuid immutability for base; + universal exec + ptrace + uid/gid syscalls + cron/systemd-unit writes for paranoid) that drive the auditd collector — without rules the kernel emits almost nothing. 3 more eBPF programs deferred per SDD-032. **Multi-line SYSCALL+EXECVE auditd parsing shipped** (SDD-059 C-5 closure 2026-05-21): single-slot pending_syscall buffer pairs SYSCALL + EXECVE records emitted by the kernel as contiguous blocks; emits one PROCESS_ACTIVITY::Launch event with full argv vector + exit code + T1059 attack tag instead of two generic events. |
| MS003 | done | correlator + store + responder + signing shipped pre-session |
| MS004 | done | 12 notifier integrations shipped (SDD-008 implemented); promoted 2026-05-21 |
| MS005 | done | notifier engine + orchestrator crates shipped |
| MS006 | done | 14 modules shipped + /v1/modules + /v1/modules/:name + /v1/modules/diff + /v1/modules/:name/check (cross-cutting health probe across all 12 operator modules) |
| MS007 | done | 8/8 typed-mirror crates pre-session |
| MS008 | partial | SDD-010 scoping; SDD-012 review; SDD-017 implemented — Sain-01 hardware inventory + /v1/hardware/sain01 verdict + doctor integration shipped |
| MS009 | done | per-watchdog audit_chain_check fn + 2 audit-cycle replay CLI verbs + /v1/audit-chains + dashboard panel + selfdefctl audit-chains CLI all shipped 2026-05-21 |
| MS010 | done | crate + CLI + /v1/hardware* (3 routes) + dashboard panel + L1 gates — end-to-end |
| MS011 | done | All 13 Z-vectors end-to-end (backend + dashboard + L1 + CLI where applicable). Z-1 8-tab restructure via SDD-056. Z-2 probe + `selfdefctl inference-backends {show,version}` invocation seed. Z-3 GET `/v1/flex-profile` + POST `/v1/flex-profile/{apply,revert}` atomic-persisted mutations. Z-4..Z-7,Z-9,Z-10 hardware/health/network/storage/raid/gpu/cpu surfaces. Z-8 `[install_paths]` manifest on all 14 modules + path-conflict detection in install-plan + dashboard conflict badge. Z-11 MCP interop foundation. Z-12 multi-tier REPL (Tier 1 + SD-R97/R98/R101/R102 layered + auto-load doctrine SDD-058). Z-13 modules diff + install-options (hardware-gate enriched via SDD-057) + install-plan (Kahn's topological sort). SDD-026 → implemented. Bigger follow-up arcs (Z-2 module-driven install pipeline, Z-8 actually-containerized module variants, Z-12 dashboard REPL pop-out UI) remain as separate *next* surfaces. |
| MS012 | done | perimeter coexistence CLI + config + agent-guard module (SDD-015 implemented) |
| MS013 | partial | 51 implemented + 1 superseded (SDD-009 → SDD-026/054/056/060) + 1 living + 1 review + 3 scoping + 5 draft = 62 total SDDs in `docs/sdd/`. Net+24 ratifications + 1 supersession since pre-session count. Ongoing as production catches up to spec authoring; SDD-026 + SDD-058 + SDD-059 + SDD-060 + SDD-009-superseded are this session's promotions |
| MS014 | done | `selfdef-ssh-wrap` crate shipped (drop-in `ssh` replacement with per-host policy + OCSF events) + SDD-052 + `selfdefctl ssh-wrap {doctrine,install}` CLI + L1 gates. HTTP surface intentionally deferred per SDD-052 D-2 (wrapper is per-operator-user, not daemon-owned; HTTP would cross the isolation boundary). Sain-01 integration deferred per SDD-052 D-3. |
| MS015 | done | `selfdef-nats` crate shipped (two-way bus pump + echo defense + passive/active modes) + SDD-053 + `selfdefctl nats` CLI + `GET /v1/nats` schema discovery + L1 gates. Multi-host operator integration arc (NATS server provisioning + per-fleet subject coordination) is the deferred follow-up — separate from the IPS layer-up. |
| MS016 | partial | 1 aya-rs eBPF program (execve) + tetragon TracingPolicy directory + collector crates + **new `host-sentinel` module shipping 2 host-scope Tetragon TracingPolicies** (kmod-watch via `do_init_module` kprobe + ld-preload-watch via `security_file_open` against `/etc/ld.so.preload`; audit+enforce profiles; integrates cleanly with the existing tetragon collector). 3 SDD-032 programs remain deferred for kernel-toolchain bring-up (proc-ancestry / hidden-process / tcp-fingerprint — these genuinely need aya-rs eBPF, not Tetragon). |
| MS017 | done | agent-guard module shipped + /v1/modules/:name/check probe integration |
| MS018 | done | vpn-bridge module + SDD-003; L2 bats coverage |
| MS019 | done | SECURITY.md threat model accurate for all /v1/* surfaces shipped through 2026-05-21 |
| MS020 | done | L1-L5 layered harness shipped (L1 8 gates, L2 14 modules, cargo) per SDD-030 |
| MS021 | done | shared module-script lib shipped per SDD-006 (`crates/selfdef-shared-module-script-lib`) |
| MS022 | done | per-token SSE quota shipped per SDD-007 |
| MS023 | done | polarproxy module shipped + L2 bats + /v1/modules/:name/check |
| MS024 | done | bridge-l2 module shipped + L2 bats + /v1/modules/:name/check |
| MS025 | done | detect-host module shipped + L2 bats + /v1/modules/:name/check |
| MS026 | done | integrity-sentinel module shipped + L2 bats + /v1/modules/:name/check |
| MS027 | done | observability module + 17 Prometheus gauges + 20-panel Grafana dashboard + 9 alert rules + /v1/alerts server-side classifier + dashboard panel + selfdefctl alerts + doctor integration — end-to-end fullstack |
| MS028 | done | `modules/bitnet-gpu-inference/` shipped (manifest + apply.sh + check.sh + uninstall.sh) + L2 bats `L2-bitnet-gpu-inference` + cross-cutting `/v1/modules/:name/check` health probe (commit c1f41c6) + `/v1/modules/diff` activation tracking + dashboard "Modules" panel + SDD-035 promoted to `implemented` 2026-05-21. |
| MS029 | done | slm-cpu-loop module shipped + L2 bats + /v1/modules/:name/check |
| MS030 | done | tensor-parallel-inference module shipped + L2 bats + /v1/modules/:name/check |
| MS031 | done | `modules/wasm-aot-cache/` shipped + L2 bats `L2-wasm-aot-cache` + cross-cutting `/v1/modules/:name/check` health probe + `/v1/modules/diff` activation tracking + dashboard "Modules" panel + SDD-022 (hardware-exploit doctrine including wasm AOT) implemented. Selfdef-hardware crate's `wasm_aot.target_cpu` / `target_features` / `ternary_kernel_hint` capabilities surfaced through `/v1/hardware/capabilities`. |
| MS032 | done | 5-crate sandbox set (tier-policy + dispatcher + fs-isolation + network-isolation + mirror, ~1400 LOC, 29 tests) + SDD-047 + `selfdefctl sandbox-tiers` CLI + `GET /v1/sandbox-tiers` schema discovery + L1 gates. Live-state surface (D-3 GET /v1/sandbox-tiers/active) deferred. |
| MS033 | done | 36 `selfdef-policy-*` crates + SDD-051 + `selfdefctl policy {clusters,crates}` CLI + `GET /v1/policy` schema discovery + L1 gates. Live policy-trace surface (D-3 GET /v1/policy/trace/:id) + integration-test cluster crate (D-4 selfdef-policy-suite) deferred. |
| MS034 | done | `selfdef-communication-boundary` crate (372 LOC) + SDD-048 + `selfdefctl communication-boundary` CLI + `GET /v1/communication-boundary` schema discovery + L1 gates. Per-message-type Prom counters (D-4) deferred. |
| MS035 | done | 5-crate ecosystem (token-store + word + mirror + tool-capability-policy + profile-authority-gate) + SDD-044 + `selfdefctl capability-tokens {verdicts,schema}` CLI + `GET /v1/capability-tokens` schema discovery + L1 gates. Mutation surface (issue/revoke via CLI) deferred per SDD-044 D-3 (in-memory store; token-minting goes through MS003-signed config + SDD-043 high-risk classifier per D-4). |
| MS036 | done | covered by the MS032 sandbox-tiers surfaces (commit aa0f77a) — `selfdef-sandbox-dispatcher` is the route-by-tier engine that owns tool-sandbox dispatch per dump 3528-3549; the SDD-047 + `selfdefctl sandbox-tiers` + `GET /v1/sandbox-tiers` discovery layer surfaces it. Per-tool live dispatch state (D-3 GET /v1/sandbox-tiers/active) deferred. |
| MS037 | done | `selfdef-filesystem-boundary` crate (496 LOC) + SDD-045 + `selfdefctl filesystem-boundary {doctrine,schema}` CLI + `GET /v1/filesystem-boundary` schema discovery + L1 gates. Caller-integration arc deferred per SDD-045 D-3/D-4. |
| MS038 | done | `selfdef-network-boundary` crate (459 LOC) + SDD-046 + `selfdefctl network-boundary {profiles,classify}` CLI + `GET /v1/network-boundary` schema discovery + L1 gates. Host-firewall nftables emission (SDD-046 D-3) + IPv6 (D-4) deferred. |
| MS039 | done | 5-crate authority stack (mode-transition + toggle-audit + config-mutation + recovery-snapshot + profile-authority-gate, ~1639 LOC) + SDD-049 + `selfdefctl authority` CLI + `GET /v1/authority` schema discovery + L1 gates. Mode-transition log persistence (SDD-049 D-4) + GET /v1/authority/active live state (D-3) deferred. |
| MS040 | done | Same 5-crate authority stack covers MS040 (the 6-profile envelope matrix is part of `selfdef-profile-authority-gate`) + SDD-049 + `selfdefctl authority` CLI + `GET /v1/authority` schema discovery + L1 gates. |
| MS041 | done | `selfdef-commit-authority` crate (473 LOC, 22 tests) + SDD-043 + `selfdefctl commit-authority {types,validate,classify}` CLI + `GET /v1/commit-authority` schema discovery + L1 gates. Caller-integration arc (SDD-043 D-2) deferred but doctrine-discovery surface is end-to-end through every operator layer. |
| MS042 | done | 11-crate tool-policy pipeline (capability-policy + call-latency-budget + cancellation-policy + version-pinning + stream-watchdog + invocation-rate-limit + output-language-policy + arg-redaction-policy + output-truncation-policy + output-trust-veil + output-byte-quota) + SDD-050 + `selfdefctl tool-authority {tools,permits}` CLI + `GET /v1/tool-authority` schema discovery + L1 gates. Caller-integration arc (SDD-050 D-3) deferred. |
| MS043 | partial | IPS operator surface — CLI shipped (selfdefctl 16 top-level verbs + many subverbs, including `inference-backends {show,version}` + `dashboard-prefs {show,set}` + `dashboards` discovery); HTTP `GET /v1/dashboards` operator-pull preset catalog (5 entries: compact/default/inference/performance/security); dashboard at 17 panels under SDD-056 8-tab nav (composite-health + 4-watchdog + modules + audit-chains + alerts + hardware + network + storage + raid + gpu + cpu + flex-profile + inference-backends + control + findings) + **operator-facing per-panel visibility menu** ("View ▾" → localStorage-persisted `selfdef.hiddenPanels` set; closes the operator's "everything can be turned on and off" verbatim UX requirement) + **refresh-rate selector** (Fast/Normal/Slow/Paused → 0.25×/1×/4×/∞ multiplier on gated intervals; localStorage `selfdef.refreshRate`; closes the operator's "tons of modes" verbatim UX requirement) + **operator-named view presets** (Default/Security/Performance/Inference/Compact → each snaps `{hiddenPanels, activeTab, refreshRate}` atomically; localStorage `selfdef.activePreset`; tractable interim toward the operator's "20 dashboards" verbatim UX requirement — distinct dashboard URL paths is the Stage-2 arc) + **daemon-side dashboard-prefs persistence + PWA sync** (`GET/PUT /v1/dashboard-prefs` at `/etc/selfdef/dashboard-prefs.toml`; atomic write; enum-validated; PWA fetches on load + PUTs on change debounced 400ms; localStorage is offline-mode fallback; closes the cross-browser/host preference-sync gap end-to-end per SDD-060); MS045 coherence harness validates surface. Operator-pull TUI deferred. |
| MS044 | done | Guardian daemon + binary + systemd unit + 4 CLI subverbs + /v1/guardian{,/history} + dashboard panel + 5 runbooks + 3 Prom alerts — end-to-end fullstack (SDD-029 implemented) |
| MS045 | done | UX coherence harness — 28 layers (8 L1 + 14 L2 + cargo) + CI gating per push/PR/tag (SDD-030 implemented) |
| MS046 | done | Friction-audit system — crate + 3 CLI subverbs + /v1/friction-audit{,/history} + dashboard panel + sovereign-guard.service + 5 runbooks + 1 Prom alert — end-to-end fullstack (SDD-027 implemented) |
| MS047 | done | Perimeter engine — crate + 7 CLI subverbs + /v1/perimeter{,/history} + dashboard panel + 6 runbooks + 3 Prom alerts — end-to-end fullstack (SDD-028 implemented) |
| MS048 | done | Goldilocks scheduler — crate + 7 CLI subverbs + /v1/scheduler{,/history,/backpressure,/weights,/explain/:id} + dashboard panel + 5 runbooks + 2 Prom alerts — end-to-end fullstack (SDD-031 implemented) |

**Tally as of 2026-05-21 (post-MS014/MS015 promotion):**
- `done`: 42 milestones (was 40)
- `partial`: 6 milestones
- `stage-1`: 0 milestones

MS041 (commit-authority) + MS042 (tool-authority) promoted from
`partial` to `done` this session — both now have crate + SDD-043/050
+ selfdefctl CLI + GET /v1/* schema discovery + L1 gates. The
caller-integration arcs (durable-change call sites routing through
validate(); tool-invocation call sites routing through the 9-gate
pipeline) remain deferred but the doctrine-discovery surfaces are
end-to-end across every operator-facing layer.

Forward queue is now LAYER-UP work for the remaining 19 partials:
each milestone has its core Rust crates but needs the HTTP/CLI/
dashboard/runbook layers to reach `done`. That's the same pattern
this session executed for MS009/MS010/MS011/MS027/MS041/MS042 +
the four-watchdog set + the cross-cutting module check.sh probe.

## Decomposition each milestone owes

Per operator's standing directive:

- ≥ ~10 epics per milestone (≥ 400+ epics total across selfdef)
- ≥ ~25 modules per milestone (≥ 1000+ modules total)
- ≥ ~120 features per milestone (≥ 5000+ features total)
- ≥ ~240 requirements per milestone (≥ 10000+ requirements total, each ≥ 10 sub-requirements)

These targets are progressive. Each milestone file fills its slice over
many SDD rounds. The catalog's primary job is **identification +
writing** — the operator's first-thing instruction. Implementation
under SDD discipline follows after scaffold-tier completion.

## Cross-references

- Sister sovereign-os catalog: `~/sovereign-os/backlog/milestones/INDEX.md`
- Cross-repo binding doctrine: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md`
- Selfdef SDD ledger: `docs/sdd/`
- Selfdef CHANGELOG: `CHANGELOG.md`
- Selfdef findings ledger: `docs/review/99-findings-ledger.md`
