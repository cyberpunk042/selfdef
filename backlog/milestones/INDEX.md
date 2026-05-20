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
