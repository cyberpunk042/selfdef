# MS032 — Sandbox tiers — read-only / workspace-write / Podman / network-denied / network-allowed / VFIO 3090 / browser-GUI / CRIU / ZFS clone

> Parent: `backlog/milestones/INDEX.md` row MS032 (source ref dump 16252–16277 Phase 4: Sandbox Execution).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 16252–16290 (Phase 4 doctrinal block + adjacent Phase 5 transition).
> All entries below extract verbatim from these dump lines or trace to existing selfdef + sovereign-os repo state. No invention.

## Epics (E0321–E0330)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0321 | Phase 4: Sandbox Execution + goal — "Let agents act without trusting them blindly" | dump 16252–16258 |
| E0322 | Sandbox tier 1 — `read-only shell` (starting tier; no filesystem mutation) | dump 16264 |
| E0323 | Sandbox tier 2 — `workspace-write shell` (next tier; bounded write surface) | dump 16265 |
| E0324 | Sandbox tier 3 — `Podman sandbox` (container-managed; namespace + cgroup boundaries) | dump 16266 |
| E0325 | Sandbox tier 4 — `network-denied sandbox` (Podman + network namespace isolation) | dump 16267 |
| E0326 | Sandbox tier 5 — `network-allowed sandbox` (Podman with allowed network egress) | dump 16268 |
| E0327 | Future tier 6 — `VFIO 3090 VM` + `browser/GUI sandbox` (hard isolate + perception/GUI workload sandbox) | dump 16274 + 16275 |
| E0328 | Future tier 7 — `CRIU checkpoints` + `ZFS clone workspaces` (process state save-restore + filesystem clone-per-experiment) | dump 16276 + 16277 |
| E0329 | Runtime rule — "tool intent is not execution" — proposing a tool call is NOT the same as executing it; sandbox tier resolution + policy check sits between intent and execution | dump 16282–16284 |
| E0330 | Cross-module + cross-repo composition + composite — selfdef-side sandbox-tier enforcement realizes sovereign-os M048 Module 3 Container/Sandbox Fabric's 8 sandbox profiles (read-only repo / write-workspace / network-denied / network-docs-only / gpu-scout / no-gpu / vm-isolated / vfio-3090) + M042 Choice Architecture choice-envelope `execution` domain (dry_run / sandbox / vm / host) + M045 Linux as intelligence governor (cgroup v2 + AppArmor + namespaces) + M047 Continuity Manager (CRIU + ZFS) | architecture + cross-ref M042 + M045 + M047 + M048 |

## Modules (M00811–M00836)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00811 | Phase 4 doctrine — "Let agents act without trusting them blindly" | dump 16258 | E0321 |
| M00812 | Tier 1 — read-only shell (no fs mutation) | dump 16264 | E0322 |
| M00813 | Tier 2 — workspace-write shell (bounded write surface) | dump 16265 | E0323 |
| M00814 | Tier 3 — Podman sandbox (namespace + cgroup boundaries) | dump 16266 | E0324 |
| M00815 | Tier 4 — network-denied sandbox (Podman + netns isolation) | dump 16267 | E0325 |
| M00816 | Tier 5 — network-allowed sandbox (Podman + allowed egress) | dump 16268 | E0326 |
| M00817 | Future Tier 6a — VFIO 3090 VM (hard isolate via IOMMU passthrough) | dump 16274 | E0327 |
| M00818 | Future Tier 6b — browser/GUI sandbox (perception/GUI workload) | dump 16275 | E0327 |
| M00819 | Future Tier 7a — CRIU checkpoints (Checkpoint/Restore In Userspace) | dump 16276 | E0328 |
| M00820 | Future Tier 7b — ZFS clone workspaces (filesystem clone-per-experiment) | dump 16277 | E0328 |
| M00821 | Runtime rule — "tool intent is not execution" | dump 16282 | E0329 |
| M00822 | Tier escalation — start with 5 tiers + add 4 future tiers when needed | dump 16260–16277 | E0321 |
| M00823 | Sandbox-tier predicate — what filesystem permissions does the agent get? | dump 16264–16265 + cross-ref M048 sandbox profile catalog | E0322 + E0323 |
| M00824 | Sandbox-tier predicate — what process isolation does the agent get? (none / container / VM) | dump 16266 + 16274 + cross-ref M045 namespaces | E0324 + E0327 |
| M00825 | Sandbox-tier predicate — what network access does the agent get? (none / docs-only / full / VFIO-isolated) | dump 16267 + 16268 + cross-ref M048 sandbox profiles | E0325 + E0326 |
| M00826 | Sandbox-tier predicate — what GPU access does the agent get? (none / scout / VFIO-passthrough) | dump 16274 + cross-ref M048 gpu-scout + vfio-3090 profiles | E0327 |
| M00827 | Sandbox-tier predicate — does the agent need checkpoint/restore? (CRIU) | dump 16276 + cross-ref M047 Continuity Manager | E0328 |
| M00828 | Sandbox-tier predicate — does the agent need rollback? (ZFS clone) | dump 16277 + cross-ref M044 Storage Plane + M047 ZFS+CRIU 5-layer save-state | E0328 |
| M00829 | Selfdef enforcement surface — selfdef MS017 agent-guard enforces sandbox-tier choice via host-level invariants on AI agents in Docker/Podman/containerd | cross-ref MS017 | E0330 |
| M00830 | Selfdef observability surface — selfdef MS027 observability module renders sandbox_start + sandbox_stop events from sovereign-os M049's 16-event taxonomy | cross-ref MS027 + cross-ref M049 | E0330 |
| M00831 | Selfdef policy surface — selfdef MS017 agent-guard maps to sovereign-os M048 Module 4 Gateway + M049 Policy Fabric's 7 policy decisions ("Can this sandbox access network?") | cross-ref MS017 + cross-ref M048 + M049 | E0330 |
| M00832 | Cross-repo binding — sandbox-tier choice envelope surfaces via MS007 surface-manifest typed-mirror crate (8/8 SATURATED) | architecture + cross-ref MS007 | E0330 |
| M00833 | Configuration overlay — operator selects sandbox tier per-action / per-profile / per-session via M042 Choice Architecture envelope | cross-ref M042 | E0329 |
| M00834 | Hardware mapping — VFIO 3090 requires IOMMU + GPU passthrough kernel modules (vfio-pci) | cross-ref M044 VFIO + dump 16274 | E0327 |
| M00835 | Hardware mapping — CRIU requires Podman checkpoint integration + criu binary on host | cross-ref M047 + dump 16276 | E0328 |
| M00836 | Hardware mapping — ZFS clone workspaces require ZFS dataset hierarchy with clone-capable parent | cross-ref M044 ZFS + dump 16277 | E0328 |

## Features (F03721–F03840)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03721 | Phase 4 header — "Sandbox Execution" | dump 16252 | M00811 |
| F03722 | Phase 4 goal — "Let agents act without trusting them blindly" | dump 16258 | M00811 |
| F03723 | "Start with tiers" — escalation doctrine | dump 16260 | M00822 |
| F03724 | Tier 1 — read-only shell | dump 16264 | M00812 |
| F03725 | Tier 1 — agent reads filesystem but cannot mutate | dump 16264 + cross-ref M048 sandbox-profile "read-only repo" | M00812 |
| F03726 | Tier 1 — appropriate for code review / analysis / explanation tasks | architecture + dump 16258 | M00812 |
| F03727 | Tier 2 — workspace-write shell | dump 16265 | M00813 |
| F03728 | Tier 2 — agent writes to bounded workspace dir | dump 16265 + cross-ref M048 sandbox-profile "write-workspace" | M00813 |
| F03729 | Tier 2 — host fs outside workspace remains read-only | dump 16265 | M00813 |
| F03730 | Tier 3 — Podman sandbox | dump 16266 | M00814 |
| F03731 | Tier 3 — container namespaces (mount + UTS + IPC + PID + user) | cross-ref M045 namespaces + M048 Podman/Quadlet | M00814 |
| F03732 | Tier 3 — cgroup v2 resource limits | cross-ref M045 cgroup v2 + M048 clean pattern | M00814 |
| F03733 | Tier 3 — rootless Podman by default | cross-ref M048 clean pattern "rootless where possible" | M00814 |
| F03734 | Tier 3 — AppArmor profile applied | cross-ref M044 + M045 AppArmor | M00814 |
| F03735 | Tier 4 — network-denied sandbox | dump 16267 | M00815 |
| F03736 | Tier 4 — Podman + `--network=none` | cross-ref M048 Container/Sandbox Fabric | M00815 |
| F03737 | Tier 4 — applicable to autonomous offline workflows | cross-ref M042 Offline-Peace-Mode profile | M00815 |
| F03738 | Tier 4 — eBPF observes network syscalls and alerts on attempts | cross-ref M045 eBPF + M049 eBPF truth sensor | M00815 |
| F03739 | Tier 5 — network-allowed sandbox | dump 16268 | M00816 |
| F03740 | Tier 5 — Podman + allowed network egress | cross-ref M048 sandbox-profile network-docs-only | M00816 |
| F03741 | Tier 5 — egress filtering via nftables (per-domain or per-endpoint) | cross-ref MS024 bridge-l2 + MS023 polarproxy | M00816 |
| F03742 | Tier 5 — policy decides allowed destinations | cross-ref M049 Policy Fabric "Can this sandbox access network?" | M00816 |
| F03743 | "Then later" — future tier doctrine | dump 16270 | M00822 |
| F03744 | Tier 6a — VFIO 3090 VM | dump 16274 | M00817 |
| F03745 | Tier 6a — IOMMU passthrough kernel modules (vfio-pci) | cross-ref M044 VFIO/IOMMU | M00817 |
| F03746 | Tier 6a — GPU passthrough to VM (libvirt/QEMU) | cross-ref M048 sandbox-profile "vfio-3090" | M00817 |
| F03747 | Tier 6a — appropriate for high-risk experiments + computer-use agents | cross-ref M040 Hyper Feature 7 VFIO + M042 High-Risk profile | M00817 |
| F03748 | Tier 6b — browser/GUI sandbox | dump 16275 | M00818 |
| F03749 | Tier 6b — for perception/GUI workloads | cross-ref M043 3090 use "GUI/perception models" | M00818 |
| F03750 | Tier 6b — typically uses browser sandbox + display isolation | architecture + dump 16275 | M00818 |
| F03751 | Tier 6b — can stack on Tier 6a VFIO for full isolation | architecture + cross-ref M048 Sandbox Plane | M00818 |
| F03752 | Tier 7a — CRIU checkpoints | dump 16276 | M00819 |
| F03753 | Tier 7a — Checkpoint/Restore In Userspace | cross-ref M047 CRIU | M00819 |
| F03754 | Tier 7a — Podman supports checkpoint/restore via CRIU | cross-ref M047 Podman+CRIU | M00819 |
| F03755 | Tier 7a — warm sandbox replay for fast retries | cross-ref M047 Warm Sandboxes | M00819 |
| F03756 | Tier 7a — branch experiments via checkpoint restore | cross-ref M047 branch-search pattern | M00819 |
| F03757 | Tier 7b — ZFS clone workspaces | dump 16277 | M00820 |
| F03758 | Tier 7b — filesystem clone-per-experiment | cross-ref M047 ZFS+CRIU 5-layer save-state | M00820 |
| F03759 | Tier 7b — clone is copy-on-write (low cost) | cross-ref M044 ZFS Storage Plane | M00820 |
| F03760 | Tier 7b — clone destroy rolls back experiment | cross-ref M040 Hyper Feature 8 ZFS commit gate | M00820 |
| F03761 | Runtime rule — "tool intent is not execution" | dump 16282 | M00821 |
| F03762 | Runtime rule — proposing tool call ≠ executing it | dump 16282 | M00821 |
| F03763 | Runtime rule — sandbox-tier resolution sits between intent and execution | architecture + dump 16282 | M00821 |
| F03764 | Runtime rule — policy check (M049 Policy Fabric) gates tier selection | cross-ref M049 + dump 16282 | M00821 |
| F03765 | Selfdef enforcement — MS017 agent-guard enforces sandbox-tier choice via host-level invariants | cross-ref MS017 | M00829 |
| F03766 | Selfdef enforcement — invariants apply to Docker / Podman / containerd | cross-ref MS017 README | M00829 |
| F03767 | Selfdef observability — MS027 observability renders sandbox_start + sandbox_stop events | cross-ref MS027 + M049 16-event taxonomy | M00830 |
| F03768 | Selfdef observability — events flow to MS025 detect-host event-bus → notifier chain | cross-ref MS025 + M049 | M00830 |
| F03769 | Selfdef policy — MS017 agent-guard maps to M049's "Can this sandbox access network?" | cross-ref MS017 + M049 Policy Fabric | M00831 |
| F03770 | Selfdef policy — sandbox-tier-as-policy expressed via OPA/Cedar/OpenFGA | cross-ref M049 + MS017 | M00831 |
| F03771 | Cross-repo binding — sandbox-tier choice envelope surfaces via MS007 typed-mirror crates | cross-ref MS007 | M00832 |
| F03772 | Cross-repo binding — selfdef MS007 surface-manifest crate carries tier descriptor schema | architecture + cross-ref MS007 | M00832 |
| F03773 | Cross-repo binding — sovereign-os M048 Module 3 Container/Sandbox Fabric provides 8 profiles | cross-ref M048 | M00832 |
| F03774 | Cross-repo binding — selfdef provides host-level enforcement; sovereign-os provides tier policy | cross-ref MS017 + M048 + M049 | M00832 |
| F03775 | Configuration overlay — operator selects tier per-action | cross-ref M042 Choice Envelope | M00833 |
| F03776 | Configuration overlay — operator selects tier per-profile | cross-ref M042 Profile Bundles | M00833 |
| F03777 | Configuration overlay — operator selects tier per-session | cross-ref M042 + M047 session continuity | M00833 |
| F03778 | Configuration overlay — choice-envelope.execution = dry_run / sandbox / vm / host | cross-ref M042 | M00833 |
| F03779 | Hardware — VFIO 3090 requires IOMMU enabled in BIOS + kernel | cross-ref M044 Sovereign-OS substrate | M00834 |
| F03780 | Hardware — VFIO 3090 requires vfio-pci kernel module | cross-ref M044 + dump 16274 | M00834 |
| F03781 | Hardware — CRIU requires criu binary on host (apt install criu) | cross-ref M047 | M00835 |
| F03782 | Hardware — CRIU requires Podman compiled with checkpoint support | cross-ref M047 Podman+CRIU integration | M00835 |
| F03783 | Hardware — ZFS clone workspaces require ZFS dataset hierarchy | cross-ref M044 ZFS Storage Plane | M00836 |
| F03784 | Hardware — ZFS clone-capable parent dataset = `tank/workspaces` or similar | architecture + cross-ref M044 ZFS | M00836 |
| F03785 | Tier 1 capability — read filesystem | dump 16264 + architecture | M00812 |
| F03786 | Tier 1 forbidden — write filesystem | dump 16264 + M00823 | M00812 |
| F03787 | Tier 1 forbidden — execute new processes outside shell | architecture + dump 16264 | M00812 |
| F03788 | Tier 1 forbidden — network egress | dump 16264 + M00825 | M00812 |
| F03789 | Tier 2 capability — write to bounded workspace | dump 16265 | M00813 |
| F03790 | Tier 2 capability — read filesystem outside workspace | dump 16265 + cross-ref M048 write-workspace | M00813 |
| F03791 | Tier 2 forbidden — write outside workspace | dump 16265 | M00813 |
| F03792 | Tier 2 forbidden — execute new privileged operations | dump 16265 + M00824 | M00813 |
| F03793 | Tier 3 capability — full file IO within container | dump 16266 + cross-ref M048 | M00814 |
| F03794 | Tier 3 capability — exec arbitrary commands within container | dump 16266 + cross-ref M048 | M00814 |
| F03795 | Tier 3 forbidden — host filesystem mutation | dump 16266 + M00824 | M00814 |
| F03796 | Tier 3 forbidden — privilege escalation | dump 16266 + cross-ref M048 rootless | M00814 |
| F03797 | Tier 4 capability — all of Tier 3 within container | dump 16266 + 16267 | M00815 |
| F03798 | Tier 4 forbidden — ANY network egress | dump 16267 + M00825 | M00815 |
| F03799 | Tier 4 forbidden — DNS resolution | dump 16267 + architecture | M00815 |
| F03800 | Tier 5 capability — all of Tier 3 + allowed network egress | dump 16268 + M00816 | M00816 |
| F03801 | Tier 5 capability — egress to allowed endpoints (whitelisted) | dump 16268 + M00816 | M00816 |
| F03802 | Tier 5 forbidden — egress to non-whitelisted endpoints | dump 16268 + M00816 | M00816 |
| F03803 | Tier 5 forbidden — privilege escalation | dump 16268 + cross-ref M048 rootless | M00816 |
| F03804 | Tier 6a capability — full GPU access (passthrough) | dump 16274 + M00826 | M00817 |
| F03805 | Tier 6a capability — full VM sandbox with allocated CPU + RAM | dump 16274 + cross-ref M048 vm-isolated | M00817 |
| F03806 | Tier 6a forbidden — host visibility (VM has its own kernel) | dump 16274 + architecture | M00817 |
| F03807 | Tier 6a forbidden — second VM accessing same GPU (single-VM passthrough) | architecture + cross-ref M044 VFIO | M00817 |
| F03808 | Tier 6b capability — browser/GUI surface (X11/Wayland) | dump 16275 + cross-ref M048 | M00818 |
| F03809 | Tier 6b capability — perception model invocation | dump 16275 + cross-ref M043 3090 perception role | M00818 |
| F03810 | Tier 6b forbidden — host GUI compromise | dump 16275 + architecture | M00818 |
| F03811 | Tier 7a capability — checkpoint container state | dump 16276 + cross-ref M047 CRIU | M00819 |
| F03812 | Tier 7a capability — restore container state | dump 16276 + cross-ref M047 | M00819 |
| F03813 | Tier 7a capability — branch experiment via restore | dump 16276 + cross-ref M047 branch-search | M00819 |
| F03814 | Tier 7a forbidden — checkpoint with GPU state (per M047 caveat) | cross-ref M047 CRIU caveat | M00819 |
| F03815 | Tier 7b capability — ZFS snapshot before experiment | dump 16277 + cross-ref M040 Hyper Feature 8 | M00820 |
| F03816 | Tier 7b capability — ZFS clone for parallel branches | dump 16277 + cross-ref M044 ZFS | M00820 |
| F03817 | Tier 7b capability — destroy clone on rollback | dump 16277 + cross-ref M040 Hyper Feature 8 | M00820 |
| F03818 | Tier 7b forbidden — operate on parent dataset without snapshot | dump 16277 + architecture | M00820 |
| F03819 | Tier policy doctrine — operator picks tier based on task risk | architecture + cross-ref M049 Intent-Based Policy | E0329 |
| F03820 | Tier policy doctrine — runtime can escalate tier (down) for safety | architecture + cross-ref M049 | E0329 |
| F03821 | Tier policy doctrine — runtime requires policy approval to escalate tier (up) | cross-ref M049 + M042 user-approval state | E0329 |
| F03822 | Tier policy doctrine — every tier transition logged via M049 16-event taxonomy (sandbox_start + sandbox_stop) | cross-ref M049 + M00830 | E0329 |
| F03823 | Tier observability — sandbox_start event fields include tier, profile, agent_id, trace_id | cross-ref M049 13-field span | M00830 |
| F03824 | Tier observability — sandbox_stop event fields include duration, exit_code, side_effects | cross-ref M049 + architecture | M00830 |
| F03825 | Tier observability — selfdef MS027 observability dashboard renders sandbox tier distribution histogram | cross-ref MS027 + M049 | M00830 |
| F03826 | Tier integration — MS017 agent-guard sandboxes Docker/Podman/containerd containers | cross-ref MS017 | M00829 |
| F03827 | Tier integration — MS017 enforces tier-as-policy via host-level invariants | cross-ref MS017 | M00829 |
| F03828 | Tier integration — MS016 eBPF (Tetragon) observes process behavior within sandbox | cross-ref MS016 | M00829 |
| F03829 | Tier integration — MS023 polarproxy provides network observability for Tier 4/5 sandboxes | cross-ref MS023 | M00829 |
| F03830 | Tier integration — MS024 bridge-l2 provides L2 transparent bridge for network-allowed sandboxes | cross-ref MS024 | M00816 |
| F03831 | Tier integration — MS026 integrity-sentinel baselines sandbox configs (Podman quadlets) | cross-ref MS026 | M00829 |
| F03832 | Tier integration — MS010 hardware-tune-cache informs Tier 6a VFIO GPU availability | cross-ref MS010 | M00834 |
| F03833 | Tier integration — MS013 27-SDD charter governs sandbox-tier finding ledger | cross-ref MS013 | E0330 |
| F03834 | Cross-repo cross-binding — sovereign-os M047 Continuity Manager 8 states (active / paused / hibernated / checkpointed / archived / quarantined / promoted / rolled back) align with sandbox-tier lifecycle | cross-ref M047 + dump 16276 + 16277 | M00819 + M00820 |
| F03835 | Cross-repo cross-binding — sovereign-os M048 Module 3 8 sandbox profiles map to selfdef tier enforcement | cross-ref M048 | M00832 |
| F03836 | Cross-repo cross-binding — sovereign-os M049 9-class memory sensitivity composes with sandbox tier (Tier 1 sandbox + private memory class) | cross-ref M049 | M00832 |
| F03837 | Cross-repo cross-binding — sovereign-os M042 9-axis Choice Architecture boundary "sandbox or host" axis is realized here | cross-ref M042 | M00833 |
| F03838 | Cross-repo cross-binding — sovereign-os M046 LoRA foundry adapters may run in Tier 3 Podman sandbox | cross-ref M046 | M00814 |
| F03839 | Cross-repo cross-binding — sovereign-os M043 Bridge Layer 8-bulk-eval-decision use_sandbox is realized here | cross-ref M043 | M00833 |
| F03840 | Test integration — MS020 L1-L5 layered harness covers tier transitions + tier escalation policy + tier-as-policy enforcement + sandbox event emission + sandbox_start/stop event schema + sandbox tier histogram dashboard | cross-ref MS020 | E0330 |

## Requirements (R07441–R07680)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R07441 | Phase 4 header — "Sandbox Execution" | dump 16252 | F03721 | non-negotiable | false | 10 |
| R07442 | Phase 4 goal — "Let agents act without trusting them blindly" | dump 16258 | F03722 | non-negotiable | false | 10 |
| R07443 | Escalation doctrine — "Start with tiers" | dump 16260 | F03723 | non-negotiable | false | 10 |
| R07444 | Tier 1 — read-only shell | dump 16264 | F03724 | non-negotiable | false | 10 |
| R07445 | Tier 1 capability — agent reads filesystem but cannot mutate | dump 16264 | F03725 | non-negotiable | false | 10 |
| R07446 | Tier 1 use case — code review / analysis / explanation tasks | architecture | F03726 | non-negotiable | false | 10 |
| R07447 | Tier 2 — workspace-write shell | dump 16265 | F03727 | non-negotiable | false | 10 |
| R07448 | Tier 2 capability — write to bounded workspace dir | dump 16265 | F03728 | non-negotiable | false | 10 |
| R07449 | Tier 2 invariant — host fs outside workspace remains read-only | dump 16265 | F03729 | non-negotiable | false | 10 |
| R07450 | Tier 3 — Podman sandbox | dump 16266 | F03730 | non-negotiable | false | 10 |
| R07451 | Tier 3 — container namespaces (mount + UTS + IPC + PID + user) | architecture + cross-ref M045 | F03731 | non-negotiable | false | 10 |
| R07452 | Tier 3 — cgroup v2 resource limits | cross-ref M045 cgroup v2 | F03732 | non-negotiable | false | 10 |
| R07453 | Tier 3 — rootless Podman by default | cross-ref M048 clean pattern | F03733 | non-negotiable | false | 10 |
| R07454 | Tier 3 — AppArmor profile applied | cross-ref M044 AppArmor | F03734 | non-negotiable | false | 10 |
| R07455 | Tier 4 — network-denied sandbox | dump 16267 | F03735 | non-negotiable | false | 10 |
| R07456 | Tier 4 — Podman + `--network=none` | cross-ref M048 | F03736 | non-negotiable | false | 10 |
| R07457 | Tier 4 use case — autonomous offline workflows | cross-ref M042 Offline-Peace-Mode | F03737 | non-negotiable | false | 10 |
| R07458 | Tier 4 — eBPF observes network syscalls + alerts on attempts | cross-ref M045 eBPF + M049 truth sensor | F03738 | non-negotiable | false | 10 |
| R07459 | Tier 5 — network-allowed sandbox | dump 16268 | F03739 | non-negotiable | false | 10 |
| R07460 | Tier 5 — Podman + allowed network egress | cross-ref M048 network-docs-only | F03740 | non-negotiable | false | 10 |
| R07461 | Tier 5 — egress filtering via nftables (per-domain or per-endpoint) | cross-ref MS024 + MS023 | F03741 | non-negotiable | false | 10 |
| R07462 | Tier 5 — policy decides allowed destinations | cross-ref M049 Policy Fabric | F03742 | non-negotiable | false | 10 |
| R07463 | Future tier doctrine — "Then later" | dump 16270 | F03743 | non-negotiable | false | 10 |
| R07464 | Tier 6a — VFIO 3090 VM | dump 16274 | F03744 | non-negotiable | false | 10 |
| R07465 | Tier 6a — IOMMU passthrough kernel modules (vfio-pci) | cross-ref M044 VFIO | F03745 | non-negotiable | false | 10 |
| R07466 | Tier 6a — GPU passthrough to VM (libvirt/QEMU) | cross-ref M048 vfio-3090 | F03746 | non-negotiable | false | 10 |
| R07467 | Tier 6a use case — high-risk experiments + computer-use agents | cross-ref M040 + M042 | F03747 | non-negotiable | false | 10 |
| R07468 | Tier 6b — browser/GUI sandbox | dump 16275 | F03748 | non-negotiable | false | 10 |
| R07469 | Tier 6b use case — perception/GUI workloads | cross-ref M043 3090 perception | F03749 | non-negotiable | false | 10 |
| R07470 | Tier 6b — browser sandbox + display isolation | dump 16275 | F03750 | non-negotiable | false | 10 |
| R07471 | Tier 6b — can stack on Tier 6a VFIO for full isolation | architecture | F03751 | non-negotiable | false | 10 |
| R07472 | Tier 7a — CRIU checkpoints | dump 16276 | F03752 | non-negotiable | false | 10 |
| R07473 | Tier 7a — Checkpoint/Restore In Userspace | cross-ref M047 CRIU | F03753 | non-negotiable | false | 10 |
| R07474 | Tier 7a — Podman supports checkpoint/restore via CRIU | cross-ref M047 Podman+CRIU | F03754 | non-negotiable | false | 10 |
| R07475 | Tier 7a use case — warm sandbox replay for fast retries | cross-ref M047 Warm Sandboxes | F03755 | non-negotiable | false | 10 |
| R07476 | Tier 7a use case — branch experiments via checkpoint restore | cross-ref M047 branch-search | F03756 | non-negotiable | false | 10 |
| R07477 | Tier 7b — ZFS clone workspaces | dump 16277 | F03757 | non-negotiable | false | 10 |
| R07478 | Tier 7b — filesystem clone-per-experiment | cross-ref M047 5-layer save-state | F03758 | non-negotiable | false | 10 |
| R07479 | Tier 7b — clone is copy-on-write (low cost) | cross-ref M044 ZFS | F03759 | non-negotiable | false | 10 |
| R07480 | Tier 7b — clone destroy rolls back experiment | cross-ref M040 Hyper Feature 8 | F03760 | non-negotiable | false | 10 |
| R07481 | Runtime rule — "tool intent is not execution" | dump 16282 | F03761 | non-negotiable | false | 10 |
| R07482 | Runtime rule — proposing tool call ≠ executing it | dump 16282 | F03762 | non-negotiable | false | 10 |
| R07483 | Runtime rule — sandbox-tier resolution sits between intent and execution | architecture | F03763 | non-negotiable | false | 10 |
| R07484 | Runtime rule — policy check (M049 Policy Fabric) gates tier selection | cross-ref M049 | F03764 | non-negotiable | false | 10 |
| R07485 | Selfdef enforcement — MS017 agent-guard enforces sandbox-tier choice | cross-ref MS017 | F03765 | non-negotiable | false | 10 |
| R07486 | Selfdef enforcement — invariants apply to Docker / Podman / containerd | cross-ref MS017 README | F03766 | non-negotiable | false | 10 |
| R07487 | Selfdef observability — MS027 renders sandbox_start + sandbox_stop events | cross-ref MS027 + M049 | F03767 | non-negotiable | false | 10 |
| R07488 | Selfdef observability — events flow to MS025 detect-host event-bus | cross-ref MS025 | F03768 | non-negotiable | false | 10 |
| R07489 | Selfdef policy — MS017 maps to M049's "Can this sandbox access network?" | cross-ref MS017 + M049 | F03769 | non-negotiable | false | 10 |
| R07490 | Selfdef policy — sandbox-tier-as-policy via OPA/Cedar/OpenFGA | cross-ref M049 + MS017 | F03770 | non-negotiable | false | 10 |
| R07491 | Cross-repo binding — sandbox-tier choice envelope surfaces via MS007 typed-mirror | cross-ref MS007 | F03771 | non-negotiable | false | 10 |
| R07492 | Cross-repo binding — MS007 surface-manifest crate carries tier descriptor schema | architecture + cross-ref MS007 | F03772 | non-negotiable | false | 10 |
| R07493 | Cross-repo binding — sovereign-os M048 Module 3 provides 8 profiles | cross-ref M048 | F03773 | non-negotiable | false | 10 |
| R07494 | Cross-repo binding — selfdef enforces host-level; sovereign-os provides tier policy | cross-ref MS017 + M048 + M049 | F03774 | non-negotiable | false | 10 |
| R07495 | Configuration overlay — operator selects tier per-action | cross-ref M042 | F03775 | non-negotiable | false | 10 |
| R07496 | Configuration overlay — operator selects tier per-profile | cross-ref M042 | F03776 | non-negotiable | false | 10 |
| R07497 | Configuration overlay — operator selects tier per-session | cross-ref M042 + M047 | F03777 | non-negotiable | false | 10 |
| R07498 | Configuration overlay — choice-envelope.execution = dry_run / sandbox / vm / host | cross-ref M042 | F03778 | non-negotiable | false | 10 |
| R07499 | Hardware — VFIO 3090 requires IOMMU enabled in BIOS + kernel | cross-ref M044 | F03779 | non-negotiable | false | 10 |
| R07500 | Hardware — VFIO 3090 requires vfio-pci kernel module | cross-ref M044 | F03780 | non-negotiable | false | 10 |
| R07501 | Hardware — CRIU requires criu binary on host | cross-ref M047 | F03781 | non-negotiable | false | 10 |
| R07502 | Hardware — CRIU requires Podman compiled with checkpoint support | cross-ref M047 | F03782 | non-negotiable | false | 10 |
| R07503 | Hardware — ZFS clone workspaces require ZFS dataset hierarchy | cross-ref M044 ZFS | F03783 | non-negotiable | false | 10 |
| R07504 | Hardware — ZFS clone-capable parent dataset | architecture + cross-ref M044 | F03784 | non-negotiable | false | 10 |
| R07505 | Tier 1 capability — read filesystem | dump 16264 + architecture | F03785 | non-negotiable | false | 10 |
| R07506 | Tier 1 forbidden — write filesystem | dump 16264 | F03786 | non-negotiable | false | 10 |
| R07507 | Tier 1 forbidden — execute new processes outside shell | architecture | F03787 | non-negotiable | false | 10 |
| R07508 | Tier 1 forbidden — network egress | dump 16264 | F03788 | non-negotiable | false | 10 |
| R07509 | Tier 2 capability — write to bounded workspace | dump 16265 | F03789 | non-negotiable | false | 10 |
| R07510 | Tier 2 capability — read filesystem outside workspace | dump 16265 | F03790 | non-negotiable | false | 10 |
| R07511 | Tier 2 forbidden — write outside workspace | dump 16265 | F03791 | non-negotiable | false | 10 |
| R07512 | Tier 2 forbidden — execute new privileged operations | dump 16265 | F03792 | non-negotiable | false | 10 |
| R07513 | Tier 3 capability — full file IO within container | dump 16266 | F03793 | non-negotiable | false | 10 |
| R07514 | Tier 3 capability — exec arbitrary commands within container | dump 16266 | F03794 | non-negotiable | false | 10 |
| R07515 | Tier 3 forbidden — host filesystem mutation | dump 16266 | F03795 | non-negotiable | false | 10 |
| R07516 | Tier 3 forbidden — privilege escalation | dump 16266 + cross-ref M048 rootless | F03796 | non-negotiable | false | 10 |
| R07517 | Tier 4 capability — all of Tier 3 within container | dump 16267 | F03797 | non-negotiable | false | 10 |
| R07518 | Tier 4 forbidden — ANY network egress | dump 16267 | F03798 | non-negotiable | false | 10 |
| R07519 | Tier 4 forbidden — DNS resolution | dump 16267 + architecture | F03799 | non-negotiable | false | 10 |
| R07520 | Tier 5 capability — all of Tier 3 + allowed network egress | dump 16268 | F03800 | non-negotiable | false | 10 |
| R07521 | Tier 5 capability — egress to allowed endpoints (whitelisted) | dump 16268 | F03801 | non-negotiable | false | 10 |
| R07522 | Tier 5 forbidden — egress to non-whitelisted endpoints | dump 16268 | F03802 | non-negotiable | false | 10 |
| R07523 | Tier 5 forbidden — privilege escalation | cross-ref M048 rootless | F03803 | non-negotiable | false | 10 |
| R07524 | Tier 6a capability — full GPU access (passthrough) | dump 16274 | F03804 | non-negotiable | false | 10 |
| R07525 | Tier 6a capability — full VM sandbox with allocated CPU + RAM | dump 16274 | F03805 | non-negotiable | false | 10 |
| R07526 | Tier 6a forbidden — host visibility | dump 16274 + architecture | F03806 | non-negotiable | false | 10 |
| R07527 | Tier 6a forbidden — second VM accessing same GPU | architecture + cross-ref M044 VFIO | F03807 | non-negotiable | false | 10 |
| R07528 | Tier 6b capability — browser/GUI surface (X11/Wayland) | dump 16275 | F03808 | non-negotiable | false | 10 |
| R07529 | Tier 6b capability — perception model invocation | dump 16275 + cross-ref M043 | F03809 | non-negotiable | false | 10 |
| R07530 | Tier 6b forbidden — host GUI compromise | dump 16275 + architecture | F03810 | non-negotiable | false | 10 |
| R07531 | Tier 7a capability — checkpoint container state | dump 16276 | F03811 | non-negotiable | false | 10 |
| R07532 | Tier 7a capability — restore container state | dump 16276 | F03812 | non-negotiable | false | 10 |
| R07533 | Tier 7a capability — branch experiment via restore | dump 16276 + cross-ref M047 | F03813 | non-negotiable | false | 10 |
| R07534 | Tier 7a forbidden — checkpoint with GPU state (M047 caveat) | cross-ref M047 CRIU caveat | F03814 | non-negotiable | false | 10 |
| R07535 | Tier 7b capability — ZFS snapshot before experiment | dump 16277 + cross-ref M040 | F03815 | non-negotiable | false | 10 |
| R07536 | Tier 7b capability — ZFS clone for parallel branches | dump 16277 | F03816 | non-negotiable | false | 10 |
| R07537 | Tier 7b capability — destroy clone on rollback | dump 16277 | F03817 | non-negotiable | false | 10 |
| R07538 | Tier 7b forbidden — operate on parent dataset without snapshot | dump 16277 + architecture | F03818 | non-negotiable | false | 10 |
| R07539 | Tier policy — operator picks tier based on task risk | architecture + cross-ref M049 | F03819 | non-negotiable | false | 10 |
| R07540 | Tier policy — runtime can escalate tier (down) for safety | architecture + cross-ref M049 | F03820 | non-negotiable | false | 10 |
| R07541 | Tier policy — runtime requires policy approval to escalate tier (up) | cross-ref M049 + M042 | F03821 | non-negotiable | false | 10 |
| R07542 | Tier policy — every transition logged (sandbox_start + sandbox_stop) | cross-ref M049 16-event taxonomy | F03822 | non-negotiable | false | 10 |
| R07543 | Tier observability — sandbox_start fields include tier, profile, agent_id, trace_id | cross-ref M049 13-field span | F03823 | non-negotiable | false | 10 |
| R07544 | Tier observability — sandbox_stop fields include duration, exit_code, side_effects | cross-ref M049 | F03824 | non-negotiable | false | 10 |
| R07545 | Tier observability — MS027 dashboard renders sandbox tier distribution histogram | cross-ref MS027 + M049 | F03825 | non-negotiable | false | 10 |
| R07546 | Tier integration — MS017 agent-guard sandboxes Docker/Podman/containerd | cross-ref MS017 | F03826 | non-negotiable | false | 10 |
| R07547 | Tier integration — MS017 enforces tier-as-policy | cross-ref MS017 | F03827 | non-negotiable | false | 10 |
| R07548 | Tier integration — MS016 eBPF observes process behavior within sandbox | cross-ref MS016 | F03828 | non-negotiable | false | 10 |
| R07549 | Tier integration — MS023 polarproxy provides network observability for Tier 4/5 | cross-ref MS023 | F03829 | non-negotiable | false | 10 |
| R07550 | Tier integration — MS024 bridge-l2 L2 transparent bridge for network-allowed | cross-ref MS024 | F03830 | non-negotiable | false | 10 |
| R07551 | Tier integration — MS026 integrity-sentinel baselines sandbox configs | cross-ref MS026 | F03831 | non-negotiable | false | 10 |
| R07552 | Tier integration — MS010 hardware-tune-cache informs Tier 6a VFIO GPU availability | cross-ref MS010 | F03832 | non-negotiable | false | 10 |
| R07553 | Tier integration — MS013 27-SDD charter governs sandbox-tier finding ledger | cross-ref MS013 | F03833 | non-negotiable | false | 10 |
| R07554 | Cross-repo — M047 Continuity Manager 8 states align with sandbox-tier lifecycle | cross-ref M047 | F03834 | non-negotiable | false | 10 |
| R07555 | Cross-repo — M048 Module 3 8 sandbox profiles map to selfdef tier enforcement | cross-ref M048 | F03835 | non-negotiable | false | 10 |
| R07556 | Cross-repo — M049 9-class memory sensitivity composes with sandbox tier | cross-ref M049 | F03836 | non-negotiable | false | 10 |
| R07557 | Cross-repo — M042 "sandbox or host" axis realized here | cross-ref M042 | F03837 | non-negotiable | false | 10 |
| R07558 | Cross-repo — M046 LoRA foundry adapters may run in Tier 3 Podman sandbox | cross-ref M046 | F03838 | non-negotiable | false | 10 |
| R07559 | Cross-repo — M043 8-bulk-eval-decision use_sandbox realized here | cross-ref M043 | F03839 | non-negotiable | false | 10 |
| R07560 | Test integration — MS020 L1-L5 covers tier transitions + tier escalation policy + enforcement + sandbox event emission | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07561 | Selfdef MS017 agent-guard module-system invariant — depends on detect-host event-bus | cross-ref MS017 + MS025 | M00829 | non-negotiable | false | 10 |
| R07562 | Selfdef MS027 observability dashboard — exposes sandbox tier metric `selfdef_sandbox_tier_in_use{tier}` | cross-ref MS027 + architecture | F03825 | non-negotiable | false | 10 |
| R07563 | Selfdef MS027 observability dashboard — exposes sandbox transition rate `rate(selfdef_sandbox_transitions_total[5m])` | cross-ref MS027 + architecture | F03825 | non-negotiable | false | 10 |
| R07564 | Selfdef MS023 polarproxy module — Tier 5 network-allowed sandboxes route HTTPS via polarproxy for TLS inspection | cross-ref MS023 | F03829 | non-negotiable | false | 10 |
| R07565 | Selfdef MS024 bridge-l2 module — Tier 5 network-allowed sandboxes connect via bridge_name br0 | cross-ref MS024 | F03830 | non-negotiable | false | 10 |
| R07566 | Selfdef MS016 eBPF — Tetragon TracingPolicies detect tier-violation attempts | cross-ref MS016 | F03828 | non-negotiable | false | 10 |
| R07567 | Selfdef MS026 integrity-sentinel — baselines /usr/share/selfdef/modules/agent-guard/profiles/*.toml as sandbox-policy artifact | cross-ref MS026 | F03831 | non-negotiable | false | 10 |
| R07568 | Selfdef MS017 agent-guard — 2 profiles (host-default + autonomous-agent) align with sandbox tier escalation | cross-ref MS017 | F03826 | non-negotiable | false | 10 |
| R07569 | Selfdef MS019 threat model — sandbox-tier escape is a primary attack surface | cross-ref MS019 | F03826 | non-negotiable | false | 10 |
| R07570 | Selfdef MS022 SSE quota — tier transitions emit OCSF events through detect-host api | cross-ref MS022 | F03767 | non-negotiable | false | 10 |
| R07571 | Tier numbering invariant — tiers 1-5 ship now; 6a + 6b + 7a + 7b are future | dump 16260 + 16270 | M00822 | non-negotiable | false | 10 |
| R07572 | Tier numbering invariant — tier order is monotonically increasing in capability + risk | dump 16264–16277 + architecture | M00823 | non-negotiable | false | 10 |
| R07573 | Tier numbering invariant — operator may use tier-X-with-restrictions notation (e.g. "Tier 3 + AppArmor strict") | architecture | M00833 | non-negotiable | false | 10 |
| R07574 | Tier numbering invariant — runtime SHALL default to lowest-tier-that-satisfies-task-needs | cross-ref M049 + architecture | F03819 | non-negotiable | false | 10 |
| R07575 | Tier defaults — Tier 1 read-only is default for code review / explain / analyze | architecture + dump 16264 | F03726 | non-negotiable | false | 10 |
| R07576 | Tier defaults — Tier 2 workspace-write is default for code generation / patch / refactor | architecture + dump 16265 | F03727 | non-negotiable | false | 10 |
| R07577 | Tier defaults — Tier 3 Podman is default for test execution / build / lint | architecture + dump 16266 | F03730 | non-negotiable | false | 10 |
| R07578 | Tier defaults — Tier 4 network-denied is default for autonomous offline tasks | dump 16267 + cross-ref M042 Offline-Peace-Mode | F03735 | non-negotiable | false | 10 |
| R07579 | Tier defaults — Tier 5 network-allowed is default for research / package install | dump 16268 + cross-ref M042 Research Mode | F03739 | non-negotiable | false | 10 |
| R07580 | Tier defaults — Tier 6a VFIO 3090 VM is default for high-risk computer-use agents | dump 16274 + cross-ref M042 High-Risk Mode | F03744 | non-negotiable | false | 10 |
| R07581 | Tier defaults — Tier 6b browser/GUI is default for perception/screenshot tasks | dump 16275 + cross-ref M043 | F03748 | non-negotiable | false | 10 |
| R07582 | Tier defaults — Tier 7a CRIU is default for branch-experiment workflows | dump 16276 + cross-ref M047 branch-search | F03752 | non-negotiable | false | 10 |
| R07583 | Tier defaults — Tier 7b ZFS clone is default for ZFS-snapshot-before-write profile | dump 16277 + cross-ref M040 + M042 Autonomous Code Mode | F03757 | non-negotiable | false | 10 |
| R07584 | Phase 3 context — sandbox transitions emit policy_decision + sandbox_start + sandbox_stop events | dump 16207–16240 + cross-ref M049 | F03822 | non-negotiable | false | 10 |
| R07585 | Phase 3 context — basic allow/deny/ask/sandbox states inform tier selection | dump 16222–16224 | F03764 | non-negotiable | false | 10 |
| R07586 | Phase 5 context — "Make the station situated" follows Phase 4 Sandbox Execution | dump 16288–16290 | E0330 | non-negotiable | false | 10 |
| R07587 | Phase 5 context — situated station integrates sandbox + memory + MAP planes | dump 16288 + cross-ref M028 + M036 | E0330 | non-negotiable | false | 10 |
| R07588 | Doctrine — sandbox tiers are a TRUST surface, not just a SECURITY surface | dump 16258 + architecture | E0321 | non-negotiable | false | 10 |
| R07589 | Doctrine — "agents act without trusting them blindly" implies sandbox tiers are operator-trust-calibrated | dump 16258 | E0321 | non-negotiable | false | 10 |
| R07590 | Doctrine — tier choice realizes operator's calibration of trust per task | architecture + cross-ref M042 | E0329 | non-negotiable | false | 10 |
| R07591 | Doctrine — runtime SHALL surface tier choice to operator (Choice Architecture) | cross-ref M042 + M049 | F03819 | non-negotiable | false | 10 |
| R07592 | Doctrine — runtime SHALL log every tier transition (Observability Fabric) | cross-ref M049 | F03822 | non-negotiable | false | 10 |
| R07593 | Doctrine — runtime SHALL refuse tier escalation without policy approval (Policy Fabric) | cross-ref M049 + M042 | F03821 | non-negotiable | false | 10 |
| R07594 | Doctrine — runtime MAY downgrade tier automatically for safety (Telemetry As Control) | cross-ref M049 + architecture | F03820 | non-negotiable | false | 10 |
| R07595 | Doctrine — every sandbox tier MUST have a checkable invariant set (file IO + process + network + GPU + escalation) | architecture + dump 16264–16277 | M00823 + M00824 + M00825 + M00826 | non-negotiable | false | 10 |
| R07596 | Doctrine — tier invariants enforced via MS017 agent-guard + MS016 eBPF + MS044 nftables + AppArmor + cgroup v2 | cross-ref MS017 + MS016 + MS024 + M044 + M045 | F03765 + F03828 | non-negotiable | false | 10 |
| R07597 | Doctrine — tier invariant violations emit OCSF Detection Finding via MS026 integrity-sentinel-style emission | cross-ref MS026 + M049 | F03767 | non-negotiable | false | 10 |
| R07598 | Doctrine — tier capabilities cumulate (Tier N includes Tier N-1 capabilities except where explicitly overridden) | architecture + dump 16264–16277 | M00822 | non-negotiable | false | 10 |
| R07599 | Project-boundary — selfdef MS032 is the IPS-side tier-enforcement scope (host invariants) | architecture + cross-ref MS017 | E0330 | non-negotiable | false | 10 |
| R07600 | Project-boundary — sovereign-os M048 Module 3 is the runtime-side tier-profile catalog | cross-ref M048 | E0330 | non-negotiable | false | 10 |
| R07601 | Project-boundary — sovereign-os M049 Policy Fabric is the runtime-side tier-policy engine | cross-ref M049 | E0330 | non-negotiable | false | 10 |
| R07602 | Project-boundary — cross-repo binding via MS007 typed-mirror crates (8/8 SATURATED) | cross-ref MS007 | E0330 | non-negotiable | false | 10 |
| R07603 | Operator UX — operator chooses tier via `selfdefctl sandbox apply --tier=read-only` or per-action via M042 Choice Envelope | cross-ref M042 | F03819 | non-negotiable | false | 10 |
| R07604 | Operator UX — operator inspects active tier via `selfdefctl sandbox status` | architecture + cross-ref MS017 | F03826 | non-negotiable | false | 10 |
| R07605 | Operator UX — operator escalates tier via `selfdefctl sandbox escalate --to=podman` with policy approval | cross-ref MS017 + M049 | F03821 | non-negotiable | false | 10 |
| R07606 | Operator UX — operator views tier transition history via MS027 dashboard | cross-ref MS027 | F03825 | non-negotiable | false | 10 |
| R07607 | Hardware reality — Zen 5 9900X + RTX PRO 6000 + RTX 3090 SAIN-01 supports all 9 sandbox tiers | architecture + cross-ref M044 + M048 | F03779 | non-negotiable | false | 10 |
| R07608 | Hardware reality — IOMMU groups MUST be sufficient for VFIO 3090 isolation (vfio-pci.ids check) | cross-ref M044 + dump 16274 | F03779 | non-negotiable | false | 10 |
| R07609 | Hardware reality — VFIO 3090 binding is OS-boot time (vfio-pci.ids kernel parameter) | cross-ref M044 + dump 16274 | F03779 | non-negotiable | false | 10 |
| R07610 | Hardware reality — VFIO 3090 hot-rebind is possible but disruptive | cross-ref M044 | F03780 | non-negotiable | false | 10 |
| R07611 | Hardware reality — Podman + CRIU requires Linux kernel CONFIG_CHECKPOINT_RESTORE=y | cross-ref M047 + dump 16276 | F03781 | non-negotiable | false | 10 |
| R07612 | Hardware reality — ZFS clone is O(1) creation cost (copy-on-write) | cross-ref M044 ZFS | F03759 | non-negotiable | false | 10 |
| R07613 | Hardware reality — ZFS clone has space overhead proportional to divergence | cross-ref M044 ZFS | F03759 | non-negotiable | false | 10 |
| R07614 | Hardware reality — Tier 6a single-VM passthrough means RTX 3090 can host ONE sandbox at a time | cross-ref M044 VFIO + dump 16274 | F03807 | non-negotiable | false | 10 |
| R07615 | Hardware reality — Tier 6a passes through PCI device, so VM boot/destroy is GPU cycle | cross-ref M044 | F03807 | non-negotiable | false | 10 |
| R07616 | Cross-module — MS022 SSE quota module-system invariant — `selfdef_subscriber_count{token}` excludes sandbox-internal subscribers | cross-ref MS022 + architecture | F03767 | non-negotiable | false | 10 |
| R07617 | Cross-module — MS015 NATS messaging — sandbox-internal NATS subjects use `selfdef.sandbox.<tier>.<agent_id>` namespacing | cross-ref MS015 + architecture | F03828 | non-negotiable | false | 10 |
| R07618 | Cross-module — MS016 Tetragon TracingPolicies — sandbox-tier-aware policies emit different events per tier | cross-ref MS016 + architecture | F03828 | non-negotiable | false | 10 |
| R07619 | Cross-module — MS003 correlator + store + responder — sandbox events flow through normal selfdef-daemon pipeline | cross-ref MS003 + MS025 | F03767 | non-negotiable | false | 10 |
| R07620 | Cross-module — MS004 14-notifier-integrations — sandbox-tier-escape events route through ntfy/Signal/etc. | cross-ref MS004 + M049 | F03767 | non-negotiable | false | 10 |
| R07621 | Cross-module — MS005 notifier engine — sandbox-tier-escape severity high triggers high-priority notification | cross-ref MS005 + architecture | F03767 | non-negotiable | false | 10 |
| R07622 | Cross-module — MS008 selfdef-on-sain01 integration — full 9-tier sandbox catalog deployed to SAIN-01 reference box | cross-ref MS008 | E0330 | non-negotiable | false | 10 |
| R07623 | Cross-module — MS009 audit cycles — sandbox-tier audit is part of Phase 6/7/8 + cycle3/4/5/6 vectors | cross-ref MS009 | F03826 | non-negotiable | false | 10 |
| R07624 | Cross-module — MS010 hardware-tune-cache — exposes vfio.available + criu.available + zfs.available + iommu.groups | cross-ref MS010 | F03832 | non-negotiable | false | 10 |
| R07625 | Cross-module — MS011 operator dashboard — sandbox-tier widget shows active tier + transition history + escalation requests | cross-ref MS011 + MS027 | F03825 | non-negotiable | false | 10 |
| R07626 | Cross-module — MS012 perimeter coexistence — Tier 5 network-allowed traffic respects perimeter rules | cross-ref MS012 + dump 16268 | F03742 | non-negotiable | false | 10 |
| R07627 | Cross-module — MS013 27-SDD charter — sandbox-tier doctrine traces to SDD-005 test contract + SDD-019 + SDD-020 audit cycles | cross-ref MS013 + architecture | F03833 | non-negotiable | false | 10 |
| R07628 | Cross-module — MS014 SSH-wrap — Tier 5+ outbound SSH respects ssh-wrap defense | cross-ref MS014 + architecture | F03742 | non-negotiable | false | 10 |
| R07629 | Cross-module — MS018 VPN-bridge — Tier 5 network-allowed traffic may route via per-profile VPN instance | cross-ref MS018 | F03742 | non-negotiable | false | 10 |
| R07630 | Cross-module — MS020 L1-L5 test harness — sandbox-tier transitions tested via Pipeline category + Seam category | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07631 | Cross-module — MS021 shared module-script lib v2 — sandbox-tier helpers (sandbox_run, sandbox_check) available to all modules | cross-ref MS021 + architecture | F03826 | non-negotiable | false | 10 |
| R07632 | Cross-module — MS028 bitnet-gpu-inference — sandboxed bitnet workloads use Tier 6a VFIO 3090 OR host-mode | cross-ref MS028 | F03744 | non-negotiable | false | 10 |
| R07633 | Cross-module — MS029 slm-cpu-loop — sandboxed SLM CPU workloads use Tier 3/4/5 Podman | cross-ref MS029 | F03730 | non-negotiable | false | 10 |
| R07634 | Cross-module — MS030 tensor-parallel-inference — multi-GPU TP requires host or VM-with-all-GPUs (not Tier 6a) | cross-ref MS030 | F03804 | non-negotiable | false | 10 |
| R07635 | Cross-module — MS031 wasm-aot-cache — Tier 3 Podman sandboxes may consume cached .cwasm artifacts | cross-ref MS031 | F03730 | non-negotiable | false | 10 |
| R07636 | Documentation — sandbox tier descriptor schema lives in MS007 surface-manifest crate | cross-ref MS007 | F03771 | non-negotiable | false | 10 |
| R07637 | Documentation — sandbox tier ATT&CK mapping documented in MS019 threat model | cross-ref MS019 | F03826 | non-negotiable | false | 10 |
| R07638 | Documentation — sandbox tier audit trail format documented in MS013 27-SDD charter | cross-ref MS013 | F03833 | non-negotiable | false | 10 |
| R07639 | Documentation — sandbox tier dashboard widget rendered via MS027 observability | cross-ref MS027 | F03825 | non-negotiable | false | 10 |
| R07640 | Documentation — sandbox tier integration matrix exposed via `selfdefctl modules info sandbox-tiers` | architecture + cross-ref MS006 | F03804 | non-negotiable | false | 10 |
| R07641 | Operator references — Podman documentation root (docs.podman.io) | cross-ref M048 | F03730 | non-negotiable | false | 10 |
| R07642 | Operator references — CRIU documentation root (criu.org) | cross-ref M047 | F03752 | non-negotiable | false | 10 |
| R07643 | Operator references — OpenZFS documentation root (openzfs.org) | cross-ref M044 | F03757 | non-negotiable | false | 10 |
| R07644 | Operator references — Linux VFIO documentation (kernel.org/doc/Documentation/vfio.txt) | cross-ref M044 + dump 16274 | F03744 | non-negotiable | false | 10 |
| R07645 | Operator references — AppArmor Linux Security Module documentation | cross-ref M044 + M045 | F03734 | non-negotiable | false | 10 |
| R07646 | Operator references — seccomp BPF Linux kernel documentation | cross-ref M045 | F03734 | non-negotiable | false | 10 |
| R07647 | Operator references — cgroup v2 admin guide (kernel.org/doc/Documentation/cgroup-v2.txt) | cross-ref M045 | F03732 | non-negotiable | false | 10 |
| R07648 | Operator references — Linux network namespaces ip-netns(8) man page | cross-ref M045 | F03735 | non-negotiable | false | 10 |
| R07649 | Operator references — Podman Quadlet podman-systemd.unit(5) man page | cross-ref M048 | F03730 | non-negotiable | false | 10 |
| R07650 | Operator references — NVIDIA Container Toolkit CDI specs for GPU access | cross-ref M048 NVIDIA CDI | F03804 | non-negotiable | false | 10 |
| R07651 | Doctrine — sandbox tier is OPERATOR-FACING surface (NOT internal-only) | architecture + cross-ref M042 | F03819 | non-negotiable | false | 10 |
| R07652 | Doctrine — sandbox tier choice composes with model choice + memory class choice + cloud-or-not choice | cross-ref M042 9-axis + M049 + M048 | F03837 | non-negotiable | false | 10 |
| R07653 | Doctrine — runtime SHALL recommend a tier per task but operator SHALL be able to override (within hard limits) | cross-ref M042 user-approval + M049 hard policy beats profile | F03820 | non-negotiable | false | 10 |
| R07654 | Doctrine — every tier MUST have a documented attack surface mapping (MS019 threat model) | cross-ref MS019 | F03826 | non-negotiable | false | 10 |
| R07655 | Doctrine — every tier MUST have a documented escape detection mechanism (MS016 Tetragon + eBPF) | cross-ref MS016 + M045 | F03828 | non-negotiable | false | 10 |
| R07656 | Doctrine — tier upgrade/downgrade MUST be atomic (no half-states) | architecture + cross-ref M049 | F03821 | non-negotiable | false | 10 |
| R07657 | Doctrine — tier descriptor MUST include tier_id + name + capabilities + forbidden + required-hardware + observability-events | architecture + cross-ref MS007 | F03771 | non-negotiable | false | 10 |
| R07658 | Doctrine — tier descriptor schema versioned ("schema_version": "1.0.0") | cross-ref MS028 + MS030 schema pattern | F03771 | non-negotiable | false | 10 |
| R07659 | Doctrine — tier descriptor exported via MS007 surface-manifest typed-mirror to sovereign-os | cross-ref MS007 + cross-ref M048 | F03771 | non-negotiable | false | 10 |
| R07660 | Doctrine — tier transitions emit OCSF events (class_uid=2004 Detection Finding or class_uid=1006 Process Activity) | cross-ref M049 + cross-ref MS026 | F03822 | non-negotiable | false | 10 |
| R07661 | Test contract — MS020 L1 (translation) test category covers tier descriptor schema rendering | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07662 | Test contract — MS020 L2 (pipeline) test category covers tier transition state machine | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07663 | Test contract — MS020 L3 (module-script) test category covers sandbox apply/check/uninstall (if module-as-script) | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07664 | Test contract — MS020 L4 (seam) test category covers tier-enforcement-via-MS017-agent-guard | cross-ref MS020 + MS017 | F03840 | non-negotiable | false | 10 |
| R07665 | Test contract — MS020 L5 (system) test category covers end-to-end tier escalation under policy approval | cross-ref MS020 + M049 | F03840 | non-negotiable | false | 10 |
| R07666 | Cross-repo cross-binding — sovereign-os M042 8-axis-choice = (local/cloud + fast/careful + private/shared + automatic/gated + cheap/best + sandbox/host + scout/oracle + spec-first/exploratory + TDD strict/prototype) — "sandbox or host" is the axis realized here | cross-ref M042 | F03837 | non-negotiable | false | 10 |
| R07667 | Cross-repo cross-binding — sovereign-os M042 5-profile-bundle (Offline Peace + Research + Autonomous Code + High-Risk + Fast Local) — Autonomous Code + High-Risk default to Tier 6+ | cross-ref M042 | F03821 | non-negotiable | false | 10 |
| R07668 | Cross-repo cross-binding — sovereign-os M046 LoRA foundry adapter training MUST run in Tier 3 Podman sandbox (CPU-only / no host write) | cross-ref M046 | F03838 | non-negotiable | false | 10 |
| R07669 | Cross-repo cross-binding — sovereign-os M047 Continuity Manager checkpoint/restore IS Tier 7a CRIU implementation | cross-ref M047 | F03811 | non-negotiable | false | 10 |
| R07670 | Cross-repo cross-binding — sovereign-os M050 Design Law "Tools prove" = sandbox tier resolves how tools prove | cross-ref M050 | F03763 | non-negotiable | false | 10 |
| R07671 | Doctrine — sandbox tier IS the answer to "trust but verify" for AI agents | dump 16258 + architecture | E0321 | non-negotiable | false | 10 |
| R07672 | Doctrine — operator MUST be able to ASK runtime "what tier am I in right now" via simple CLI | architecture + cross-ref M042 | F03826 | non-negotiable | false | 10 |
| R07673 | Doctrine — operator MUST be able to SET tier from CLI/dashboard/profile | cross-ref M042 + MS011 | F03819 | non-negotiable | false | 10 |
| R07674 | Doctrine — operator MUST be able to AUDIT all tier transitions ever | cross-ref MS009 + M049 | F03822 | non-negotiable | false | 10 |
| R07675 | Doctrine — tier-as-code (declarative tier definitions live in sovereign-os M048 sandbox profile catalog) | cross-ref M048 | F03835 | non-negotiable | false | 10 |
| R07676 | Doctrine — tier-as-policy (tier rules enforced by sovereign-os M049 Policy Fabric) | cross-ref M049 | F03769 | non-negotiable | false | 10 |
| R07677 | Doctrine — tier-as-observability (tier transitions emit M049 16-event taxonomy entries) | cross-ref M049 | F03822 | non-negotiable | false | 10 |
| R07678 | Doctrine — tier-as-test (MS020 L1-L5 covers full tier lifecycle) | cross-ref MS020 | F03840 | non-negotiable | false | 10 |
| R07679 | Doctrine — tier-as-bridge (selfdef enforces; sovereign-os orchestrates; operator decides) | cross-ref MS017 + M048 + M049 + M042 | F03774 | non-negotiable | false | 10 |
| R07680 | Composite — MS032 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Phase 4 Sandbox Execution from dump 16252-16290 ("Let agents act without trusting them blindly" + 5 starter tiers read-only/workspace-write/Podman/network-denied/network-allowed + 4 future tiers VFIO-3090-VM/browser-GUI/CRIU-checkpoints/ZFS-clone-workspaces + runtime rule "tool intent is not execution"); cross-module enforcement via selfdef MS017 agent-guard + observability via MS027 + policy via M049 + 9-axis choice via M042 + profile bundles via M042/M044/M048 + continuity via M047 + hardware substrate via M044+M048; cross-repo binding via MS007 surface-manifest typed-mirror crate | dump 16252–16290 + cross-ref MS017 + MS027 + M042 + M044 + M045 + M047 + M048 + M049 + M050 + MS007 | E0321 + E0322 + E0323 + E0324 + E0325 + E0326 + E0327 + E0328 + E0329 + E0330 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: Phase 4 doctrine + 5 starter tiers + 4 future tiers (R07441–R07480) + runtime rule + selfdef enforcement + observability + policy + cross-repo binding (R07481–R07494) + configuration overlay + hardware reality (R07495–R07504) + per-tier capabilities + forbidden invariants (R07505–R07538) + tier policy doctrine + observability + 8 selfdef integration modules (R07539–R07570) + tier numbering invariants + defaults (R07571–R07583) + Phase 3+5 context (R07584–R07587) + doctrine (R07588–R07598) + project-boundary (R07599–R07602) + operator UX (R07603–R07606) + hardware reality detail (R07607–R07615) + cross-module integration (R07616–R07635) + documentation (R07636–R07640) + operator references (R07641–R07650) + doctrine extended (R07651–R07660) + test contract MS020 L1-L5 (R07661–R07665) + cross-repo cross-binding (R07666–R07670) + doctrine summarization (R07671–R07679) + composite (R07680)
- Source range 39 lines from dump (16252–16290) yields 240 R-rows representing a 6.2:1 R-per-line ratio (the dump section is intentionally compact; architectural elaboration via cross-module + cross-repo bindings carries the bulk per established pattern)
- Project boundary — MS032 is selfdef IPS sandbox-tier enforcement scope; sovereign-os M048 Module 3 owns runtime-side profile catalog; sovereign-os M049 Policy Fabric owns tier-policy engine; cross-repo binding via MS007 typed-mirror crates

## Cross-references

- Adjacent INDEX rows: MS031 WASM AOT cache / MS033 Policy and trace
- Source — dump 16252–16290 Phase 4 Sandbox Execution doctrinal block (+ Phase 3 + Phase 5 transition context)
- Cross-repo realization — sovereign-os M042 Choice Architecture 9-axis (sandbox/host axis) + M044 Sovereign-OS substrate (Sandbox Plane) + M045 Linux as intelligence governor (cgroup v2 + AppArmor + namespaces + eBPF) + M047 Continuity (CRIU + ZFS clone) + M048 Module 3 Container/Sandbox Fabric (8 sandbox profiles + Podman Quadlet + NVIDIA CDI) + M049 Policy Fabric (OPA/Cedar/OpenFGA + 7 policy decisions + Intent-Based Policy) + M050 Design Law ("Tools prove")
- Selfdef integration — MS010 hardware-tune-cache (VFIO/CRIU/ZFS availability) + MS013 27-SDD charter (audit findings) + MS016 Tetragon TracingPolicies (escape detection) + MS017 agent-guard (host-level invariants) + MS019 threat model (attack surface) + MS020 L1-L5 test harness (lifecycle coverage) + MS022 SSE quota + MS023 polarproxy (Tier 5 TLS inspection) + MS024 bridge-l2 (network bridge) + MS025 detect-host (event-bus) + MS026 integrity-sentinel (sandbox-policy baseline) + MS027 observability (tier metric + transition histogram)
- Cross-repo binding — MS007 surface-manifest typed-mirror crate (SATURATED 8/8) carries tier-descriptor schema between repos
- SD-R lineage — MS032 ties into SDD-019 + SDD-020 audit cycle findings + SDD-005 test contract
- Operator references: docs.podman.io + criu.org + openzfs.org + kernel.org/doc/Documentation/vfio.txt + AppArmor LSM docs + seccomp BPF kernel docs + kernel.org/doc/Documentation/cgroup-v2.txt + ip-netns(8) + podman-systemd.unit(5) + NVIDIA Container Toolkit CDI specs
