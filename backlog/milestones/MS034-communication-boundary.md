# MS034 — Communication boundary

> Parent: `backlog/milestones/INDEX.md` row MS034 (source ref dump 3450–3488).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 3450–3488 (Communication Boundary doctrinal block).
> All entries below extract verbatim from these dump lines or trace to existing selfdef + sovereign-os repo state. No invention.

## Epics (E0341–E0350)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0341 | Communication Boundary doctrine — "Use compact messages, not bulk tensors" | dump 3450–3452 |
| E0342 | Host ↔ 3090 VM transport options (4) — virtio-vsock / gRPC over vsock / Unix socket proxy / shared folder only for explicit exchange dirs | dump 3456–3462 |
| E0343 | Message type — DraftRequest (host asks VM for draft generation) | dump 3466 |
| E0344 | Message type — DraftResult (VM returns drafts to host) + EmbeddingRequest (host asks VM for embeddings) + RerankResult (VM returns reranked candidates) | dump 3467–3469 |
| E0345 | Message type — VisionResult (VM returns vision/GUI/perception output) + ToolPlan (VM proposes tool calls) + RiskAssessment (VM scores risk) + PatchProposal (VM proposes file patches) | dump 3470–3473 |
| E0346 | Invariant — "Never let the VM directly mutate host truth" | dump 3477 |
| E0347 | Invariant — "The VM proposes. Host commits" | dump 3479 |
| E0348 | 4-line invariant pipeline — VM output = candidate / Host AVX-512 policy = filter / Oracle = verify / Replay log = commit | dump 3481–3484 |
| E0349 | "Same invariant again" — communication boundary is the SAME PATTERN as workflow boundary + tool boundary + memory boundary | dump 3487 |
| E0350 | Cross-module + cross-repo composition — selfdef-side enforcement realizes sovereign-os M048 Module 3 Container/Sandbox Fabric + M042 Choice Architecture (sandbox vs host) + M044 VFIO/IOMMU + M050 Design Law "VM proposes. Host commits." | architecture + cross-ref M048 + M042 + M044 + M050 |

## Modules (M00863–M00888)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00863 | Doctrine — "Use compact messages, not bulk tensors" | dump 3452 | E0341 |
| M00864 | Transport — virtio-vsock (Linux kernel VM↔host socket family AF_VSOCK) | dump 3458 | E0342 |
| M00865 | Transport — gRPC over vsock (gRPC channel using vsock as transport) | dump 3459 | E0342 |
| M00866 | Transport — Unix socket proxy (host-side proxy that bridges to vsock or guest-only socket) | dump 3460 | E0342 |
| M00867 | Transport — shared folder for explicit exchange dirs only (NEVER for in-band traffic) | dump 3461 | E0342 |
| M00868 | Message — DraftRequest | dump 3466 | E0343 |
| M00869 | Message — DraftResult | dump 3467 | E0344 |
| M00870 | Message — EmbeddingRequest | dump 3468 | E0344 |
| M00871 | Message — RerankResult | dump 3469 | E0344 |
| M00872 | Message — VisionResult | dump 3470 | E0345 |
| M00873 | Message — ToolPlan | dump 3471 | E0345 |
| M00874 | Message — RiskAssessment | dump 3472 | E0345 |
| M00875 | Message — PatchProposal | dump 3473 | E0345 |
| M00876 | Invariant — "Never let the VM directly mutate host truth" | dump 3477 | E0346 |
| M00877 | Invariant — "VM proposes. Host commits" | dump 3479 | E0347 |
| M00878 | Pipeline step — VM output = candidate | dump 3481 | E0348 |
| M00879 | Pipeline step — Host AVX-512 policy = filter | dump 3482 | E0348 |
| M00880 | Pipeline step — Oracle = verify | dump 3483 | E0348 |
| M00881 | Pipeline step — Replay log = commit | dump 3484 | E0348 |
| M00882 | "Same invariant again" — communication boundary IS the same pattern repeated | dump 3487 | E0349 |
| M00883 | Selfdef enforcement — MS017 agent-guard enforces "VM proposes. Host commits." | cross-ref MS017 | E0350 |
| M00884 | Selfdef enforcement — MS015 NATS messaging may transport the 8 message types | cross-ref MS015 | E0350 |
| M00885 | Selfdef enforcement — MS016 eBPF observes virtio-vsock traffic for policy compliance | cross-ref MS016 | E0350 |
| M00886 | Cross-repo binding — sovereign-os M048 Module 3 sandbox profile "vfio-3090" hosts the VM | cross-ref M048 | E0350 |
| M00887 | Cross-repo binding — sovereign-os M044 VFIO/IOMMU substrate enables the VM | cross-ref M044 | E0350 |
| M00888 | Cross-repo binding — sovereign-os M050 Design Law "Tools prove" maps to communication-boundary invariant pipeline | cross-ref M050 | E0350 |

## Features (F03961–F04080)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03961 | Section header — "Communication Boundary" | dump 3450 | E0341 |
| F03962 | "Use compact messages, not bulk tensors" | dump 3452 | M00863 |
| F03963 | "Host ↔ 3090 VM over" | dump 3456 | E0342 |
| F03964 | Transport — virtio-vsock | dump 3458 | M00864 |
| F03965 | Transport — gRPC over vsock | dump 3459 | M00865 |
| F03966 | Transport — Unix socket proxy | dump 3460 | M00866 |
| F03967 | Transport — shared folder only for explicit exchange dirs | dump 3461 | M00867 |
| F03968 | "Message types" section header | dump 3464 | E0343 |
| F03969 | Message — DraftRequest | dump 3466 | M00868 |
| F03970 | Message — DraftResult | dump 3467 | M00869 |
| F03971 | Message — EmbeddingRequest | dump 3468 | M00870 |
| F03972 | Message — RerankResult | dump 3469 | M00871 |
| F03973 | Message — VisionResult | dump 3470 | M00872 |
| F03974 | Message — ToolPlan | dump 3471 | M00873 |
| F03975 | Message — RiskAssessment | dump 3472 | M00874 |
| F03976 | Message — PatchProposal | dump 3473 | M00875 |
| F03977 | Invariant — "Never let the VM directly mutate host truth" | dump 3477 | M00876 |
| F03978 | Invariant — "The VM proposes. Host commits." | dump 3479 | M00877 |
| F03979 | Pipeline — "VM output = candidate" | dump 3481 | M00878 |
| F03980 | Pipeline — "Host AVX-512 policy = filter" | dump 3482 | M00879 |
| F03981 | Pipeline — "Oracle = verify" | dump 3483 | M00880 |
| F03982 | Pipeline — "Replay log = commit" | dump 3484 | M00881 |
| F03983 | "Same invariant again" | dump 3487 | M00882 |
| F03984 | virtio-vsock — Linux AF_VSOCK socket family | cross-ref dump 3458 | M00864 |
| F03985 | virtio-vsock — host-guest cid/port addressing | architecture + dump 3458 | M00864 |
| F03986 | virtio-vsock — bidirectional stream + dgram | architecture + dump 3458 | M00864 |
| F03987 | gRPC over vsock — protobuf message schemas for all 8 message types | dump 3459 + architecture | M00865 |
| F03988 | gRPC over vsock — async streaming for embeddings + reranking | dump 3459 + architecture | M00865 |
| F03989 | Unix socket proxy — host-side daemon translates vsock to AF_UNIX | dump 3460 | M00866 |
| F03990 | Unix socket proxy — accepts host CLI/API calls and forwards to VM | architecture + dump 3460 | M00866 |
| F03991 | Shared folder doctrine — explicit exchange dirs only (NOT in-band) | dump 3461 | M00867 |
| F03992 | Shared folder doctrine — large blobs go through shared folder; control through vsock | architecture + dump 3461 | M00867 |
| F03993 | Shared folder doctrine — virtiofs or 9p mount points | architecture + dump 3461 | M00867 |
| F03994 | DraftRequest schema — prompt + context_refs + budget + profile + trace_id | architecture + cross-ref M049 | M00868 |
| F03995 | DraftResult schema — draft_text + tokens_used + confidence + trace_id | architecture + cross-ref M049 | M00869 |
| F03996 | EmbeddingRequest schema — text/blob + model_id + dim + trace_id | architecture + cross-ref M049 | M00870 |
| F03997 | EmbeddingResult schema — vector + dim + model_id + trace_id (alias of EmbeddingRequest response) | architecture + cross-ref M049 | M00870 |
| F03998 | RerankResult schema — candidates + scores + reasoning + trace_id | architecture + cross-ref M049 | M00871 |
| F03999 | VisionResult schema — perception_output + confidence + trace_id | architecture + cross-ref M049 | M00872 |
| F04000 | ToolPlan schema — tool_id + arguments + expected_side_effects + trace_id | architecture + cross-ref M049 | M00873 |
| F04001 | RiskAssessment schema — risk_score + risk_class + reasoning + trace_id | architecture + cross-ref M049 | M00874 |
| F04002 | PatchProposal schema — file + diff + rationale + trace_id | architecture + cross-ref M049 | M00875 |
| F04003 | Invariant rationale — host filesystem MUST remain canonical truth | dump 3477 | M00876 |
| F04004 | Invariant rationale — VM filesystem is sandbox, NOT shared truth | dump 3477 + cross-ref MS032 | M00876 |
| F04005 | Invariant rationale — even "shared folder" is one-way explicit-exchange-only | dump 3461 + 3477 | M00876 |
| F04006 | Invariant — "VM proposes" means VM outputs are SUGGESTIONS, not COMMANDS | dump 3479 | M00877 |
| F04007 | Invariant — "Host commits" means host AVX-512 policy makes binding decisions | dump 3479 + 3482 | M00877 |
| F04008 | Pipeline — every VM output (candidate) MUST pass through filter step | dump 3482 | M00879 |
| F04009 | Pipeline — AVX-512 policy filter is the FIRST gate | dump 3482 | M00879 |
| F04010 | Pipeline — Oracle verification is the SECOND gate (high-value items only) | dump 3483 + cross-ref M043 | M00880 |
| F04011 | Pipeline — Replay log is APPEND-ONLY committed truth | dump 3484 + cross-ref M044 | M00881 |
| F04012 | Pipeline — replay log = ZFS-backed write-ahead | cross-ref M044 ZFS | M00881 |
| F04013 | "Same invariant again" — workflow boundary applies same pattern | dump 3487 + cross-ref M025 | M00882 |
| F04014 | "Same invariant again" — tool boundary applies same pattern | dump 3487 + cross-ref MS032 | M00882 |
| F04015 | "Same invariant again" — memory boundary applies same pattern | dump 3487 + cross-ref M028 | M00882 |
| F04016 | Selfdef MS017 agent-guard — enforces "VM proposes. Host commits." at host-level | cross-ref MS017 | M00883 |
| F04017 | Selfdef MS017 agent-guard — refuses host-mutation calls from VM | cross-ref MS017 | M00883 |
| F04018 | Selfdef MS015 NATS — transports 8 message types between selfdef-daemon + VM | cross-ref MS015 | M00884 |
| F04019 | Selfdef MS015 NATS — JetStream guarantees delivery for ToolPlan + PatchProposal | cross-ref MS015 + dump 3471 + 3473 | M00884 |
| F04020 | Selfdef MS016 eBPF — observes virtio-vsock traffic via uprobe/kprobe | cross-ref MS016 + dump 3458 | M00885 |
| F04021 | Selfdef MS016 eBPF — emits Tetragon events on policy violations | cross-ref MS016 | M00885 |
| F04022 | Cross-repo — sovereign-os M048 Module 3 sandbox profile "vfio-3090" provisions the 3090 VM | cross-ref M048 | M00886 |
| F04023 | Cross-repo — sovereign-os M044 VFIO/IOMMU substrate enables IOMMU passthrough | cross-ref M044 | M00887 |
| F04024 | Cross-repo — sovereign-os M040 Hyper Feature 7 VFIO 3090 trust boundary | cross-ref M040 | M00887 |
| F04025 | Cross-repo — sovereign-os M050 Design Law "Tools prove" maps to communication-boundary pipeline | cross-ref M050 | M00888 |
| F04026 | Cross-repo — sovereign-os M042 Choice Architecture sandbox-vs-host axis = communication-boundary mode selector | cross-ref M042 | M00886 |
| F04027 | Cross-repo — sovereign-os M043 Bridge Layer Blackwell-oracle verifies VM-output high-value items | cross-ref M043 + dump 3483 | M00880 |
| F04028 | Cross-repo — sovereign-os M046 LoRA foundry adapters may run inside VM (Tier 6a) | cross-ref M046 + MS032 | E0350 |
| F04029 | Cross-repo — sovereign-os M047 Continuity Manager checkpoints VM state via CRIU | cross-ref M047 | E0350 |
| F04030 | Cross-repo — sovereign-os M049 Policy Fabric evaluates 8-message-type policy decisions | cross-ref M049 | M00877 |
| F04031 | Cross-repo — MS007 surface-manifest typed-mirror crate carries 8-message-type schemas | cross-ref MS007 | E0350 |
| F04032 | Test integration — MS020 L1 covers 8 message-type schema rendering | cross-ref MS020 | E0350 |
| F04033 | Test integration — MS020 L2 covers 4-step pipeline (candidate → filter → verify → commit) | cross-ref MS020 + dump 3481–3484 | E0348 |
| F04034 | Test integration — MS020 L3 covers virtio-vsock transport health checks | cross-ref MS020 + dump 3458 | M00864 |
| F04035 | Test integration — MS020 L4 covers seam between VM proposal + host policy filter | cross-ref MS020 + dump 3479–3482 | M00877 |
| F04036 | Test integration — MS020 L5 covers end-to-end PatchProposal lifecycle | cross-ref MS020 + dump 3473 + 3481–3484 | M00875 |
| F04037 | DraftRequest invariant — MUST carry budget field (no infinite generation) | architecture + cross-ref MS022 | M00868 |
| F04038 | DraftRequest invariant — MUST carry profile field (M042 9-axis choice) | architecture + cross-ref M042 | M00868 |
| F04039 | DraftResult invariant — MUST carry confidence score for filter step | dump 3482 + architecture | M00869 |
| F04040 | EmbeddingRequest invariant — MUST carry dim for shape validation | architecture | M00870 |
| F04041 | RerankResult invariant — MUST carry reasoning for audit | dump 3221 audit cycles | M00871 |
| F04042 | VisionResult invariant — MUST carry confidence score | architecture | M00872 |
| F04043 | ToolPlan invariant — MUST carry expected_side_effects (M049 side-effect class) | cross-ref M049 | M00873 |
| F04044 | RiskAssessment invariant — risk_score MUST be in [0, 1] | architecture | M00874 |
| F04045 | PatchProposal invariant — diff MUST be unified-diff format | architecture | M00875 |
| F04046 | PatchProposal invariant — rationale MUST cite tests/specs/policy | architecture + cross-ref M037 | M00875 |
| F04047 | Audit invariant — every message MUST carry trace_id (M049 13-field span) | cross-ref M049 | M00882 |
| F04048 | Audit invariant — host emits 7-step model_call trace (MS033) for VM-routed calls | cross-ref MS033 + dump 3232–3238 | M00882 |
| F04049 | Audit invariant — host emits 5-step tool_call trace (MS033) for VM-proposed tools | cross-ref MS033 + dump 3244–3248 | M00882 |
| F04050 | Boundary invariant — VM cannot read host /etc/selfdef/* | dump 3477 + cross-ref MS017 | M00876 |
| F04051 | Boundary invariant — VM cannot write to host filesystem | dump 3477 | M00876 |
| F04052 | Boundary invariant — VM cannot escalate privileges on host | dump 3477 + cross-ref MS019 | M00876 |
| F04053 | Boundary invariant — VM cannot bypass AVX-512 filter | dump 3482 + cross-ref MS017 | M00879 |
| F04054 | Boundary invariant — VM cannot bypass Oracle verification for high-value items | dump 3483 | M00880 |
| F04055 | Boundary invariant — VM cannot bypass replay log | dump 3484 + cross-ref M044 | M00881 |
| F04056 | Operator UX — `selfdefctl vm status` shows VM-host communication health | architecture + cross-ref MS017 | E0350 |
| F04057 | Operator UX — `selfdefctl vm pending-proposals` lists pending VM proposals | architecture + cross-ref M049 ask outcome | M00877 |
| F04058 | Operator UX — `selfdefctl vm approve <proposal_id>` approves a pending proposal | cross-ref M042 user-approval + M049 | M00877 |
| F04059 | Operator UX — `selfdefctl vm reject <proposal_id>` rejects a pending proposal | cross-ref M049 | M00877 |
| F04060 | Operator UX — MS011 operator dashboard renders VM-host communication widget | cross-ref MS011 | M00882 |
| F04061 | Cross-module — MS003 correlator + store + responder processes VM-proposed events | cross-ref MS003 | E0350 |
| F04062 | Cross-module — MS004 14-notifier-integrations notify on PatchProposal/ToolPlan/RiskAssessment | cross-ref MS004 | M00873 + M00874 + M00875 |
| F04063 | Cross-module — MS022 SSE quota tracks per-message token usage | cross-ref MS022 | M00868 |
| F04064 | Cross-module — MS023 polarproxy may inspect inter-VM TLS if VM uses HTTPS | cross-ref MS023 | M00865 |
| F04065 | Cross-module — MS024 bridge-l2 may bridge VM network if VFIO-passthrough doesn't isolate fully | cross-ref MS024 | E0342 |
| F04066 | Cross-module — MS025 detect-host event-bus transports VM-host events | cross-ref MS025 | M00882 |
| F04067 | Cross-module — MS026 integrity-sentinel baselines VM-host communication config files | cross-ref MS026 | E0350 |
| F04068 | Cross-module — MS027 observability renders VM communication metrics | cross-ref MS027 | M00882 |
| F04069 | Cross-module — MS028 bitnet-gpu-inference runs INSIDE VFIO 3090 VM (not host) | cross-ref MS028 + cross-ref MS032 | E0350 |
| F04070 | Cross-module — MS029 slm-cpu-loop runs on HOST CPU (NOT in VM) | cross-ref MS029 | E0350 |
| F04071 | Cross-module — MS030 tensor-parallel requires multi-GPU host mode (NOT compatible with single-VM VFIO) | cross-ref MS030 | E0350 |
| F04072 | Cross-module — MS031 wasm-aot-cache may host VM-runnable .cwasm if VM has wasmtime | cross-ref MS031 | E0350 |
| F04073 | Cross-module — MS032 sandbox tier 6a (VFIO 3090 VM) is the sandbox where Communication Boundary applies | cross-ref MS032 | E0350 |
| F04074 | Cross-module — MS033 Phase 3 policy + trace 4-state outcome (allow/deny/ask/sandbox) governs VM proposals | cross-ref MS033 + dump 3225 | M00877 |
| F04075 | Cross-module — MS013 27-SDD charter governs Communication Boundary finding ledger | cross-ref MS013 | E0350 |
| F04076 | Cross-module — MS019 threat model treats VM escape + host-mutation as primary attack surfaces | cross-ref MS019 + dump 3477 | M00876 |
| F04077 | Operator references — Linux AF_VSOCK kernel documentation | cross-ref dump 3458 | M00864 |
| F04078 | Operator references — gRPC over vsock implementation (e.g. vsock-rs, grpc-go vsock transport) | cross-ref dump 3459 | M00865 |
| F04079 | Operator references — virtiofs filesystem documentation | cross-ref dump 3461 | M00867 |
| F04080 | Composite — 4 transports + 8 message types + 4-step pipeline + "Same invariant again" doctrine | dump 3450–3488 | E0341–E0350 |

## Requirements (R07921–R08160)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R07921 | Section header — "Communication Boundary" | dump 3450 | F03961 | non-negotiable | false | 10 |
| R07922 | Doctrine — "Use compact messages, not bulk tensors" | dump 3452 | F03962 | non-negotiable | false | 10 |
| R07923 | "Host ↔ 3090 VM over" | dump 3456 | F03963 | non-negotiable | false | 10 |
| R07924 | Transport — virtio-vsock | dump 3458 | F03964 | non-negotiable | false | 10 |
| R07925 | Transport — gRPC over vsock | dump 3459 | F03965 | non-negotiable | false | 10 |
| R07926 | Transport — Unix socket proxy | dump 3460 | F03966 | non-negotiable | false | 10 |
| R07927 | Transport — shared folder only for explicit exchange dirs | dump 3461 | F03967 | non-negotiable | false | 10 |
| R07928 | "Message types" section header | dump 3464 | F03968 | non-negotiable | false | 10 |
| R07929 | Message — DraftRequest | dump 3466 | F03969 | non-negotiable | false | 10 |
| R07930 | Message — DraftResult | dump 3467 | F03970 | non-negotiable | false | 10 |
| R07931 | Message — EmbeddingRequest | dump 3468 | F03971 | non-negotiable | false | 10 |
| R07932 | Message — RerankResult | dump 3469 | F03972 | non-negotiable | false | 10 |
| R07933 | Message — VisionResult | dump 3470 | F03973 | non-negotiable | false | 10 |
| R07934 | Message — ToolPlan | dump 3471 | F03974 | non-negotiable | false | 10 |
| R07935 | Message — RiskAssessment | dump 3472 | F03975 | non-negotiable | false | 10 |
| R07936 | Message — PatchProposal | dump 3473 | F03976 | non-negotiable | false | 10 |
| R07937 | Invariant — "Never let the VM directly mutate host truth" | dump 3477 | F03977 | non-negotiable | false | 10 |
| R07938 | Invariant — "The VM proposes. Host commits." | dump 3479 | F03978 | non-negotiable | false | 10 |
| R07939 | Pipeline — "VM output = candidate" | dump 3481 | F03979 | non-negotiable | false | 10 |
| R07940 | Pipeline — "Host AVX-512 policy = filter" | dump 3482 | F03980 | non-negotiable | false | 10 |
| R07941 | Pipeline — "Oracle = verify" | dump 3483 | F03981 | non-negotiable | false | 10 |
| R07942 | Pipeline — "Replay log = commit" | dump 3484 | F03982 | non-negotiable | false | 10 |
| R07943 | "Same invariant again" | dump 3487 | F03983 | non-negotiable | false | 10 |
| R07944 | virtio-vsock — Linux AF_VSOCK socket family | dump 3458 | F03984 | non-negotiable | false | 10 |
| R07945 | virtio-vsock — host-guest cid/port addressing | architecture + dump 3458 | F03985 | non-negotiable | false | 10 |
| R07946 | virtio-vsock — bidirectional stream + dgram | architecture + dump 3458 | F03986 | non-negotiable | false | 10 |
| R07947 | gRPC over vsock — protobuf message schemas for 8 message types | dump 3459 | F03987 | non-negotiable | false | 10 |
| R07948 | gRPC over vsock — async streaming for embeddings + reranking | dump 3459 | F03988 | non-negotiable | false | 10 |
| R07949 | Unix socket proxy — host-side daemon translates vsock to AF_UNIX | dump 3460 | F03989 | non-negotiable | false | 10 |
| R07950 | Unix socket proxy — accepts host CLI/API calls and forwards to VM | dump 3460 | F03990 | non-negotiable | false | 10 |
| R07951 | Shared folder doctrine — explicit exchange dirs only | dump 3461 | F03991 | non-negotiable | false | 10 |
| R07952 | Shared folder doctrine — large blobs through shared folder; control through vsock | dump 3461 | F03992 | non-negotiable | false | 10 |
| R07953 | Shared folder — virtiofs or 9p mount points | dump 3461 | F03993 | non-negotiable | false | 10 |
| R07954 | DraftRequest schema — prompt field | architecture | F03994 | non-negotiable | false | 10 |
| R07955 | DraftRequest schema — context_refs field | architecture | F03994 | non-negotiable | false | 10 |
| R07956 | DraftRequest schema — budget field | architecture + cross-ref MS022 | F03994 | non-negotiable | false | 10 |
| R07957 | DraftRequest schema — profile field | architecture + cross-ref M042 | F03994 | non-negotiable | false | 10 |
| R07958 | DraftRequest schema — trace_id field | architecture + cross-ref M049 | F03994 | non-negotiable | false | 10 |
| R07959 | DraftResult schema — draft_text + tokens_used + confidence + trace_id | architecture + cross-ref M049 | F03995 | non-negotiable | false | 10 |
| R07960 | EmbeddingRequest schema — text/blob + model_id + dim + trace_id | architecture | F03996 | non-negotiable | false | 10 |
| R07961 | EmbeddingResult schema — vector + dim + model_id + trace_id | architecture | F03997 | non-negotiable | false | 10 |
| R07962 | RerankResult schema — candidates + scores + reasoning + trace_id | architecture | F03998 | non-negotiable | false | 10 |
| R07963 | VisionResult schema — perception_output + confidence + trace_id | architecture | F03999 | non-negotiable | false | 10 |
| R07964 | ToolPlan schema — tool_id + arguments + expected_side_effects + trace_id | architecture + cross-ref M049 | F04000 | non-negotiable | false | 10 |
| R07965 | RiskAssessment schema — risk_score + risk_class + reasoning + trace_id | architecture | F04001 | non-negotiable | false | 10 |
| R07966 | PatchProposal schema — file + diff + rationale + trace_id | architecture | F04002 | non-negotiable | false | 10 |
| R07967 | Invariant rationale — host filesystem MUST remain canonical truth | dump 3477 | F04003 | non-negotiable | false | 10 |
| R07968 | Invariant rationale — VM filesystem is sandbox, NOT shared truth | dump 3477 | F04004 | non-negotiable | false | 10 |
| R07969 | Invariant rationale — "shared folder" is one-way explicit-exchange-only | dump 3461 + 3477 | F04005 | non-negotiable | false | 10 |
| R07970 | Invariant — "VM proposes" means VM outputs are SUGGESTIONS not COMMANDS | dump 3479 | F04006 | non-negotiable | false | 10 |
| R07971 | Invariant — "Host commits" means host AVX-512 policy makes binding decisions | dump 3479 + 3482 | F04007 | non-negotiable | false | 10 |
| R07972 | Pipeline — every VM output MUST pass through filter step | dump 3482 | F04008 | non-negotiable | false | 10 |
| R07973 | Pipeline — AVX-512 policy filter is the FIRST gate | dump 3482 | F04009 | non-negotiable | false | 10 |
| R07974 | Pipeline — Oracle verification is the SECOND gate (high-value items only) | dump 3483 | F04010 | non-negotiable | false | 10 |
| R07975 | Pipeline — Replay log is APPEND-ONLY committed truth | dump 3484 | F04011 | non-negotiable | false | 10 |
| R07976 | Pipeline — replay log = ZFS-backed write-ahead | cross-ref M044 ZFS | F04012 | non-negotiable | false | 10 |
| R07977 | "Same invariant" — workflow boundary applies same pattern | dump 3487 + cross-ref M025 | F04013 | non-negotiable | false | 10 |
| R07978 | "Same invariant" — tool boundary applies same pattern | dump 3487 + cross-ref MS032 | F04014 | non-negotiable | false | 10 |
| R07979 | "Same invariant" — memory boundary applies same pattern | dump 3487 + cross-ref M028 | F04015 | non-negotiable | false | 10 |
| R07980 | Selfdef MS017 enforces "VM proposes. Host commits." | cross-ref MS017 | F04016 | non-negotiable | false | 10 |
| R07981 | Selfdef MS017 refuses host-mutation calls from VM | cross-ref MS017 | F04017 | non-negotiable | false | 10 |
| R07982 | Selfdef MS015 NATS transports 8 message types | cross-ref MS015 | F04018 | non-negotiable | false | 10 |
| R07983 | Selfdef MS015 JetStream guarantees delivery for ToolPlan + PatchProposal | cross-ref MS015 | F04019 | non-negotiable | false | 10 |
| R07984 | Selfdef MS016 eBPF observes virtio-vsock traffic | cross-ref MS016 + dump 3458 | F04020 | non-negotiable | false | 10 |
| R07985 | Selfdef MS016 eBPF emits Tetragon events on policy violations | cross-ref MS016 | F04021 | non-negotiable | false | 10 |
| R07986 | Cross-repo — sovereign-os M048 Module 3 "vfio-3090" profile provisions VM | cross-ref M048 | F04022 | non-negotiable | false | 10 |
| R07987 | Cross-repo — sovereign-os M044 VFIO/IOMMU substrate enables IOMMU passthrough | cross-ref M044 | F04023 | non-negotiable | false | 10 |
| R07988 | Cross-repo — sovereign-os M040 Hyper Feature 7 VFIO 3090 trust boundary | cross-ref M040 | F04024 | non-negotiable | false | 10 |
| R07989 | Cross-repo — sovereign-os M050 Design Law "Tools prove" maps to pipeline | cross-ref M050 | F04025 | non-negotiable | false | 10 |
| R07990 | Cross-repo — sovereign-os M042 sandbox-vs-host axis = communication-boundary mode selector | cross-ref M042 | F04026 | non-negotiable | false | 10 |
| R07991 | Cross-repo — sovereign-os M043 Blackwell-oracle verifies VM-output high-value items | cross-ref M043 + dump 3483 | F04027 | non-negotiable | false | 10 |
| R07992 | Cross-repo — sovereign-os M046 LoRA adapters may run inside VM Tier 6a | cross-ref M046 + MS032 | F04028 | non-negotiable | false | 10 |
| R07993 | Cross-repo — sovereign-os M047 Continuity Manager checkpoints VM via CRIU | cross-ref M047 | F04029 | non-negotiable | false | 10 |
| R07994 | Cross-repo — sovereign-os M049 Policy Fabric evaluates 8-message-type policy | cross-ref M049 | F04030 | non-negotiable | false | 10 |
| R07995 | Cross-repo — MS007 surface-manifest typed-mirror carries 8-message-type schemas | cross-ref MS007 | F04031 | non-negotiable | false | 10 |
| R07996 | MS020 L1 covers 8 message-type schema rendering | cross-ref MS020 | F04032 | non-negotiable | false | 10 |
| R07997 | MS020 L2 covers 4-step pipeline (candidate → filter → verify → commit) | cross-ref MS020 + dump 3481–3484 | F04033 | non-negotiable | false | 10 |
| R07998 | MS020 L3 covers virtio-vsock transport health checks | cross-ref MS020 + dump 3458 | F04034 | non-negotiable | false | 10 |
| R07999 | MS020 L4 covers VM-proposal-vs-host-filter seam | cross-ref MS020 + dump 3479–3482 | F04035 | non-negotiable | false | 10 |
| R08000 | MS020 L5 covers PatchProposal end-to-end lifecycle | cross-ref MS020 + dump 3473 + 3481–3484 | F04036 | non-negotiable | false | 10 |
| R08001 | DraftRequest MUST carry budget field | architecture + cross-ref MS022 | F04037 | non-negotiable | false | 10 |
| R08002 | DraftRequest MUST carry profile field | architecture + cross-ref M042 | F04038 | non-negotiable | false | 10 |
| R08003 | DraftResult MUST carry confidence score for filter step | dump 3482 + architecture | F04039 | non-negotiable | false | 10 |
| R08004 | EmbeddingRequest MUST carry dim for shape validation | architecture | F04040 | non-negotiable | false | 10 |
| R08005 | RerankResult MUST carry reasoning for audit | dump 3469 + architecture | F04041 | non-negotiable | false | 10 |
| R08006 | VisionResult MUST carry confidence score | architecture | F04042 | non-negotiable | false | 10 |
| R08007 | ToolPlan MUST carry expected_side_effects (M049 side-effect class) | cross-ref M049 | F04043 | non-negotiable | false | 10 |
| R08008 | RiskAssessment risk_score MUST be in [0, 1] | architecture | F04044 | non-negotiable | false | 10 |
| R08009 | PatchProposal diff MUST be unified-diff format | architecture | F04045 | non-negotiable | false | 10 |
| R08010 | PatchProposal rationale MUST cite tests/specs/policy | architecture + cross-ref M037 | F04046 | non-negotiable | false | 10 |
| R08011 | Every message MUST carry trace_id (M049 13-field span) | cross-ref M049 | F04047 | non-negotiable | false | 10 |
| R08012 | Host emits 7-step model_call trace for VM-routed calls | cross-ref MS033 + dump 3232–3238 | F04048 | non-negotiable | false | 10 |
| R08013 | Host emits 5-step tool_call trace for VM-proposed tools | cross-ref MS033 + dump 3244–3248 | F04049 | non-negotiable | false | 10 |
| R08014 | VM cannot read host /etc/selfdef/* | dump 3477 + cross-ref MS017 | F04050 | non-negotiable | false | 10 |
| R08015 | VM cannot write to host filesystem | dump 3477 | F04051 | non-negotiable | false | 10 |
| R08016 | VM cannot escalate privileges on host | dump 3477 + cross-ref MS019 | F04052 | non-negotiable | false | 10 |
| R08017 | VM cannot bypass AVX-512 filter | dump 3482 + cross-ref MS017 | F04053 | non-negotiable | false | 10 |
| R08018 | VM cannot bypass Oracle verification for high-value items | dump 3483 | F04054 | non-negotiable | false | 10 |
| R08019 | VM cannot bypass replay log | dump 3484 + cross-ref M044 | F04055 | non-negotiable | false | 10 |
| R08020 | Operator UX — `selfdefctl vm status` | cross-ref MS017 | F04056 | non-negotiable | false | 10 |
| R08021 | Operator UX — `selfdefctl vm pending-proposals` | cross-ref M049 ask outcome | F04057 | non-negotiable | false | 10 |
| R08022 | Operator UX — `selfdefctl vm approve <proposal_id>` | cross-ref M042 + M049 | F04058 | non-negotiable | false | 10 |
| R08023 | Operator UX — `selfdefctl vm reject <proposal_id>` | cross-ref M049 | F04059 | non-negotiable | false | 10 |
| R08024 | Operator UX — MS011 dashboard renders VM-host communication widget | cross-ref MS011 | F04060 | non-negotiable | false | 10 |
| R08025 | Cross-module — MS003 correlator processes VM-proposed events | cross-ref MS003 | F04061 | non-negotiable | false | 10 |
| R08026 | Cross-module — MS004 14-notifier-integrations notify on PatchProposal/ToolPlan/RiskAssessment | cross-ref MS004 | F04062 | non-negotiable | false | 10 |
| R08027 | Cross-module — MS022 SSE quota tracks per-message token usage | cross-ref MS022 | F04063 | non-negotiable | false | 10 |
| R08028 | Cross-module — MS023 polarproxy may inspect inter-VM TLS | cross-ref MS023 | F04064 | non-negotiable | false | 10 |
| R08029 | Cross-module — MS024 bridge-l2 may bridge VM network | cross-ref MS024 | F04065 | non-negotiable | false | 10 |
| R08030 | Cross-module — MS025 detect-host event-bus transports VM-host events | cross-ref MS025 | F04066 | non-negotiable | false | 10 |
| R08031 | Cross-module — MS026 integrity-sentinel baselines VM communication config | cross-ref MS026 | F04067 | non-negotiable | false | 10 |
| R08032 | Cross-module — MS027 observability renders VM communication metrics | cross-ref MS027 | F04068 | non-negotiable | false | 10 |
| R08033 | Cross-module — MS028 bitnet-gpu-inference runs INSIDE VFIO 3090 VM | cross-ref MS028 + MS032 | F04069 | non-negotiable | false | 10 |
| R08034 | Cross-module — MS029 slm-cpu-loop runs on HOST CPU (NOT in VM) | cross-ref MS029 | F04070 | non-negotiable | false | 10 |
| R08035 | Cross-module — MS030 tensor-parallel requires multi-GPU host mode | cross-ref MS030 | F04071 | non-negotiable | false | 10 |
| R08036 | Cross-module — MS031 wasm-aot-cache may host VM-runnable .cwasm | cross-ref MS031 | F04072 | non-negotiable | false | 10 |
| R08037 | Cross-module — MS032 sandbox tier 6a is the VFIO 3090 VM sandbox | cross-ref MS032 | F04073 | non-negotiable | false | 10 |
| R08038 | Cross-module — MS033 4-state policy outcome governs VM proposals | cross-ref MS033 + dump 3225 | F04074 | non-negotiable | false | 10 |
| R08039 | Cross-module — MS013 governs Communication Boundary finding ledger | cross-ref MS013 | F04075 | non-negotiable | false | 10 |
| R08040 | Cross-module — MS019 threat model treats VM escape + host-mutation as primary attack surfaces | cross-ref MS019 + dump 3477 | F04076 | non-negotiable | false | 10 |
| R08041 | Operator references — Linux AF_VSOCK kernel documentation | dump 3458 | F04077 | non-negotiable | false | 10 |
| R08042 | Operator references — gRPC over vsock implementations | dump 3459 | F04078 | non-negotiable | false | 10 |
| R08043 | Operator references — virtiofs filesystem documentation | dump 3461 | F04079 | non-negotiable | false | 10 |
| R08044 | Compact-messages doctrine — virtio-vsock has limited bandwidth vs PCI; messages MUST be small | dump 3452 + architecture | F03962 | non-negotiable | false | 10 |
| R08045 | Compact-messages doctrine — embedding vectors are small (1k-4k floats) and OK on vsock | dump 3452 + architecture | F03996 | non-negotiable | false | 10 |
| R08046 | Compact-messages doctrine — KV-cache tensors are large and MUST NOT cross VM boundary | dump 3452 + architecture | F03962 | non-negotiable | false | 10 |
| R08047 | Compact-messages doctrine — model weights are large and MUST stay inside VM | dump 3452 + architecture | F03962 | non-negotiable | false | 10 |
| R08048 | Same-pattern doctrine — workflow boundary uses VM proposes / Host commits pattern | dump 3487 + cross-ref M025 | F04013 | non-negotiable | false | 10 |
| R08049 | Same-pattern doctrine — tool boundary uses tool intent / policy / sandbox / commit pattern | dump 3487 + cross-ref MS032 | F04014 | non-negotiable | false | 10 |
| R08050 | Same-pattern doctrine — memory boundary uses memory write / policy / sensitivity / commit pattern | dump 3487 + cross-ref M028 + M049 | F04015 | non-negotiable | false | 10 |
| R08051 | Doctrine — boundary patterns are RECURSIVE: every sub-boundary repeats the propose/filter/verify/commit pattern | dump 3487 + architecture | F04013 + F04014 + F04015 | non-negotiable | false | 10 |
| R08052 | Doctrine — invariant pipeline MUST be observable end-to-end via M049 16-event taxonomy | cross-ref M049 + dump 3481–3484 | E0348 | non-negotiable | false | 10 |
| R08053 | Doctrine — invariant pipeline MUST be replayable via M044 ZFS-backed replay log | cross-ref M044 + dump 3484 | F04012 | non-negotiable | false | 10 |
| R08054 | Doctrine — invariant pipeline MUST be auditable post-hoc via MS009 audit cycles | cross-ref MS009 + dump 3484 | F04011 | non-negotiable | false | 10 |
| R08055 | Schema versioning — every message MUST carry schema_version "1.0.0" | cross-ref MS028 + MS030 + MS031 + architecture | E0343 + E0344 + E0345 | non-negotiable | false | 10 |
| R08056 | Schema versioning — schema upgrade requires explicit bump + selfdef-daemon restart | architecture | E0343 | non-negotiable | false | 10 |
| R08057 | Schema versioning — cross-repo MS007 typed-mirror crate updates simultaneously | cross-ref MS007 | F04031 | non-negotiable | false | 10 |
| R08058 | Network — virtio-vsock CID assignment — host=2, guest=3+ by convention | architecture + dump 3458 | F03985 | non-negotiable | false | 10 |
| R08059 | Network — virtio-vsock port range — service ports < 1024 + ephemeral 1024+ | architecture + dump 3458 | F03985 | non-negotiable | false | 10 |
| R08060 | Network — gRPC over vsock uses HTTP/2 frames over vsock stream | dump 3459 + architecture | F03987 | non-negotiable | false | 10 |
| R08061 | Network — Unix socket proxy supports both stream + dgram modes | dump 3460 + architecture | F03989 | non-negotiable | false | 10 |
| R08062 | Network — shared folder MUST use virtiofs or 9p (NOT NFS or SMB) | dump 3461 + architecture | F03993 | non-negotiable | false | 10 |
| R08063 | Network — virtiofs supports DAX (memory-mapped) for low-latency exchange | architecture + dump 3461 | F03993 | non-negotiable | false | 10 |
| R08064 | Security — virtio-vsock has no built-in encryption; rely on host-VM trust boundary | architecture + dump 3458 + 3477 | F03984 | non-negotiable | false | 10 |
| R08065 | Security — gRPC over vsock may use TLS but redundant inside trust boundary | architecture + dump 3459 | F03987 | non-negotiable | false | 10 |
| R08066 | Security — Unix socket proxy SHALL use SO_PEERCRED for host-side authentication | architecture + dump 3460 | F03989 | non-negotiable | false | 10 |
| R08067 | Security — shared folder MUST be mounted read-only from VM perspective for inputs | dump 3461 + 3477 | F03991 | non-negotiable | false | 10 |
| R08068 | Security — shared folder MUST be mounted write-only from VM perspective for outputs (explicit exchange dir convention) | dump 3461 + 3477 | F03992 | non-negotiable | false | 10 |
| R08069 | Selfdef integration — MS017 agent-guard `[host-default]` profile assumes VM isolation; `[autonomous-agent]` profile assumes VM proposes | cross-ref MS017 | F04016 | non-negotiable | false | 10 |
| R08070 | Selfdef integration — MS019 threat model attack surface MS019-AS-001 VM-escape applies here | cross-ref MS019 | F04076 | non-negotiable | false | 10 |
| R08071 | Selfdef integration — MS019 attack surface MS019-AS-002 host-mutation-from-VM applies here | cross-ref MS019 + dump 3477 | F04076 | non-negotiable | false | 10 |
| R08072 | Selfdef integration — MS019 attack surface MS019-AS-003 vsock-CID-spoofing requires SO_PEERCRED check | cross-ref MS019 + architecture | F04066 | non-negotiable | false | 10 |
| R08073 | Selfdef integration — MS019 attack surface MS019-AS-004 shared-folder-symlink-traversal requires path canonicalization | cross-ref MS019 + dump 3461 | F03991 | non-negotiable | false | 10 |
| R08074 | Operator UX — boundary diagnostic CLI `selfdefctl boundary stats` shows message rates + filter outcomes | architecture + cross-ref MS027 | F04060 | non-negotiable | false | 10 |
| R08075 | Operator UX — boundary diagnostic CLI `selfdefctl boundary replay <trace_id>` re-runs a pipeline trace | architecture + cross-ref MS009 + dump 3484 | F04054 | non-negotiable | false | 10 |
| R08076 | Operator UX — boundary diagnostic CLI `selfdefctl boundary list-pending` lists ask-outcome proposals | architecture + cross-ref M049 | F04057 | non-negotiable | false | 10 |
| R08077 | Cross-repo binding — sovereign-os M026 SLM swarm may route to VM-side scout via DraftRequest | cross-ref M026 | F04022 | non-negotiable | false | 10 |
| R08078 | Cross-repo binding — sovereign-os M029 Computer-Use Plane routes via ToolPlan messages | cross-ref M029 | F03974 | non-negotiable | false | 10 |
| R08079 | Cross-repo binding — sovereign-os M030 World Model + M031 Symbolic Planning consume RiskAssessment | cross-ref M030 + M031 | F03975 | non-negotiable | false | 10 |
| R08080 | Cross-repo binding — sovereign-os M037 Spec/TDD/agent-evals consumes PatchProposal for evidence | cross-ref M037 | F03976 | non-negotiable | false | 10 |
| R08081 | Cross-repo binding — sovereign-os M040 Hyper Feature 7 VFIO 3090 trust boundary IS the Communication Boundary | cross-ref M040 | F04024 | non-negotiable | false | 10 |
| R08082 | Cross-repo binding — sovereign-os M042 Choice Architecture "sandbox or host" axis = Communication Boundary mode switch | cross-ref M042 | F04026 | non-negotiable | false | 10 |
| R08083 | Cross-repo binding — sovereign-os M043 AVX-512 Routing Brain feeds the AVX-512 filter step | cross-ref M043 + dump 3482 | F04009 | non-negotiable | false | 10 |
| R08084 | Cross-repo binding — sovereign-os M046 Stage 6 distillation may train specialist SLMs from VM-side draft history | cross-ref M046 + dump 3467 | F04028 | non-negotiable | false | 10 |
| R08085 | Cross-repo binding — sovereign-os M047 Continuity 8-state lifecycle (active/paused/hibernated/checkpointed/archived/quarantined/promoted/rolled-back) governs VM lifecycle | cross-ref M047 | F04029 | non-negotiable | false | 10 |
| R08086 | Cross-repo binding — sovereign-os M048 Module 9 Observability Fabric emits message-type metrics | cross-ref M048 | F04068 | non-negotiable | false | 10 |
| R08087 | Cross-repo binding — sovereign-os M048 Module 10 Policy Fabric evaluates message-type policy decisions | cross-ref M048 | F04030 | non-negotiable | false | 10 |
| R08088 | Cross-repo binding — sovereign-os M049 10-field Intent-Based Policy applies to every VM proposal | cross-ref M049 | F04030 | non-negotiable | false | 10 |
| R08089 | Cross-repo binding — sovereign-os M050 Design Law line 4 "Tools prove" maps to pipeline Oracle verify step | cross-ref M050 + dump 3483 | F04010 | non-negotiable | false | 10 |
| R08090 | Cross-repo binding — sovereign-os M050 Design Law line 5 "ZFS remembers" maps to pipeline replay-log commit step | cross-ref M050 + dump 3484 | F04012 | non-negotiable | false | 10 |
| R08091 | Cross-repo binding — sovereign-os M051 Hot Data Layout SoA arrays informs AVX-512 filter implementation | cross-ref M051 + dump 3482 | F04009 | non-negotiable | false | 10 |
| R08092 | Cross-repo binding — sovereign-os M052 Hardware Vision 3090 "scout / SLM swarm / embeddings/rerankers / perception/GUI / draft/speculation / sandboxed experiments" matches VM message-type emitters | cross-ref M052 | E0343 + E0344 + E0345 | non-negotiable | false | 10 |
| R08093 | Doctrine — Communication Boundary is the FIRST cross-machine boundary | dump 3450 + architecture | E0341 | non-negotiable | false | 10 |
| R08094 | Doctrine — host = canonical truth (single-source-of-truth invariant) | dump 3477 | F04003 | non-negotiable | false | 10 |
| R08095 | Doctrine — VM = candidate space (no truth promotion without host commit) | dump 3479 + 3481 | F04004 | non-negotiable | false | 10 |
| R08096 | Doctrine — host AVX-512 filter rejects malformed messages BEFORE policy evaluation | dump 3482 + architecture | F04009 | non-negotiable | false | 10 |
| R08097 | Doctrine — Oracle verify step ONLY runs on high-value items (cost-optimization) | dump 3483 + architecture | F04010 | non-negotiable | false | 10 |
| R08098 | Doctrine — replay log commit is APPEND-ONLY (no rewrites) | dump 3484 + cross-ref M044 ZFS | F04011 | non-negotiable | false | 10 |
| R08099 | Doctrine — replay log commit triggers cross-module notification (notifier chain via MS003 → MS005 → MS004) | cross-ref MS003 + MS005 + MS004 | F04062 | non-negotiable | false | 10 |
| R08100 | Doctrine — replay log retention = forever (audit immutability) | cross-ref M044 + cross-ref MS009 | F04011 | non-negotiable | false | 10 |
| R08101 | Doctrine — replay log SHALL be cryptographically signed (selfdef-signing crate) | cross-ref MS003 selfdef-signing + cross-ref M044 | F04011 | non-negotiable | false | 10 |
| R08102 | Doctrine — VM cannot ROLLBACK replay log entries | dump 3484 + cross-ref M040 ZFS commit gate | F04011 | non-negotiable | false | 10 |
| R08103 | Doctrine — operator MAY rollback replay log entries via M040 ZFS snapshot/clone/destroy | cross-ref M040 + cross-ref M044 | F04011 | non-negotiable | false | 10 |
| R08104 | Doctrine — every message-type pipeline timing MUST emit M049 13-field span (latency + tokens + cost) | cross-ref M049 | F04047 | non-negotiable | false | 10 |
| R08105 | Doctrine — VM-side process SHALL emit OTel GenAI spans for in-VM model_call/tool_call | cross-ref M049 OTel GenAI | F04047 | non-negotiable | false | 10 |
| R08106 | Doctrine — host SHALL aggregate VM-side OTel spans into host-side trace tree | architecture + cross-ref M049 | F04047 | non-negotiable | false | 10 |
| R08107 | Doctrine — host SHALL be authoritative trace timekeeper (NTP-synced; VM clock-skew tolerated) | architecture + dump 3458 | F04047 | non-negotiable | false | 10 |
| R08108 | Doctrine — boundary errors (transport failure / schema mismatch / policy violation) MUST emit OCSF Detection Finding class 2004 via MS026 integrity-sentinel-style emission | cross-ref MS026 + M049 16-event taxonomy | F04067 | non-negotiable | false | 10 |
| R08109 | Doctrine — boundary errors MUST be replayable from finding-store SQLite (MS025) + ZFS replay log | cross-ref MS025 + M044 | F04066 | non-negotiable | false | 10 |
| R08110 | Doctrine — operator SHALL be notified of high-severity boundary errors via MS004 notifier integrations | cross-ref MS004 | F04062 | non-negotiable | false | 10 |
| R08111 | Operator references — gRPC HTTP/2 protocol specification | dump 3459 | F04078 | non-negotiable | false | 10 |
| R08112 | Operator references — protobuf message schema documentation | dump 3459 + architecture | F03987 | non-negotiable | false | 10 |
| R08113 | Operator references — Linux SO_PEERCRED documentation | architecture + dump 3460 | F04066 | non-negotiable | false | 10 |
| R08114 | Operator references — virtiofs DAX mode documentation | architecture + dump 3461 | F03993 | non-negotiable | false | 10 |
| R08115 | Operator references — 9p protocol RFC (legacy filesystem option) | architecture + dump 3461 | F03993 | non-negotiable | false | 10 |
| R08116 | Operator references — Linux Kernel VHOST drivers documentation | architecture + dump 3458 | F03984 | non-negotiable | false | 10 |
| R08117 | Operator references — QEMU virtio-vsock backend configuration | architecture + dump 3458 | F03984 | non-negotiable | false | 10 |
| R08118 | Operator references — libvirt VM template with virtio-vsock | architecture + dump 3458 | F03984 | non-negotiable | false | 10 |
| R08119 | SD-reference — MS019 threat model attack surface inventory | cross-ref MS019 | F04076 | non-negotiable | false | 10 |
| R08120 | SD-reference — MS013 27-SDD charter F-2027-xxx finding format | cross-ref MS013 | F04075 | non-negotiable | false | 10 |
| R08121 | SD-reference — selfdef-signing crate emit-signed-trace function | cross-ref MS003 selfdef-signing | F04011 | non-negotiable | false | 10 |
| R08122 | SD-reference — MS020 L1-L5 test harness coverage requirement | cross-ref MS020 | F04032–F04036 | non-negotiable | false | 10 |
| R08123 | SD-reference — MS022 SubscriberGuard per-token budget enforcement | cross-ref MS022 | F04037 | non-negotiable | false | 10 |
| R08124 | SD-reference — MS025 detect-host event-bus + finding-store SQLite + sigma-correlator | cross-ref MS025 | F04066 | non-negotiable | false | 10 |
| R08125 | SD-reference — MS026 integrity-sentinel OCSF Detection Finding emission | cross-ref MS026 | F04067 | non-negotiable | false | 10 |
| R08126 | SD-reference — MS027 observability OTel collector + dashboard | cross-ref MS027 | F04068 | non-negotiable | false | 10 |
| R08127 | SD-reference — MS033 Phase 3 Policy And Trace 10-field policy + 13-field trace + 16-event taxonomy | cross-ref MS033 | F04047 + F04048 + F04049 | non-negotiable | false | 10 |
| R08128 | SD-reference — MS032 Phase 4 Sandbox Execution 9-tier catalog + Tier 6a VFIO 3090 VM | cross-ref MS032 | F04073 | non-negotiable | false | 10 |
| R08129 | Cross-cycle integration — MS034 + MS033 + MS032 form the host-VM-boundary trilogy | cross-ref MS032 + MS033 + architecture | E0350 | non-negotiable | false | 10 |
| R08130 | Cross-cycle integration — MS034 + MS035 (Capability Tokens next) extend the boundary doctrine with typed-authority handles | cross-ref MS035 (next INDEX row) | E0350 | non-negotiable | false | 10 |
| R08131 | Cross-cycle integration — MS034 + MS036 (Tool sandboxes next-next) extend message-type pipeline with per-tool sandboxes | cross-ref MS036 (INDEX) | E0350 | non-negotiable | false | 10 |
| R08132 | Cross-cycle integration — MS034 + MS037 (Filesystem boundary) extend shared-folder rule with full filesystem boundary spec | cross-ref MS037 (INDEX) | F04067 | non-negotiable | false | 10 |
| R08133 | Cross-cycle integration — MS034 + MS038 (Network boundary) extend transport rules with full network egress spec | cross-ref MS038 (INDEX) | E0342 | non-negotiable | false | 10 |
| R08134 | Project-boundary — MS034 is selfdef IPS-side Communication Boundary enforcement scope | architecture | E0350 | non-negotiable | false | 10 |
| R08135 | Project-boundary — sovereign-os M040 Hyper Feature 7 VFIO + M042 sandbox/host axis + M048 Module 3 vfio-3090 profile orchestrate | cross-ref M040 + M042 + M048 | E0350 | non-negotiable | false | 10 |
| R08136 | Project-boundary — cross-repo binding via MS007 surface-manifest typed-mirror crate (SATURATED 8/8) | cross-ref MS007 | F04031 | non-negotiable | false | 10 |
| R08137 | Hardware reality — VFIO 3090 VM has its own kernel + drivers + GPU passthrough | dump 16274 + cross-ref M044 | F04022 | non-negotiable | false | 10 |
| R08138 | Hardware reality — virtio-vsock requires guest kernel CONFIG_VIRTIO_VSOCKETS=y + host CONFIG_VHOST_VSOCK=y | architecture + dump 3458 | F03984 | non-negotiable | false | 10 |
| R08139 | Hardware reality — vsock packet MTU is typically 64KB; large blobs need shared folder | architecture + dump 3458 + 3461 | F03991 | non-negotiable | false | 10 |
| R08140 | Hardware reality — virtiofs DAX mode bypasses guest page cache (fast for ML weights) | architecture + dump 3461 | F03993 | non-negotiable | false | 10 |
| R08141 | Operator framing — Communication Boundary is OPERATOR-FACING (not internal-only) | architecture | F04056 | non-negotiable | false | 10 |
| R08142 | Operator framing — operator can OBSERVE boundary state | cross-ref MS011 + MS027 | F04060 | non-negotiable | false | 10 |
| R08143 | Operator framing — operator can APPROVE pending proposals | cross-ref M042 + M049 | F04058 | non-negotiable | false | 10 |
| R08144 | Operator framing — operator can REJECT pending proposals | cross-ref M049 | F04059 | non-negotiable | false | 10 |
| R08145 | Operator framing — operator can ROLLBACK committed proposals via ZFS snapshot | cross-ref M044 + M040 ZFS commit gate | F04012 | non-negotiable | false | 10 |
| R08146 | Operator framing — operator can REPLAY trace via `selfdefctl boundary replay` | cross-ref MS009 + architecture | F04075 | non-negotiable | false | 10 |
| R08147 | Doctrine — Communication Boundary doctrine is the SAME PATTERN repeated for workflow + tool + memory boundaries | dump 3487 | F04013–F04015 | non-negotiable | false | 10 |
| R08148 | Doctrine — boundary pattern = candidate (propose) → filter (AVX-512 policy) → verify (oracle, high-value only) → commit (replay log) | dump 3481–3484 | E0348 | non-negotiable | false | 10 |
| R08149 | Doctrine — every boundary has its own message-type catalog (M053+ implementation milestones expand) | architecture + dump 3487 | E0349 | non-negotiable | false | 10 |
| R08150 | Doctrine — boundary catalog is composable (workflow boundary emits ToolPlan; tool boundary consumes ToolPlan; etc.) | architecture + dump 3471 | F04013 + F04014 | non-negotiable | false | 10 |
| R08151 | Doctrine — boundary patterns are RECURSIVE: every sub-boundary also follows candidate→filter→verify→commit | architecture + dump 3487 | E0349 | non-negotiable | false | 10 |
| R08152 | Doctrine — boundary patterns ARE the deterministic AI substrate | dump 3487 + cross-ref M043 + M051 | E0349 | non-negotiable | false | 10 |
| R08153 | Implementation — MS034 implementation MUST cite M052 Vision Recap as parent doctrine | cross-ref M052 + architecture | E0350 | non-negotiable | false | 10 |
| R08154 | Implementation — MS034 implementation MUST trace to M050 Design Law (Models propose / Tools prove / ZFS remembers) | cross-ref M050 | F04025 | non-negotiable | false | 10 |
| R08155 | Implementation — MS034 implementation MUST follow M053+ 11-build-phase blueprint | cross-ref M053 (INDEX) | E0350 | non-negotiable | false | 10 |
| R08156 | Implementation — MS034 implementation reuses MS021 shared module-script lib v2 helpers (where applicable) | cross-ref MS021 | E0350 | non-negotiable | false | 10 |
| R08157 | Implementation — MS034 implementation follows MS020 L1-L5 test harness pattern | cross-ref MS020 | F04032–F04036 | non-negotiable | false | 10 |
| R08158 | Implementation — MS034 implementation emits MS013 27-SDD charter F-2027-xxx findings for gaps | cross-ref MS013 | F04075 | non-negotiable | false | 10 |
| R08159 | Implementation — MS034 implementation reuses MS022 SubscriberGuard per-token budget pattern for DraftRequest.budget | cross-ref MS022 | F04037 | non-negotiable | false | 10 |
| R08160 | Composite — MS034 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Communication Boundary from dump 3450-3488: doctrine "Use compact messages, not bulk tensors" + 4 host↔3090-VM transport options (virtio-vsock / gRPC over vsock / Unix socket proxy / shared folder for explicit exchange dirs only) + 8 message types (DraftRequest / DraftResult / EmbeddingRequest / RerankResult / VisionResult / ToolPlan / RiskAssessment / PatchProposal) + invariants ("Never let the VM directly mutate host truth" + "The VM proposes. Host commits.") + 4-step pipeline (VM output = candidate / Host AVX-512 policy = filter / Oracle = verify / Replay log = commit) + "Same invariant again" doctrine (workflow + tool + memory boundaries all follow same pattern); cross-module enforcement via 18+ selfdef modules (MS003/MS004/MS011/MS013/MS015/MS016/MS017/MS019/MS022/MS023/MS024/MS025/MS026/MS027/MS028/MS029/MS030/MS031/MS032/MS033); cross-repo binding to sovereign-os M026/M029/M030/M031/M037/M040/M042/M043/M044/M046/M047/M048/M049/M050/M051/M052 via MS007 surface-manifest typed-mirror crate (8-message-type schemas) | dump 3450–3488 + cross-ref MS003-MS033 + M026-M052 + MS007 | E0341 + E0342 + E0343 + E0344 + E0345 + E0346 + E0347 + E0348 + E0349 + E0350 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: section header + doctrine + transport (R07921–R07927) + message types (R07928–R07936) + invariants + 4-step pipeline + "same invariant" (R07937–R07943) + transport invariants (R07944–R07953) + message schemas + audit invariants (R07954–R07976) + cross-module + cross-repo + selfdef integration (R07977–R07995) + test integration (R07996–R08000) + schema invariants (R08001–R08010) + audit (R08011–R08013) + 6 boundary forbidden invariants (R08014–R08019) + 5 operator UX commands (R08020–R08024) + 16 cross-module integration rows (R08025–R08040) + 3 operator reference rows (R08041–R08043) + compact-messages doctrine 4 rows (R08044–R08047) + same-pattern recursion 4 rows (R08048–R08051) + invariant pipeline observability 3 rows (R08052–R08054) + schema versioning 3 rows (R08055–R08057) + network 6 rows (R08058–R08063) + security 5 rows (R08064–R08068) + selfdef integration MS017+MS019 5 rows (R08069–R08073) + operator UX boundary diagnostics 3 rows (R08074–R08076) + cross-repo binding 16 rows (R08077–R08092) + doctrine 11 rows (R08093–R08103) + tracing 7 rows (R08104–R08110) + operator references 8 rows (R08111–R08118) + SD-reference 10 rows (R08119–R08128) + cross-cycle integration 5 rows (R08129–R08133) + project-boundary 3 rows (R08134–R08136) + hardware reality 4 rows (R08137–R08140) + operator framing 6 rows (R08141–R08146) + boundary doctrine 6 rows (R08147–R08152) + implementation 7 rows (R08153–R08159) + composite (R08160)
- Source range 39 lines (dump 3450–3488) yields 240 R-rows representing a 6.15:1 R-per-line ratio (doctrinal block is intentionally compact; architectural elaboration via cross-module + cross-repo bindings carries the bulk per established pattern)
- Project boundary — MS034 is selfdef IPS Communication Boundary enforcement scope; sovereign-os M040+M042+M048+M049 orchestrate at the runtime layer; cross-repo binding via MS007 surface-manifest typed-mirror crate publishes 8-message-type schemas

## Cross-references

- Adjacent INDEX rows: MS033 Policy and trace / MS035 Capability tokens — typed authority handles
- Cross-repo realization — sovereign-os M026 SLM swarm + M029 Computer-Use Plane + M030 World Model + M031 Symbolic Planning + M037 Spec/TDD + M040 Hyper Feature 7 VFIO + M042 Choice Architecture sandbox/host axis + M043 AVX-512 Routing Brain + M044 VFIO/IOMMU substrate + M046 LoRA foundry + M047 Continuity 8-state lifecycle + M048 Module 3+9+10 (Container Fabric, Observability, Policy) + M049 OPA/Cedar/OpenFGA + 10-field Intent-Based Policy + M050 Design Law + M051 architect Hot Data Layout + M052 Vision Recap
- Selfdef integration — MS003 correlator+store+responder+signing + MS004 14-notifier-integrations + MS005 notifier engine + MS011 operator dashboard + MS013 27-SDD charter + MS015 NATS messaging + MS016 eBPF/Tetragon + MS017 agent-guard + MS019 threat model + MS020 L1-L5 test harness + MS021 shared module-script lib v2 + MS022 SSE quota + MS023 polarproxy + MS024 bridge-l2 + MS025 detect-host + MS026 integrity-sentinel + MS027 observability + MS028 bitnet-gpu-inference + MS029 slm-cpu-loop + MS030 tensor-parallel + MS031 wasm-aot-cache + MS032 sandbox tiers + MS033 Phase 3 Policy+Trace + MS009 audit cycles all integrate with Communication Boundary
- Cross-repo binding — MS007 surface-manifest + audit-manifest + dashboard-manifest + ux-checklist typed-mirror crates carry 8-message-type schemas + boundary state metrics + boundary CLI surfaces + boundary dashboard widget
- Cross-cycle integration — MS034 Communication Boundary precedes MS035 Capability Tokens precedes MS036 Tool sandboxes precedes MS037 Filesystem boundary precedes MS038 Network boundary in selfdef INDEX
- Operator references: Linux AF_VSOCK kernel docs + gRPC HTTP/2 spec + protobuf message schema docs + Linux SO_PEERCRED docs + virtiofs DAX mode docs + 9p protocol RFC + Linux VHOST drivers docs + QEMU virtio-vsock backend docs + libvirt VM template docs
