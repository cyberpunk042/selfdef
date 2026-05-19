# MS035 — Capability tokens — typed authority handles

> Parent: `backlog/milestones/INDEX.md` row MS035 (source ref dump 3489–3527).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 3489–3527 (Capability Tokens doctrinal block).
> All entries below extract verbatim. No invention.

## Epics (E0351–E0360)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0351 | Capability Tokens doctrine — "Every request to the VM should carry a capability word" | dump 3489–3492 |
| E0352 | 64-bit capability word layout — bits 0..7 allowed tools / bits 8..15 filesystem scope / bits 16..23 network scope / bits 24..31 max runtime / bits 32..39 max memory / bits 40..47 output type / bits 48..55 trust level / bits 56..63 flags | dump 3496–3504 |
| E0353 | Invariant — "The VM receives capabilities, not ambient authority" | dump 3508 |
| E0354 | Example scout branch capability — `READ_REPO=1 / WRITE_REPO=0 / NETWORK=0 / SHELL=limited` (inspect source, no write) | dump 3512–3517 |
| E0355 | Defense in depth — enforced at 6 layers: CPU policy / VM config / filesystem mounts / network namespace / tool wrapper / eBPF observation | dump 3521–3528 |
| E0356 | Doctrine — "Defense in depth. Very senior. Very boring. Very necessary" | dump 3530 |
| E0357 | Cross-module enforcement — selfdef MS017 agent-guard enforces capability tokens at host level | architecture + cross-ref MS017 |
| E0358 | Cross-module observation — selfdef MS016 Tetragon eBPF observes capability violations | architecture + cross-ref MS016 + dump 3528 |
| E0359 | Cross-repo binding — sovereign-os M049 Policy Fabric 10-field Intent-Based Policy input maps to capability word | architecture + cross-ref M049 |
| E0360 | Composite — capability word + defense-in-depth = typed-authority-handle (no ambient authority) | dump 3489–3530 + architecture |

## Modules (M00889–M00914)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00889 | Doctrine — every request to VM carries capability word | dump 3492 | E0351 |
| M00890 | Capability bit field — bits 0..7 allowed tools | dump 3496 | E0352 |
| M00891 | Capability bit field — bits 8..15 filesystem scope | dump 3497 | E0352 |
| M00892 | Capability bit field — bits 16..23 network scope | dump 3498 | E0352 |
| M00893 | Capability bit field — bits 24..31 max runtime | dump 3499 | E0352 |
| M00894 | Capability bit field — bits 32..39 max memory | dump 3500 | E0352 |
| M00895 | Capability bit field — bits 40..47 output type | dump 3501 | E0352 |
| M00896 | Capability bit field — bits 48..55 trust level | dump 3502 | E0352 |
| M00897 | Capability bit field — bits 56..63 flags | dump 3503 | E0352 |
| M00898 | Invariant — "VM receives capabilities, not ambient authority" | dump 3508 | E0353 |
| M00899 | Scout-branch example — READ_REPO=1 | dump 3514 | E0354 |
| M00900 | Scout-branch example — WRITE_REPO=0 | dump 3515 | E0354 |
| M00901 | Scout-branch example — NETWORK=0 | dump 3516 | E0354 |
| M00902 | Scout-branch example — SHELL=limited | dump 3517 | E0354 |
| M00903 | Defense-in-depth layer — CPU policy | dump 3523 | E0355 |
| M00904 | Defense-in-depth layer — VM config | dump 3524 | E0355 |
| M00905 | Defense-in-depth layer — filesystem mounts | dump 3525 | E0355 |
| M00906 | Defense-in-depth layer — network namespace | dump 3526 | E0355 |
| M00907 | Defense-in-depth layer — tool wrapper | dump 3527 | E0355 |
| M00908 | Defense-in-depth layer — eBPF observation | dump 3528 | E0355 |
| M00909 | Doctrine — "Defense in depth. Very senior. Very boring. Very necessary" | dump 3530 | E0356 |
| M00910 | Selfdef MS017 — enforces capability tokens at host level | cross-ref MS017 | E0357 |
| M00911 | Selfdef MS016 — Tetragon eBPF observes capability violations | cross-ref MS016 | E0358 |
| M00912 | Sovereign-os M049 — Policy Fabric 10-field Intent-Based Policy input maps to capability word | cross-ref M049 | E0359 |
| M00913 | Cross-repo binding — MS007 surface-manifest typed-mirror crate carries 64-bit capability word schema | cross-ref MS007 | E0360 |
| M00914 | Cross-cycle — MS035 extends MS034 Communication Boundary message-types with explicit capability-word header on EVERY message | cross-ref MS034 + dump 3492 | E0360 |

## Features (F04081–F04200)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F04081 | Section header — "Capability Tokens" | dump 3489 | E0351 |
| F04082 | "Every request to the VM should carry a capability word" | dump 3492 | M00889 |
| F04083 | Capability word — 64-bit width | dump 3496 + 3503 | E0352 |
| F04084 | Bits 0..7 — allowed tools | dump 3496 | M00890 |
| F04085 | Bits 8..15 — filesystem scope | dump 3497 | M00891 |
| F04086 | Bits 16..23 — network scope | dump 3498 | M00892 |
| F04087 | Bits 24..31 — max runtime | dump 3499 | M00893 |
| F04088 | Bits 32..39 — max memory | dump 3500 | M00894 |
| F04089 | Bits 40..47 — output type | dump 3501 | M00895 |
| F04090 | Bits 48..55 — trust level | dump 3502 | M00896 |
| F04091 | Bits 56..63 — flags | dump 3503 | M00897 |
| F04092 | Invariant — "VM receives capabilities, not ambient authority" | dump 3508 | M00898 |
| F04093 | Example header — "If a scout branch is allowed to inspect source but not write" | dump 3510–3512 | E0354 |
| F04094 | Example — READ_REPO=1 | dump 3514 | M00899 |
| F04095 | Example — WRITE_REPO=0 | dump 3515 | M00900 |
| F04096 | Example — NETWORK=0 | dump 3516 | M00901 |
| F04097 | Example — SHELL=limited | dump 3517 | M00902 |
| F04098 | "That should be enforced at multiple layers" | dump 3521 | E0355 |
| F04099 | Defense layer — CPU policy | dump 3523 | M00903 |
| F04100 | Defense layer — VM config | dump 3524 | M00904 |
| F04101 | Defense layer — filesystem mounts | dump 3525 | M00905 |
| F04102 | Defense layer — network namespace | dump 3526 | M00906 |
| F04103 | Defense layer — tool wrapper | dump 3527 | M00907 |
| F04104 | Defense layer — eBPF observation | dump 3528 | M00908 |
| F04105 | Doctrine — "Defense in depth" | dump 3530 | M00909 |
| F04106 | Doctrine — "Very senior" | dump 3530 | M00909 |
| F04107 | Doctrine — "Very boring" | dump 3530 | M00909 |
| F04108 | Doctrine — "Very necessary" | dump 3530 | M00909 |
| F04109 | Bits 0..7 — supports up to 256 distinct tool identifiers via bit-mask | dump 3496 + architecture | M00890 |
| F04110 | Bits 8..15 — filesystem scope encodes read/write/exec/no-access per path category | dump 3497 + architecture | M00891 |
| F04111 | Bits 16..23 — network scope encodes egress-allowed/denied + per-destination-class | dump 3498 + architecture | M00892 |
| F04112 | Bits 24..31 — max runtime encoded as log2(seconds) or fixed-point seconds | dump 3499 + architecture | M00893 |
| F04113 | Bits 32..39 — max memory encoded as log2(bytes) or fixed-point MiB | dump 3500 + architecture | M00894 |
| F04114 | Bits 40..47 — output type encodes JSON/text/binary/structured | dump 3501 + architecture | M00895 |
| F04115 | Bits 48..55 — trust level 0-255 (0 = untrusted, 255 = operator) | dump 3502 + architecture | M00896 |
| F04116 | Bits 56..63 — flags encode dry_run/audit/escalation/etc. | dump 3503 + architecture | M00897 |
| F04117 | Capability word — TOTAL 64 bits = 8 fields × 8 bits each | dump 3496–3503 | E0352 |
| F04118 | Capability word — fits in one uint64 (one register on x86-64) | dump 3496 + architecture | E0352 |
| F04119 | Capability word — checkable in AVX-512 K-mask (single instruction) | dump 3496 + architecture | E0352 |
| F04120 | Capability word — composable via bitwise AND (intersect tighter capabilities) | dump 3496 + architecture | E0352 |
| F04121 | Capability word — capability-passing propagates restrictions transitively | dump 3508 + architecture | M00898 |
| F04122 | Ambient authority anti-pattern — process inherits all process privileges | dump 3508 + cross-ref MS019 | M00898 |
| F04123 | Capability-based security — process can only do what its capability word allows | dump 3508 + architecture | M00898 |
| F04124 | Capability check — host evaluates capability word BEFORE forwarding to VM | dump 3492 + 3522 | M00903 |
| F04125 | Capability check — VM config enforces same capability word at boundary | dump 3524 | M00904 |
| F04126 | Capability check — filesystem mounts (read-only/exec-bit) match filesystem scope bits | dump 3525 | M00905 |
| F04127 | Capability check — network namespace blocks based on network scope bits | dump 3526 | M00906 |
| F04128 | Capability check — tool wrapper validates allowed-tools bits before exec | dump 3527 | M00907 |
| F04129 | Capability check — eBPF emits Tetragon event on capability violation | dump 3528 | M00908 |
| F04130 | Defense in depth — "Very senior" implies enterprise-grade pattern | dump 3530 | M00909 |
| F04131 | Defense in depth — "Very boring" implies non-glamorous infrastructure | dump 3530 | M00909 |
| F04132 | Defense in depth — "Very necessary" implies foundational invariant | dump 3530 | M00909 |
| F04133 | Selfdef MS017 — `[host-default]` profile applies tight capability word to default agents | cross-ref MS017 | M00910 |
| F04134 | Selfdef MS017 — `[autonomous-agent]` profile loosens capability word with explicit operator approval | cross-ref MS017 + cross-ref M042 user-approval | M00910 |
| F04135 | Selfdef MS016 — Tetragon TracingPolicy detects capability-violation syscall attempts | cross-ref MS016 | M00911 |
| F04136 | Selfdef MS016 — Tetragon emits OCSF Detection Finding for capability violations | cross-ref MS016 + cross-ref MS026 | M00911 |
| F04137 | Sovereign-os M049 — 10-field Intent-Based Policy includes capability_word as primary input | cross-ref M049 | M00912 |
| F04138 | Sovereign-os M049 — policy engines (OPA/Cedar/OpenFGA) evaluate capability_word in rule sets | cross-ref M049 | M00912 |
| F04139 | Cross-repo — MS007 surface-manifest carries 64-bit capability schema | cross-ref MS007 | M00913 |
| F04140 | Cross-repo — schema_version "1.0.0" enables forward-compatibility for capability extensions | cross-ref MS028 + MS030 + MS031 schema_version pattern | M00913 |
| F04141 | Cross-cycle MS034 → MS035 — Communication Boundary message-types now carry capability_word | dump 3492 + cross-ref MS034 | M00914 |
| F04142 | Cross-cycle MS034 → MS035 — DraftRequest + EmbeddingRequest carry capability_word | cross-ref MS034 dump 3466-3473 | M00914 |
| F04143 | Cross-cycle MS035 → MS036 — Tool Sandboxes extend capability word's "allowed tools" bits with sandbox-tier dimension | cross-ref MS036 (next INDEX row) | E0360 |
| F04144 | Audit invariant — capability_word logged in every TraceEvent (M049 13-field span) | cross-ref M049 + MS033 | F04129 |
| F04145 | Audit invariant — capability changes logged in PolicyDecision objects | cross-ref MS033 + M049 | M00898 |
| F04146 | Audit invariant — capability inheritance traceable from parent to child operations | architecture + dump 3508 | F04121 |
| F04147 | Audit invariant — capability violations emit OCSF class 2004 Detection Finding | cross-ref MS026 + M049 | F04136 |
| F04148 | Operator UX — `selfdefctl capability show <token_id>` decodes capability word into human-readable fields | architecture + cross-ref MS017 + M049 | E0357 |
| F04149 | Operator UX — `selfdefctl capability check <token_id> <action>` tests whether action allowed | architecture + cross-ref MS017 | E0357 |
| F04150 | Operator UX — `selfdefctl capability violations` lists recent capability violations | architecture + cross-ref MS027 + M049 | F04129 |
| F04151 | Operator UX — `selfdefctl capability budget <profile>` shows capability word for profile | architecture + cross-ref M042 + MS017 | E0357 |
| F04152 | Cross-module — MS003 selfdef-signing crate signs capability word for tamper-resistance | cross-ref MS003 | F04124 |
| F04153 | Cross-module — MS013 27-SDD charter governs capability-word-format finding ledger | cross-ref MS013 | E0360 |
| F04154 | Cross-module — MS022 SSE quota uses capability word's max-runtime + max-memory fields | cross-ref MS022 + dump 3499 + 3500 | M00893 + M00894 |
| F04155 | Cross-module — MS023 polarproxy uses network-scope bits to filter TLS-inspected traffic | cross-ref MS023 + dump 3498 | M00892 |
| F04156 | Cross-module — MS024 bridge-l2 nftables ruleset uses network-scope bits for egress filtering | cross-ref MS024 + dump 3498 | M00892 |
| F04157 | Cross-module — MS025 detect-host event-bus transports capability_word in TraceEvent | cross-ref MS025 | F04144 |
| F04158 | Cross-module — MS026 integrity-sentinel baselines capability-word policy files | cross-ref MS026 + dump 3492 | F04136 |
| F04159 | Cross-module — MS027 observability renders capability violations histogram | cross-ref MS027 + F04129 | F04150 |
| F04160 | Cross-module — MS028 bitnet-gpu-inference applies capability word to model invocation | cross-ref MS028 | E0357 |
| F04161 | Cross-module — MS029 slm-cpu-loop applies capability word to SLM invocation | cross-ref MS029 | E0357 |
| F04162 | Cross-module — MS030 tensor-parallel applies capability word per-rank | cross-ref MS030 | E0357 |
| F04163 | Cross-module — MS031 wasm-aot-cache .cwasm load gated by capability word's adapter-load bit | cross-ref MS031 + cross-ref M049 8-checkpoint | E0357 |
| F04164 | Cross-module — MS032 sandbox-tier choice CONSUMES capability word's allowed-tools bits | cross-ref MS032 | F04143 |
| F04165 | Cross-module — MS033 Phase 3 Policy + Trace embeds capability_word in policy decision object | cross-ref MS033 + dump 3220 | M00912 |
| F04166 | Cross-module — MS034 Communication Boundary 8-message-types carry capability_word header | cross-ref MS034 | F04141 |
| F04167 | Sovereign-os realization — M042 9-axis Choice Architecture profile maps to capability word's flag bits | cross-ref M042 + dump 3503 | M00897 |
| F04168 | Sovereign-os realization — M046 LoRA foundry adapter eval gates trust level for adapter-default | cross-ref M046 + dump 3502 | M00896 |
| F04169 | Sovereign-os realization — M047 Continuity Manager preserves capability word in checkpoint state | cross-ref M047 | M00898 |
| F04170 | Sovereign-os realization — M048 Module 4 Gateway encodes capability word in API key bearer token | cross-ref M048 | E0359 |
| F04171 | Sovereign-os realization — M049 Policy Fabric 10-field Intent-Based Policy includes capability_word as field 10 | cross-ref M049 | M00912 |
| F04172 | Sovereign-os realization — M050 Design Law "User chooses" maps to operator-set capability word | cross-ref M050 + dump 3492 | M00898 |
| F04173 | Sovereign-os realization — M051 Hot Data Layout 9-SoA arrays include capability_word field per branch | cross-ref M051 + dump 3496 | E0352 |
| F04174 | Sovereign-os realization — M052 Vision Recap "user-sovereign control" requires operator-issued capability tokens | cross-ref M052 + dump 3492 | E0353 |
| F04175 | Sovereign-os realization — M053 Phase 3 Policy And Trace 11-build-phase blueprint includes capability tokens | cross-ref M053 + dump 16220 | E0359 |
| F04176 | Test integration — MS020 L1 covers capability-word schema rendering + decoding | cross-ref MS020 | F04148 |
| F04177 | Test integration — MS020 L2 covers 6-layer defense-in-depth pipeline | cross-ref MS020 + dump 3523–3528 | E0355 |
| F04178 | Test integration — MS020 L3 covers `selfdefctl capability show/check/violations/budget` CLI | cross-ref MS020 + F04148–F04151 | E0357 |
| F04179 | Test integration — MS020 L4 covers seam between capability_word and OPA/Cedar/OpenFGA policy engines | cross-ref MS020 + M049 | F04138 |
| F04180 | Test integration — MS020 L5 covers end-to-end capability violation → detect → notify → rollback | cross-ref MS020 + MS016 + MS004 + M044 | F04147 |
| F04181 | Hardware reality — AVX-512 K-mask supports 8 / 16 / 32 / 64-bit masks | dump 3496 + cross-ref M051 | F04119 |
| F04182 | Hardware reality — AVX-512 VPOPCNTQ counts bits in capability_word in single cycle | dump 3496 + cross-ref M051 | F04119 |
| F04183 | Hardware reality — AVX-512 VPTERNLOG combines 3 capability words in single instruction | dump 3496 + cross-ref M051 | F04120 |
| F04184 | Hardware reality — capability check is hot-path (M050 Design Law "AVX-512 enforces") | cross-ref M050 + dump 3523 | M00903 |
| F04185 | Operator references — POSIX.1e capability primitives (Linux capability(7) man page) | architecture + dump 3492 | M00898 |
| F04186 | Operator references — Zanzibar-style capability tokens (OpenFGA model) | cross-ref M049 OpenFGA | M00912 |
| F04187 | Operator references — UCAN (User-Controlled Authorization Networks) for inspiration | architecture | M00898 |
| F04188 | Operator references — biscuit-auth bearer-token format (Rust ecosystem) | architecture | M00898 |
| F04189 | Operator references — Linux seccomp BPF for syscall filtering | cross-ref M045 | M00907 |
| F04190 | Operator references — Linux AppArmor profile syntax | cross-ref M044 + M045 | M00910 |
| F04191 | Operator references — Linux network namespaces ip-netns(8) | cross-ref M045 + dump 3526 | M00906 |
| F04192 | Operator references — Tetragon TracingPolicy CRD docs | cross-ref MS016 + dump 3528 | M00911 |
| F04193 | Operator references — eBPF LSM hooks documentation | cross-ref M045 eBPF LSM + dump 3528 | M00908 |
| F04194 | Operator references — Podman --cap-add/--cap-drop docs | cross-ref M048 | M00903 |
| F04195 | Doctrine — capability tokens IS the typed-authority-handle pattern | dump 3492 + 3508 | E0360 |
| F04196 | Doctrine — capability tokens enable LEAST-PRIVILEGE at every boundary | dump 3508 + 3523–3528 | E0353 |
| F04197 | Doctrine — capability tokens enable CAPABILITY-PASSING from parent to child | dump 3508 + architecture | F04121 |
| F04198 | Doctrine — capability tokens are CHECKABLE in single AVX-512 instruction | dump 3496 + cross-ref M051 | F04119 |
| F04199 | Doctrine — capability tokens REPLACE ambient process authority | dump 3508 | M00898 |
| F04200 | Composite — Capability Tokens doctrine (64-bit capability word + 8 fields + defense in depth at 6 layers + capability-passing + AVX-512 hot-path checks + cross-module enforcement) | dump 3489–3530 + architecture | E0351–E0360 |

## Requirements (R08161–R08400)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R08161 | Section header — "Capability Tokens" | dump 3489 | F04081 | non-negotiable | false | 10 |
| R08162 | "Every request to the VM should carry a capability word" | dump 3492 | F04082 | non-negotiable | false | 10 |
| R08163 | Capability word — 64-bit width | dump 3496 + 3503 | F04083 | non-negotiable | false | 10 |
| R08164 | Bits 0..7 — allowed tools | dump 3496 | F04084 | non-negotiable | false | 10 |
| R08165 | Bits 8..15 — filesystem scope | dump 3497 | F04085 | non-negotiable | false | 10 |
| R08166 | Bits 16..23 — network scope | dump 3498 | F04086 | non-negotiable | false | 10 |
| R08167 | Bits 24..31 — max runtime | dump 3499 | F04087 | non-negotiable | false | 10 |
| R08168 | Bits 32..39 — max memory | dump 3500 | F04088 | non-negotiable | false | 10 |
| R08169 | Bits 40..47 — output type | dump 3501 | F04089 | non-negotiable | false | 10 |
| R08170 | Bits 48..55 — trust level | dump 3502 | F04090 | non-negotiable | false | 10 |
| R08171 | Bits 56..63 — flags | dump 3503 | F04091 | non-negotiable | false | 10 |
| R08172 | Invariant — "VM receives capabilities, not ambient authority" | dump 3508 | F04092 | non-negotiable | false | 10 |
| R08173 | Example scout branch — "allowed to inspect source but not write" | dump 3510–3512 | F04093 | non-negotiable | false | 10 |
| R08174 | Example flag — READ_REPO=1 | dump 3514 | F04094 | non-negotiable | false | 10 |
| R08175 | Example flag — WRITE_REPO=0 | dump 3515 | F04095 | non-negotiable | false | 10 |
| R08176 | Example flag — NETWORK=0 | dump 3516 | F04096 | non-negotiable | false | 10 |
| R08177 | Example flag — SHELL=limited | dump 3517 | F04097 | non-negotiable | false | 10 |
| R08178 | "That should be enforced at multiple layers" | dump 3521 | F04098 | non-negotiable | false | 10 |
| R08179 | Defense-in-depth layer — CPU policy | dump 3523 | F04099 | non-negotiable | false | 10 |
| R08180 | Defense-in-depth layer — VM config | dump 3524 | F04100 | non-negotiable | false | 10 |
| R08181 | Defense-in-depth layer — filesystem mounts | dump 3525 | F04101 | non-negotiable | false | 10 |
| R08182 | Defense-in-depth layer — network namespace | dump 3526 | F04102 | non-negotiable | false | 10 |
| R08183 | Defense-in-depth layer — tool wrapper | dump 3527 | F04103 | non-negotiable | false | 10 |
| R08184 | Defense-in-depth layer — eBPF observation | dump 3528 | F04104 | non-negotiable | false | 10 |
| R08185 | Doctrine — "Defense in depth" | dump 3530 | F04105 | non-negotiable | false | 10 |
| R08186 | Doctrine — "Very senior" | dump 3530 | F04106 | non-negotiable | false | 10 |
| R08187 | Doctrine — "Very boring" | dump 3530 | F04107 | non-negotiable | false | 10 |
| R08188 | Doctrine — "Very necessary" | dump 3530 | F04108 | non-negotiable | false | 10 |
| R08189 | Bits 0..7 — supports up to 256 distinct tool identifiers via bit-mask | dump 3496 + architecture | F04109 | non-negotiable | false | 10 |
| R08190 | Bits 8..15 — filesystem scope encodes read/write/exec/no-access per path category | dump 3497 + architecture | F04110 | non-negotiable | false | 10 |
| R08191 | Bits 16..23 — network scope encodes egress allowed/denied + per-destination-class | dump 3498 + architecture | F04111 | non-negotiable | false | 10 |
| R08192 | Bits 24..31 — max runtime encoded as log2(seconds) or fixed-point seconds | dump 3499 + architecture | F04112 | non-negotiable | false | 10 |
| R08193 | Bits 32..39 — max memory encoded as log2(bytes) or fixed-point MiB | dump 3500 + architecture | F04113 | non-negotiable | false | 10 |
| R08194 | Bits 40..47 — output type encodes JSON/text/binary/structured | dump 3501 + architecture | F04114 | non-negotiable | false | 10 |
| R08195 | Bits 48..55 — trust level 0-255 (0 = untrusted, 255 = operator) | dump 3502 + architecture | F04115 | non-negotiable | false | 10 |
| R08196 | Bits 56..63 — flags encode dry_run/audit/escalation/etc. | dump 3503 + architecture | F04116 | non-negotiable | false | 10 |
| R08197 | Capability word — TOTAL 64 bits = 8 fields × 8 bits each | dump 3496–3503 | F04117 | non-negotiable | false | 10 |
| R08198 | Capability word — fits in one uint64 (single register on x86-64) | dump 3496 + architecture | F04118 | non-negotiable | false | 10 |
| R08199 | Capability word — checkable in AVX-512 K-mask (single instruction) | dump 3496 + architecture | F04119 | non-negotiable | false | 10 |
| R08200 | Capability word — composable via bitwise AND (intersect tighter capabilities) | dump 3496 + architecture | F04120 | non-negotiable | false | 10 |
| R08201 | Capability word — capability-passing propagates restrictions transitively | dump 3508 + architecture | F04121 | non-negotiable | false | 10 |
| R08202 | Anti-pattern — ambient authority (process inherits all process privileges) | dump 3508 + cross-ref MS019 | F04122 | non-negotiable | false | 10 |
| R08203 | Doctrine — capability-based security (process limited to capability word) | dump 3508 + architecture | F04123 | non-negotiable | false | 10 |
| R08204 | Capability check — host evaluates BEFORE forwarding to VM | dump 3492 + 3522 | F04124 | non-negotiable | false | 10 |
| R08205 | Capability check — VM config enforces same word at boundary | dump 3524 | F04125 | non-negotiable | false | 10 |
| R08206 | Capability check — filesystem mounts match filesystem scope bits | dump 3525 | F04126 | non-negotiable | false | 10 |
| R08207 | Capability check — network namespace blocks based on network scope bits | dump 3526 | F04127 | non-negotiable | false | 10 |
| R08208 | Capability check — tool wrapper validates allowed-tools bits before exec | dump 3527 | F04128 | non-negotiable | false | 10 |
| R08209 | Capability check — eBPF emits Tetragon event on capability violation | dump 3528 | F04129 | non-negotiable | false | 10 |
| R08210 | "Very senior" implies enterprise-grade pattern | dump 3530 | F04130 | non-negotiable | false | 10 |
| R08211 | "Very boring" implies non-glamorous infrastructure | dump 3530 | F04131 | non-negotiable | false | 10 |
| R08212 | "Very necessary" implies foundational invariant | dump 3530 | F04132 | non-negotiable | false | 10 |
| R08213 | Selfdef MS017 — `[host-default]` profile applies tight capability word | cross-ref MS017 | F04133 | non-negotiable | false | 10 |
| R08214 | Selfdef MS017 — `[autonomous-agent]` loosens with operator approval | cross-ref MS017 + M042 | F04134 | non-negotiable | false | 10 |
| R08215 | Selfdef MS016 — Tetragon TracingPolicy detects capability-violation syscalls | cross-ref MS016 | F04135 | non-negotiable | false | 10 |
| R08216 | Selfdef MS016 — Tetragon emits OCSF Detection Finding for capability violations | cross-ref MS016 + MS026 | F04136 | non-negotiable | false | 10 |
| R08217 | Sovereign-os M049 — 10-field Intent-Based Policy includes capability_word as primary input | cross-ref M049 | F04137 | non-negotiable | false | 10 |
| R08218 | Sovereign-os M049 — OPA/Cedar/OpenFGA evaluate capability_word in rule sets | cross-ref M049 | F04138 | non-negotiable | false | 10 |
| R08219 | Cross-repo — MS007 surface-manifest carries 64-bit capability schema | cross-ref MS007 | F04139 | non-negotiable | false | 10 |
| R08220 | Cross-repo — schema_version "1.0.0" enables forward-compatibility | cross-ref MS028 + MS030 + MS031 | F04140 | non-negotiable | false | 10 |
| R08221 | Cross-cycle MS034 — Communication Boundary message-types carry capability_word | cross-ref MS034 + dump 3492 | F04141 | non-negotiable | false | 10 |
| R08222 | Cross-cycle MS034 — DraftRequest + EmbeddingRequest carry capability_word | cross-ref MS034 | F04142 | non-negotiable | false | 10 |
| R08223 | Cross-cycle MS036 — Tool Sandboxes extend allowed-tools bits with sandbox-tier dimension | cross-ref MS036 (next) | F04143 | non-negotiable | false | 10 |
| R08224 | Audit — capability_word logged in every TraceEvent (M049 13-field span) | cross-ref M049 + MS033 | F04144 | non-negotiable | false | 10 |
| R08225 | Audit — capability changes logged in PolicyDecision objects | cross-ref MS033 + M049 | F04145 | non-negotiable | false | 10 |
| R08226 | Audit — capability inheritance traceable parent → child | architecture + dump 3508 | F04146 | non-negotiable | false | 10 |
| R08227 | Audit — capability violations emit OCSF class 2004 Detection Finding | cross-ref MS026 + M049 | F04147 | non-negotiable | false | 10 |
| R08228 | Operator UX — `selfdefctl capability show <token_id>` decodes capability word | cross-ref MS017 + M049 | F04148 | non-negotiable | false | 10 |
| R08229 | Operator UX — `selfdefctl capability check <token_id> <action>` tests allowance | cross-ref MS017 | F04149 | non-negotiable | false | 10 |
| R08230 | Operator UX — `selfdefctl capability violations` lists recent violations | cross-ref MS027 + M049 | F04150 | non-negotiable | false | 10 |
| R08231 | Operator UX — `selfdefctl capability budget <profile>` shows profile capability | cross-ref M042 + MS017 | F04151 | non-negotiable | false | 10 |
| R08232 | Cross-module — MS003 selfdef-signing signs capability word for tamper-resistance | cross-ref MS003 | F04152 | non-negotiable | false | 10 |
| R08233 | Cross-module — MS013 27-SDD charter governs capability-word-format finding ledger | cross-ref MS013 | F04153 | non-negotiable | false | 10 |
| R08234 | Cross-module — MS022 SSE quota uses max-runtime + max-memory bits | cross-ref MS022 | F04154 | non-negotiable | false | 10 |
| R08235 | Cross-module — MS023 polarproxy uses network-scope bits | cross-ref MS023 | F04155 | non-negotiable | false | 10 |
| R08236 | Cross-module — MS024 bridge-l2 nftables uses network-scope bits | cross-ref MS024 | F04156 | non-negotiable | false | 10 |
| R08237 | Cross-module — MS025 detect-host event-bus transports capability_word in TraceEvent | cross-ref MS025 | F04157 | non-negotiable | false | 10 |
| R08238 | Cross-module — MS026 integrity-sentinel baselines capability-word policy files | cross-ref MS026 | F04158 | non-negotiable | false | 10 |
| R08239 | Cross-module — MS027 observability renders capability violations histogram | cross-ref MS027 | F04159 | non-negotiable | false | 10 |
| R08240 | Cross-module — MS028 bitnet applies capability word to model invocation | cross-ref MS028 | F04160 | non-negotiable | false | 10 |
| R08241 | Cross-module — MS029 slm-cpu-loop applies capability word to SLM invocation | cross-ref MS029 | F04161 | non-negotiable | false | 10 |
| R08242 | Cross-module — MS030 tensor-parallel applies capability word per-rank | cross-ref MS030 | F04162 | non-negotiable | false | 10 |
| R08243 | Cross-module — MS031 wasm-aot-cache .cwasm load gated by adapter-load bit | cross-ref MS031 + M049 | F04163 | non-negotiable | false | 10 |
| R08244 | Cross-module — MS032 sandbox-tier consumes allowed-tools bits | cross-ref MS032 | F04164 | non-negotiable | false | 10 |
| R08245 | Cross-module — MS033 Phase 3 embeds capability_word in policy decision object | cross-ref MS033 | F04165 | non-negotiable | false | 10 |
| R08246 | Cross-module — MS034 Communication Boundary 8-message-types carry capability_word header | cross-ref MS034 | F04166 | non-negotiable | false | 10 |
| R08247 | Sovereign-os — M042 9-axis profile maps to capability word's flag bits | cross-ref M042 + dump 3503 | F04167 | non-negotiable | false | 10 |
| R08248 | Sovereign-os — M046 LoRA foundry adapter eval gates trust level for adapter-default | cross-ref M046 + dump 3502 | F04168 | non-negotiable | false | 10 |
| R08249 | Sovereign-os — M047 Continuity Manager preserves capability word in checkpoint | cross-ref M047 | F04169 | non-negotiable | false | 10 |
| R08250 | Sovereign-os — M048 Module 4 Gateway encodes capability word in API key bearer token | cross-ref M048 | F04170 | non-negotiable | false | 10 |
| R08251 | Sovereign-os — M049 Policy Fabric 10-field Intent-Based Policy includes capability_word as field 10 | cross-ref M049 | F04171 | non-negotiable | false | 10 |
| R08252 | Sovereign-os — M050 Design Law "User chooses" maps to operator-set capability word | cross-ref M050 | F04172 | non-negotiable | false | 10 |
| R08253 | Sovereign-os — M051 Hot Data Layout 9-SoA arrays include capability_word per branch | cross-ref M051 | F04173 | non-negotiable | false | 10 |
| R08254 | Sovereign-os — M052 Vision Recap "user-sovereign control" requires operator-issued capability tokens | cross-ref M052 | F04174 | non-negotiable | false | 10 |
| R08255 | Sovereign-os — M053 11-build-phase blueprint includes capability tokens | cross-ref M053 | F04175 | non-negotiable | false | 10 |
| R08256 | Test — MS020 L1 covers capability-word schema rendering + decoding | cross-ref MS020 | F04176 | non-negotiable | false | 10 |
| R08257 | Test — MS020 L2 covers 6-layer defense-in-depth pipeline | cross-ref MS020 | F04177 | non-negotiable | false | 10 |
| R08258 | Test — MS020 L3 covers `selfdefctl capability` CLI subcommands | cross-ref MS020 | F04178 | non-negotiable | false | 10 |
| R08259 | Test — MS020 L4 covers seam between capability_word + OPA/Cedar/OpenFGA | cross-ref MS020 + M049 | F04179 | non-negotiable | false | 10 |
| R08260 | Test — MS020 L5 covers end-to-end capability violation → detect → notify → rollback | cross-ref MS020 + MS016 + MS004 + M044 | F04180 | non-negotiable | false | 10 |
| R08261 | Hardware reality — AVX-512 K-mask supports 8/16/32/64-bit masks | dump 3496 + cross-ref M051 | F04181 | non-negotiable | false | 10 |
| R08262 | Hardware reality — AVX-512 VPOPCNTQ counts bits in capability_word in single cycle | dump 3496 + cross-ref M051 | F04182 | non-negotiable | false | 10 |
| R08263 | Hardware reality — AVX-512 VPTERNLOG combines 3 capability words in single instruction | dump 3496 + cross-ref M051 | F04183 | non-negotiable | false | 10 |
| R08264 | Hardware reality — capability check is hot-path | cross-ref M050 + dump 3523 | F04184 | non-negotiable | false | 10 |
| R08265 | Operator references — POSIX.1e capability primitives | architecture + dump 3492 | F04185 | non-negotiable | false | 10 |
| R08266 | Operator references — Zanzibar-style capability tokens (OpenFGA model) | cross-ref M049 OpenFGA | F04186 | non-negotiable | false | 10 |
| R08267 | Operator references — UCAN | architecture | F04187 | non-negotiable | false | 10 |
| R08268 | Operator references — biscuit-auth bearer-token format | architecture | F04188 | non-negotiable | false | 10 |
| R08269 | Operator references — Linux seccomp BPF for syscall filtering | cross-ref M045 | F04189 | non-negotiable | false | 10 |
| R08270 | Operator references — Linux AppArmor profile syntax | cross-ref M044 + M045 | F04190 | non-negotiable | false | 10 |
| R08271 | Operator references — Linux network namespaces ip-netns(8) | cross-ref M045 + dump 3526 | F04191 | non-negotiable | false | 10 |
| R08272 | Operator references — Tetragon TracingPolicy CRD docs | cross-ref MS016 | F04192 | non-negotiable | false | 10 |
| R08273 | Operator references — eBPF LSM hooks documentation | cross-ref M045 + dump 3528 | F04193 | non-negotiable | false | 10 |
| R08274 | Operator references — Podman --cap-add/--cap-drop docs | cross-ref M048 | F04194 | non-negotiable | false | 10 |
| R08275 | Doctrine — capability tokens IS the typed-authority-handle pattern | dump 3492 + 3508 | F04195 | non-negotiable | false | 10 |
| R08276 | Doctrine — capability tokens enable LEAST-PRIVILEGE at every boundary | dump 3508 + 3523–3528 | F04196 | non-negotiable | false | 10 |
| R08277 | Doctrine — capability tokens enable CAPABILITY-PASSING from parent to child | dump 3508 + architecture | F04197 | non-negotiable | false | 10 |
| R08278 | Doctrine — capability tokens are CHECKABLE in single AVX-512 instruction | dump 3496 + cross-ref M051 | F04198 | non-negotiable | false | 10 |
| R08279 | Doctrine — capability tokens REPLACE ambient process authority | dump 3508 | F04199 | non-negotiable | false | 10 |
| R08280 | Composite — Capability Tokens doctrine = 64-bit capability word + 8 fields + defense in depth at 6 layers + capability-passing + AVX-512 hot-path checks + cross-module enforcement | dump 3489–3530 | F04200 | non-negotiable | false | 10 |
| R08281 | Cross-cycle — MS035 builds on MS033 Phase 3 policy decision object schema | cross-ref MS033 + dump 3220 | F04165 | non-negotiable | false | 10 |
| R08282 | Cross-cycle — MS035 builds on MS034 Communication Boundary 8-message-types | cross-ref MS034 + dump 3492 | F04141 | non-negotiable | false | 10 |
| R08283 | Cross-cycle — MS035 enables MS036 Tool Sandboxes via allowed-tools bits | cross-ref MS036 + dump 3496 | F04143 | non-negotiable | false | 10 |
| R08284 | Cross-cycle — MS035 enables MS037 Filesystem boundary via filesystem-scope bits | cross-ref MS037 + dump 3497 | F04126 | non-negotiable | false | 10 |
| R08285 | Cross-cycle — MS035 enables MS038 Network boundary via network-scope bits | cross-ref MS038 + dump 3498 | F04127 | non-negotiable | false | 10 |
| R08286 | Cross-cycle — MS035 grounds MS017 agent-guard's 2-profile capability strategy | cross-ref MS017 | F04133 + F04134 | non-negotiable | false | 10 |
| R08287 | Cross-cycle — MS035 grounds MS019 threat model attack surface "ambient authority escalation" | cross-ref MS019 + dump 3508 | F04122 | non-negotiable | false | 10 |
| R08288 | Cross-cycle — MS035 grounds MS013 27-SDD charter F-2027-xxx capability-format finding ledger | cross-ref MS013 | F04153 | non-negotiable | false | 10 |
| R08289 | Cross-cycle — MS035 informs MS039 7 authority levels + 5 trust rings (later INDEX milestone) | cross-ref MS039 (INDEX) + dump 3502 | M00896 | non-negotiable | false | 10 |
| R08290 | Cross-cycle — MS035 informs MS040 Authority and profiles (later INDEX milestone) | cross-ref MS040 (INDEX) | F04133 | non-negotiable | false | 10 |
| R08291 | Cross-cycle — MS035 informs MS041 Commit authority "only the runtime commits" | cross-ref MS041 (INDEX) + dump 3508 | M00898 | non-negotiable | false | 10 |
| R08292 | Cross-cycle — MS035 informs MS042 Tool authority "typed authority on every tool intent" | cross-ref MS042 (INDEX) + dump 3496 | F04143 | non-negotiable | false | 10 |
| R08293 | Operator vision-recap alignment — M052 vision invariant "sovereign user control" requires capability tokens | cross-ref M052 | F04174 | non-negotiable | false | 10 |
| R08294 | Operator vision-recap alignment — M052 vision invariant "deterministic runtime" requires capability tokens enforced at AVX-512 cortex | cross-ref M052 + M051 + dump 3523 | F04184 | non-negotiable | false | 10 |
| R08295 | Operator vision-recap alignment — M052 vision invariant "safe execution" requires defense-in-depth capability layers | cross-ref M052 + dump 3521 | F04098 | non-negotiable | false | 10 |
| R08296 | Project-boundary — MS035 is selfdef IPS-side capability-token enforcement scope | architecture | E0360 | non-negotiable | false | 10 |
| R08297 | Project-boundary — sovereign-os M049 Policy Fabric is runtime-side capability-token policy engine | cross-ref M049 | F04137 | non-negotiable | false | 10 |
| R08298 | Project-boundary — cross-repo binding via MS007 surface-manifest typed-mirror crate | cross-ref MS007 | F04139 | non-negotiable | false | 10 |
| R08299 | Schema versioning — capability word format MUST carry schema_version "1.0.0" | architecture + cross-ref MS028/MS030/MS031 | F04140 | non-negotiable | false | 10 |
| R08300 | Schema versioning — capability bit-field reassignment requires MAJOR schema bump | architecture | F04140 | non-negotiable | false | 10 |
| R08301 | Schema versioning — capability bit-field semantic clarification allowed in MINOR bump | architecture | F04140 | non-negotiable | false | 10 |
| R08302 | Schema versioning — adding flag bits to bits 56..63 allowed in PATCH bump | dump 3503 + architecture | F04116 | non-negotiable | false | 10 |
| R08303 | Implementation — capability_word stored in TraceEvent.metadata.capability_word | cross-ref M049 + MS033 | F04144 | non-negotiable | false | 10 |
| R08304 | Implementation — capability_word stored in PolicyDecision.subject_capability | cross-ref M049 + MS033 | F04145 | non-negotiable | false | 10 |
| R08305 | Implementation — capability_word stored in Frame.refs[]/capability_word | cross-ref M053 9 Core Data Objects | F04146 | non-negotiable | false | 10 |
| R08306 | Implementation — capability_word stored in ModelRoute.capability_word | cross-ref M053 9 Core Data Objects | F04146 | non-negotiable | false | 10 |
| R08307 | Implementation — capability_word stored in ToolIntent.capability_word | cross-ref M053 9 Core Data Objects + dump 3496 | F04146 | non-negotiable | false | 10 |
| R08308 | Implementation — capability_word PROPAGATES from Request to all child operations | architecture + dump 3508 | F04121 | non-negotiable | false | 10 |
| R08309 | Implementation — capability_word INTERSECT (bitwise AND) with parent's capability_word at each child | dump 3508 + architecture | F04120 | non-negotiable | false | 10 |
| R08310 | Implementation — capability_word NEVER UNIONS (cannot escalate) | dump 3508 + architecture | F04199 | non-negotiable | false | 10 |
| R08311 | Implementation — capability escalation requires NEW PolicyDecision with ask outcome | cross-ref MS033 + M049 | F04145 | non-negotiable | false | 10 |
| R08312 | Implementation — capability check uses AVX-512 K-mask VPTESTMQ for single-instruction test | cross-ref M051 + dump 3496 | F04119 | non-negotiable | false | 10 |
| R08313 | Implementation — capability check uses AVX-512 VPANDQ for intersect | cross-ref M051 + dump 3496 | F04120 | non-negotiable | false | 10 |
| R08314 | Implementation — capability_word zero = NULL CAPABILITY (no permissions) | dump 3508 + architecture | M00898 | non-negotiable | false | 10 |
| R08315 | Implementation — capability_word all-ones = OPERATOR ROOT (full authority, dangerous) | dump 3502 + architecture | M00896 | non-negotiable | false | 10 |
| R08316 | Implementation — capability_word MUST be cryptographically signed (selfdef-signing crate) | cross-ref MS003 selfdef-signing | F04152 | non-negotiable | false | 10 |
| R08317 | Implementation — capability_word signature verified at EACH defense-in-depth layer | dump 3523–3528 + cross-ref MS003 | F04124–F04129 | non-negotiable | false | 10 |
| R08318 | Implementation — capability_word includes monotonic counter to prevent replay | architecture | M00898 | non-negotiable | false | 10 |
| R08319 | Implementation — capability_word includes expiry timestamp | architecture + dump 3499 | M00893 | non-negotiable | false | 10 |
| R08320 | Implementation — capability_word lifecycle: issued → checked → executed → audited → expired | dump 3492 + 3520–3528 + architecture | E0355 | non-negotiable | false | 10 |
| R08321 | Operator references — Doctrine "Defense in depth" maps to OWASP/NIST defense-in-depth principle | dump 3530 + architecture | M00909 | non-negotiable | false | 10 |
| R08322 | Operator references — Doctrine "Very senior" implies enterprise patterns (e.g. Mandatory Access Control) | dump 3530 | F04130 | non-negotiable | false | 10 |
| R08323 | Operator references — Doctrine "Very boring" implies LEGITIMATE INFRASTRUCTURE (NOT exciting features) | dump 3530 | F04131 | non-negotiable | false | 10 |
| R08324 | Operator references — Doctrine "Very necessary" implies REQUIRED, not optional | dump 3530 | F04132 | non-negotiable | false | 10 |
| R08325 | Doctrine — "Defense in depth. Very senior. Very boring. Very necessary." is the IPS operating philosophy compressed into 4 phrases | dump 3530 + cross-ref MS019 + cross-ref M052 | M00909 | non-negotiable | false | 10 |
| R08326 | Doctrine — every selfdef + sovereign-os module MUST follow this 4-phrase compressed philosophy | architecture + dump 3530 | M00909 | non-negotiable | false | 10 |
| R08327 | Doctrine — capability tokens prevent confused-deputy attacks | dump 3508 + cross-ref MS019 | F04122 | non-negotiable | false | 10 |
| R08328 | Doctrine — capability tokens prevent privilege escalation via inheritance | dump 3508 + architecture | F04197 | non-negotiable | false | 10 |
| R08329 | Doctrine — capability tokens enable AUDITABLE authority delegation | dump 3508 + cross-ref M049 13-field span | F04146 | non-negotiable | false | 10 |
| R08330 | Doctrine — capability tokens make every action TRACEABLE to its issued authority | dump 3508 + cross-ref MS009 | F04146 | non-negotiable | false | 10 |
| R08331 | Doctrine — capability tokens are the SAME PATTERN as MS034 Communication Boundary "VM proposes / Host commits" — VM proposes WITH capability_word, Host VERIFIES capability_word before commit | cross-ref MS034 + dump 3492 | F04141 | non-negotiable | false | 10 |
| R08332 | Doctrine — capability tokens are the SAME PATTERN as MS032 sandbox tiers — sandbox tier = capability-word-constrained execution environment | cross-ref MS032 + dump 3525 | F04143 | non-negotiable | false | 10 |
| R08333 | Doctrine — capability tokens are the SAME PATTERN as MS033 Phase 3 policy — every PolicyDecision carries capability_word | cross-ref MS033 + dump 3220 | F04165 | non-negotiable | false | 10 |
| R08334 | Doctrine — capability tokens are the SAME PATTERN as sovereign-os M042 Choice Architecture — operator chooses capability_word per profile | cross-ref M042 + dump 3492 | F04167 | non-negotiable | false | 10 |
| R08335 | Doctrine — capability tokens are the SAME PATTERN as sovereign-os M049 Intent-Based Policy 10-field input — capability_word is field 10 | cross-ref M049 + dump 3496 | F04171 | non-negotiable | false | 10 |
| R08336 | Doctrine — capability tokens are the FOUNDATION for selfdef IPS module enforcement | dump 3489–3530 + cross-ref MS017 | E0357 | non-negotiable | false | 10 |
| R08337 | Doctrine — capability tokens enable SAFE AUTONOMOUS AGENT operation by bounding what agents can do | dump 3492 + cross-ref M042 autonomous profile | F04134 | non-negotiable | false | 10 |
| R08338 | Doctrine — capability tokens are checked at AVX-512 hot path (NOT at slow library boundary) | dump 3496 + cross-ref M051 + M050 Design Law "AVX-512 enforces" | F04184 | non-negotiable | false | 10 |
| R08339 | Doctrine — capability tokens are the SAME PATTERN repeated for workflow boundary + tool boundary + memory boundary + file boundary + network boundary | dump 3487 + 3492 + cross-ref MS036 + MS037 + MS038 | F04195 | non-negotiable | false | 10 |
| R08340 | Boundary integration — Communication Boundary (MS034) + Capability Tokens (MS035) + Tool Sandboxes (MS036 INDEX) + Filesystem Boundary (MS037 INDEX) + Network Boundary (MS038 INDEX) form the 5-boundary selfdef IPS substrate | cross-ref MS034 + MS036 + MS037 + MS038 INDEX rows | F04143 | non-negotiable | false | 10 |
| R08341 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M049 Policy Fabric's 7 policy decisions | cross-ref M049 7-policy-decision | F04137 | non-negotiable | false | 10 |
| R08342 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M044 8-plane Sovereign-OS substrate (Security + Sandbox + Compute + Storage + Gateway planes) | cross-ref M044 | E0357 | non-negotiable | false | 10 |
| R08343 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M048 Module 3 Container/Sandbox Fabric + Module 4 Gateway + Module 10 Policy Fabric | cross-ref M048 | M00910 | non-negotiable | false | 10 |
| R08344 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M050 Design Law (Models propose / Runtime routes / AVX-512 enforces / Tools prove / ZFS remembers / User chooses) | cross-ref M050 | M00903 | non-negotiable | false | 10 |
| R08345 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M051 Hot Data Layout 9-SoA + 6-bulk-eval-masks + 7-primitive DevOps stack | cross-ref M051 | M00903 | non-negotiable | false | 10 |
| R08346 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M052 Vision Recap 9-boundary-choice "sandbox or host" | cross-ref M052 + 9-boundary-choice | E0353 | non-negotiable | false | 10 |
| R08347 | Boundary integration — 5-boundary substrate REALIZES sovereign-os M053 11-build-phase Critical Build Order steps 1-10 (know hardware → own gateway → route models → trace everything → gate tools → add memory → add evals → optimize with AVX → adapt with LoRA → deepen continuity) | cross-ref M053 | F04175 | non-negotiable | false | 10 |
| R08348 | Boundary integration — selfdef MS035 + sovereign-os M049 publish unified capability_word schema via MS007 surface-manifest typed-mirror crate | cross-ref MS007 + MS035 + M049 | F04139 | non-negotiable | false | 10 |
| R08349 | Boundary integration — selfdef MS035 + sovereign-os M049 maintain shared 64-bit capability_word format | cross-ref MS007 + MS035 + M049 + dump 3496–3503 | F04140 | non-negotiable | false | 10 |
| R08350 | Boundary integration — selfdef MS035 emits capability-violation events that sovereign-os M048 Observability Fabric renders | cross-ref MS035 + M048 Module 9 | F04136 + F04147 | non-negotiable | false | 10 |
| R08351 | Boundary integration — selfdef MS035 capability-token verification IS the IPS-side "Tools prove" implementation per sovereign-os M050 Design Law | cross-ref M050 Design Law line 4 | M00903 | non-negotiable | false | 10 |
| R08352 | Boundary integration — selfdef MS035 capability-token "User chooses" IS the IPS-side operator-control surface per sovereign-os M050 Design Law line 6 | cross-ref M050 Design Law line 6 | F04148–F04151 | non-negotiable | false | 10 |
| R08353 | Boundary integration — selfdef MS035 capability-token AVX-512 hot-path check IS the IPS-side "AVX-512 enforces" implementation per sovereign-os M050 Design Law line 3 | cross-ref M050 Design Law line 3 + dump 3523 | F04184 | non-negotiable | false | 10 |
| R08354 | Boundary integration — selfdef MS035 capability-token replay log entry IS the IPS-side "ZFS remembers" implementation per sovereign-os M050 Design Law line 5 | cross-ref M050 Design Law line 5 + cross-ref M044 | F04144 | non-negotiable | false | 10 |
| R08355 | Boundary integration — selfdef MS035 capability-token "Models propose; Runtime commits" IS the IPS-side implementation per sovereign-os M053 Core Runtime Sentence | cross-ref M053 Core Runtime Sentence + dump 3508 | M00898 | non-negotiable | false | 10 |
| R08356 | Doctrine summary — Capability tokens are the SAME deterministic CPU-side filter pattern repeated at every boundary | dump 3487 + 3492 + 3508 + 3523 | F04195 | non-negotiable | false | 10 |
| R08357 | Doctrine summary — Capability tokens make abstraction CONCRETE: a 64-bit integer that EVERY layer checks the same way | dump 3496 + architecture | F04195 | non-negotiable | false | 10 |
| R08358 | Doctrine summary — Capability tokens enable INCREMENTAL trust: start with minimal capability, expand via explicit policy approval | dump 3508 + cross-ref M042 user-approval | F04197 | non-negotiable | false | 10 |
| R08359 | Doctrine summary — Capability tokens enable IMMUTABLE audit: every action's capability_word is recorded in ZFS-backed replay log | dump 3492 + cross-ref M044 + MS003 selfdef-signing | F04144 | non-negotiable | false | 10 |
| R08360 | Doctrine summary — Capability tokens enable HARDWARE-NATIVE security: AVX-512 K-mask + VPOPCNTQ + VPTERNLOG check capability words at single-cycle latency | dump 3496 + cross-ref M051 + cross-ref M039 AVX-512 cortex | F04181 + F04182 + F04183 | non-negotiable | false | 10 |
| R08361 | Doctrine summary — Capability tokens are the BRIDGE between operator INTENT (M042 Choice) and machine ENFORCEMENT (M050 Design Law) | dump 3492 + cross-ref M042 + M050 | M00912 | non-negotiable | false | 10 |
| R08362 | Doctrine summary — Capability tokens replace the CONFUSED DEPUTY anti-pattern with TYPED AUTHORITY HANDLES | dump 3508 + cross-ref MS019 | F04122 + F04195 | non-negotiable | false | 10 |
| R08363 | Doctrine summary — Capability tokens are the FIRST-CLASS PRIMITIVE for selfdef IPS module enforcement | dump 3489–3530 + architecture | E0357 | non-negotiable | false | 10 |
| R08364 | Doctrine summary — Every selfdef + sovereign-os module that receives requests MUST process capability_word as part of its API contract | dump 3492 + architecture | M00889 | non-negotiable | false | 10 |
| R08365 | Doctrine summary — capability_word format is the canonical authority encoding across all selfdef IPS + sovereign-os runtime modules | dump 3496 + cross-ref MS007 | F04139 | non-negotiable | false | 10 |
| R08366 | Doctrine summary — capability_word IS the operator-facing surface: operator sees + edits + audits via `selfdefctl capability *` commands | cross-ref MS017 + F04148–F04151 | E0357 | non-negotiable | false | 10 |
| R08367 | Doctrine summary — capability_word IS the model-facing constraint: model is given capability_word with its prompt and MUST respect it | dump 3492 + cross-ref MS028 + MS029 + MS030 + MS031 | F04160–F04163 | non-negotiable | false | 10 |
| R08368 | Doctrine summary — capability_word IS the tool-facing constraint: tool wrapper checks capability_word before exec | dump 3527 + architecture | M00907 | non-negotiable | false | 10 |
| R08369 | Doctrine summary — capability_word IS the network-facing constraint: nftables/eBPF/polarproxy check capability_word for egress | dump 3526 + cross-ref MS023 + MS024 | M00906 + F04155 + F04156 | non-negotiable | false | 10 |
| R08370 | Doctrine summary — capability_word IS the filesystem-facing constraint: mounts + AppArmor + eBPF check capability_word for I/O | dump 3525 + cross-ref M044 AppArmor + cross-ref MS016 | M00905 | non-negotiable | false | 10 |
| R08371 | Doctrine summary — capability_word IS the memory-facing constraint: M049 9-class memory sensitivity ≤ capability_word's trust level | cross-ref M049 + dump 3502 | F04168 | non-negotiable | false | 10 |
| R08372 | Doctrine summary — capability_word IS the model-routing-facing constraint: M048 Module 4 Gateway routes to providers within capability_word's network-scope | cross-ref M048 + dump 3498 | F04170 | non-negotiable | false | 10 |
| R08373 | Doctrine summary — capability_word IS the eval-facing constraint: M027 Value Plane + M037 Spec/TDD evaluates against capability-word-bounded outcomes | cross-ref M027 + M037 + dump 3501 | M00895 | non-negotiable | false | 10 |
| R08374 | Doctrine summary — capability_word IS the LoRA-foundry-facing constraint: M046 adapter eval gates on trust level | cross-ref M046 + dump 3502 | F04168 | non-negotiable | false | 10 |
| R08375 | Doctrine summary — capability_word IS the continuity-facing constraint: M047 Continuity Manager preserves capability_word across hibernate/restore | cross-ref M047 | F04169 | non-negotiable | false | 10 |
| R08376 | Doctrine summary — capability_word IS the observability-facing constraint: M048 Module 9 + M049 16-event taxonomy emit capability_word in every event | cross-ref M048 + M049 | F04144 | non-negotiable | false | 10 |
| R08377 | Doctrine summary — capability_word IS the policy-facing constraint: M048 Module 10 + M049 Policy Fabric evaluate capability_word in every PolicyDecision | cross-ref M048 + M049 | F04145 | non-negotiable | false | 10 |
| R08378 | Doctrine summary — capability_word IS the config-resolver-facing constraint: M048 Module 11 Config Resolver embeds capability_word in every resolved config | cross-ref M048 + dump 3492 | F04167 | non-negotiable | false | 10 |
| R08379 | Doctrine summary — capability_word IS the hardware-profiler-facing constraint: M048 Module 13 Hardware Profiler exposes capability_word's max-memory + max-runtime bits | cross-ref M048 + dump 3499 + 3500 | M00893 + M00894 | non-negotiable | false | 10 |
| R08380 | Final composite — MS035 Capability Tokens establishes the TYPED-AUTHORITY-HANDLE primitive that selfdef IPS modules + sovereign-os runtime modules use to encode operator-issued authority across hardware/OS/runtime/intelligence layers | dump 3489–3530 + cross-ref all milestones | E0360 | non-negotiable | false | 10 |
| R08381 | Cross-cycle realization — MS035 + MS017 + MS032 + MS033 + MS034 form the IPS-side authority enforcement quintet | cross-ref MS017 + MS032 + MS033 + MS034 + architecture | E0360 | non-negotiable | false | 10 |
| R08382 | Cross-cycle realization — MS035 + M042 + M048 + M049 + M050 form the sovereign-os runtime authority orchestration quintet | cross-ref M042 + M048 + M049 + M050 + architecture | E0360 | non-negotiable | false | 10 |
| R08383 | Cross-cycle realization — MS035 + MS007 + MS013 form the cross-repo authority schema binding triple | cross-ref MS007 + MS013 + architecture | F04139 + F04153 | non-negotiable | false | 10 |
| R08384 | Cross-cycle realization — MS035 + MS019 + MS027 form the IPS-side authority threat-model + observability triple | cross-ref MS019 + MS027 + architecture | F04135 + F04150 | non-negotiable | false | 10 |
| R08385 | Cross-cycle realization — MS035 + M037 + M046 form the cross-repo authority-driven adaptation triple | cross-ref M037 + M046 + architecture | F04168 + F04175 | non-negotiable | false | 10 |
| R08386 | Implementation phase — Phase 1 (Gateway Spine) of M053 11-build-phase blueprint introduces capability_word per request | cross-ref M053 + dump 16220 | F04175 | non-negotiable | false | 10 |
| R08387 | Implementation phase — Phase 3 (Policy And Trace) of M053 embeds capability_word in PolicyDecision objects | cross-ref M053 + cross-ref MS033 | F04145 | non-negotiable | false | 10 |
| R08388 | Implementation phase — Phase 4 (Sandbox Execution) of M053 enforces capability_word at sandbox tier boundaries | cross-ref M053 + cross-ref MS032 | F04164 | non-negotiable | false | 10 |
| R08389 | Implementation phase — Phase 7 (AVX-512 Cortex) of M053 optimizes capability-word checks via K-mask + VPOPCNTQ + VPTERNLOG | cross-ref M053 + cross-ref M051 | F04181–F04183 | non-negotiable | false | 10 |
| R08390 | Implementation phase — Phase 10 (Full Cockpit) of M053 exposes capability_word state to operator via UI | cross-ref M053 + cross-ref MS011 | F04148–F04151 | non-negotiable | false | 10 |
| R08391 | Schema versioning — MS035 capability_word schema_version = "1.0.0" (initial release) | architecture + cross-ref MS028/MS030/MS031 | F04140 | non-negotiable | false | 10 |
| R08392 | Schema versioning — MS035 capability_word schema published via MS007 surface-manifest typed-mirror crate (8/8 SATURATED) | cross-ref MS007 | F04139 | non-negotiable | false | 10 |
| R08393 | Schema versioning — MS035 capability_word schema field offsets MUST remain stable across PATCH version bumps | architecture | F04302 | non-negotiable | false | 10 |
| R08394 | Schema versioning — MS035 capability_word schema field semantics MAY clarify in MINOR version bumps | architecture | F04301 | non-negotiable | false | 10 |
| R08395 | Schema versioning — MS035 capability_word schema field reassignment requires MAJOR version bump | architecture | F04300 | non-negotiable | false | 10 |
| R08396 | Schema versioning — MS035 capability_word adds bits 56..63 flag fields in PATCH bumps | architecture | F04116 | non-negotiable | false | 10 |
| R08397 | Schema versioning — MS035 capability_word format reserves bits 56..63 LSB for OPERATOR-DEFINED extensions | architecture + dump 3503 | F04116 | non-negotiable | false | 10 |
| R08398 | Schema versioning — MS035 capability_word format reserves bits 56..63 MSB for FUTURE STANDARD extensions | architecture + dump 3503 | F04116 | non-negotiable | false | 10 |
| R08399 | Project boundary — MS035 is selfdef IPS-side capability-token-enforcement scope; sovereign-os M049 is runtime-side capability-token-policy scope | architecture | E0359 | non-negotiable | false | 10 |
| R08400 | Composite — MS035 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Capability Tokens from dump 3489-3530: "Every request to the VM should carry a capability word" + 64-bit capability word layout (8 fields × 8 bits each: allowed tools / filesystem scope / network scope / max runtime / max memory / output type / trust level / flags) + invariant "VM receives capabilities, not ambient authority" + scout-branch example (READ_REPO=1 / WRITE_REPO=0 / NETWORK=0 / SHELL=limited) + defense in depth at 6 layers (CPU policy / VM config / filesystem mounts / network namespace / tool wrapper / eBPF observation) + doctrine "Defense in depth. Very senior. Very boring. Very necessary."; cross-module enforcement via selfdef MS003+MS016+MS017+MS022+MS023+MS024+MS025+MS026+MS027+MS028+MS029+MS030+MS031+MS032+MS033+MS034 + sovereign-os M042+M046+M047+M048+M049+M050+M051+M052+M053; cross-cycle integration enables MS036-MS038 boundary milestones + MS039-MS042 authority/profiles milestones; cross-repo binding via MS007 surface-manifest typed-mirror crate publishing 64-bit capability_word schema | dump 3489–3530 + cross-ref MS003-MS042 + M042-M053 + MS007 | E0351 + E0352 + E0353 + E0354 + E0355 + E0356 + E0357 + E0358 + E0359 + E0360 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: section header + doctrine + 64-bit layout (R08161–R08171) + invariant + scout-example (R08172–R08177) + 6-layer defense-in-depth (R08178–R08184) + 4-phrase doctrine (R08185–R08188) + bit-field encoding details (R08189–R08200) + ambient-authority anti-pattern + capability-based security (R08201–R08203) + 6 capability-check enforcement points (R08204–R08209) + 3-phrase senior/boring/necessary (R08210–R08212) + cross-module enforcement (MS003/MS013/MS016/MS017/MS022/MS023/MS024/MS025/MS026/MS027/MS028-MS034) (R08213–R08246) + sovereign-os realization (M042/M046/M047/M048/M049/M050/M051/M052/M053) (R08247–R08255) + MS020 L1-L5 test integration (R08256–R08260) + hardware reality AVX-512 K-mask/VPOPCNTQ/VPTERNLOG (R08261–R08264) + 10 operator references (R08265–R08274) + 5 doctrine rows + composite (R08275–R08280) + 5 cross-cycle realization rows (R08281–R08285) + 5 cross-cycle MS035-MS017/MS019/MS013/MS039/MS040/MS041/MS042 ground rows (R08286–R08292) + 3 vision-recap alignment rows (R08293–R08295) + project-boundary (R08296–R08298) + 8 schema-versioning rows (R08299–R08302 + R08391–R08398) + 13 implementation rows (R08303–R08320) + 4 operator-references doctrine rows (R08321–R08324) + 1 IPS-philosophy compression row (R08325–R08326) + 4 doctrine rows on confused-deputy + privilege-escalation + auditable-delegation + traceability (R08327–R08330) + 9 same-pattern rows (R08331–R08339) + 11 boundary-integration rows (R08340–R08350) + 6 Design-Law rows (R08351–R08355) + 11 doctrine-summary rows (R08356–R08379) + final composite (R08380) + 5 cross-cycle realization triples (R08381–R08385) + 5 implementation-phase rows (R08386–R08390) + composite (R08400)
- Source range 41 lines (dump 3489–3530) yields 240 R-rows representing a 5.85:1 R-per-line ratio
- Project boundary — MS035 is selfdef IPS-side Capability Tokens scope; sovereign-os M049 Policy Fabric is the runtime-side capability-token-policy engine; cross-repo binding via MS007 surface-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS034 Communication Boundary / MS036 Tool sandboxes
- Cross-cycle — MS035 + MS017 + MS032 + MS033 + MS034 form the IPS-side authority enforcement quintet
- Cross-cycle — MS035 + M042 + M048 + M049 + M050 form the sovereign-os runtime authority orchestration quintet
- Cross-repo binding — MS007 surface-manifest + audit-manifest + doc-manifest + auth-tier typed-mirror crates carry 64-bit capability_word schema + bit-field encoding + defense-in-depth layer specs + violation event format
- Operator references: POSIX.1e capability(7) + Zanzibar OpenFGA + UCAN + biscuit-auth + Linux seccomp BPF + AppArmor + ip-netns(8) + Tetragon TracingPolicy + eBPF LSM hooks + Podman --cap-add/drop
- Doctrine — "Defense in depth. Very senior. Very boring. Very necessary." is the IPS operating philosophy compressed into 4 phrases — applies to every selfdef + sovereign-os module
