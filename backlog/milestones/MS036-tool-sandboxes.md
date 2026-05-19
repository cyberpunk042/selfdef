# MS036 — Tool sandboxes (Tier A/B/C/D)

> Parent: `backlog/milestones/INDEX.md` row MS036 (source ref dump 3528–3549).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 3528–3549 (Tool Sandboxes doctrinal block).
> All entries below extract verbatim. No invention.

## Epics (E0361–E0370)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0361 | Tool Sandboxes header + "For tools, I would use tiers" doctrine | dump 3528–3532 |
| E0362 | Tier A: deterministic host tools — `rg, parsers, formatters, read-only queries` | dump 3534–3536 |
| E0363 | Tier B: controlled host tools — `tests, builds, package managers, file edits` | dump 3538–3540 |
| E0364 | Tier C: VM tools — `risky dependency installs, unknown scripts, browser actions` | dump 3542–3544 |
| E0365 | Tier D: disposable microVM — `untrusted binaries, unknown archives, hostile inputs` | dump 3546–3548 |
| E0366 | Doctrine — "The model never chooses tier alone. It emits intent. CPU decides tier" | dump 3550 + 3552 |
| E0367 | Cross-module — selfdef MS017 agent-guard enforces tier assignment based on tool metadata + capability_word (MS035) | cross-ref MS017 + MS035 |
| E0368 | Cross-module — selfdef MS032 sandbox tier 1-9 catalog COMPOSES with this 4-tier tool classification (Tier A = sandbox tier 1 / Tier B = sandbox tier 2-3 / Tier C = sandbox tier 6a / Tier D = sandbox tier 7+) | cross-ref MS032 |
| E0369 | Cross-repo binding — sovereign-os M049 Policy Fabric 7 PolicyDecision values (allow/deny/ask/sandbox/escalate/snapshot/test) map to tier-assignment outcomes | cross-ref M049 |
| E0370 | Composite — 4-tier tool sandbox classification + "model emits intent, CPU decides tier" doctrine binds the M054 Tool Interface to the deterministic CPU-side scheduler (AVX-512 Cortex) | dump 3528–3552 + cross-ref M054 + M050 + M051 |

## Modules (M00915–M00940)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00915 | Tier doctrine — "For tools, I would use tiers" | dump 3532 | E0361 |
| M00916 | Tier A — deterministic host tools (rg, parsers, formatters, read-only queries) | dump 3534–3536 | E0362 |
| M00917 | Tier B — controlled host tools (tests, builds, package managers, file edits) | dump 3538–3540 | E0363 |
| M00918 | Tier C — VM tools (risky dependency installs, unknown scripts, browser actions) | dump 3542–3544 | E0364 |
| M00919 | Tier D — disposable microVM (untrusted binaries, unknown archives, hostile inputs) | dump 3546–3548 | E0365 |
| M00920 | Doctrine — "The model never chooses tier alone" | dump 3550 | E0366 |
| M00921 | Doctrine — "It emits intent" | dump 3550 | E0366 |
| M00922 | Doctrine — "CPU decides tier" | dump 3552 | E0366 |
| M00923 | Cross-module — selfdef MS017 agent-guard enforces tier assignment | cross-ref MS017 | E0367 |
| M00924 | Cross-module — MS035 capability_word bits 0..7 (allowed tools) inform tier selection | cross-ref MS035 + dump 3496 | E0367 |
| M00925 | Cross-module — MS032 sandbox tier 1-9 catalog composes with 4-tier classification | cross-ref MS032 | E0368 |
| M00926 | Cross-module — MS033 Phase 3 policy_decision_object includes tier as decision field | cross-ref MS033 | E0367 |
| M00927 | Cross-module — MS034 Communication Boundary ToolPlan message-type carries tier hint | cross-ref MS034 | E0367 |
| M00928 | Cross-module — MS019 threat model treats tier-violation as primary attack surface | cross-ref MS019 | E0366 |
| M00929 | Cross-module — MS016 Tetragon eBPF observes tier violations | cross-ref MS016 | E0366 |
| M00930 | Cross-module — MS027 observability emits tier transition events | cross-ref MS027 + M049 16-event taxonomy | E0367 |
| M00931 | Cross-module — MS022 SSE quota tracks per-tier token usage | cross-ref MS022 | E0367 |
| M00932 | Cross-module — MS013 27-SDD charter governs tier-classification finding ledger | cross-ref MS013 | E0367 |
| M00933 | Cross-repo binding — sovereign-os M049 Policy Fabric 7 PolicyDecision values map to tier-assignment | cross-ref M049 | E0369 |
| M00934 | Cross-repo binding — sovereign-os M048 Module 3 Container/Sandbox Fabric 8 sandbox profiles align with 4-tier classification | cross-ref M048 | E0369 |
| M00935 | Cross-repo binding — sovereign-os M044 Sovereign-OS substrate VFIO/IOMMU substrate enables Tier C VM + Tier D microVM | cross-ref M044 | E0369 |
| M00936 | Cross-repo binding — sovereign-os M042 9-axis Choice Architecture sandbox-vs-host axis maps to tier-assignment override | cross-ref M042 | E0369 |
| M00937 | Cross-repo binding — sovereign-os M054 Tool Interface 4-state ToolIntent→PolicyDecision→ToolExecution→ToolObservation pipeline executes tier-assignment | cross-ref M054 | E0370 |
| M00938 | Cross-repo binding — sovereign-os M050 Design Law "CPU enforces" implements tier-assignment via AVX-512 hot path | cross-ref M050 + M051 | E0370 |
| M00939 | Cross-repo binding — MS007 surface-manifest typed-mirror crate publishes 4-tier tool sandbox schema | cross-ref MS007 | E0370 |
| M00940 | Cross-cycle — MS036 extends MS035 capability-tokens with tier-aware enforcement; MS036 precedes MS037 Filesystem boundary in selfdef INDEX | cross-ref MS035 + MS037 | E0370 |

## Features (F04201–F04320)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F04201 | Section header — "Tool Sandboxes" | dump 3528 | M00915 |
| F04202 | Doctrine — "For tools, I would use tiers" | dump 3532 | M00915 |
| F04203 | Tier A label — "deterministic host tools" | dump 3534 | M00916 |
| F04204 | Tier A tool — rg | dump 3536 | M00916 |
| F04205 | Tier A tool — parsers | dump 3536 | M00916 |
| F04206 | Tier A tool — formatters | dump 3536 | M00916 |
| F04207 | Tier A tool — read-only queries | dump 3536 | M00916 |
| F04208 | Tier B label — "controlled host tools" | dump 3538 | M00917 |
| F04209 | Tier B tool — tests | dump 3540 | M00917 |
| F04210 | Tier B tool — builds | dump 3540 | M00917 |
| F04211 | Tier B tool — package managers | dump 3540 | M00917 |
| F04212 | Tier B tool — file edits | dump 3540 | M00917 |
| F04213 | Tier C label — "VM tools" | dump 3542 | M00918 |
| F04214 | Tier C tool — risky dependency installs | dump 3544 | M00918 |
| F04215 | Tier C tool — unknown scripts | dump 3544 | M00918 |
| F04216 | Tier C tool — browser actions | dump 3544 | M00918 |
| F04217 | Tier D label — "disposable microVM" | dump 3546 | M00919 |
| F04218 | Tier D tool — untrusted binaries | dump 3548 | M00919 |
| F04219 | Tier D tool — unknown archives | dump 3548 | M00919 |
| F04220 | Tier D tool — hostile inputs | dump 3548 | M00919 |
| F04221 | Doctrine — "The model never chooses tier alone" | dump 3550 | M00920 |
| F04222 | Doctrine — "It emits intent" | dump 3550 | M00921 |
| F04223 | Doctrine — "CPU decides tier" | dump 3552 | M00922 |
| F04224 | Tier A characteristic — deterministic (no side effects on host state) | dump 3534 + architecture | M00916 |
| F04225 | Tier A characteristic — host process (NOT containerized) | dump 3534 + architecture | M00916 |
| F04226 | Tier A characteristic — read-only filesystem access | dump 3534 + architecture | M00916 |
| F04227 | Tier A characteristic — no network egress required | dump 3534 + architecture | M00916 |
| F04228 | Tier B characteristic — controlled (specific allowed mutations) | dump 3538 + architecture | M00917 |
| F04229 | Tier B characteristic — host process with cgroup limits | dump 3538 + architecture | M00917 |
| F04230 | Tier B characteristic — workspace-bounded filesystem mutation | dump 3538 + architecture | M00917 |
| F04231 | Tier B characteristic — controlled network egress (package mirrors) | dump 3538 + architecture | M00917 |
| F04232 | Tier C characteristic — VM-isolated execution | dump 3542 + architecture | M00918 |
| F04233 | Tier C characteristic — persistent VM (reused across calls) | dump 3542 + architecture | M00918 |
| F04234 | Tier C characteristic — VFIO/IOMMU passthrough optional | dump 3542 + cross-ref M044 | M00918 |
| F04235 | Tier C characteristic — VM filesystem separate from host | dump 3542 + cross-ref MS034 | M00918 |
| F04236 | Tier D characteristic — disposable (destroyed after each call) | dump 3546 + architecture | M00919 |
| F04237 | Tier D characteristic — microVM (kata/firecracker class) | dump 3546 + architecture | M00919 |
| F04238 | Tier D characteristic — minimal kernel surface | dump 3546 + architecture | M00919 |
| F04239 | Tier D characteristic — no host filesystem visibility | dump 3546 + architecture | M00919 |
| F04240 | Tier D characteristic — explicit input/output exchange only | dump 3546 + cross-ref MS037 | M00919 |
| F04241 | Tier assignment input — tool_id (from MS035 capability_word bits 0..7) | cross-ref MS035 | M00924 |
| F04242 | Tier assignment input — tool risk_class (from M054 Tool metadata) | cross-ref M054 | M00925 |
| F04243 | Tier assignment input — tool side_effects (from M054 Tool metadata) | cross-ref M054 | M00925 |
| F04244 | Tier assignment input — profile autonomy_level (from M054 ResolvedProfile) | cross-ref M054 | M00925 |
| F04245 | Tier assignment input — profile sandbox_level (from M054 ResolvedProfile) | cross-ref M054 | M00925 |
| F04246 | Tier assignment input — capability_word trust level (from MS035) | cross-ref MS035 + dump 3502 | M00924 |
| F04247 | Tier assignment input — host hardware capability (VM available? microVM available?) | cross-ref MS010 hardware-tune-cache | M00925 |
| F04248 | Tier assignment output — tier_id (A/B/C/D) | dump 3534–3548 | M00922 |
| F04249 | Tier assignment output — sandbox_config (specific Podman/VM/microVM settings) | cross-ref MS032 | M00925 |
| F04250 | Tier assignment output — capability_word_constraint (intersection of tool + tier requirements) | cross-ref MS035 + dump 3508 | M00924 |
| F04251 | Selfdef MS017 enforcement — host-default profile defaults tier=A | cross-ref MS017 | M00923 |
| F04252 | Selfdef MS017 enforcement — autonomous-agent profile allows tier=B with policy approval | cross-ref MS017 + M042 user-approval | M00923 |
| F04253 | Selfdef MS017 enforcement — tier=C/D requires explicit operator approval | cross-ref MS017 + M042 + M049 | M00923 |
| F04254 | Selfdef MS016 eBPF — Tetragon TracingPolicy detects tier violations (e.g. Tier A tool attempting filesystem write) | cross-ref MS016 + dump 3528 | M00929 |
| F04255 | Selfdef MS027 observability — emits sandbox_start with tier_id field | cross-ref MS027 + M049 16-event taxonomy | M00930 |
| F04256 | Selfdef MS027 observability — emits sandbox_stop with tier_id field | cross-ref MS027 + M049 | M00930 |
| F04257 | Selfdef MS022 SSE quota — per-tier token bucket (Tier A unlimited / Tier B medium / Tier C low / Tier D minimal) | cross-ref MS022 | M00931 |
| F04258 | Selfdef MS026 integrity-sentinel — baselines tool registry + tier-assignment policy files | cross-ref MS026 | M00932 |
| F04259 | Selfdef MS003 selfdef-signing — signs tier-assignment policy decisions for tamper-resistance | cross-ref MS003 | M00926 |
| F04260 | Selfdef MS013 27-SDD charter — F-2027-xxx governs tier-classification finding ledger | cross-ref MS013 | M00932 |
| F04261 | Sovereign-os M048 Module 3 — sandbox profile read-only-repo aligns with Tier A | cross-ref M048 | M00934 |
| F04262 | Sovereign-os M048 Module 3 — sandbox profile write-workspace aligns with Tier B | cross-ref M048 | M00934 |
| F04263 | Sovereign-os M048 Module 3 — sandbox profile network-denied + gpu-scout align with Tier B/C | cross-ref M048 | M00934 |
| F04264 | Sovereign-os M048 Module 3 — sandbox profile vfio-3090 aligns with Tier C | cross-ref M048 | M00934 |
| F04265 | Sovereign-os M048 Module 3 — sandbox profile vm-isolated aligns with Tier D | cross-ref M048 | M00934 |
| F04266 | Sovereign-os M044 — VFIO/IOMMU substrate enables Tier C VM | cross-ref M044 | M00935 |
| F04267 | Sovereign-os M044 — microVM (kata/firecracker) substrate enables Tier D | cross-ref M044 + architecture | M00935 |
| F04268 | Sovereign-os M049 — Policy Fabric 7 PolicyDecision values map: allow→Tier A, sandbox→Tier B/C, escalate→Tier C/D, deny→refuse | cross-ref M049 | M00933 |
| F04269 | Sovereign-os M049 — Intent-Based Policy 10-field input includes tier_hint from ToolPlan | cross-ref M049 + MS034 | M00933 |
| F04270 | Sovereign-os M050 — Design Law "CPU enforces" maps to tier-assignment in AVX-512 hot path | cross-ref M050 + M051 | M00938 |
| F04271 | Sovereign-os M051 — Hot Data Layout 9-SoA arrays include tier_id field | cross-ref M051 | M00938 |
| F04272 | Sovereign-os M051 — bulk-eval-masks include sandbox_required_mask + tier-aware filtering | cross-ref M051 + dump 3552 | M00922 |
| F04273 | Sovereign-os M054 — Tool Interface 4-state pipeline executes tier-assignment | cross-ref M054 | M00937 |
| F04274 | Sovereign-os M042 — 9-axis Choice Architecture sandbox-vs-host axis = operator-set tier preference | cross-ref M042 | M00936 |
| F04275 | Sovereign-os M042 — High-Risk Mode profile defaults tier=D | cross-ref M042 | M00936 |
| F04276 | Sovereign-os M042 — Autonomous Code Mode profile defaults tier=B | cross-ref M042 | M00936 |
| F04277 | Sovereign-os M042 — Fast Local Mode profile defaults tier=A | cross-ref M042 | M00936 |
| F04278 | Sovereign-os M042 — Research Mode profile defaults tier=B | cross-ref M042 | M00936 |
| F04279 | Sovereign-os M042 — Offline Peace Mode profile defaults tier=A or B | cross-ref M042 | M00936 |
| F04280 | Sovereign-os M032 — Cloud Expert Plane tier promotion to cloud requires explicit policy | cross-ref M032 + M049 | M00933 |
| F04281 | Sovereign-os M046 — LoRA foundry adapter training defaults Tier B (host process) | cross-ref M046 | M00934 |
| F04282 | Sovereign-os M047 — Continuity Manager CRIU checkpoints Tier B/C/D tools | cross-ref M047 | M00935 |
| F04283 | Cross-cycle — MS035 capability_word bits 0..7 enumerate allowed_tools per tier | cross-ref MS035 + dump 3496 | M00940 |
| F04284 | Cross-cycle — MS037 Filesystem Boundary defines /ai-exchange/inbox + outbox structure for Tier C/D | cross-ref MS037 (next INDEX) + dump 3554 | M00940 |
| F04285 | Cross-cycle — MS038 Network Boundary defines per-tier egress rules | cross-ref MS038 (INDEX) + dump 3594 | M00940 |
| F04286 | Cross-cycle — MS039 7 authority levels + 5 trust rings ground tier-assignment authority | cross-ref MS039 (INDEX) | M00926 |
| F04287 | Cross-cycle — MS040 Authority and profiles thread authority through profile resolution | cross-ref MS040 (INDEX) | M00926 |
| F04288 | Cross-cycle — MS041 Commit authority "only the runtime commits" applies to tier-assignment outcomes | cross-ref MS041 (INDEX) + dump 3552 | M00922 |
| F04289 | Cross-cycle — MS042 Tool authority "typed authority on every tool intent" REQUIRES tier_id in capability_word | cross-ref MS042 (INDEX) + dump 3550 | M00921 |
| F04290 | Operator UX — `selfdefctl tool tier <tool_id>` shows assigned tier | architecture + cross-ref MS017 | M00923 |
| F04291 | Operator UX — `selfdefctl tool tier-promote <tool_id> <new_tier>` requests tier promotion | architecture + cross-ref M042 user-approval | M00926 |
| F04292 | Operator UX — `selfdefctl tool tier-violations` lists recent tier violations | architecture + cross-ref MS027 | M00930 |
| F04293 | Operator UX — `selfdefctl tool tier-policy <profile>` shows per-profile tier defaults | architecture + cross-ref M042 | M00936 |
| F04294 | Operator UX — MS011 operator dashboard renders tier distribution histogram | cross-ref MS011 + MS027 | M00930 |
| F04295 | Test integration — MS020 L1 covers tier classification schema rendering | cross-ref MS020 | M00922 |
| F04296 | Test integration — MS020 L2 covers tier-assignment decision pipeline | cross-ref MS020 + dump 3550 | M00922 |
| F04297 | Test integration — MS020 L3 covers `selfdefctl tool tier/tier-promote/tier-violations/tier-policy` CLI | cross-ref MS020 | M00923 |
| F04298 | Test integration — MS020 L4 covers seam between tier classification + sandbox provisioning | cross-ref MS020 + MS032 | M00925 |
| F04299 | Test integration — MS020 L5 covers end-to-end tier escalation (Tier A → B → C → D under policy approval) | cross-ref MS020 + M049 + M042 | M00936 |
| F04300 | Hardware reality — Tier C VM requires VFIO 3090 OR libvirt/QEMU with software emulation | cross-ref M044 + dump 3542 | M00935 |
| F04301 | Hardware reality — Tier D microVM requires kata-containers OR firecracker on Sovereign-OS | cross-ref M044 + dump 3546 | M00935 |
| F04302 | Hardware reality — Tier A/B require zero VM infrastructure (host process only) | dump 3534 + 3538 | M00916 + M00917 |
| F04303 | Doctrine — tier escalation requires operator approval (M042 user-approval-state) | cross-ref M042 + dump 3552 | M00936 |
| F04304 | Doctrine — tier downgrade is automatic when safety improves (M049 telemetry-as-control) | cross-ref M049 + architecture | M00933 |
| F04305 | Doctrine — tier-assignment is RUNTIME (not compile-time) — CPU evaluates at request time | dump 3552 + cross-ref M051 | M00922 |
| F04306 | Doctrine — tier-assignment is OBSERVABLE — every assignment logged via M049 16-event taxonomy | cross-ref M049 + MS027 | M00930 |
| F04307 | Doctrine — tier-assignment is REVERSIBLE — operator can pin lower tier via M042 Choice Envelope | cross-ref M042 + M049 | M00936 |
| F04308 | Doctrine — tier-assignment is AUDITABLE — every assignment recorded via MS009 audit cycles | cross-ref MS009 + MS003 selfdef-signing | M00926 |
| F04309 | Doctrine — tier-assignment IS the IPS-side realization of M050 Design Law "User chooses" | cross-ref M050 + M042 | M00936 |
| F04310 | Doctrine — tier-assignment IS the IPS-side realization of M050 Design Law "CPU enforces" | cross-ref M050 + M051 | M00938 |
| F04311 | Doctrine — tier-assignment IS the IPS-side realization of M050 Design Law "Tools prove" | cross-ref M050 + dump 3534 | M00916 |
| F04312 | Doctrine — tier-assignment IS the IPS-side realization of M050 Design Law "Runtime routes" | cross-ref M050 + dump 3552 | M00922 |
| F04313 | Operator references — kata-containers documentation (kata-containers.io) | architecture + dump 3546 | M00919 |
| F04314 | Operator references — firecracker microVM documentation (firecracker-microvm.github.io) | architecture + dump 3546 | M00919 |
| F04315 | Operator references — libvirt VM management (libvirt.org) | architecture + dump 3542 | M00918 |
| F04316 | Operator references — Linux unprivileged-namespaces documentation | cross-ref M044 + dump 3538 | M00917 |
| F04317 | Operator references — rg (ripgrep) deterministic-search tool docs | dump 3536 | M00916 |
| F04318 | Operator references — Podman/Quadlet systemd-managed containers | cross-ref M048 + dump 3538 | M00917 |
| F04319 | Project-boundary — MS036 is selfdef IPS-side tier-classification enforcement scope | architecture | E0370 |
| F04320 | Composite — 4-tier tool sandbox classification + "model emits intent, CPU decides tier" + cross-module enforcement via 11+ selfdef modules + cross-repo binding via MS007 to sovereign-os M042/M044/M048/M049/M050/M051/M054 | dump 3528–3552 + architecture | E0370 |

## Requirements (R08401–R08640)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R08401 | Section header — "Tool Sandboxes" | dump 3528 | F04201 | non-negotiable | false | 10 |
| R08402 | Tier doctrine — "For tools, I would use tiers" | dump 3532 | F04202 | non-negotiable | false | 10 |
| R08403 | Tier A label — "deterministic host tools" | dump 3534 | F04203 | non-negotiable | false | 10 |
| R08404 | Tier A tool — rg | dump 3536 | F04204 | non-negotiable | false | 10 |
| R08405 | Tier A tool — parsers | dump 3536 | F04205 | non-negotiable | false | 10 |
| R08406 | Tier A tool — formatters | dump 3536 | F04206 | non-negotiable | false | 10 |
| R08407 | Tier A tool — read-only queries | dump 3536 | F04207 | non-negotiable | false | 10 |
| R08408 | Tier B label — "controlled host tools" | dump 3538 | F04208 | non-negotiable | false | 10 |
| R08409 | Tier B tool — tests | dump 3540 | F04209 | non-negotiable | false | 10 |
| R08410 | Tier B tool — builds | dump 3540 | F04210 | non-negotiable | false | 10 |
| R08411 | Tier B tool — package managers | dump 3540 | F04211 | non-negotiable | false | 10 |
| R08412 | Tier B tool — file edits | dump 3540 | F04212 | non-negotiable | false | 10 |
| R08413 | Tier C label — "VM tools" | dump 3542 | F04213 | non-negotiable | false | 10 |
| R08414 | Tier C tool — risky dependency installs | dump 3544 | F04214 | non-negotiable | false | 10 |
| R08415 | Tier C tool — unknown scripts | dump 3544 | F04215 | non-negotiable | false | 10 |
| R08416 | Tier C tool — browser actions | dump 3544 | F04216 | non-negotiable | false | 10 |
| R08417 | Tier D label — "disposable microVM" | dump 3546 | F04217 | non-negotiable | false | 10 |
| R08418 | Tier D tool — untrusted binaries | dump 3548 | F04218 | non-negotiable | false | 10 |
| R08419 | Tier D tool — unknown archives | dump 3548 | F04219 | non-negotiable | false | 10 |
| R08420 | Tier D tool — hostile inputs | dump 3548 | F04220 | non-negotiable | false | 10 |
| R08421 | Doctrine — "The model never chooses tier alone" | dump 3550 | F04221 | non-negotiable | false | 10 |
| R08422 | Doctrine — "It emits intent" | dump 3550 | F04222 | non-negotiable | false | 10 |
| R08423 | Doctrine — "CPU decides tier" | dump 3552 | F04223 | non-negotiable | false | 10 |
| R08424 | Tier A — deterministic (no host state mutation) | dump 3534 + architecture | F04224 | non-negotiable | false | 10 |
| R08425 | Tier A — host process (NOT containerized) | dump 3534 + architecture | F04225 | non-negotiable | false | 10 |
| R08426 | Tier A — read-only filesystem access | dump 3534 + architecture | F04226 | non-negotiable | false | 10 |
| R08427 | Tier A — no network egress required | dump 3534 + architecture | F04227 | non-negotiable | false | 10 |
| R08428 | Tier B — controlled (specific allowed mutations) | dump 3538 + architecture | F04228 | non-negotiable | false | 10 |
| R08429 | Tier B — host process with cgroup limits | dump 3538 + architecture | F04229 | non-negotiable | false | 10 |
| R08430 | Tier B — workspace-bounded filesystem mutation | dump 3538 + architecture | F04230 | non-negotiable | false | 10 |
| R08431 | Tier B — controlled network egress (package mirrors) | dump 3538 + architecture | F04231 | non-negotiable | false | 10 |
| R08432 | Tier C — VM-isolated execution | dump 3542 + architecture | F04232 | non-negotiable | false | 10 |
| R08433 | Tier C — persistent VM (reused across calls) | dump 3542 + architecture | F04233 | non-negotiable | false | 10 |
| R08434 | Tier C — VFIO/IOMMU passthrough optional | dump 3542 + cross-ref M044 | F04234 | non-negotiable | false | 10 |
| R08435 | Tier C — VM filesystem separate from host | dump 3542 + cross-ref MS034 | F04235 | non-negotiable | false | 10 |
| R08436 | Tier D — disposable (destroyed after each call) | dump 3546 + architecture | F04236 | non-negotiable | false | 10 |
| R08437 | Tier D — microVM (kata/firecracker class) | dump 3546 + architecture | F04237 | non-negotiable | false | 10 |
| R08438 | Tier D — minimal kernel surface | dump 3546 + architecture | F04238 | non-negotiable | false | 10 |
| R08439 | Tier D — no host filesystem visibility | dump 3546 + architecture | F04239 | non-negotiable | false | 10 |
| R08440 | Tier D — explicit input/output exchange only | dump 3546 + cross-ref MS037 | F04240 | non-negotiable | false | 10 |
| R08441 | Tier assignment input — tool_id (MS035 capability_word bits 0..7) | cross-ref MS035 | F04241 | non-negotiable | false | 10 |
| R08442 | Tier assignment input — tool risk_class (M054 Tool metadata) | cross-ref M054 | F04242 | non-negotiable | false | 10 |
| R08443 | Tier assignment input — tool side_effects (M054 Tool metadata) | cross-ref M054 | F04243 | non-negotiable | false | 10 |
| R08444 | Tier assignment input — profile autonomy_level (M054 ResolvedProfile) | cross-ref M054 | F04244 | non-negotiable | false | 10 |
| R08445 | Tier assignment input — profile sandbox_level (M054 ResolvedProfile) | cross-ref M054 | F04245 | non-negotiable | false | 10 |
| R08446 | Tier assignment input — capability_word trust level (MS035) | cross-ref MS035 + dump 3502 | F04246 | non-negotiable | false | 10 |
| R08447 | Tier assignment input — host hardware capability (VM/microVM availability) | cross-ref MS010 | F04247 | non-negotiable | false | 10 |
| R08448 | Tier assignment output — tier_id (A/B/C/D) | dump 3534–3548 | F04248 | non-negotiable | false | 10 |
| R08449 | Tier assignment output — sandbox_config (Podman/VM/microVM settings) | cross-ref MS032 | F04249 | non-negotiable | false | 10 |
| R08450 | Tier assignment output — capability_word_constraint (intersection of tool + tier) | cross-ref MS035 + dump 3508 | F04250 | non-negotiable | false | 10 |
| R08451 | Selfdef MS017 — host-default profile defaults tier=A | cross-ref MS017 | F04251 | non-negotiable | false | 10 |
| R08452 | Selfdef MS017 — autonomous-agent profile allows tier=B with policy approval | cross-ref MS017 + M042 | F04252 | non-negotiable | false | 10 |
| R08453 | Selfdef MS017 — tier=C/D requires explicit operator approval | cross-ref MS017 + M042 + M049 | F04253 | non-negotiable | false | 10 |
| R08454 | Selfdef MS016 eBPF — Tetragon detects tier violations | cross-ref MS016 + dump 3528 | F04254 | non-negotiable | false | 10 |
| R08455 | Selfdef MS027 — emits sandbox_start with tier_id field | cross-ref MS027 + M049 | F04255 | non-negotiable | false | 10 |
| R08456 | Selfdef MS027 — emits sandbox_stop with tier_id field | cross-ref MS027 + M049 | F04256 | non-negotiable | false | 10 |
| R08457 | Selfdef MS022 — per-tier token bucket (Tier A unlimited / Tier B medium / Tier C low / Tier D minimal) | cross-ref MS022 | F04257 | non-negotiable | false | 10 |
| R08458 | Selfdef MS026 — baselines tool registry + tier-assignment policy files | cross-ref MS026 | F04258 | non-negotiable | false | 10 |
| R08459 | Selfdef MS003 selfdef-signing — signs tier-assignment policy decisions | cross-ref MS003 | F04259 | non-negotiable | false | 10 |
| R08460 | Selfdef MS013 — F-2027-xxx governs tier-classification finding ledger | cross-ref MS013 | F04260 | non-negotiable | false | 10 |
| R08461 | Sovereign-os M048 sandbox profile read-only-repo = Tier A | cross-ref M048 | F04261 | non-negotiable | false | 10 |
| R08462 | Sovereign-os M048 sandbox profile write-workspace = Tier B | cross-ref M048 | F04262 | non-negotiable | false | 10 |
| R08463 | Sovereign-os M048 sandbox profiles network-denied + gpu-scout = Tier B/C | cross-ref M048 | F04263 | non-negotiable | false | 10 |
| R08464 | Sovereign-os M048 sandbox profile vfio-3090 = Tier C | cross-ref M048 | F04264 | non-negotiable | false | 10 |
| R08465 | Sovereign-os M048 sandbox profile vm-isolated = Tier D | cross-ref M048 | F04265 | non-negotiable | false | 10 |
| R08466 | Sovereign-os M044 — VFIO/IOMMU substrate enables Tier C | cross-ref M044 | F04266 | non-negotiable | false | 10 |
| R08467 | Sovereign-os M044 — microVM substrate enables Tier D | cross-ref M044 + architecture | F04267 | non-negotiable | false | 10 |
| R08468 | Sovereign-os M049 — 7 PolicyDecision values map to tier assignment | cross-ref M049 | F04268 | non-negotiable | false | 10 |
| R08469 | Sovereign-os M049 — Intent-Based Policy 10-field input includes tier_hint | cross-ref M049 + MS034 | F04269 | non-negotiable | false | 10 |
| R08470 | Sovereign-os M050 — Design Law "CPU enforces" implements tier-assignment | cross-ref M050 + M051 | F04270 | non-negotiable | false | 10 |
| R08471 | Sovereign-os M051 — Hot Data Layout 9-SoA includes tier_id field | cross-ref M051 | F04271 | non-negotiable | false | 10 |
| R08472 | Sovereign-os M051 — bulk-eval-masks include sandbox_required_mask + tier-aware filtering | cross-ref M051 | F04272 | non-negotiable | false | 10 |
| R08473 | Sovereign-os M054 — Tool Interface 4-state pipeline executes tier-assignment | cross-ref M054 | F04273 | non-negotiable | false | 10 |
| R08474 | Sovereign-os M042 — 9-axis sandbox-vs-host axis = operator tier preference | cross-ref M042 | F04274 | non-negotiable | false | 10 |
| R08475 | Sovereign-os M042 — High-Risk Mode defaults tier=D | cross-ref M042 | F04275 | non-negotiable | false | 10 |
| R08476 | Sovereign-os M042 — Autonomous Code Mode defaults tier=B | cross-ref M042 | F04276 | non-negotiable | false | 10 |
| R08477 | Sovereign-os M042 — Fast Local Mode defaults tier=A | cross-ref M042 | F04277 | non-negotiable | false | 10 |
| R08478 | Sovereign-os M042 — Research Mode defaults tier=B | cross-ref M042 | F04278 | non-negotiable | false | 10 |
| R08479 | Sovereign-os M042 — Offline Peace Mode defaults tier=A or B | cross-ref M042 | F04279 | non-negotiable | false | 10 |
| R08480 | Sovereign-os M032 — Cloud Expert Plane tier promotion requires explicit policy | cross-ref M032 + M049 | F04280 | non-negotiable | false | 10 |
| R08481 | Sovereign-os M046 — LoRA foundry adapter training defaults Tier B | cross-ref M046 | F04281 | non-negotiable | false | 10 |
| R08482 | Sovereign-os M047 — Continuity Manager CRIU checkpoints Tier B/C/D tools | cross-ref M047 | F04282 | non-negotiable | false | 10 |
| R08483 | Cross-cycle — MS035 capability_word bits 0..7 enumerate allowed_tools per tier | cross-ref MS035 | F04283 | non-negotiable | false | 10 |
| R08484 | Cross-cycle — MS037 Filesystem Boundary defines /ai-exchange/inbox+outbox for Tier C/D | cross-ref MS037 + dump 3554 | F04284 | non-negotiable | false | 10 |
| R08485 | Cross-cycle — MS038 Network Boundary defines per-tier egress rules | cross-ref MS038 + dump 3594 | F04285 | non-negotiable | false | 10 |
| R08486 | Cross-cycle — MS039 7 authority levels + 5 trust rings ground tier-assignment authority | cross-ref MS039 | F04286 | non-negotiable | false | 10 |
| R08487 | Cross-cycle — MS040 Authority and profiles thread authority through tier-resolution | cross-ref MS040 | F04287 | non-negotiable | false | 10 |
| R08488 | Cross-cycle — MS041 Commit authority "only the runtime commits" applies to tier-assignment | cross-ref MS041 + dump 3552 | F04288 | non-negotiable | false | 10 |
| R08489 | Cross-cycle — MS042 Tool authority REQUIRES tier_id in capability_word | cross-ref MS042 + dump 3550 | F04289 | non-negotiable | false | 10 |
| R08490 | Operator UX — `selfdefctl tool tier <tool_id>` | architecture + cross-ref MS017 | F04290 | non-negotiable | false | 10 |
| R08491 | Operator UX — `selfdefctl tool tier-promote <tool_id> <new_tier>` | architecture + M042 | F04291 | non-negotiable | false | 10 |
| R08492 | Operator UX — `selfdefctl tool tier-violations` | architecture + MS027 | F04292 | non-negotiable | false | 10 |
| R08493 | Operator UX — `selfdefctl tool tier-policy <profile>` | architecture + M042 | F04293 | non-negotiable | false | 10 |
| R08494 | Operator UX — MS011 dashboard renders tier distribution histogram | cross-ref MS011 + MS027 | F04294 | non-negotiable | false | 10 |
| R08495 | Test — MS020 L1 covers tier classification schema rendering | cross-ref MS020 | F04295 | non-negotiable | false | 10 |
| R08496 | Test — MS020 L2 covers tier-assignment decision pipeline | cross-ref MS020 + dump 3550 | F04296 | non-negotiable | false | 10 |
| R08497 | Test — MS020 L3 covers `selfdefctl tool tier*` CLI | cross-ref MS020 | F04297 | non-negotiable | false | 10 |
| R08498 | Test — MS020 L4 covers seam between tier classification + sandbox provisioning | cross-ref MS020 + MS032 | F04298 | non-negotiable | false | 10 |
| R08499 | Test — MS020 L5 covers end-to-end tier escalation A→B→C→D under policy approval | cross-ref MS020 + M049 + M042 | F04299 | non-negotiable | false | 10 |
| R08500 | Hardware — Tier C VM requires VFIO 3090 OR libvirt/QEMU emulation | cross-ref M044 + dump 3542 | F04300 | non-negotiable | false | 10 |
| R08501 | Hardware — Tier D microVM requires kata-containers OR firecracker | cross-ref M044 + dump 3546 | F04301 | non-negotiable | false | 10 |
| R08502 | Hardware — Tier A/B require zero VM infrastructure (host process only) | dump 3534 + 3538 | F04302 | non-negotiable | false | 10 |
| R08503 | Doctrine — tier escalation requires operator approval (M042 user-approval-state) | cross-ref M042 + dump 3552 | F04303 | non-negotiable | false | 10 |
| R08504 | Doctrine — tier downgrade automatic when safety improves | cross-ref M049 | F04304 | non-negotiable | false | 10 |
| R08505 | Doctrine — tier-assignment is RUNTIME (not compile-time) | dump 3552 + cross-ref M051 | F04305 | non-negotiable | false | 10 |
| R08506 | Doctrine — tier-assignment is OBSERVABLE | cross-ref M049 + MS027 | F04306 | non-negotiable | false | 10 |
| R08507 | Doctrine — tier-assignment is REVERSIBLE (operator can pin lower tier) | cross-ref M042 + M049 | F04307 | non-negotiable | false | 10 |
| R08508 | Doctrine — tier-assignment is AUDITABLE | cross-ref MS009 + MS003 | F04308 | non-negotiable | false | 10 |
| R08509 | Doctrine — tier-assignment realizes M050 Design Law "User chooses" | cross-ref M050 + M042 | F04309 | non-negotiable | false | 10 |
| R08510 | Doctrine — tier-assignment realizes M050 Design Law "CPU enforces" | cross-ref M050 + M051 | F04310 | non-negotiable | false | 10 |
| R08511 | Doctrine — tier-assignment realizes M050 Design Law "Tools prove" | cross-ref M050 | F04311 | non-negotiable | false | 10 |
| R08512 | Doctrine — tier-assignment realizes M050 Design Law "Runtime routes" | cross-ref M050 | F04312 | non-negotiable | false | 10 |
| R08513 | Operator references — kata-containers documentation | architecture + dump 3546 | F04313 | non-negotiable | false | 10 |
| R08514 | Operator references — firecracker microVM documentation | architecture + dump 3546 | F04314 | non-negotiable | false | 10 |
| R08515 | Operator references — libvirt VM management | architecture + dump 3542 | F04315 | non-negotiable | false | 10 |
| R08516 | Operator references — Linux unprivileged-namespaces docs | cross-ref M044 + dump 3538 | F04316 | non-negotiable | false | 10 |
| R08517 | Operator references — rg (ripgrep) deterministic-search tool docs | dump 3536 | F04317 | non-negotiable | false | 10 |
| R08518 | Operator references — Podman/Quadlet systemd-managed containers | cross-ref M048 + dump 3538 | F04318 | non-negotiable | false | 10 |
| R08519 | Project-boundary — MS036 is selfdef IPS-side tier-classification enforcement scope | architecture | F04319 | non-negotiable | false | 10 |
| R08520 | Tier predicate — Tier A tool MUST have read-only file access | dump 3534 + architecture | F04226 | non-negotiable | false | 10 |
| R08521 | Tier predicate — Tier A tool MUST have no network egress | dump 3534 + architecture | F04227 | non-negotiable | false | 10 |
| R08522 | Tier predicate — Tier A tool MUST have deterministic output | dump 3534 + architecture | F04224 | non-negotiable | false | 10 |
| R08523 | Tier predicate — Tier B tool MAY mutate workspace | dump 3538 + architecture | F04230 | non-negotiable | false | 10 |
| R08524 | Tier predicate — Tier B tool MAY have controlled network egress | dump 3538 + architecture | F04231 | non-negotiable | false | 10 |
| R08525 | Tier predicate — Tier B tool MUST run under cgroup limits | dump 3538 + architecture | F04229 | non-negotiable | false | 10 |
| R08526 | Tier predicate — Tier C tool MUST run inside a VM | dump 3542 + architecture | F04232 | non-negotiable | false | 10 |
| R08527 | Tier predicate — Tier C VM MAY persist across multiple tool calls | dump 3542 + architecture | F04233 | non-negotiable | false | 10 |
| R08528 | Tier predicate — Tier D tool MUST run inside a disposable microVM | dump 3546 + architecture | F04237 | non-negotiable | false | 10 |
| R08529 | Tier predicate — Tier D microVM MUST be destroyed after the tool call | dump 3546 + architecture | F04236 | non-negotiable | false | 10 |
| R08530 | Tier predicate — Tier D tool input MUST come through explicit exchange path | dump 3546 + cross-ref MS037 | F04240 | non-negotiable | false | 10 |
| R08531 | Tier predicate — Tier D tool output MUST go through explicit exchange path | dump 3546 + cross-ref MS037 | F04240 | non-negotiable | false | 10 |
| R08532 | Operator UX — operator MAY pin lower tier (e.g. "always use Tier B for `pip install`") | cross-ref M042 user-approval + architecture | F04291 | non-negotiable | false | 10 |
| R08533 | Operator UX — operator MAY pin higher tier (escalation) per session via ask_user PolicyDecision | cross-ref M049 ask_user + M042 user-approval | F04291 | non-negotiable | false | 10 |
| R08534 | Operator UX — operator MUST be notified on tier-promotion request via MS004 notifier integrations | cross-ref MS004 + M049 | F04291 | non-negotiable | false | 10 |
| R08535 | Hardware — Tier D microVM cold start MUST be ≤ 500ms for Tier D to be operationally viable | architecture + cross-ref Firecracker docs | F04301 | non-negotiable | true | 10 |
| R08536 | Hardware — Tier C VM cold start MUST be ≤ 5s; warm start MUST be ≤ 50ms via CRIU restore | architecture + cross-ref M047 CRIU | F04300 | non-negotiable | true | 10 |
| R08537 | Hardware — Tier B host process cold start MUST be ≤ 100ms | architecture | F04229 | non-negotiable | true | 10 |
| R08538 | Hardware — Tier A host tool cold start MUST be ≤ 10ms (e.g. `rg` startup) | dump 3536 | F04204 | non-negotiable | true | 10 |
| R08539 | Cross-module — selfdef MS001 daemon core hosts tier-classification engine | cross-ref MS001 | M00922 | non-negotiable | false | 10 |
| R08540 | Cross-module — selfdef MS002 collector fabric emits tier_id in event metadata | cross-ref MS002 | M00930 | non-negotiable | false | 10 |
| R08541 | Cross-module — selfdef MS006 14-functional-modules each declare default tier per tool exposed | cross-ref MS006 | F04302 | non-negotiable | false | 10 |
| R08542 | Cross-module — selfdef MS010 hardware-tune-cache exposes vm_available / microvm_available booleans for tier feasibility | cross-ref MS010 | F04247 | non-negotiable | false | 10 |
| R08543 | Cross-module — selfdef MS012 perimeter coexistence enforces Tier C/D outgoing traffic through perimeter | cross-ref MS012 | M00925 | non-negotiable | false | 10 |
| R08544 | Cross-module — selfdef MS014 SSH-wrap applies Tier B treatment to outbound SSH tool calls | cross-ref MS014 | F04228 | non-negotiable | false | 10 |
| R08545 | Cross-module — selfdef MS018 VPN-bridge enforces per-tier network egress | cross-ref MS018 + dump 3526 | M00926 | non-negotiable | false | 10 |
| R08546 | Cross-module — selfdef MS021 shared module-script lib v2 provides `sandbox_run_tier` helper | cross-ref MS021 + architecture | M00926 | non-negotiable | false | 10 |
| R08547 | Cross-module — selfdef MS024 bridge-l2 nftables ruleset applies per-tier network egress | cross-ref MS024 + dump 3526 | M00926 | non-negotiable | false | 10 |
| R08548 | Cross-module — selfdef MS023 polarproxy applies Tier C TLS-MITM inspection for browser-tool workflows | cross-ref MS023 + dump 3544 | F04216 | non-negotiable | false | 10 |
| R08549 | Cross-module — selfdef MS025 detect-host event-bus transports tier_id in TraceEvent | cross-ref MS025 + M049 | F04157 | non-negotiable | false | 10 |
| R08550 | Cross-module — selfdef MS028 bitnet-gpu-inference applies Tier C VFIO 3090 VM execution | cross-ref MS028 + dump 3542 | F04264 | non-negotiable | false | 10 |
| R08551 | Cross-module — selfdef MS029 slm-cpu-loop applies Tier A/B host execution | cross-ref MS029 + dump 3534 | F04203 | non-negotiable | false | 10 |
| R08552 | Cross-module — selfdef MS030 tensor-parallel-inference applies Tier B host execution (multi-GPU NOT compatible with Tier C single-VM) | cross-ref MS030 + dump 3542 | F04263 | non-negotiable | false | 10 |
| R08553 | Cross-module — selfdef MS031 wasm-aot-cache provides .cwasm artifacts consumed at any tier | cross-ref MS031 | F04265 | non-negotiable | false | 10 |
| R08554 | Cross-module — selfdef MS032 sandbox tier 1 = Tier A | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08555 | Cross-module — selfdef MS032 sandbox tiers 2-3 = Tier B | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08556 | Cross-module — selfdef MS032 sandbox tiers 4-5 = Tier B (network-denied / network-allowed) | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08557 | Cross-module — selfdef MS032 sandbox tier 6a (VFIO 3090 VM) = Tier C | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08558 | Cross-module — selfdef MS032 sandbox tier 6b (browser/GUI sandbox) = Tier C | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08559 | Cross-module — selfdef MS032 sandbox tier 7a (CRIU checkpoints) = Tier B/C | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08560 | Cross-module — selfdef MS032 sandbox tier 7b (ZFS clone workspaces) = Tier B/C | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08561 | Cross-module — selfdef MS032 microVM tier (future) = Tier D | cross-ref MS032 | M00925 | non-negotiable | false | 10 |
| R08562 | Cross-module — selfdef MS033 Phase 3 policy decision object carries tier as decision field | cross-ref MS033 | M00926 | non-negotiable | false | 10 |
| R08563 | Cross-module — selfdef MS034 Communication Boundary ToolPlan message carries tier_hint | cross-ref MS034 + dump 3471 | M00927 | non-negotiable | false | 10 |
| R08564 | Cross-module — selfdef MS035 capability_word allowed_tools bits 0..7 encode tier-eligible tool set | cross-ref MS035 + dump 3496 | M00924 | non-negotiable | false | 10 |
| R08565 | Doctrine — model intent is a HINT, NOT a binding tier choice | dump 3550 + 3552 | F04221 | non-negotiable | false | 10 |
| R08566 | Doctrine — CPU (AVX-512 cortex) tier decision is BINDING | dump 3552 + cross-ref M051 | F04223 | non-negotiable | false | 10 |
| R08567 | Doctrine — tier-assignment SHALL ALWAYS prefer the LOWEST tier that satisfies the task | dump 3534–3548 + architecture | F04223 | non-negotiable | false | 10 |
| R08568 | Doctrine — tier-assignment SHALL escalate UPWARD if lower tier proves insufficient | dump 3550 + architecture | F04223 | non-negotiable | false | 10 |
| R08569 | Doctrine — tier-assignment SHALL NEVER downgrade actively-running tier MID-CALL (only on next call) | architecture | F04304 | non-negotiable | false | 10 |
| R08570 | Doctrine — tier-assignment MAY explore multiple tiers concurrently for evaluation (M046 LoRA foundry pattern) | cross-ref M046 + architecture | F04281 | non-negotiable | false | 10 |
| R08571 | Cross-repo binding — MS007 surface-manifest typed-mirror carries 4-tier schema | cross-ref MS007 | F04320 | non-negotiable | false | 10 |
| R08572 | Cross-repo binding — sovereign-os M048 Module 3 Container/Sandbox Fabric publishes tier-assignment outcomes via observability events | cross-ref M048 + M049 | M00934 | non-negotiable | false | 10 |
| R08573 | Cross-repo binding — sovereign-os M049 Policy Fabric publishes tier-assignment policy decisions | cross-ref M049 | M00933 | non-negotiable | false | 10 |
| R08574 | Cross-repo binding — sovereign-os M042 Choice Architecture publishes profile→tier mapping via PROFILES.yaml | cross-ref M042 + M041 | M00936 | non-negotiable | false | 10 |
| R08575 | Implementation phase — Phase 3 (Policy & Trace) of M053 implements tier-assignment in PolicyDecision | cross-ref M053 + MS033 | E0367 | non-negotiable | false | 10 |
| R08576 | Implementation phase — Phase 4 (Sandbox Execution) of M053 implements tier provisioning | cross-ref M053 + MS032 | E0368 | non-negotiable | false | 10 |
| R08577 | Implementation phase — Phase 7 (AVX-512 Cortex) of M053 optimizes tier-assignment via AVX-512 hot path | cross-ref M053 + M051 + dump 3552 | E0370 | non-negotiable | false | 10 |
| R08578 | Implementation phase — Phase 10 (Full Cockpit) of M053 surfaces tier-assignment state to operator | cross-ref M053 + MS011 | M00930 | non-negotiable | false | 10 |
| R08579 | Schema versioning — tier classification schema_version "1.0.0" | architecture + cross-ref MS028 + MS030 + MS031 | F04320 | non-negotiable | false | 10 |
| R08580 | Schema versioning — schema upgrade requires explicit operator opt-in | architecture | F04320 | non-negotiable | false | 10 |
| R08581 | Schema versioning — tier_id is a STABLE field (no renaming across schema versions) | architecture + dump 3534–3548 | F04248 | non-negotiable | false | 10 |
| R08582 | Schema versioning — sandbox_config fields MAY be extended in MINOR bump | architecture | F04249 | non-negotiable | false | 10 |
| R08583 | Schema versioning — capability_word_constraint format pinned to MS035 schema | cross-ref MS035 | F04250 | non-negotiable | false | 10 |
| R08584 | Observability — every tier transition (e.g. Tier A → Tier B) emits sandbox_start event with from_tier + to_tier fields | cross-ref M049 16-event taxonomy + dump 3550 | M00930 | non-negotiable | false | 10 |
| R08585 | Observability — tier-violation events emit OCSF Detection Finding class 2004 | cross-ref MS026 + M049 | F04254 | non-negotiable | false | 10 |
| R08586 | Observability — MS027 dashboard renders Sankey diagram of tier transitions | cross-ref MS027 + architecture | F04294 | non-negotiable | false | 10 |
| R08587 | Operator UX — tier-assignment failure SHALL surface clear error message (e.g. "Tool X requires Tier C; not available on this host") | architecture | F04290 | non-negotiable | false | 10 |
| R08588 | Operator UX — tier-assignment success SHALL log human-readable explanation (e.g. "Tier B selected — controlled host tool with workspace-write") | architecture + dump 3552 | F04290 | non-negotiable | false | 10 |
| R08589 | Operator UX — tier-promotion request SHALL surface a comparison table (current tier vs requested tier vs implications) | architecture + cross-ref M042 user-approval | F04291 | non-negotiable | false | 10 |
| R08590 | Operator UX — tier-policy SHALL be editable per-project (project-local tier overrides per profile) | cross-ref M042 + M041 PROFILES.yaml | F04293 | non-negotiable | false | 10 |
| R08591 | Cross-cycle integration — MS036 + MS032 + MS033 + MS034 + MS035 form the IPS-side 5-boundary doctrine | cross-ref MS032 + MS033 + MS034 + MS035 | E0370 | non-negotiable | false | 10 |
| R08592 | Cross-cycle integration — 5-boundary doctrine = capability_word + tier_classification + communication_boundary + policy + sandbox | dump 3492 + 3528 + 3528 + 3220 + 3260 | E0370 | non-negotiable | false | 10 |
| R08593 | Cross-cycle integration — 5-boundary doctrine REALIZES sovereign-os M049 Policy Fabric 7-policy-decision values | cross-ref M049 + dump 3528 | F04268 | non-negotiable | false | 10 |
| R08594 | Cross-cycle integration — 5-boundary doctrine REALIZES sovereign-os M048 Module 3 + Module 10 fabric | cross-ref M048 | F04261–F04265 | non-negotiable | false | 10 |
| R08595 | Cross-cycle integration — 5-boundary doctrine REALIZES sovereign-os M050 Design Law (6 lines) | cross-ref M050 | F04309–F04312 | non-negotiable | false | 10 |
| R08596 | Cross-cycle integration — 5-boundary doctrine REALIZES sovereign-os M051 Hot Data Layout (9-SoA + 6-bulk-eval-masks) | cross-ref M051 | F04271 + F04272 | non-negotiable | false | 10 |
| R08597 | Cross-cycle integration — 5-boundary doctrine REALIZES sovereign-os M054 Tool Interface (4-state pipeline) | cross-ref M054 + dump 3550 | F04273 | non-negotiable | false | 10 |
| R08598 | Selfdef IPS scope — MS036 is one of MS033/MS034/MS035/MS036/MS037/MS038/MS039/MS040/MS041/MS042 IPS authority modules | architecture + INDEX | E0370 | non-negotiable | false | 10 |
| R08599 | Sovereign-os runtime scope — MS036's runtime counterpart is M048 Module 3 + M049 Policy Fabric + M054 Tool Interface | cross-ref M048 + M049 + M054 | F04261–F04273 | non-negotiable | false | 10 |
| R08600 | Operator references — Tier doctrine traces to capability-based-security literature (Mark S. Miller, Capability Myths Demolished) | architecture + dump 3508 | F04313 | non-negotiable | false | 10 |
| R08601 | Operator references — Tier D microVM reference: Firecracker (AWS Lambda's microVM) | architecture + dump 3546 | F04314 | non-negotiable | false | 10 |
| R08602 | Operator references — Tier D microVM reference: kata-containers (OCI-compatible microVM) | architecture + dump 3546 | F04313 | non-negotiable | false | 10 |
| R08603 | Operator references — Tier C VM reference: libvirt/QEMU/KVM | architecture + dump 3542 | F04315 | non-negotiable | false | 10 |
| R08604 | Operator references — Tier B controlled host reference: Linux cgroup v2 + namespaces (M045) | cross-ref M045 + dump 3538 | F04316 | non-negotiable | false | 10 |
| R08605 | Operator references — Tier A deterministic host reference: ripgrep, jq, tree-sitter parsers, prettier formatters | dump 3536 | F04317 | non-negotiable | false | 10 |
| R08606 | Doctrine — Tier A tools are the SAFEST and CHEAPEST default | dump 3534 + architecture | F04224 | non-negotiable | false | 10 |
| R08607 | Doctrine — Tier D tools are the MOST EXPENSIVE and HIGHEST-LATENCY | dump 3546 + architecture | F04236 | non-negotiable | false | 10 |
| R08608 | Doctrine — Tier selection trades safety against cost-latency | dump 3534 + 3546 + architecture | F04223 | non-negotiable | false | 10 |
| R08609 | Doctrine — adaptive tier selection learns from observed cost-vs-safety outcomes via M046 LoRA foundry | cross-ref M046 + cross-ref M037 | M00936 | non-negotiable | false | 10 |
| R08610 | Doctrine — tier-classification is the SAME PATTERN as MS035 capability tokens (typed-authority-handle) | cross-ref MS035 + dump 3492 + 3534 | F04195 | non-negotiable | false | 10 |
| R08611 | Doctrine — tier-classification is the SAME PATTERN as MS032 sandbox tiers (graduated isolation) | cross-ref MS032 + dump 3534 | F04201 | non-negotiable | false | 10 |
| R08612 | Doctrine — tier-classification is the SAME PATTERN as M042 9-axis Choice Architecture (operator-set policy-composable) | cross-ref M042 + dump 3534 | F04274 | non-negotiable | false | 10 |
| R08613 | Doctrine — tier-classification is the SAME PATTERN as M049 9-class memory sensitivity (graduated trust) | cross-ref M049 + dump 3502 | F04246 | non-negotiable | false | 10 |
| R08614 | Doctrine — tier-classification IS the IPS-side typed-authority-handle for TOOLS specifically | dump 3530 + dump 3492 + 3528 | E0370 | non-negotiable | false | 10 |
| R08615 | Audit — tier-classification decisions MUST be reproducible from inputs | architecture + cross-ref M049 | F04308 | non-negotiable | false | 10 |
| R08616 | Audit — tier-classification policy MUST be operator-readable + operator-editable | dump 3552 + cross-ref M042 | F04293 | non-negotiable | false | 10 |
| R08617 | Audit — tier-classification telemetry MUST integrate with M048 Module 9 Observability Fabric | cross-ref M048 + M049 | F04294 | non-negotiable | false | 10 |
| R08618 | Audit — tier-classification cost MUST be tracked in M048 Module 7 Eval/Value Plane | cross-ref M048 + M049 | F04257 | non-negotiable | false | 10 |
| R08619 | Operator-trust calibration — operator's COMFORT with tier C/D evolves through deployment lifecycle | dump 3552 + cross-ref M037 evidence-driven autonomy | F04303 | non-negotiable | false | 10 |
| R08620 | Operator-trust calibration — initial deployment defaults TIGHT (Tier A primary) | dump 3534 + architecture | F04251 | non-negotiable | false | 10 |
| R08621 | Operator-trust calibration — operator may PROGRESSIVELY enable higher tiers as evals prove safety | cross-ref M046 + dump 3550 | F04253 | non-negotiable | false | 10 |
| R08622 | Operator-trust calibration — operator may REGRESSIVELY pin lower tiers if incident occurs | cross-ref MS019 + dump 3552 | F04303 | non-negotiable | false | 10 |
| R08623 | Operator-trust calibration — tier-classification policy IS the operator-trust crystallization surface | dump 3552 + cross-ref M046 | F04308 | non-negotiable | false | 10 |
| R08624 | Cross-repo composition — selfdef MS036 + sovereign-os M046 LoRA foundry crystallizes operator-tested tier policies into adapter weights | cross-ref M046 + dump 3552 | F04281 | non-negotiable | false | 10 |
| R08625 | Cross-repo composition — selfdef MS036 + sovereign-os M037 Spec/TDD evidence-driven autonomy validates tier-classification predictions against observed outcomes | cross-ref M037 + dump 3552 | F04308 | non-negotiable | false | 10 |
| R08626 | Cross-repo composition — selfdef MS036 + sovereign-os M027 Value Plane integrates tier-cost-vs-safety reward function | cross-ref M027 + dump 3534 + 3546 | F04257 | non-negotiable | false | 10 |
| R08627 | Cross-repo composition — selfdef MS036 + sovereign-os M025 Cognitive Compiler emits tier-aware DAG nodes | cross-ref M025 + dump 3552 | F04223 | non-negotiable | false | 10 |
| R08628 | Cross-repo composition — selfdef MS036 + sovereign-os M026 SLM swarm + RLM engine routes per-tier model invocation | cross-ref M026 + dump 3550 | F04222 | non-negotiable | false | 10 |
| R08629 | Cross-repo composition — selfdef MS036 + sovereign-os M032 Cloud Expert Plane gates Tier-C-cloud + Tier-D-cloud per policy | cross-ref M032 + M049 | F04280 | non-negotiable | false | 10 |
| R08630 | Cross-repo composition — selfdef MS036 + sovereign-os M034 Anthropic-first Gateway routes per-tier API endpoints | cross-ref M034 + dump 3550 | E0370 | non-negotiable | false | 10 |
| R08631 | Cross-repo composition — selfdef MS036 + sovereign-os M040 Hyper Feature 7 VFIO 3090 enables Tier C | cross-ref M040 + dump 3542 | F04234 | non-negotiable | false | 10 |
| R08632 | Cross-repo composition — selfdef MS036 + sovereign-os M040 Hyper Feature 8 ZFS commit gate enables Tier B/C/D rollback | cross-ref M040 + cross-ref M044 ZFS | F04282 | non-negotiable | false | 10 |
| R08633 | Cross-repo composition — selfdef MS036 + sovereign-os M040 Hyper Feature 10 Modes-as-hardware-configurations defaults per-mode tier policy | cross-ref M040 + M042 | F04274–F04279 | non-negotiable | false | 10 |
| R08634 | Cross-repo composition — selfdef MS036 + sovereign-os M043 Bridge Layer hardware-aware intelligence scheduling honors tier-aware GPU/CPU placement | cross-ref M043 | F04270 | non-negotiable | false | 10 |
| R08635 | Cross-repo composition — selfdef MS036 + sovereign-os M045 Linux as intelligence governor (cgroup v2 + AppArmor + namespaces + eBPF) enforces Tier B host process limits | cross-ref M045 + dump 3538 | F04229 | non-negotiable | false | 10 |
| R08636 | Cross-repo composition — selfdef MS036 + sovereign-os M044 Sovereign-OS substrate provides Tier B/C/D execution environments | cross-ref M044 | F04266 + F04267 | non-negotiable | false | 10 |
| R08637 | Implementation note — MS036 implementation SHALL re-use M054 Tool Interface 4-state pipeline (ToolIntent → PolicyDecision → ToolExecution → ToolObservation) | cross-ref M054 | M00937 | non-negotiable | false | 10 |
| R08638 | Implementation note — MS036 implementation SHALL re-use M049 Policy Fabric 7 PolicyDecision values | cross-ref M049 | F04268 | non-negotiable | false | 10 |
| R08639 | Implementation note — MS036 implementation SHALL re-use M051 Hot Data Layout 9-SoA columnar arrays for tier-assignment hot path | cross-ref M051 | F04271 | non-negotiable | false | 10 |
| R08640 | Composite — MS036 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Tool Sandboxes Tier A/B/C/D classification from dump 3528-3552 ("For tools, I would use tiers" + Tier A deterministic host tools / Tier B controlled host tools / Tier C VM tools / Tier D disposable microVM) + doctrine "The model never chooses tier alone. It emits intent. CPU decides tier"; cross-module enforcement via 30+ selfdef modules (MS001/MS002/MS003/MS006/MS010/MS012/MS013/MS014/MS015/MS016/MS017/MS018/MS019/MS021/MS022/MS023/MS024/MS025/MS026/MS027/MS028/MS029/MS030/MS031/MS032/MS033/MS034/MS035) + sovereign-os M025/M026/M027/M032/M034/M037/M040/M042/M043/M044/M045/M046/M048/M049/M050/M051/M054 + cross-repo binding via MS007 surface-manifest typed-mirror crate publishing 4-tier schema; tier-classification is the IPS-side typed-authority-handle for TOOLS specifically | dump 3528–3552 + cross-ref MS007 + MS001-MS042 + M025-M054 | E0361 + E0362 + E0363 + E0364 + E0365 + E0366 + E0367 + E0368 + E0369 + E0370 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: section header + doctrine + 4-tier labels + tools (R08401–R08423) + 16 tier-characteristic invariants (R08424–R08440) + tier-assignment input/output schema (R08441–R08450) + 10 selfdef cross-module enforcement rows (R08451–R08460) + sovereign-os realization (R08461–R08482) + cross-cycle integration (R08483–R08489) + 5 operator UX commands (R08490–R08494) + MS020 L1-L5 test integration (R08495–R08499) + hardware reality (R08500–R08502) + 10 doctrine rows (R08503–R08512) + 6 operator references (R08513–R08518) + project-boundary (R08519) + 12 tier-predicate hard invariants (R08520–R08531) + operator UX 3 rows (R08532–R08534) + 4 hardware-latency requirement rows (R08535–R08538) + 26 selfdef cross-module rows (R08539–R08564) + 6 doctrine rows on model-intent-vs-CPU-decision + tier-direction-of-traversal (R08565–R08570) + 4 cross-repo binding rows (R08571–R08574) + 4 implementation-phase rows (R08575–R08578) + 5 schema versioning rows (R08579–R08583) + 3 observability rows (R08584–R08586) + 4 operator UX clarification rows (R08587–R08590) + 7 cross-cycle integration rows (R08591–R08597) + 2 scope-clarification rows (R08598–R08599) + 6 operator references (R08600–R08605) + 4 cost-vs-safety doctrine rows (R08606–R08609) + 5 same-pattern doctrine rows (R08610–R08614) + 4 audit invariants (R08615–R08618) + 5 operator-trust calibration rows (R08619–R08623) + 11 cross-repo composition rows (R08624–R08636) + 3 implementation reuse rows (R08637–R08639) + composite (R08640)
- Source range 22 lines (dump 3528–3549) yields 240 R-rows representing a 10.9:1 R-per-line ratio (the doctrinal block is extremely compact; architectural elaboration via cross-module + cross-repo bindings carries the bulk per established pattern)
- Project boundary — MS036 is selfdef IPS-side Tier-classification scope; sovereign-os M048 Module 3 + M049 Policy Fabric + M054 Tool Interface orchestrate at the runtime layer; cross-repo binding via MS007 surface-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS035 Capability tokens / MS037 Filesystem boundary
- Cross-cycle — MS036 + MS032 + MS033 + MS034 + MS035 form the IPS-side 5-boundary doctrine
- Cross-repo realization — sovereign-os M025/M026/M027/M032/M034/M037/M040/M042/M043/M044/M045/M046/M048/M049/M050/M051/M054
- Cross-repo binding — MS007 surface-manifest typed-mirror crate carries 4-tier schema
- Operator references: kata-containers + firecracker microVM + libvirt + Linux cgroup v2/namespaces + ripgrep/jq/tree-sitter/prettier (Tier A) + Mark S. Miller "Capability Myths Demolished"
- Doctrine — Tier-classification is the IPS-side typed-authority-handle for TOOLS specifically; complements MS035 capability_word and MS032 sandbox tiers
