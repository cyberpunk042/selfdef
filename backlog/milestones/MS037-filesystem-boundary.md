# MS037 — Filesystem boundary

> Parent: `backlog/milestones/INDEX.md` row MS037 (source ref dump 3550–3593).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 3550–3593 (Filesystem Boundary doctrinal block).
> All entries below extract verbatim. No invention.

## Epics (E0371–E0380)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0371 | Filesystem Boundary doctrine — "Use explicit exchange directories" | dump 3550–3552 |
| E0372 | 3 explicit exchange directories — `/ai-exchange/inbox` / `/ai-exchange/outbox` / `/ai-exchange/artifacts` | dump 3556–3558 |
| E0373 | Doctrine — "VM writes proposals, not final state" | dump 3562 |
| E0374 | Host import pipeline (6 steps) — parse / scan / diff / policy-check / oracle-review if needed / commit | dump 3566–3572 |
| E0375 | Code patch output schema (5 fields) — unified diff / metadata / declared files touched / test notes / risk flags | dump 3578–3584 |
| E0376 | Host application predicates (6 checks) — paths inside workspace / no forbidden files / diff parses / policy allows writes / branch budget permits / user approval if required | dump 3588–3594 |
| E0377 | Cross-module — selfdef MS017 agent-guard enforces filesystem boundary | cross-ref MS017 |
| E0378 | Cross-module — selfdef MS016 Tetragon eBPF observes filesystem-boundary violations | cross-ref MS016 |
| E0379 | Cross-repo binding — sovereign-os M048 Module 3 sandbox profile write-workspace + M049 Policy Fabric "file write" checkpoint | cross-ref M048 + M049 |
| E0380 | Composite — 3-dir exchange + "VM writes proposals not final state" + 6-step host import + 5-field patch schema + 6-check application predicates binds the M054 Tool Interface filesystem operations to MS035 capability_word filesystem-scope bits (bits 8..15) | dump 3550–3593 + cross-ref M054 + MS035 |

## Modules (M00941–M00966)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00941 | Explicit exchange doctrine — "Use explicit exchange directories" | dump 3552 | E0371 |
| M00942 | Directory — `/ai-exchange/inbox` (host → VM input drop) | dump 3556 | E0372 |
| M00943 | Directory — `/ai-exchange/outbox` (VM → host output drop) | dump 3557 | E0372 |
| M00944 | Directory — `/ai-exchange/artifacts` (binary artifacts / model outputs / blobs) | dump 3558 | E0372 |
| M00945 | Doctrine — "VM writes proposals, not final state" | dump 3562 | E0373 |
| M00946 | Host import step — parse | dump 3568 | E0374 |
| M00947 | Host import step — scan | dump 3568 | E0374 |
| M00948 | Host import step — diff | dump 3569 | E0374 |
| M00949 | Host import step — policy-check | dump 3570 | E0374 |
| M00950 | Host import step — oracle-review if needed | dump 3571 | E0374 |
| M00951 | Host import step — commit | dump 3572 | E0374 |
| M00952 | Code patch field — unified diff | dump 3580 | E0375 |
| M00953 | Code patch field — metadata | dump 3581 | E0375 |
| M00954 | Code patch field — declared files touched | dump 3582 | E0375 |
| M00955 | Code patch field — test notes | dump 3583 | E0375 |
| M00956 | Code patch field — risk flags | dump 3584 | E0375 |
| M00957 | Application predicate — paths inside workspace | dump 3590 | E0376 |
| M00958 | Application predicate — no forbidden files | dump 3591 | E0376 |
| M00959 | Application predicate — diff parses | dump 3591 | E0376 |
| M00960 | Application predicate — policy allows writes | dump 3592 | E0376 |
| M00961 | Application predicate — branch budget permits | dump 3593 | E0376 |
| M00962 | Application predicate — user approval if required | dump 3594 | E0376 |
| M00963 | Cross-module — selfdef MS017 agent-guard enforces filesystem boundary | cross-ref MS017 | E0377 |
| M00964 | Cross-module — selfdef MS016 Tetragon eBPF observes filesystem-boundary violations | cross-ref MS016 | E0378 |
| M00965 | Cross-module — selfdef MS035 capability_word filesystem-scope bits 8..15 encode allowed file IO | cross-ref MS035 + dump 3497 | E0376 |
| M00966 | Cross-repo binding — MS007 surface-manifest typed-mirror crate publishes 3-dir + 5-field schema | cross-ref MS007 | E0380 |

## Features (F04321–F04440)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F04321 | Section header — "Filesystem Boundary" | dump 3550 | M00941 |
| F04322 | "Use explicit exchange directories" | dump 3552 | M00941 |
| F04323 | Directory — /ai-exchange/inbox | dump 3556 | M00942 |
| F04324 | Directory — /ai-exchange/outbox | dump 3557 | M00943 |
| F04325 | Directory — /ai-exchange/artifacts | dump 3558 | M00944 |
| F04326 | Doctrine — "VM writes proposals, not final state" | dump 3562 | M00945 |
| F04327 | Doctrine — "Host imports only after validation" | dump 3566 | E0374 |
| F04328 | Host import step — parse | dump 3568 | M00946 |
| F04329 | Host import step — scan | dump 3568 | M00947 |
| F04330 | Host import step — diff | dump 3569 | M00948 |
| F04331 | Host import step — policy-check | dump 3570 | M00949 |
| F04332 | Host import step — oracle-review if needed | dump 3571 | M00950 |
| F04333 | Host import step — commit | dump 3572 | M00951 |
| F04334 | Code patch doctrine — "For code patches, VM outputs" | dump 3578 | E0375 |
| F04335 | Code patch field — unified diff | dump 3580 | M00952 |
| F04336 | Code patch field — metadata | dump 3581 | M00953 |
| F04337 | Code patch field — declared files touched | dump 3582 | M00954 |
| F04338 | Code patch field — test notes | dump 3583 | M00955 |
| F04339 | Code patch field — risk flags | dump 3584 | M00956 |
| F04340 | Application doctrine — "Host applies only if" | dump 3588 | E0376 |
| F04341 | Application predicate — paths inside workspace | dump 3590 | M00957 |
| F04342 | Application predicate — no forbidden files | dump 3591 | M00958 |
| F04343 | Application predicate — diff parses | dump 3591 | M00959 |
| F04344 | Application predicate — policy allows writes | dump 3592 | M00960 |
| F04345 | Application predicate — branch budget permits | dump 3593 | M00961 |
| F04346 | Application predicate — user approval if required | dump 3594 | M00962 |
| F04347 | inbox semantics — host drops files for VM to consume | dump 3556 + architecture | M00942 |
| F04348 | inbox semantics — typically prompts + context + tool args | architecture + dump 3556 | M00942 |
| F04349 | inbox semantics — mounted read-only inside VM | architecture + dump 3477 (MS034 invariant) | M00942 |
| F04350 | outbox semantics — VM writes results for host to validate | dump 3557 + architecture | M00943 |
| F04351 | outbox semantics — typically responses + diffs + tool outputs | architecture + dump 3557 | M00943 |
| F04352 | outbox semantics — mounted write-only inside VM | architecture + cross-ref MS034 | M00943 |
| F04353 | artifacts semantics — binary artifacts (model outputs, .cwasm, images) | dump 3558 + architecture | M00944 |
| F04354 | artifacts semantics — mounted write-only inside VM | architecture + cross-ref MS034 | M00944 |
| F04355 | artifacts semantics — separate from outbox to avoid mixing text proposals with binary outputs | architecture + dump 3558 | M00944 |
| F04356 | Doctrine corollary — host filesystem outside /ai-exchange/* is INVISIBLE to VM | dump 3477 + 3552 | M00945 |
| F04357 | Doctrine corollary — VM cannot mutate host repo, /etc, /usr, /var, etc. | dump 3477 + 3552 | M00945 |
| F04358 | Doctrine corollary — VM proposals = "candidate truth" not "committed truth" | dump 3562 + cross-ref MS034 | M00945 |
| F04359 | Parse step — JSON/YAML/diff/markdown schema validation | dump 3568 + architecture | M00946 |
| F04360 | Parse step — fail-closed on parse error | dump 3568 + architecture | M00946 |
| F04361 | Scan step — antivirus / yara / sigma rule scanning | dump 3568 + cross-ref MS025 sigma-correlator | M00947 |
| F04362 | Scan step — known-bad pattern detection | dump 3568 + architecture | M00947 |
| F04363 | Diff step — git diff or unified diff parsing | dump 3569 + architecture | M00948 |
| F04364 | Diff step — file-path validation against workspace boundary | dump 3569 + 3590 | M00948 |
| F04365 | Policy-check step — invoke M049 Policy Fabric 7-decision evaluation | dump 3570 + cross-ref M049 | M00949 |
| F04366 | Policy-check step — selfdef MS033 Phase 3 PolicyDecision object | dump 3570 + cross-ref MS033 | M00949 |
| F04367 | Oracle-review step — invoke high-cost Blackwell-class model for verification | dump 3571 + cross-ref M043 + M050 | M00950 |
| F04368 | Oracle-review step — conditional on risk_class + side_effect_class | dump 3571 + cross-ref M049 + MS036 | M00950 |
| F04369 | Commit step — atomic write to host filesystem | dump 3572 + architecture | M00951 |
| F04370 | Commit step — ZFS snapshot before commit (M040 Hyper Feature 8) | cross-ref M040 + dump 3572 | M00951 |
| F04371 | Commit step — append to replay log (M044 ZFS-backed) | cross-ref M044 + dump 3484 (MS034) | M00951 |
| F04372 | Patch schema — unified diff format (POSIX `diff -u` output) | dump 3580 + architecture | M00952 |
| F04373 | Patch schema — metadata = profile + trace_id + capability_word + timestamp | architecture + cross-ref MS035 | M00953 |
| F04374 | Patch schema — declared_files_touched = list of relative paths VM intends to modify | dump 3582 + architecture | M00954 |
| F04375 | Patch schema — declared_files_touched MUST MATCH actual files in diff | dump 3582 + 3591 | M00954 |
| F04376 | Patch schema — test notes = description of what tests pass/fail after patch | dump 3583 + architecture | M00955 |
| F04377 | Patch schema — risk_flags = bit field signaling concerning code patterns (e.g. exec, eval, network, fs) | dump 3584 + architecture | M00956 |
| F04378 | Predicate — workspace boundary checked via absolute-path canonicalization (symlink-safe) | dump 3590 + architecture | M00957 |
| F04379 | Predicate — forbidden files = .ssh / .gnupg / .aws / /etc / /usr / /var / etc. | dump 3591 + cross-ref MS019 threat model | M00958 |
| F04380 | Predicate — diff parse failure rejects the entire proposal | dump 3591 + architecture | M00959 |
| F04381 | Predicate — policy allows writes via M049 Policy Fabric file-write checkpoint | dump 3592 + cross-ref M049 | M00960 |
| F04382 | Predicate — branch budget = MS022 SubscriberGuard token budget for this branch | cross-ref MS022 + dump 3593 | M00961 |
| F04383 | Predicate — user approval = M049 ask outcome + M042 user-approval-state | cross-ref M042 + M049 + dump 3594 | M00962 |
| F04384 | Selfdef MS017 — agent-guard enforces filesystem boundary at host level | cross-ref MS017 | M00963 |
| F04385 | Selfdef MS017 — `[host-default]` profile assumes inbox/outbox/artifacts mounted read-only / write-only / write-only | cross-ref MS017 | M00963 |
| F04386 | Selfdef MS017 — `[autonomous-agent]` profile relaxes only with operator approval | cross-ref MS017 + M042 | M00963 |
| F04387 | Selfdef MS016 — Tetragon TracingPolicy detects filesystem-boundary syscall violations | cross-ref MS016 + dump 3528 (MS035) | M00964 |
| F04388 | Selfdef MS016 — Tetragon emits OCSF Detection Finding class 2004 on violation | cross-ref MS016 + MS026 | M00964 |
| F04389 | Selfdef MS026 — integrity-sentinel baselines /ai-exchange/* directory permissions + mount options | cross-ref MS026 | M00963 |
| F04390 | Selfdef MS027 — observability renders filesystem boundary metric `selfdef_fs_boundary_violations_total{file_class}` | cross-ref MS027 | M00964 |
| F04391 | Selfdef MS035 — capability_word filesystem-scope bits 8..15 encode allowed file IO | cross-ref MS035 + dump 3497 | M00965 |
| F04392 | Selfdef MS036 — Tier A tools have read-only /ai-exchange/inbox; Tier B has /workspace write; Tier C/D have isolated FS | cross-ref MS036 | M00965 |
| F04393 | Selfdef MS003 — selfdef-signing signs patch metadata (unified diff signed) | cross-ref MS003 | M00951 |
| F04394 | Selfdef MS013 — 27-SDD charter governs filesystem boundary finding ledger | cross-ref MS013 | M00963 |
| F04395 | Selfdef MS019 — threat model treats /ai-exchange/* traversal as primary attack surface | cross-ref MS019 + dump 3590 | M00958 |
| F04396 | Sovereign-os M048 — Module 3 Container/Sandbox Fabric mounts /ai-exchange/* via virtiofs DAX | cross-ref M048 + dump 3461 (MS034) | M00966 |
| F04397 | Sovereign-os M048 — Module 3 sandbox profile write-workspace = host /ai-exchange/outbox visible | cross-ref M048 | M00966 |
| F04398 | Sovereign-os M049 — Policy Fabric "Can this action mutate files?" checkpoint guards Commit step | cross-ref M049 + dump 3572 | M00960 |
| F04399 | Sovereign-os M044 — Storage Plane ZFS snapshot before commit | cross-ref M044 + dump 3572 | M00951 |
| F04400 | Sovereign-os M040 — Hyper Feature 8 ZFS snapshots as commit gate IS the filesystem-boundary commit semantics | cross-ref M040 + dump 3572 | M00951 |
| F04401 | Sovereign-os M042 — Choice Architecture user-approval-state IS application predicate "user approval if required" | cross-ref M042 + dump 3594 | M00962 |
| F04402 | Sovereign-os M046 — LoRA foundry adapter PatchProposal flow goes through filesystem boundary | cross-ref M046 + dump 3473 (MS034) + 3580 | M00952 |
| F04403 | Sovereign-os M047 — Continuity Manager ZFS clone workspaces enable per-branch /ai-exchange/* | cross-ref M047 + dump 3556 | M00942 |
| F04404 | Sovereign-os M050 — Design Law "ZFS remembers" IS the Commit step's replay log | cross-ref M050 + dump 3572 | M00951 |
| F04405 | Sovereign-os M054 — Tool Interface ToolIntent→PolicyDecision→ToolExecution→ToolObservation 4-state pipeline traverses filesystem boundary | cross-ref M054 + dump 3550 | M00946–M00951 |
| F04406 | Cross-repo binding — MS007 surface-manifest typed-mirror crate carries 3-dir + 5-field patch + 6-check predicate schemas | cross-ref MS007 | M00966 |
| F04407 | Test integration — MS020 L1 covers /ai-exchange/* schema rendering | cross-ref MS020 | M00942–M00944 |
| F04408 | Test integration — MS020 L2 covers 6-step host import pipeline | cross-ref MS020 + dump 3566–3572 | E0374 |
| F04409 | Test integration — MS020 L3 covers selfdefctl filesystem-boundary CLI | cross-ref MS020 + architecture | M00963 |
| F04410 | Test integration — MS020 L4 covers seam between VM outbox + host policy-check | cross-ref MS020 + dump 3570 | M00949 |
| F04411 | Test integration — MS020 L5 covers end-to-end VM PatchProposal → host commit lifecycle | cross-ref MS020 + dump 3473–3594 | E0380 |
| F04412 | Operator UX — `selfdefctl fs-boundary status` shows pending VM proposals | architecture + cross-ref MS011 | M00945 |
| F04413 | Operator UX — `selfdefctl fs-boundary approve <proposal_id>` approves pending proposal | architecture + cross-ref M042 + M049 | M00962 |
| F04414 | Operator UX — `selfdefctl fs-boundary reject <proposal_id>` rejects pending proposal | architecture + cross-ref M049 | M00962 |
| F04415 | Operator UX — `selfdefctl fs-boundary log` shows commit history | architecture + cross-ref MS009 audit cycles | M00951 |
| F04416 | Operator UX — MS011 dashboard renders pending-proposals widget | cross-ref MS011 | M00962 |
| F04417 | Hardware reality — /ai-exchange/* uses virtiofs DAX for low-latency exchange | dump 3461 (MS034) + 3556 | M00942 |
| F04418 | Hardware reality — large blobs go through /ai-exchange/artifacts (NOT through vsock) | dump 3558 + cross-ref MS034 | M00944 |
| F04419 | Hardware reality — small messages (DraftRequest etc.) go through virtio-vsock (NOT through /ai-exchange/*) | cross-ref MS034 + dump 3458 | E0372 |
| F04420 | Cross-cycle — MS037 binds MS034 Communication Boundary 8-message-types with concrete filesystem exchange dirs | cross-ref MS034 + dump 3550 | E0380 |
| F04421 | Cross-cycle — MS037 grounds MS035 capability_word filesystem-scope bits 8..15 with directory-level scope | cross-ref MS035 + dump 3497 | M00965 |
| F04422 | Cross-cycle — MS037 grounds MS036 Tier A/B/C/D tool sandbox filesystem access patterns | cross-ref MS036 | M00965 |
| F04423 | Cross-cycle — MS037 feeds MS038 Network boundary (next INDEX) with parallel "explicit exchange" doctrine | cross-ref MS038 (INDEX) | E0380 |
| F04424 | Cross-cycle — MS037 feeds MS039 7 authority levels by treating filesystem access as authority-graded | cross-ref MS039 (INDEX) | E0380 |
| F04425 | Doctrine — explicit exchange directories are the SAME PATTERN as MS035 capability tokens (typed-authority-handle for filesystem) | dump 3508 (MS035) + 3552 | M00945 |
| F04426 | Doctrine — explicit exchange directories enable LEAST-PRIVILEGE for filesystem operations | dump 3552 + 3590 | M00957 |
| F04427 | Doctrine — explicit exchange directories enable CAPABILITY-PASSING for filesystem operations | dump 3552 + cross-ref MS035 | M00965 |
| F04428 | Doctrine — filesystem boundary REPLACES ambient filesystem authority with typed-authority-handles | dump 3552 + cross-ref MS035 | M00945 |
| F04429 | Doctrine — "Same invariant again" — filesystem boundary follows the candidate→filter→verify→commit pattern from MS034 | cross-ref MS034 + dump 3566–3572 | E0374 |
| F04430 | Operator references — virtiofs DAX mode docs | dump 3461 (MS034) | F04417 |
| F04431 | Operator references — `diff -u` unified diff format spec | dump 3580 | F04372 |
| F04432 | Operator references — Linux mount-namespace docs | cross-ref M045 + dump 3552 | F04347 |
| F04433 | Operator references — POSIX path-canonicalization (`realpath(3)`) | dump 3590 + architecture | F04378 |
| F04434 | Operator references — OCI image-spec filesystem layout | architecture + dump 3552 | M00942 |
| F04435 | Operator references — git apply / patch(1) for unified-diff application | dump 3580 + architecture | F04372 |
| F04436 | Schema versioning — filesystem boundary schema_version "1.0.0" | architecture + cross-ref MS028 + MS030 + MS031 | F04373 |
| F04437 | Schema versioning — 3-dir layout + 5-field patch schema is STABLE across MAJOR versions | architecture | M00942–M00956 |
| F04438 | Project-boundary — MS037 is selfdef IPS-side filesystem boundary scope; sovereign-os M048 Module 3 + M049 Policy Fabric orchestrate at runtime layer | architecture | E0379 |
| F04439 | Cross-repo binding — selfdef MS037 + sovereign-os M048 Module 3 + M049 file-write checkpoint + M042 user-approval-state + M044 Storage Plane ZFS form the cross-repo filesystem-governance quartet | cross-ref M048 + M049 + M042 + M044 | E0380 |
| F04440 | Composite — 3-dir explicit exchange + "VM writes proposals not final state" + 6-step host import + 5-field code patch schema + 6-check application predicates + cross-module enforcement via MS017/MS016/MS026/MS027/MS035/MS036 + cross-repo binding via MS007 to sovereign-os M042/M044/M046/M047/M048/M049/M050/M054 | dump 3550–3593 + cross-ref MS007 + architecture | E0380 |

## Requirements (R08641–R08880)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R08641 | Section header — "Filesystem Boundary" | dump 3550 | F04321 | non-negotiable | false | 10 |
| R08642 | Doctrine — "Use explicit exchange directories" | dump 3552 | F04322 | non-negotiable | false | 10 |
| R08643 | Directory — `/ai-exchange/inbox` | dump 3556 | F04323 | non-negotiable | false | 10 |
| R08644 | Directory — `/ai-exchange/outbox` | dump 3557 | F04324 | non-negotiable | false | 10 |
| R08645 | Directory — `/ai-exchange/artifacts` | dump 3558 | F04325 | non-negotiable | false | 10 |
| R08646 | Doctrine — "VM writes proposals, not final state" | dump 3562 | F04326 | non-negotiable | false | 10 |
| R08647 | Doctrine — "Host imports only after validation" | dump 3566 | F04327 | non-negotiable | false | 10 |
| R08648 | Host import step — parse | dump 3568 | F04328 | non-negotiable | false | 10 |
| R08649 | Host import step — scan | dump 3568 | F04329 | non-negotiable | false | 10 |
| R08650 | Host import step — diff | dump 3569 | F04330 | non-negotiable | false | 10 |
| R08651 | Host import step — policy-check | dump 3570 | F04331 | non-negotiable | false | 10 |
| R08652 | Host import step — oracle-review if needed | dump 3571 | F04332 | non-negotiable | false | 10 |
| R08653 | Host import step — commit | dump 3572 | F04333 | non-negotiable | false | 10 |
| R08654 | Code patch doctrine — "For code patches, VM outputs" | dump 3578 | F04334 | non-negotiable | false | 10 |
| R08655 | Code patch field — unified diff | dump 3580 | F04335 | non-negotiable | false | 10 |
| R08656 | Code patch field — metadata | dump 3581 | F04336 | non-negotiable | false | 10 |
| R08657 | Code patch field — declared files touched | dump 3582 | F04337 | non-negotiable | false | 10 |
| R08658 | Code patch field — test notes | dump 3583 | F04338 | non-negotiable | false | 10 |
| R08659 | Code patch field — risk flags | dump 3584 | F04339 | non-negotiable | false | 10 |
| R08660 | Application doctrine — "Host applies only if" | dump 3588 | F04340 | non-negotiable | false | 10 |
| R08661 | Application predicate — paths inside workspace | dump 3590 | F04341 | non-negotiable | false | 10 |
| R08662 | Application predicate — no forbidden files | dump 3591 | F04342 | non-negotiable | false | 10 |
| R08663 | Application predicate — diff parses | dump 3591 | F04343 | non-negotiable | false | 10 |
| R08664 | Application predicate — policy allows writes | dump 3592 | F04344 | non-negotiable | false | 10 |
| R08665 | Application predicate — branch budget permits | dump 3593 | F04345 | non-negotiable | false | 10 |
| R08666 | Application predicate — user approval if required | dump 3594 | F04346 | non-negotiable | false | 10 |
| R08667 | inbox — host drops files for VM to consume | dump 3556 + architecture | F04347 | non-negotiable | false | 10 |
| R08668 | inbox — typically prompts + context + tool args | architecture + dump 3556 | F04348 | non-negotiable | false | 10 |
| R08669 | inbox — mounted read-only inside VM | architecture + cross-ref MS034 | F04349 | non-negotiable | false | 10 |
| R08670 | outbox — VM writes results for host to validate | dump 3557 + architecture | F04350 | non-negotiable | false | 10 |
| R08671 | outbox — typically responses + diffs + tool outputs | architecture + dump 3557 | F04351 | non-negotiable | false | 10 |
| R08672 | outbox — mounted write-only inside VM | architecture + cross-ref MS034 | F04352 | non-negotiable | false | 10 |
| R08673 | artifacts — binary artifacts (model outputs, .cwasm, images) | dump 3558 + architecture | F04353 | non-negotiable | false | 10 |
| R08674 | artifacts — mounted write-only inside VM | architecture + cross-ref MS034 | F04354 | non-negotiable | false | 10 |
| R08675 | artifacts — separate from outbox to avoid mixing text proposals with binary outputs | architecture + dump 3558 | F04355 | non-negotiable | false | 10 |
| R08676 | Corollary — host filesystem outside /ai-exchange/* is INVISIBLE to VM | dump 3477 + 3552 | F04356 | non-negotiable | false | 10 |
| R08677 | Corollary — VM cannot mutate host repo, /etc, /usr, /var, etc. | dump 3477 + 3552 | F04357 | non-negotiable | false | 10 |
| R08678 | Corollary — VM proposals = "candidate truth" not "committed truth" | dump 3562 + cross-ref MS034 | F04358 | non-negotiable | false | 10 |
| R08679 | Parse step — JSON/YAML/diff/markdown schema validation | dump 3568 + architecture | F04359 | non-negotiable | false | 10 |
| R08680 | Parse step — fail-closed on parse error | dump 3568 + architecture | F04360 | non-negotiable | false | 10 |
| R08681 | Scan step — antivirus / yara / sigma rule scanning | dump 3568 + cross-ref MS025 | F04361 | non-negotiable | false | 10 |
| R08682 | Scan step — known-bad pattern detection | dump 3568 + architecture | F04362 | non-negotiable | false | 10 |
| R08683 | Diff step — git diff or unified diff parsing | dump 3569 + architecture | F04363 | non-negotiable | false | 10 |
| R08684 | Diff step — file-path validation against workspace boundary | dump 3569 + 3590 | F04364 | non-negotiable | false | 10 |
| R08685 | Policy-check step — invoke M049 Policy Fabric 7-decision evaluation | dump 3570 + cross-ref M049 | F04365 | non-negotiable | false | 10 |
| R08686 | Policy-check step — selfdef MS033 Phase 3 PolicyDecision object | dump 3570 + cross-ref MS033 | F04366 | non-negotiable | false | 10 |
| R08687 | Oracle-review step — invoke high-cost Blackwell-class model for verification | dump 3571 + cross-ref M043 + M050 | F04367 | non-negotiable | false | 10 |
| R08688 | Oracle-review step — conditional on risk_class + side_effect_class | dump 3571 + cross-ref M049 + MS036 | F04368 | non-negotiable | false | 10 |
| R08689 | Commit step — atomic write to host filesystem | dump 3572 + architecture | F04369 | non-negotiable | false | 10 |
| R08690 | Commit step — ZFS snapshot before commit (M040 Hyper Feature 8) | cross-ref M040 + dump 3572 | F04370 | non-negotiable | false | 10 |
| R08691 | Commit step — append to replay log (M044 ZFS-backed) | cross-ref M044 + dump 3484 | F04371 | non-negotiable | false | 10 |
| R08692 | Patch — unified diff format (POSIX diff -u output) | dump 3580 + architecture | F04372 | non-negotiable | false | 10 |
| R08693 | Patch — metadata = profile + trace_id + capability_word + timestamp | architecture + cross-ref MS035 | F04373 | non-negotiable | false | 10 |
| R08694 | Patch — declared_files_touched = list of relative paths VM intends to modify | dump 3582 + architecture | F04374 | non-negotiable | false | 10 |
| R08695 | Patch — declared_files_touched MUST MATCH actual files in diff | dump 3582 + 3591 | F04375 | non-negotiable | false | 10 |
| R08696 | Patch — test notes = description of what tests pass/fail after patch | dump 3583 + architecture | F04376 | non-negotiable | false | 10 |
| R08697 | Patch — risk_flags = bit field signaling concerning code patterns | dump 3584 + architecture | F04377 | non-negotiable | false | 10 |
| R08698 | Predicate — workspace boundary checked via absolute-path canonicalization (symlink-safe) | dump 3590 + architecture | F04378 | non-negotiable | false | 10 |
| R08699 | Predicate — forbidden files = .ssh / .gnupg / .aws / /etc / /usr / /var / etc. | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08700 | Predicate — diff parse failure rejects the entire proposal | dump 3591 + architecture | F04380 | non-negotiable | false | 10 |
| R08701 | Predicate — policy allows writes via M049 Policy Fabric file-write checkpoint | dump 3592 + cross-ref M049 | F04381 | non-negotiable | false | 10 |
| R08702 | Predicate — branch budget = MS022 SubscriberGuard token budget for this branch | cross-ref MS022 + dump 3593 | F04382 | non-negotiable | false | 10 |
| R08703 | Predicate — user approval = M049 ask outcome + M042 user-approval-state | cross-ref M042 + M049 + dump 3594 | F04383 | non-negotiable | false | 10 |
| R08704 | Selfdef MS017 — agent-guard enforces filesystem boundary at host level | cross-ref MS017 | F04384 | non-negotiable | false | 10 |
| R08705 | Selfdef MS017 — host-default profile: inbox r/o, outbox w/o, artifacts w/o | cross-ref MS017 | F04385 | non-negotiable | false | 10 |
| R08706 | Selfdef MS017 — autonomous-agent profile relaxes only with operator approval | cross-ref MS017 + M042 | F04386 | non-negotiable | false | 10 |
| R08707 | Selfdef MS016 — Tetragon detects filesystem-boundary syscall violations | cross-ref MS016 + dump 3528 | F04387 | non-negotiable | false | 10 |
| R08708 | Selfdef MS016 — Tetragon emits OCSF Detection Finding class 2004 on violation | cross-ref MS016 + MS026 | F04388 | non-negotiable | false | 10 |
| R08709 | Selfdef MS026 — integrity-sentinel baselines /ai-exchange/* permissions + mount options | cross-ref MS026 | F04389 | non-negotiable | false | 10 |
| R08710 | Selfdef MS027 — metric `selfdef_fs_boundary_violations_total{file_class}` | cross-ref MS027 | F04390 | non-negotiable | false | 10 |
| R08711 | Selfdef MS035 — capability_word filesystem-scope bits 8..15 encode allowed file IO | cross-ref MS035 + dump 3497 | F04391 | non-negotiable | false | 10 |
| R08712 | Selfdef MS036 — Tier A r/o /ai-exchange/inbox; Tier B /workspace write; Tier C/D isolated FS | cross-ref MS036 | F04392 | non-negotiable | false | 10 |
| R08713 | Selfdef MS003 selfdef-signing signs patch metadata | cross-ref MS003 | F04393 | non-negotiable | false | 10 |
| R08714 | Selfdef MS013 — 27-SDD charter governs filesystem boundary finding ledger | cross-ref MS013 | F04394 | non-negotiable | false | 10 |
| R08715 | Selfdef MS019 — threat model treats /ai-exchange/* traversal as primary attack surface | cross-ref MS019 + dump 3590 | F04395 | non-negotiable | false | 10 |
| R08716 | Sovereign-os M048 Module 3 mounts /ai-exchange/* via virtiofs DAX | cross-ref M048 + dump 3461 | F04396 | non-negotiable | false | 10 |
| R08717 | Sovereign-os M048 Module 3 sandbox profile write-workspace = host /ai-exchange/outbox visible | cross-ref M048 | F04397 | non-negotiable | false | 10 |
| R08718 | Sovereign-os M049 Policy Fabric file-write checkpoint guards Commit step | cross-ref M049 + dump 3572 | F04398 | non-negotiable | false | 10 |
| R08719 | Sovereign-os M044 Storage Plane ZFS snapshot before commit | cross-ref M044 + dump 3572 | F04399 | non-negotiable | false | 10 |
| R08720 | Sovereign-os M040 Hyper Feature 8 ZFS snapshots as commit gate | cross-ref M040 + dump 3572 | F04400 | non-negotiable | false | 10 |
| R08721 | Sovereign-os M042 Choice Architecture user-approval-state | cross-ref M042 + dump 3594 | F04401 | non-negotiable | false | 10 |
| R08722 | Sovereign-os M046 LoRA foundry PatchProposal flow goes through filesystem boundary | cross-ref M046 + dump 3473 + 3580 | F04402 | non-negotiable | false | 10 |
| R08723 | Sovereign-os M047 Continuity Manager ZFS clone workspaces enable per-branch /ai-exchange/* | cross-ref M047 + dump 3556 | F04403 | non-negotiable | false | 10 |
| R08724 | Sovereign-os M050 Design Law "ZFS remembers" IS the Commit step's replay log | cross-ref M050 + dump 3572 | F04404 | non-negotiable | false | 10 |
| R08725 | Sovereign-os M054 Tool Interface 4-state pipeline traverses filesystem boundary | cross-ref M054 + dump 3550 | F04405 | non-negotiable | false | 10 |
| R08726 | Cross-repo binding — MS007 surface-manifest typed-mirror crate carries 3-dir + 5-field + 6-check schemas | cross-ref MS007 | F04406 | non-negotiable | false | 10 |
| R08727 | Test — MS020 L1 covers /ai-exchange/* schema rendering | cross-ref MS020 | F04407 | non-negotiable | false | 10 |
| R08728 | Test — MS020 L2 covers 6-step host import pipeline | cross-ref MS020 + dump 3566–3572 | F04408 | non-negotiable | false | 10 |
| R08729 | Test — MS020 L3 covers selfdefctl filesystem-boundary CLI | cross-ref MS020 | F04409 | non-negotiable | false | 10 |
| R08730 | Test — MS020 L4 covers seam between VM outbox + host policy-check | cross-ref MS020 + dump 3570 | F04410 | non-negotiable | false | 10 |
| R08731 | Test — MS020 L5 covers end-to-end VM PatchProposal → host commit lifecycle | cross-ref MS020 + dump 3473–3594 | F04411 | non-negotiable | false | 10 |
| R08732 | Operator UX — `selfdefctl fs-boundary status` | architecture + cross-ref MS011 | F04412 | non-negotiable | false | 10 |
| R08733 | Operator UX — `selfdefctl fs-boundary approve <proposal_id>` | architecture + M042 + M049 | F04413 | non-negotiable | false | 10 |
| R08734 | Operator UX — `selfdefctl fs-boundary reject <proposal_id>` | architecture + M049 | F04414 | non-negotiable | false | 10 |
| R08735 | Operator UX — `selfdefctl fs-boundary log` | architecture + cross-ref MS009 | F04415 | non-negotiable | false | 10 |
| R08736 | Operator UX — MS011 dashboard renders pending-proposals widget | cross-ref MS011 | F04416 | non-negotiable | false | 10 |
| R08737 | Hardware — /ai-exchange/* uses virtiofs DAX for low-latency exchange | dump 3461 + 3556 | F04417 | non-negotiable | false | 10 |
| R08738 | Hardware — large blobs go through /ai-exchange/artifacts (NOT vsock) | dump 3558 + cross-ref MS034 | F04418 | non-negotiable | false | 10 |
| R08739 | Hardware — small messages go through virtio-vsock (NOT /ai-exchange/*) | cross-ref MS034 + dump 3458 | F04419 | non-negotiable | false | 10 |
| R08740 | Cross-cycle — MS037 binds MS034 Communication Boundary 8-message-types with concrete filesystem exchange dirs | cross-ref MS034 + dump 3550 | F04420 | non-negotiable | false | 10 |
| R08741 | Cross-cycle — MS037 grounds MS035 capability_word filesystem-scope bits 8..15 with directory-level scope | cross-ref MS035 + dump 3497 | F04421 | non-negotiable | false | 10 |
| R08742 | Cross-cycle — MS037 grounds MS036 Tier A/B/C/D tool sandbox filesystem access patterns | cross-ref MS036 | F04422 | non-negotiable | false | 10 |
| R08743 | Cross-cycle — MS037 feeds MS038 Network boundary with parallel "explicit exchange" doctrine | cross-ref MS038 | F04423 | non-negotiable | false | 10 |
| R08744 | Cross-cycle — MS037 feeds MS039 7 authority levels by treating filesystem access as authority-graded | cross-ref MS039 | F04424 | non-negotiable | false | 10 |
| R08745 | Doctrine — explicit exchange directories = SAME PATTERN as MS035 capability tokens | dump 3508 + 3552 | F04425 | non-negotiable | false | 10 |
| R08746 | Doctrine — explicit exchange enables LEAST-PRIVILEGE for filesystem operations | dump 3552 + 3590 | F04426 | non-negotiable | false | 10 |
| R08747 | Doctrine — explicit exchange enables CAPABILITY-PASSING for filesystem operations | dump 3552 + cross-ref MS035 | F04427 | non-negotiable | false | 10 |
| R08748 | Doctrine — filesystem boundary REPLACES ambient filesystem authority with typed-authority-handles | dump 3552 + cross-ref MS035 | F04428 | non-negotiable | false | 10 |
| R08749 | Doctrine — "Same invariant again" — candidate→filter→verify→commit pattern from MS034 | cross-ref MS034 + dump 3566–3572 | F04429 | non-negotiable | false | 10 |
| R08750 | Operator references — virtiofs DAX mode docs | dump 3461 | F04430 | non-negotiable | false | 10 |
| R08751 | Operator references — `diff -u` unified diff format spec | dump 3580 | F04431 | non-negotiable | false | 10 |
| R08752 | Operator references — Linux mount-namespace docs | cross-ref M045 + dump 3552 | F04432 | non-negotiable | false | 10 |
| R08753 | Operator references — POSIX `realpath(3)` path-canonicalization | dump 3590 + architecture | F04433 | non-negotiable | false | 10 |
| R08754 | Operator references — OCI image-spec filesystem layout | architecture + dump 3552 | F04434 | non-negotiable | false | 10 |
| R08755 | Operator references — git apply / patch(1) for unified-diff application | dump 3580 + architecture | F04435 | non-negotiable | false | 10 |
| R08756 | Schema versioning — filesystem boundary schema_version "1.0.0" | architecture | F04436 | non-negotiable | false | 10 |
| R08757 | Schema versioning — 3-dir + 5-field patch schema STABLE across MAJOR versions | architecture | F04437 | non-negotiable | false | 10 |
| R08758 | Project-boundary — MS037 is selfdef IPS-side filesystem boundary; sovereign-os M048 Module 3 + M049 orchestrate at runtime | architecture | F04438 | non-negotiable | false | 10 |
| R08759 | Cross-repo binding — selfdef MS037 + sovereign-os M048 + M049 file-write + M042 user-approval + M044 ZFS = cross-repo filesystem-governance quartet | cross-ref M048 + M049 + M042 + M044 | F04439 | non-negotiable | false | 10 |
| R08760 | Per-step parse — output is structured AST | architecture + dump 3568 | F04359 | non-negotiable | false | 10 |
| R08761 | Per-step parse — invalid encoding rejects proposal | architecture + dump 3568 | F04360 | non-negotiable | false | 10 |
| R08762 | Per-step parse — schema mismatch rejects proposal | architecture + dump 3568 | F04360 | non-negotiable | false | 10 |
| R08763 | Per-step scan — sigma rules from /etc/selfdef/rules/ (MS025 sigma-correlator) | cross-ref MS025 + dump 3568 | F04361 | non-negotiable | false | 10 |
| R08764 | Per-step scan — yara rules optional | architecture + dump 3568 | F04362 | non-negotiable | false | 10 |
| R08765 | Per-step diff — file-path enumeration extracted | architecture + dump 3569 | F04363 | non-negotiable | false | 10 |
| R08766 | Per-step diff — per-file line count extracted | architecture + dump 3569 | F04363 | non-negotiable | false | 10 |
| R08767 | Per-step diff — per-file hunk count extracted | architecture + dump 3569 | F04363 | non-negotiable | false | 10 |
| R08768 | Per-step policy-check — 10-field Intent-Based Policy input populated | cross-ref M049 + dump 3570 | F04365 | non-negotiable | false | 10 |
| R08769 | Per-step policy-check — output PolicyDecision (allow/deny/ask/sandbox/escalate/snapshot/test) | cross-ref M049 + dump 3570 | F04365 | non-negotiable | false | 10 |
| R08770 | Per-step oracle-review — only invoked when risk_flags AND OR risk_class meets threshold | architecture + dump 3571 + MS036 | F04368 | non-negotiable | false | 10 |
| R08771 | Per-step oracle-review — Blackwell oracle reviews patch + tests + risk explanation | cross-ref M043 + dump 3571 | F04367 | non-negotiable | false | 10 |
| R08772 | Per-step commit — uses `git apply --index` or atomic file rename | architecture + dump 3572 | F04369 | non-negotiable | false | 10 |
| R08773 | Per-step commit — emits MS049 16-event taxonomy commit event | cross-ref M049 + dump 3572 | F04371 | non-negotiable | false | 10 |
| R08774 | Per-step commit — operator can rollback via M040 ZFS snapshot | cross-ref M040 + dump 3572 | F04370 | non-negotiable | false | 10 |
| R08775 | Patch field — unified diff format MUST match `diff -u` output exactly | dump 3580 + architecture | F04372 | non-negotiable | false | 10 |
| R08776 | Patch field — unified diff MAY include binary diffs (rejected at parse step) | dump 3580 + architecture | F04372 | non-negotiable | false | 10 |
| R08777 | Patch field — metadata MUST include profile field | architecture + cross-ref M042 | F04373 | non-negotiable | false | 10 |
| R08778 | Patch field — metadata MUST include trace_id field | architecture + cross-ref M049 | F04373 | non-negotiable | false | 10 |
| R08779 | Patch field — metadata MUST include capability_word field | architecture + cross-ref MS035 | F04373 | non-negotiable | false | 10 |
| R08780 | Patch field — metadata MUST include timestamp field | architecture | F04373 | non-negotiable | false | 10 |
| R08781 | Patch field — declared_files_touched MUST be a list of relative paths | dump 3582 + architecture | F04374 | non-negotiable | false | 10 |
| R08782 | Patch field — declared_files_touched MUST be canonical (no .. or symlink traversal) | dump 3582 + dump 3590 | F04374 | non-negotiable | false | 10 |
| R08783 | Patch field — declared_files_touched MUST equal set of files in unified diff | dump 3582 + 3591 | F04375 | non-negotiable | false | 10 |
| R08784 | Patch field — declared_files_touched mismatch rejects entire proposal | dump 3582 + 3591 | F04375 | non-negotiable | false | 10 |
| R08785 | Patch field — test notes are human-readable text | dump 3583 + architecture | F04376 | non-negotiable | false | 10 |
| R08786 | Patch field — test notes SHOULD include test commands run | dump 3583 + architecture | F04376 | non-negotiable | false | 10 |
| R08787 | Patch field — test notes SHOULD include test pass/fail counts | dump 3583 + architecture | F04376 | non-negotiable | false | 10 |
| R08788 | Patch field — risk_flags = bit field with named flags (exec_introduced / eval_introduced / network_introduced / fs_outside_workspace / secret_in_diff / etc.) | dump 3584 + architecture | F04377 | non-negotiable | false | 10 |
| R08789 | Patch field — risk_flags MAY include LLM-self-reported confidence | dump 3584 + architecture | F04377 | non-negotiable | false | 10 |
| R08790 | Predicate — workspace boundary uses absolute paths only (no relative paths) | dump 3590 + architecture | F04378 | non-negotiable | false | 10 |
| R08791 | Predicate — workspace boundary canonicalizes via realpath(3) BEFORE comparison | dump 3590 + architecture | F04378 | non-negotiable | false | 10 |
| R08792 | Predicate — workspace boundary REJECTS symlinks pointing outside workspace | dump 3590 + architecture | F04378 | non-negotiable | false | 10 |
| R08793 | Predicate — forbidden files include ~/.ssh/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08794 | Predicate — forbidden files include ~/.gnupg/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08795 | Predicate — forbidden files include ~/.aws/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08796 | Predicate — forbidden files include /etc/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08797 | Predicate — forbidden files include /usr/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08798 | Predicate — forbidden files include /var/* | dump 3591 + cross-ref MS019 | F04379 | non-negotiable | false | 10 |
| R08799 | Predicate — forbidden files include any path beginning with `/` (absolute system path) | dump 3591 + architecture | F04379 | non-negotiable | false | 10 |
| R08800 | Predicate — diff parse error rejects entire proposal | dump 3591 + architecture | F04380 | non-negotiable | false | 10 |
| R08801 | Predicate — diff with binary changes rejects entire proposal | dump 3591 + architecture | F04380 | non-negotiable | false | 10 |
| R08802 | Predicate — diff with hunk header errors rejects entire proposal | dump 3591 + architecture | F04380 | non-negotiable | false | 10 |
| R08803 | Predicate — diff that fails to apply (3-way merge conflict) rejects entire proposal | dump 3591 + architecture | F04380 | non-negotiable | false | 10 |
| R08804 | Predicate — policy allows writes via M049 PolicyDecision = allow OR sandbox-then-allow OR ask-then-allow | dump 3592 + cross-ref M049 | F04381 | non-negotiable | false | 10 |
| R08805 | Predicate — policy denies writes via M049 PolicyDecision = deny | dump 3592 + cross-ref M049 | F04381 | non-negotiable | false | 10 |
| R08806 | Predicate — policy require_snapshot triggers M040 ZFS snapshot before commit | dump 3592 + cross-ref M040 | F04381 | non-negotiable | false | 10 |
| R08807 | Predicate — policy require_test triggers test execution before commit | dump 3592 + cross-ref M037 | F04381 | non-negotiable | false | 10 |
| R08808 | Predicate — branch budget = MS022 SubscriberGuard token budget remaining | cross-ref MS022 + dump 3593 | F04382 | non-negotiable | false | 10 |
| R08809 | Predicate — branch budget exhaustion rejects proposal with "out of budget" error | cross-ref MS022 + dump 3593 | F04382 | non-negotiable | false | 10 |
| R08810 | Predicate — user approval via M049 ask outcome + M042 user-approval-state | cross-ref M042 + M049 + dump 3594 | F04383 | non-negotiable | false | 10 |
| R08811 | Predicate — user approval defaults to NO (deny if no response) | architecture + dump 3594 | F04383 | non-negotiable | false | 10 |
| R08812 | Predicate — user approval timeout configurable per profile (M042) | cross-ref M042 + architecture | F04383 | non-negotiable | false | 10 |
| R08813 | Operator UX — pending proposals list shows: trace_id, profile, declared_files, risk_flags, test_notes_summary | dump 3578–3584 + cross-ref MS011 | F04412 | non-negotiable | false | 10 |
| R08814 | Operator UX — approve action commits proposal AFTER predicates re-checked | dump 3588–3594 + cross-ref M049 | F04413 | non-negotiable | false | 10 |
| R08815 | Operator UX — reject action surfaces reason via M049 PolicyDecision.reason field | cross-ref M049 + dump 3592 | F04414 | non-negotiable | false | 10 |
| R08816 | Operator UX — log action shows ZFS-backed replay log (M044 + M050) | cross-ref M044 + M050 + dump 3572 | F04415 | non-negotiable | false | 10 |
| R08817 | Selfdef MS001 daemon hosts the filesystem-boundary engine | cross-ref MS001 + architecture | M00963 | non-negotiable | false | 10 |
| R08818 | Selfdef MS002 14-collector-fabric collects filesystem-boundary trace events | cross-ref MS002 + cross-ref M049 | M00964 | non-negotiable | false | 10 |
| R08819 | Selfdef MS003 correlator + store + responder + signing — selfdef-signing signs commit-step replay log entries | cross-ref MS003 + dump 3572 | F04393 | non-negotiable | false | 10 |
| R08820 | Selfdef MS004 14-notifier-integrations notify on filesystem-boundary policy violations | cross-ref MS004 + dump 3592 | M00964 | non-negotiable | false | 10 |
| R08821 | Selfdef MS005 notifier engine + orchestrator route filesystem-boundary events | cross-ref MS005 | M00964 | non-negotiable | false | 10 |
| R08822 | Selfdef MS006 14-functional-modules each declare exchange-dir mount preference | cross-ref MS006 + dump 3556 | M00942 | non-negotiable | false | 10 |
| R08823 | Selfdef MS009 audit cycles trace filesystem-boundary commit lineage | cross-ref MS009 + dump 3572 | F04415 | non-negotiable | false | 10 |
| R08824 | Selfdef MS010 hardware-tune-cache exposes virtiofs DAX availability | cross-ref MS010 + dump 3461 | F04417 | non-negotiable | false | 10 |
| R08825 | Selfdef MS011 operator dashboard renders pending-proposals widget + commit-history widget | cross-ref MS011 + dump 3588 + 3572 | F04412 + F04415 | non-negotiable | false | 10 |
| R08826 | Selfdef MS012 perimeter coexistence respects /ai-exchange/* mount perimeter | cross-ref MS012 + dump 3556 | M00942 | non-negotiable | false | 10 |
| R08827 | Selfdef MS014 SSH-wrap respects filesystem boundary for SSH-mediated file IO | cross-ref MS014 + dump 3552 | M00958 | non-negotiable | false | 10 |
| R08828 | Selfdef MS015 NATS messaging transports filesystem-boundary events between selfdef-daemon + VM | cross-ref MS015 + dump 3568 | M00946 | non-negotiable | false | 10 |
| R08829 | Selfdef MS018 VPN-bridge respects per-profile /ai-exchange/* mount | cross-ref MS018 + dump 3556 | M00942 | non-negotiable | false | 10 |
| R08830 | Selfdef MS019 threat model treats /ai-exchange/* traversal + symlink + race as 3 primary attack surfaces | cross-ref MS019 + dump 3590 | F04395 | non-negotiable | false | 10 |
| R08831 | Selfdef MS020 L1-L5 test harness covers 6-step host import + 6-check application predicate pipeline | cross-ref MS020 + dump 3566–3594 | F04408 + F04411 | non-negotiable | false | 10 |
| R08832 | Selfdef MS021 shared module-script lib v2 provides `fs_boundary_apply_patch` helper | cross-ref MS021 + architecture | M00963 | non-negotiable | false | 10 |
| R08833 | Selfdef MS022 SSE quota tracks per-branch file-write budget | cross-ref MS022 + dump 3593 | F04382 | non-negotiable | false | 10 |
| R08834 | Selfdef MS023 polarproxy applies filesystem-boundary policy to TLS-MITM traffic with file uploads | cross-ref MS023 + dump 3556 | M00942 | non-negotiable | false | 10 |
| R08835 | Selfdef MS024 bridge-l2 nftables ruleset blocks unauthorized filesystem-network calls | cross-ref MS024 + dump 3552 | M00958 | non-negotiable | false | 10 |
| R08836 | Selfdef MS025 detect-host event-bus transports filesystem-boundary events to sigma-correlator | cross-ref MS025 + dump 3568 | F04361 | non-negotiable | false | 10 |
| R08837 | Selfdef MS026 integrity-sentinel baselines /ai-exchange/* permissions + mount options | cross-ref MS026 + dump 3556 | F04389 | non-negotiable | false | 10 |
| R08838 | Selfdef MS027 observability dashboard renders `selfdef_fs_boundary_violations_total{file_class}` histogram | cross-ref MS027 + dump 3592 | F04390 | non-negotiable | false | 10 |
| R08839 | Selfdef MS028 bitnet-gpu-inference applies filesystem-boundary to model weight loads | cross-ref MS028 + dump 3558 | M00944 | non-negotiable | false | 10 |
| R08840 | Selfdef MS029 slm-cpu-loop applies filesystem-boundary to SLM model weight loads | cross-ref MS029 + dump 3558 | M00944 | non-negotiable | false | 10 |
| R08841 | Selfdef MS030 tensor-parallel applies filesystem-boundary to multi-GPU weight sharding | cross-ref MS030 + dump 3558 | M00944 | non-negotiable | false | 10 |
| R08842 | Selfdef MS031 wasm-aot-cache applies filesystem-boundary to .cwasm artifacts | cross-ref MS031 + dump 3558 | M00944 | non-negotiable | false | 10 |
| R08843 | Selfdef MS032 sandbox tier 1-9 catalog composes with filesystem-boundary 3-dir layout | cross-ref MS032 + dump 3556 | M00942 | non-negotiable | false | 10 |
| R08844 | Selfdef MS033 Phase 3 PolicyDecision object includes filesystem-boundary fields | cross-ref MS033 + dump 3570 | F04366 | non-negotiable | false | 10 |
| R08845 | Selfdef MS034 Communication Boundary 8-message-types use /ai-exchange/* for large blobs | cross-ref MS034 + dump 3558 | F04418 | non-negotiable | false | 10 |
| R08846 | Selfdef MS035 capability_word filesystem-scope bits 8..15 gate /ai-exchange/* access | cross-ref MS035 + dump 3497 | F04391 | non-negotiable | false | 10 |
| R08847 | Selfdef MS036 Tool Sandboxes 4-tier classification gates filesystem mount/permissions | cross-ref MS036 | F04392 | non-negotiable | false | 10 |
| R08848 | Cross-cycle — MS037 extends MS034 Communication Boundary 4-step pipeline with 6-step host-import pipeline | cross-ref MS034 + dump 3566–3572 | F04429 | non-negotiable | false | 10 |
| R08849 | Cross-cycle — MS037 extends MS035 capability_word with directory-level scope semantics | cross-ref MS035 + dump 3497 | F04421 | non-negotiable | false | 10 |
| R08850 | Cross-cycle — MS037 extends MS036 Tier A/B/C/D with concrete filesystem mount patterns | cross-ref MS036 | F04422 | non-negotiable | false | 10 |
| R08851 | Cross-cycle — MS037 PRECEDES MS038 Network boundary (parallel pattern) | cross-ref MS038 + dump 3596 | F04423 | non-negotiable | false | 10 |
| R08852 | Cross-cycle — MS037 PRECEDES MS039 7 authority levels (filesystem access as authority-graded) | cross-ref MS039 + dump 3590 | F04424 | non-negotiable | false | 10 |
| R08853 | Doctrine — explicit exchange dirs IS the typed-authority-handle pattern for filesystem | dump 3552 + 3508 (MS035) | F04425 | non-negotiable | false | 10 |
| R08854 | Doctrine — explicit exchange dirs ENABLE least-privilege filesystem operations | dump 3552 + 3590 | F04426 | non-negotiable | false | 10 |
| R08855 | Doctrine — explicit exchange dirs ENABLE capability-passing from parent to child operations | dump 3552 + cross-ref MS035 | F04427 | non-negotiable | false | 10 |
| R08856 | Doctrine — filesystem boundary REPLACES ambient process filesystem authority | dump 3552 + cross-ref MS035 | F04428 | non-negotiable | false | 10 |
| R08857 | Doctrine — filesystem boundary follows candidate→filter→verify→commit pattern | dump 3566–3572 + cross-ref MS034 | F04429 | non-negotiable | false | 10 |
| R08858 | Doctrine — every commit step MUST update M044 ZFS-backed replay log | cross-ref M044 + dump 3572 | F04371 | non-negotiable | false | 10 |
| R08859 | Doctrine — every commit step MUST emit M049 16-event taxonomy event | cross-ref M049 + dump 3572 | F04373 | non-negotiable | false | 10 |
| R08860 | Doctrine — every rejected proposal MUST emit OCSF Detection Finding class 2004 | cross-ref MS026 + dump 3591 | F04388 | non-negotiable | false | 10 |
| R08861 | Doctrine — every approved proposal MUST update memory/eval (M046 LoRA foundry pipeline) | cross-ref M046 + dump 3572 | F04402 | non-negotiable | false | 10 |
| R08862 | Doctrine — every commit step REVERSIBLE via M040 ZFS snapshot + M044 ZFS Storage Plane | cross-ref M040 + M044 + dump 3572 | F04370 | non-negotiable | false | 10 |
| R08863 | Doctrine — every commit step AUDITABLE via MS009 audit cycles | cross-ref MS009 + dump 3572 | F04415 | non-negotiable | false | 10 |
| R08864 | Doctrine — every commit step TRACEABLE to issuing capability_word | cross-ref MS035 + dump 3572 | F04373 | non-negotiable | false | 10 |
| R08865 | Doctrine — every commit step OBSERVABLE via MS027 observability dashboard | cross-ref MS027 + dump 3572 | F04416 | non-negotiable | false | 10 |
| R08866 | Doctrine — every commit step REPLAYABLE via M044 ZFS replay log | cross-ref M044 + dump 3572 | F04371 | non-negotiable | false | 10 |
| R08867 | Implementation phase — Phase 4 (Sandbox Execution) of M053 implements filesystem boundary | cross-ref M053 + MS032 | F04405 | non-negotiable | false | 10 |
| R08868 | Implementation phase — Phase 3 (Policy & Trace) of M053 implements policy-check step | cross-ref M053 + MS033 | F04365 | non-negotiable | false | 10 |
| R08869 | Implementation phase — Phase 7 (AVX-512 Cortex) of M053 optimizes path-canonicalization via SIMD | cross-ref M053 + dump 3590 + M051 | F04378 | non-negotiable | false | 10 |
| R08870 | Implementation phase — Phase 9 (Continuity) of M053 implements ZFS-backed replay log | cross-ref M053 + M044 + dump 3572 | F04371 | non-negotiable | false | 10 |
| R08871 | Implementation phase — Phase 10 (Full Cockpit) of M053 surfaces pending-proposals + commit-history widgets | cross-ref M053 + MS011 | F04416 | non-negotiable | false | 10 |
| R08872 | Operator approval timeout — defaults to 5 minutes; configurable per profile via M042 | architecture + cross-ref M042 | F04812 | non-negotiable | false | 10 |
| R08873 | Operator approval timeout — expired approval defaults to DENY (no implicit allow) | architecture + dump 3594 | F04811 | non-negotiable | false | 10 |
| R08874 | Operator approval surface — MS004 14-notifier-integrations push approval requests to ntfy/Signal/etc. | cross-ref MS004 + dump 3594 | F04413 | non-negotiable | false | 10 |
| R08875 | Operator approval surface — MS011 operator dashboard renders inline approve/reject buttons per proposal | cross-ref MS011 + dump 3594 | F04416 | non-negotiable | false | 10 |
| R08876 | Operator approval surface — CLI surface `selfdefctl fs-boundary approve <proposal_id>` mirrors dashboard action | architecture + dump 3594 | F04413 | non-negotiable | false | 10 |
| R08877 | Cross-repo composition — selfdef MS037 + sovereign-os M048 Module 3 + M049 Policy Fabric + M042 user-approval + M044 ZFS Storage Plane + M040 Hyper Feature 8 ZFS commit gate form the cross-repo filesystem-governance quintet | cross-ref M048 + M049 + M042 + M044 + M040 | F04439 | non-negotiable | false | 10 |
| R08878 | Cross-repo composition — selfdef MS037 + sovereign-os M046 LoRA foundry PatchProposal flow + M037 Spec/TDD evidence-driven autonomy form the cross-repo adapter-governance triple | cross-ref M046 + M037 + dump 3473 + 3580 | F04402 | non-negotiable | false | 10 |
| R08879 | Cross-repo composition — selfdef MS037 + sovereign-os M047 Continuity Manager + M048 Module 8 Continuity Manager + M040 Hyper Feature 8 ZFS commit gate form the cross-repo continuity quartet | cross-ref M047 + M048 + M040 + dump 3572 | F04403 | non-negotiable | false | 10 |
| R08880 | Composite — MS037 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Filesystem Boundary from dump 3550-3593: "Use explicit exchange directories" + 3-dir layout (/ai-exchange/inbox / /ai-exchange/outbox / /ai-exchange/artifacts) + doctrine "VM writes proposals, not final state" + 6-step host import pipeline (parse / scan / diff / policy-check / oracle-review if needed / commit) + 5-field code patch schema (unified diff / metadata / declared files touched / test notes / risk flags) + 6-check application predicates (paths inside workspace / no forbidden files / diff parses / policy allows writes / branch budget permits / user approval if required); cross-module enforcement via 35+ selfdef modules (MS001-MS036) + sovereign-os M040/M042/M044/M046/M047/M048/M049/M050/M054; cross-repo binding via MS007 surface-manifest typed-mirror crate publishing 3-dir + 5-field + 6-check schemas; filesystem boundary IS the IPS-side typed-authority-handle for filesystem operations | dump 3550–3593 + cross-ref MS007 + MS001-MS036 + M040-M054 | E0371-E0380 | non-negotiable | false | 10 |

## Cross-references

- Adjacent INDEX rows: MS036 Tool sandboxes / MS038 Network boundary
- Cross-cycle — MS037 + MS034 + MS035 + MS036 + MS038 form the IPS-side 5-boundary doctrine
- Cross-repo realization — sovereign-os M040 + M042 + M044 + M046 + M047 + M048 + M049 + M050 + M054 realize runtime-side orchestration
- Cross-repo binding — MS007 surface-manifest + audit-manifest typed-mirror crates carry 3-dir + 5-field + 6-check schemas
- Operator references: virtiofs DAX docs + `diff -u` unified diff spec + Linux mount-namespace docs + POSIX realpath(3) + OCI image-spec + git apply / patch(1)
- Doctrine — filesystem boundary IS the IPS-side typed-authority-handle for filesystem operations; complements MS035 capability_word and MS032 sandbox tiers
