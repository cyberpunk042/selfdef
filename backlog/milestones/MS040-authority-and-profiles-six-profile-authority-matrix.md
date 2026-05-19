# MS040 — Authority-and-profiles — six-profile authority matrix — IPS-side projection

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 17468-17500 (Authority And Profiles — six profile authority envelopes: private / fast / careful / autonomous / experimental / production) + The Key Rule "Authority follows evidence" (dump 17501-17517) + check ladder (valid schema / safe policy / successful sandbox / tests pass / oracle agrees / user approves)
**Cross-repo mirror**: sovereign-os M042 (canonical choice-architecture sovereignty-as-policy-composable) + M056 (canonical authority model) — selfdef receives this canon through MS007 typed mirrors only
**Project boundary**: this milestone catalogs ONLY how the IPS daemon scopes each profile's allowable authority levels for its OWN mutations; profile selection + policy composition live in sovereign-os M042

## Projection statement

> "Different profiles allow different maximum levels." (dump 17274)

> "Authority follows evidence." (dump 17501)

The IPS daemon enforces six profile-specific authority envelopes against its own boundary-mutation surface (MS034-MS038): every L4 active filter, L5 ruleset commit, L6 manifest persistence must lie within the active profile's maximum authority level. The six profiles (private / fast / careful / autonomous / experimental / production) each clip the L0..L6 ladder differently. This milestone catalogs that matrix, the evidence-ladder that promotes a branch within the envelope, and the IPS-side wiring that observes/enforces it.

## Epics (E0401-E0410)

| epic | name | source |
|---|---|---|
| E0401 | Profile `private` — max authority local observe/suggest unless approved | dump 17470-17472 |
| E0402 | Profile `fast` — bounded execute for safe tools | dump 17473-17475 |
| E0403 | Profile `careful` — oracle/test gates before commit | dump 17476-17478 |
| E0404 | Profile `autonomous` — execute bounded tasks, commit only after predeclared gates | dump 17479-17481 |
| E0405 | Profile `experimental` — high exploration authority inside sandbox, zero host commit | dump 17482-17484 |
| E0406 | Profile `production` — strict commit gates, strong trace, rollback required | dump 17485-17487 |
| E0407 | Evidence ladder — valid schema → safe policy → successful sandbox → tests pass → oracle agrees → user approves | dump 17501-17517 |
| E0408 | Profile-bound authority FSM — same L0..L6 ladder, six different clips | architecture + dump 17468-17500 |
| E0409 | Profile transition — switching profile re-clips active grants + capability tokens | architecture + cross-ref MS035 |
| E0410 | Profile audit — every authority decision records active profile in M049 trace span | cross-ref M049 + MS039 |

## Modules (M01019-M01044)

| module | name | source |
|---|---|---|
| M01019 | selfdef-profile-private-envelope | dump 17470-17472 |
| M01020 | selfdef-profile-fast-envelope | dump 17473-17475 |
| M01021 | selfdef-profile-careful-envelope | dump 17476-17478 |
| M01022 | selfdef-profile-autonomous-envelope | dump 17479-17481 |
| M01023 | selfdef-profile-experimental-envelope | dump 17482-17484 |
| M01024 | selfdef-profile-production-envelope | dump 17485-17487 |
| M01025 | selfdef-profile-active-resolver | cross-ref M048 + dump 17468 |
| M01026 | selfdef-profile-transition-coordinator | architecture + cross-ref MS035 |
| M01027 | selfdef-profile-grant-re-clipper | cross-ref MS038 + MS037 + MS035 |
| M01028 | selfdef-profile-cap-token-re-clipper | cross-ref MS035 |
| M01029 | selfdef-profile-audit-emitter | cross-ref M049 + MS039 |
| M01030 | selfdef-evidence-check-1-valid-schema | dump 17506 + cross-ref MS003 |
| M01031 | selfdef-evidence-check-2-safe-policy | dump 17507 + cross-ref MS033 |
| M01032 | selfdef-evidence-check-3-successful-sandbox | dump 17508 + cross-ref MS032 |
| M01033 | selfdef-evidence-check-4-tests-pass | dump 17509 + cross-ref MS009 |
| M01034 | selfdef-evidence-check-5-oracle-agrees | dump 17510 + cross-ref M048 |
| M01035 | selfdef-evidence-check-6-user-approves | dump 17511 + cross-ref MS007 |
| M01036 | selfdef-evidence-aggregator | architecture + dump 17501-17517 |
| M01037 | selfdef-evidence-digest-signer | cross-ref MS003 |
| M01038 | selfdef-profile-config-loader | architecture |
| M01039 | selfdef-profile-config-validator | cross-ref MS003 + architecture |
| M01040 | selfdef-profile-default-resolver | architecture |
| M01041 | selfdef-profile-override-policy | cross-ref MS033 |
| M01042 | selfdef-profile-typed-mirror | cross-ref MS007 |
| M01043 | selfdef-profile-fsm-bridge | cross-ref MS039 |
| M01044 | selfdef-profile-replay-validator | cross-ref MS009 |

## Features (F04681-F04800)

| feature | name | source |
|---|---|---|
| F04681 | Private profile — max L1 Suggest unless operator approves explicit promotion | dump 17470-17472 |
| F04682 | Private profile — no L4 Execute without explicit operator approval | dump 17470-17472 |
| F04683 | Private profile — no L5 Commit without explicit operator approval | dump 17470-17472 |
| F04684 | Private profile — no L6 Persist without explicit operator approval | dump 17470-17472 |
| F04685 | Private profile — local-only enforcement, no Ring 4 grants | dump 17470-17472 + cross-ref MS039 |
| F04686 | Private profile — strict memory exposure rules (cross-ref M042 user choices) | cross-ref M042 |
| F04687 | Private profile — capability tokens never carry trust_ring `>=` 3 | cross-ref MS035 + MS039 |
| F04688 | Private profile — default for new operator sessions | architecture + dump 17468 |
| F04689 | Private profile — selectable via dashboard surface | cross-ref MS007 |
| F04690 | Private profile — every promotion logged via M049 trace | cross-ref M049 |
| F04691 | Fast profile — bounded L4 Execute for safe tools | dump 17473-17475 |
| F04692 | Fast profile — "safe tools" = tools in MS036 Tier A (deterministic host) | cross-ref MS036 |
| F04693 | Fast profile — no L5 Commit without TTL + trace | dump 17473-17475 + cross-ref MS038 |
| F04694 | Fast profile — no L6 Persist | dump 17473-17475 |
| F04695 | Fast profile — favors latency over correctness (cross-ref M058 fast scheduling) | cross-ref M058 |
| F04696 | Fast profile — capability tokens may carry trust_ring up to 2 | cross-ref MS035 + MS039 |
| F04697 | Fast profile — TTL grants default 60s | cross-ref MS038 |
| F04698 | Fast profile — emits OCSF Audit Activity class 1003 on every L4 grant | cross-ref MS026 |
| F04699 | Fast profile — selectable via dashboard surface | cross-ref MS007 |
| F04700 | Fast profile — autorevert L4 grants on policy bus revoke | cross-ref MS033 |
| F04701 | Careful profile — oracle gate required before L5 Commit | dump 17476-17478 |
| F04702 | Careful profile — test gate required before L5 Commit | dump 17476-17478 |
| F04703 | Careful profile — oracle = sovereign-os Blackwell oracle (cross-ref M058) | cross-ref M058 + cross-ref M048 |
| F04704 | Careful profile — tests = MS009 audit cycle pass | cross-ref MS009 |
| F04705 | Careful profile — L4 grants require sandbox simulation pass first | cross-ref MS032 |
| F04706 | Careful profile — L6 Persist requires double-gate (oracle + operator + snapshot) | cross-ref MS037 |
| F04707 | Careful profile — capability tokens carry evidence_digest field non-empty | cross-ref MS035 + MS039 |
| F04708 | Careful profile — emits OCSF Audit class 1003 + Detection 2004 on gate failure | cross-ref MS026 |
| F04709 | Careful profile — selectable via dashboard surface | cross-ref MS007 |
| F04710 | Careful profile — L5 Commit rollback automatic on verification failure | cross-ref MS039 |
| F04711 | Autonomous profile — execute bounded tasks within predeclared gates | dump 17479-17481 |
| F04712 | Autonomous profile — predeclared gates encoded in /etc/selfdef/profiles/autonomous-gates.toml | architecture + dump 17479 |
| F04713 | Autonomous profile — gates include allowed-paths, allowed-domains, allowed-tools, max-TTL | architecture |
| F04714 | Autonomous profile — gates signed via MS003 selfdef-signing | cross-ref MS003 |
| F04715 | Autonomous profile — L5 Commit allowed only within predeclared gate envelope | dump 17479-17481 |
| F04716 | Autonomous profile — L6 Persist requires oracle + operator (still) | dump 17415-17421 |
| F04717 | Autonomous profile — gate violations halt all autonomous activity | architecture + dump 17479-17481 |
| F04718 | Autonomous profile — emits OCSF Audit Activity class 1003 on every gate evaluation | cross-ref MS026 |
| F04719 | Autonomous profile — gate budget exhaustion halts new tasks | architecture |
| F04720 | Autonomous profile — supports M047 CRIU hibernation + ZFS continuity (cross-ref M047) | cross-ref M047 |
| F04721 | Experimental profile — high exploration authority inside sandbox | dump 17482-17484 |
| F04722 | Experimental profile — zero host commit (no L5 / no L6) | dump 17482-17484 |
| F04723 | Experimental profile — sandbox = MS036 Tier C (VM) or Tier D (disposable microVM) | cross-ref MS036 |
| F04724 | Experimental profile — outputs marked exposure-tainted at boundary | cross-ref MS037 + MS039 |
| F04725 | Experimental profile — capability tokens never carry authority_level `>=` 5 | cross-ref MS035 + MS039 |
| F04726 | Experimental profile — Ring 3 placement default | cross-ref MS039 |
| F04727 | Experimental profile — emits OCSF Detection Finding class 2004 on cross-ring breach | cross-ref MS026 |
| F04728 | Experimental profile — selectable via dashboard surface | cross-ref MS007 |
| F04729 | Experimental profile — branches must be promoted explicitly to enter Careful/Production | architecture + dump 17302 |
| F04730 | Experimental profile — promotion artifact signed via MS003 | cross-ref MS003 |
| F04731 | Production profile — strict commit gates | dump 17485-17487 |
| F04732 | Production profile — strong trace (M049 13-field span on every event) | cross-ref M049 |
| F04733 | Production profile — rollback required (signed revert artifact present) | cross-ref MS003 + cross-ref MS039 |
| F04734 | Production profile — L4 grants short TTL (max 600s without re-approval) | cross-ref MS038 |
| F04735 | Production profile — L5 Commit requires triple-gate (test + oracle + operator) | cross-ref MS009 + MS048 + MS007 |
| F04736 | Production profile — L6 Persist requires quadruple-gate (test + oracle + operator + snapshot) | cross-ref MS037 |
| F04737 | Production profile — capability tokens never carry trust_ring `>=` 4 | cross-ref MS035 + MS039 |
| F04738 | Production profile — low-variance enforcement (cross-ref M058 production scheduling) | cross-ref M058 |
| F04739 | Production profile — emits OCSF Audit + Detection + Config Change on every L5/L6 | cross-ref MS026 |
| F04740 | Production profile — autoreverts on any chain-break (cross-ref MS009 replay validator) | cross-ref MS009 + MS039 |
| F04741 | Evidence check 1 — valid schema (CBOR + MS003 signature) | dump 17506 + cross-ref MS003 |
| F04742 | Evidence check 2 — safe policy (policy bus approval) | dump 17507 + cross-ref MS033 |
| F04743 | Evidence check 3 — successful sandbox (MS032 simulation pass) | dump 17508 + cross-ref MS032 |
| F04744 | Evidence check 4 — tests pass (MS009 audit cycle green) | dump 17509 + cross-ref MS009 |
| F04745 | Evidence check 5 — oracle agrees (sovereign-os Blackwell verification) | dump 17510 + cross-ref M058 |
| F04746 | Evidence check 6 — user approves (operator dashboard approval signal) | dump 17511 + cross-ref MS007 |
| F04747 | Evidence aggregator — collects check 1..6 results into evidence bundle | architecture + dump 17501-17517 |
| F04748 | Evidence aggregator — bundle CBOR-encoded + MS003-signed | cross-ref MS003 |
| F04749 | Evidence aggregator — bundle includes timestamp + active profile + actor | architecture |
| F04750 | Evidence aggregator — bundle stored under /var/lib/selfdef/evidence/profile-bundles/ | architecture |
| F04751 | Profile resolver — reads /etc/selfdef/profile.toml at boot | architecture |
| F04752 | Profile resolver — reads dashboard-selected profile at runtime | cross-ref MS007 |
| F04753 | Profile resolver — never auto-promotes profile beyond user selection | architecture + dump 17249 |
| F04754 | Profile resolver — emits trace event on profile change | cross-ref M049 |
| F04755 | Profile resolver — falls back to private profile on resolver failure | architecture |
| F04756 | Profile transition coordinator — re-clips active L4 grants on profile change | architecture + cross-ref MS038 |
| F04757 | Profile transition coordinator — re-clips active L5 commits (revokes if outside new envelope) | architecture + cross-ref MS039 |
| F04758 | Profile transition coordinator — re-clips capability tokens (revokes if outside new envelope) | cross-ref MS035 |
| F04759 | Profile transition coordinator — emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04760 | Profile transition coordinator — re-clip operation is atomic | architecture |
| F04761 | Profile config loader — TOML format under /etc/selfdef/profiles/*.toml | architecture |
| F04762 | Profile config loader — validates schema via MS003 typed schema | cross-ref MS003 |
| F04763 | Profile config loader — rejects unknown profile names | architecture |
| F04764 | Profile config loader — supports operator-defined custom profiles (extension) | architecture |
| F04765 | Profile config loader — custom profiles inherit from one of six base profiles | architecture |
| F04766 | Profile audit emitter — emits M049 13-field span on every authority decision | cross-ref M049 |
| F04767 | Profile audit emitter — span includes active profile name | cross-ref M049 + dump 17468 |
| F04768 | Profile audit emitter — span includes target authority level | cross-ref M049 + cross-ref MS039 |
| F04769 | Profile audit emitter — span includes evidence bundle reference | architecture + cross-ref MS003 |
| F04770 | Profile audit emitter — span deterministic for MS009 replay | cross-ref MS009 |
| F04771 | Profile typed-mirror — published under MS007 8/8 SATURATED scheme | cross-ref MS007 |
| F04772 | Profile typed-mirror — Profile enum (Private / Fast / Careful / Autonomous / Experimental / Production) | cross-ref MS007 + dump 17468-17487 |
| F04773 | Profile typed-mirror — AuthorityEnvelope struct (profile, max_level, gates, ring_clip) | cross-ref MS007 |
| F04774 | Profile typed-mirror — EvidenceBundle struct (checks_passed, digest, signature) | cross-ref MS007 + dump 17501-17517 |
| F04775 | Profile typed-mirror — Rust crate selfdef-profile-mirror | cross-ref MS007 |
| F04776 | Profile FSM bridge — re-uses MS039 authority FSM with envelope mask | cross-ref MS039 |
| F04777 | Profile FSM bridge — illegal transition rejected (e.g. Private → L4 without approval) | cross-ref MS039 + dump 17470 |
| F04778 | Profile FSM bridge — transition emits trace event | cross-ref M049 |
| F04779 | Profile FSM bridge — transitions signed via MS003 | cross-ref MS003 |
| F04780 | Profile FSM bridge — transitions retained 100 days | cross-ref MS037 |
| F04781 | Profile replay validator — verifies historical profile-decision chain | cross-ref MS009 |
| F04782 | Profile replay validator — detects unauthorized profile escalations | cross-ref MS009 + cross-ref MS003 |
| F04783 | Profile replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 |
| F04784 | Profile replay validator — runs daily | cross-ref MS009 |
| F04785 | Profile replay validator — failures halt all L5/L6 activity | architecture |
| F04786 | Profile override policy — overrides require operator signature | cross-ref MS003 |
| F04787 | Profile override policy — overrides time-bounded (max 24h) | cross-ref MS038 |
| F04788 | Profile override policy — overrides logged via M049 | cross-ref M049 |
| F04789 | Profile override policy — overrides composable with policy bus decisions | cross-ref MS033 |
| F04790 | Profile override policy — emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04791 | Profile default resolver — returns Private if no explicit selection | architecture + dump 17468 |
| F04792 | Profile default resolver — returns operator-chosen default if set | architecture |
| F04793 | Profile default resolver — never returns Production by default | architecture |
| F04794 | Profile default resolver — never returns Autonomous by default | architecture |
| F04795 | Profile default resolver — defaults can be operator-overridden per session | architecture |
| F04796 | Six profiles - cumulative coverage of dump 17468-17487 (every line referenced) | dump 17468-17487 |
| F04797 | Six profiles - "the same request can schedule differently" (dump 18036 cross-ref) | dump 18036 + cross-ref M058 |
| F04798 | Six profiles - integrate with M058 hardware-aware scheduler routing | cross-ref M058 |
| F04799 | Six profiles - integrate with M057 12-step lifecycle (profile carried per step) | cross-ref M057 |
| F04800 | Six profiles - integrate with M042 choice architecture (profile = composable policy) | cross-ref M042 |

## Requirements (R09361-R09600)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R09361 | Doctrinal — different profiles allow different maximum authority levels | dump 17274 | F04681 | non-negotiable | false | 10 |
| R09362 | Doctrinal — authority follows evidence | dump 17501 | F04741 | non-negotiable | false | 10 |
| R09363 | Doctrinal — branch earns more authority by passing checks | dump 17503-17510 | F04747 | non-negotiable | false | 10 |
| R09364 | Doctrinal — capable because authority is granular | dump 17524 | F04776 | non-negotiable | false | 10 |
| R09365 | Doctrinal — safe because authority is earned and observable | dump 17525 | F04766 | non-negotiable | false | 10 |
| R09366 | Private profile — max authority level = L1 Suggest unless approved | dump 17470-17472 | F04681 | non-negotiable | false | 10 |
| R09367 | Private profile — no L2 Simulate without approval | dump 17470-17472 | F04681 | non-negotiable | false | 10 |
| R09368 | Private profile — no L3 Prepare without approval | dump 17470-17472 | F04681 | non-negotiable | false | 10 |
| R09369 | Private profile — no L4 Execute without explicit operator approval | dump 17470-17472 | F04682 | non-negotiable | false | 10 |
| R09370 | Private profile — no L5 Commit without explicit operator approval | dump 17470-17472 | F04683 | non-negotiable | false | 10 |
| R09371 | Private profile — no L6 Persist without explicit operator approval | dump 17470-17472 | F04684 | non-negotiable | false | 10 |
| R09372 | Private profile — local-only enforcement (no Ring 4 grants) | dump 17470-17472 + cross-ref MS039 | F04685 | non-negotiable | false | 10 |
| R09373 | Private profile — strict memory exposure rules | cross-ref M042 | F04686 | non-negotiable | false | 10 |
| R09374 | Private profile — capability tokens never carry trust_ring `>=` 3 | cross-ref MS035 + MS039 | F04687 | non-negotiable | false | 10 |
| R09375 | Private profile — default for new operator sessions | architecture | F04688 | non-negotiable | false | 10 |
| R09376 | Private profile — selectable via dashboard surface | cross-ref MS007 | F04689 | non-negotiable | false | 10 |
| R09377 | Private profile — every promotion logged via M049 trace | cross-ref M049 | F04690 | non-negotiable | false | 10 |
| R09378 | Private profile — promotion signed via MS003 | cross-ref MS003 | F04786 | non-negotiable | false | 10 |
| R09379 | Private profile — promotion time-bounded (max 24h) | cross-ref MS038 | F04787 | non-negotiable | false | 10 |
| R09380 | Private profile — promotion emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04790 | non-negotiable | false | 10 |
| R09381 | Fast profile — bounded L4 Execute for safe tools | dump 17473-17475 | F04691 | non-negotiable | false | 10 |
| R09382 | Fast profile — "safe tools" = MS036 Tier A (deterministic host) | cross-ref MS036 | F04692 | non-negotiable | false | 10 |
| R09383 | Fast profile — L4 grants require TTL | dump 17473-17475 + cross-ref MS038 | F04693 | non-negotiable | false | 10 |
| R09384 | Fast profile — L4 grants require trace | cross-ref M049 | F04693 | non-negotiable | false | 10 |
| R09385 | Fast profile — no L5 Commit without TTL + trace + actor field | dump 17473 + dump 17396-17402 | F04693 | non-negotiable | false | 10 |
| R09386 | Fast profile — no L6 Persist allowed | dump 17473-17475 | F04694 | non-negotiable | false | 10 |
| R09387 | Fast profile — favors latency over correctness | cross-ref M058 | F04695 | non-negotiable | false | 10 |
| R09388 | Fast profile — capability tokens may carry trust_ring up to 2 | cross-ref MS035 + MS039 | F04696 | non-negotiable | false | 10 |
| R09389 | Fast profile — TTL grants default 60s | cross-ref MS038 | F04697 | non-negotiable | false | 10 |
| R09390 | Fast profile — TTL grants maximum 3600s without operator approval | cross-ref MS038 | F04697 | non-negotiable | false | 10 |
| R09391 | Fast profile — emits OCSF Audit Activity class 1003 on every L4 grant | cross-ref MS026 | F04698 | non-negotiable | false | 10 |
| R09392 | Fast profile — selectable via dashboard surface | cross-ref MS007 | F04699 | non-negotiable | false | 10 |
| R09393 | Fast profile — autorevert L4 grants on policy bus revoke | cross-ref MS033 | F04700 | non-negotiable | false | 10 |
| R09394 | Fast profile — autorevert L4 grants on TTL expiry | cross-ref MS038 | F04700 | non-negotiable | false | 10 |
| R09395 | Fast profile — autorevert L4 grants on profile transition | architecture | F04756 | non-negotiable | false | 10 |
| R09396 | Careful profile — oracle gate required before L5 Commit | dump 17476-17478 | F04701 | non-negotiable | false | 10 |
| R09397 | Careful profile — test gate required before L5 Commit | dump 17476-17478 | F04702 | non-negotiable | false | 10 |
| R09398 | Careful profile — oracle = sovereign-os Blackwell oracle | cross-ref M058 | F04703 | non-negotiable | false | 10 |
| R09399 | Careful profile — tests = MS009 audit cycle pass | cross-ref MS009 | F04704 | non-negotiable | false | 10 |
| R09400 | Careful profile — L4 grants require sandbox simulation pass first | cross-ref MS032 | F04705 | non-negotiable | false | 10 |
| R09401 | Careful profile — L6 Persist requires double-gate (oracle + operator + snapshot) | cross-ref MS037 + dump 17415-17421 | F04706 | non-negotiable | false | 10 |
| R09402 | Careful profile — capability tokens carry evidence_digest field non-empty | cross-ref MS035 + MS039 | F04707 | non-negotiable | false | 10 |
| R09403 | Careful profile — emits OCSF Audit class 1003 on every gate evaluation | cross-ref MS026 | F04708 | non-negotiable | false | 10 |
| R09404 | Careful profile — emits OCSF Detection Finding class 2004 on gate failure | cross-ref MS026 | F04708 | non-negotiable | false | 10 |
| R09405 | Careful profile — selectable via dashboard surface | cross-ref MS007 | F04709 | non-negotiable | false | 10 |
| R09406 | Careful profile — L5 Commit rollback automatic on verification failure | cross-ref MS039 | F04710 | non-negotiable | false | 10 |
| R09407 | Careful profile — gate timeout default 24h then auto-deny | cross-ref MS039 | F04702 | non-negotiable | false | 10 |
| R09408 | Careful profile — gate evidence retained 100 days | cross-ref MS037 + cross-ref MS039 | F04748 | non-negotiable | false | 10 |
| R09409 | Careful profile — gate evidence indexed by trace-id | cross-ref M049 | F04748 | non-negotiable | false | 10 |
| R09410 | Careful profile — gate evidence indexed by actor | architecture | F04748 | non-negotiable | false | 10 |
| R09411 | Autonomous profile — execute bounded tasks within predeclared gates | dump 17479-17481 | F04711 | non-negotiable | false | 10 |
| R09412 | Autonomous profile — predeclared gates in /etc/selfdef/profiles/autonomous-gates.toml | architecture | F04712 | non-negotiable | false | 10 |
| R09413 | Autonomous profile — gates include allowed-paths list | architecture | F04713 | non-negotiable | false | 10 |
| R09414 | Autonomous profile — gates include allowed-domains list | architecture + cross-ref MS038 | F04713 | non-negotiable | false | 10 |
| R09415 | Autonomous profile — gates include allowed-tools list | architecture + cross-ref MS036 | F04713 | non-negotiable | false | 10 |
| R09416 | Autonomous profile — gates include max-TTL per category | architecture + cross-ref MS038 | F04713 | non-negotiable | false | 10 |
| R09417 | Autonomous profile — gates signed via MS003 selfdef-signing | cross-ref MS003 | F04714 | non-negotiable | false | 10 |
| R09418 | Autonomous profile — L5 Commit allowed only within predeclared gate envelope | dump 17479-17481 | F04715 | non-negotiable | false | 10 |
| R09419 | Autonomous profile — L6 Persist requires oracle + operator (still) | dump 17415-17421 | F04716 | non-negotiable | false | 10 |
| R09420 | Autonomous profile — gate violation halts all autonomous activity | architecture + dump 17479-17481 | F04717 | non-negotiable | false | 10 |
| R09421 | Autonomous profile — gate violation emits OCSF Detection Finding class 2004 | cross-ref MS026 | F04717 | non-negotiable | false | 10 |
| R09422 | Autonomous profile — emits OCSF Audit Activity class 1003 on every gate evaluation | cross-ref MS026 | F04718 | non-negotiable | false | 10 |
| R09423 | Autonomous profile — gate budget exhaustion halts new tasks | architecture | F04719 | non-negotiable | false | 10 |
| R09424 | Autonomous profile — supports M047 CRIU hibernation | cross-ref M047 | F04720 | non-negotiable | false | 10 |
| R09425 | Autonomous profile — supports ZFS continuity | cross-ref M047 | F04720 | non-negotiable | false | 10 |
| R09426 | Autonomous profile — preserves continuity across resume (M057 step 12) | cross-ref M057 | F04720 | non-negotiable | false | 10 |
| R09427 | Autonomous profile — batches approvals (cross-ref M058 autonomous policy) | cross-ref M058 | F04711 | non-negotiable | false | 10 |
| R09428 | Autonomous profile — checkpoint often (cross-ref M058 autonomous policy) | cross-ref M058 | F04711 | non-negotiable | false | 10 |
| R09429 | Autonomous profile — sandbox-first (cross-ref M058 autonomous policy) | cross-ref M058 | F04711 | non-negotiable | false | 10 |
| R09430 | Autonomous profile — selectable via dashboard surface | cross-ref MS007 | F04711 | non-negotiable | false | 10 |
| R09431 | Experimental profile — high exploration authority inside sandbox | dump 17482-17484 | F04721 | non-negotiable | false | 10 |
| R09432 | Experimental profile — zero host commit (no L5) | dump 17482-17484 | F04722 | non-negotiable | false | 10 |
| R09433 | Experimental profile — zero host commit (no L6) | dump 17482-17484 | F04722 | non-negotiable | false | 10 |
| R09434 | Experimental profile — sandbox = MS036 Tier C (VM) or Tier D (disposable microVM) | cross-ref MS036 | F04723 | non-negotiable | false | 10 |
| R09435 | Experimental profile — outputs marked exposure-tainted at boundary | cross-ref MS037 + MS039 | F04724 | non-negotiable | false | 10 |
| R09436 | Experimental profile — capability tokens never carry authority_level `>=` 5 | cross-ref MS035 + MS039 | F04725 | non-negotiable | false | 10 |
| R09437 | Experimental profile — Ring 3 placement default | cross-ref MS039 | F04726 | non-negotiable | false | 10 |
| R09438 | Experimental profile — emits OCSF Detection Finding class 2004 on cross-ring breach | cross-ref MS026 | F04727 | non-negotiable | false | 10 |
| R09439 | Experimental profile — selectable via dashboard surface | cross-ref MS007 | F04728 | non-negotiable | false | 10 |
| R09440 | Experimental profile — branches must be promoted explicitly to Careful or Production | dump 17302 | F04729 | non-negotiable | false | 10 |
| R09441 | Experimental profile — promotion artifact signed via MS003 | cross-ref MS003 | F04730 | non-negotiable | false | 10 |
| R09442 | Experimental profile — wide branch search (cross-ref M058 experimental policy) | cross-ref M058 | F04721 | non-negotiable | false | 10 |
| R09443 | Experimental profile — sandbox-only routing (cross-ref M058) | cross-ref M058 | F04722 | non-negotiable | false | 10 |
| R09444 | Experimental profile — no host commit by routing (cross-ref M058) | cross-ref M058 | F04722 | non-negotiable | false | 10 |
| R09445 | Experimental profile — emits trace event on every branch exploration | cross-ref M049 | F04727 | non-negotiable | false | 10 |
| R09446 | Production profile — strict commit gates | dump 17485-17487 | F04731 | non-negotiable | false | 10 |
| R09447 | Production profile — strong trace (M049 13-field span on every event) | cross-ref M049 | F04732 | non-negotiable | false | 10 |
| R09448 | Production profile — rollback required (signed revert artifact present) | cross-ref MS003 + MS039 | F04733 | non-negotiable | false | 10 |
| R09449 | Production profile — L4 grants short TTL (max 600s without re-approval) | cross-ref MS038 | F04734 | non-negotiable | false | 10 |
| R09450 | Production profile — L5 Commit requires triple-gate test | cross-ref MS009 | F04735 | non-negotiable | false | 10 |
| R09451 | Production profile — L5 Commit requires triple-gate oracle | cross-ref M058 | F04735 | non-negotiable | false | 10 |
| R09452 | Production profile — L5 Commit requires triple-gate operator | cross-ref MS007 | F04735 | non-negotiable | false | 10 |
| R09453 | Production profile — L6 Persist requires quadruple-gate (test + oracle + operator + snapshot) | cross-ref MS037 | F04736 | non-negotiable | false | 10 |
| R09454 | Production profile — capability tokens never carry trust_ring `>=` 4 | cross-ref MS035 + MS039 | F04737 | non-negotiable | false | 10 |
| R09455 | Production profile — low-variance enforcement | cross-ref M058 | F04738 | non-negotiable | false | 10 |
| R09456 | Production profile — emits OCSF Audit Activity class 1003 on every L5/L6 | cross-ref MS026 | F04739 | non-negotiable | false | 10 |
| R09457 | Production profile — emits OCSF Detection Finding class 2004 on any gate failure | cross-ref MS026 | F04739 | non-negotiable | false | 10 |
| R09458 | Production profile — emits OCSF Configuration Change class 5001 on every L5/L6 | cross-ref MS026 | F04739 | non-negotiable | false | 10 |
| R09459 | Production profile — autoreverts on chain-break detection | cross-ref MS009 + MS039 | F04740 | non-negotiable | false | 10 |
| R09460 | Production profile — selectable via dashboard surface (gated by operator confirmation) | cross-ref MS007 | F04731 | non-negotiable | false | 10 |
| R09461 | Evidence check 1 — valid schema (CBOR + MS003 signature) | dump 17506 + cross-ref MS003 | F04741 | non-negotiable | false | 10 |
| R09462 | Evidence check 1 — schema digest verified against typed-schema registry | cross-ref MS003 | F04741 | non-negotiable | false | 10 |
| R09463 | Evidence check 1 — failure halts authority promotion | architecture | F04741 | non-negotiable | false | 10 |
| R09464 | Evidence check 2 — safe policy (policy bus approval) | dump 17507 + cross-ref MS033 | F04742 | non-negotiable | false | 10 |
| R09465 | Evidence check 2 — policy bus decision signed via MS003 | cross-ref MS003 + cross-ref MS033 | F04742 | non-negotiable | false | 10 |
| R09466 | Evidence check 2 — failure halts authority promotion | architecture | F04742 | non-negotiable | false | 10 |
| R09467 | Evidence check 3 — successful sandbox (MS032 simulation pass) | dump 17508 + cross-ref MS032 | F04743 | non-negotiable | false | 10 |
| R09468 | Evidence check 3 — sandbox digest cited in evidence bundle | cross-ref MS003 + cross-ref MS032 | F04743 | non-negotiable | false | 10 |
| R09469 | Evidence check 3 — failure halts authority promotion | architecture | F04743 | non-negotiable | false | 10 |
| R09470 | Evidence check 4 — tests pass (MS009 audit cycle green) | dump 17509 + cross-ref MS009 | F04744 | non-negotiable | false | 10 |
| R09471 | Evidence check 4 — audit-cycle digest cited in evidence bundle | cross-ref MS003 + cross-ref MS009 | F04744 | non-negotiable | false | 10 |
| R09472 | Evidence check 4 — failure halts authority promotion | architecture | F04744 | non-negotiable | false | 10 |
| R09473 | Evidence check 5 — oracle agrees (sovereign-os Blackwell verification) | dump 17510 + cross-ref M058 | F04745 | non-negotiable | false | 10 |
| R09474 | Evidence check 5 — oracle response signed by oracle service key | cross-ref MS003 + cross-ref M048 | F04745 | non-negotiable | false | 10 |
| R09475 | Evidence check 5 — failure halts authority promotion to L5/L6 | architecture | F04745 | non-negotiable | false | 10 |
| R09476 | Evidence check 6 — user approves (operator dashboard approval signal) | dump 17511 + cross-ref MS007 | F04746 | non-negotiable | false | 10 |
| R09477 | Evidence check 6 — approval carries operator key signature | cross-ref MS003 + cross-ref MS007 | F04746 | non-negotiable | false | 10 |
| R09478 | Evidence check 6 — failure halts authority promotion to L5/L6 | architecture | F04746 | non-negotiable | false | 10 |
| R09479 | Evidence aggregator — collects checks 1..6 results | dump 17501-17517 | F04747 | non-negotiable | false | 10 |
| R09480 | Evidence aggregator — produces bundle in CBOR | architecture | F04748 | non-negotiable | false | 10 |
| R09481 | Evidence aggregator — bundle signed via MS003 | cross-ref MS003 | F04748 | non-negotiable | false | 10 |
| R09482 | Evidence aggregator — bundle includes timestamp | architecture | F04749 | non-negotiable | false | 10 |
| R09483 | Evidence aggregator — bundle includes active profile name | dump 17468 | F04749 | non-negotiable | false | 10 |
| R09484 | Evidence aggregator — bundle includes actor field | dump 17396-17402 | F04749 | non-negotiable | false | 10 |
| R09485 | Evidence aggregator — bundle stored under /var/lib/selfdef/evidence/profile-bundles/ | architecture | F04750 | non-negotiable | false | 10 |
| R09486 | Evidence aggregator — bundle retention 100 days | cross-ref MS037 | F04750 | non-negotiable | false | 10 |
| R09487 | Evidence aggregator — bundle indexed by trace-id | cross-ref M049 | F04750 | non-negotiable | false | 10 |
| R09488 | Evidence aggregator — bundle indexed by profile name | architecture | F04750 | non-negotiable | false | 10 |
| R09489 | Profile resolver — reads /etc/selfdef/profile.toml at boot | architecture | F04751 | non-negotiable | false | 10 |
| R09490 | Profile resolver — reads dashboard-selected profile at runtime | cross-ref MS007 | F04752 | non-negotiable | false | 10 |
| R09491 | Profile resolver — never auto-promotes beyond user selection | architecture + dump 17249 | F04753 | non-negotiable | false | 10 |
| R09492 | Profile resolver — emits trace event on profile change | cross-ref M049 | F04754 | non-negotiable | false | 10 |
| R09493 | Profile resolver — falls back to Private on resolver failure | architecture | F04755 | non-negotiable | false | 10 |
| R09494 | Profile transition — re-clips active L4 grants | architecture + cross-ref MS038 | F04756 | non-negotiable | false | 10 |
| R09495 | Profile transition — re-clips active L5 commits (revokes if outside new envelope) | architecture + cross-ref MS039 | F04757 | non-negotiable | false | 10 |
| R09496 | Profile transition — re-clips capability tokens (revokes if outside new envelope) | cross-ref MS035 | F04758 | non-negotiable | false | 10 |
| R09497 | Profile transition — emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04759 | non-negotiable | false | 10 |
| R09498 | Profile transition — re-clip operation atomic | architecture | F04760 | non-negotiable | false | 10 |
| R09499 | Profile transition — failure leaves prior profile active | architecture | F04760 | non-negotiable | false | 10 |
| R09500 | Profile transition — emits M049 trace span on transition | cross-ref M049 | F04754 | non-negotiable | false | 10 |
| R09501 | Profile config loader — TOML format under /etc/selfdef/profiles/*.toml | architecture | F04761 | non-negotiable | false | 10 |
| R09502 | Profile config loader — validates schema via MS003 | cross-ref MS003 | F04762 | non-negotiable | false | 10 |
| R09503 | Profile config loader — rejects unknown profile names | architecture | F04763 | non-negotiable | false | 10 |
| R09504 | Profile config loader — supports operator-defined custom profiles | architecture | F04764 | non-negotiable | false | 10 |
| R09505 | Profile config loader — custom profiles inherit from one of six base profiles | architecture | F04765 | non-negotiable | false | 10 |
| R09506 | Profile audit emitter — emits M049 13-field span on every authority decision | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09507 | Profile audit emitter — span includes active profile name | cross-ref M049 + dump 17468 | F04767 | non-negotiable | false | 10 |
| R09508 | Profile audit emitter — span includes target authority level | cross-ref M049 + cross-ref MS039 | F04768 | non-negotiable | false | 10 |
| R09509 | Profile audit emitter — span includes evidence bundle reference | architecture + cross-ref MS003 | F04769 | non-negotiable | false | 10 |
| R09510 | Profile audit emitter — span deterministic for MS009 replay | cross-ref MS009 | F04770 | non-negotiable | false | 10 |
| R09511 | Profile typed-mirror — published under MS007 8/8 SATURATED scheme | cross-ref MS007 | F04771 | non-negotiable | false | 10 |
| R09512 | Profile typed-mirror — Profile enum (Private/Fast/Careful/Autonomous/Experimental/Production) | cross-ref MS007 + dump 17468-17487 | F04772 | non-negotiable | false | 10 |
| R09513 | Profile typed-mirror — AuthorityEnvelope struct {profile, max_level, gates, ring_clip} | cross-ref MS007 | F04773 | non-negotiable | false | 10 |
| R09514 | Profile typed-mirror — EvidenceBundle struct {checks_passed, digest, signature} | cross-ref MS007 + dump 17501-17517 | F04774 | non-negotiable | false | 10 |
| R09515 | Profile typed-mirror — Rust crate name selfdef-profile-mirror | cross-ref MS007 | F04775 | non-negotiable | false | 10 |
| R09516 | Profile typed-mirror — re-exported via sovereign-os cargo workspace | cross-ref MS007 | F04775 | non-negotiable | false | 10 |
| R09517 | Profile typed-mirror — no_std friendly | architecture | F04775 | non-negotiable | false | 10 |
| R09518 | Profile typed-mirror — serde + bincode derives present | architecture | F04775 | non-negotiable | false | 10 |
| R09519 | Profile typed-mirror — schema_version "1.0.0" | cross-ref MS007 | F04775 | non-negotiable | false | 10 |
| R09520 | Profile FSM bridge — re-uses MS039 authority FSM with envelope mask | cross-ref MS039 | F04776 | non-negotiable | false | 10 |
| R09521 | Profile FSM bridge — illegal transition rejected (e.g. Private → L4 without approval) | cross-ref MS039 + dump 17470 | F04777 | non-negotiable | false | 10 |
| R09522 | Profile FSM bridge — transition emits trace event | cross-ref M049 | F04778 | non-negotiable | false | 10 |
| R09523 | Profile FSM bridge — transitions signed via MS003 | cross-ref MS003 | F04779 | non-negotiable | false | 10 |
| R09524 | Profile FSM bridge — transitions retained 100 days | cross-ref MS037 | F04780 | non-negotiable | false | 10 |
| R09525 | Profile replay validator — verifies historical profile-decision chain | cross-ref MS009 | F04781 | non-negotiable | false | 10 |
| R09526 | Profile replay validator — detects unauthorized profile escalations | cross-ref MS009 + cross-ref MS003 | F04782 | non-negotiable | false | 10 |
| R09527 | Profile replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 | F04783 | non-negotiable | false | 10 |
| R09528 | Profile replay validator — runs daily as cron unit | cross-ref MS009 | F04784 | non-negotiable | false | 10 |
| R09529 | Profile replay validator — failures halt all L5/L6 activity | architecture | F04785 | non-negotiable | false | 10 |
| R09530 | Profile override policy — overrides require operator signature | cross-ref MS003 | F04786 | non-negotiable | false | 10 |
| R09531 | Profile override policy — overrides time-bounded (max 24h) | cross-ref MS038 | F04787 | non-negotiable | false | 10 |
| R09532 | Profile override policy — overrides logged via M049 | cross-ref M049 | F04788 | non-negotiable | false | 10 |
| R09533 | Profile override policy — overrides composable with policy bus decisions | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09534 | Profile override policy — emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04790 | non-negotiable | false | 10 |
| R09535 | Profile default resolver — returns Private if no explicit selection | architecture + dump 17468 | F04791 | non-negotiable | false | 10 |
| R09536 | Profile default resolver — returns operator-chosen default if set | architecture | F04792 | non-negotiable | false | 10 |
| R09537 | Profile default resolver — never returns Production by default | architecture | F04793 | non-negotiable | false | 10 |
| R09538 | Profile default resolver — never returns Autonomous by default | architecture | F04794 | non-negotiable | false | 10 |
| R09539 | Profile default resolver — defaults can be operator-overridden per session | architecture | F04795 | non-negotiable | false | 10 |
| R09540 | Cumulative — six profiles cover dump 17468-17487 every line | dump 17468-17487 | F04796 | non-negotiable | false | 10 |
| R09541 | Cumulative — "the same request can schedule differently under different profiles" | dump 18036 + cross-ref M058 | F04797 | non-negotiable | false | 10 |
| R09542 | Cumulative — six profiles integrate with M058 hardware-aware scheduler | cross-ref M058 | F04798 | non-negotiable | false | 10 |
| R09543 | Cumulative — six profiles integrate with M057 12-step lifecycle (profile carried per step) | cross-ref M057 | F04799 | non-negotiable | false | 10 |
| R09544 | Cumulative — six profiles integrate with M042 choice architecture | cross-ref M042 | F04800 | non-negotiable | false | 10 |
| R09545 | Integration — profile name carried in capability_word.profile_id field (3 bits) | cross-ref MS035 | F04687 | non-negotiable | false | 10 |
| R09546 | Integration — profile name carried in network-grant.profile field | cross-ref MS038 | F04697 | non-negotiable | false | 10 |
| R09547 | Integration — profile name carried in filesystem-grant.profile field | cross-ref MS037 | F04697 | non-negotiable | false | 10 |
| R09548 | Integration — profile name carried in capability-grant.profile field | cross-ref MS035 | F04697 | non-negotiable | false | 10 |
| R09549 | Integration — profile name carried in sandbox-allocation.profile field | cross-ref MS036 | F04697 | non-negotiable | false | 10 |
| R09550 | Integration — profile name carried in communication-grant.profile field | cross-ref MS034 | F04697 | non-negotiable | false | 10 |
| R09551 | Integration — profile name reflected in M049 trace span (selfdef.profile attribute) | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09552 | Integration — profile name reflected in OCSF events (selfdef.profile field) | cross-ref MS026 | F04766 | non-negotiable | false | 10 |
| R09553 | Integration — profile name surfaced in operator dashboard summary | cross-ref MS007 | F04752 | non-negotiable | false | 10 |
| R09554 | Integration — profile name surfaced in info-hub knowledge bridge (read-only) | architecture + operator standing direction | F04752 | non-negotiable | false | 10 |
| R09555 | Operational — daemon refuses to start with no valid profile config | architecture | F04762 | non-negotiable | false | 10 |
| R09556 | Operational — daemon refuses to start with chain-break in profile audit log | cross-ref MS009 | F04785 | non-negotiable | false | 10 |
| R09557 | Operational — daemon honors SIGHUP for profile reload | architecture | F04761 | non-negotiable | false | 10 |
| R09558 | Operational — daemon emits readiness probe at /run/selfdef/profile-ready | architecture | F04751 | non-negotiable | false | 10 |
| R09559 | Operational — daemon emits current profile via D-Bus property | architecture + cross-ref MS007 | F04752 | non-negotiable | false | 10 |
| R09560 | Operational — daemon graceful drain on profile transition | architecture | F04760 | non-negotiable | false | 10 |
| R09561 | Profile composition — Private+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09562 | Profile composition — Fast+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09563 | Profile composition — Careful+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09564 | Profile composition — Autonomous+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09565 | Profile composition — Experimental+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09566 | Profile composition — Production+overrides composable with policy bus | cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09567 | Profile composition — composed envelope = min(profile_envelope, policy_envelope) | architecture + cross-ref MS033 | F04789 | non-negotiable | false | 10 |
| R09568 | Profile composition — composed envelope re-evaluated on every authority decision | architecture | F04766 | non-negotiable | false | 10 |
| R09569 | Profile composition — composed envelope cached with 5s TTL | architecture | F04766 | non-negotiable | false | 10 |
| R09570 | Profile composition — composed envelope cache flushed on policy bus revoke | cross-ref MS033 | F04766 | non-negotiable | false | 10 |
| R09571 | Profile telemetry — count of authority decisions per profile emitted via M049 | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09572 | Profile telemetry — count of gate failures per profile emitted via M049 | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09573 | Profile telemetry — count of profile transitions emitted via M049 | cross-ref M049 | F04754 | non-negotiable | false | 10 |
| R09574 | Profile telemetry — average gate-evaluation latency per profile via M049 | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09575 | Profile telemetry — observability surfaced via M049 dashboards | cross-ref M049 | F04766 | non-negotiable | false | 10 |
| R09576 | Profile cross-repo — sovereign-os M042 owns profile selection semantics | cross-ref M042 | F04800 | non-negotiable | false | 10 |
| R09577 | Profile cross-repo — sovereign-os M048 ConfigResolver mediates profile choice | cross-ref M048 | F04752 | non-negotiable | false | 10 |
| R09578 | Profile cross-repo — sovereign-os M054 ProfileResolver typed interface | cross-ref M054 | F04771 | non-negotiable | false | 10 |
| R09579 | Profile cross-repo — selfdef profile-mirror crate consumed by sovereign-os runtime | cross-ref MS007 | F04775 | non-negotiable | false | 10 |
| R09580 | Profile cross-repo — info-hub knowledge layer treats profile as read-only context | operator standing direction | F04752 | non-negotiable | false | 10 |
| R09581 | Profile boundary — IPS does NOT decide which profile is active (sovereign-os runtime decides) | architecture + operator standing direction | F04751 | non-negotiable | false | 10 |
| R09582 | Profile boundary — IPS only ENFORCES the envelope of the active profile on its own mutations | architecture + operator standing direction | F04681 | non-negotiable | false | 10 |
| R09583 | Profile boundary — IPS does NOT propose profile changes (sovereign-os does via choice architecture) | architecture + cross-ref M042 | F04753 | non-negotiable | false | 10 |
| R09584 | Profile boundary — IPS does NOT compose new profiles dynamically (only operator/sovereign-os do) | architecture + operator standing direction | F04763 | non-negotiable | false | 10 |
| R09585 | Profile boundary — IPS exposes profile state read-only via MS007 mirror | cross-ref MS007 | F04771 | non-negotiable | false | 10 |
| R09586 | Profile lifecycle — profile enters "loading" state on config load | architecture | F04761 | non-negotiable | false | 10 |
| R09587 | Profile lifecycle — profile enters "validating" state on schema check | cross-ref MS003 | F04762 | non-negotiable | false | 10 |
| R09588 | Profile lifecycle — profile enters "active" state on validation pass | architecture | F04751 | non-negotiable | false | 10 |
| R09589 | Profile lifecycle — profile enters "transitioning" state on switch request | architecture | F04756 | non-negotiable | false | 10 |
| R09590 | Profile lifecycle — profile enters "draining" state on profile change | architecture | F04760 | non-negotiable | false | 10 |
| R09591 | Profile lifecycle — profile enters "inactive" state after drain complete | architecture | F04760 | non-negotiable | false | 10 |
| R09592 | Profile lifecycle — every state transition emits M049 trace | cross-ref M049 | F04754 | non-negotiable | false | 10 |
| R09593 | Profile lifecycle — every state transition emits OCSF Configuration Change | cross-ref MS026 | F04759 | non-negotiable | false | 10 |
| R09594 | Profile lifecycle — state transitions signed via MS003 | cross-ref MS003 | F04779 | non-negotiable | false | 10 |
| R09595 | Profile lifecycle — state retained in /var/lib/selfdef/profile-state.json | architecture | F04751 | non-negotiable | false | 10 |
| R09596 | Closing — six profiles fully cover dump 17468-17487 | dump 17468-17487 | F04796 | non-negotiable | false | 10 |
| R09597 | Closing — evidence ladder fully covers dump 17501-17517 | dump 17501-17517 | F04747 | non-negotiable | false | 10 |
| R09598 | Closing — profile envelopes never invented beyond dump declarations | dump 17468-17487 + operator standing direction | F04796 | non-negotiable | false | 10 |
| R09599 | Closing — IPS-side projection respects sovereign-os ownership of profile semantics | operator standing direction + cross-ref M042 | F04800 | non-negotiable | false | 10 |
| R09600 | Closing — every R-row above carries 10 hard non-negotiable sub-requirements per operator standing direction | operator standing direction | F04796 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements per operator standing direction. Total enforced sub-reqs = 240 R × 10 = **2,400 sub-requirements** for MS040.

## Cross-references

- **sovereign-os M042** — canonical choice-architecture (selfdef projects through MS007 typed mirrors only)
- **sovereign-os M046** — runtime adaptation + LoRA Foundry (profile influences adaptation paths)
- **sovereign-os M047** — continuity (autonomous profile depends on CRIU + ZFS)
- **sovereign-os M048** — ConfigResolver mediates profile choice
- **sovereign-os M049** — observability / trace pipeline
- **sovereign-os M054** — ProfileResolver typed interface
- **sovereign-os M057** — 12-step task lifecycle carries profile per step
- **sovereign-os M058** — hardware-aware scheduler honors profile policies
- **MS003** — selfdef-signing (signs profile transitions, evidence bundles, override artifacts)
- **MS007** — typed-mirror crate scheme (selfdef-profile-mirror)
- **MS009** — audit cycles + replay validator
- **MS026** — observability + OCSF event emission
- **MS032** — sandbox tiers (evidence check 3 sandbox simulation pass)
- **MS033** — policy bus (envelope composition with policy decisions)
- **MS034-MS038** — Communication / Capability / Sandbox / Filesystem / Network boundaries (the five enforcement layers this milestone clips per profile)
- **MS039** — Authority levels + trust rings (this milestone clips the L0..L6 FSM per profile)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS040
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines: 17468-17517
cross_repo_mirror: sovereign-os/M042
typed_mirror_crate: selfdef-profile-mirror
profiles:
  - private
  - fast
  - careful
  - autonomous
  - experimental
  - production
evidence_checks:
  - valid_schema
  - safe_policy
  - successful_sandbox
  - tests_pass
  - oracle_agrees
  - user_approves
```
