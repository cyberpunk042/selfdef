# MS041 — Commit authority — durable-change discipline — IPS-side projection

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 17389-17421 (Commit Authority — 8 commit types + 5 mandatory fields + 3 high-risk additional gates)
**Cross-repo mirror**: sovereign-os M056 (canonical authority model — commit-authority arc) — selfdef receives this canon through MS007 typed mirrors only
**Project boundary**: this milestone catalogs ONLY the IPS-side enforcement of commit-authority for its OWN durable mutations (network rules, filesystem mounts, capability registry, sandbox tier upgrades, audit catalog); cross-repo commit semantics live in sovereign-os M056

## Projection statement

> "A commit is any durable change." (dump 17389)

> "Every commit needs: actor / reason / policy decision / rollback status / trace reference." (dump 17396-17402)

> "High-risk commits need: snapshot / test/eval / oracle or human gate." (dump 17415-17421)

The IPS daemon performs durable mutations across all five MS034-MS038 boundary layers (Communication / Capability / Sandbox / Filesystem / Network). This milestone catalogs the discipline that every such mutation observes the 8-commit-type taxonomy, carries the 5 mandatory fields, and — for high-risk variants — satisfies the snapshot + test/eval + oracle-or-human gate triple.

## Epics (E0411-E0420)

| epic | name | source |
|---|---|---|
| E0411 | Commit type 1 — file write | dump 17391 |
| E0412 | Commit type 2 — memory write | dump 17392 |
| E0413 | Commit type 3 — policy update | dump 17393 |
| E0414 | Commit type 4 — profile update | dump 17394 |
| E0415 | Commit type 5 — adapter promotion | dump 17395 |
| E0416 | Commit type 6 — cloud exposure log | dump 17396 |
| E0417 | Commit type 7 — tool side effect | dump 17397 |
| E0418 | Commit type 8 — workflow completion | dump 17398 |
| E0419 | Five mandatory fields — actor / reason / policy-decision / rollback-status / trace-reference | dump 17396-17402 |
| E0420 | High-risk triple gate — snapshot + test/eval + oracle-or-human | dump 17415-17421 |

## Modules (M01045-M01070)

| module | name | source |
|---|---|---|
| M01045 | selfdef-commit-type-file-write | dump 17391 + cross-ref MS037 |
| M01046 | selfdef-commit-type-memory-write | dump 17392 + cross-ref M048 |
| M01047 | selfdef-commit-type-policy-update | dump 17393 + cross-ref MS033 |
| M01048 | selfdef-commit-type-profile-update | dump 17394 + cross-ref MS040 |
| M01049 | selfdef-commit-type-adapter-promotion | dump 17395 + cross-ref M046 |
| M01050 | selfdef-commit-type-cloud-exposure-log | dump 17396 + cross-ref MS038 |
| M01051 | selfdef-commit-type-tool-side-effect | dump 17397 + cross-ref MS036 |
| M01052 | selfdef-commit-type-workflow-completion | dump 17398 + cross-ref M057 |
| M01053 | selfdef-commit-field-actor | dump 17398 |
| M01054 | selfdef-commit-field-reason | dump 17399 |
| M01055 | selfdef-commit-field-policy-decision | dump 17400 + cross-ref MS033 |
| M01056 | selfdef-commit-field-rollback-status | dump 17401 + cross-ref MS039 |
| M01057 | selfdef-commit-field-trace-reference | dump 17402 + cross-ref M049 |
| M01058 | selfdef-commit-mandatory-field-validator | dump 17396-17402 |
| M01059 | selfdef-commit-mandatory-field-signer | cross-ref MS003 + dump 17396-17402 |
| M01060 | selfdef-commit-high-risk-classifier | dump 17415-17421 + architecture |
| M01061 | selfdef-commit-gate-snapshot | dump 17418 + cross-ref MS037 |
| M01062 | selfdef-commit-gate-test-eval | dump 17419 + cross-ref MS009 |
| M01063 | selfdef-commit-gate-oracle-or-human | dump 17420 + cross-ref MS007 + cross-ref M058 |
| M01064 | selfdef-commit-receipt-store | architecture + cross-ref MS037 |
| M01065 | selfdef-commit-replay-validator | cross-ref MS009 |
| M01066 | selfdef-commit-rollback-engine | cross-ref MS039 + cross-ref MS003 |
| M01067 | selfdef-commit-typed-mirror | cross-ref MS007 |
| M01068 | selfdef-commit-event-emitter | cross-ref M049 + cross-ref MS026 |
| M01069 | selfdef-commit-actor-registry | architecture + cross-ref MS035 |
| M01070 | selfdef-commit-reason-validator | architecture + dump 17399 |

## Features (F04801-F04920)

| feature | name | source |
|---|---|---|
| F04801 | Commit type — file write (durable filesystem mutation) | dump 17391 |
| F04802 | Commit type — file write via fanotify FAN_MARK_ADD + write hook | dump 17391 + cross-ref MS037 |
| F04803 | Commit type — file write integrates with ZFS snapshot pre-commit hook | dump 17418 + cross-ref MS037 |
| F04804 | Commit type — file write rollback via ZFS rollback to pre-commit snapshot | cross-ref MS037 |
| F04805 | Commit type — file write emits OCSF File System Activity class 1001 | cross-ref MS026 |
| F04806 | Commit type — memory write (memory graph / replay / ZFS ARC) | dump 17392 + cross-ref M048 |
| F04807 | Commit type — memory write signed via MS003 | cross-ref MS003 |
| F04808 | Commit type — memory write rollback via memory-graph undo | cross-ref M048 + cross-ref MS039 |
| F04809 | Commit type — memory write emits OCSF Audit Activity class 1003 | cross-ref MS026 |
| F04810 | Commit type — policy update (policy bus state mutation) | dump 17393 + cross-ref MS033 |
| F04811 | Commit type — policy update signed via MS003 | cross-ref MS003 |
| F04812 | Commit type — policy update rollback via signed revert | cross-ref MS003 + cross-ref MS033 |
| F04813 | Commit type — policy update emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04814 | Commit type — profile update (active profile transition) | dump 17394 + cross-ref MS040 |
| F04815 | Commit type — profile update signed via MS003 | cross-ref MS003 |
| F04816 | Commit type — profile update rollback via prior-profile restore | cross-ref MS040 |
| F04817 | Commit type — profile update emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04818 | Commit type — adapter promotion (LoRA crystallization promotion) | dump 17395 + cross-ref M046 |
| F04819 | Commit type — adapter promotion signed via MS003 | cross-ref MS003 |
| F04820 | Commit type — adapter promotion rollback via prior-adapter restore | cross-ref M046 |
| F04821 | Commit type — adapter promotion requires high-risk triple gate | dump 17415-17421 + cross-ref M046 |
| F04822 | Commit type — adapter promotion emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04823 | Commit type — cloud exposure log (Ring 4 outbound record) | dump 17396 + cross-ref MS038 + MS039 |
| F04824 | Commit type — cloud exposure log signed via MS003 | cross-ref MS003 |
| F04825 | Commit type — cloud exposure log immutable (append-only) | cross-ref MS009 |
| F04826 | Commit type — cloud exposure log emits OCSF Network Activity class 4001 cloud_exposure=true | cross-ref MS026 |
| F04827 | Commit type — tool side effect (MS036 tool execution observable effect) | dump 17397 + cross-ref MS036 |
| F04828 | Commit type — tool side effect signed via MS003 | cross-ref MS003 |
| F04829 | Commit type — tool side effect rollback via signed revert (if available) | cross-ref MS003 + cross-ref MS036 |
| F04830 | Commit type — tool side effect emits OCSF Audit Activity class 1003 | cross-ref MS026 |
| F04831 | Commit type — workflow completion (M057 12-step lifecycle final step) | dump 17398 + cross-ref M057 |
| F04832 | Commit type — workflow completion signed via MS003 | cross-ref MS003 |
| F04833 | Commit type — workflow completion rollback via M057 step-12 archive-restore | cross-ref M057 |
| F04834 | Commit type — workflow completion emits OCSF Configuration Change class 5001 | cross-ref MS026 |
| F04835 | Mandatory field — actor (who initiated commit) | dump 17398 |
| F04836 | Mandatory field — actor identified by signed identity (MS003 key fingerprint) | cross-ref MS003 |
| F04837 | Mandatory field — actor registered in /etc/selfdef/actors/ catalog | architecture |
| F04838 | Mandatory field — actor field non-empty (enforced at signer) | architecture |
| F04839 | Mandatory field — actor field rejected if not in registered catalog | architecture |
| F04840 | Mandatory field — reason (human-readable justification) | dump 17399 |
| F04841 | Mandatory field — reason field non-empty string | architecture |
| F04842 | Mandatory field — reason field minimum 16 characters | architecture |
| F04843 | Mandatory field — reason field maximum 4096 characters | architecture |
| F04844 | Mandatory field — reason field UTF-8 normalized | architecture |
| F04845 | Mandatory field — policy-decision (policy bus decision reference) | dump 17400 + cross-ref MS033 |
| F04846 | Mandatory field — policy-decision is ULID reference to policy bus log | cross-ref MS033 |
| F04847 | Mandatory field — policy-decision signed by policy bus key | cross-ref MS003 + cross-ref MS033 |
| F04848 | Mandatory field — policy-decision must be "allow" or "allow_with_conditions" | cross-ref MS033 |
| F04849 | Mandatory field — policy-decision rejected if "deny" | architecture |
| F04850 | Mandatory field — rollback-status (rollback availability declaration) | dump 17401 + cross-ref MS039 |
| F04851 | Mandatory field — rollback-status values: {available, available-with-loss, unavailable, irreversible} | architecture |
| F04852 | Mandatory field — rollback-status "unavailable" rejected for high-risk commits | architecture + dump 17415-17421 |
| F04853 | Mandatory field — rollback-status "irreversible" requires explicit operator confirmation | architecture |
| F04854 | Mandatory field — rollback-status carries rollback-artifact reference | cross-ref MS003 + cross-ref MS039 |
| F04855 | Mandatory field — trace-reference (M049 13-field span reference) | dump 17402 + cross-ref M049 |
| F04856 | Mandatory field — trace-reference is M049 ULID trace-id | cross-ref M049 |
| F04857 | Mandatory field — trace-reference resolvable in observability pipeline | cross-ref M049 |
| F04858 | Mandatory field — trace-reference rejected if not found in trace store | cross-ref M049 |
| F04859 | Mandatory field — trace-reference indexed in commit receipt store | architecture + cross-ref M049 |
| F04860 | Mandatory field validator — checks all 5 fields present | dump 17396-17402 |
| F04861 | Mandatory field validator — checks all 5 fields well-formed | architecture |
| F04862 | Mandatory field validator — checks all 5 fields signed | cross-ref MS003 |
| F04863 | Mandatory field validator — failure halts commit | architecture |
| F04864 | Mandatory field validator — failure emits OCSF Detection Finding class 2004 | cross-ref MS026 |
| F04865 | Mandatory field signer — produces signed commit envelope | cross-ref MS003 |
| F04866 | Mandatory field signer — envelope = CBOR-encoded {type, actor, reason, policy-decision, rollback-status, trace-reference, timestamp, signature} | architecture + cross-ref MS003 |
| F04867 | Mandatory field signer — signature uses MS003 selfdef-signing | cross-ref MS003 |
| F04868 | Mandatory field signer — envelope stored in /var/lib/selfdef/commits/ | architecture |
| F04869 | Mandatory field signer — envelope retention 365 days | architecture + cross-ref MS037 |
| F04870 | High-risk classifier — classifies commits by risk score | dump 17415-17421 + architecture |
| F04871 | High-risk classifier — adapter promotion = high-risk (always) | dump 17415-17421 + cross-ref M046 |
| F04872 | High-risk classifier — L6 Persist commits = high-risk (always) | cross-ref MS039 + dump 17415-17421 |
| F04873 | High-risk classifier — cloud exposure log = high-risk (always) | cross-ref MS038 + dump 17415-17421 |
| F04874 | High-risk classifier — production-profile L5 Commit = high-risk | cross-ref MS040 + dump 17415-17421 |
| F04875 | High-risk classifier — autonomous-profile L5 Commit outside predeclared gate = high-risk | cross-ref MS040 |
| F04876 | High-risk gate — snapshot (ZFS snapshot pre-commit) | dump 17418 + cross-ref MS037 |
| F04877 | High-risk gate — snapshot named selfdef-pre-commit-<commit-id> | architecture + cross-ref MS037 |
| F04878 | High-risk gate — snapshot retained 365 days | cross-ref MS037 |
| F04879 | High-risk gate — snapshot verified via zfs list before commit proceeds | architecture |
| F04880 | High-risk gate — snapshot signature cited in commit envelope | cross-ref MS003 + cross-ref MS037 |
| F04881 | High-risk gate — test/eval (MS009 audit cycle + eval suite) | dump 17419 + cross-ref MS009 |
| F04882 | High-risk gate — test/eval result signed by eval service | cross-ref MS003 + cross-ref M048 |
| F04883 | High-risk gate — test/eval digest cited in commit envelope | cross-ref MS003 + cross-ref MS009 |
| F04884 | High-risk gate — test/eval gate failure halts commit | architecture |
| F04885 | High-risk gate — test/eval gate timeout default 24h then auto-deny | architecture |
| F04886 | High-risk gate — oracle-or-human (sovereign-os oracle OR operator approval) | dump 17420 + cross-ref M058 + cross-ref MS007 |
| F04887 | High-risk gate — oracle response signed by oracle service key | cross-ref MS003 + cross-ref M048 |
| F04888 | High-risk gate — human approval signed by operator key | cross-ref MS003 + cross-ref MS007 |
| F04889 | High-risk gate — at least one of oracle/human must approve | dump 17420 |
| F04890 | High-risk gate — production profile requires BOTH oracle AND human | cross-ref MS040 |
| F04891 | Receipt store — every commit produces receipt with all 5 fields + gate digests | dump 17396-17421 |
| F04892 | Receipt store — receipts in CBOR format | architecture |
| F04893 | Receipt store — receipts signed via MS003 | cross-ref MS003 |
| F04894 | Receipt store — receipts retained 365 days minimum | cross-ref MS037 |
| F04895 | Receipt store — receipts indexed by commit-id, actor, trace-id, type | architecture |
| F04896 | Receipt store — receipts queryable via MS007 typed-mirror interface | cross-ref MS007 |
| F04897 | Replay validator — verifies historical commit-chain integrity | cross-ref MS009 |
| F04898 | Replay validator — detects missing/malformed signatures | cross-ref MS003 + cross-ref MS009 |
| F04899 | Replay validator — detects gate-fields missing on historical high-risk commits | architecture + cross-ref MS009 |
| F04900 | Replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 |
| F04901 | Replay validator — runs daily as cron unit | cross-ref MS009 |
| F04902 | Replay validator — failures halt all new high-risk commits until resolved | architecture |
| F04903 | Rollback engine — reverts L5 Commit via signed revert | cross-ref MS003 + cross-ref MS039 |
| F04904 | Rollback engine — reverts L6 Persist via signed revert | cross-ref MS003 + cross-ref MS039 |
| F04905 | Rollback engine — uses ZFS snapshot for file-write commit type | cross-ref MS037 |
| F04906 | Rollback engine — uses memory-graph undo for memory-write commit type | cross-ref M048 |
| F04907 | Rollback engine — uses prior-profile restore for profile-update commit type | cross-ref MS040 |
| F04908 | Rollback engine — uses prior-adapter restore for adapter-promotion commit type | cross-ref M046 |
| F04909 | Rollback engine — never silently drops state | cross-ref MS039 |
| F04910 | Typed-mirror — published under MS007 8/8 SATURATED | cross-ref MS007 |
| F04911 | Typed-mirror — CommitType enum (8 variants) | cross-ref MS007 + dump 17391-17398 |
| F04912 | Typed-mirror — CommitEnvelope struct (5 fields + signature) | cross-ref MS007 + dump 17396-17402 |
| F04913 | Typed-mirror — HighRiskGates struct (snapshot/test-eval/oracle-or-human) | cross-ref MS007 + dump 17415-17421 |
| F04914 | Typed-mirror — RollbackStatus enum | cross-ref MS007 |
| F04915 | Typed-mirror — Rust crate name selfdef-commit-mirror | cross-ref MS007 |
| F04916 | Event emitter — every commit emits M049 trace span | cross-ref M049 |
| F04917 | Event emitter — every commit emits OCSF event (type-dependent class) | cross-ref MS026 |
| F04918 | Actor registry — actors keyed by MS003 key fingerprint | cross-ref MS003 |
| F04919 | Actor registry — registry signed via MS003 | cross-ref MS003 |
| F04920 | Reason validator — UTF-8 normalization NFKC | architecture |

## Requirements (R09601-R09840)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R09601 | Doctrinal — "A commit is any durable change" | dump 17389 | F04801 | non-negotiable | false | 10 |
| R09602 | Doctrinal — every commit needs actor | dump 17398 | F04835 | non-negotiable | false | 10 |
| R09603 | Doctrinal — every commit needs reason | dump 17399 | F04840 | non-negotiable | false | 10 |
| R09604 | Doctrinal — every commit needs policy decision | dump 17400 | F04845 | non-negotiable | false | 10 |
| R09605 | Doctrinal — every commit needs rollback status | dump 17401 | F04850 | non-negotiable | false | 10 |
| R09606 | Doctrinal — every commit needs trace reference | dump 17402 | F04855 | non-negotiable | false | 10 |
| R09607 | Doctrinal — high-risk commits need snapshot | dump 17418 | F04876 | non-negotiable | false | 10 |
| R09608 | Doctrinal — high-risk commits need test/eval | dump 17419 | F04881 | non-negotiable | false | 10 |
| R09609 | Doctrinal — high-risk commits need oracle or human gate | dump 17420 | F04886 | non-negotiable | false | 10 |
| R09610 | Doctrinal — 8 commit types enumerated verbatim from dump | dump 17391-17398 | F04801 | non-negotiable | false | 10 |
| R09611 | Type — file write is a commit | dump 17391 | F04801 | non-negotiable | false | 10 |
| R09612 | Type — file write via fanotify FAN_MARK_ADD + write hook | cross-ref MS037 | F04802 | non-negotiable | false | 10 |
| R09613 | Type — file write integrates with ZFS snapshot pre-commit hook | cross-ref MS037 + dump 17418 | F04803 | non-negotiable | false | 10 |
| R09614 | Type — file write rollback via ZFS rollback | cross-ref MS037 | F04804 | non-negotiable | false | 10 |
| R09615 | Type — file write emits OCSF File System Activity class 1001 | cross-ref MS026 | F04805 | non-negotiable | false | 10 |
| R09616 | Type — memory write is a commit | dump 17392 | F04806 | non-negotiable | false | 10 |
| R09617 | Type — memory write applies to memory graph (M048) | cross-ref M048 | F04806 | non-negotiable | false | 10 |
| R09618 | Type — memory write applies to ZFS ARC | cross-ref MS037 | F04806 | non-negotiable | false | 10 |
| R09619 | Type — memory write signed via MS003 | cross-ref MS003 | F04807 | non-negotiable | false | 10 |
| R09620 | Type — memory write rollback via memory-graph undo | cross-ref M048 + cross-ref MS039 | F04808 | non-negotiable | false | 10 |
| R09621 | Type — memory write emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04809 | non-negotiable | false | 10 |
| R09622 | Type — policy update is a commit | dump 17393 | F04810 | non-negotiable | false | 10 |
| R09623 | Type — policy update applies to policy bus state | cross-ref MS033 | F04810 | non-negotiable | false | 10 |
| R09624 | Type — policy update signed via MS003 | cross-ref MS003 | F04811 | non-negotiable | false | 10 |
| R09625 | Type — policy update rollback via signed revert | cross-ref MS003 | F04812 | non-negotiable | false | 10 |
| R09626 | Type — policy update emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04813 | non-negotiable | false | 10 |
| R09627 | Type — profile update is a commit | dump 17394 | F04814 | non-negotiable | false | 10 |
| R09628 | Type — profile update applies to active profile transition | cross-ref MS040 | F04814 | non-negotiable | false | 10 |
| R09629 | Type — profile update signed via MS003 | cross-ref MS003 | F04815 | non-negotiable | false | 10 |
| R09630 | Type — profile update rollback via prior-profile restore | cross-ref MS040 | F04816 | non-negotiable | false | 10 |
| R09631 | Type — profile update emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04817 | non-negotiable | false | 10 |
| R09632 | Type — adapter promotion is a commit | dump 17395 | F04818 | non-negotiable | false | 10 |
| R09633 | Type — adapter promotion applies to LoRA Foundry crystallization | cross-ref M046 | F04818 | non-negotiable | false | 10 |
| R09634 | Type — adapter promotion signed via MS003 | cross-ref MS003 | F04819 | non-negotiable | false | 10 |
| R09635 | Type — adapter promotion rollback via prior-adapter restore | cross-ref M046 | F04820 | non-negotiable | false | 10 |
| R09636 | Type — adapter promotion requires high-risk triple gate (always) | dump 17415-17421 | F04821 | non-negotiable | false | 10 |
| R09637 | Type — adapter promotion emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04822 | non-negotiable | false | 10 |
| R09638 | Type — cloud exposure log is a commit | dump 17396 | F04823 | non-negotiable | false | 10 |
| R09639 | Type — cloud exposure log applies to Ring 4 outbound traffic | cross-ref MS039 + MS038 | F04823 | non-negotiable | false | 10 |
| R09640 | Type — cloud exposure log signed via MS003 | cross-ref MS003 | F04824 | non-negotiable | false | 10 |
| R09641 | Type — cloud exposure log immutable (append-only) | cross-ref MS009 | F04825 | non-negotiable | false | 10 |
| R09642 | Type — cloud exposure log emits OCSF Network Activity class 4001 cloud_exposure=true | cross-ref MS026 | F04826 | non-negotiable | false | 10 |
| R09643 | Type — tool side effect is a commit | dump 17397 | F04827 | non-negotiable | false | 10 |
| R09644 | Type — tool side effect applies to MS036 tool execution observable effect | cross-ref MS036 | F04827 | non-negotiable | false | 10 |
| R09645 | Type — tool side effect signed via MS003 | cross-ref MS003 | F04828 | non-negotiable | false | 10 |
| R09646 | Type — tool side effect rollback via signed revert when available | cross-ref MS003 + cross-ref MS036 | F04829 | non-negotiable | false | 10 |
| R09647 | Type — tool side effect emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04830 | non-negotiable | false | 10 |
| R09648 | Type — workflow completion is a commit | dump 17398 | F04831 | non-negotiable | false | 10 |
| R09649 | Type — workflow completion applies to M057 12-step lifecycle final step | cross-ref M057 | F04831 | non-negotiable | false | 10 |
| R09650 | Type — workflow completion signed via MS003 | cross-ref MS003 | F04832 | non-negotiable | false | 10 |
| R09651 | Type — workflow completion rollback via M057 step-12 archive-restore | cross-ref M057 | F04833 | non-negotiable | false | 10 |
| R09652 | Type — workflow completion emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04834 | non-negotiable | false | 10 |
| R09653 | Field — actor identified by signed identity (MS003 key fingerprint) | cross-ref MS003 | F04836 | non-negotiable | false | 10 |
| R09654 | Field — actor registered in /etc/selfdef/actors/ catalog | architecture | F04837 | non-negotiable | false | 10 |
| R09655 | Field — actor field non-empty (enforced at signer) | architecture | F04838 | non-negotiable | false | 10 |
| R09656 | Field — actor field rejected if not in registered catalog | architecture | F04839 | non-negotiable | false | 10 |
| R09657 | Field — reason is human-readable justification | dump 17399 | F04840 | non-negotiable | false | 10 |
| R09658 | Field — reason field non-empty string | architecture | F04841 | non-negotiable | false | 10 |
| R09659 | Field — reason field minimum 16 characters | architecture | F04842 | non-negotiable | false | 10 |
| R09660 | Field — reason field maximum 4096 characters | architecture | F04843 | non-negotiable | false | 10 |
| R09661 | Field — reason field UTF-8 NFKC normalized | architecture | F04920 | non-negotiable | false | 10 |
| R09662 | Field — policy-decision is ULID reference to policy bus log | cross-ref MS033 | F04846 | non-negotiable | false | 10 |
| R09663 | Field — policy-decision signed by policy bus key | cross-ref MS003 + cross-ref MS033 | F04847 | non-negotiable | false | 10 |
| R09664 | Field — policy-decision must be "allow" or "allow_with_conditions" | cross-ref MS033 | F04848 | non-negotiable | false | 10 |
| R09665 | Field — policy-decision rejected if "deny" | architecture | F04849 | non-negotiable | false | 10 |
| R09666 | Field — rollback-status values: {available, available-with-loss, unavailable, irreversible} | architecture | F04851 | non-negotiable | false | 10 |
| R09667 | Field — rollback-status "unavailable" rejected for high-risk commits | dump 17415-17421 | F04852 | non-negotiable | false | 10 |
| R09668 | Field — rollback-status "irreversible" requires explicit operator confirmation | architecture | F04853 | non-negotiable | false | 10 |
| R09669 | Field — rollback-status carries rollback-artifact reference | cross-ref MS003 + cross-ref MS039 | F04854 | non-negotiable | false | 10 |
| R09670 | Field — trace-reference is M049 ULID trace-id | cross-ref M049 | F04856 | non-negotiable | false | 10 |
| R09671 | Field — trace-reference resolvable in observability pipeline | cross-ref M049 | F04857 | non-negotiable | false | 10 |
| R09672 | Field — trace-reference rejected if not found in trace store | cross-ref M049 | F04858 | non-negotiable | false | 10 |
| R09673 | Field — trace-reference indexed in commit receipt store | architecture + cross-ref M049 | F04859 | non-negotiable | false | 10 |
| R09674 | Validator — checks all 5 fields present | dump 17396-17402 | F04860 | non-negotiable | false | 10 |
| R09675 | Validator — checks all 5 fields well-formed | architecture | F04861 | non-negotiable | false | 10 |
| R09676 | Validator — checks all 5 fields signed | cross-ref MS003 | F04862 | non-negotiable | false | 10 |
| R09677 | Validator — failure halts commit | architecture | F04863 | non-negotiable | false | 10 |
| R09678 | Validator — failure emits OCSF Detection Finding class 2004 | cross-ref MS026 | F04864 | non-negotiable | false | 10 |
| R09679 | Signer — produces signed commit envelope | cross-ref MS003 | F04865 | non-negotiable | false | 10 |
| R09680 | Signer — envelope CBOR-encoded | architecture | F04866 | non-negotiable | false | 10 |
| R09681 | Signer — envelope includes type field | architecture + dump 17391-17398 | F04866 | non-negotiable | false | 10 |
| R09682 | Signer — envelope includes actor field | dump 17398 | F04866 | non-negotiable | false | 10 |
| R09683 | Signer — envelope includes reason field | dump 17399 | F04866 | non-negotiable | false | 10 |
| R09684 | Signer — envelope includes policy-decision field | dump 17400 | F04866 | non-negotiable | false | 10 |
| R09685 | Signer — envelope includes rollback-status field | dump 17401 | F04866 | non-negotiable | false | 10 |
| R09686 | Signer — envelope includes trace-reference field | dump 17402 | F04866 | non-negotiable | false | 10 |
| R09687 | Signer — envelope includes timestamp field | architecture | F04866 | non-negotiable | false | 10 |
| R09688 | Signer — envelope includes signature field | cross-ref MS003 | F04866 | non-negotiable | false | 10 |
| R09689 | Signer — signature uses MS003 selfdef-signing key | cross-ref MS003 | F04867 | non-negotiable | false | 10 |
| R09690 | Signer — envelope stored in /var/lib/selfdef/commits/ | architecture | F04868 | non-negotiable | false | 10 |
| R09691 | Signer — envelope retention 365 days minimum | cross-ref MS037 | F04869 | non-negotiable | false | 10 |
| R09692 | High-risk classifier — adapter promotion = high-risk (always) | dump 17415-17421 | F04871 | non-negotiable | false | 10 |
| R09693 | High-risk classifier — L6 Persist commits = high-risk (always) | cross-ref MS039 | F04872 | non-negotiable | false | 10 |
| R09694 | High-risk classifier — cloud exposure log = high-risk (always) | dump 17415-17421 + cross-ref MS038 | F04873 | non-negotiable | false | 10 |
| R09695 | High-risk classifier — production-profile L5 Commit = high-risk | cross-ref MS040 | F04874 | non-negotiable | false | 10 |
| R09696 | High-risk classifier — autonomous-profile L5 Commit outside predeclared gate = high-risk | cross-ref MS040 | F04875 | non-negotiable | false | 10 |
| R09697 | Gate snapshot — ZFS snapshot pre-commit | dump 17418 + cross-ref MS037 | F04876 | non-negotiable | false | 10 |
| R09698 | Gate snapshot — name selfdef-pre-commit-<commit-id> | architecture + cross-ref MS037 | F04877 | non-negotiable | false | 10 |
| R09699 | Gate snapshot — retained 365 days | cross-ref MS037 | F04878 | non-negotiable | false | 10 |
| R09700 | Gate snapshot — verified via zfs list before commit proceeds | architecture | F04879 | non-negotiable | false | 10 |
| R09701 | Gate snapshot — signature cited in commit envelope | cross-ref MS003 + cross-ref MS037 | F04880 | non-negotiable | false | 10 |
| R09702 | Gate test/eval — MS009 audit cycle + eval suite | dump 17419 + cross-ref MS009 | F04881 | non-negotiable | false | 10 |
| R09703 | Gate test/eval — result signed by eval service | cross-ref MS003 + cross-ref M048 | F04882 | non-negotiable | false | 10 |
| R09704 | Gate test/eval — digest cited in commit envelope | cross-ref MS003 + cross-ref MS009 | F04883 | non-negotiable | false | 10 |
| R09705 | Gate test/eval — failure halts commit | architecture | F04884 | non-negotiable | false | 10 |
| R09706 | Gate test/eval — timeout default 24h then auto-deny | architecture | F04885 | non-negotiable | false | 10 |
| R09707 | Gate oracle-or-human — sovereign-os oracle OR operator approval | dump 17420 | F04886 | non-negotiable | false | 10 |
| R09708 | Gate oracle-or-human — oracle response signed by oracle service key | cross-ref MS003 + cross-ref M048 | F04887 | non-negotiable | false | 10 |
| R09709 | Gate oracle-or-human — human approval signed by operator key | cross-ref MS003 + cross-ref MS007 | F04888 | non-negotiable | false | 10 |
| R09710 | Gate oracle-or-human — at least one must approve | dump 17420 | F04889 | non-negotiable | false | 10 |
| R09711 | Gate oracle-or-human — production profile requires BOTH oracle AND human | cross-ref MS040 | F04890 | non-negotiable | false | 10 |
| R09712 | Receipt store — every commit produces receipt with all 5 fields + gate digests | dump 17396-17421 | F04891 | non-negotiable | false | 10 |
| R09713 | Receipt store — receipts in CBOR format | architecture | F04892 | non-negotiable | false | 10 |
| R09714 | Receipt store — receipts signed via MS003 | cross-ref MS003 | F04893 | non-negotiable | false | 10 |
| R09715 | Receipt store — receipts retained 365 days minimum | cross-ref MS037 | F04894 | non-negotiable | false | 10 |
| R09716 | Receipt store — receipts indexed by commit-id | architecture | F04895 | non-negotiable | false | 10 |
| R09717 | Receipt store — receipts indexed by actor | architecture | F04895 | non-negotiable | false | 10 |
| R09718 | Receipt store — receipts indexed by trace-id | cross-ref M049 | F04895 | non-negotiable | false | 10 |
| R09719 | Receipt store — receipts indexed by commit type | architecture | F04895 | non-negotiable | false | 10 |
| R09720 | Receipt store — receipts queryable via MS007 typed-mirror interface | cross-ref MS007 | F04896 | non-negotiable | false | 10 |
| R09721 | Replay validator — verifies historical commit-chain integrity | cross-ref MS009 | F04897 | non-negotiable | false | 10 |
| R09722 | Replay validator — detects missing signatures | cross-ref MS003 | F04898 | non-negotiable | false | 10 |
| R09723 | Replay validator — detects malformed signatures | cross-ref MS003 | F04898 | non-negotiable | false | 10 |
| R09724 | Replay validator — detects gate-fields missing on historical high-risk commits | architecture | F04899 | non-negotiable | false | 10 |
| R09725 | Replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 | F04900 | non-negotiable | false | 10 |
| R09726 | Replay validator — runs daily as cron unit | cross-ref MS009 | F04901 | non-negotiable | false | 10 |
| R09727 | Replay validator — failures halt new high-risk commits until resolved | architecture | F04902 | non-negotiable | false | 10 |
| R09728 | Rollback engine — reverts L5 Commit via signed revert | cross-ref MS003 + cross-ref MS039 | F04903 | non-negotiable | false | 10 |
| R09729 | Rollback engine — reverts L6 Persist via signed revert | cross-ref MS003 + cross-ref MS039 | F04904 | non-negotiable | false | 10 |
| R09730 | Rollback engine — uses ZFS snapshot for file-write | cross-ref MS037 | F04905 | non-negotiable | false | 10 |
| R09731 | Rollback engine — uses memory-graph undo for memory-write | cross-ref M048 | F04906 | non-negotiable | false | 10 |
| R09732 | Rollback engine — uses prior-profile restore for profile-update | cross-ref MS040 | F04907 | non-negotiable | false | 10 |
| R09733 | Rollback engine — uses prior-adapter restore for adapter-promotion | cross-ref M046 | F04908 | non-negotiable | false | 10 |
| R09734 | Rollback engine — never silently drops state | cross-ref MS039 | F04909 | non-negotiable | false | 10 |
| R09735 | Rollback engine — emits OCSF Audit Activity class 1003 on revert | cross-ref MS026 | F04909 | non-negotiable | false | 10 |
| R09736 | Rollback engine — emits M049 trace span on revert | cross-ref M049 | F04909 | non-negotiable | false | 10 |
| R09737 | Typed-mirror — published under MS007 8/8 SATURATED scheme | cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09738 | Typed-mirror — CommitType enum has 8 variants matching dump | cross-ref MS007 + dump 17391-17398 | F04911 | non-negotiable | false | 10 |
| R09739 | Typed-mirror — CommitEnvelope struct fields match dump 5-field list | cross-ref MS007 + dump 17396-17402 | F04912 | non-negotiable | false | 10 |
| R09740 | Typed-mirror — HighRiskGates struct fields match dump 3-gate list | cross-ref MS007 + dump 17415-17421 | F04913 | non-negotiable | false | 10 |
| R09741 | Typed-mirror — RollbackStatus enum has 4 variants | cross-ref MS007 | F04914 | non-negotiable | false | 10 |
| R09742 | Typed-mirror — Rust crate name selfdef-commit-mirror | cross-ref MS007 | F04915 | non-negotiable | false | 10 |
| R09743 | Typed-mirror — re-exported via sovereign-os cargo workspace | cross-ref MS007 | F04915 | non-negotiable | false | 10 |
| R09744 | Typed-mirror — no_std friendly | architecture | F04915 | non-negotiable | false | 10 |
| R09745 | Typed-mirror — serde + bincode derives present | architecture | F04915 | non-negotiable | false | 10 |
| R09746 | Typed-mirror — schema_version "1.0.0" | cross-ref MS007 | F04915 | non-negotiable | false | 10 |
| R09747 | Event emitter — every commit emits M049 13-field span | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09748 | Event emitter — every commit emits OCSF event (type-dependent class) | cross-ref MS026 | F04917 | non-negotiable | false | 10 |
| R09749 | Event emitter — file-write → OCSF File System Activity class 1001 | cross-ref MS026 | F04805 | non-negotiable | false | 10 |
| R09750 | Event emitter — memory-write → OCSF Audit Activity class 1003 | cross-ref MS026 | F04809 | non-negotiable | false | 10 |
| R09751 | Event emitter — policy-update → OCSF Configuration Change class 5001 | cross-ref MS026 | F04813 | non-negotiable | false | 10 |
| R09752 | Event emitter — profile-update → OCSF Configuration Change class 5001 | cross-ref MS026 | F04817 | non-negotiable | false | 10 |
| R09753 | Event emitter — adapter-promotion → OCSF Configuration Change class 5001 | cross-ref MS026 | F04822 | non-negotiable | false | 10 |
| R09754 | Event emitter — cloud-exposure-log → OCSF Network Activity class 4001 cloud_exposure=true | cross-ref MS026 | F04826 | non-negotiable | false | 10 |
| R09755 | Event emitter — tool-side-effect → OCSF Audit Activity class 1003 | cross-ref MS026 | F04830 | non-negotiable | false | 10 |
| R09756 | Event emitter — workflow-completion → OCSF Configuration Change class 5001 | cross-ref MS026 | F04834 | non-negotiable | false | 10 |
| R09757 | Actor registry — actors keyed by MS003 key fingerprint | cross-ref MS003 | F04918 | non-negotiable | false | 10 |
| R09758 | Actor registry — registry signed via MS003 | cross-ref MS003 | F04919 | non-negotiable | false | 10 |
| R09759 | Actor registry — registry retained at /etc/selfdef/actors/registry.json | architecture | F04918 | non-negotiable | false | 10 |
| R09760 | Actor registry — registry reload on SIGHUP | architecture | F04918 | non-negotiable | false | 10 |
| R09761 | Operational — daemon refuses to start with no actor registry | architecture | F04918 | non-negotiable | false | 10 |
| R09762 | Operational — daemon refuses to start with chain-break in commit audit log | cross-ref MS009 | F04902 | non-negotiable | false | 10 |
| R09763 | Operational — daemon graceful drain on commit-queue shutdown | architecture | F04864 | non-negotiable | false | 10 |
| R09764 | Operational — daemon emits readiness probe at /run/selfdef/commit-ready | architecture | F04860 | non-negotiable | false | 10 |
| R09765 | Operational — daemon emits commit queue depth via M049 metric | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09766 | Operational — daemon emits commit latency histograms via M049 metrics | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09767 | Boundary — IPS handles commit-authority enforcement for its own mutations only | architecture + operator standing direction | F04801 | non-negotiable | false | 10 |
| R09768 | Boundary — sovereign-os runtime handles commit-authority for runtime mutations (M057) | cross-ref M057 + operator standing direction | F04831 | non-negotiable | false | 10 |
| R09769 | Boundary — info-hub knowledge layer treats commit-events as read-only context | operator standing direction | F04891 | non-negotiable | false | 10 |
| R09770 | Boundary — cross-repo commit semantics live in sovereign-os M056 | cross-ref M056 | F04910 | non-negotiable | false | 10 |
| R09771 | Composition — commit envelope composable with MS040 profile envelope | cross-ref MS040 | F04866 | non-negotiable | false | 10 |
| R09772 | Composition — commit envelope composable with MS039 authority FSM | cross-ref MS039 | F04866 | non-negotiable | false | 10 |
| R09773 | Composition — commit envelope composable with MS033 policy bus decision | cross-ref MS033 | F04866 | non-negotiable | false | 10 |
| R09774 | Composition — commit envelope composable with MS035 capability token | cross-ref MS035 | F04866 | non-negotiable | false | 10 |
| R09775 | Composition — commit envelope composable with MS036 sandbox attestation | cross-ref MS036 | F04866 | non-negotiable | false | 10 |
| R09776 | Composition — commit envelope composable with MS037 filesystem grant | cross-ref MS037 | F04866 | non-negotiable | false | 10 |
| R09777 | Composition — commit envelope composable with MS038 network grant | cross-ref MS038 | F04866 | non-negotiable | false | 10 |
| R09778 | Composition — commit envelope composable with MS034 communication grant | cross-ref MS034 | F04866 | non-negotiable | false | 10 |
| R09779 | Composition — commit envelope composable with MS009 audit cycle digest | cross-ref MS009 | F04866 | non-negotiable | false | 10 |
| R09780 | Composition — commit envelope composable with MS003 chain-of-trust | cross-ref MS003 | F04866 | non-negotiable | false | 10 |
| R09781 | Lifecycle — commit enters "drafting" state on creation | architecture | F04865 | non-negotiable | false | 10 |
| R09782 | Lifecycle — commit enters "validating" state on field check | architecture | F04860 | non-negotiable | false | 10 |
| R09783 | Lifecycle — commit enters "gated" state on high-risk classification | architecture + dump 17415-17421 | F04870 | non-negotiable | false | 10 |
| R09784 | Lifecycle — commit enters "approved" state on all gates pass | architecture | F04886 | non-negotiable | false | 10 |
| R09785 | Lifecycle — commit enters "applied" state on durable mutation | architecture + dump 17389 | F04891 | non-negotiable | false | 10 |
| R09786 | Lifecycle — commit enters "verified" state on post-commit verification pass | architecture + cross-ref MS039 | F04891 | non-negotiable | false | 10 |
| R09787 | Lifecycle — commit enters "reverted" state on rollback | cross-ref MS039 + cross-ref MS003 | F04903 | non-negotiable | false | 10 |
| R09788 | Lifecycle — every state transition emits M049 trace | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09789 | Lifecycle — every state transition signed via MS003 | cross-ref MS003 | F04865 | non-negotiable | false | 10 |
| R09790 | Lifecycle — state retained in commit receipt store 365 days | cross-ref MS037 | F04894 | non-negotiable | false | 10 |
| R09791 | Telemetry — commits-per-second per type emitted via M049 | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09792 | Telemetry — gate-failures-per-hour per type emitted via M049 | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09793 | Telemetry — average-gate-evaluation-latency per type emitted via M049 | cross-ref M049 | F04916 | non-negotiable | false | 10 |
| R09794 | Telemetry — rollback-rate per type emitted via M049 | cross-ref M049 | F04903 | non-negotiable | false | 10 |
| R09795 | Telemetry — high-risk-classification-rate emitted via M049 | cross-ref M049 | F04870 | non-negotiable | false | 10 |
| R09796 | Compliance — every commit citation chain back to dump line resolvable | architecture + operator standing direction | F04891 | non-negotiable | false | 10 |
| R09797 | Compliance — no invented commit types beyond 8 enumerated in dump | dump 17391-17398 + operator standing direction | F04801 | non-negotiable | false | 10 |
| R09798 | Compliance — no invented mandatory fields beyond 5 enumerated in dump | dump 17396-17402 + operator standing direction | F04860 | non-negotiable | false | 10 |
| R09799 | Compliance — no invented gates beyond 3 enumerated in dump for high-risk | dump 17415-17421 + operator standing direction | F04870 | non-negotiable | false | 10 |
| R09800 | Compliance — additional fields permitted only as extensions, never replacements | architecture + operator standing direction | F04866 | non-negotiable | false | 10 |
| R09801 | Schema — commit envelope schema_version "1.0.0" | cross-ref MS007 | F04866 | non-negotiable | false | 10 |
| R09802 | Schema — commit envelope schema fields ordered deterministically | architecture | F04866 | non-negotiable | false | 10 |
| R09803 | Schema — commit envelope schema published in MS007 typed-mirror crate | cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09804 | Schema — commit envelope schema breaking changes require schema_version bump | architecture | F04866 | non-negotiable | false | 10 |
| R09805 | Schema — commit envelope schema validated at signer | architecture + cross-ref MS003 | F04865 | non-negotiable | false | 10 |
| R09806 | Failure recovery — gate timeout emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04885 | non-negotiable | false | 10 |
| R09807 | Failure recovery — gate timeout retains commit in "gated" state | architecture | F04885 | non-negotiable | false | 10 |
| R09808 | Failure recovery — gate timeout reopens after operator nudge | architecture + cross-ref MS007 | F04885 | non-negotiable | false | 10 |
| R09809 | Failure recovery — apply failure auto-rollback (file write only) | cross-ref MS037 | F04905 | non-negotiable | false | 10 |
| R09810 | Failure recovery — apply failure preserves snapshot for forensics | cross-ref MS037 | F04877 | non-negotiable | false | 10 |
| R09811 | Cross-boundary — file write commit MUST be preceded by MS037 filesystem-grant L4 issuance | cross-ref MS037 | F04801 | non-negotiable | false | 10 |
| R09812 | Cross-boundary — memory write commit MUST be preceded by capability token validation | cross-ref MS035 | F04806 | non-negotiable | false | 10 |
| R09813 | Cross-boundary — policy update commit MUST be preceded by MS033 policy bus quorum | cross-ref MS033 | F04810 | non-negotiable | false | 10 |
| R09814 | Cross-boundary — profile update commit MUST be preceded by MS040 profile envelope check | cross-ref MS040 | F04814 | non-negotiable | false | 10 |
| R09815 | Cross-boundary — adapter promotion commit MUST be preceded by M046 LoRA Foundry crystallization gate | cross-ref M046 | F04818 | non-negotiable | false | 10 |
| R09816 | Cross-boundary — cloud exposure log commit MUST be preceded by MS038 Ring 4 grant | cross-ref MS038 + cross-ref MS039 | F04823 | non-negotiable | false | 10 |
| R09817 | Cross-boundary — tool side effect commit MUST be preceded by MS036 tool tier attestation | cross-ref MS036 | F04827 | non-negotiable | false | 10 |
| R09818 | Cross-boundary — workflow completion commit MUST be preceded by M057 step-11 Learn completion | cross-ref M057 | F04831 | non-negotiable | false | 10 |
| R09819 | Doctrinal preservation — dump 17389 "A commit is any durable change" verbatim in commit-mirror crate doc | dump 17389 + cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09820 | Doctrinal preservation — dump 17396-17402 5-field list verbatim in commit-mirror crate doc | dump 17396-17402 + cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09821 | Doctrinal preservation — dump 17415-17421 3-gate list verbatim in commit-mirror crate doc | dump 17415-17421 + cross-ref MS007 | F04913 | non-negotiable | false | 10 |
| R09822 | Doctrinal preservation — dump 17391-17398 8-type list verbatim in commit-mirror crate doc | dump 17391-17398 + cross-ref MS007 | F04911 | non-negotiable | false | 10 |
| R09823 | Doctrinal preservation — commit envelope JSON Schema published with verbatim dump quotes | architecture + cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09824 | Doctrinal preservation — commit-mirror crate documentation tests assert verbatim quotes | architecture + cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09825 | Doctrinal preservation — commit-mirror crate version published under selfdef-signing | cross-ref MS003 + cross-ref MS007 | F04910 | non-negotiable | false | 10 |
| R09826 | Doctrinal preservation — info-hub knowledge graph indexes verbatim quotes via knowledge entries | operator standing direction (knowledge = second-brain) | F04910 | non-negotiable | false | 10 |
| R09827 | Doctrinal preservation — verbatim quotes never paraphrased in any selfdef artifact | operator standing direction | F04910 | non-negotiable | false | 10 |
| R09828 | Doctrinal preservation — verbatim quotes layered (additive) when new dumps redefine | operator standing direction | F04910 | non-negotiable | false | 10 |
| R09829 | Closing — 8 commit types cover dump 17391-17398 every line | dump 17391-17398 | F04801 | non-negotiable | false | 10 |
| R09830 | Closing — 5 mandatory fields cover dump 17396-17402 every line | dump 17396-17402 | F04860 | non-negotiable | false | 10 |
| R09831 | Closing — 3 high-risk gates cover dump 17415-17421 every line | dump 17415-17421 | F04870 | non-negotiable | false | 10 |
| R09832 | Closing — commit-authority arc fully cataloged in IPS-side projection | dump 17389-17421 + operator standing direction | F04891 | non-negotiable | false | 10 |
| R09833 | Closing — sovereign-os retains canonical commit-authority semantics | operator standing direction + cross-ref M056 | F04910 | non-negotiable | false | 10 |
| R09834 | Closing — cross-repo binding only through MS007 selfdef-commit-mirror | cross-ref MS007 + operator standing direction | F04910 | non-negotiable | false | 10 |
| R09835 | Closing — no invented commit types beyond dump enumeration | operator standing direction | F04801 | non-negotiable | false | 10 |
| R09836 | Closing — no invented mandatory fields beyond dump enumeration | operator standing direction | F04860 | non-negotiable | false | 10 |
| R09837 | Closing — no invented gates beyond dump enumeration | operator standing direction | F04870 | non-negotiable | false | 10 |
| R09838 | Closing — every R-row carries 10 hard non-negotiable sub-requirements | operator standing direction | F04801 | non-negotiable | false | 10 |
| R09839 | Closing — total enforced sub-reqs for MS041 = 240 × 10 = 2400 | operator standing direction | F04801 | non-negotiable | false | 10 |
| R09840 | Closing — MS041 catalog complete; alternation continues to MS042 (Tool authority) | architecture + operator standing direction | F04801 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements per operator standing direction. Total enforced sub-reqs = 240 R × 10 = **2,400 sub-requirements** for MS041.

## Cross-references

- **sovereign-os M046** — runtime adaptation + LoRA Foundry (adapter promotion commit type)
- **sovereign-os M048** — modules map (memory service / eval service signer keys)
- **sovereign-os M049** — observability + trace pipeline (trace-reference field)
- **sovereign-os M054** — typed interfaces (commit-mirror crate consumed)
- **sovereign-os M056** — trust boundaries + authority levels (canonical commit-authority arc)
- **sovereign-os M057** — 12-step task lifecycle (workflow completion commit type)
- **sovereign-os M058** — hardware-aware scheduler (oracle gate consumes Blackwell)
- **MS003** — selfdef-signing (signs every commit envelope, every gate digest)
- **MS007** — typed-mirror crate scheme (selfdef-commit-mirror)
- **MS009** — audit cycles + replay validator
- **MS026** — observability + OCSF event emission
- **MS033** — policy bus (policy-decision field)
- **MS034-MS038** — Communication / Capability / Sandbox / Filesystem / Network boundaries (cross-boundary precondition checks)
- **MS039** — Authority levels + trust rings (L5 Commit + L6 Persist arc)
- **MS040** — Six-profile authority matrix (production-profile + autonomous-profile high-risk classification)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS041
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines: 17389-17421
cross_repo_mirror: sovereign-os/M056
typed_mirror_crate: selfdef-commit-mirror
commit_types:
  - file_write
  - memory_write
  - policy_update
  - profile_update
  - adapter_promotion
  - cloud_exposure_log
  - tool_side_effect
  - workflow_completion
mandatory_fields:
  - actor
  - reason
  - policy_decision
  - rollback_status
  - trace_reference
high_risk_gates:
  - snapshot
  - test_eval
  - oracle_or_human
```
