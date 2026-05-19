# MS039 — Authority levels (L0..L6) and trust rings (Ring 0..4) — IPS-side projection

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 17215-17532 (Trust boundaries + Authority Model + Authority Levels + Trust Rings + Model Trust Contextual + Cloud Trust + Memory Trust + The Key Rule "Authority follows evidence")
**Cross-repo mirror**: sovereign-os M056 (canonical authority model) — selfdef receives this canon through MS007 typed mirrors only; this milestone projects the authority arc onto the IPS daemon's own boundary enforcement
**Project boundary**: this milestone scopes ONLY the IPS-side enforcement representation of L0..L6 + Ring 0..4 — the runtime/gateway authority arc itself lives in sovereign-os M056

## Projection statement

> "A model can request authority. It cannot grant itself authority." (dump 17249)

Selfdef IPS daemon is the **enforcement organ** for the network / filesystem / communication / capability / sandbox boundaries cataloged in MS034-MS038. Every mutation crossing those boundaries — adding a network rule, mounting a filesystem path, minting a capability token, promoting a sandbox tier — is itself a **commit** in the authority arc. This milestone catalogs how the IPS represents the seven authority levels (Observe / Suggest / Simulate / Prepare / Execute bounded / Commit / Persist) and the five trust rings (Sovereign Kernel / Trusted Local / Sandboxed Agents / Experimental / Cloud-External) for its own mutations, traffic segmentation, and policy decisions.

## Epics (E0391-E0400)

| epic | name | source |
|---|---|---|
| E0391 | Authority Level L0 Observe — IPS read-only enforcement, passive sniffer, no side effects | dump 17252-17254 |
| E0392 | Authority Level L1 Suggest — IPS candidate generation, proposal records, no execution | dump 17255-17257 |
| E0393 | Authority Level L2 Simulate — IPS shadow filter, sandboxed evaluation, no host mutation | dump 17258-17260 |
| E0394 | Authority Level L3 Prepare — IPS staged rules, pending operator approval | dump 17261-17263 |
| E0395 | Authority Level L4 Execute-bounded — IPS active filter within policy envelope | dump 17264-17266 |
| E0396 | Authority Level L5 Commit — IPS durable mutation of ruleset / policy / capability registry | dump 17267-17269 |
| E0397 | Authority Level L6 Persist — IPS profile / adapter / signed manifest updates | dump 17270-17272 |
| E0398 | Trust Rings 0-4 — IPS-side ring assignment for traffic, processes, and namespaces | dump 17280-17302 |
| E0399 | "Authority follows evidence" — evidence-gated transitions L0→L1→...→L6 within selfdef enforcement | dump 17501-17517 |
| E0400 | IPS-side authority taxonomy mirror — MS007 typed crate for cross-repo binding | cross-ref MS007 |

## Modules (M00993-M01018)

| module | name | source |
|---|---|---|
| M00993 | selfdef-authority-l0-observer | dump 17252-17254 + cross-ref MS026 |
| M00994 | selfdef-authority-l1-suggester | dump 17255-17257 + cross-ref MS033 |
| M00995 | selfdef-authority-l2-simulator | dump 17258-17260 + cross-ref MS032 |
| M00996 | selfdef-authority-l3-preparator | dump 17261-17263 + cross-ref MS033 |
| M00997 | selfdef-authority-l4-executor | dump 17264-17266 + cross-ref MS024 |
| M00998 | selfdef-authority-l5-committer | dump 17267-17269 + cross-ref MS003 |
| M00999 | selfdef-authority-l6-persister | dump 17270-17272 + cross-ref MS003 + MS007 |
| M01000 | selfdef-trust-ring0-kernel | dump 17280-17284 + cross-ref MS037 |
| M01001 | selfdef-trust-ring1-local-services | dump 17285-17287 + cross-ref MS016 |
| M01002 | selfdef-trust-ring2-sandboxed-agents | dump 17288-17290 + cross-ref MS036 |
| M01003 | selfdef-trust-ring3-experimental | dump 17291-17293 + cross-ref MS032 |
| M01004 | selfdef-trust-ring4-cloud-external | dump 17294-17302 + cross-ref MS038 |
| M01005 | selfdef-authority-transition-evaluator | dump 17501-17517 + architecture |
| M01006 | selfdef-authority-evidence-collector | dump 17501-17517 + cross-ref MS026 |
| M01007 | selfdef-authority-gate-coordinator | dump 17501-17517 + cross-ref MS033 |
| M01008 | selfdef-ring-transition-policy | dump 17302 + cross-ref MS033 |
| M01009 | selfdef-ring-membership-registry | architecture + cross-ref MS035 |
| M01010 | selfdef-authority-trace-emitter | cross-ref MS026 + M049 |
| M01011 | selfdef-authority-rollback-engine | dump 17269 + cross-ref MS003 |
| M01012 | selfdef-authority-snapshot-bridge | dump 17415-17421 + cross-ref MS037 |
| M01013 | selfdef-authority-policy-decision-cache | cross-ref MS033 + dump 17501-17517 |
| M01014 | selfdef-authority-typed-mirror-crate | cross-ref MS007 |
| M01015 | selfdef-authority-level-fsm | architecture + dump 17252-17272 |
| M01016 | selfdef-ring-isolation-namespace-allocator | cross-ref MS037 + MS038 |
| M01017 | selfdef-authority-receipt-store | cross-ref MS003 + MS026 |
| M01018 | selfdef-authority-replay-validator | cross-ref MS003 + MS009 |

## Features (F04561-F04680)

| feature | name | source |
|---|---|---|
| F04561 | L0 observer attaches to network boundary via passive eBPF | dump 17252-17254 + cross-ref MS024 |
| F04562 | L0 observer attaches to filesystem boundary via fanotify FAN_REPORT_FID | dump 17252 + cross-ref MS037 |
| F04563 | L0 observer attaches to capability bus via libnetfilter_queue read-only | dump 17252 + cross-ref MS035 |
| F04564 | L0 observer emits OCSF System Activity class 1001 (no mutation) | dump 17252 + cross-ref MS026 |
| F04565 | L0 observer load = bounded `<=` 1% CPU overhead | architecture + dump 17252 |
| F04566 | L1 suggester generates rule candidates from observed traffic | dump 17255-17257 |
| F04567 | L1 suggester writes proposals to /var/lib/selfdef/proposals/ | architecture + dump 17255 |
| F04568 | L1 suggester never installs nftables rules directly | dump 17255-17257 |
| F04569 | L1 suggester emits proposal-id + trace-id for every candidate | architecture + dump 17256 |
| F04570 | L1 suggester proposals carry M049 16-event taxonomy classification | cross-ref M049 + dump 17255 |
| F04571 | L2 simulator runs candidate rules in shadow netns | dump 17258-17260 + cross-ref MS032 |
| F04572 | L2 simulator runs filesystem candidates in disposable overlay | dump 17258 + cross-ref MS037 |
| F04573 | L2 simulator captures false-positive / false-negative rates | dump 17258-17260 |
| F04574 | L2 simulator emits OCSF Audit Activity class 1003 | dump 17259 + cross-ref MS026 |
| F04575 | L2 simulator never mutates host state | dump 17260 |
| F04576 | L3 preparator stages candidate rules as draft files | dump 17261-17263 |
| F04577 | L3 preparator signs draft with operator preview key | dump 17262 + cross-ref MS003 |
| F04578 | L3 preparator presents diff via operator dashboard surface | dump 17263 + cross-ref MS007 |
| F04579 | L3 preparator records pending-approval timestamp + actor | dump 17263 + architecture |
| F04580 | L3 preparator never auto-promotes without approval | dump 17263 + dump 17249 |
| F04581 | L4 executor applies bounded-scope nftables rules | dump 17264-17266 + cross-ref MS024 |
| F04582 | L4 executor applies bounded-scope fanotify policy | dump 17264 + cross-ref MS037 |
| F04583 | L4 executor enforces TTL on every applied rule | dump 17266 + cross-ref MS038 |
| F04584 | L4 executor emits OCSF Network Activity class 4001 | dump 17265 + cross-ref MS026 |
| F04585 | L4 executor reverts rule on TTL expiry | dump 17266 + cross-ref MS038 |
| F04586 | L5 committer persists durable ruleset to /etc/selfdef/policy.d/ | dump 17267-17269 |
| F04587 | L5 committer signs ruleset with selfdef-signing | dump 17268 + cross-ref MS003 |
| F04588 | L5 committer records actor/reason/policy-decision/rollback-status/trace-ref | dump 17268 + dump 17396-17402 |
| F04589 | L5 committer integrates with snapshot pre-commit hook | dump 17415-17421 + cross-ref MS037 |
| F04590 | L5 committer rolls back on post-commit verification failure | dump 17269 + architecture |
| F04591 | L6 persister updates IPS profile catalog | dump 17270-17272 |
| F04592 | L6 persister updates LoRA-driven traffic-classifier adapter | dump 17271 + cross-ref M046 |
| F04593 | L6 persister updates signed manifest exposed via MS007 mirrors | dump 17272 + cross-ref MS007 |
| F04594 | L6 persister requires operator + oracle gate combination | dump 17415-17421 |
| F04595 | L6 persister emits OCSF Configuration Change class 5001 | dump 17272 + cross-ref MS026 |
| F04596 | Ring 0 kernel = IPS daemon + nftables + kernel modules | dump 17280-17284 + cross-ref MS037 |
| F04597 | Ring 0 kernel processes run as PID 1 child or systemd unit with CAP_SYS_ADMIN | dump 17282 + architecture |
| F04598 | Ring 0 kernel traffic exempt from L0 observer recursion | dump 17282 + architecture |
| F04599 | Ring 0 kernel mutates ruleset only via L5/L6 commit pipeline | dump 17283 + dump 17269 |
| F04600 | Ring 0 kernel exports state read-only to other rings | dump 17284 + cross-ref MS035 |
| F04601 | Ring 1 trusted local services = sovereign-os runtime + memory service + eval service | dump 17285-17287 |
| F04602 | Ring 1 access to IPS via signed cap-token | dump 17286 + cross-ref MS035 |
| F04603 | Ring 1 traffic placed in selfdef-ring1 netns | dump 17287 + cross-ref MS038 |
| F04604 | Ring 1 cannot escalate to Ring 0 without explicit policy | dump 17302 |
| F04605 | Ring 1 trust scope encoded in 8-bit capability_word.trust_ring | cross-ref MS035 + dump 17287 |
| F04606 | Ring 2 sandboxed agents = build/test containers + browser agents + tool workers | dump 17288-17290 |
| F04607 | Ring 2 traffic placed in selfdef-ring2 netns with default-deny | dump 17288 + cross-ref MS038 |
| F04608 | Ring 2 filesystem in disposable overlay | dump 17288 + cross-ref MS037 |
| F04609 | Ring 2 sandbox enforced via MS036 Tier B or Tier C | cross-ref MS036 + dump 17289 |
| F04610 | Ring 2 cannot direct-write to Ring 0 ruleset | dump 17302 |
| F04611 | Ring 3 experimental = unknown code, external downloads, risky web | dump 17291-17293 |
| F04612 | Ring 3 traffic placed in selfdef-ring3 netns with TLS-only egress | dump 17291 + cross-ref MS023 |
| F04613 | Ring 3 sandbox enforced via MS036 Tier D disposable microVM | cross-ref MS036 + dump 17292 |
| F04614 | Ring 3 cannot reach Ring 1 services without explicit grant | dump 17293 + dump 17302 |
| F04615 | Ring 3 outputs marked exposure-tainted | architecture + cross-ref MS037 |
| F04616 | Ring 4 cloud-external = remote APIs, external services, internet | dump 17294-17302 |
| F04617 | Ring 4 traffic placed in selfdef-ring4 netns with explicit FQDN allowlist | dump 17294 + cross-ref MS038 |
| F04618 | Ring 4 enforced redaction at egress per allowed/restricted lists | dump 17354-17372 + cross-ref MS023 |
| F04619 | Ring 4 traffic emits OCSF Network Activity class 4001 with cloud_exposure=true | dump 17302 + cross-ref MS026 |
| F04620 | Ring 4 grants carry explicit TTL + operator approval | dump 17302 + cross-ref MS038 |
| F04621 | Authority transition L0→L1 evidence = observation-count threshold | dump 17501-17517 |
| F04622 | Authority transition L1→L2 evidence = candidate signature + non-conflict check | dump 17501-17517 + cross-ref MS003 |
| F04623 | Authority transition L2→L3 evidence = sandbox simulation pass | dump 17501-17517 + cross-ref MS032 |
| F04624 | Authority transition L3→L4 evidence = operator approval | dump 17501-17517 |
| F04625 | Authority transition L4→L5 evidence = TTL expiration + verified absence of regression | dump 17501-17517 + cross-ref MS026 |
| F04626 | Authority transition L5→L6 evidence = oracle gate + persistence-impact analysis | dump 17501-17517 + dump 17415-17421 |
| F04627 | Authority transition L6→L5 (demotion) evidence = signed rollback receipt | architecture + cross-ref MS003 |
| F04628 | Authority transition L5→L4 (demotion) evidence = revert-token from policy bus | cross-ref MS033 + architecture |
| F04629 | Authority transitions emit M049 trace event with 13-field span | cross-ref M049 + dump 17501-17517 |
| F04630 | Authority transitions never bypass M033 policy bus | cross-ref MS033 + dump 17249 |
| F04631 | Ring transition Ring 1→Ring 0 = forbidden without operator manual approval | dump 17302 |
| F04632 | Ring transition Ring 2→Ring 1 = requires signed promotion artifact | dump 17302 + cross-ref MS003 |
| F04633 | Ring transition Ring 3→Ring 2 = requires sandbox-pass + policy-bus decision | dump 17302 + cross-ref MS033 |
| F04634 | Ring transition Ring 4→Ring 3 = forbidden (cloud cannot collapse into local) | dump 17294-17302 |
| F04635 | Ring transition emits OCSF Configuration Change class 5001 | cross-ref MS026 + dump 17302 |
| F04636 | Authority evidence collector aggregates eBPF traces | cross-ref MS024 + dump 17501-17517 |
| F04637 | Authority evidence collector aggregates fanotify events | cross-ref MS037 + dump 17501-17517 |
| F04638 | Authority evidence collector aggregates audit-cycle results | cross-ref MS009 + dump 17501-17517 |
| F04639 | Authority evidence collector preserves provenance chain | architecture + cross-ref MS003 |
| F04640 | Authority evidence collector emits structured evidence bundle | architecture + dump 17501-17517 |
| F04641 | Authority gate coordinator multiplexes per-level gates | architecture + dump 17501-17517 |
| F04642 | Authority gate coordinator integrates with operator dashboard surface | cross-ref MS007 + dump 17263 |
| F04643 | Authority gate coordinator integrates with sovereign-os policy bus | cross-ref MS033 + dump 17249 |
| F04644 | Authority gate coordinator never auto-approves above L4 | dump 17263 + dump 17249 |
| F04645 | Authority gate coordinator records gate-decision + actor + timestamp | architecture + dump 17501-17517 |
| F04646 | Ring isolation = Linux namespace allocation per ring | architecture + cross-ref MS037 |
| F04647 | Ring isolation = nftables chain per ring | cross-ref MS024 + dump 17288-17302 |
| F04648 | Ring isolation = cgroup v2 hierarchy per ring | architecture + cross-ref MS045 |
| F04649 | Ring isolation = SELinux/AppArmor profile per ring (where applicable) | architecture + cross-ref MS037 |
| F04650 | Ring isolation = unique UID range per ring | architecture |
| F04651 | Capability tokens carry trust_ring 3-bit field | cross-ref MS035 + dump 17287 |
| F04652 | Capability tokens carry authority_level 3-bit field | cross-ref MS035 + dump 17252-17272 |
| F04653 | Capability tokens carry evidence_digest 32-byte field | cross-ref MS035 + dump 17501-17517 |
| F04654 | Capability tokens reject mismatched ring + level pairs | cross-ref MS035 + dump 17302 |
| F04655 | Capability tokens emit M049 trace on every redemption | cross-ref M049 + cross-ref MS035 |
| F04656 | Authority trace emitter is M049-compliant 13-field span | cross-ref M049 + dump 17501-17517 |
| F04657 | Authority trace emitter records before-level + after-level | architecture + dump 17501-17517 |
| F04658 | Authority trace emitter records before-ring + after-ring | architecture + dump 17302 |
| F04659 | Authority trace emitter is replay-safe (deterministic field order) | cross-ref MS009 + architecture |
| F04660 | Authority trace emitter routes to M049 observability pipeline | cross-ref M049 |
| F04661 | Authority rollback engine reverts L5 commits via signed revert | dump 17269 + cross-ref MS003 |
| F04662 | Authority rollback engine reverts L6 persistences via signed revert | dump 17272 + cross-ref MS003 |
| F04663 | Authority rollback engine integrates with ZFS snapshot bridge | dump 17415-17421 + cross-ref MS037 |
| F04664 | Authority rollback engine emits OCSF Audit Activity class 1003 | cross-ref MS026 + dump 17269 |
| F04665 | Authority rollback engine never silently drops state | architecture + dump 17269 |
| F04666 | Authority typed-mirror crate published under MS007 8/8 SATURATED scheme | cross-ref MS007 |
| F04667 | Authority typed-mirror exposes AuthorityLevel enum L0..L6 | cross-ref MS007 + dump 17252-17272 |
| F04668 | Authority typed-mirror exposes TrustRing enum Ring0..Ring4 | cross-ref MS007 + dump 17280-17302 |
| F04669 | Authority typed-mirror exposes AuthorityTransition struct | cross-ref MS007 + dump 17501-17517 |
| F04670 | Authority typed-mirror exposes RingMembership struct | cross-ref MS007 + dump 17287-17302 |
| F04671 | Authority FSM has exactly 7 states (L0..L6) | architecture + dump 17252-17272 |
| F04672 | Authority FSM transitions are append-only audit log | architecture + cross-ref MS009 |
| F04673 | Authority FSM transitions all signed via MS003 | cross-ref MS003 |
| F04674 | Authority receipt store keeps last 100 days of transitions | architecture + cross-ref MS037 |
| F04675 | Authority receipt store integrates with MS009 replay validator | cross-ref MS009 |
| F04676 | Authority replay validator verifies historical transition chain | cross-ref MS009 + architecture |
| F04677 | Authority replay validator detects chain breaks | cross-ref MS009 + cross-ref MS003 |
| F04678 | Authority replay validator emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 + cross-ref MS009 |
| F04679 | Authority decision cache TTL = 60s for L0-L2 | architecture + dump 17501-17517 |
| F04680 | Authority decision cache TTL = 0 (no cache) for L4-L6 | architecture + dump 17263-17272 |

## Requirements (R09121-R09360)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R09121 | Doctrinal — "A model can request authority. It cannot grant itself authority." | dump 17249 | F04644 | non-negotiable | false | 10 |
| R09122 | Doctrinal — Nothing should have ambient authority | dump 17220 | F04644 | non-negotiable | false | 10 |
| R09123 | Doctrinal — Authority follows evidence | dump 17501 | F04621 | non-negotiable | false | 10 |
| R09124 | Doctrinal — A branch earns more authority by passing checks | dump 17503-17510 | F04621 | non-negotiable | false | 10 |
| R09125 | Doctrinal — Capable because authority is granular | dump 17524 | F04652 | non-negotiable | false | 10 |
| R09126 | Doctrinal — Safe because authority is earned and observable | dump 17525 | F04656 | non-negotiable | false | 10 |
| R09127 | Doctrinal — That is the sovereign design | dump 17527 | F04666 | non-negotiable | false | 10 |
| R09128 | Doctrinal — Movement between rings requires explicit policy | dump 17302 | F04604 | non-negotiable | false | 10 |
| R09129 | Doctrinal — Different profiles allow different maximum levels | dump 17274 | F04644 | non-negotiable | false | 10 |
| R09130 | Doctrinal — Cloud is not forbidden. It is scoped. | dump 17312 | F04616 | non-negotiable | false | 10 |
| R09131 | L0 Observe — read-only, no side effects | dump 17252-17254 | F04564 | non-negotiable | false | 10 |
| R09132 | L0 Observe — attach to network boundary via passive eBPF kprobe | dump 17252 + cross-ref MS024 | F04561 | non-negotiable | false | 10 |
| R09133 | L0 Observe — attach to filesystem boundary via fanotify FAN_REPORT_FID | dump 17252 + cross-ref MS037 | F04562 | non-negotiable | false | 10 |
| R09134 | L0 Observe — attach to capability bus via libnetfilter_queue read-only | dump 17252 + cross-ref MS035 | F04563 | non-negotiable | false | 10 |
| R09135 | L0 Observe — never installs nftables rules | dump 17253 | F04561 | non-negotiable | false | 10 |
| R09136 | L0 Observe — never mutates filesystem state | dump 17253 + cross-ref MS037 | F04562 | non-negotiable | false | 10 |
| R09137 | L0 Observe — never mutates capability registry | dump 17253 + cross-ref MS035 | F04563 | non-negotiable | false | 10 |
| R09138 | L0 Observe — emits OCSF System Activity class 1001 (observation) | cross-ref MS026 | F04564 | non-negotiable | false | 10 |
| R09139 | L0 Observe — CPU overhead `<=` 1% of host budget | architecture | F04565 | non-negotiable | false | 10 |
| R09140 | L0 Observe — observations persist to /var/lib/selfdef/observations/ | architecture | F04564 | non-negotiable | false | 10 |
| R09141 | L1 Suggest — generates rule candidates from observed traffic | dump 17255-17257 | F04566 | non-negotiable | false | 10 |
| R09142 | L1 Suggest — writes proposals to /var/lib/selfdef/proposals/ | architecture | F04567 | non-negotiable | false | 10 |
| R09143 | L1 Suggest — never installs nftables rules directly | dump 17256 | F04568 | non-negotiable | false | 10 |
| R09144 | L1 Suggest — emits proposal-id (ULID) for every candidate | architecture | F04569 | non-negotiable | false | 10 |
| R09145 | L1 Suggest — emits trace-id for every candidate | cross-ref M049 | F04569 | non-negotiable | false | 10 |
| R09146 | L1 Suggest — candidate carries M049 16-event taxonomy classification | cross-ref M049 | F04570 | non-negotiable | false | 10 |
| R09147 | L1 Suggest — candidate signed with selfdef-signing | cross-ref MS003 | F04566 | non-negotiable | false | 10 |
| R09148 | L1 Suggest — candidate carries originating observation digest | cross-ref MS003 | F04566 | non-negotiable | false | 10 |
| R09149 | L1 Suggest — candidate lifetime default 24h | architecture | F04566 | non-negotiable | false | 10 |
| R09150 | L1 Suggest — candidate auto-discarded if no L2→L3 progression in 7 days | architecture | F04566 | non-negotiable | false | 10 |
| R09151 | L2 Simulate — runs candidate rules in shadow netns | dump 17258-17260 + cross-ref MS032 | F04571 | non-negotiable | false | 10 |
| R09152 | L2 Simulate — runs filesystem candidates in disposable overlay | dump 17258 + cross-ref MS037 | F04572 | non-negotiable | false | 10 |
| R09153 | L2 Simulate — captures false-positive rate | dump 17258-17260 | F04573 | non-negotiable | false | 10 |
| R09154 | L2 Simulate — captures false-negative rate | dump 17258-17260 | F04573 | non-negotiable | false | 10 |
| R09155 | L2 Simulate — emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04574 | non-negotiable | false | 10 |
| R09156 | L2 Simulate — never mutates host state | dump 17260 | F04575 | non-negotiable | false | 10 |
| R09157 | L2 Simulate — simulation window bounded `<=` 60s default | architecture | F04571 | non-negotiable | false | 10 |
| R09158 | L2 Simulate — replays captured traffic from L0 observer | architecture | F04571 | non-negotiable | false | 10 |
| R09159 | L2 Simulate — simulation result digest signed via MS003 | cross-ref MS003 | F04573 | non-negotiable | false | 10 |
| R09160 | L2 Simulate — simulation digest cited in L3 staging | architecture | F04576 | non-negotiable | false | 10 |
| R09161 | L3 Prepare — stages candidate rules as draft files | dump 17261-17263 | F04576 | non-negotiable | false | 10 |
| R09162 | L3 Prepare — signs draft with operator preview key | cross-ref MS003 | F04577 | non-negotiable | false | 10 |
| R09163 | L3 Prepare — presents diff via operator dashboard surface | cross-ref MS007 | F04578 | non-negotiable | false | 10 |
| R09164 | L3 Prepare — diff format = unified context with 3-line buffer | architecture | F04578 | non-negotiable | false | 10 |
| R09165 | L3 Prepare — records pending-approval timestamp | architecture | F04579 | non-negotiable | false | 10 |
| R09166 | L3 Prepare — records pending-approval actor (proposer ID) | architecture | F04579 | non-negotiable | false | 10 |
| R09167 | L3 Prepare — never auto-promotes without approval | dump 17263 | F04580 | non-negotiable | false | 10 |
| R09168 | L3 Prepare — staged file path /etc/selfdef/policy.d/pending/ | architecture | F04576 | non-negotiable | false | 10 |
| R09169 | L3 Prepare — staging integrated with M049 trace emission | cross-ref M049 | F04576 | non-negotiable | false | 10 |
| R09170 | L3 Prepare — staging expires after 30 days of no operator action | architecture | F04576 | non-negotiable | false | 10 |
| R09171 | L4 Execute-bounded — applies bounded-scope nftables rules | dump 17264-17266 + cross-ref MS024 | F04581 | non-negotiable | false | 10 |
| R09172 | L4 Execute-bounded — applies bounded-scope fanotify policy | dump 17264 + cross-ref MS037 | F04582 | non-negotiable | false | 10 |
| R09173 | L4 Execute-bounded — applies bounded-scope capability mints | dump 17264 + cross-ref MS035 | F04581 | non-negotiable | false | 10 |
| R09174 | L4 Execute-bounded — enforces TTL on every applied rule | dump 17266 + cross-ref MS038 | F04583 | non-negotiable | false | 10 |
| R09175 | L4 Execute-bounded — TTL default = 60s | cross-ref MS038 | F04583 | non-negotiable | false | 10 |
| R09176 | L4 Execute-bounded — TTL maximum = 3600s without operator approval | cross-ref MS038 | F04583 | non-negotiable | false | 10 |
| R09177 | L4 Execute-bounded — TTL maximum = 86400s (24h) with operator approval | cross-ref MS038 | F04583 | non-negotiable | false | 10 |
| R09178 | L4 Execute-bounded — emits OCSF Network Activity class 4001 | cross-ref MS026 | F04584 | non-negotiable | false | 10 |
| R09179 | L4 Execute-bounded — reverts rule on TTL expiry | dump 17266 + cross-ref MS038 | F04585 | non-negotiable | false | 10 |
| R09180 | L4 Execute-bounded — reverts rule on policy bus revoke | cross-ref MS033 | F04585 | non-negotiable | false | 10 |
| R09181 | L5 Commit — persists durable ruleset to /etc/selfdef/policy.d/ | dump 17267-17269 | F04586 | non-negotiable | false | 10 |
| R09182 | L5 Commit — signs ruleset with selfdef-signing | cross-ref MS003 | F04587 | non-negotiable | false | 10 |
| R09183 | L5 Commit — records actor field | dump 17396-17402 | F04588 | non-negotiable | false | 10 |
| R09184 | L5 Commit — records reason field (non-empty human-readable string) | dump 17396-17402 | F04588 | non-negotiable | false | 10 |
| R09185 | L5 Commit — records policy-decision field | dump 17396-17402 | F04588 | non-negotiable | false | 10 |
| R09186 | L5 Commit — records rollback-status field | dump 17396-17402 | F04588 | non-negotiable | false | 10 |
| R09187 | L5 Commit — records trace-reference field | dump 17396-17402 | F04588 | non-negotiable | false | 10 |
| R09188 | L5 Commit — integrates with ZFS snapshot pre-commit hook | dump 17415-17421 + cross-ref MS037 | F04589 | non-negotiable | false | 10 |
| R09189 | L5 Commit — rolls back on post-commit verification failure | architecture | F04590 | non-negotiable | false | 10 |
| R09190 | L5 Commit — emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04590 | non-negotiable | false | 10 |
| R09191 | L6 Persist — updates IPS profile catalog | dump 17270-17272 | F04591 | non-negotiable | false | 10 |
| R09192 | L6 Persist — updates LoRA-driven traffic-classifier adapter | cross-ref M046 | F04592 | non-negotiable | false | 10 |
| R09193 | L6 Persist — updates signed manifest exposed via MS007 mirrors | cross-ref MS007 | F04593 | non-negotiable | false | 10 |
| R09194 | L6 Persist — requires operator gate | dump 17415-17421 | F04594 | non-negotiable | false | 10 |
| R09195 | L6 Persist — requires oracle gate (model agreement) | dump 17415-17421 | F04594 | non-negotiable | false | 10 |
| R09196 | L6 Persist — requires snapshot pre-condition | dump 17415-17421 + cross-ref MS037 | F04594 | non-negotiable | false | 10 |
| R09197 | L6 Persist — emits OCSF Configuration Change class 5001 | cross-ref MS026 | F04595 | non-negotiable | false | 10 |
| R09198 | L6 Persist — never overwrites without keeping prior version | cross-ref MS003 | F04591 | non-negotiable | false | 10 |
| R09199 | L6 Persist — prior versions retained for 365 days | architecture | F04591 | non-negotiable | false | 10 |
| R09200 | L6 Persist — operator can demote (revert) within retention window | cross-ref MS003 | F04591 | non-negotiable | false | 10 |
| R09201 | Ring 0 — IPS daemon process | dump 17280-17284 | F04596 | non-negotiable | false | 10 |
| R09202 | Ring 0 — nftables ruleset | cross-ref MS024 | F04596 | non-negotiable | false | 10 |
| R09203 | Ring 0 — kernel modules (selfdef custom modules where applicable) | architecture | F04596 | non-negotiable | false | 10 |
| R09204 | Ring 0 — runs as PID 1 child or systemd unit | dump 17282 | F04597 | non-negotiable | false | 10 |
| R09205 | Ring 0 — has CAP_SYS_ADMIN, CAP_NET_ADMIN | dump 17282 + cross-ref MS024 | F04597 | non-negotiable | false | 10 |
| R09206 | Ring 0 — exempt from L0 observer recursion (avoid feedback loop) | architecture | F04598 | non-negotiable | false | 10 |
| R09207 | Ring 0 — mutates ruleset only via L5/L6 commit pipeline | dump 17283 | F04599 | non-negotiable | false | 10 |
| R09208 | Ring 0 — exports state read-only to other rings | dump 17284 | F04600 | non-negotiable | false | 10 |
| R09209 | Ring 0 — read-only export via MS007 typed-mirror crate | cross-ref MS007 | F04600 | non-negotiable | false | 10 |
| R09210 | Ring 0 — encoded as trust_ring=0 in capability_word | cross-ref MS035 | F04600 | non-negotiable | false | 10 |
| R09211 | Ring 1 — sovereign-os runtime process | dump 17285-17287 | F04601 | non-negotiable | false | 10 |
| R09212 | Ring 1 — memory service process | dump 17285 + cross-ref M048 | F04601 | non-negotiable | false | 10 |
| R09213 | Ring 1 — eval service process | dump 17285 + cross-ref M048 | F04601 | non-negotiable | false | 10 |
| R09214 | Ring 1 — accesses IPS via signed cap-token | cross-ref MS035 | F04602 | non-negotiable | false | 10 |
| R09215 | Ring 1 — traffic placed in selfdef-ring1 netns | cross-ref MS038 | F04603 | non-negotiable | false | 10 |
| R09216 | Ring 1 — cannot escalate to Ring 0 without explicit policy | dump 17302 | F04604 | non-negotiable | false | 10 |
| R09217 | Ring 1 — trust scope encoded in capability_word.trust_ring=1 | cross-ref MS035 | F04605 | non-negotiable | false | 10 |
| R09218 | Ring 1 — process has no CAP_SYS_ADMIN | architecture | F04601 | non-negotiable | false | 10 |
| R09219 | Ring 1 — process runs as dedicated UID range 4000-4999 | architecture | F04650 | non-negotiable | false | 10 |
| R09220 | Ring 1 — emits OCSF System Activity class 1001 on every IPS access | cross-ref MS026 | F04601 | non-negotiable | false | 10 |
| R09221 | Ring 2 — build/test containers | dump 17288-17290 | F04606 | non-negotiable | false | 10 |
| R09222 | Ring 2 — browser agents | dump 17288 | F04606 | non-negotiable | false | 10 |
| R09223 | Ring 2 — tool workers | dump 17288 | F04606 | non-negotiable | false | 10 |
| R09224 | Ring 2 — traffic placed in selfdef-ring2 netns with default-deny | cross-ref MS038 | F04607 | non-negotiable | false | 10 |
| R09225 | Ring 2 — filesystem in disposable overlay | cross-ref MS037 | F04608 | non-negotiable | false | 10 |
| R09226 | Ring 2 — sandbox enforced via MS036 Tier B (controlled host) or Tier C (VM) | cross-ref MS036 | F04609 | non-negotiable | false | 10 |
| R09227 | Ring 2 — cannot direct-write to Ring 0 ruleset | dump 17302 | F04610 | non-negotiable | false | 10 |
| R09228 | Ring 2 — process runs as dedicated UID range 5000-5999 | architecture | F04650 | non-negotiable | false | 10 |
| R09229 | Ring 2 — trust scope encoded in capability_word.trust_ring=2 | cross-ref MS035 | F04606 | non-negotiable | false | 10 |
| R09230 | Ring 2 — emits OCSF Network Activity class 4001 + Audit class 1003 on policy interactions | cross-ref MS026 | F04606 | non-negotiable | false | 10 |
| R09231 | Ring 3 — unknown code | dump 17291-17293 | F04611 | non-negotiable | false | 10 |
| R09232 | Ring 3 — external downloads | dump 17291 | F04611 | non-negotiable | false | 10 |
| R09233 | Ring 3 — risky web | dump 17291 | F04611 | non-negotiable | false | 10 |
| R09234 | Ring 3 — traffic placed in selfdef-ring3 netns with TLS-only egress | cross-ref MS023 + MS038 | F04612 | non-negotiable | false | 10 |
| R09235 | Ring 3 — sandbox enforced via MS036 Tier D disposable microVM | cross-ref MS036 | F04613 | non-negotiable | false | 10 |
| R09236 | Ring 3 — cannot reach Ring 1 services without explicit grant | dump 17293 | F04614 | non-negotiable | false | 10 |
| R09237 | Ring 3 — outputs marked exposure-tainted | cross-ref MS037 | F04615 | non-negotiable | false | 10 |
| R09238 | Ring 3 — process runs as dedicated UID range 6000-6999 | architecture | F04650 | non-negotiable | false | 10 |
| R09239 | Ring 3 — trust scope encoded in capability_word.trust_ring=3 | cross-ref MS035 | F04611 | non-negotiable | false | 10 |
| R09240 | Ring 3 — emits OCSF Detection Finding class 2004 on cross-ring breach attempt | cross-ref MS026 | F04611 | non-negotiable | false | 10 |
| R09241 | Ring 4 — remote APIs | dump 17294-17302 | F04616 | non-negotiable | false | 10 |
| R09242 | Ring 4 — external services | dump 17294 | F04616 | non-negotiable | false | 10 |
| R09243 | Ring 4 — internet | dump 17294 | F04616 | non-negotiable | false | 10 |
| R09244 | Ring 4 — traffic placed in selfdef-ring4 netns with explicit FQDN allowlist | cross-ref MS038 | F04617 | non-negotiable | false | 10 |
| R09245 | Ring 4 — enforces redaction at egress | dump 17354-17372 + cross-ref MS023 | F04618 | non-negotiable | false | 10 |
| R09246 | Ring 4 — allowed list: public docs, high-level reasoning, redacted summaries, optional critique, user-approved oracle calls | dump 17354-17363 | F04618 | non-negotiable | false | 10 |
| R09247 | Ring 4 — restricted list: secrets, private source, personal memory, credentials, raw traces, proprietary data | dump 17364-17372 | F04618 | non-negotiable | false | 10 |
| R09248 | Ring 4 — emits OCSF Network Activity class 4001 with cloud_exposure=true | cross-ref MS026 | F04619 | non-negotiable | false | 10 |
| R09249 | Ring 4 — grants carry explicit TTL | cross-ref MS038 | F04620 | non-negotiable | false | 10 |
| R09250 | Ring 4 — grants carry explicit operator approval | dump 17302 | F04620 | non-negotiable | false | 10 |
| R09251 | Transition L0→L1 — evidence = observation-count threshold (default 100 distinct observations) | dump 17501-17517 | F04621 | non-negotiable | false | 10 |
| R09252 | Transition L1→L2 — evidence = candidate signature + non-conflict check | dump 17501-17517 + cross-ref MS003 | F04622 | non-negotiable | false | 10 |
| R09253 | Transition L2→L3 — evidence = sandbox simulation pass | dump 17501-17517 + cross-ref MS032 | F04623 | non-negotiable | false | 10 |
| R09254 | Transition L3→L4 — evidence = operator approval signal | dump 17501-17517 | F04624 | non-negotiable | false | 10 |
| R09255 | Transition L4→L5 — evidence = TTL expiration + verified absence of regression | dump 17501-17517 + cross-ref MS026 | F04625 | non-negotiable | false | 10 |
| R09256 | Transition L5→L6 — evidence = oracle gate + persistence-impact analysis | dump 17501-17517 + dump 17415-17421 | F04626 | non-negotiable | false | 10 |
| R09257 | Transition L6→L5 — evidence = signed rollback receipt | cross-ref MS003 | F04627 | non-negotiable | false | 10 |
| R09258 | Transition L5→L4 — evidence = revert-token from policy bus | cross-ref MS033 | F04628 | non-negotiable | false | 10 |
| R09259 | Transitions emit M049 13-field span trace event | cross-ref M049 | F04629 | non-negotiable | false | 10 |
| R09260 | Transitions never bypass policy bus | cross-ref MS033 + dump 17249 | F04630 | non-negotiable | false | 10 |
| R09261 | Ring transition Ring 1→Ring 0 — forbidden without operator manual approval | dump 17302 | F04631 | non-negotiable | false | 10 |
| R09262 | Ring transition Ring 2→Ring 1 — requires signed promotion artifact | cross-ref MS003 | F04632 | non-negotiable | false | 10 |
| R09263 | Ring transition Ring 3→Ring 2 — requires sandbox-pass + policy-bus decision | cross-ref MS033 | F04633 | non-negotiable | false | 10 |
| R09264 | Ring transition Ring 4→Ring 3 — forbidden (cloud cannot collapse into local) | dump 17294-17302 | F04634 | non-negotiable | false | 10 |
| R09265 | Ring transitions emit OCSF Configuration Change class 5001 | cross-ref MS026 | F04635 | non-negotiable | false | 10 |
| R09266 | Ring transitions sign with MS003 selfdef-signing | cross-ref MS003 | F04635 | non-negotiable | false | 10 |
| R09267 | Ring transitions carry source + target ring | architecture | F04635 | non-negotiable | false | 10 |
| R09268 | Ring transitions carry justification text (non-empty) | architecture + dump 17396-17402 | F04635 | non-negotiable | false | 10 |
| R09269 | Ring transitions carry policy-decision reference | cross-ref MS033 | F04635 | non-negotiable | false | 10 |
| R09270 | Ring transitions carry trace-id reference | cross-ref M049 | F04635 | non-negotiable | false | 10 |
| R09271 | Evidence collector — aggregates eBPF traces | cross-ref MS024 | F04636 | non-negotiable | false | 10 |
| R09272 | Evidence collector — aggregates fanotify events | cross-ref MS037 | F04637 | non-negotiable | false | 10 |
| R09273 | Evidence collector — aggregates audit-cycle results | cross-ref MS009 | F04638 | non-negotiable | false | 10 |
| R09274 | Evidence collector — preserves provenance chain | cross-ref MS003 | F04639 | non-negotiable | false | 10 |
| R09275 | Evidence collector — emits structured evidence bundle | architecture | F04640 | non-negotiable | false | 10 |
| R09276 | Evidence collector — bundle format = CBOR-encoded with MS003 signature | cross-ref MS003 | F04640 | non-negotiable | false | 10 |
| R09277 | Evidence collector — bundle includes timestamp + actor + collection scope | architecture | F04640 | non-negotiable | false | 10 |
| R09278 | Evidence collector — bundle includes evidence-digest (32-byte SHA-256) | cross-ref MS003 | F04640 | non-negotiable | false | 10 |
| R09279 | Evidence collector — bundle stored under /var/lib/selfdef/evidence/ | architecture | F04640 | non-negotiable | false | 10 |
| R09280 | Evidence collector — bundle retention 100 days | architecture | F04674 | non-negotiable | false | 10 |
| R09281 | Gate coordinator — multiplexes per-level gates L3..L6 | architecture | F04641 | non-negotiable | false | 10 |
| R09282 | Gate coordinator — integrates with operator dashboard surface | cross-ref MS007 | F04642 | non-negotiable | false | 10 |
| R09283 | Gate coordinator — integrates with sovereign-os policy bus | cross-ref MS033 | F04643 | non-negotiable | false | 10 |
| R09284 | Gate coordinator — never auto-approves above L4 | dump 17249 | F04644 | non-negotiable | false | 10 |
| R09285 | Gate coordinator — records gate-decision | architecture | F04645 | non-negotiable | false | 10 |
| R09286 | Gate coordinator — records actor (who approved) | architecture | F04645 | non-negotiable | false | 10 |
| R09287 | Gate coordinator — records timestamp | architecture | F04645 | non-negotiable | false | 10 |
| R09288 | Gate coordinator — records justification (non-empty) | architecture | F04645 | non-negotiable | false | 10 |
| R09289 | Gate coordinator — gate timeout default 24h then auto-expire | architecture | F04641 | non-negotiable | false | 10 |
| R09290 | Gate coordinator — expired gate counts as denied | architecture + dump 17263 | F04641 | non-negotiable | false | 10 |
| R09291 | Ring isolation — Linux namespace allocation per ring | architecture | F04646 | non-negotiable | false | 10 |
| R09292 | Ring isolation — nftables chain per ring | cross-ref MS024 | F04647 | non-negotiable | false | 10 |
| R09293 | Ring isolation — cgroup v2 hierarchy per ring | cross-ref M045 | F04648 | non-negotiable | false | 10 |
| R09294 | Ring isolation — SELinux/AppArmor profile per ring (where applicable) | cross-ref MS037 | F04649 | non-negotiable | false | 10 |
| R09295 | Ring isolation — unique UID range per ring (4000/5000/6000/7000/8000) | architecture | F04650 | non-negotiable | false | 10 |
| R09296 | Capability — token carries trust_ring 3-bit field (Ring 0..4 + reserved) | cross-ref MS035 | F04651 | non-negotiable | false | 10 |
| R09297 | Capability — token carries authority_level 3-bit field (L0..L6 + reserved) | cross-ref MS035 | F04652 | non-negotiable | false | 10 |
| R09298 | Capability — token carries evidence_digest 32-byte field | cross-ref MS035 | F04653 | non-negotiable | false | 10 |
| R09299 | Capability — token rejects mismatched ring + level pairs (e.g. Ring 4 + L6) | cross-ref MS035 + dump 17302 | F04654 | non-negotiable | false | 10 |
| R09300 | Capability — token emits M049 trace on every redemption | cross-ref M049 | F04655 | non-negotiable | false | 10 |
| R09301 | Trace emitter — span format = M049 13-field schema | cross-ref M049 | F04656 | non-negotiable | false | 10 |
| R09302 | Trace emitter — records before-level + after-level | architecture | F04657 | non-negotiable | false | 10 |
| R09303 | Trace emitter — records before-ring + after-ring | dump 17302 | F04658 | non-negotiable | false | 10 |
| R09304 | Trace emitter — deterministic field order (replay-safe) | cross-ref MS009 | F04659 | non-negotiable | false | 10 |
| R09305 | Trace emitter — routes to M049 observability pipeline | cross-ref M049 | F04660 | non-negotiable | false | 10 |
| R09306 | Rollback engine — reverts L5 commits via signed revert artifact | cross-ref MS003 | F04661 | non-negotiable | false | 10 |
| R09307 | Rollback engine — reverts L6 persistences via signed revert artifact | cross-ref MS003 | F04662 | non-negotiable | false | 10 |
| R09308 | Rollback engine — integrates with ZFS snapshot bridge | cross-ref MS037 | F04663 | non-negotiable | false | 10 |
| R09309 | Rollback engine — emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04664 | non-negotiable | false | 10 |
| R09310 | Rollback engine — never silently drops state | architecture | F04665 | non-negotiable | false | 10 |
| R09311 | MS007 mirror — published under 8/8 SATURATED scheme | cross-ref MS007 | F04666 | non-negotiable | false | 10 |
| R09312 | MS007 mirror — exposes AuthorityLevel enum L0..L6 | cross-ref MS007 + dump 17252-17272 | F04667 | non-negotiable | false | 10 |
| R09313 | MS007 mirror — exposes TrustRing enum Ring0..Ring4 | cross-ref MS007 + dump 17280-17302 | F04668 | non-negotiable | false | 10 |
| R09314 | MS007 mirror — exposes AuthorityTransition struct {from, to, evidence_digest, actor, timestamp, trace_id, signature} | cross-ref MS007 | F04669 | non-negotiable | false | 10 |
| R09315 | MS007 mirror — exposes RingMembership struct {ring, namespace, cgroup, uid_range, capability_word} | cross-ref MS007 | F04670 | non-negotiable | false | 10 |
| R09316 | MS007 mirror — schema_version "1.0.0" | cross-ref MS007 | F04666 | non-negotiable | false | 10 |
| R09317 | MS007 mirror — Rust crate name selfdef-authority-mirror | cross-ref MS007 | F04666 | non-negotiable | false | 10 |
| R09318 | MS007 mirror — re-exported via sovereign-os runtime cargo workspace | cross-ref MS007 | F04666 | non-negotiable | false | 10 |
| R09319 | MS007 mirror — no_std friendly (compiles for embedded / kernel contexts) | architecture | F04666 | non-negotiable | false | 10 |
| R09320 | MS007 mirror — serde + bincode derives present | architecture + cross-ref MS007 | F04666 | non-negotiable | false | 10 |
| R09321 | Authority FSM — exactly 7 states (L0..L6) | dump 17252-17272 | F04671 | non-negotiable | false | 10 |
| R09322 | Authority FSM — transitions append-only audit log | cross-ref MS009 | F04672 | non-negotiable | false | 10 |
| R09323 | Authority FSM — transitions all signed via MS003 | cross-ref MS003 | F04673 | non-negotiable | false | 10 |
| R09324 | Authority FSM — illegal jumps (e.g. L0→L4) rejected | architecture | F04671 | non-negotiable | false | 10 |
| R09325 | Authority FSM — direct demotions allowed only L6→L5 and L5→L4 | architecture + dump 17269 | F04671 | non-negotiable | false | 10 |
| R09326 | Receipt store — keeps last 100 days of transitions | cross-ref MS037 | F04674 | non-negotiable | false | 10 |
| R09327 | Receipt store — integrates with MS009 replay validator | cross-ref MS009 | F04675 | non-negotiable | false | 10 |
| R09328 | Receipt store — receipts include all 7 fields (actor/reason/policy-decision/rollback-status/trace-ref/before/after) | dump 17396-17402 | F04674 | non-negotiable | false | 10 |
| R09329 | Receipt store — receipts indexed by trace-id | cross-ref M049 | F04674 | non-negotiable | false | 10 |
| R09330 | Receipt store — receipts indexed by actor | architecture | F04674 | non-negotiable | false | 10 |
| R09331 | Replay validator — verifies historical transition chain | cross-ref MS009 | F04676 | non-negotiable | false | 10 |
| R09332 | Replay validator — detects chain breaks (missing/malformed signatures) | cross-ref MS003 | F04677 | non-negotiable | false | 10 |
| R09333 | Replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 | F04678 | non-negotiable | false | 10 |
| R09334 | Replay validator — runs daily as cron unit | cross-ref MS009 | F04676 | non-negotiable | false | 10 |
| R09335 | Replay validator — failures halt L5/L6 transitions until resolved | architecture | F04676 | non-negotiable | false | 10 |
| R09336 | Decision cache — TTL = 60s for L0-L2 | architecture | F04679 | non-negotiable | false | 10 |
| R09337 | Decision cache — TTL = 0 (no cache) for L4-L6 | dump 17263-17272 | F04680 | non-negotiable | false | 10 |
| R09338 | Decision cache — TTL = 5s for L3 (operator may re-evaluate) | architecture | F04679 | non-negotiable | false | 10 |
| R09339 | Decision cache — flushed on policy bus revoke | cross-ref MS033 | F04679 | non-negotiable | false | 10 |
| R09340 | Decision cache — flushed on ring transition | dump 17302 | F04679 | non-negotiable | false | 10 |
| R09341 | Memory trust — raw_observation = highest provenance, maybe noisy | dump 17376-17378 | F04640 | non-negotiable | false | 10 |
| R09342 | Memory trust — derived_summary = useful, lossy | dump 17379-17381 | F04640 | non-negotiable | false | 10 |
| R09343 | Memory trust — model_reflection = low authority until verified | dump 17382-17384 | F04640 | non-negotiable | false | 10 |
| R09344 | Memory trust — user_statement = high preference authority | dump 17385-17387 | F04640 | non-negotiable | false | 10 |
| R09345 | Memory trust — test_result = high technical authority | dump 17388-17390 | F04640 | non-negotiable | false | 10 |
| R09346 | Memory trust — external_claim = requires source/freshness | dump 17391-17393 | F04640 | non-negotiable | false | 10 |
| R09347 | Memory trust — cloud_generated = useful, but exposure-marked | dump 17394-17395 | F04618 | non-negotiable | false | 10 |
| R09348 | Cloud trust — gateway enforces allowed/restricted lists | dump 17354-17374 | F04618 | non-negotiable | false | 10 |
| R09349 | Cloud trust — IPS-side enforcement via egress filter at netns boundary | cross-ref MS038 | F04618 | non-negotiable | false | 10 |
| R09350 | Cloud trust — every cloud call emits trace + exposure log | cross-ref M049 | F04619 | non-negotiable | false | 10 |
| R09351 | Operational — selfdef IPS daemon runs as systemd unit selfdef.service | architecture | F04597 | non-negotiable | false | 10 |
| R09352 | Operational — selfdef IPS daemon restart preserves Ring 0 state via /var/lib/selfdef/state.json | architecture + cross-ref MS003 | F04598 | non-negotiable | false | 10 |
| R09353 | Operational — selfdef IPS daemon shutdown drains pending L4 grants gracefully | architecture | F04585 | non-negotiable | false | 10 |
| R09354 | Operational — selfdef IPS daemon emits readiness probe at /run/selfdef/ready | architecture | F04597 | non-negotiable | false | 10 |
| R09355 | Operational — selfdef IPS daemon emits liveness probe at /run/selfdef/alive | architecture | F04597 | non-negotiable | false | 10 |
| R09356 | Operational — selfdef IPS daemon honors SIGTERM for graceful drain | architecture | F04597 | non-negotiable | false | 10 |
| R09357 | Operational — selfdef IPS daemon honors SIGHUP for ruleset reload | architecture | F04586 | non-negotiable | false | 10 |
| R09358 | Operational — selfdef IPS daemon refuses to start on chain-break detection | cross-ref MS009 | F04676 | non-negotiable | false | 10 |
| R09359 | Operational — selfdef IPS daemon refuses to start on missing MS003 signing key | cross-ref MS003 | F04673 | non-negotiable | false | 10 |
| R09360 | Operational — selfdef IPS daemon emits start/stop event via M049 trace | cross-ref M049 | F04656 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements per operator standing direction. Total enforced sub-reqs = 240 R × 10 = **2,400 sub-requirements** for MS039.

## Cross-references

- **sovereign-os M056** — canonical authority model + trust rings (selfdef projects this through MS007 typed mirrors only)
- **sovereign-os M049** — observability / trace pipeline consumed for span emission
- **sovereign-os M045** — Linux as intelligence governor (cgroup v2 / systemd / PSI / eBPF substrate)
- **sovereign-os M048** — modules map (memory service / eval service Ring 1 placement)
- **MS003** — selfdef-signing (signs all transitions, receipts, capability tokens, ring promotions)
- **MS007** — typed-mirror crate scheme (cross-repo binding)
- **MS009** — audit cycles + replay validator
- **MS023** — TLS inspection (Ring 4 egress redaction enforcement)
- **MS024** — L2 transparent bridge (Ring 1/2/3/4 nftables chain hosting)
- **MS026** — observability + OCSF event emission
- **MS032** — sandbox tiers (L2 simulator + Ring 2/3 placement)
- **MS033** — policy bus + trace (L4→L5 revoke + ring transition decisions)
- **MS034-MS038** — Communication / Capability tokens / Tool sandboxes / Filesystem / Network boundaries (the five enforcement layers this milestone parameterizes with L0..L6 + Ring 0..4)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS039
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines: 17215-17532
cross_repo_mirror: sovereign-os/M056
typed_mirror_crate: selfdef-authority-mirror
```
