# MS033 — Policy and trace — every action observable + governed

> Parent: `backlog/milestones/INDEX.md` row MS033 (source ref dump 16210–16250 Phase 3: Policy And Trace).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 16210–16250 (Phase 3 doctrinal block).
> All entries below extract verbatim from these dump lines or trace to existing selfdef + sovereign-os repo state. No invention.

## Epics (E0331–E0340)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0331 | Phase 3: Policy And Trace + goal — "Every action becomes observable and governed" | dump 16210–16216 |
| E0332 | 5-element Phase 3 Add list — policy decision object / trace event object / cost/token accounting / profile resolution / basic allow/deny/ask/sandbox states | dump 16220–16226 |
| E0333 | Doctrine — "Even before sophisticated policy, the shape matters" | dump 16228 |
| E0334 | 7-step model-call trace template — request received / profile resolved / route selected / model called / tokens counted / response returned / trace closed | dump 16232–16238 |
| E0335 | 5-step tool-call trace template — tool proposed / policy checked / tool executed or denied / result observed / side effects recorded | dump 16244–16250 |
| E0336 | Policy decision object schema — must carry subject + action + resource + intent + profile + decision + reason (matches sovereign-os M049 Intent-Based Policy 10-field input subset) | dump 16220 + cross-ref M049 | 
| E0337 | Trace event object schema — must carry trace_id + event_type + timestamp + module + status + duration + metadata (matches sovereign-os M049 13-field span subset) | dump 16221 + cross-ref M049 |
| E0338 | Cost/token accounting — every model call charges against per-token quota (MS022) + emits cost_event into M049 16-event taxonomy | dump 16222 + cross-ref MS022 + M049 |
| E0339 | Profile resolution — every request resolves to a profile (M042 9-axis choice envelopes) BEFORE policy check | dump 16223 + cross-ref M042 |
| E0340 | 4-state policy outcome — allow / deny / ask / sandbox; "basic states" before sophisticated policy engines | dump 16225 |

## Modules (M00837–M00862)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00837 | Phase 3 doctrine — "Every action becomes observable and governed" | dump 16216 | E0331 |
| M00838 | Phase 3 Add — policy decision object | dump 16220 | E0332 |
| M00839 | Phase 3 Add — trace event object | dump 16221 | E0332 |
| M00840 | Phase 3 Add — cost/token accounting | dump 16222 | E0332 |
| M00841 | Phase 3 Add — profile resolution | dump 16223 | E0332 |
| M00842 | Phase 3 Add — basic allow/deny/ask/sandbox states | dump 16225 | E0332 |
| M00843 | "Even before sophisticated policy, the shape matters" doctrine | dump 16228 | E0333 |
| M00844 | Model call trace step 1 — request received | dump 16232 | E0334 |
| M00845 | Model call trace step 2 — profile resolved | dump 16233 | E0334 |
| M00846 | Model call trace step 3 — route selected | dump 16234 | E0334 |
| M00847 | Model call trace step 4 — model called | dump 16235 | E0334 |
| M00848 | Model call trace step 5 — tokens counted | dump 16236 | E0334 |
| M00849 | Model call trace step 6 — response returned | dump 16237 | E0334 |
| M00850 | Model call trace step 7 — trace closed | dump 16238 | E0334 |
| M00851 | Tool call trace step 1 — tool proposed | dump 16244 | E0335 |
| M00852 | Tool call trace step 2 — policy checked | dump 16245 | E0335 |
| M00853 | Tool call trace step 3 — tool executed or denied | dump 16246 | E0335 |
| M00854 | Tool call trace step 4 — result observed | dump 16247 | E0335 |
| M00855 | Tool call trace step 5 — side effects recorded | dump 16248 | E0335 |
| M00856 | Policy decision object schema — selfdef-side enforcement of M049 Intent-Based 10-field policy input | dump 16220 + cross-ref M049 | E0336 |
| M00857 | Trace event object schema — selfdef-side emission of M049 13-field span | dump 16221 + cross-ref M049 | E0337 |
| M00858 | Cost accounting — per-token quota integration (MS022 SubscriberGuard) | dump 16222 + cross-ref MS022 | E0338 |
| M00859 | Cost event — emitted into M049 16-event taxonomy (cost_event) | dump 16222 + cross-ref M049 | E0338 |
| M00860 | Profile resolution — M042 9-axis choice envelope evaluated before policy check | dump 16223 + cross-ref M042 | E0339 |
| M00861 | 4-state policy outcome — allow / deny / ask / sandbox | dump 16225 | E0340 |
| M00862 | Cross-repo binding — selfdef MS033 enforces; sovereign-os M049 Policy Fabric (OPA/Cedar/OpenFGA) orchestrates; MS007 typed-mirror crates bind | architecture + cross-ref M049 + MS007 | E0336 + E0337 + E0340 |

## Features (F03841–F03960)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03841 | Phase 3 header — "Policy And Trace" | dump 16210 | M00837 |
| F03842 | Phase 3 goal — "Every action becomes observable and governed" | dump 16216 | M00837 |
| F03843 | Add — policy decision object | dump 16220 | M00838 |
| F03844 | Add — trace event object | dump 16221 | M00839 |
| F03845 | Add — cost/token accounting | dump 16222 | M00840 |
| F03846 | Add — profile resolution | dump 16223 | M00841 |
| F03847 | Add — basic allow/deny/ask/sandbox states | dump 16225 | M00842 |
| F03848 | Doctrine — "Even before sophisticated policy, the shape matters" | dump 16228 | M00843 |
| F03849 | Model-call doctrine — "A model call should emit" | dump 16230 | M00844 |
| F03850 | Model call step — request received | dump 16232 | M00844 |
| F03851 | Model call step — profile resolved | dump 16233 | M00845 |
| F03852 | Model call step — route selected | dump 16234 | M00846 |
| F03853 | Model call step — model called | dump 16235 | M00847 |
| F03854 | Model call step — tokens counted | dump 16236 | M00848 |
| F03855 | Model call step — response returned | dump 16237 | M00849 |
| F03856 | Model call step — trace closed | dump 16238 | M00850 |
| F03857 | Tool-call doctrine — "A tool call should emit" | dump 16242 | M00851 |
| F03858 | Tool call step — tool proposed | dump 16244 | M00851 |
| F03859 | Tool call step — policy checked | dump 16245 | M00852 |
| F03860 | Tool call step — tool executed or denied | dump 16246 | M00853 |
| F03861 | Tool call step — result observed | dump 16247 | M00854 |
| F03862 | Tool call step — side effects recorded | dump 16248 | M00855 |
| F03863 | Policy decision object — subject field | dump 16220 + cross-ref M049 | M00856 |
| F03864 | Policy decision object — action field | dump 16220 + cross-ref M049 | M00856 |
| F03865 | Policy decision object — resource field | dump 16220 + cross-ref M049 | M00856 |
| F03866 | Policy decision object — intent field | dump 16220 + cross-ref M049 | M00856 |
| F03867 | Policy decision object — profile field | dump 16220 + cross-ref M049 + M042 | M00856 |
| F03868 | Policy decision object — risk field | dump 16220 + cross-ref M049 | M00856 |
| F03869 | Policy decision object — model/provider field | dump 16220 + cross-ref M049 | M00856 |
| F03870 | Policy decision object — context sensitivity field | dump 16220 + cross-ref M049 | M00856 |
| F03871 | Policy decision object — side effect class field | dump 16220 + cross-ref M049 | M00856 |
| F03872 | Policy decision object — user approval state field | dump 16220 + cross-ref M049 | M00856 |
| F03873 | Policy decision object — decision field (allow/deny/ask/sandbox) | dump 16225 | M00861 |
| F03874 | Policy decision object — reason field | architecture + dump 16220 | M00856 |
| F03875 | Trace event object — trace_id field | dump 16221 + cross-ref M049 | M00857 |
| F03876 | Trace event object — event_type field | dump 16221 + cross-ref M049 | M00857 |
| F03877 | Trace event object — timestamp field | dump 16221 + cross-ref M049 | M00857 |
| F03878 | Trace event object — module field | dump 16221 + cross-ref M049 | M00857 |
| F03879 | Trace event object — status field | dump 16221 + cross-ref M049 | M00857 |
| F03880 | Trace event object — duration field | dump 16221 + cross-ref M049 | M00857 |
| F03881 | Trace event object — metadata field | dump 16221 + cross-ref M049 | M00857 |
| F03882 | Trace event object — links to M049 13-field span (profile/model/provider/hardware/tokens/latency/cost/risk/memory_refs/tool_refs/policy_result/branch_id/trace_id) | dump 16221 + cross-ref M049 | M00857 |
| F03883 | Cost/token accounting — every model call charges per-token quota | dump 16222 + cross-ref MS022 | M00858 |
| F03884 | Cost/token accounting — per-token quota enforced by MS022 SubscriberGuard | cross-ref MS022 | M00858 |
| F03885 | Cost/token accounting — emits cost_event into M049 16-event taxonomy | dump 16222 + cross-ref M049 | M00859 |
| F03886 | Cost/token accounting — supports per-profile cost caps via M042 user-config | cross-ref M042 + dump 16222 | M00858 |
| F03887 | Profile resolution — M042 9-axis choice envelope evaluated FIRST | dump 16223 + cross-ref M042 | M00860 |
| F03888 | Profile resolution — M044 4 security profiles overlay choice envelope | cross-ref M044 + dump 16223 | M00860 |
| F03889 | Profile resolution — M045 5 sovereign profiles overlay security profiles | cross-ref M045 + dump 16223 | M00860 |
| F03890 | Profile resolution — operator-selected profile passed to policy decision object | dump 16223 + dump 16220 | M00860 |
| F03891 | Policy outcome — allow | dump 16225 | M00861 |
| F03892 | Policy outcome — deny | dump 16225 | M00861 |
| F03893 | Policy outcome — ask (request user approval) | dump 16225 | M00861 |
| F03894 | Policy outcome — sandbox (escalate to higher sandbox tier MS032) | dump 16225 + cross-ref MS032 | M00861 |
| F03895 | Doctrine — "shape matters" means schema MUST be stable BEFORE engine logic matures | dump 16228 | M00843 |
| F03896 | Doctrine — selfdef policy decision object IS the schema published via MS007 surface-manifest typed-mirror | cross-ref MS007 + architecture | M00862 |
| F03897 | Doctrine — sovereign-os M049 OPA/Cedar/OpenFGA engines consume this schema | cross-ref M049 | M00862 |
| F03898 | Doctrine — selfdef MS017 agent-guard ENFORCES the 4-state policy outcome | cross-ref MS017 | M00861 |
| F03899 | Doctrine — selfdef MS027 observability EMITS the trace event objects | cross-ref MS027 | M00857 |
| F03900 | Doctrine — selfdef MS026 integrity-sentinel BASELINES the policy decision schemas | cross-ref MS026 | M00856 |
| F03901 | Doctrine — selfdef MS025 detect-host event-bus TRANSPORTS the trace events | cross-ref MS025 | M00857 |
| F03902 | Doctrine — selfdef MS003 correlator + store + responder PROCESSES the trace events | cross-ref MS003 | M00857 |
| F03903 | Doctrine — selfdef MS004 14 notifier integrations DELIVER the policy outcomes | cross-ref MS004 | M00861 |
| F03904 | Doctrine — selfdef MS022 SSE quota module enforces cost/token accounting | cross-ref MS022 | M00858 |
| F03905 | Cross-repo binding — MS007 typed-mirror crates publish 10-field policy schema | cross-ref MS007 + cross-ref M049 | M00862 |
| F03906 | Cross-repo binding — MS007 typed-mirror crates publish 13-field trace span schema | cross-ref MS007 + cross-ref M049 | M00862 |
| F03907 | Cross-repo binding — MS007 typed-mirror crates publish 16-event taxonomy schema | cross-ref MS007 + cross-ref M049 | M00862 |
| F03908 | Operator UX — `selfdefctl policy explain` shows policy decision object | cross-ref MS017 + dump 16220 | M00856 |
| F03909 | Operator UX — `selfdefctl trace show <trace_id>` shows trace event chain | cross-ref MS027 + dump 16221 | M00857 |
| F03910 | Operator UX — `selfdefctl cost report` shows token usage ledger | cross-ref MS022 + dump 16222 | M00858 |
| F03911 | Operator UX — `selfdefctl profile current` shows resolved profile | cross-ref M042 + dump 16223 | M00860 |
| F03912 | Operator UX — `selfdefctl policy approve <decision_id>` resolves "ask" outcome | dump 16225 + cross-ref M042 user-approval | M00861 |
| F03913 | Test integration — MS020 L1 covers policy decision schema rendering | cross-ref MS020 | M00856 |
| F03914 | Test integration — MS020 L2 covers 7-step model-call trace pipeline | cross-ref MS020 + dump 16232–16238 | M00857 |
| F03915 | Test integration — MS020 L2 covers 5-step tool-call trace pipeline | cross-ref MS020 + dump 16244–16248 | M00857 |
| F03916 | Test integration — MS020 L3 covers selfdefctl policy + trace + cost + profile + approve CLI scripts | cross-ref MS020 | M00862 |
| F03917 | Test integration — MS020 L4 covers seam between policy decision schema + OPA/Cedar/OpenFGA engines | cross-ref MS020 + M049 | M00862 |
| F03918 | Test integration — MS020 L5 covers end-to-end action lifecycle (intent → policy → trace → execute/deny → record) | cross-ref MS020 + dump 16216 | M00862 |
| F03919 | Cross-module — MS022 per-token quota composes with cost/token accounting | cross-ref MS022 | M00858 |
| F03920 | Cross-module — MS017 agent-guard enforces policy decision outcomes on agents | cross-ref MS017 | M00861 |
| F03921 | Cross-module — MS016 Tetragon eBPF programs observe tool-call execution | cross-ref MS016 | M00854 |
| F03922 | Cross-module — MS026 integrity-sentinel emits OCSF Detection Finding 2004 for policy violations | cross-ref MS026 | M00861 |
| F03923 | Cross-module — MS013 27-SDD charter governs policy decision finding ledger | cross-ref MS013 | M00862 |
| F03924 | Cross-module — MS019 threat model identifies policy bypass as primary attack surface | cross-ref MS019 | M00861 |
| F03925 | Cross-module — MS027 observability dashboard renders policy decision histogram | cross-ref MS027 | M00857 |
| F03926 | Cross-module — MS011 operator dashboard renders policy approval queue | cross-ref MS011 | M00861 |
| F03927 | Cross-module — MS032 sandbox tier escalation triggered by "sandbox" policy outcome | cross-ref MS032 | M00861 |
| F03928 | Cross-module — MS028 bitnet-gpu-inference emits model_call trace events | cross-ref MS028 | M00844 |
| F03929 | Cross-module — MS029 slm-cpu-loop emits model_call trace events | cross-ref MS029 | M00844 |
| F03930 | Cross-module — MS030 tensor-parallel-inference emits model_call trace events | cross-ref MS030 | M00844 |
| F03931 | Cross-module — MS031 wasm-aot-cache .cwasm artifacts subject to policy adapter-load checkpoint | cross-ref MS031 + M049 | M00856 |
| F03932 | Cross-module — MS023 polarproxy enforces TLS-MITM policy at network egress | cross-ref MS023 | M00861 |
| F03933 | Cross-module — MS024 bridge-l2 nftables ruleset enforces network policy | cross-ref MS024 | M00861 |
| F03934 | Cross-module — MS015 NATS messaging backbone transports policy decision objects across daemons | cross-ref MS015 + dump 16220 | M00856 |
| F03935 | Cross-module — MS018 VPN-bridge per-profile-instance enforces network policy per profile | cross-ref MS018 + M042 | M00861 |
| F03936 | Cross-module — MS014 SSH-wrap client-side defense applies tool-call policy to outbound SSH | cross-ref MS014 | M00853 |
| F03937 | Cross-module — MS009 audit cycles trace policy decision lineage | cross-ref MS009 | M00856 |
| F03938 | Cross-module — MS008 selfdef-on-sain01 deploys full policy+trace stack on SAIN-01 reference box | cross-ref MS008 | M00837 |
| F03939 | Cross-module — MS010 hardware-tune-cache informs policy decision (e.g. AVX-512 BF16 → BF16 model allowed) | cross-ref MS010 | M00856 |
| F03940 | Cross-module — MS012 perimeter coexistence applies tool-call policy at perimeter | cross-ref MS012 | M00853 |
| F03941 | Doctrine — policy is enforced ON THE BOUNDARY (network/file/tool/memory), NOT inside the model | dump 16220 + cross-ref M049 | M00856 |
| F03942 | Doctrine — trace is emitted WHEN the action is decided, not after (no after-the-fact reconstruction) | dump 16221 | M00857 |
| F03943 | Doctrine — every action MUST have a policy decision object | dump 16220 + dump 16216 | M00856 |
| F03944 | Doctrine — every action MUST emit a trace event object | dump 16221 + dump 16216 | M00857 |
| F03945 | Doctrine — every model call MUST count tokens (no exceptions) | dump 16222 + 16236 | M00848 |
| F03946 | Doctrine — every request MUST resolve to a profile (no anonymous calls) | dump 16223 | M00860 |
| F03947 | Doctrine — every action MUST get one of 4 outcomes (allow/deny/ask/sandbox) | dump 16225 | M00861 |
| F03948 | Doctrine — "allow" SHALL execute the action with full trace | dump 16225 + 16238 | M00861 |
| F03949 | Doctrine — "deny" SHALL refuse the action with reason in policy decision object | dump 16225 + architecture | M00861 |
| F03950 | Doctrine — "ask" SHALL pause the action and request operator approval (M042 user-approval-state) | dump 16225 + cross-ref M042 | M00861 |
| F03951 | Doctrine — "sandbox" SHALL escalate the action to higher sandbox tier (MS032) | dump 16225 + cross-ref MS032 | M00861 |
| F03952 | Doctrine — model-call trace MUST emit 7 events in order (request_received → profile_resolved → route_selected → model_called → tokens_counted → response_returned → trace_closed) | dump 16232–16238 | M00844 |
| F03953 | Doctrine — tool-call trace MUST emit 5 events in order (tool_proposed → policy_checked → tool_executed_or_denied → result_observed → side_effects_recorded) | dump 16244–16248 | M00851 |
| F03954 | Doctrine — trace events MUST be append-only (no deletion or amendment) | dump 16221 + architecture | M00857 |
| F03955 | Doctrine — trace events MUST be persisted to ZFS (M044 Storage Plane) for replay | cross-ref M044 | M00857 |
| F03956 | Doctrine — trace events MUST be queryable by trace_id + event_type + timestamp | architecture + dump 16221 | M00857 |
| F03957 | Doctrine — policy decision objects MUST be persisted alongside trace events | dump 16220 + 16221 | M00856 |
| F03958 | Doctrine — policy decision objects MUST be auditable post-hoc (MS009 audit cycles) | cross-ref MS009 | M00856 |
| F03959 | Doctrine — cost/token accounting MUST be queryable per-profile + per-session + per-day | cross-ref MS022 + dump 16222 | M00858 |
| F03960 | Composite — Phase 3 catalogs the ENABLING SHAPE for sovereign-os M049 sophisticated policy + observability planes | dump 16210–16250 + cross-ref M049 | E0331 |

## Requirements (R07681–R07920)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R07681 | Phase 3 header — "Policy And Trace" | dump 16210 | F03841 | non-negotiable | false | 10 |
| R07682 | Phase 3 goal — "Every action becomes observable and governed" | dump 16216 | F03842 | non-negotiable | false | 10 |
| R07683 | Add — policy decision object | dump 16220 | F03843 | non-negotiable | false | 10 |
| R07684 | Add — trace event object | dump 16221 | F03844 | non-negotiable | false | 10 |
| R07685 | Add — cost/token accounting | dump 16222 | F03845 | non-negotiable | false | 10 |
| R07686 | Add — profile resolution | dump 16223 | F03846 | non-negotiable | false | 10 |
| R07687 | Add — basic allow/deny/ask/sandbox states | dump 16225 | F03847 | non-negotiable | false | 10 |
| R07688 | Doctrine — "Even before sophisticated policy, the shape matters" | dump 16228 | F03848 | non-negotiable | false | 10 |
| R07689 | Model-call doctrine — "A model call should emit" | dump 16230 | F03849 | non-negotiable | false | 10 |
| R07690 | Model call step 1 — request received | dump 16232 | F03850 | non-negotiable | false | 10 |
| R07691 | Model call step 2 — profile resolved | dump 16233 | F03851 | non-negotiable | false | 10 |
| R07692 | Model call step 3 — route selected | dump 16234 | F03852 | non-negotiable | false | 10 |
| R07693 | Model call step 4 — model called | dump 16235 | F03853 | non-negotiable | false | 10 |
| R07694 | Model call step 5 — tokens counted | dump 16236 | F03854 | non-negotiable | false | 10 |
| R07695 | Model call step 6 — response returned | dump 16237 | F03855 | non-negotiable | false | 10 |
| R07696 | Model call step 7 — trace closed | dump 16238 | F03856 | non-negotiable | false | 10 |
| R07697 | Tool-call doctrine — "A tool call should emit" | dump 16242 | F03857 | non-negotiable | false | 10 |
| R07698 | Tool call step 1 — tool proposed | dump 16244 | F03858 | non-negotiable | false | 10 |
| R07699 | Tool call step 2 — policy checked | dump 16245 | F03859 | non-negotiable | false | 10 |
| R07700 | Tool call step 3 — tool executed or denied | dump 16246 | F03860 | non-negotiable | false | 10 |
| R07701 | Tool call step 4 — result observed | dump 16247 | F03861 | non-negotiable | false | 10 |
| R07702 | Tool call step 5 — side effects recorded | dump 16248 | F03862 | non-negotiable | false | 10 |
| R07703 | Policy decision object — subject field | dump 16220 + cross-ref M049 | F03863 | non-negotiable | false | 10 |
| R07704 | Policy decision object — action field | dump 16220 + cross-ref M049 | F03864 | non-negotiable | false | 10 |
| R07705 | Policy decision object — resource field | dump 16220 + cross-ref M049 | F03865 | non-negotiable | false | 10 |
| R07706 | Policy decision object — intent field | dump 16220 + cross-ref M049 | F03866 | non-negotiable | false | 10 |
| R07707 | Policy decision object — profile field | dump 16220 + cross-ref M049 | F03867 | non-negotiable | false | 10 |
| R07708 | Policy decision object — risk field | dump 16220 + cross-ref M049 | F03868 | non-negotiable | false | 10 |
| R07709 | Policy decision object — model/provider field | dump 16220 + cross-ref M049 | F03869 | non-negotiable | false | 10 |
| R07710 | Policy decision object — context sensitivity field | dump 16220 + cross-ref M049 | F03870 | non-negotiable | false | 10 |
| R07711 | Policy decision object — side effect class field | dump 16220 + cross-ref M049 | F03871 | non-negotiable | false | 10 |
| R07712 | Policy decision object — user approval state field | dump 16220 + cross-ref M049 | F03872 | non-negotiable | false | 10 |
| R07713 | Policy decision object — decision field (allow/deny/ask/sandbox) | dump 16225 | F03873 | non-negotiable | false | 10 |
| R07714 | Policy decision object — reason field | architecture + dump 16220 | F03874 | non-negotiable | false | 10 |
| R07715 | Trace event object — trace_id field | dump 16221 + cross-ref M049 | F03875 | non-negotiable | false | 10 |
| R07716 | Trace event object — event_type field | dump 16221 + cross-ref M049 | F03876 | non-negotiable | false | 10 |
| R07717 | Trace event object — timestamp field | dump 16221 + cross-ref M049 | F03877 | non-negotiable | false | 10 |
| R07718 | Trace event object — module field | dump 16221 + cross-ref M049 | F03878 | non-negotiable | false | 10 |
| R07719 | Trace event object — status field | dump 16221 + cross-ref M049 | F03879 | non-negotiable | false | 10 |
| R07720 | Trace event object — duration field | dump 16221 + cross-ref M049 | F03880 | non-negotiable | false | 10 |
| R07721 | Trace event object — metadata field | dump 16221 + cross-ref M049 | F03881 | non-negotiable | false | 10 |
| R07722 | Trace event object — links to M049 13-field span | dump 16221 + cross-ref M049 | F03882 | non-negotiable | false | 10 |
| R07723 | Cost/token — every model call charges per-token quota | dump 16222 + cross-ref MS022 | F03883 | non-negotiable | false | 10 |
| R07724 | Cost/token — quota enforced by MS022 SubscriberGuard | cross-ref MS022 | F03884 | non-negotiable | false | 10 |
| R07725 | Cost/token — emits cost_event into M049 16-event taxonomy | dump 16222 + cross-ref M049 | F03885 | non-negotiable | false | 10 |
| R07726 | Cost/token — supports per-profile cost caps via M042 | cross-ref M042 + dump 16222 | F03886 | non-negotiable | false | 10 |
| R07727 | Profile resolution — M042 9-axis choice envelope evaluated FIRST | dump 16223 + cross-ref M042 | F03887 | non-negotiable | false | 10 |
| R07728 | Profile resolution — M044 4 security profiles overlay choice envelope | cross-ref M044 + dump 16223 | F03888 | non-negotiable | false | 10 |
| R07729 | Profile resolution — M045 5 sovereign profiles overlay security profiles | cross-ref M045 + dump 16223 | F03889 | non-negotiable | false | 10 |
| R07730 | Profile resolution — operator-selected profile passed to policy decision object | dump 16223 + dump 16220 | F03890 | non-negotiable | false | 10 |
| R07731 | Policy outcome — allow | dump 16225 | F03891 | non-negotiable | false | 10 |
| R07732 | Policy outcome — deny | dump 16225 | F03892 | non-negotiable | false | 10 |
| R07733 | Policy outcome — ask | dump 16225 | F03893 | non-negotiable | false | 10 |
| R07734 | Policy outcome — sandbox | dump 16225 + cross-ref MS032 | F03894 | non-negotiable | false | 10 |
| R07735 | Doctrine — "shape matters" means schema MUST be stable BEFORE engine matures | dump 16228 | F03895 | non-negotiable | false | 10 |
| R07736 | Doctrine — selfdef policy decision schema published via MS007 surface-manifest | cross-ref MS007 | F03896 | non-negotiable | false | 10 |
| R07737 | Doctrine — sovereign-os M049 OPA/Cedar/OpenFGA engines CONSUME this schema | cross-ref M049 | F03897 | non-negotiable | false | 10 |
| R07738 | Doctrine — selfdef MS017 agent-guard ENFORCES 4-state policy outcome | cross-ref MS017 | F03898 | non-negotiable | false | 10 |
| R07739 | Doctrine — selfdef MS027 observability EMITS trace event objects | cross-ref MS027 | F03899 | non-negotiable | false | 10 |
| R07740 | Doctrine — selfdef MS026 integrity-sentinel BASELINES policy decision schemas | cross-ref MS026 | F03900 | non-negotiable | false | 10 |
| R07741 | Doctrine — selfdef MS025 detect-host event-bus TRANSPORTS trace events | cross-ref MS025 | F03901 | non-negotiable | false | 10 |
| R07742 | Doctrine — selfdef MS003 correlator + store + responder PROCESSES trace events | cross-ref MS003 | F03902 | non-negotiable | false | 10 |
| R07743 | Doctrine — selfdef MS004 14 notifier integrations DELIVER policy outcomes | cross-ref MS004 | F03903 | non-negotiable | false | 10 |
| R07744 | Doctrine — selfdef MS022 SSE quota module enforces cost/token accounting | cross-ref MS022 | F03904 | non-negotiable | false | 10 |
| R07745 | Cross-repo — MS007 typed-mirror crates publish 10-field policy schema | cross-ref MS007 + M049 | F03905 | non-negotiable | false | 10 |
| R07746 | Cross-repo — MS007 typed-mirror crates publish 13-field trace span schema | cross-ref MS007 + M049 | F03906 | non-negotiable | false | 10 |
| R07747 | Cross-repo — MS007 typed-mirror crates publish 16-event taxonomy schema | cross-ref MS007 + M049 | F03907 | non-negotiable | false | 10 |
| R07748 | Operator UX — `selfdefctl policy explain` shows policy decision object | cross-ref MS017 + dump 16220 | F03908 | non-negotiable | false | 10 |
| R07749 | Operator UX — `selfdefctl trace show <trace_id>` shows trace event chain | cross-ref MS027 + dump 16221 | F03909 | non-negotiable | false | 10 |
| R07750 | Operator UX — `selfdefctl cost report` shows token usage ledger | cross-ref MS022 + dump 16222 | F03910 | non-negotiable | false | 10 |
| R07751 | Operator UX — `selfdefctl profile current` shows resolved profile | cross-ref M042 + dump 16223 | F03911 | non-negotiable | false | 10 |
| R07752 | Operator UX — `selfdefctl policy approve <decision_id>` resolves "ask" outcome | dump 16225 + cross-ref M042 | F03912 | non-negotiable | false | 10 |
| R07753 | Test integration — MS020 L1 covers policy decision schema rendering | cross-ref MS020 | F03913 | non-negotiable | false | 10 |
| R07754 | Test integration — MS020 L2 covers 7-step model-call trace pipeline | cross-ref MS020 + dump 16232–16238 | F03914 | non-negotiable | false | 10 |
| R07755 | Test integration — MS020 L2 covers 5-step tool-call trace pipeline | cross-ref MS020 + dump 16244–16248 | F03915 | non-negotiable | false | 10 |
| R07756 | Test integration — MS020 L3 covers selfdefctl policy + trace + cost + profile + approve CLI | cross-ref MS020 | F03916 | non-negotiable | false | 10 |
| R07757 | Test integration — MS020 L4 covers seam between policy decision schema + OPA/Cedar/OpenFGA | cross-ref MS020 + M049 | F03917 | non-negotiable | false | 10 |
| R07758 | Test integration — MS020 L5 covers end-to-end action lifecycle | cross-ref MS020 + dump 16216 | F03918 | non-negotiable | false | 10 |
| R07759 | Cross-module — MS022 per-token quota composes with cost/token accounting | cross-ref MS022 | F03919 | non-negotiable | false | 10 |
| R07760 | Cross-module — MS017 agent-guard enforces policy decision outcomes | cross-ref MS017 | F03920 | non-negotiable | false | 10 |
| R07761 | Cross-module — MS016 Tetragon eBPF observes tool-call execution | cross-ref MS016 | F03921 | non-negotiable | false | 10 |
| R07762 | Cross-module — MS026 integrity-sentinel emits OCSF 2004 for policy violations | cross-ref MS026 | F03922 | non-negotiable | false | 10 |
| R07763 | Cross-module — MS013 27-SDD charter governs policy decision finding ledger | cross-ref MS013 | F03923 | non-negotiable | false | 10 |
| R07764 | Cross-module — MS019 threat model identifies policy bypass as primary attack surface | cross-ref MS019 | F03924 | non-negotiable | false | 10 |
| R07765 | Cross-module — MS027 dashboard renders policy decision histogram | cross-ref MS027 | F03925 | non-negotiable | false | 10 |
| R07766 | Cross-module — MS011 operator dashboard renders policy approval queue | cross-ref MS011 | F03926 | non-negotiable | false | 10 |
| R07767 | Cross-module — MS032 sandbox tier escalation triggered by "sandbox" outcome | cross-ref MS032 | F03927 | non-negotiable | false | 10 |
| R07768 | Cross-module — MS028 bitnet emits model_call trace events | cross-ref MS028 | F03928 | non-negotiable | false | 10 |
| R07769 | Cross-module — MS029 slm-cpu-loop emits model_call trace events | cross-ref MS029 | F03929 | non-negotiable | false | 10 |
| R07770 | Cross-module — MS030 tensor-parallel emits model_call trace events | cross-ref MS030 | F03930 | non-negotiable | false | 10 |
| R07771 | Cross-module — MS031 wasm-aot-cache subject to policy adapter-load checkpoint | cross-ref MS031 + M049 | F03931 | non-negotiable | false | 10 |
| R07772 | Cross-module — MS023 polarproxy enforces TLS-MITM policy | cross-ref MS023 | F03932 | non-negotiable | false | 10 |
| R07773 | Cross-module — MS024 bridge-l2 nftables enforces network policy | cross-ref MS024 | F03933 | non-negotiable | false | 10 |
| R07774 | Cross-module — MS015 NATS messaging transports policy decision objects | cross-ref MS015 + dump 16220 | F03934 | non-negotiable | false | 10 |
| R07775 | Cross-module — MS018 VPN-bridge enforces network policy per profile | cross-ref MS018 + M042 | F03935 | non-negotiable | false | 10 |
| R07776 | Cross-module — MS014 SSH-wrap applies tool-call policy to outbound SSH | cross-ref MS014 | F03936 | non-negotiable | false | 10 |
| R07777 | Cross-module — MS009 audit cycles trace policy decision lineage | cross-ref MS009 | F03937 | non-negotiable | false | 10 |
| R07778 | Cross-module — MS008 selfdef-on-sain01 deploys full policy+trace stack | cross-ref MS008 | F03938 | non-negotiable | false | 10 |
| R07779 | Cross-module — MS010 hardware-tune-cache informs policy decision | cross-ref MS010 | F03939 | non-negotiable | false | 10 |
| R07780 | Cross-module — MS012 perimeter coexistence applies tool-call policy at perimeter | cross-ref MS012 | F03940 | non-negotiable | false | 10 |
| R07781 | Doctrine — policy enforced ON THE BOUNDARY, NOT inside the model | dump 16220 + cross-ref M049 | F03941 | non-negotiable | false | 10 |
| R07782 | Doctrine — trace emitted WHEN action is decided, NOT after | dump 16221 | F03942 | non-negotiable | false | 10 |
| R07783 | Doctrine — every action MUST have a policy decision object | dump 16220 + 16216 | F03943 | non-negotiable | false | 10 |
| R07784 | Doctrine — every action MUST emit a trace event object | dump 16221 + 16216 | F03944 | non-negotiable | false | 10 |
| R07785 | Doctrine — every model call MUST count tokens | dump 16222 + 16236 | F03945 | non-negotiable | false | 10 |
| R07786 | Doctrine — every request MUST resolve to a profile | dump 16223 | F03946 | non-negotiable | false | 10 |
| R07787 | Doctrine — every action MUST get one of 4 outcomes | dump 16225 | F03947 | non-negotiable | false | 10 |
| R07788 | "Allow" outcome — execute action with full trace | dump 16225 + 16238 | F03948 | non-negotiable | false | 10 |
| R07789 | "Deny" outcome — refuse with reason in policy decision object | dump 16225 + architecture | F03949 | non-negotiable | false | 10 |
| R07790 | "Ask" outcome — pause + request operator approval | dump 16225 + cross-ref M042 | F03950 | non-negotiable | false | 10 |
| R07791 | "Sandbox" outcome — escalate to higher sandbox tier | dump 16225 + cross-ref MS032 | F03951 | non-negotiable | false | 10 |
| R07792 | Model-call trace MUST emit 7 events in order | dump 16232–16238 | F03952 | non-negotiable | false | 10 |
| R07793 | Tool-call trace MUST emit 5 events in order | dump 16244–16248 | F03953 | non-negotiable | false | 10 |
| R07794 | Trace events MUST be append-only | dump 16221 + architecture | F03954 | non-negotiable | false | 10 |
| R07795 | Trace events MUST be persisted to ZFS for replay | cross-ref M044 | F03955 | non-negotiable | false | 10 |
| R07796 | Trace events MUST be queryable by trace_id + event_type + timestamp | architecture + dump 16221 | F03956 | non-negotiable | false | 10 |
| R07797 | Policy decision objects MUST be persisted alongside trace events | dump 16220 + 16221 | F03957 | non-negotiable | false | 10 |
| R07798 | Policy decision objects MUST be auditable post-hoc | cross-ref MS009 | F03958 | non-negotiable | false | 10 |
| R07799 | Cost/token accounting MUST be queryable per-profile + per-session + per-day | cross-ref MS022 + dump 16222 | F03959 | non-negotiable | false | 10 |
| R07800 | Composite phase — Phase 3 catalogs the ENABLING SHAPE for M049 | dump 16210–16250 + cross-ref M049 | F03960 | non-negotiable | false | 10 |
| R07801 | Cross-repo — selfdef MS033 enforces; sovereign-os M049 orchestrates | architecture + cross-ref M049 | M00862 | non-negotiable | false | 10 |
| R07802 | Cross-repo — selfdef MS033 publishes schema; sovereign-os M049 consumes | architecture + cross-ref M049 + MS007 | M00862 | non-negotiable | false | 10 |
| R07803 | Cross-repo — sandbox outcome composes with sovereign-os M048 Module 3 + selfdef MS032 sandbox-tier escalation | cross-ref MS032 + M048 | M00861 | non-negotiable | false | 10 |
| R07804 | Cross-repo — ask outcome composes with sovereign-os M042 user-approval state | cross-ref M042 | M00861 | non-negotiable | false | 10 |
| R07805 | Cross-repo — deny outcome composes with sovereign-os M049 Policy Fabric refusal | cross-ref M049 | M00861 | non-negotiable | false | 10 |
| R07806 | Cross-repo — allow outcome composes with sovereign-os M050 Design Law "Tools prove" | cross-ref M050 | M00861 | non-negotiable | false | 10 |
| R07807 | Cross-repo — profile resolution composes with sovereign-os M050 9-axis Choice Architecture | cross-ref M042 + M050 | M00860 | non-negotiable | false | 10 |
| R07808 | Cross-repo — cost accounting composes with sovereign-os M048 Module 4 Gateway cost ledger | cross-ref M048 | M00858 | non-negotiable | false | 10 |
| R07809 | Cross-repo — trace events compose with sovereign-os M049 16-event taxonomy + 13-field span | cross-ref M049 | M00857 | non-negotiable | false | 10 |
| R07810 | Cross-repo — policy decision objects compose with sovereign-os M049 10-field Intent-Based input | cross-ref M049 | M00856 | non-negotiable | false | 10 |
| R07811 | Policy decision lifecycle — created at action proposal | dump 16244 | M00851 | non-negotiable | false | 10 |
| R07812 | Policy decision lifecycle — evaluated at policy check | dump 16245 | M00852 | non-negotiable | false | 10 |
| R07813 | Policy decision lifecycle — frozen at outcome | dump 16246 | M00853 | non-negotiable | false | 10 |
| R07814 | Policy decision lifecycle — persisted forever (audit retention) | cross-ref MS009 | M00856 | non-negotiable | false | 10 |
| R07815 | Trace event lifecycle — created at event boundary | dump 16221 | M00857 | non-negotiable | false | 10 |
| R07816 | Trace event lifecycle — buffered in NATS for guaranteed delivery | cross-ref MS015 | M00857 | non-negotiable | false | 10 |
| R07817 | Trace event lifecycle — persisted to finding-store SQLite + ZFS replay log | cross-ref MS025 + M044 | M00857 | non-negotiable | false | 10 |
| R07818 | Trace event lifecycle — replayable from ZFS snapshots | cross-ref M044 + M047 | M00857 | non-negotiable | false | 10 |
| R07819 | Cost accounting lifecycle — token count starts when API request hits Gateway | dump 16235 + cross-ref M048 | M00858 | non-negotiable | false | 10 |
| R07820 | Cost accounting lifecycle — token count finalizes when response is fully received | dump 16236 + 16237 | M00858 | non-negotiable | false | 10 |
| R07821 | Cost accounting lifecycle — cost_event emitted into M049 16-event taxonomy | cross-ref M049 | M00859 | non-negotiable | false | 10 |
| R07822 | Cost accounting lifecycle — quota deducted from MS022 SubscriberGuard per-token bucket | cross-ref MS022 | M00858 | non-negotiable | false | 10 |
| R07823 | Profile resolution lifecycle — request carries profile_id header | dump 16223 + architecture | M00860 | non-negotiable | false | 10 |
| R07824 | Profile resolution lifecycle — profile_id resolved to PROFILES.yaml entry via M041 7-canonical-contracts | cross-ref M041 + dump 16223 | M00860 | non-negotiable | false | 10 |
| R07825 | Profile resolution lifecycle — resolved profile attaches to policy decision object | dump 16220 + 16223 | M00860 | non-negotiable | false | 10 |
| R07826 | Profile resolution lifecycle — profile carries cost cap + cloud allow-list + sandbox tier default | cross-ref M042 + M044 + M045 | M00860 | non-negotiable | false | 10 |
| R07827 | Profile resolution lifecycle — anonymous request defaults to "secure" / "private" profile | dump 16223 + cross-ref M044 + M045 | M00860 | non-negotiable | false | 10 |
| R07828 | Doctrine — "shape matters" implies versioned schemas (schema_version "1.0.0" pattern) | dump 16228 + cross-ref MS028 + MS030 + MS031 schema_version pattern | M00843 | non-negotiable | false | 10 |
| R07829 | Doctrine — schema versioning enables cross-repo audit via MS007 typed-mirror crate updates | cross-ref MS007 + dump 16228 | M00862 | non-negotiable | false | 10 |
| R07830 | Project-boundary — MS033 is selfdef IPS policy+trace enforcement scope | architecture | E0331 | non-negotiable | false | 10 |
| R07831 | Project-boundary — sovereign-os M049 is the runtime-side policy orchestration scope | cross-ref M049 | E0331 | non-negotiable | false | 10 |
| R07832 | Project-boundary — cross-repo binding via MS007 typed-mirror crates (8/8 SATURATED) | cross-ref MS007 | M00862 | non-negotiable | false | 10 |
| R07833 | Cross-module — selfdef MS001 daemon core hosts policy_engine sub-service | cross-ref MS001 | M00837 | non-negotiable | false | 10 |
| R07834 | Cross-module — selfdef MS002 collector fabric emits trace events into event-bus | cross-ref MS002 | M00857 | non-negotiable | false | 10 |
| R07835 | Cross-module — selfdef MS005 notifier engine + orchestrator deliver policy outcomes | cross-ref MS005 | M00861 | non-negotiable | false | 10 |
| R07836 | Cross-module — selfdef MS006 14-functional-modules each emit per-module trace events | cross-ref MS006 | M00857 | non-negotiable | false | 10 |
| R07837 | Cross-module — selfdef MS021 shared module-script lib v2 provides emit_status JSON helper for trace events | cross-ref MS021 | M00857 | non-negotiable | false | 10 |
| R07838 | Cross-module — MS013 27-SDD charter F-2027-xxx findings track policy/trace gaps | cross-ref MS013 | M00862 | non-negotiable | false | 10 |
| R07839 | Operator references — OpenTelemetry GenAI conventions (opentelemetry.io/docs/specs/semconv/gen-ai/) | cross-ref M049 | M00857 | non-negotiable | false | 10 |
| R07840 | Operator references — OPA Rego language (openpolicyagent.org/docs/latest) | cross-ref M049 | M00856 | non-negotiable | false | 10 |
| R07841 | Operator references — Cedar authorization language (docs.cedarpolicy.com) | cross-ref M049 | M00856 | non-negotiable | false | 10 |
| R07842 | Operator references — OpenFGA Zanzibar-style RBAC (openfga.dev) | cross-ref M049 | M00856 | non-negotiable | false | 10 |
| R07843 | Operator references — OCSF event class schema | cross-ref MS026 + M049 | M00857 | non-negotiable | false | 10 |
| R07844 | Operator references — Anthropic API request/response format | cross-ref M048 + dump 16232 | M00844 | non-negotiable | false | 10 |
| R07845 | Operator references — Sigma rule format (correlator) | cross-ref MS025 sigma-correlator | M00857 | non-negotiable | false | 10 |
| R07846 | Operator references — systemd-journal-gatewayd OTel exporter | cross-ref MS027 + M048 otel-collector.service | M00857 | non-negotiable | false | 10 |
| R07847 | Doctrine — policy-as-data (decision objects) + observation-as-data (trace events) = continuity | dump 16216 + architecture | E0331 | non-negotiable | false | 10 |
| R07848 | Doctrine — policy + trace together form the AUDIT SURFACE | dump 16216 + cross-ref MS009 | E0331 | non-negotiable | false | 10 |
| R07849 | Doctrine — every action is observable (Phase 3) + governed (Phase 3) + sandboxed (Phase 4) + memory-aware (Phase 5) | dump 16216 + 16258 + 16288 | E0331 | non-negotiable | false | 10 |
| R07850 | Doctrine — Phase 3 SHALL precede Phase 4 (sandbox needs policy/trace machinery to be useful) | dump 16210 + 16250 | E0331 | non-negotiable | false | 10 |
| R07851 | Doctrine — Phase 3 SHALL precede Phase 5 (memory needs policy decisions on what to remember) | dump 16210 + 16290 + cross-ref M049 | E0331 | non-negotiable | false | 10 |
| R07852 | Schema versioning — policy decision object MUST carry schema_version "1.0.0" | architecture + cross-ref MS028 + MS030 + MS031 | F03895 | non-negotiable | false | 10 |
| R07853 | Schema versioning — trace event object MUST carry schema_version "1.0.0" | architecture + cross-ref MS028 + MS030 + MS031 | F03895 | non-negotiable | false | 10 |
| R07854 | Schema versioning — cost event object MUST carry schema_version "1.0.0" | architecture + cross-ref MS028 + MS030 + MS031 | F03895 | non-negotiable | false | 10 |
| R07855 | Output schema — policy decision serialized as JSON with stable field order | architecture + cross-ref MS028 emit_status JSON pattern | F03843 | non-negotiable | false | 10 |
| R07856 | Output schema — trace event serialized as JSONL (one event per line) | cross-ref MS026 eventstream format + dump 16221 | F03844 | non-negotiable | false | 10 |
| R07857 | Output schema — cost event serialized as JSON with token_count + cost_usd | dump 16236 + cross-ref MS022 | F03845 | non-negotiable | false | 10 |
| R07858 | Output schema — policy/trace/cost are NEWLINE-DELIMITED JSON (JSONL) compatible | cross-ref MS026 + cross-ref M049 OTel | F03844 | non-negotiable | false | 10 |
| R07859 | Output schema — OTel SpanContext propagates trace_id + parent_span_id across module boundaries | cross-ref M049 OTel GenAI | F03875 | non-negotiable | false | 10 |
| R07860 | Output schema — span hierarchy preserved (model_call > tool_call > policy_check) | dump 16244–16248 + cross-ref M049 | F03875 | non-negotiable | false | 10 |
| R07861 | Test integration — MS020 covers schema_version "1.0.0" forward-compat per object type | cross-ref MS020 + R07852–R07854 | F03917 | non-negotiable | false | 10 |
| R07862 | Test integration — MS020 covers JSONL parsing of trace event stream | cross-ref MS020 + R07856 | F03917 | non-negotiable | false | 10 |
| R07863 | Test integration — MS020 covers cross-repo schema mirror integrity (MS007 typed-mirror) | cross-ref MS020 + MS007 | F03917 | non-negotiable | false | 10 |
| R07864 | Doctrine — policy must be DETERMINISTIC (same input → same outcome) | architecture + cross-ref M049 | M00861 | non-negotiable | false | 10 |
| R07865 | Doctrine — policy decision MUST be reproducible from policy decision object | dump 16220 + architecture | M00856 | non-negotiable | false | 10 |
| R07866 | Doctrine — trace event MUST be replayable from trace event object | dump 16221 + cross-ref M047 | M00857 | non-negotiable | false | 10 |
| R07867 | Doctrine — cost accounting MUST be reproducible from token_count + model_price | cross-ref MS022 + dump 16236 | M00858 | non-negotiable | false | 10 |
| R07868 | Doctrine — policy/trace/cost together provide ACTION RECEIPT | dump 16216 + architecture | E0331 | non-negotiable | false | 10 |
| R07869 | Doctrine — every action has a unique trace_id (UUID v4 or similar) | dump 16221 + cross-ref M049 | F03875 | non-negotiable | false | 10 |
| R07870 | Doctrine — every action has a unique decision_id (linked to trace_id) | dump 16220 + architecture | F03908 | non-negotiable | false | 10 |
| R07871 | Doctrine — trace events from different modules SHARE trace_id (cross-module attribution) | cross-ref M049 OTel + dump 16221 | F03882 | non-negotiable | false | 10 |
| R07872 | Doctrine — policy decision references parent decision_id (decision tree) | architecture + dump 16244 | F03873 | non-negotiable | false | 10 |
| R07873 | Doctrine — model call trace events form a STRICT sequence (no out-of-order delivery within trace_id) | dump 16232–16238 + architecture | F03952 | non-negotiable | false | 10 |
| R07874 | Doctrine — tool call trace events form a STRICT sequence (no out-of-order within trace_id) | dump 16244–16248 + architecture | F03953 | non-negotiable | false | 10 |
| R07875 | Doctrine — trace events MAY be reordered ACROSS trace_ids (best-effort delivery) | architecture + cross-ref MS015 NATS | F03954 | non-negotiable | false | 10 |
| R07876 | Doctrine — trace events MUST include latency (start to end of span) | dump 16221 + cross-ref M049 13-field span | F03880 | non-negotiable | false | 10 |
| R07877 | Doctrine — trace events MUST include status (ok/failed/timeout/cancelled) | dump 16221 + cross-ref M049 | F03879 | non-negotiable | false | 10 |
| R07878 | Cross-cycle — MS033 Phase 3 doctrine extends MS017 agent-guard's policy enforcement | cross-ref MS017 + dump 16220 | F03898 | non-negotiable | false | 10 |
| R07879 | Cross-cycle — MS033 Phase 3 doctrine extends MS027 observability's event emission | cross-ref MS027 + dump 16221 | F03899 | non-negotiable | false | 10 |
| R07880 | Cross-cycle — MS033 Phase 3 doctrine extends MS022 SSE quota's token-bucket model | cross-ref MS022 + dump 16222 | F03904 | non-negotiable | false | 10 |
| R07881 | Cross-cycle — MS033 Phase 3 doctrine extends MS026 integrity-sentinel's drift event emission | cross-ref MS026 + dump 16221 | F03900 | non-negotiable | false | 10 |
| R07882 | Cross-cycle — MS033 Phase 3 doctrine extends MS016 Tetragon's tracingpolicy framework | cross-ref MS016 + dump 16245 | F03921 | non-negotiable | false | 10 |
| R07883 | Cross-cycle — MS033 Phase 3 doctrine extends MS032 sandbox-tier choice with "sandbox" outcome | cross-ref MS032 + dump 16225 | F03894 | non-negotiable | false | 10 |
| R07884 | Cross-cycle — MS033 Phase 3 doctrine extends MS021 module-script-lib v2 emit_status pattern | cross-ref MS021 + dump 16221 | F03899 | non-negotiable | false | 10 |
| R07885 | Cross-cycle — MS033 Phase 3 doctrine extends MS013 27-SDD charter's F-2027-xxx finding format | cross-ref MS013 + dump 16220 | F03923 | non-negotiable | false | 10 |
| R07886 | Cross-cycle — MS033 Phase 3 doctrine extends MS009 audit cycles' replay model | cross-ref MS009 + dump 16221 | F03937 | non-negotiable | false | 10 |
| R07887 | Cross-cycle — MS033 Phase 3 doctrine extends MS003 correlator + store + responder pipeline | cross-ref MS003 + dump 16216 | F03902 | non-negotiable | false | 10 |
| R07888 | Cross-cycle — MS033 Phase 3 doctrine extends MS005 notifier engine for policy outcomes | cross-ref MS005 + dump 16225 | F03903 | non-negotiable | false | 10 |
| R07889 | Cross-cycle — MS033 Phase 3 doctrine extends MS025 detect-host event-bus | cross-ref MS025 + dump 16221 | F03901 | non-negotiable | false | 10 |
| R07890 | Cross-cycle — MS033 Phase 3 doctrine extends MS001 daemon-core orchestrator | cross-ref MS001 + dump 16216 | F03919 | non-negotiable | false | 10 |
| R07891 | Cross-cycle — MS033 Phase 3 doctrine extends MS002 14-collector-fabric trace emission | cross-ref MS002 + dump 16221 | F03834 | non-negotiable | false | 10 |
| R07892 | Cross-cycle — MS033 Phase 3 doctrine extends MS006 14-functional-modules trace emission | cross-ref MS006 + dump 16221 | F03836 | non-negotiable | false | 10 |
| R07893 | Cross-cycle — MS033 Phase 3 doctrine extends MS010 hardware-tune-cache + MS028/MS029/MS030/MS031 hardware-aware inference modules | cross-ref MS010 + MS028 + MS029 + MS030 + MS031 | F03939 | non-negotiable | false | 10 |
| R07894 | Cross-cycle — MS033 Phase 3 doctrine extends MS011 operator dashboard surfaces | cross-ref MS011 + dump 16216 | F03926 | non-negotiable | false | 10 |
| R07895 | Cross-cycle — MS033 Phase 3 doctrine extends MS012 perimeter coexistence integration | cross-ref MS012 + dump 16244 | F03940 | non-negotiable | false | 10 |
| R07896 | Cross-cycle — MS033 Phase 3 doctrine extends MS014 SSH-wrap client-side defense | cross-ref MS014 + dump 16244 | F03936 | non-negotiable | false | 10 |
| R07897 | Cross-cycle — MS033 Phase 3 doctrine extends MS015 NATS messaging backbone | cross-ref MS015 + dump 16221 | F03934 | non-negotiable | false | 10 |
| R07898 | Cross-cycle — MS033 Phase 3 doctrine extends MS018 VPN-bridge per-profile integration | cross-ref MS018 + dump 16245 | F03935 | non-negotiable | false | 10 |
| R07899 | Cross-cycle — MS033 Phase 3 doctrine extends MS019 threat model attack surface analysis | cross-ref MS019 + dump 16245 | F03924 | non-negotiable | false | 10 |
| R07900 | Cross-cycle — MS033 Phase 3 doctrine extends MS020 L1-L5 test harness coverage | cross-ref MS020 + dump 16221 | F03913–F03918 | non-negotiable | false | 10 |
| R07901 | Cross-cycle — MS033 Phase 3 doctrine extends MS023 polarproxy TLS-MITM policy | cross-ref MS023 + dump 16244 | F03932 | non-negotiable | false | 10 |
| R07902 | Cross-cycle — MS033 Phase 3 doctrine extends MS024 bridge-l2 nftables ruleset | cross-ref MS024 + dump 16244 | F03933 | non-negotiable | false | 10 |
| R07903 | Cross-cycle — MS033 Phase 3 doctrine extends MS008 selfdef-on-sain01 reference deployment | cross-ref MS008 + dump 16216 | F03938 | non-negotiable | false | 10 |
| R07904 | Cross-cycle — MS033 Phase 3 doctrine extends MS007 8/8 SATURATED typed-mirror crates | cross-ref MS007 + dump 16220 | F03905 + F03906 + F03907 | non-negotiable | false | 10 |
| R07905 | Cross-cycle — MS033 Phase 3 doctrine bridges to MS032 Phase 4 (Sandbox Execution) | cross-ref MS032 + dump 16250 | F03927 | non-negotiable | false | 10 |
| R07906 | Cross-cycle — MS033 Phase 3 doctrine bridges to Phase 5 (Memory and MAP) | dump 16288 + cross-ref M028 + M036 | E0331 | non-negotiable | false | 10 |
| R07907 | Sovereign-os realization — M049 Continuity through observability and policy IS Phase 3 fully realized at runtime layer | cross-ref M049 | E0331 | non-negotiable | false | 10 |
| R07908 | Sovereign-os realization — M050 Design Law "Tools prove" REQUIRES Phase 3 trace-of-execution | cross-ref M050 | F03861 | non-negotiable | false | 10 |
| R07909 | Sovereign-os realization — M051 Section 9 Policy & Observability IS architect-level Phase 3 implementation guide | cross-ref M051 | E0331 | non-negotiable | false | 10 |
| R07910 | Sovereign-os realization — M042 Choice Architecture profile-bundle integrates with Phase 3 profile resolution | cross-ref M042 | M00860 | non-negotiable | false | 10 |
| R07911 | Sovereign-os realization — M048 Module 9 Observability Fabric + Module 10 Policy Fabric IS Phase 3 module decomposition | cross-ref M048 | E0331 | non-negotiable | false | 10 |
| R07912 | Sovereign-os realization — M047 Continuity Manager preserves Phase 3 traces across hibernate/restore | cross-ref M047 | F03866 | non-negotiable | false | 10 |
| R07913 | Sovereign-os realization — M046 LoRA foundry adapter-load goes through Phase 3 policy checkpoint (M049 8-checkpoint) | cross-ref M046 + cross-ref M049 | F03856 | non-negotiable | false | 10 |
| R07914 | Sovereign-os realization — M043 Bridge Layer AVX-512 Routing Brain 8 bulk-eval decisions feed into Phase 3 route_selected event | cross-ref M043 + dump 16234 | M00846 | non-negotiable | false | 10 |
| R07915 | Sovereign-os realization — M028 Memory OS write/read/forget operations go through Phase 3 policy memory_write checkpoint | cross-ref M028 + cross-ref M049 | F03856 | non-negotiable | false | 10 |
| R07916 | Sovereign-os realization — M032 Cloud Expert Plane cloud_call events route through Phase 3 policy cloud_provider_call checkpoint | cross-ref M032 + cross-ref M049 | F03856 | non-negotiable | false | 10 |
| R07917 | Sovereign-os realization — M034 Anthropic-first Gateway emits 7-step model_call trace per request | cross-ref M034 + dump 16232–16238 | F03914 | non-negotiable | false | 10 |
| R07918 | Sovereign-os realization — M041 7-canonical-contracts SPEC.md + WORKFLOW.md + PROFILES.yaml + EVALS.yaml + POLICY.yaml + MODEL_REGISTRY.yaml + MAP.json encode Phase 3 policy inputs | cross-ref M041 | M00856 | non-negotiable | false | 10 |
| R07919 | Sovereign-os realization — M037 Spec/TDD/agent-evals evidence-driven autonomy CONSUMES Phase 3 trace events for evaluation | cross-ref M037 + dump 16221 | F03899 | non-negotiable | false | 10 |
| R07920 | Composite — MS033 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Phase 3 Policy And Trace from dump 16210-16250 ("Every action becomes observable and governed" + 5-element Add list policy-decision-object/trace-event-object/cost-token-accounting/profile-resolution/4-state-allow-deny-ask-sandbox + 7-step model-call trace template + 5-step tool-call trace template + "shape matters before sophisticated policy" doctrine); cross-module enforcement via 10+ selfdef modules (MS001/MS002/MS003/MS004/MS005/MS006/MS013/MS017/MS021/MS022/MS025/MS026/MS027) + 6 IPS-side functional modules (MS010/MS028/MS029/MS030/MS031) + 4 hardware-aware modules + sandbox-tier integration via MS032; cross-repo binding to sovereign-os M042 Choice Architecture + M046 LoRA foundry + M047 Continuity + M048 Module 9-10 Observability+Policy Fabric + M049 OPA/Cedar/OpenFGA orchestrator + M050 Design Law "Tools prove" + M051 architect-level implementation guide; cross-repo schema binding via MS007 typed-mirror crates (10-field policy + 13-field span + 16-event taxonomy) | dump 16210–16250 + cross-ref MS007 + MS017 + MS022 + MS027 + M042 + M046 + M047 + M048 + M049 + M050 + M051 | E0331 + E0332 + E0333 + E0334 + E0335 + E0336 + E0337 + E0338 + E0339 + E0340 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: Phase 3 doctrine + 5-element Add list (R07681–R07688) + 7-step model-call + 5-step tool-call trace templates (R07689–R07702) + 10-field policy decision object schema + decision + reason (R07703–R07714) + 7-field trace event object + M049 13-field span linkage (R07715–R07722) + cost/token + MS022 SubscriberGuard + M049 cost_event + M042 per-profile caps (R07723–R07726) + profile resolution + M042+M044+M045 overlay (R07727–R07730) + 4-state outcome (R07731–R07734) + 9 selfdef cross-module enforcement doctrines (R07735–R07744) + cross-repo schema mirroring (R07745–R07747) + 5 operator UX CLI commands (R07748–R07752) + MS020 L1-L5 test integration (R07753–R07758) + 22 cross-module composition rows (R07759–R07780) + 10 doctrine rows (R07781–R07790) + 4-outcome behavior (R07791) + sequence invariants (R07792–R07796) + persistence invariants (R07797–R07799) + Phase 3 phase-doctrine (R07800) + 10 cross-repo composition rows (R07801–R07810) + lifecycle rows (R07811–R07827) + shape-matters versioning (R07828–R07829) + project-boundary (R07830–R07832) + 6 selfdef cross-module composition (R07833–R07838) + 8 operator references (R07839–R07846) + 5 Phase 3 doctrine summary rows (R07847–R07851) + 7 schema versioning + output schema rows (R07852–R07858) + 2 OTel span hierarchy rows (R07859–R07860) + 3 test integration rows (R07861–R07863) + 4 determinism doctrine rows (R07864–R07867) + 5 receipt doctrine rows (R07868–R07872) + 6 sequence-and-replay doctrine rows (R07873–R07877) + 23 cross-cycle integration rows (R07878–R07900) + 5 cross-cycle continuation rows (R07901–R07906) + 13 sovereign-os realization rows (R07907–R07919) + composite (R07920)
- Source range 41 lines (dump 16210–16250) yields 240 R-rows representing a 5.85:1 R-per-line ratio (the doctrinal block is intentionally compact; architectural elaboration via cross-module + cross-repo bindings carries the bulk per established pattern)
- Project boundary — MS033 is the selfdef IPS Phase 3 policy + trace enforcement scope; sovereign-os M049 Continuity-through-observability-and-policy orchestrates at the runtime layer; cross-repo binding via MS007 typed-mirror crates publishes the 10-field policy schema + 13-field trace span + 16-event taxonomy

## Cross-references

- Adjacent INDEX rows: MS032 Sandbox tiers / MS034 Memory plane
- Source — dump 16210–16250 Phase 3 Policy And Trace doctrinal block (paired with MS032 Phase 4 Sandbox Execution adjacent block)
- Cross-repo realization — sovereign-os M042 Choice Architecture 9-axis + M044 4 security profiles + M045 5 sovereign profiles + M046 LoRA foundry 6 before-training + 7 training-to-deployment + M047 Continuity Manager 6 primitives + 8 states + M048 Module 9 Observability Fabric + Module 10 Policy Fabric + Module 11 Config Resolver + M049 OPA/Cedar/OpenFGA + 16-event taxonomy + 13-field span + 10-field Intent-Based Policy input + M050 Design Law "Tools prove" + M051 architect Section 9 Policy & Observability
- Selfdef integration — MS001 daemon core + MS002 14-collector-fabric + MS003 correlator+store+responder+signing + MS004 14-notifier-integrations + MS005 notifier engine + MS006 14-functional-modules + MS007 8/8 SATURATED typed-mirror crates + MS008 selfdef-on-sain01 + MS009 audit cycles + MS010 hardware-tune-cache + MS011 operator dashboard + MS012 perimeter coexistence + MS013 27-SDD charter + MS014 SSH-wrap + MS015 NATS messaging + MS016 eBPF+Tetragon + MS017 agent-guard + MS018 VPN-bridge + MS019 threat model + MS020 L1-L5 test harness + MS021 shared module-script lib v2 + MS022 SSE quota + MS023 polarproxy + MS024 bridge-l2 + MS025 detect-host + MS026 integrity-sentinel + MS027 observability + MS028 bitnet-gpu-inference + MS029 slm-cpu-loop + MS030 tensor-parallel + MS031 wasm-aot-cache + MS032 sandbox tiers all integrate with Phase 3 doctrine
- Cross-repo binding — MS007 audit-manifest + surface-manifest + doc-manifest + dashboard-manifest + ux-checklist + auth-tier + bashrc-install + history-sink (SATURATED 8/8) typed-mirror crates carry the 10-field policy + 13-field span + 16-event schemas across selfdef + sovereign-os
- Operator references: opentelemetry.io/docs/specs/semconv/gen-ai/ + openpolicyagent.org/docs/latest + docs.cedarpolicy.com + openfga.dev + OCSF event class schema + Anthropic API spec + Sigma rule format + systemd-journal-gatewayd OTel exporter
