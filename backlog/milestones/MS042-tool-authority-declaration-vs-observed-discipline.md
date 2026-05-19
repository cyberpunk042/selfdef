# MS042 — Tool authority — declaration-vs-observed discipline — IPS-side projection (CATALOG CLOSE)

**Parent**: selfdef IPS daemon — boundary-enforcement layer of the cyberpunk042 ecosystem
**Source**: `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 17422-17445 (Tool Authority — 7 declaration fields + declaration-vs-observed mismatch handling + example block+quarantine+trace)
**Cross-repo mirror**: sovereign-os M056 (canonical authority model — tool-authority arc) + M054 Tool typed interface — selfdef receives this canon through MS007 typed mirrors only
**Project boundary**: this milestone catalogs ONLY the IPS-side enforcement of tool-declaration verification + observed-behavior comparison + violation response; tool-execution semantics live in sovereign-os M054 Tool typed interface + M058 hardware-aware scheduler

## Projection statement

> "Tool calls should declare: read paths / write paths / network domains / environment variables / secret access / expected side effects / rollback." (dump 17424-17432)

> "If declaration and observed behavior differ, the runtime should flag it." (dump 17434-17435)

> "Example: declared: read-only / observed: opened socket / result: block + quarantine + trace" (dump 17437-17445)

The IPS daemon is the **observed-behavior arbiter** for tool calls. Every tool call enters with a 7-field declaration (signed by the caller); the IPS observes actual behavior through its existing instrumentation surface (fanotify for filesystem paths, eBPF for network domains, ptrace/seccomp for environment variable access, kernel keyring for secret access, MS036 tier-specific sandboxes); on declaration-vs-observed mismatch the response is the 3-step **block + quarantine + trace** protocol.

## Epics (E0421-E0430)

| epic | name | source |
|---|---|---|
| E0421 | Declaration field 1 — read paths | dump 17424 |
| E0422 | Declaration field 2 — write paths | dump 17425 |
| E0423 | Declaration field 3 — network domains | dump 17426 |
| E0424 | Declaration field 4 — environment variables | dump 17427 |
| E0425 | Declaration field 5 — secret access | dump 17428 |
| E0426 | Declaration field 6 — expected side effects | dump 17429 |
| E0427 | Declaration field 7 — rollback | dump 17430 |
| E0428 | Observed-behavior monitor — fanotify + eBPF + ptrace/seccomp + keyring + sandbox introspection | dump 17434-17435 + architecture |
| E0429 | Declaration-vs-observed comparator + mismatch detector | dump 17434-17435 |
| E0430 | Mismatch response — block + quarantine + trace | dump 17437-17445 |

## Modules (M01071-M01096)

| module | name | source |
|---|---|---|
| M01071 | selfdef-tool-declaration-field-read-paths | dump 17424 + cross-ref MS037 |
| M01072 | selfdef-tool-declaration-field-write-paths | dump 17425 + cross-ref MS037 |
| M01073 | selfdef-tool-declaration-field-network-domains | dump 17426 + cross-ref MS038 |
| M01074 | selfdef-tool-declaration-field-env-vars | dump 17427 + architecture |
| M01075 | selfdef-tool-declaration-field-secret-access | dump 17428 + architecture |
| M01076 | selfdef-tool-declaration-field-side-effects | dump 17429 + cross-ref MS041 |
| M01077 | selfdef-tool-declaration-field-rollback | dump 17430 + cross-ref MS041 |
| M01078 | selfdef-tool-declaration-signer | cross-ref MS003 + dump 17422-17432 |
| M01079 | selfdef-tool-declaration-validator | architecture + dump 17422-17432 |
| M01080 | selfdef-tool-observed-fanotify-monitor | cross-ref MS037 + architecture |
| M01081 | selfdef-tool-observed-ebpf-monitor | cross-ref MS024 + cross-ref MS038 |
| M01082 | selfdef-tool-observed-ptrace-seccomp-monitor | architecture + cross-ref MS036 |
| M01083 | selfdef-tool-observed-keyring-monitor | architecture |
| M01084 | selfdef-tool-observed-sandbox-introspector | cross-ref MS036 |
| M01085 | selfdef-tool-comparator-engine | dump 17434-17435 |
| M01086 | selfdef-tool-mismatch-classifier | dump 17437-17445 |
| M01087 | selfdef-tool-response-blocker | dump 17443 + cross-ref MS036 |
| M01088 | selfdef-tool-response-quarantiner | dump 17444 + cross-ref MS036 |
| M01089 | selfdef-tool-response-tracer | dump 17445 + cross-ref M049 |
| M01090 | selfdef-tool-receipt-store | architecture + cross-ref MS037 |
| M01091 | selfdef-tool-replay-validator | cross-ref MS009 |
| M01092 | selfdef-tool-typed-mirror | cross-ref MS007 |
| M01093 | selfdef-tool-event-emitter | cross-ref M049 + cross-ref MS026 |
| M01094 | selfdef-tool-quarantine-archive | architecture + cross-ref MS037 |
| M01095 | selfdef-tool-trust-score-tracker | architecture |
| M01096 | selfdef-tool-authority-fsm-bridge | cross-ref MS039 + cross-ref MS040 |

## Features (F04921-F05040)

| feature | name | source |
|---|---|---|
| F04921 | Declaration — read paths field (list of POSIX glob patterns) | dump 17424 |
| F04922 | Declaration — read paths enforced via fanotify FAN_ACCESS mask | cross-ref MS037 |
| F04923 | Declaration — read paths empty list means no read access | dump 17424 + architecture |
| F04924 | Declaration — read paths supports negation (!pattern) | architecture |
| F04925 | Declaration — read paths normalized to absolute paths | architecture |
| F04926 | Declaration — write paths field (list of POSIX glob patterns) | dump 17425 |
| F04927 | Declaration — write paths enforced via fanotify FAN_MODIFY + FAN_CLOSE_WRITE | cross-ref MS037 |
| F04928 | Declaration — write paths empty list means no write access | dump 17425 |
| F04929 | Declaration — write paths require MS037 filesystem-grant L4 issuance | cross-ref MS037 |
| F04930 | Declaration — write paths trigger ZFS snapshot pre-commit (high-risk) | cross-ref MS041 + MS037 |
| F04931 | Declaration — network domains field (list of FQDN or CIDR) | dump 17426 |
| F04932 | Declaration — network domains enforced via MS038 network boundary | cross-ref MS038 |
| F04933 | Declaration — network domains "" (empty) means offline | dump 17426 + cross-ref MS038 |
| F04934 | Declaration — network domains map to capability_word.network_scope | cross-ref MS035 + cross-ref MS038 |
| F04935 | Declaration — network domains require MS038 network-grant L4 issuance | cross-ref MS038 |
| F04936 | Declaration — environment variables field (allowlist of env-var names) | dump 17427 |
| F04937 | Declaration — environment variables enforced via ptrace + seccomp filter | architecture + cross-ref MS036 |
| F04938 | Declaration — environment variables empty list means no env access | dump 17427 |
| F04939 | Declaration — environment variables redacted from logs by default | architecture |
| F04940 | Declaration — environment variables values never cited in trace spans | cross-ref M049 |
| F04941 | Declaration — secret access field (list of secret-key references) | dump 17428 |
| F04942 | Declaration — secret access enforced via Linux kernel keyring | architecture |
| F04943 | Declaration — secret access empty list means no secret access | dump 17428 |
| F04944 | Declaration — secret access emits OCSF Audit Activity class 1003 on every read | cross-ref MS026 |
| F04945 | Declaration — secret access values never cited in trace spans | cross-ref M049 |
| F04946 | Declaration — expected side effects field (typed list of effects) | dump 17429 |
| F04947 | Declaration — expected side effects enum (file-write/process-spawn/socket-open/signal-send/ioctl/mmap/syscall-N) | architecture |
| F04948 | Declaration — expected side effects empty list means pure function | dump 17429 |
| F04949 | Declaration — expected side effects cite MS041 commit-type when durable | cross-ref MS041 |
| F04950 | Declaration — expected side effects rollback-availability declared | cross-ref MS041 |
| F04951 | Declaration — rollback field (rollback artifact reference) | dump 17430 |
| F04952 | Declaration — rollback field values: {available/available-with-loss/unavailable/irreversible} | cross-ref MS041 |
| F04953 | Declaration — rollback "unavailable" requires high-risk classification | cross-ref MS041 |
| F04954 | Declaration — rollback artifact signed via MS003 | cross-ref MS003 |
| F04955 | Declaration — rollback artifact stored under /var/lib/selfdef/tool-rollback/ | architecture |
| F04956 | Declaration signer — produces signed declaration envelope | cross-ref MS003 |
| F04957 | Declaration signer — envelope = CBOR {tool-id, 7 fields, timestamp, actor, signature} | architecture + cross-ref MS003 |
| F04958 | Declaration signer — signature uses MS003 selfdef-signing key | cross-ref MS003 |
| F04959 | Declaration signer — envelope stored in /var/lib/selfdef/tool-declarations/ | architecture |
| F04960 | Declaration signer — envelope retention 365 days minimum | cross-ref MS037 |
| F04961 | Declaration validator — checks all 7 fields present | dump 17424-17430 |
| F04962 | Declaration validator — checks all 7 fields well-formed | architecture |
| F04963 | Declaration validator — checks declaration signed | cross-ref MS003 |
| F04964 | Declaration validator — failure rejects tool call | architecture |
| F04965 | Declaration validator — failure emits OCSF Detection Finding class 2004 | cross-ref MS026 |
| F04966 | Observed — fanotify monitors file accesses against declared read-paths | cross-ref MS037 |
| F04967 | Observed — fanotify monitors file modifications against declared write-paths | cross-ref MS037 |
| F04968 | Observed — eBPF monitors connect() against declared network-domains | cross-ref MS024 + cross-ref MS038 |
| F04969 | Observed — eBPF monitors sendmsg() against declared network-domains | cross-ref MS024 + cross-ref MS038 |
| F04970 | Observed — ptrace+seccomp monitors getenv() against declared env-vars | architecture |
| F04971 | Observed — kernel keyring monitors keyctl() against declared secret-access | architecture |
| F04972 | Observed — sandbox introspector monitors syscalls against declared side-effects | cross-ref MS036 |
| F04973 | Observed — observability emits M049 13-field span on every observation | cross-ref M049 |
| F04974 | Observed — observations buffered with declared baseline for diffing | architecture |
| F04975 | Observed — observation buffer cleared on tool-call completion | architecture |
| F04976 | Comparator — diffs declared read-paths vs observed file accesses | dump 17434 + cross-ref MS037 |
| F04977 | Comparator — diffs declared write-paths vs observed file modifications | dump 17434 + cross-ref MS037 |
| F04978 | Comparator — diffs declared network-domains vs observed sockets | dump 17434 + cross-ref MS038 |
| F04979 | Comparator — diffs declared env-vars vs observed getenv() calls | dump 17434 + architecture |
| F04980 | Comparator — diffs declared secret-access vs observed keyring queries | dump 17434 + architecture |
| F04981 | Comparator — diffs declared side-effects vs observed syscalls | dump 17434 + cross-ref MS036 |
| F04982 | Comparator — emits per-field mismatch result | architecture + dump 17434-17435 |
| F04983 | Comparator — mismatch result CBOR-encoded + MS003-signed | cross-ref MS003 |
| F04984 | Comparator — mismatch result emits M049 span | cross-ref M049 |
| F04985 | Comparator — mismatch result emits OCSF Detection Finding class 2004 | cross-ref MS026 |
| F04986 | Mismatch classifier — classifies mismatch severity (low/medium/high/critical) | dump 17437-17445 + architecture |
| F04987 | Mismatch classifier — example "declared read-only / observed opened socket" = critical | dump 17437-17442 |
| F04988 | Mismatch classifier — declared write-paths violation = high (file write outside declared) | architecture |
| F04989 | Mismatch classifier — declared env-var violation = medium (extra env-var read) | architecture |
| F04990 | Mismatch classifier — declared secret-access violation = critical (unexpected secret read) | architecture |
| F04991 | Response — block (terminate tool process immediately) | dump 17443 |
| F04992 | Response — block via SIGKILL after seccomp trap | architecture + cross-ref MS036 |
| F04993 | Response — block emits OCSF System Activity class 1001 (process kill) | cross-ref MS026 |
| F04994 | Response — quarantine (move tool artifacts to quarantine dir) | dump 17444 |
| F04995 | Response — quarantine path = /var/lib/selfdef/quarantine/tools/<tool-id>-<timestamp>/ | architecture |
| F04996 | Response — quarantine artifacts include declaration envelope + observed log + mismatch result | architecture |
| F04997 | Response — quarantine signed via MS003 | cross-ref MS003 |
| F04998 | Response — quarantine retained 365 days minimum | cross-ref MS037 |
| F04999 | Response — quarantine emits OCSF Audit Activity class 1003 | cross-ref MS026 |
| F05000 | Response — trace (M049 13-field span with mismatch detail) | dump 17445 + cross-ref M049 |
| F05001 | Response — trace includes declaration digest | cross-ref MS003 |
| F05002 | Response — trace includes observed-behavior digest | architecture + cross-ref M049 |
| F05003 | Response — trace includes mismatch field list | architecture |
| F05004 | Response — trace cross-referenced from quarantine artifacts | architecture |
| F05005 | Response — full block+quarantine+trace 3-step protocol atomic | dump 17443-17445 |
| F05006 | Receipt store — every tool call produces receipt {declaration, observed, comparator, classifier, response} | architecture |
| F05007 | Receipt store — receipts CBOR-encoded + MS003-signed | cross-ref MS003 |
| F05008 | Receipt store — receipts retained 365 days minimum | cross-ref MS037 |
| F05009 | Receipt store — receipts indexed by tool-id, trace-id, actor, mismatch-severity | architecture |
| F05010 | Receipt store — receipts queryable via MS007 typed-mirror interface | cross-ref MS007 |
| F05011 | Replay validator — verifies historical tool-call chain integrity | cross-ref MS009 |
| F05012 | Replay validator — detects missing/malformed signatures on receipts | cross-ref MS003 + cross-ref MS009 |
| F05013 | Replay validator — detects mismatch responses not logged | architecture + cross-ref MS009 |
| F05014 | Replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 |
| F05015 | Replay validator — runs daily as cron unit | cross-ref MS009 |
| F05016 | Replay validator — failures halt new tool calls until resolved | architecture |
| F05017 | Typed-mirror — published under MS007 8/8 SATURATED scheme | cross-ref MS007 |
| F05018 | Typed-mirror — ToolDeclaration struct (7 fields + signature) | cross-ref MS007 + dump 17424-17430 |
| F05019 | Typed-mirror — ObservedBehavior struct (6 observation channels + digest) | cross-ref MS007 + dump 17434-17435 |
| F05020 | Typed-mirror — MismatchResult struct (per-field diff + severity + response) | cross-ref MS007 + dump 17437-17445 |
| F05021 | Typed-mirror — ResponseAction enum (Block/Quarantine/Trace combined) | cross-ref MS007 + dump 17443-17445 |
| F05022 | Typed-mirror — Rust crate name selfdef-tool-mirror | cross-ref MS007 |
| F05023 | Event emitter — every tool-call invocation emits M049 trace | cross-ref M049 |
| F05024 | Event emitter — every mismatch emits OCSF Detection Finding class 2004 | cross-ref MS026 |
| F05025 | Event emitter — every quarantine emits OCSF Audit Activity class 1003 | cross-ref MS026 |
| F05026 | Event emitter — every block emits OCSF System Activity class 1001 | cross-ref MS026 |
| F05027 | Quarantine archive — supports operator review via dashboard surface | cross-ref MS007 |
| F05028 | Quarantine archive — supports operator restore on false-positive | cross-ref MS003 + cross-ref MS007 |
| F05029 | Quarantine archive — supports forensic export | architecture |
| F05030 | Trust score tracker — accumulates tool trust based on declaration-fidelity over time | architecture |
| F05031 | Trust score tracker — score persisted under /var/lib/selfdef/tool-trust/ | architecture |
| F05032 | Trust score tracker — score factored into MS040 profile evaluation | cross-ref MS040 |
| F05033 | Trust score tracker — score decays on mismatch history | architecture |
| F05034 | Trust score tracker — score exposed via MS007 typed mirror | cross-ref MS007 |
| F05035 | Authority FSM bridge — tool calls enter at L0 Observe by default | cross-ref MS039 |
| F05036 | Authority FSM bridge — tool calls promoted to L4 Execute only after declaration validation | cross-ref MS039 |
| F05037 | Authority FSM bridge — mismatch demotes tool to L0 + emits OCSF Detection class 2004 | cross-ref MS039 + cross-ref MS026 |
| F05038 | Authority FSM bridge — mismatch promotes mismatch-record to L5 Commit (signed audit) | cross-ref MS039 + cross-ref MS041 |
| F05039 | Authority FSM bridge — tool-call observability span carries authority-level field | cross-ref MS039 + cross-ref M049 |
| F05040 | CATALOG CLOSE — MS042 final selfdef milestone; selfdef catalog reaches 42/42 milestones | architecture + operator standing direction |

## Requirements (R09841-R10080)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R09841 | Doctrinal — tool calls SHOULD declare 7 fields | dump 17422-17432 | F04921 | non-negotiable | false | 10 |
| R09842 | Doctrinal — IPS MUST enforce declaration as strict (operator override of dump "should") | operator standing direction + dump 17422 | F04956 | non-negotiable | false | 10 |
| R09843 | Doctrinal — if declaration and observed behavior differ, runtime should flag it | dump 17434-17435 | F04985 | non-negotiable | false | 10 |
| R09844 | Doctrinal — mismatch response = block + quarantine + trace | dump 17443-17445 | F05005 | non-negotiable | false | 10 |
| R09845 | Doctrinal — example "declared read-only / observed opened socket" = block+quarantine+trace | dump 17437-17445 | F04987 | non-negotiable | false | 10 |
| R09846 | Field 1 — read paths declared as list of POSIX glob patterns | dump 17424 | F04921 | non-negotiable | false | 10 |
| R09847 | Field 1 — read paths enforced via fanotify FAN_ACCESS mask | cross-ref MS037 | F04922 | non-negotiable | false | 10 |
| R09848 | Field 1 — read paths empty list means no read access | dump 17424 | F04923 | non-negotiable | false | 10 |
| R09849 | Field 1 — read paths supports negation (!pattern) | architecture | F04924 | non-negotiable | false | 10 |
| R09850 | Field 1 — read paths normalized to absolute paths | architecture | F04925 | non-negotiable | false | 10 |
| R09851 | Field 2 — write paths declared as list of POSIX glob patterns | dump 17425 | F04926 | non-negotiable | false | 10 |
| R09852 | Field 2 — write paths enforced via fanotify FAN_MODIFY + FAN_CLOSE_WRITE | cross-ref MS037 | F04927 | non-negotiable | false | 10 |
| R09853 | Field 2 — write paths empty list means no write access | dump 17425 | F04928 | non-negotiable | false | 10 |
| R09854 | Field 2 — write paths require MS037 filesystem-grant L4 issuance | cross-ref MS037 | F04929 | non-negotiable | false | 10 |
| R09855 | Field 2 — write paths trigger ZFS snapshot pre-commit (high-risk) | cross-ref MS041 + MS037 | F04930 | non-negotiable | false | 10 |
| R09856 | Field 3 — network domains declared as list of FQDN or CIDR | dump 17426 | F04931 | non-negotiable | false | 10 |
| R09857 | Field 3 — network domains enforced via MS038 network boundary | cross-ref MS038 | F04932 | non-negotiable | false | 10 |
| R09858 | Field 3 — network domains "" (empty) means offline | dump 17426 + cross-ref MS038 | F04933 | non-negotiable | false | 10 |
| R09859 | Field 3 — network domains map to capability_word.network_scope | cross-ref MS035 + MS038 | F04934 | non-negotiable | false | 10 |
| R09860 | Field 3 — network domains require MS038 network-grant L4 issuance | cross-ref MS038 | F04935 | non-negotiable | false | 10 |
| R09861 | Field 4 — environment variables declared as allowlist of env-var names | dump 17427 | F04936 | non-negotiable | false | 10 |
| R09862 | Field 4 — environment variables enforced via ptrace + seccomp filter | architecture + cross-ref MS036 | F04937 | non-negotiable | false | 10 |
| R09863 | Field 4 — environment variables empty list means no env access | dump 17427 | F04938 | non-negotiable | false | 10 |
| R09864 | Field 4 — environment variables redacted from logs by default | architecture | F04939 | non-negotiable | false | 10 |
| R09865 | Field 4 — environment variables values never cited in trace spans | cross-ref M049 | F04940 | non-negotiable | false | 10 |
| R09866 | Field 5 — secret access declared as list of secret-key references | dump 17428 | F04941 | non-negotiable | false | 10 |
| R09867 | Field 5 — secret access enforced via Linux kernel keyring | architecture | F04942 | non-negotiable | false | 10 |
| R09868 | Field 5 — secret access empty list means no secret access | dump 17428 | F04943 | non-negotiable | false | 10 |
| R09869 | Field 5 — secret access emits OCSF Audit Activity class 1003 on every read | cross-ref MS026 | F04944 | non-negotiable | false | 10 |
| R09870 | Field 5 — secret access values never cited in trace spans | cross-ref M049 | F04945 | non-negotiable | false | 10 |
| R09871 | Field 6 — expected side effects declared as typed list of effects | dump 17429 | F04946 | non-negotiable | false | 10 |
| R09872 | Field 6 — expected side effects enum (file-write/process-spawn/socket-open/signal-send/ioctl/mmap/syscall-N) | architecture | F04947 | non-negotiable | false | 10 |
| R09873 | Field 6 — expected side effects empty list means pure function | dump 17429 | F04948 | non-negotiable | false | 10 |
| R09874 | Field 6 — expected side effects cite MS041 commit-type when durable | cross-ref MS041 | F04949 | non-negotiable | false | 10 |
| R09875 | Field 6 — expected side effects rollback-availability declared | cross-ref MS041 | F04950 | non-negotiable | false | 10 |
| R09876 | Field 7 — rollback declared as rollback artifact reference | dump 17430 | F04951 | non-negotiable | false | 10 |
| R09877 | Field 7 — rollback values: {available/available-with-loss/unavailable/irreversible} | cross-ref MS041 | F04952 | non-negotiable | false | 10 |
| R09878 | Field 7 — rollback "unavailable" requires high-risk classification | cross-ref MS041 | F04953 | non-negotiable | false | 10 |
| R09879 | Field 7 — rollback artifact signed via MS003 | cross-ref MS003 | F04954 | non-negotiable | false | 10 |
| R09880 | Field 7 — rollback artifact stored under /var/lib/selfdef/tool-rollback/ | architecture | F04955 | non-negotiable | false | 10 |
| R09881 | Declaration signer — produces signed declaration envelope | cross-ref MS003 | F04956 | non-negotiable | false | 10 |
| R09882 | Declaration signer — envelope CBOR-encoded | architecture + cross-ref MS003 | F04957 | non-negotiable | false | 10 |
| R09883 | Declaration signer — envelope includes tool-id field | architecture | F04957 | non-negotiable | false | 10 |
| R09884 | Declaration signer — envelope includes all 7 declaration fields | dump 17424-17430 | F04957 | non-negotiable | false | 10 |
| R09885 | Declaration signer — envelope includes timestamp field | architecture | F04957 | non-negotiable | false | 10 |
| R09886 | Declaration signer — envelope includes actor field | cross-ref MS041 | F04957 | non-negotiable | false | 10 |
| R09887 | Declaration signer — envelope includes signature field | cross-ref MS003 | F04957 | non-negotiable | false | 10 |
| R09888 | Declaration signer — signature uses MS003 selfdef-signing key | cross-ref MS003 | F04958 | non-negotiable | false | 10 |
| R09889 | Declaration signer — envelope stored in /var/lib/selfdef/tool-declarations/ | architecture | F04959 | non-negotiable | false | 10 |
| R09890 | Declaration signer — envelope retention 365 days minimum | cross-ref MS037 | F04960 | non-negotiable | false | 10 |
| R09891 | Declaration validator — checks all 7 fields present | dump 17424-17430 | F04961 | non-negotiable | false | 10 |
| R09892 | Declaration validator — checks all 7 fields well-formed | architecture | F04962 | non-negotiable | false | 10 |
| R09893 | Declaration validator — checks declaration signed | cross-ref MS003 | F04963 | non-negotiable | false | 10 |
| R09894 | Declaration validator — failure rejects tool call | architecture | F04964 | non-negotiable | false | 10 |
| R09895 | Declaration validator — failure emits OCSF Detection Finding class 2004 | cross-ref MS026 | F04965 | non-negotiable | false | 10 |
| R09896 | Observed — fanotify monitors file accesses against declared read-paths | cross-ref MS037 | F04966 | non-negotiable | false | 10 |
| R09897 | Observed — fanotify monitors file modifications against declared write-paths | cross-ref MS037 | F04967 | non-negotiable | false | 10 |
| R09898 | Observed — eBPF monitors connect() against declared network-domains | cross-ref MS024 + MS038 | F04968 | non-negotiable | false | 10 |
| R09899 | Observed — eBPF monitors sendmsg() against declared network-domains | cross-ref MS024 + MS038 | F04969 | non-negotiable | false | 10 |
| R09900 | Observed — ptrace+seccomp monitors getenv() against declared env-vars | architecture | F04970 | non-negotiable | false | 10 |
| R09901 | Observed — kernel keyring monitors keyctl() against declared secret-access | architecture | F04971 | non-negotiable | false | 10 |
| R09902 | Observed — sandbox introspector monitors syscalls against declared side-effects | cross-ref MS036 | F04972 | non-negotiable | false | 10 |
| R09903 | Observed — observability emits M049 13-field span on every observation | cross-ref M049 | F04973 | non-negotiable | false | 10 |
| R09904 | Observed — observations buffered with declared baseline for diffing | architecture | F04974 | non-negotiable | false | 10 |
| R09905 | Observed — observation buffer cleared on tool-call completion | architecture | F04975 | non-negotiable | false | 10 |
| R09906 | Comparator — diffs declared read-paths vs observed file accesses | dump 17434 + cross-ref MS037 | F04976 | non-negotiable | false | 10 |
| R09907 | Comparator — diffs declared write-paths vs observed file modifications | dump 17434 + cross-ref MS037 | F04977 | non-negotiable | false | 10 |
| R09908 | Comparator — diffs declared network-domains vs observed sockets | dump 17434 + cross-ref MS038 | F04978 | non-negotiable | false | 10 |
| R09909 | Comparator — diffs declared env-vars vs observed getenv() calls | dump 17434 + architecture | F04979 | non-negotiable | false | 10 |
| R09910 | Comparator — diffs declared secret-access vs observed keyring queries | dump 17434 + architecture | F04980 | non-negotiable | false | 10 |
| R09911 | Comparator — diffs declared side-effects vs observed syscalls | dump 17434 + cross-ref MS036 | F04981 | non-negotiable | false | 10 |
| R09912 | Comparator — emits per-field mismatch result | dump 17434-17435 | F04982 | non-negotiable | false | 10 |
| R09913 | Comparator — mismatch result CBOR-encoded + MS003-signed | cross-ref MS003 | F04983 | non-negotiable | false | 10 |
| R09914 | Comparator — mismatch result emits M049 span | cross-ref M049 | F04984 | non-negotiable | false | 10 |
| R09915 | Comparator — mismatch result emits OCSF Detection Finding class 2004 | cross-ref MS026 | F04985 | non-negotiable | false | 10 |
| R09916 | Classifier — classifies mismatch severity (low/medium/high/critical) | dump 17437-17445 + architecture | F04986 | non-negotiable | false | 10 |
| R09917 | Classifier — declared read-only + observed opened socket = critical | dump 17437-17442 | F04987 | non-negotiable | false | 10 |
| R09918 | Classifier — declared write-paths violation = high | architecture | F04988 | non-negotiable | false | 10 |
| R09919 | Classifier — declared env-var violation = medium | architecture | F04989 | non-negotiable | false | 10 |
| R09920 | Classifier — declared secret-access violation = critical | architecture | F04990 | non-negotiable | false | 10 |
| R09921 | Classifier — declared network-domain violation = critical | architecture + dump 17437-17442 | F04987 | non-negotiable | false | 10 |
| R09922 | Classifier — declared side-effect violation = high or critical depending on durability | architecture + cross-ref MS041 | F04988 | non-negotiable | false | 10 |
| R09923 | Classifier — classifier output signed via MS003 | cross-ref MS003 | F04983 | non-negotiable | false | 10 |
| R09924 | Classifier — classifier emits M049 metric per severity bucket | cross-ref M049 | F04982 | non-negotiable | false | 10 |
| R09925 | Classifier — classifier extensible per operator-defined severity rules | architecture | F04986 | non-negotiable | false | 10 |
| R09926 | Response — block terminates tool process immediately | dump 17443 | F04991 | non-negotiable | false | 10 |
| R09927 | Response — block via SIGKILL after seccomp trap | architecture + cross-ref MS036 | F04992 | non-negotiable | false | 10 |
| R09928 | Response — block emits OCSF System Activity class 1001 | cross-ref MS026 | F04993 | non-negotiable | false | 10 |
| R09929 | Response — quarantine moves tool artifacts to quarantine dir | dump 17444 | F04994 | non-negotiable | false | 10 |
| R09930 | Response — quarantine path /var/lib/selfdef/quarantine/tools/<tool-id>-<timestamp>/ | architecture | F04995 | non-negotiable | false | 10 |
| R09931 | Response — quarantine artifacts include declaration envelope | architecture | F04996 | non-negotiable | false | 10 |
| R09932 | Response — quarantine artifacts include observed log | architecture | F04996 | non-negotiable | false | 10 |
| R09933 | Response — quarantine artifacts include mismatch result | architecture | F04996 | non-negotiable | false | 10 |
| R09934 | Response — quarantine signed via MS003 | cross-ref MS003 | F04997 | non-negotiable | false | 10 |
| R09935 | Response — quarantine retained 365 days minimum | cross-ref MS037 | F04998 | non-negotiable | false | 10 |
| R09936 | Response — quarantine emits OCSF Audit Activity class 1003 | cross-ref MS026 | F04999 | non-negotiable | false | 10 |
| R09937 | Response — trace = M049 13-field span with mismatch detail | dump 17445 + cross-ref M049 | F05000 | non-negotiable | false | 10 |
| R09938 | Response — trace includes declaration digest | cross-ref MS003 | F05001 | non-negotiable | false | 10 |
| R09939 | Response — trace includes observed-behavior digest | architecture + cross-ref M049 | F05002 | non-negotiable | false | 10 |
| R09940 | Response — trace includes mismatch field list | architecture | F05003 | non-negotiable | false | 10 |
| R09941 | Response — trace cross-referenced from quarantine artifacts | architecture | F05004 | non-negotiable | false | 10 |
| R09942 | Response — full block+quarantine+trace 3-step protocol atomic | dump 17443-17445 | F05005 | non-negotiable | false | 10 |
| R09943 | Response — protocol failure (partial application) auto-reverts via MS041 rollback engine | cross-ref MS041 | F05005 | non-negotiable | false | 10 |
| R09944 | Response — protocol emits M049 trace event on every step | cross-ref M049 | F05005 | non-negotiable | false | 10 |
| R09945 | Response — protocol order: block first, quarantine second, trace third | dump 17443-17445 | F05005 | non-negotiable | false | 10 |
| R09946 | Receipt — every tool call produces receipt | architecture + dump 17434-17445 | F05006 | non-negotiable | false | 10 |
| R09947 | Receipt — receipt includes declaration envelope | architecture | F05006 | non-negotiable | false | 10 |
| R09948 | Receipt — receipt includes observed-behavior log | architecture | F05006 | non-negotiable | false | 10 |
| R09949 | Receipt — receipt includes comparator result | architecture | F05006 | non-negotiable | false | 10 |
| R09950 | Receipt — receipt includes classifier output | architecture | F05006 | non-negotiable | false | 10 |
| R09951 | Receipt — receipt includes response taken | architecture + dump 17443-17445 | F05006 | non-negotiable | false | 10 |
| R09952 | Receipt — receipts CBOR-encoded | architecture | F05007 | non-negotiable | false | 10 |
| R09953 | Receipt — receipts signed via MS003 | cross-ref MS003 | F05007 | non-negotiable | false | 10 |
| R09954 | Receipt — receipts retained 365 days minimum | cross-ref MS037 | F05008 | non-negotiable | false | 10 |
| R09955 | Receipt — receipts indexed by tool-id | architecture | F05009 | non-negotiable | false | 10 |
| R09956 | Receipt — receipts indexed by trace-id | cross-ref M049 | F05009 | non-negotiable | false | 10 |
| R09957 | Receipt — receipts indexed by actor | architecture | F05009 | non-negotiable | false | 10 |
| R09958 | Receipt — receipts indexed by mismatch-severity | architecture | F05009 | non-negotiable | false | 10 |
| R09959 | Receipt — receipts queryable via MS007 typed-mirror interface | cross-ref MS007 | F05010 | non-negotiable | false | 10 |
| R09960 | Replay validator — verifies historical tool-call chain integrity | cross-ref MS009 | F05011 | non-negotiable | false | 10 |
| R09961 | Replay validator — detects missing signatures on receipts | cross-ref MS003 + cross-ref MS009 | F05012 | non-negotiable | false | 10 |
| R09962 | Replay validator — detects malformed signatures on receipts | cross-ref MS003 + cross-ref MS009 | F05012 | non-negotiable | false | 10 |
| R09963 | Replay validator — detects mismatch responses not logged | cross-ref MS009 | F05013 | non-negotiable | false | 10 |
| R09964 | Replay validator — emits OCSF Detection Finding class 2004 on chain break | cross-ref MS026 | F05014 | non-negotiable | false | 10 |
| R09965 | Replay validator — runs daily as cron unit | cross-ref MS009 | F05015 | non-negotiable | false | 10 |
| R09966 | Replay validator — failures halt new tool calls until resolved | architecture | F05016 | non-negotiable | false | 10 |
| R09967 | Typed-mirror — published under MS007 8/8 SATURATED scheme | cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R09968 | Typed-mirror — ToolDeclaration struct has 7 fields matching dump | cross-ref MS007 + dump 17424-17430 | F05018 | non-negotiable | false | 10 |
| R09969 | Typed-mirror — ObservedBehavior struct has 6 observation channels | cross-ref MS007 + dump 17434-17435 | F05019 | non-negotiable | false | 10 |
| R09970 | Typed-mirror — MismatchResult struct includes per-field diff + severity + response | cross-ref MS007 + dump 17437-17445 | F05020 | non-negotiable | false | 10 |
| R09971 | Typed-mirror — ResponseAction enum combines Block/Quarantine/Trace | cross-ref MS007 + dump 17443-17445 | F05021 | non-negotiable | false | 10 |
| R09972 | Typed-mirror — Rust crate name selfdef-tool-mirror | cross-ref MS007 | F05022 | non-negotiable | false | 10 |
| R09973 | Typed-mirror — re-exported via sovereign-os cargo workspace | cross-ref MS007 | F05022 | non-negotiable | false | 10 |
| R09974 | Typed-mirror — no_std friendly | architecture | F05022 | non-negotiable | false | 10 |
| R09975 | Typed-mirror — serde + bincode derives present | architecture | F05022 | non-negotiable | false | 10 |
| R09976 | Typed-mirror — schema_version "1.0.0" | cross-ref MS007 | F05022 | non-negotiable | false | 10 |
| R09977 | Event emitter — every tool-call invocation emits M049 trace | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R09978 | Event emitter — every mismatch emits OCSF Detection Finding class 2004 | cross-ref MS026 | F05024 | non-negotiable | false | 10 |
| R09979 | Event emitter — every quarantine emits OCSF Audit Activity class 1003 | cross-ref MS026 | F05025 | non-negotiable | false | 10 |
| R09980 | Event emitter — every block emits OCSF System Activity class 1001 | cross-ref MS026 | F05026 | non-negotiable | false | 10 |
| R09981 | Quarantine archive — supports operator review via dashboard surface | cross-ref MS007 | F05027 | non-negotiable | false | 10 |
| R09982 | Quarantine archive — supports operator restore on false-positive | cross-ref MS003 + cross-ref MS007 | F05028 | non-negotiable | false | 10 |
| R09983 | Quarantine archive — supports forensic export | architecture | F05029 | non-negotiable | false | 10 |
| R09984 | Trust score — accumulates tool trust based on declaration-fidelity over time | architecture | F05030 | non-negotiable | false | 10 |
| R09985 | Trust score — persisted under /var/lib/selfdef/tool-trust/ | architecture | F05031 | non-negotiable | false | 10 |
| R09986 | Trust score — factored into MS040 profile evaluation | cross-ref MS040 | F05032 | non-negotiable | false | 10 |
| R09987 | Trust score — decays on mismatch history | architecture | F05033 | non-negotiable | false | 10 |
| R09988 | Trust score — exposed via MS007 typed mirror | cross-ref MS007 | F05034 | non-negotiable | false | 10 |
| R09989 | Authority FSM bridge — tool calls enter at L0 Observe by default | cross-ref MS039 | F05035 | non-negotiable | false | 10 |
| R09990 | Authority FSM bridge — tool calls promoted to L4 Execute only after declaration validation | cross-ref MS039 | F05036 | non-negotiable | false | 10 |
| R09991 | Authority FSM bridge — mismatch demotes tool to L0 + emits OCSF Detection class 2004 | cross-ref MS039 + MS026 | F05037 | non-negotiable | false | 10 |
| R09992 | Authority FSM bridge — mismatch promotes mismatch-record to L5 Commit (signed audit) | cross-ref MS039 + MS041 | F05038 | non-negotiable | false | 10 |
| R09993 | Authority FSM bridge — tool-call observability span carries authority-level field | cross-ref MS039 + M049 | F05039 | non-negotiable | false | 10 |
| R09994 | Operational — daemon refuses to start with chain-break in tool audit log | cross-ref MS009 | F05016 | non-negotiable | false | 10 |
| R09995 | Operational — daemon graceful drain on tool-queue shutdown | architecture | F04965 | non-negotiable | false | 10 |
| R09996 | Operational — daemon emits readiness probe at /run/selfdef/tool-ready | architecture | F04961 | non-negotiable | false | 10 |
| R09997 | Operational — daemon emits tool queue depth via M049 metric | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R09998 | Operational — daemon emits tool-call latency histograms via M049 metrics | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R09999 | Operational — daemon emits per-tool trust-score via M049 metric | cross-ref M049 | F05030 | non-negotiable | false | 10 |
| R10000 | KEYSTONE — selfdef catalog reaches R10000 with verbatim source citation discipline | operator standing direction + architecture | F05040 | non-negotiable | false | 10 |
| R10001 | Boundary — IPS handles tool-authority enforcement for tool declarations + observations | architecture + operator standing direction | F04921 | non-negotiable | false | 10 |
| R10002 | Boundary — sovereign-os M054 Tool typed interface owns tool execution semantics | cross-ref M054 + operator standing direction | F05017 | non-negotiable | false | 10 |
| R10003 | Boundary — sovereign-os M058 hardware-aware scheduler owns tool routing | cross-ref M058 + operator standing direction | F05017 | non-negotiable | false | 10 |
| R10004 | Boundary — info-hub knowledge layer treats tool receipts as read-only context | operator standing direction | F05006 | non-negotiable | false | 10 |
| R10005 | Boundary — cross-repo tool semantics live in sovereign-os M056 + M054 | cross-ref M056 + M054 | F05017 | non-negotiable | false | 10 |
| R10006 | Composition — tool declaration composable with MS035 capability token | cross-ref MS035 | F04957 | non-negotiable | false | 10 |
| R10007 | Composition — tool declaration composable with MS036 sandbox tier attestation | cross-ref MS036 | F04957 | non-negotiable | false | 10 |
| R10008 | Composition — tool declaration composable with MS037 filesystem grant | cross-ref MS037 | F04957 | non-negotiable | false | 10 |
| R10009 | Composition — tool declaration composable with MS038 network grant | cross-ref MS038 | F04957 | non-negotiable | false | 10 |
| R10010 | Composition — tool declaration composable with MS040 profile envelope | cross-ref MS040 | F04957 | non-negotiable | false | 10 |
| R10011 | Composition — tool declaration composable with MS041 commit envelope (side-effect rollups) | cross-ref MS041 | F04957 | non-negotiable | false | 10 |
| R10012 | Composition — tool declaration composable with MS039 authority FSM | cross-ref MS039 | F04957 | non-negotiable | false | 10 |
| R10013 | Composition — tool declaration composable with MS033 policy bus decision | cross-ref MS033 | F04957 | non-negotiable | false | 10 |
| R10014 | Composition — tool declaration composable with MS003 chain-of-trust | cross-ref MS003 | F04957 | non-negotiable | false | 10 |
| R10015 | Composition — tool declaration composable with MS009 audit cycle digest | cross-ref MS009 | F04957 | non-negotiable | false | 10 |
| R10016 | Doctrinal preservation — dump 17422 "Tool calls should declare" verbatim in tool-mirror crate doc | dump 17422 + cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R10017 | Doctrinal preservation — dump 17424-17432 7-field list verbatim in tool-mirror crate doc | dump 17424-17432 + cross-ref MS007 | F05018 | non-negotiable | false | 10 |
| R10018 | Doctrinal preservation — dump 17434-17435 mismatch-flag rule verbatim in tool-mirror crate doc | dump 17434-17435 + cross-ref MS007 | F05020 | non-negotiable | false | 10 |
| R10019 | Doctrinal preservation — dump 17437-17445 example block+quarantine+trace verbatim in tool-mirror crate doc | dump 17437-17445 + cross-ref MS007 | F05021 | non-negotiable | false | 10 |
| R10020 | Doctrinal preservation — tool-mirror crate documentation tests assert verbatim quotes | architecture + cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R10021 | Doctrinal preservation — tool-mirror crate version published under selfdef-signing | cross-ref MS003 + cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R10022 | Doctrinal preservation — info-hub knowledge graph indexes verbatim quotes | operator standing direction | F05017 | non-negotiable | false | 10 |
| R10023 | Doctrinal preservation — verbatim quotes never paraphrased in any selfdef artifact | operator standing direction | F05017 | non-negotiable | false | 10 |
| R10024 | Doctrinal preservation — verbatim quotes layered (additive) when new dumps redefine | operator standing direction | F05017 | non-negotiable | false | 10 |
| R10025 | Schema — tool declaration schema_version "1.0.0" | cross-ref MS007 | F04957 | non-negotiable | false | 10 |
| R10026 | Schema — tool declaration schema fields ordered deterministically | architecture | F04957 | non-negotiable | false | 10 |
| R10027 | Schema — tool declaration schema published in MS007 typed-mirror crate | cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R10028 | Schema — tool declaration schema breaking changes require schema_version bump | architecture | F04957 | non-negotiable | false | 10 |
| R10029 | Schema — tool declaration schema validated at signer | architecture + cross-ref MS003 | F04956 | non-negotiable | false | 10 |
| R10030 | Compliance — no invented declaration fields beyond 7 enumerated in dump | dump 17424-17430 + operator standing direction | F04921 | non-negotiable | false | 10 |
| R10031 | Compliance — no invented response actions beyond 3 enumerated in dump | dump 17443-17445 + operator standing direction | F04991 | non-negotiable | false | 10 |
| R10032 | Compliance — additional declaration fields permitted only as extensions, never replacements | architecture + operator standing direction | F04957 | non-negotiable | false | 10 |
| R10033 | Compliance — additional response actions permitted only as extensions, never replacements | architecture + operator standing direction | F05005 | non-negotiable | false | 10 |
| R10034 | Compliance — every R-row carries 10 hard non-negotiable sub-requirements | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10035 | Telemetry — tool-calls-per-second emitted via M049 | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R10036 | Telemetry — mismatch-rate per severity emitted via M049 | cross-ref M049 | F05024 | non-negotiable | false | 10 |
| R10037 | Telemetry — quarantine-rate emitted via M049 | cross-ref M049 | F05025 | non-negotiable | false | 10 |
| R10038 | Telemetry — block-rate emitted via M049 | cross-ref M049 | F05026 | non-negotiable | false | 10 |
| R10039 | Telemetry — per-tool trust-score percentiles emitted via M049 | cross-ref M049 | F05030 | non-negotiable | false | 10 |
| R10040 | Telemetry — declaration-validation-latency emitted via M049 | cross-ref M049 | F04961 | non-negotiable | false | 10 |
| R10041 | Telemetry — comparator-latency emitted via M049 | cross-ref M049 | F04982 | non-negotiable | false | 10 |
| R10042 | Telemetry — response-protocol-latency emitted via M049 | cross-ref M049 | F05005 | non-negotiable | false | 10 |
| R10043 | Telemetry — receipts-store-fill-rate emitted via M049 | cross-ref M049 | F05006 | non-negotiable | false | 10 |
| R10044 | Telemetry — observability dashboards surface tool-authority health | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R10045 | Failure recovery — observed-channel monitor crash auto-restarts with fail-closed default | architecture | F04966 | non-negotiable | false | 10 |
| R10046 | Failure recovery — observed-channel monitor crash emits OCSF Detection class 2004 | cross-ref MS026 | F04966 | non-negotiable | false | 10 |
| R10047 | Failure recovery — comparator crash demotes active tool calls to L0 Observe | cross-ref MS039 | F05037 | non-negotiable | false | 10 |
| R10048 | Failure recovery — response-blocker crash quarantines via fanotify default-deny | cross-ref MS037 | F04991 | non-negotiable | false | 10 |
| R10049 | Failure recovery — response-quarantiner crash retries with exponential backoff | architecture | F04994 | non-negotiable | false | 10 |
| R10050 | Failure recovery — response-tracer crash emits to fallback file logger | architecture + cross-ref M049 | F05000 | non-negotiable | false | 10 |
| R10051 | Lifecycle — tool enters "registered" state on declaration validation | architecture | F04961 | non-negotiable | false | 10 |
| R10052 | Lifecycle — tool enters "active" state on first invocation | architecture | F04966 | non-negotiable | false | 10 |
| R10053 | Lifecycle — tool enters "observed" state during invocation | architecture | F04966 | non-negotiable | false | 10 |
| R10054 | Lifecycle — tool enters "compared" state at invocation end | architecture | F04982 | non-negotiable | false | 10 |
| R10055 | Lifecycle — tool enters "completed" state on no-mismatch | architecture | F04982 | non-negotiable | false | 10 |
| R10056 | Lifecycle — tool enters "violating" state on mismatch detected | dump 17434-17445 | F04986 | non-negotiable | false | 10 |
| R10057 | Lifecycle — tool enters "blocked" state on response.block | dump 17443 | F04991 | non-negotiable | false | 10 |
| R10058 | Lifecycle — tool enters "quarantined" state on response.quarantine | dump 17444 | F04994 | non-negotiable | false | 10 |
| R10059 | Lifecycle — tool enters "traced" state on response.trace | dump 17445 | F05000 | non-negotiable | false | 10 |
| R10060 | Lifecycle — every state transition emits M049 trace | cross-ref M049 | F05023 | non-negotiable | false | 10 |
| R10061 | Lifecycle — every state transition signed via MS003 | cross-ref MS003 | F05007 | non-negotiable | false | 10 |
| R10062 | Lifecycle — state retained in tool receipt store 365 days | cross-ref MS037 | F05008 | non-negotiable | false | 10 |
| R10063 | Boundary preservation — tool authority NEVER moves to sovereign-os from selfdef | operator standing direction ("Respect the projects") | F04921 | non-negotiable | false | 10 |
| R10064 | Boundary preservation — tool execution NEVER moves to selfdef from sovereign-os | operator standing direction ("Respect the projects") | F05002 | non-negotiable | false | 10 |
| R10065 | Boundary preservation — info-hub knowledge layer NEVER mutated from runtime+IPS | operator standing direction (knowledge = second-brain READ-ONLY) | F05006 | non-negotiable | false | 10 |
| R10066 | Boundary preservation — cross-repo binding ONLY through MS007 8/8 SATURATED typed mirrors | operator standing direction + cross-ref MS007 | F05017 | non-negotiable | false | 10 |
| R10067 | Closing — 7 declaration fields cover dump 17424-17432 every line | dump 17424-17432 | F04921 | non-negotiable | false | 10 |
| R10068 | Closing — mismatch-flag rule covers dump 17434-17435 every line | dump 17434-17435 | F04982 | non-negotiable | false | 10 |
| R10069 | Closing — block+quarantine+trace example covers dump 17437-17445 every line | dump 17437-17445 | F05005 | non-negotiable | false | 10 |
| R10070 | Closing — tool-authority arc fully cataloged in IPS-side projection | dump 17422-17445 + operator standing direction | F05040 | non-negotiable | false | 10 |
| R10071 | Closing — selfdef catalog reaches 42/42 milestones COMPLETE | architecture + operator standing direction | F05040 | non-negotiable | false | 10 |
| R10072 | Closing — sovereign-os catalog reaches 59/59 milestones COMPLETE (already landed) | architecture + operator standing direction | F05040 | non-negotiable | false | 10 |
| R10073 | Closing — combined ecosystem catalog: 101 milestones, R10080 + R10030 ~= 20,110 requirements with 10 sub-reqs each = 201,100 enforced sub-requirements | architecture + operator standing direction | F05040 | non-negotiable | false | 10 |
| R10074 | Closing — operator standing direction "10000+ requirements" exceeded for both repos individually | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10075 | Closing — backward-sweep review of avx-plus-plus dump pending (operator: "go backward a bit since it redefines") | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10076 | Closing — prior-dump review pending (operator: "there was also other dumps before that we decided to restart") | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10077 | Closing — SDD/TDD implementation phase begins only after both reviews complete | operator standing direction ("FIRST THING IS IDENTIFYING AND WRITING those 10000+ requirements... before starting working on them in order in SDD") | F05040 | non-negotiable | false | 10 |
| R10078 | Closing — direct-to-main commits on selfdef + sovereign-os authorized by operator | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10079 | Closing — perpetual /goal cycles (2h/4h/8h/16h) supported across catalog + implementation phases | operator standing direction | F05040 | non-negotiable | false | 10 |
| R10080 | Closing — sovereignty preserved: "intelligence remains in the user's hands" (peace machine axiom) | dump 18341 + operator standing direction | F05040 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements per operator standing direction. Total enforced sub-reqs = 240 R × 10 = **2,400 sub-requirements** for MS042.

## Cross-references

- **sovereign-os M048** — modules map (memory service / eval service signer keys)
- **sovereign-os M049** — observability + trace pipeline
- **sovereign-os M054** — Tool typed interface (canonical tool execution semantics)
- **sovereign-os M056** — trust boundaries + authority levels
- **sovereign-os M057** — 12-step task lifecycle (tool calls embedded in step 7 Execute)
- **sovereign-os M058** — hardware-aware scheduler (tool routing)
- **sovereign-os M059** — peace machine close (sovereignty preserved)
- **MS003** — selfdef-signing (signs every declaration, observation, comparator output, response artifact)
- **MS007** — typed-mirror crate scheme (selfdef-tool-mirror)
- **MS009** — audit cycles + replay validator
- **MS024** — eBPF network monitoring
- **MS026** — observability + OCSF event emission
- **MS033** — policy bus (declaration composition with policy decisions)
- **MS034-MS038** — Communication / Capability / Sandbox / Filesystem / Network boundaries (the five enforcement layers tool declarations parameterize)
- **MS036** — sandbox tiers (Tier-specific introspection surfaces)
- **MS039** — Authority levels + trust rings (tool FSM bridge)
- **MS040** — Six-profile authority matrix (trust score factored into profile evaluation)
- **MS041** — Commit authority (tool side-effect commit-type)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS042
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
source_dump_lines: 17422-17445
cross_repo_mirror: sovereign-os/M054 + M056
typed_mirror_crate: selfdef-tool-mirror
declaration_fields:
  - read_paths
  - write_paths
  - network_domains
  - environment_variables
  - secret_access
  - expected_side_effects
  - rollback
mismatch_response:
  - block
  - quarantine
  - trace
catalog_status:
  selfdef: 42/42 milestones COMPLETE
  sovereign_os: 59/59 milestones COMPLETE
  combined: 101 milestones COMPLETE
  total_requirements_selfdef: R10080
  total_requirements_sovereign_os: R10030
  total_sub_requirements: 201100
  next_phase: backward-sweep review of avx-plus-plus dump, then prior-dump review, then SDD/TDD implementation
```
