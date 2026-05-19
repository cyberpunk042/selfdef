# MS038 — Network boundary

> Parent: `backlog/milestones/INDEX.md` row MS038 (source ref dump 3594–3621).
> Source: `raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` lines 3594–3621 (Network Boundary doctrinal block).
> All entries below extract verbatim. No invention.

## Epics (E0381–E0390)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0381 | Network Boundary doctrine — "This matters" | dump 3594–3596 |
| E0382 | Network Profile 1 — offline (no network egress at all) | dump 3602 |
| E0383 | Network Profile 2 — allow package registries (npm, PyPI, crates.io, etc.) | dump 3603 |
| E0384 | Network Profile 3 — allow documentation web (read-only docs fetch) | dump 3604 |
| E0385 | Network Profile 4 — allow arbitrary web (general egress) | dump 3605 |
| E0386 | Network Profile 5 — allow authenticated browser profile (logged-in sessions) | dump 3606 |
| E0387 | Doctrine — "Each profile maps to policy bits" | dump 3610 |
| E0388 | ToolIntent network request — `network_scope: docs_only / reason: "fetch API documentation" / ttl: 120s` | dump 3614–3618 |
| E0389 | Doctrine — "The CPU can approve, deny, or ask user" | dump 3620 |
| E0390 | Composite — 5-profile network catalog + ToolIntent schema + CPU-decides-route + MS035 capability_word network-scope bits (16..23) + MS024 bridge-l2 nftables enforcement + sovereign-os M048 Module 3 sandbox profile network-denied/network-allowed/network-docs-only | dump 3594–3620 + cross-ref MS035 + MS024 + M048 |

## Modules (M00967–M00992)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00967 | Network Boundary preamble — "This matters" | dump 3596 | E0381 |
| M00968 | 3090 VM controlled network profiles introduction | dump 3600 | E0381 |
| M00969 | Profile — offline | dump 3602 | E0382 |
| M00970 | Profile — allow package registries | dump 3603 | E0383 |
| M00971 | Profile — allow documentation web | dump 3604 | E0384 |
| M00972 | Profile — allow arbitrary web | dump 3605 | E0385 |
| M00973 | Profile — allow authenticated browser profile | dump 3606 | E0386 |
| M00974 | Doctrine — "Each profile maps to policy bits" | dump 3610 | E0387 |
| M00975 | ToolIntent network request — network_scope field | dump 3614 | E0388 |
| M00976 | ToolIntent network request — reason field ("fetch API documentation" example) | dump 3616 | E0388 |
| M00977 | ToolIntent network request — ttl field (120s example) | dump 3618 | E0388 |
| M00978 | Doctrine — "The CPU can approve, deny, or ask user" | dump 3620 | E0389 |
| M00979 | Cross-module — MS035 capability_word network-scope bits 16..23 encode network profile | cross-ref MS035 + dump 3498 | E0387 |
| M00980 | Cross-module — MS017 agent-guard enforces network boundary at host level | cross-ref MS017 | E0389 |
| M00981 | Cross-module — MS024 bridge-l2 nftables ruleset enforces per-profile egress | cross-ref MS024 + dump 3610 | E0387 |
| M00982 | Cross-module — MS023 polarproxy applies TLS-MITM inspection on docs-only/arbitrary-web profiles | cross-ref MS023 + dump 3604–3605 | E0384 + E0385 |
| M00983 | Cross-module — MS016 Tetragon eBPF observes network-boundary violations | cross-ref MS016 | E0389 |
| M00984 | Cross-module — MS018 VPN-bridge applies per-profile VPN instance | cross-ref MS018 | E0387 |
| M00985 | Cross-module — MS012 perimeter coexistence applies upstream egress filtering | cross-ref MS012 + dump 3605 | E0385 |
| M00986 | Cross-module — MS027 observability emits per-profile network violation metric | cross-ref MS027 | E0389 |
| M00987 | Cross-module — MS022 SSE quota tracks per-network-profile token usage | cross-ref MS022 | E0388 |
| M00988 | Cross-module — MS026 integrity-sentinel baselines network-profile config files | cross-ref MS026 | E0387 |
| M00989 | Cross-repo binding — sovereign-os M048 Module 3 sandbox profile catalog maps 8 profiles to 5 network profiles | cross-ref M048 | E0390 |
| M00990 | Cross-repo binding — sovereign-os M049 Policy Fabric "Can this sandbox access network?" gates network-profile choice | cross-ref M049 | E0389 |
| M00991 | Cross-repo binding — sovereign-os M042 9-axis Choice Architecture sandbox-vs-host + local-or-cloud axes map to network-profile choice | cross-ref M042 | E0387 |
| M00992 | Cross-repo binding — MS007 surface-manifest typed-mirror crate publishes 5-profile + 3-field-ToolIntent schemas | cross-ref MS007 | E0390 |

## Features (F04441–F04560)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F04441 | Section header — "Network Boundary" | dump 3594 | M00967 |
| F04442 | Doctrine — "This matters" | dump 3596 | M00967 |
| F04443 | Premise — "The 3090 VM can have controlled network profiles" | dump 3600 | M00968 |
| F04444 | Network profile — offline | dump 3602 | M00969 |
| F04445 | Network profile — allow package registries | dump 3603 | M00970 |
| F04446 | Network profile — allow documentation web | dump 3604 | M00971 |
| F04447 | Network profile — allow arbitrary web | dump 3605 | M00972 |
| F04448 | Network profile — allow authenticated browser profile | dump 3606 | M00973 |
| F04449 | Doctrine — "Each profile maps to policy bits" | dump 3610 | M00974 |
| F04450 | ToolIntent example — branch requests network access | dump 3612 | M00975 |
| F04451 | ToolIntent — network_scope: docs_only | dump 3614 | M00975 |
| F04452 | ToolIntent — reason: "fetch API documentation" | dump 3616 | M00976 |
| F04453 | ToolIntent — ttl: 120s | dump 3618 | M00977 |
| F04454 | Doctrine — "The CPU can approve, deny, or ask user" | dump 3620 | M00978 |
| F04455 | Offline profile — no network egress at all (deny all) | dump 3602 + architecture | M00969 |
| F04456 | Offline profile — appropriate for autonomous offline workflows | cross-ref M042 Offline-Peace-Mode + dump 3602 | M00969 |
| F04457 | Offline profile — nftables: drop all egress | cross-ref MS024 + dump 3602 | M00969 |
| F04458 | Offline profile — network namespace: detach from default route | cross-ref M045 + dump 3602 | M00969 |
| F04459 | Package-registries profile — allow npm.npmjs.org, pypi.org, crates.io, deb.debian.org, etc. | dump 3603 + architecture | M00970 |
| F04460 | Package-registries profile — nftables: allowlist TLS 443 to registry FQDNs | cross-ref MS024 + dump 3603 | M00970 |
| F04461 | Package-registries profile — DNS limited to known registries | cross-ref MS024 + dump 3603 | M00970 |
| F04462 | Documentation-web profile — read-only HTTPS to documentation hosts | dump 3604 + architecture | M00971 |
| F04463 | Documentation-web profile — polarproxy TLS inspection for content classification | cross-ref MS023 + dump 3604 | M00971 |
| F04464 | Documentation-web profile — nftables: allowlist HTTPS to /docs/ subdomains | cross-ref MS024 + dump 3604 | M00971 |
| F04465 | Arbitrary-web profile — general HTTPS egress (no allowlist) | dump 3605 + architecture | M00972 |
| F04466 | Arbitrary-web profile — polarproxy TLS-MITM inspection mandatory | cross-ref MS023 + dump 3605 | M00972 |
| F04467 | Arbitrary-web profile — eBPF Tetragon TracingPolicy observes outbound connections | cross-ref MS016 + dump 3605 | M00972 |
| F04468 | Authenticated-browser profile — logged-in browser session (OAuth cookies, session tokens) | dump 3606 + architecture | M00973 |
| F04469 | Authenticated-browser profile — secrets MUST stay inside VM (vault sidecar pattern) | cross-ref MS034 + cross-ref M046 vault-proxy + dump 3606 | M00973 |
| F04470 | Authenticated-browser profile — operator approval required for sensitive sites | cross-ref M042 + M049 + dump 3606 | M00973 |
| F04471 | Policy-bits mapping — each profile maps to MS035 capability_word bits 16..23 | dump 3610 + cross-ref MS035 | M00974 |
| F04472 | Policy-bits mapping — offline = 0b00000000 (all denied) | dump 3602 + cross-ref MS035 | M00974 |
| F04473 | Policy-bits mapping — package-registries = 0b00000001 (registries only) | dump 3603 + cross-ref MS035 | M00974 |
| F04474 | Policy-bits mapping — documentation-web = 0b00000011 (registries + docs) | dump 3604 + cross-ref MS035 | M00974 |
| F04475 | Policy-bits mapping — arbitrary-web = 0b00000111 (all HTTP/S allowed) | dump 3605 + cross-ref MS035 | M00974 |
| F04476 | Policy-bits mapping — authenticated-browser = 0b00001111 (full + browser session) | dump 3606 + cross-ref MS035 | M00974 |
| F04477 | ToolIntent schema — network_scope is the requested profile name | dump 3614 + architecture | M00975 |
| F04478 | ToolIntent schema — reason is operator/model-supplied justification | dump 3616 + architecture | M00976 |
| F04479 | ToolIntent schema — ttl is time-bounded grant (e.g. 120s) | dump 3618 + architecture | M00977 |
| F04480 | ToolIntent schema — ttl expiration revokes network access automatically | dump 3618 + architecture | M00977 |
| F04481 | ToolIntent schema — operator MAY extend ttl with explicit approval | dump 3618 + cross-ref M042 | M00977 |
| F04482 | CPU decision — approve: instantly applies network profile via nftables | dump 3620 + cross-ref MS024 | M00978 |
| F04483 | CPU decision — deny: emits OCSF Detection Finding class 2004 + notifier | dump 3620 + cross-ref MS026 + MS004 | M00978 |
| F04484 | CPU decision — ask user: M049 ask outcome + M042 user-approval-state | dump 3620 + cross-ref M042 + M049 | M00978 |
| F04485 | CPU decision — output emitted via M049 16-event taxonomy network_access event | dump 3620 + cross-ref M049 | M00978 |
| F04486 | Selfdef MS017 — `[host-default]` profile defaults network_scope=offline | cross-ref MS017 + dump 3602 | M00980 |
| F04487 | Selfdef MS017 — `[autonomous-agent]` profile allows network_scope=docs_only with approval | cross-ref MS017 + dump 3604 | M00980 |
| F04488 | Selfdef MS024 bridge-l2 nftables ruleset per-profile: input + forward + output chains gate egress | cross-ref MS024 + dump 3610 | M00981 |
| F04489 | Selfdef MS024 bridge-l2 — forward_hook chain allows other modules (polarproxy) to add jumps | cross-ref MS024 | M00981 |
| F04490 | Selfdef MS023 polarproxy — TLS-MITM inspection on docs_only + arbitrary_web + authenticated_browser profiles | cross-ref MS023 + dump 3604–3606 | M00982 |
| F04491 | Selfdef MS023 polarproxy — JA3 fingerprints + SNI extraction for compliance | cross-ref MS023 README | M00982 |
| F04492 | Selfdef MS023 polarproxy — pcap-over-ip feed for downstream IDS | cross-ref MS023 + dump 3605 | M00982 |
| F04493 | Selfdef MS016 — Tetragon TracingPolicy detects unauthorized socket() syscalls | cross-ref MS016 + dump 3605 | M00983 |
| F04494 | Selfdef MS016 — Tetragon emits OCSF Detection Finding on network-boundary violation | cross-ref MS016 + MS026 | M00983 |
| F04495 | Selfdef MS018 — VPN-bridge instances per-profile (separate VPN per network-scope) | cross-ref MS018 + dump 3605 | M00984 |
| F04496 | Selfdef MS018 — VPN-bridge SELFDEF_INSTANCE_ID maps to network profile | cross-ref MS018 + architecture | M00984 |
| F04497 | Selfdef MS012 — perimeter coexistence respects per-profile FQDN allowlist | cross-ref MS012 + dump 3603 | M00985 |
| F04498 | Selfdef MS027 — metric `selfdef_network_violations_total{profile, destination}` histogram | cross-ref MS027 + dump 3620 | M00986 |
| F04499 | Selfdef MS027 — metric `selfdef_network_egress_bytes{profile, fqdn}` counter | cross-ref MS027 + dump 3620 | M00986 |
| F04500 | Selfdef MS022 — SubscriberGuard per-profile network token bucket | cross-ref MS022 + dump 3603 | M00987 |
| F04501 | Selfdef MS026 — integrity-sentinel baselines /etc/nftables.d/* + /etc/selfdef/policy/* network profile files | cross-ref MS026 + cross-ref MS024 | M00988 |
| F04502 | Sovereign-os M048 — Module 3 sandbox profile network-denied = offline | cross-ref M048 + dump 3602 | M00989 |
| F04503 | Sovereign-os M048 — Module 3 sandbox profile network-docs-only = docs_only | cross-ref M048 + dump 3604 | M00989 |
| F04504 | Sovereign-os M048 — Module 3 sandbox profile network-allowed = arbitrary_web | cross-ref M048 + dump 3605 | M00989 |
| F04505 | Sovereign-os M049 — Policy Fabric "Can this sandbox access network?" gates network-profile choice | cross-ref M049 + dump 3620 | M00990 |
| F04506 | Sovereign-os M049 — 7 PolicyDecision values (allow/deny/ask/sandbox/escalate/snapshot/test) map to CPU approve/deny/ask | cross-ref M049 + dump 3620 | M00990 |
| F04507 | Sovereign-os M042 — 9-axis Choice Architecture "local or cloud" + "sandbox or host" map to network profile choice | cross-ref M042 + dump 3610 | M00991 |
| F04508 | Sovereign-os M042 — Offline Peace Mode → network_scope=offline | cross-ref M042 + dump 3602 | M00991 |
| F04509 | Sovereign-os M042 — Research Mode → network_scope=docs_only or arbitrary_web | cross-ref M042 + dump 3604 + 3605 | M00991 |
| F04510 | Sovereign-os M042 — Fast Local Mode → network_scope=offline or package-registries | cross-ref M042 + dump 3602 + 3603 | M00991 |
| F04511 | Sovereign-os M042 — Autonomous Code Mode → network_scope=package-registries (build dependencies only) | cross-ref M042 + dump 3603 | M00991 |
| F04512 | Sovereign-os M042 — High-Risk Mode → network_scope=offline (no egress) | cross-ref M042 + dump 3602 | M00991 |
| F04513 | Sovereign-os M044 — Sovereign-OS substrate network plane (10GbE + 2.5GbE NICs) carries per-profile traffic | cross-ref M044 + dump 3596 | E0381 |
| F04514 | Sovereign-os M046 — LoRA foundry adapter download from HuggingFace = network_scope=package_registries | cross-ref M046 + dump 3603 | M00970 |
| F04515 | Sovereign-os M032 — Cloud Expert Plane invocation = network_scope=arbitrary_web with explicit operator approval | cross-ref M032 + M042 user-approval + dump 3605 | M00972 |
| F04516 | Sovereign-os M034 — Anthropic-first Gateway → outbound HTTPS only with capability_word.cloud_allowed=true | cross-ref M034 + cross-ref MS035 + dump 3606 | M00973 |
| F04517 | Sovereign-os M040 — Hyper Feature 6 10GbE + 2.5GbE data-plane-vs-management-plane split aligns with network-boundary scope | cross-ref M040 + dump 3596 | E0381 |
| F04518 | Sovereign-os M043 — Bridge Layer AVX-512 Routing Brain bulk-eval use_cloud decision maps to network_scope choice | cross-ref M043 + dump 3620 | M00978 |
| F04519 | Sovereign-os M045 — Linux as intelligence governor (netfilter + eBPF + namespaces) IS the network-boundary substrate | cross-ref M045 + dump 3610 | M00974 |
| F04520 | Sovereign-os M050 — Design Law "CPU enforces" implements CPU approve/deny/ask via AVX-512 hot path | cross-ref M050 + M051 + dump 3620 | M00978 |
| F04521 | Sovereign-os M054 — Tool Interface ToolIntent message-type carries network_scope + reason + ttl fields | cross-ref M054 + dump 3614–3618 | M00975 |
| F04522 | Sovereign-os M055 — Failure mode Sandbox Failure "network leakage" detection via eBPF observation | cross-ref M055 | M00983 |
| F04523 | Sovereign-os M056 — Trust boundaries Ring 4 Cloud/External maps to network_scope=arbitrary_web | cross-ref M056 + dump 3605 | M00972 |
| F04524 | Sovereign-os M056 — Cloud Trust scope (5 allowed + 6 restricted) gates network egress | cross-ref M056 + dump 3605 | M00978 |
| F04525 | Cross-cycle MS034 → MS038 — Communication Boundary 8-message-types carry network_scope hint in ToolPlan messages | cross-ref MS034 + dump 3471 | M00975 |
| F04526 | Cross-cycle MS035 → MS038 — capability_word bits 16..23 (network scope) encode 5 profile values | cross-ref MS035 + dump 3498 + 3610 | F04471 |
| F04527 | Cross-cycle MS036 → MS038 — Tier A/B/C/D maps to network-profile defaults (Tier A=offline / Tier B=package-registries / Tier C=docs+arbitrary / Tier D=authenticated-browser) | cross-ref MS036 + dump 3602–3606 | M00969 + M00970 + M00971 + M00973 |
| F04527 | Cross-cycle MS037 → MS038 — filesystem boundary 3-dir layout pairs with network-boundary 5-profile layout (parallel patterns) | cross-ref MS037 | F04449 |
| F04528 | Cross-cycle MS038 → MS039 — 7 authority levels + 5 trust rings (next INDEX) extend network-boundary with authority-graded egress | cross-ref MS039 (INDEX) | E0390 |
| F04529 | Cross-cycle MS038 → MS040 — Authority and profiles thread per-profile network scope | cross-ref MS040 (INDEX) | M00991 |
| F04530 | Cross-cycle MS038 → MS041 — Commit authority "only the runtime commits" applies to network-grant lifecycle | cross-ref MS041 (INDEX) + dump 3618 | M00977 |
| F04531 | Cross-cycle MS038 → MS042 — Tool authority "typed authority on every tool intent" REQUIRES network_scope in ToolIntent | cross-ref MS042 (INDEX) + dump 3614 | M00975 |
| F04532 | Operator UX — `selfdefctl network status` shows current profile per VM/branch | architecture + cross-ref MS011 | M00978 |
| F04533 | Operator UX — `selfdefctl network request <scope> <reason> [ttl]` requests network grant | architecture + cross-ref M042 user-approval | M00975 |
| F04534 | Operator UX — `selfdefctl network grants` lists active grants with countdown | architecture + cross-ref MS027 | M00977 |
| F04535 | Operator UX — `selfdefctl network violations` lists recent boundary violations | architecture + cross-ref MS027 | F04483 |
| F04536 | Operator UX — `selfdefctl network deny <scope>` revokes active grant | architecture + cross-ref M049 | M00978 |
| F04537 | Operator UX — MS011 dashboard renders network-boundary widget with active grants + per-profile traffic histogram | cross-ref MS011 + cross-ref MS027 | F04532 |
| F04538 | Hardware reality — ProArt X870E-Creator dual NIC (10GbE + 2.5GbE) supports per-profile NIC binding | cross-ref M040 Hyper Feature 6 + dump 3596 | F04513 |
| F04539 | Hardware reality — virtio-net-pci device per VM supports per-VM network profile | cross-ref MS034 + dump 3458 | M00968 |
| F04540 | Hardware reality — Linux network namespace per profile enables strict isolation | cross-ref M045 + dump 3526 | F04458 |
| F04541 | Hardware reality — nftables jump-table per-profile chain enables stateful filtering | cross-ref MS024 + dump 3610 | F04488 |
| F04542 | Test integration — MS020 L1 covers 5-profile schema rendering | cross-ref MS020 + dump 3602–3606 | E0387 |
| F04543 | Test integration — MS020 L2 covers ToolIntent → network-grant pipeline | cross-ref MS020 + dump 3614–3620 | M00975 |
| F04544 | Test integration — MS020 L3 covers `selfdefctl network` CLI subcommands | cross-ref MS020 + F04532–F04536 | F04532 |
| F04545 | Test integration — MS020 L4 covers seam between ToolIntent + nftables ruleset | cross-ref MS020 + MS024 | F04488 |
| F04546 | Test integration — MS020 L5 covers end-to-end network-grant lifecycle (request → ask → approve → apply → ttl-expire → revoke) | cross-ref MS020 + dump 3618 + 3620 | M00977 |
| F04547 | Schema versioning — network-boundary schema_version "1.0.0" | architecture + cross-ref MS028/MS030/MS031 | E0390 |
| F04548 | Schema versioning — 5-profile names STABLE across MAJOR versions | architecture + dump 3602–3606 | M00969–M00973 |
| F04549 | Schema versioning — capability_word bits 16..23 STABLE across MAJOR versions | cross-ref MS035 + dump 3498 | M00979 |
| F04550 | Doctrine — network access is EPHEMERAL (ttl-bounded) | dump 3618 + architecture | M00977 |
| F04551 | Doctrine — network access is AUDITABLE (every request logged via M049 16-event taxonomy) | cross-ref M049 + dump 3620 | F04485 |
| F04552 | Doctrine — network access is REVERSIBLE (operator can revoke any active grant) | cross-ref M042 + F04536 | F04536 |
| F04553 | Doctrine — network access is OBSERVABLE (MS027 dashboard renders per-profile traffic) | cross-ref MS027 + F04498 | F04498 |
| F04554 | Doctrine — network access is TYPED (5-profile catalog, not free-form) | dump 3602–3606 | M00969–M00973 |
| F04555 | Doctrine — network access is JUSTIFIED (reason field required) | dump 3616 + architecture | M00976 |
| F04556 | Doctrine — network access is BOUNDED (ttl required, scope required) | dump 3614 + 3618 | M00975 + M00977 |
| F04557 | Doctrine — network boundary is the SAME PATTERN as MS035 capability tokens (typed-authority-handle for network) | dump 3508 + 3614 | M00974 |
| F04558 | Doctrine — network boundary is the SAME PATTERN as MS037 filesystem boundary (explicit exchange + bounded ops) | cross-ref MS037 + dump 3552 | M00974 |
| F04559 | Operator references — Linux netfilter / nftables docs | cross-ref MS024 + dump 3610 | F04488 |
| F04560 | Composite — 5-profile network catalog + ToolIntent network_scope+reason+ttl + CPU approve/deny/ask + cross-module enforcement (MS012/MS016/MS017/MS018/MS022/MS023/MS024/MS026/MS027/MS034/MS035) + cross-repo binding to sovereign-os M032/M034/M040/M042/M043/M044/M045/M046/M048/M049/M050/M054/M055/M056 via MS007 surface-manifest typed-mirror crate | dump 3594–3620 + architecture | E0390 |

## Requirements (R08881–R09120)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R08881 | Section header — "Network Boundary" | dump 3594 | F04441 | non-negotiable | false | 10 |
| R08882 | Doctrine — "This matters" | dump 3596 | F04442 | non-negotiable | false | 10 |
| R08883 | "The 3090 VM can have controlled network profiles" | dump 3600 | F04443 | non-negotiable | false | 10 |
| R08884 | Network profile — offline | dump 3602 | F04444 | non-negotiable | false | 10 |
| R08885 | Network profile — allow package registries | dump 3603 | F04445 | non-negotiable | false | 10 |
| R08886 | Network profile — allow documentation web | dump 3604 | F04446 | non-negotiable | false | 10 |
| R08887 | Network profile — allow arbitrary web | dump 3605 | F04447 | non-negotiable | false | 10 |
| R08888 | Network profile — allow authenticated browser profile | dump 3606 | F04448 | non-negotiable | false | 10 |
| R08889 | "Each profile maps to policy bits" | dump 3610 | F04449 | non-negotiable | false | 10 |
| R08890 | ToolIntent example — branch requests network access | dump 3612 | F04450 | non-negotiable | false | 10 |
| R08891 | ToolIntent — network_scope: docs_only | dump 3614 | F04451 | non-negotiable | false | 10 |
| R08892 | ToolIntent — reason: "fetch API documentation" | dump 3616 | F04452 | non-negotiable | false | 10 |
| R08893 | ToolIntent — ttl: 120s | dump 3618 | F04453 | non-negotiable | false | 10 |
| R08894 | "The CPU can approve, deny, or ask user" | dump 3620 | F04454 | non-negotiable | false | 10 |
| R08895 | Offline — no egress at all (deny all) | dump 3602 + architecture | F04455 | non-negotiable | false | 10 |
| R08896 | Offline — appropriate for autonomous offline workflows | cross-ref M042 + dump 3602 | F04456 | non-negotiable | false | 10 |
| R08897 | Offline — nftables drop all egress | cross-ref MS024 | F04457 | non-negotiable | false | 10 |
| R08898 | Offline — network namespace detach from default route | cross-ref M045 | F04458 | non-negotiable | false | 10 |
| R08899 | Package-registries — allow npm.npmjs.org, pypi.org, crates.io, deb.debian.org | dump 3603 | F04459 | non-negotiable | false | 10 |
| R08900 | Package-registries — nftables allowlist TLS 443 to registry FQDNs | cross-ref MS024 | F04460 | non-negotiable | false | 10 |
| R08901 | Package-registries — DNS limited to known registries | cross-ref MS024 | F04461 | non-negotiable | false | 10 |
| R08902 | Documentation-web — read-only HTTPS to documentation hosts | dump 3604 | F04462 | non-negotiable | false | 10 |
| R08903 | Documentation-web — polarproxy TLS inspection for content classification | cross-ref MS023 + dump 3604 | F04463 | non-negotiable | false | 10 |
| R08904 | Documentation-web — nftables allowlist HTTPS to /docs/ subdomains | cross-ref MS024 + dump 3604 | F04464 | non-negotiable | false | 10 |
| R08905 | Arbitrary-web — general HTTPS egress (no allowlist) | dump 3605 | F04465 | non-negotiable | false | 10 |
| R08906 | Arbitrary-web — polarproxy TLS-MITM inspection mandatory | cross-ref MS023 + dump 3605 | F04466 | non-negotiable | false | 10 |
| R08907 | Arbitrary-web — eBPF Tetragon observes outbound connections | cross-ref MS016 + dump 3605 | F04467 | non-negotiable | false | 10 |
| R08908 | Authenticated-browser — logged-in browser session (OAuth cookies, session tokens) | dump 3606 | F04468 | non-negotiable | false | 10 |
| R08909 | Authenticated-browser — secrets MUST stay inside VM (vault sidecar pattern) | cross-ref MS034 + M046 + dump 3606 | F04469 | non-negotiable | false | 10 |
| R08910 | Authenticated-browser — operator approval required for sensitive sites | cross-ref M042 + M049 | F04470 | non-negotiable | false | 10 |
| R08911 | Policy bits — each profile maps to MS035 capability_word bits 16..23 | dump 3610 + cross-ref MS035 | F04471 | non-negotiable | false | 10 |
| R08912 | Policy bits — offline = 0b00000000 | dump 3602 + cross-ref MS035 | F04472 | non-negotiable | false | 10 |
| R08913 | Policy bits — package-registries = 0b00000001 | dump 3603 + cross-ref MS035 | F04473 | non-negotiable | false | 10 |
| R08914 | Policy bits — documentation-web = 0b00000011 | dump 3604 + cross-ref MS035 | F04474 | non-negotiable | false | 10 |
| R08915 | Policy bits — arbitrary-web = 0b00000111 | dump 3605 + cross-ref MS035 | F04475 | non-negotiable | false | 10 |
| R08916 | Policy bits — authenticated-browser = 0b00001111 | dump 3606 + cross-ref MS035 | F04476 | non-negotiable | false | 10 |
| R08917 | ToolIntent — network_scope is requested profile name | dump 3614 | F04477 | non-negotiable | false | 10 |
| R08918 | ToolIntent — reason is operator/model-supplied justification | dump 3616 | F04478 | non-negotiable | false | 10 |
| R08919 | ToolIntent — ttl is time-bounded grant | dump 3618 | F04479 | non-negotiable | false | 10 |
| R08920 | ToolIntent — ttl expiration revokes network access automatically | dump 3618 | F04480 | non-negotiable | false | 10 |
| R08921 | ToolIntent — operator MAY extend ttl with explicit approval | dump 3618 + cross-ref M042 | F04481 | non-negotiable | false | 10 |
| R08922 | CPU decision — approve: instantly applies network profile via nftables | dump 3620 + cross-ref MS024 | F04482 | non-negotiable | false | 10 |
| R08923 | CPU decision — deny: emits OCSF Detection Finding class 2004 + notifier | dump 3620 + cross-ref MS026 + MS004 | F04483 | non-negotiable | false | 10 |
| R08924 | CPU decision — ask user: M049 ask outcome + M042 user-approval-state | dump 3620 + cross-ref M042 + M049 | F04484 | non-negotiable | false | 10 |
| R08925 | CPU decision — output emitted via M049 16-event taxonomy network_access event | dump 3620 + cross-ref M049 | F04485 | non-negotiable | false | 10 |
| R08926 | Selfdef MS017 — host-default profile defaults network_scope=offline | cross-ref MS017 + dump 3602 | F04486 | non-negotiable | false | 10 |
| R08927 | Selfdef MS017 — autonomous-agent profile allows docs_only with approval | cross-ref MS017 + dump 3604 | F04487 | non-negotiable | false | 10 |
| R08928 | Selfdef MS024 — nftables per-profile chain (input + forward + output) | cross-ref MS024 + dump 3610 | F04488 | non-negotiable | false | 10 |
| R08929 | Selfdef MS024 — forward_hook chain allows polarproxy to add jumps | cross-ref MS024 | F04489 | non-negotiable | false | 10 |
| R08930 | Selfdef MS023 — TLS-MITM inspection on docs_only + arbitrary_web + authenticated_browser | cross-ref MS023 + dump 3604–3606 | F04490 | non-negotiable | false | 10 |
| R08931 | Selfdef MS023 — JA3 + SNI extraction for compliance | cross-ref MS023 | F04491 | non-negotiable | false | 10 |
| R08932 | Selfdef MS023 — pcap-over-ip feed for downstream IDS | cross-ref MS023 + dump 3605 | F04492 | non-negotiable | false | 10 |
| R08933 | Selfdef MS016 — Tetragon TracingPolicy detects unauthorized socket() syscalls | cross-ref MS016 + dump 3605 | F04493 | non-negotiable | false | 10 |
| R08934 | Selfdef MS016 — Tetragon emits OCSF Detection Finding on network-boundary violation | cross-ref MS016 + MS026 | F04494 | non-negotiable | false | 10 |
| R08935 | Selfdef MS018 — VPN-bridge instances per-profile (separate VPN per network-scope) | cross-ref MS018 | F04495 | non-negotiable | false | 10 |
| R08936 | Selfdef MS018 — SELFDEF_INSTANCE_ID maps to network profile | cross-ref MS018 | F04496 | non-negotiable | false | 10 |
| R08937 | Selfdef MS012 — perimeter coexistence respects per-profile FQDN allowlist | cross-ref MS012 + dump 3603 | F04497 | non-negotiable | false | 10 |
| R08938 | Selfdef MS027 — metric selfdef_network_violations_total{profile, destination} | cross-ref MS027 + dump 3620 | F04498 | non-negotiable | false | 10 |
| R08939 | Selfdef MS027 — metric selfdef_network_egress_bytes{profile, fqdn} | cross-ref MS027 + dump 3620 | F04499 | non-negotiable | false | 10 |
| R08940 | Selfdef MS022 — SubscriberGuard per-profile network token bucket | cross-ref MS022 + dump 3603 | F04500 | non-negotiable | false | 10 |
| R08941 | Selfdef MS026 — integrity-sentinel baselines /etc/nftables.d/* + /etc/selfdef/policy/* | cross-ref MS026 + MS024 | F04501 | non-negotiable | false | 10 |
| R08942 | Sovereign-os M048 Module 3 sandbox profile network-denied = offline | cross-ref M048 + dump 3602 | F04502 | non-negotiable | false | 10 |
| R08943 | Sovereign-os M048 Module 3 sandbox profile network-docs-only = docs_only | cross-ref M048 + dump 3604 | F04503 | non-negotiable | false | 10 |
| R08944 | Sovereign-os M048 Module 3 sandbox profile network-allowed = arbitrary_web | cross-ref M048 + dump 3605 | F04504 | non-negotiable | false | 10 |
| R08945 | Sovereign-os M049 Policy Fabric "Can this sandbox access network?" gates network-profile choice | cross-ref M049 + dump 3620 | F04505 | non-negotiable | false | 10 |
| R08946 | Sovereign-os M049 — 7 PolicyDecision values map to CPU approve/deny/ask | cross-ref M049 + dump 3620 | F04506 | non-negotiable | false | 10 |
| R08947 | Sovereign-os M042 — "local or cloud" + "sandbox or host" axes map to network-profile choice | cross-ref M042 + dump 3610 | F04507 | non-negotiable | false | 10 |
| R08948 | Sovereign-os M042 — Offline Peace Mode → network_scope=offline | cross-ref M042 + dump 3602 | F04508 | non-negotiable | false | 10 |
| R08949 | Sovereign-os M042 — Research Mode → docs_only or arbitrary_web | cross-ref M042 + dump 3604 + 3605 | F04509 | non-negotiable | false | 10 |
| R08950 | Sovereign-os M042 — Fast Local Mode → offline or package-registries | cross-ref M042 + dump 3602 + 3603 | F04510 | non-negotiable | false | 10 |
| R08951 | Sovereign-os M042 — Autonomous Code Mode → package-registries (build deps only) | cross-ref M042 + dump 3603 | F04511 | non-negotiable | false | 10 |
| R08952 | Sovereign-os M042 — High-Risk Mode → offline (no egress) | cross-ref M042 + dump 3602 | F04512 | non-negotiable | false | 10 |
| R08953 | Sovereign-os M044 — network plane (10GbE + 2.5GbE) carries per-profile traffic | cross-ref M044 + dump 3596 | F04513 | non-negotiable | false | 10 |
| R08954 | Sovereign-os M046 — LoRA foundry adapter download = network_scope=package_registries | cross-ref M046 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R08955 | Sovereign-os M032 — Cloud Expert Plane = arbitrary_web with operator approval | cross-ref M032 + M042 + dump 3605 | F04515 | non-negotiable | false | 10 |
| R08956 | Sovereign-os M034 — Anthropic-first Gateway outbound HTTPS only with capability_word.cloud_allowed=true | cross-ref M034 + MS035 + dump 3606 | F04516 | non-negotiable | false | 10 |
| R08957 | Sovereign-os M040 — Hyper Feature 6 10GbE + 2.5GbE data-vs-management split | cross-ref M040 + dump 3596 | F04517 | non-negotiable | false | 10 |
| R08958 | Sovereign-os M043 — AVX-512 Routing Brain bulk-eval use_cloud decision maps to network_scope | cross-ref M043 + dump 3620 | F04518 | non-negotiable | false | 10 |
| R08959 | Sovereign-os M045 — Linux netfilter + eBPF + namespaces IS the network-boundary substrate | cross-ref M045 + dump 3610 | F04519 | non-negotiable | false | 10 |
| R08960 | Sovereign-os M050 — Design Law "CPU enforces" implements approve/deny/ask via AVX-512 hot path | cross-ref M050 + M051 + dump 3620 | F04520 | non-negotiable | false | 10 |
| R08961 | Sovereign-os M054 — ToolIntent message-type carries network_scope + reason + ttl fields | cross-ref M054 + dump 3614–3618 | F04521 | non-negotiable | false | 10 |
| R08962 | Sovereign-os M055 — Sandbox Failure "network leakage" detection via eBPF observation | cross-ref M055 | F04522 | non-negotiable | false | 10 |
| R08963 | Sovereign-os M056 — Ring 4 Cloud/External maps to network_scope=arbitrary_web | cross-ref M056 + dump 3605 | F04523 | non-negotiable | false | 10 |
| R08964 | Sovereign-os M056 — Cloud Trust scope (5 allowed + 6 restricted) gates network egress | cross-ref M056 + dump 3605 | F04524 | non-negotiable | false | 10 |
| R08965 | Cross-cycle MS034 → MS038 — Communication Boundary 8-message-types carry network_scope hint | cross-ref MS034 + dump 3471 | F04525 | non-negotiable | false | 10 |
| R08966 | Cross-cycle MS035 → MS038 — capability_word bits 16..23 encode 5 profile values | cross-ref MS035 + dump 3498 + 3610 | F04526 | non-negotiable | false | 10 |
| R08967 | Cross-cycle MS036 → MS038 — Tier A=offline / Tier B=package-registries / Tier C=docs+arbitrary / Tier D=authenticated-browser | cross-ref MS036 + dump 3602–3606 | F04527 | non-negotiable | false | 10 |
| R08968 | Cross-cycle MS037 → MS038 — filesystem boundary 3-dir + network boundary 5-profile = parallel patterns | cross-ref MS037 | F04527 | non-negotiable | false | 10 |
| R08969 | Cross-cycle MS038 → MS039 — 7 authority levels + 5 trust rings extend network-boundary with authority-graded egress | cross-ref MS039 | F04528 | non-negotiable | false | 10 |
| R08970 | Cross-cycle MS038 → MS040 — Authority and profiles thread per-profile network scope | cross-ref MS040 | F04529 | non-negotiable | false | 10 |
| R08971 | Cross-cycle MS038 → MS041 — Commit authority applies to network-grant lifecycle | cross-ref MS041 + dump 3618 | F04530 | non-negotiable | false | 10 |
| R08972 | Cross-cycle MS038 → MS042 — Tool authority REQUIRES network_scope in ToolIntent | cross-ref MS042 + dump 3614 | F04531 | non-negotiable | false | 10 |
| R08973 | Operator UX — `selfdefctl network status` | architecture + cross-ref MS011 | F04532 | non-negotiable | false | 10 |
| R08974 | Operator UX — `selfdefctl network request <scope> <reason> [ttl]` | architecture + M042 | F04533 | non-negotiable | false | 10 |
| R08975 | Operator UX — `selfdefctl network grants` | architecture + MS027 | F04534 | non-negotiable | false | 10 |
| R08976 | Operator UX — `selfdefctl network violations` | architecture + MS027 | F04535 | non-negotiable | false | 10 |
| R08977 | Operator UX — `selfdefctl network deny <scope>` | architecture + M049 | F04536 | non-negotiable | false | 10 |
| R08978 | Operator UX — MS011 dashboard renders network-boundary widget | cross-ref MS011 + MS027 | F04537 | non-negotiable | false | 10 |
| R08979 | Hardware — ProArt X870E-Creator dual NIC supports per-profile NIC binding | cross-ref M040 + dump 3596 | F04538 | non-negotiable | false | 10 |
| R08980 | Hardware — virtio-net-pci per VM supports per-VM network profile | cross-ref MS034 + dump 3458 | F04539 | non-negotiable | false | 10 |
| R08981 | Hardware — Linux network namespace per profile enables strict isolation | cross-ref M045 | F04540 | non-negotiable | false | 10 |
| R08982 | Hardware — nftables jump-table per-profile chain enables stateful filtering | cross-ref MS024 + dump 3610 | F04541 | non-negotiable | false | 10 |
| R08983 | Test — MS020 L1 covers 5-profile schema rendering | cross-ref MS020 | F04542 | non-negotiable | false | 10 |
| R08984 | Test — MS020 L2 covers ToolIntent → network-grant pipeline | cross-ref MS020 + dump 3614–3620 | F04543 | non-negotiable | false | 10 |
| R08985 | Test — MS020 L3 covers `selfdefctl network` CLI | cross-ref MS020 | F04544 | non-negotiable | false | 10 |
| R08986 | Test — MS020 L4 covers seam between ToolIntent + nftables ruleset | cross-ref MS020 + MS024 | F04545 | non-negotiable | false | 10 |
| R08987 | Test — MS020 L5 covers end-to-end network-grant lifecycle | cross-ref MS020 + dump 3618 + 3620 | F04546 | non-negotiable | false | 10 |
| R08988 | Schema versioning — network-boundary schema_version "1.0.0" | architecture | F04547 | non-negotiable | false | 10 |
| R08989 | Schema versioning — 5-profile names STABLE across MAJOR versions | architecture + dump 3602–3606 | F04548 | non-negotiable | false | 10 |
| R08990 | Schema versioning — capability_word bits 16..23 STABLE across MAJOR versions | cross-ref MS035 + dump 3498 | F04549 | non-negotiable | false | 10 |
| R08991 | Doctrine — network access is EPHEMERAL (ttl-bounded) | dump 3618 | F04550 | non-negotiable | false | 10 |
| R08992 | Doctrine — network access is AUDITABLE (every request logged via M049) | cross-ref M049 + dump 3620 | F04551 | non-negotiable | false | 10 |
| R08993 | Doctrine — network access is REVERSIBLE (operator can revoke) | cross-ref M042 | F04552 | non-negotiable | false | 10 |
| R08994 | Doctrine — network access is OBSERVABLE (MS027 dashboard) | cross-ref MS027 | F04553 | non-negotiable | false | 10 |
| R08995 | Doctrine — network access is TYPED (5-profile catalog) | dump 3602–3606 | F04554 | non-negotiable | false | 10 |
| R08996 | Doctrine — network access is JUSTIFIED (reason field required) | dump 3616 | F04555 | non-negotiable | false | 10 |
| R08997 | Doctrine — network access is BOUNDED (ttl + scope required) | dump 3614 + 3618 | F04556 | non-negotiable | false | 10 |
| R08998 | Doctrine — network boundary IS the same pattern as MS035 capability tokens | cross-ref MS035 + dump 3508 + 3614 | F04557 | non-negotiable | false | 10 |
| R08999 | Doctrine — network boundary IS the same pattern as MS037 filesystem boundary | cross-ref MS037 + dump 3552 | F04558 | non-negotiable | false | 10 |
| R09000 | Operator references — Linux netfilter / nftables docs | cross-ref MS024 + dump 3610 | F04559 | non-negotiable | false | 10 |
| R09001 | Cross-repo binding — MS007 surface-manifest typed-mirror crate publishes 5-profile + 3-field-ToolIntent + 8-bit-mapping schemas | cross-ref MS007 + dump 3498 | F04547 | non-negotiable | false | 10 |
| R09002 | Operator references — SNI extraction (TLS Server Name Indication RFC 6066) | cross-ref MS023 + dump 3604 | F04491 | non-negotiable | false | 10 |
| R09003 | Operator references — JA3 fingerprint (Salesforce open-source TLS client fingerprint) | cross-ref MS023 + dump 3604 | F04491 | non-negotiable | false | 10 |
| R09004 | Operator references — OWASP Cloud-Native Application Security Top 10 | cross-ref M056 + dump 3605 | F04524 | non-negotiable | false | 10 |
| R09005 | Operator references — Linux network namespace ip-netns(8) | cross-ref M045 + dump 3526 | F04540 | non-negotiable | false | 10 |
| R09006 | Operator references — Podman --network=none + --network=host modes | cross-ref M048 | F04502 + F04504 | non-negotiable | false | 10 |
| R09007 | Operator references — virtio-net-pci device model documentation | cross-ref MS034 + dump 3458 | F04539 | non-negotiable | false | 10 |
| R09008 | Operator references — eBPF LSM hook BPF_PROG_TYPE_CGROUP_SOCK_ADDR for socket() interception | cross-ref MS016 + dump 3605 | F04493 | non-negotiable | false | 10 |
| R09009 | Operator references — sigma rule format for network policy alerts | cross-ref MS025 + dump 3620 | F04483 | non-negotiable | false | 10 |
| R09010 | Operator references — TLS-MITM tooling (PolarProxy, mitmproxy, sslsplit) | cross-ref MS023 + dump 3604 | F04490 | non-negotiable | false | 10 |
| R09011 | Doctrine — network grants MUST be operator-readable + operator-auditable | dump 3618 + cross-ref MS009 | F04551 | non-negotiable | false | 10 |
| R09012 | Doctrine — network grants MUST be revocable on operator command | dump 3618 + cross-ref F04536 | F04552 | non-negotiable | false | 10 |
| R09013 | Doctrine — network grants MUST be replayable via M044 ZFS-backed replay log | cross-ref M044 + dump 3620 | F04551 | non-negotiable | false | 10 |
| R09014 | Doctrine — network grants MUST be signed via MS003 selfdef-signing | cross-ref MS003 + dump 3618 | F04551 | non-negotiable | false | 10 |
| R09015 | Doctrine — network grants MUST emit OCSF events (M049 16-event taxonomy network_access) | cross-ref M049 + dump 3620 | F04485 | non-negotiable | false | 10 |
| R09016 | Doctrine — operator approval for high-risk grants follows M042 user-approval-state lifecycle | cross-ref M042 + dump 3620 | F04484 | non-negotiable | false | 10 |
| R09017 | Doctrine — automatic grants default to LOWEST profile + REQUIRE explicit upgrade | dump 3602 + 3620 | F04445 | non-negotiable | false | 10 |
| R09018 | Doctrine — grants EXPIRE on ttl boundary without explicit renewal | dump 3618 + architecture | F04480 | non-negotiable | false | 10 |
| R09019 | Doctrine — grants can be REVOKED before ttl via operator action | dump 3618 + cross-ref F04536 | F04552 | non-negotiable | false | 10 |
| R09020 | Doctrine — grants can be EXTENDED before ttl via operator action | dump 3618 + cross-ref M042 | F04481 | non-negotiable | false | 10 |
| R09021 | Implementation — Phase 4 (Sandbox Execution) of M053 implements network-boundary | cross-ref M053 + MS032 | E0390 | non-negotiable | false | 10 |
| R09022 | Implementation — Phase 3 (Policy & Trace) of M053 implements CPU approve/deny/ask flow | cross-ref M053 + MS033 | F04482–F04484 | non-negotiable | false | 10 |
| R09023 | Implementation — Phase 7 (AVX-512 Cortex) of M053 optimizes capability_word bit-checks via SIMD | cross-ref M053 + M051 + dump 3610 | F04471 | non-negotiable | false | 10 |
| R09024 | Implementation — Phase 10 (Full Cockpit) of M053 surfaces network-boundary widget | cross-ref M053 + MS011 | F04537 | non-negotiable | false | 10 |
| R09025 | Project boundary — MS038 is selfdef IPS-side network boundary scope | architecture | E0390 | non-negotiable | false | 10 |
| R09026 | Project boundary — sovereign-os M048 Module 3 + M049 Policy Fabric orchestrate at runtime | cross-ref M048 + M049 | E0390 | non-negotiable | false | 10 |
| R09027 | Cross-repo binding — MS007 surface-manifest typed-mirror carries 5-profile + 3-field schema | cross-ref MS007 + dump 3498 | F04547 | non-negotiable | false | 10 |
| R09028 | Selfdef MS001 — daemon-core hosts network-boundary engine | cross-ref MS001 + dump 3610 | M00974 | non-negotiable | false | 10 |
| R09029 | Selfdef MS002 — 14-collector-fabric collects network-boundary trace events | cross-ref MS002 + cross-ref M049 | F04485 | non-negotiable | false | 10 |
| R09030 | Selfdef MS003 — selfdef-signing signs network-grant decisions | cross-ref MS003 + dump 3618 | F04482 | non-negotiable | false | 10 |
| R09031 | Selfdef MS004 — 14 notifier integrations push network-grant approval requests | cross-ref MS004 + dump 3620 | F04484 | non-negotiable | false | 10 |
| R09032 | Selfdef MS005 — notifier engine routes network-boundary events | cross-ref MS005 | F04484 | non-negotiable | false | 10 |
| R09033 | Selfdef MS006 — 14-functional-modules each declare network-profile preference | cross-ref MS006 + dump 3603 | M00969–M00973 | non-negotiable | false | 10 |
| R09034 | Selfdef MS008 — selfdef-on-sain01 deploys full 5-profile network stack | cross-ref MS008 + dump 3596 | E0381 | non-negotiable | false | 10 |
| R09035 | Selfdef MS009 — audit cycles trace network-grant lineage | cross-ref MS009 + dump 3620 | F04534 | non-negotiable | false | 10 |
| R09036 | Selfdef MS010 — hardware-tune-cache exposes nic_count + nic_speeds for profile binding | cross-ref MS010 + cross-ref M040 | F04538 | non-negotiable | false | 10 |
| R09037 | Selfdef MS011 — operator dashboard renders network-boundary widget + grant queue | cross-ref MS011 + dump 3618 | F04537 | non-negotiable | false | 10 |
| R09038 | Selfdef MS012 — perimeter coexistence respects per-profile FQDN allowlist | cross-ref MS012 + dump 3603 | F04497 | non-negotiable | false | 10 |
| R09039 | Selfdef MS013 — 27-SDD charter governs network-boundary finding ledger | cross-ref MS013 + dump 3596 | M00974 | non-negotiable | false | 10 |
| R09040 | Selfdef MS014 — SSH-wrap respects per-profile outbound SSH | cross-ref MS014 + dump 3605 | F04467 | non-negotiable | false | 10 |
| R09041 | Selfdef MS015 — NATS messaging transports network-grant events between selfdef-daemon + VM | cross-ref MS015 + dump 3620 | F04485 | non-negotiable | false | 10 |
| R09042 | Selfdef MS018 — VPN-bridge per-profile instance | cross-ref MS018 + dump 3605 | F04495 | non-negotiable | false | 10 |
| R09043 | Selfdef MS019 — threat model treats network-boundary escape as primary attack surface | cross-ref MS019 + dump 3605 | F04494 | non-negotiable | false | 10 |
| R09044 | Selfdef MS020 — L1-L5 test harness covers full 5-profile network-boundary lifecycle | cross-ref MS020 | F04542–F04546 | non-negotiable | false | 10 |
| R09045 | Selfdef MS021 — shared module-script lib v2 provides `network_apply_profile` helper | cross-ref MS021 + architecture | F04482 | non-negotiable | false | 10 |
| R09046 | Selfdef MS022 — SSE quota per-network-profile token bucket | cross-ref MS022 + dump 3603 | F04500 | non-negotiable | false | 10 |
| R09047 | Selfdef MS028 — bitnet-gpu-inference adapter download = network_scope=package_registries | cross-ref MS028 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R09048 | Selfdef MS029 — slm-cpu-loop adapter download = network_scope=package_registries | cross-ref MS029 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R09049 | Selfdef MS030 — tensor-parallel-inference weight sharding = network_scope=package_registries | cross-ref MS030 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R09050 | Selfdef MS031 — wasm-aot-cache .cwasm fetch = network_scope=package_registries | cross-ref MS031 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R09051 | Selfdef MS032 — sandbox tier 1-9 catalog composes with 5-profile network catalog | cross-ref MS032 + dump 3602–3606 | M00969–M00973 | non-negotiable | false | 10 |
| R09052 | Selfdef MS033 — Phase 3 PolicyDecision object includes network-scope field | cross-ref MS033 + dump 3620 | F04484 | non-negotiable | false | 10 |
| R09053 | Selfdef MS034 — Communication Boundary 8-message-types use network_scope hint | cross-ref MS034 + dump 3471 | F04525 | non-negotiable | false | 10 |
| R09054 | Selfdef MS035 — capability_word network-scope bits 16..23 gate 5-profile choice | cross-ref MS035 + dump 3498 | F04471 | non-negotiable | false | 10 |
| R09055 | Selfdef MS036 — Tier A/B/C/D defaults to offline/package-registries/docs+arbitrary/authenticated-browser | cross-ref MS036 | F04527 | non-negotiable | false | 10 |
| R09056 | Selfdef MS037 — filesystem boundary 3-dir = parallel pattern to 5-profile network boundary | cross-ref MS037 + dump 3552 | F04558 | non-negotiable | false | 10 |
| R09057 | Cross-cycle — MS038 + MS034 + MS035 + MS036 + MS037 form the IPS-side 5-boundary doctrine | cross-ref MS034 + MS035 + MS036 + MS037 | E0390 | non-negotiable | false | 10 |
| R09058 | Cross-cycle — 5-boundary doctrine = capability + tier + communication + filesystem + network | dump 3492 + 3528 + 3550 + 3594 | E0390 | non-negotiable | false | 10 |
| R09059 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M049 Policy Fabric's 7 policy decisions | cross-ref M049 | F04505 | non-negotiable | false | 10 |
| R09060 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M048 Module 3 sandbox profiles | cross-ref M048 | F04502–F04504 | non-negotiable | false | 10 |
| R09061 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M050 Design Law (6 lines) | cross-ref M050 | F04520 | non-negotiable | false | 10 |
| R09062 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M051 Hot Data Layout 9-SoA + 6-mask | cross-ref M051 + dump 3610 | F04471 | non-negotiable | false | 10 |
| R09063 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M042 9-axis Choice Architecture | cross-ref M042 + dump 3610 | F04507 | non-negotiable | false | 10 |
| R09064 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M054 Tool Interface ToolIntent | cross-ref M054 + dump 3614 | F04521 | non-negotiable | false | 10 |
| R09065 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M055 Failure mode Sandbox+Tool+Policy taxonomies | cross-ref M055 | F04522 | non-negotiable | false | 10 |
| R09066 | Cross-cycle — 5-boundary doctrine REALIZES sovereign-os M056 Trust boundaries 7-level authority + 5-ring trust | cross-ref M056 + dump 3605 | F04523 | non-negotiable | false | 10 |
| R09067 | Doctrine — network boundary IS the IPS-side typed-authority-handle for network operations | dump 3614 + cross-ref MS035 | F04557 | non-negotiable | false | 10 |
| R09068 | Doctrine — 5-profile catalog IS the operator-facing network-scope vocabulary | dump 3602–3606 | M00969–M00973 | non-negotiable | false | 10 |
| R09069 | Doctrine — ToolIntent 3-field schema IS the runtime-facing network request format | dump 3614–3618 | M00975–M00977 | non-negotiable | false | 10 |
| R09070 | Doctrine — CPU 3-decision outcome (approve/deny/ask) IS the typed-authority-handle return value | dump 3620 | M00978 | non-negotiable | false | 10 |
| R09071 | Doctrine — network boundary REPLACES ambient process network authority with typed handles | dump 3508 (MS035) + 3614 | F04557 | non-negotiable | false | 10 |
| R09072 | Doctrine — network boundary follows candidate→filter→verify→commit pattern from MS034 | cross-ref MS034 + dump 3614–3620 | F04558 | non-negotiable | false | 10 |
| R09073 | Doctrine — "Same invariant again" — workflow + tool + memory + filesystem + network boundaries all follow same pattern | cross-ref MS034 + dump 3487 + 3552 + 3614 | F04558 | non-negotiable | false | 10 |
| R09074 | Operator UX — operator MAY pin lower network profile than ToolIntent requests | cross-ref M042 + dump 3620 | F04533 | non-negotiable | false | 10 |
| R09075 | Operator UX — operator MAY escalate network profile via explicit approval | cross-ref M042 + dump 3620 | F04533 | non-negotiable | false | 10 |
| R09076 | Operator UX — operator MUST be notified on high-risk grant requests (authenticated-browser, arbitrary-web) | cross-ref MS004 + dump 3605–3606 | F04484 | non-negotiable | false | 10 |
| R09077 | Operator UX — operator MUST be able to view all active grants + countdown | cross-ref MS011 + dump 3618 | F04534 | non-negotiable | false | 10 |
| R09078 | Operator UX — operator MUST be able to view grant history + denial history | cross-ref MS009 + dump 3620 | F04535 | non-negotiable | false | 10 |
| R09079 | Operator UX — operator MUST be able to set per-profile default ttl | cross-ref M042 + dump 3618 | F04481 | non-negotiable | false | 10 |
| R09080 | Operator UX — operator MUST be able to set per-profile maximum ttl | cross-ref M042 + dump 3618 | F04481 | non-negotiable | false | 10 |
| R09081 | Hardware reality — ProArt X870E-Creator dual NIC (10GbE Aquantia AQC113C + 2.5GbE Intel I226-V) | cross-ref M040 + dump 3596 | F04513 | non-negotiable | false | 10 |
| R09082 | Hardware reality — 10GbE NIC = data plane (NAS / dataset sync / model artifact transfer) | cross-ref M040 + dump 3596 | F04517 | non-negotiable | false | 10 |
| R09083 | Hardware reality — 2.5GbE NIC = management plane (web dashboard / SSH / observability) | cross-ref M040 + dump 3596 | F04517 | non-negotiable | false | 10 |
| R09084 | Hardware reality — per-profile NIC binding via macvlan or ipvlan | cross-ref M045 + dump 3526 | F04540 | non-negotiable | false | 10 |
| R09085 | Hardware reality — per-VM virtio-net-pci device + bridge | cross-ref MS034 + dump 3458 | F04539 | non-negotiable | false | 10 |
| R09086 | Hardware reality — Linux netfilter nftables stateful tracking via conntrack | cross-ref MS024 + dump 3610 | F04541 | non-negotiable | false | 10 |
| R09087 | Hardware reality — eBPF cgroup_sock_addr program hooks connect() / sendmsg() | cross-ref MS016 + dump 3605 | F04493 | non-negotiable | false | 10 |
| R09088 | Hardware reality — TLS handshake JA3 fingerprinting at network boundary | cross-ref MS023 + dump 3604 | F04491 | non-negotiable | false | 10 |
| R09089 | Implementation — 5-profile network catalog encoded in /etc/selfdef/network-profiles.toml | architecture + dump 3602–3606 | F04488 | non-negotiable | false | 10 |
| R09090 | Implementation — per-profile nftables rule set encoded in /etc/nftables.d/selfdef-network-<profile>.conf | architecture + cross-ref MS024 | F04488 | non-negotiable | false | 10 |
| R09091 | Implementation — per-profile FQDN allowlist encoded in /etc/selfdef/network-fqdns-<profile>.list | architecture + dump 3603 | F04459 | non-negotiable | false | 10 |
| R09092 | Implementation — per-profile SNI allowlist encoded in /etc/selfdef/network-sni-<profile>.list | cross-ref MS023 + dump 3604 | F04491 | non-negotiable | false | 10 |
| R09093 | Implementation — per-profile network namespace name `selfdef-net-<profile>` | architecture + cross-ref M045 | F04458 | non-negotiable | false | 10 |
| R09094 | Implementation — capability_word.network_scope encoded in 8 bits (256 possible profiles) | dump 3498 + cross-ref MS035 | F04471 | non-negotiable | false | 10 |
| R09095 | Implementation — ToolIntent.network_scope MUST be one of {offline, package_registries, docs_only, arbitrary_web, authenticated_browser} | dump 3614 + dump 3602–3606 | F04451 | non-negotiable | false | 10 |
| R09096 | Implementation — ToolIntent.reason MUST be non-empty human-readable string | dump 3616 + architecture | F04478 | non-negotiable | false | 10 |
| R09097 | Implementation — ToolIntent.ttl MUST be positive integer seconds | dump 3618 + architecture | F04479 | non-negotiable | false | 10 |
| R09098 | Implementation — ToolIntent.ttl default = 60s when unspecified | dump 3618 + architecture | F04479 | non-negotiable | false | 10 |
| R09099 | Implementation — ToolIntent.ttl maximum = 3600s without operator approval | dump 3618 + cross-ref M042 | F04481 | non-negotiable | false | 10 |
| R09100 | Implementation — ToolIntent.ttl maximum = 86400s (24h) with operator approval | dump 3618 + cross-ref M042 | F04481 | non-negotiable | false | 10 |
| R09101 | Implementation — network-grant data structure = {grant_id, scope, reason, ttl, expires_at, capability_word, trace_id, signature} | architecture + dump 3614–3620 | F04482 | non-negotiable | false | 10 |
| R09102 | Implementation — network-grant signature uses MS003 selfdef-signing | cross-ref MS003 + dump 3618 | F04482 | non-negotiable | false | 10 |
| R09103 | Implementation — network-grant lifecycle = {pending, approved, active, expired, revoked} | architecture + dump 3618–3620 | F04482 | non-negotiable | false | 10 |
| R09104 | Implementation — network-grant transition pending → approved emits M049 16-event taxonomy event | cross-ref M049 + dump 3620 | F04485 | non-negotiable | false | 10 |
| R09105 | Implementation — network-grant transition approved → active applies nftables rules | cross-ref MS024 + dump 3620 | F04482 | non-negotiable | false | 10 |
| R09106 | Implementation — network-grant transition active → expired removes nftables rules | cross-ref MS024 + dump 3618 | F04480 | non-negotiable | false | 10 |
| R09107 | Implementation — network-grant transition active → revoked removes nftables rules + emits OCSF event | cross-ref MS024 + MS026 + dump 3620 | F04483 + F04536 | non-negotiable | false | 10 |
| R09108 | Observability — every network-grant transition emits trace event via M049 13-field span | cross-ref M049 + dump 3620 | F04485 | non-negotiable | false | 10 |
| R09109 | Observability — network-boundary violations emit OCSF Detection Finding class 2004 | cross-ref MS026 + M049 | F04483 | non-negotiable | false | 10 |
| R09110 | Observability — MS027 dashboard renders Sankey diagram of profile transitions | cross-ref MS027 + dump 3620 | F04537 | non-negotiable | false | 10 |
| R09111 | Observability — MS027 dashboard renders per-FQDN egress histogram | cross-ref MS027 + dump 3605 | F04499 | non-negotiable | false | 10 |
| R09112 | Operator UX — `selfdefctl network status` output format: JSON with active grants list | architecture | F04532 | non-negotiable | false | 10 |
| R09113 | Operator UX — `selfdefctl network grants` output format: table with grant_id + scope + ttl_remaining + reason | architecture | F04534 | non-negotiable | false | 10 |
| R09114 | Cross-repo binding — selfdef MS038 + sovereign-os M048 Module 3 + M049 + M042 + M044 (10GbE/2.5GbE NICs) form the cross-repo network-governance quintet | cross-ref M048 + M049 + M042 + M044 | E0390 | non-negotiable | false | 10 |
| R09115 | Cross-repo binding — selfdef MS038 + sovereign-os M040 (Hyper Feature 6 dual NIC) realizes data-plane-vs-management-plane network split | cross-ref M040 + dump 3596 | F04517 | non-negotiable | false | 10 |
| R09116 | Cross-repo binding — selfdef MS038 + sovereign-os M046 (LoRA foundry adapter download flow) demonstrates package-registries profile use | cross-ref M046 + dump 3603 | F04514 | non-negotiable | false | 10 |
| R09117 | Cross-repo binding — selfdef MS038 + sovereign-os M032 (Cloud Expert Plane) demonstrates arbitrary-web profile use | cross-ref M032 + dump 3605 | F04515 | non-negotiable | false | 10 |
| R09118 | Cross-repo binding — selfdef MS038 + sovereign-os M034 (Anthropic-first Gateway) demonstrates authenticated-browser profile use | cross-ref M034 + dump 3606 | F04516 | non-negotiable | false | 10 |
| R09119 | Cross-repo binding — selfdef MS038 + sovereign-os M050 Design Law "CPU enforces" + "Tools prove" + "ZFS remembers" + "User chooses" + "Runtime routes" + "Models propose" align with network-grant lifecycle | cross-ref M050 + dump 3620 | F04520 | non-negotiable | false | 10 |
| R09120 | Composite — MS038 (10 epics / 26 modules / 120 features / 240 reqs) catalogs Network Boundary from dump 3594-3621: "This matters" + 5 network profiles (offline / allow package registries / allow documentation web / allow arbitrary web / allow authenticated browser profile) + "Each profile maps to policy bits" + ToolIntent 3-field schema (network_scope + reason + ttl) + "The CPU can approve, deny, or ask user"; cross-module enforcement via 30+ selfdef modules (MS001-MS037) + sovereign-os M032/M034/M040/M042/M043/M044/M045/M046/M048/M049/M050/M054/M055/M056; cross-repo binding via MS007 surface-manifest typed-mirror crate publishing 5-profile + 3-field-ToolIntent + 8-bit-mapping schemas; network boundary IS the IPS-side typed-authority-handle for network operations | dump 3594–3620 + cross-ref MS007 + MS001-MS037 + M032-M056 | E0381 + E0382 + E0383 + E0384 + E0385 + E0386 + E0387 + E0388 + E0389 + E0390 | non-negotiable | false | 10 |

## Cross-references

- Adjacent INDEX rows: MS037 Filesystem boundary / MS039 7 authority levels + 5 trust rings
- Cross-cycle — MS038 + MS034 + MS035 + MS036 + MS037 form the IPS-side 5-boundary doctrine
- Cross-repo realization — sovereign-os M032/M034/M040/M042/M043/M044/M045/M046/M048/M049/M050/M054/M055/M056 realize runtime-side orchestration
- Cross-repo binding — MS007 surface-manifest typed-mirror crate carries 5-profile + 3-field schemas
- Operator references: Linux netfilter/nftables + SNI RFC 6066 + JA3 fingerprint + OWASP Cloud-Native Top 10 + ip-netns(8) + Podman --network modes + virtio-net-pci docs + eBPF LSM hooks + Sigma rule format + TLS-MITM tooling
- Doctrine — network boundary IS the IPS-side typed-authority-handle for network operations; complements MS035 capability_word, MS036 tier-classification, MS037 filesystem boundary
