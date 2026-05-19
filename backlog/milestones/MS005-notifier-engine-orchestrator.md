# MS005 — Notifier engine + orchestrator

> Parent: `backlog/milestones/INDEX.md` row MS005.
> Source: `crates/selfdef-notifier` + `crates/selfdef-notifier-engine` + `crates/selfdef-notifier-orchestrator` + SDD-008 notifications-orchestration (charter; design points D-1..D-8 + D-5e + D-4 HTTP ack + D-024 write(1) shipped per PR #109..#173).

## Epics (E0046–E0055)

| Epic ID | Phrase | Source |
|---|---|---|
| E0046 | Notifier engine — template rendering + queue + dedup + retry + rate-limit | `crates/selfdef-notifier-engine` + SDD-008 |
| E0047 | Notifier orchestrator — fan-out + failover + escalation + routing rules across 14 integrations | `crates/selfdef-notifier-orchestrator` + SDD-008 |
| E0048 | Notifier core trait + envelope/receipt schemas (extends MS004 contract) | `crates/selfdef-notifier` + MS004 |
| E0049 | D-1..D-8 design-point implementation status (per SDD-008) | SDD-008 charter |
| E0050 | D-5e adapter — operator-extensible adapter pattern (post-Phase-6 PRs #140..#146) | SDD-008 + per-channel-adapter crates |
| E0051 | D-4 HTTP ack — webhook-driven delivery confirmation | SDD-008 D-4 |
| E0052 | D-024 — `write(1)` per-user TTY (sibling of D-8 wall, realises D-004) | `crates/selfdef-integration-write` + SDD-008 D-024 |
| E0053 | `selfdefctl notify` 4-verb CLI surface (list / test / deliveries / resend) | `crates/selfdef-cli` + SDD-008 D-4 |
| E0054 | Operator routing rules — verdict-severity + source + channel-policy expressions | `crates/selfdef-notifier-orchestrator` |
| E0055 | F-2031-NNN findings ledger — Phase 6 closure-cycle audit follow-ups | `docs/review/phase-6/` |

## Modules (M00107–M00132)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00107 | Engine queue — bounded MPMC queue with operator-tunable capacity | `crates/selfdef-notifier-engine` Queue | E0046 |
| M00108 | Engine template registry — handlebars-style templates per (channel, severity) tuple | `crates/selfdef-notifier-engine` Templates | E0046 |
| M00109 | Engine dedup table — verdict_id + window-based suppression | `crates/selfdef-notifier-engine` Dedup | E0046 |
| M00110 | Engine retry scheduler — exponential backoff + jitter + max-retries | `crates/selfdef-notifier-engine` Retry | E0046 |
| M00111 | Engine rate-limit governor — per-channel sliding-window cap | `crates/selfdef-notifier-engine` RateLimit | E0046 |
| M00112 | Engine digest mode — hourly + daily roll-up | `crates/selfdef-notifier-engine` Digest | E0046 |
| M00113 | Engine silence window — operator-tunable per-channel quiet hours | `crates/selfdef-notifier-engine` Silence | E0046 |
| M00114 | Orchestrator routing rules — DSL for (severity, source, urgency) → channels expression | `crates/selfdef-notifier-orchestrator` Rules | E0054 |
| M00115 | Orchestrator fan-out — one NotifyEnvelope → N integrations in parallel | `crates/selfdef-notifier-orchestrator` FanOut | E0047 |
| M00116 | Orchestrator failover — primary → backup integration when primary errors | `crates/selfdef-notifier-orchestrator` Failover | E0047 |
| M00117 | Orchestrator escalation — warn → error → critical re-routing chain | `crates/selfdef-notifier-orchestrator` Escalation | E0047 |
| M00118 | Orchestrator durability — DeliveryReceipts persisted across daemon restart | `crates/selfdef-notifier-orchestrator` Durability + `crates/selfdef-store` | E0047 |
| M00119 | Orchestrator shutdown drain — graceful drain on SIGTERM | `crates/selfdef-notifier-orchestrator` Drain | E0047 |
| M00120 | Orchestrator dispatcher — pulls from queue + maps NotifyEnvelope → per-channel adapter | `crates/selfdef-notifier-orchestrator` Dispatcher | E0047 |
| M00121 | D-1 — NotifyEnvelope canonical schema | SDD-008 D-1 | E0049 |
| M00122 | D-2 — DeliveryReceipt canonical schema | SDD-008 D-2 | E0049 |
| M00123 | D-3 — Channel adapter trait | SDD-008 D-3 | E0049 |
| M00124 | D-4 — HTTP ack receiver (webhook-driven delivery confirmation) | SDD-008 D-4 | E0051 |
| M00125 | D-5 — Routing-rule DSL | SDD-008 D-5 | E0054 |
| M00126 | D-5e — Operator-extensible adapter pattern (third-party channel adapter via stable trait) | SDD-008 D-5e | E0050 |
| M00127 | D-6 — Engine queue + scheduler | SDD-008 D-6 | E0046 |
| M00128 | D-7 — Orchestrator fan-out + failover + escalation | SDD-008 D-7 | E0047 |
| M00129 | D-8 — Wall channel adapter | SDD-008 D-8 | E0052 |
| M00130 | D-024 — Write(1) per-user TTY channel adapter | SDD-008 D-024 | E0052 |
| M00131 | `selfdefctl notify resend` verb — re-dispatch a previously-delivered envelope | `crates/selfdef-cli` notify resend | E0053 |
| M00132 | F-2031-NNN findings ledger — per-finding tracking + remediation status | `docs/review/phase-6/` | E0055 |

## Features (F00481–F00600)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00481 | Engine queue capacity operator-tunable | `crates/selfdef-config` | M00107 | profile | true |
| F00482 | Engine queue overflow policy (drop-with-warning / block) | `crates/selfdef-config` | M00107 | mode | true |
| F00483 | Engine queue metric `selfdef_notifier_queue_depth` | `crates/selfdef-notifier-engine` | M00107 | observability_metric | true |
| F00484 | Engine queue metric `selfdef_notifier_queue_overflow_total` | `crates/selfdef-notifier-engine` | M00107 | observability_metric | true |
| F00485 | Engine template registry — handlebars-style template per (channel, severity) tuple | `crates/selfdef-notifier-engine` | M00108 | composite | true |
| F00486 | Engine template — built-in default per severity (info / warn / error / critical) | `crates/selfdef-notifier-engine` | M00108 | composite | true |
| F00487 | Engine template — operator-supplied overrides via `/etc/selfdef/notifier-templates/<channel>-<severity>.hbs` | `crates/selfdef-config` | M00108 | profile | true |
| F00488 | Engine template — accessible vars (severity / title / body / verdict_id / action_id / source / urgency / metadata.*) | `crates/selfdef-notifier-engine` | M00108 | composite | true |
| F00489 | Engine template — refuses on missing required var (operator-readable error) | `crates/selfdef-notifier-engine` | M00108 | composite | false |
| F00490 | Engine dedup window — operator-tunable per-channel (default 5m for non-critical) | `crates/selfdef-config` | M00109 | profile | true |
| F00491 | Engine dedup key — `verdict_id` (default) | `crates/selfdef-notifier-engine` | M00109 | composite | false |
| F00492 | Engine dedup key — `verdict_id + channel` (per-channel dedup) | `crates/selfdef-notifier-engine` | M00109 | composite | true |
| F00493 | Engine dedup key — operator-extensible expression | `crates/selfdef-notifier-engine` | M00109 | composite | true |
| F00494 | Engine dedup metric `selfdef_notifier_dedup_suppressed_total{channel}` | `crates/selfdef-notifier-engine` | M00109 | observability_metric | true |
| F00495 | Engine retry — max_retries operator-tunable (default 3) | `crates/selfdef-config` | M00110 | profile | true |
| F00496 | Engine retry — backoff_base_ms operator-tunable (default 500) | `crates/selfdef-config` | M00110 | profile | true |
| F00497 | Engine retry — backoff_max_ms operator-tunable (default 60000) | `crates/selfdef-config` | M00110 | profile | true |
| F00498 | Engine retry — jitter operator-tunable (default 25%) | `crates/selfdef-config` | M00110 | profile | true |
| F00499 | Engine retry — honors `Retry-After` header when present | `crates/selfdef-notifier-engine` | M00110 | composite | true |
| F00500 | Engine retry metric `selfdef_notifier_retry_total{channel,attempt}` | `crates/selfdef-notifier-engine` | M00110 | observability_metric | true |
| F00501 | Engine rate-limit — per-second cap | `crates/selfdef-config` | M00111 | profile | true |
| F00502 | Engine rate-limit — per-minute cap | `crates/selfdef-config` | M00111 | profile | true |
| F00503 | Engine rate-limit — per-hour cap | `crates/selfdef-config` | M00111 | profile | true |
| F00504 | Engine rate-limit — sliding-window algorithm (not fixed-bucket) | `crates/selfdef-notifier-engine` | M00111 | composite | false |
| F00505 | Engine rate-limit metric `selfdef_notifier_rate_limited_total{channel,window}` | `crates/selfdef-notifier-engine` | M00111 | observability_metric | true |
| F00506 | Engine digest mode — hourly roll-up | `crates/selfdef-notifier-engine` | M00112 | mode | true |
| F00507 | Engine digest mode — daily roll-up | `crates/selfdef-notifier-engine` | M00112 | mode | true |
| F00508 | Engine digest mode — operator-tunable digest schedule (cron-style) | `crates/selfdef-config` | M00112 | profile | true |
| F00509 | Engine silence window — operator-tunable quiet hours (e.g. 23:00-07:00) | `crates/selfdef-config` | M00113 | profile | true |
| F00510 | Engine silence window — per-severity bypass (critical bypasses silence by default) | `crates/selfdef-config` | M00113 | profile | true |
| F00511 | Orchestrator routing-rule DSL — boolean expression `(severity ≥ X) AND (source == Y) AND (urgency == Z) → [channel1, channel2, ...]` | `crates/selfdef-notifier-orchestrator` | M00114 | composite | true |
| F00512 | Orchestrator routing-rule DSL — operator-supplied via `/etc/selfdef/notifier-routes.toml` | `crates/selfdef-config` | M00114 | profile | true |
| F00513 | Orchestrator routing-rule DSL — hot-reload without daemon restart | `crates/selfdef-notifier-orchestrator` | M00114 | composite | true |
| F00514 | Orchestrator routing-rule DSL — validation refuses malformed rules with operator-readable error | `crates/selfdef-notifier-orchestrator` | M00114 | composite | false |
| F00515 | Orchestrator routing-rule DSL — default fallback route when no rule matches | `crates/selfdef-config` | M00114 | profile | true |
| F00516 | Orchestrator routing-rule DSL — wildcard `*` for source/severity/urgency | `crates/selfdef-notifier-orchestrator` | M00114 | composite | true |
| F00517 | Orchestrator routing-rule DSL — recipient-list overrides per rule | `crates/selfdef-notifier-orchestrator` | M00114 | composite | true |
| F00518 | Orchestrator fan-out — parallel dispatch to N integrations | `crates/selfdef-notifier-orchestrator` | M00115 | composite | false |
| F00519 | Orchestrator fan-out — per-channel parallelism cap | `crates/selfdef-config` | M00115 | profile | true |
| F00520 | Orchestrator fan-out metric `selfdef_notifier_fanout_total{rule_id,channels_count}` | `crates/selfdef-notifier-orchestrator` | M00115 | observability_metric | true |
| F00521 | Orchestrator failover — primary→backup chain per channel | `crates/selfdef-notifier-orchestrator` | M00116 | composite | true |
| F00522 | Orchestrator failover — operator-tunable failure-threshold before failover triggers | `crates/selfdef-config` | M00116 | profile | true |
| F00523 | Orchestrator failover — automatic recovery when primary recovers | `crates/selfdef-notifier-orchestrator` | M00116 | composite | true |
| F00524 | Orchestrator failover metric `selfdef_notifier_failover_total{primary,backup}` | `crates/selfdef-notifier-orchestrator` | M00116 | observability_metric | true |
| F00525 | Orchestrator escalation — warn → error severity bump after N occurrences | `crates/selfdef-config` | M00117 | profile | true |
| F00526 | Orchestrator escalation — error → critical severity bump after N occurrences | `crates/selfdef-config` | M00117 | profile | true |
| F00527 | Orchestrator escalation — per-recipient escalation list (different recipients per severity) | `crates/selfdef-config` | M00117 | profile | true |
| F00528 | Orchestrator escalation metric `selfdef_notifier_escalation_total{from_sev,to_sev}` | `crates/selfdef-notifier-orchestrator` | M00117 | observability_metric | true |
| F00529 | Orchestrator durability — DeliveryReceipts persisted to `selfdef-store` actions table | `crates/selfdef-store` | M00118 | composite | false |
| F00530 | Orchestrator durability — un-acked envelopes resume after daemon restart | `crates/selfdef-notifier-orchestrator` | M00118 | composite | false |
| F00531 | Orchestrator shutdown drain — SIGTERM blocks until in-flight envelopes complete or hard-deadline | `crates/selfdef-notifier-orchestrator` | M00119 | composite | false |
| F00532 | Orchestrator shutdown drain — operator-tunable drain timeout (default 30s) | `crates/selfdef-config` | M00119 | profile | true |
| F00533 | Orchestrator dispatcher — pulls from engine queue and maps envelope to channel adapter | `crates/selfdef-notifier-orchestrator` | M00120 | composite | false |
| F00534 | Orchestrator dispatcher — concurrent worker pool with operator-tunable size | `crates/selfdef-config` | M00120 | profile | true |
| F00535 | D-1 NotifyEnvelope schema honored verbatim from MS004 R00728-R00735 | SDD-008 D-1 + MS004 | M00121 | composite | false |
| F00536 | D-2 DeliveryReceipt schema honored verbatim from MS004 R00736-R00740 | SDD-008 D-2 + MS004 | M00122 | composite | false |
| F00537 | D-3 Channel adapter trait — every integration in MS004 implements this | SDD-008 D-3 + MS004 | M00123 | composite | false |
| F00538 | D-4 HTTP ack receiver — webhook endpoint for delivery confirmation | SDD-008 D-4 | M00124 | composite | true |
| F00539 | D-4 HTTP ack — operator-tunable expected ack URL per integration | `crates/selfdef-config` | M00124 | profile | true |
| F00540 | D-4 HTTP ack — TLS verification required by default | `crates/selfdef-config` | M00124 | non-negotiable | false |
| F00541 | D-4 HTTP ack — ack timeout operator-tunable (default 30s) | `crates/selfdef-config` | M00124 | profile | true |
| F00542 | D-4 HTTP ack metric `selfdef_notifier_http_ack_total{channel,status}` | `crates/selfdef-notifier-engine` | M00124 | observability_metric | true |
| F00543 | D-5 Routing-rule DSL formal grammar documented | `docs/sdd/008-notifications-orchestration.md` | M00125 | composite | true |
| F00544 | D-5e Operator-extensible adapter pattern — 4 Q-G adapter pattern-instances shipped (PRs #140-#146) | SDD-008 D-5e | M00126 | composite | true |
| F00545 | D-5e — third-party adapter via stable `Channel` trait | `crates/selfdef-notifier` | M00126 | composite | true |
| F00546 | D-5e — adapter registry hot-loadable at daemon start | `crates/selfdef-notifier-orchestrator` | M00126 | composite | true |
| F00547 | D-6 Engine queue + scheduler implementation matches charter | SDD-008 D-6 | M00127 | composite | false |
| F00548 | D-7 Orchestrator fan-out + failover + escalation implementation matches charter | SDD-008 D-7 | M00128 | composite | false |
| F00549 | D-8 Wall adapter — implements MS004 Wall integration end-to-end | SDD-008 D-8 + MS004 E0044 | M00129 | composite | true |
| F00550 | D-024 Write(1) adapter — implements MS004 Write integration end-to-end (PR #170) | SDD-008 D-024 + MS004 E0045 | M00130 | composite | true |
| F00551 | CLI `selfdefctl notify list` — lists all 14 integrations + engine queue depth + orchestrator state | `crates/selfdef-cli` | E0053 | cli_verb | true |
| F00552 | CLI `selfdefctl notify test <channel>` — send synthetic test envelope | `crates/selfdef-cli` | E0053 | cli_verb | true |
| F00553 | CLI `selfdefctl notify deliveries [--channel <name>]` — list recent deliveries | `crates/selfdef-cli` | E0053 | cli_verb | true |
| F00554 | CLI `selfdefctl notify resend --receipt-id <id>` — re-dispatch previously-delivered envelope (PR #173) | `crates/selfdef-cli` | M00131 | cli_verb | true |
| F00555 | API `POST /v1/notifier/test/<channel>` (operator-triggered test) | `crates/selfdef-api` | E0053 | api_endpoint | true |
| F00556 | API `POST /v1/notifier/resend` (operator-triggered resend) | `crates/selfdef-api` | M00131 | api_endpoint | true |
| F00557 | API `GET /v1/notifier/queue` (engine queue depth + per-channel breakdown) | `crates/selfdef-api` | M00107 | api_endpoint | true |
| F00558 | API `GET /v1/notifier/rules` (lists active routing rules + last reload time) | `crates/selfdef-api` | M00114 | api_endpoint | true |
| F00559 | API `POST /v1/notifier/rules/reload` (hot-reload rules without daemon restart) | `crates/selfdef-api` | F00513 | api_endpoint | true |
| F00560 | Routing-rule example — `severity=critical AND urgency=immediate → [pagerduty, twilio, signal]` | `docs/sdd/008-notifications-orchestration.md` | M00114 | composite | true |
| F00561 | Routing-rule example — `severity=warn AND urgency=batched → [slack, discord, smtp]` | `docs/sdd/008-notifications-orchestration.md` | M00114 | composite | true |
| F00562 | Routing-rule example — `severity=info AND source=canary → [shared-audit-summary, loki]` | `docs/sdd/008-notifications-orchestration.md` | M00114 | composite | true |
| F00563 | Routing-rule example — `urgency=digest → [smtp]` | `docs/sdd/008-notifications-orchestration.md` | M00114 | composite | true |
| F00564 | Routing-rule example — `source=tetragon AND severity≥error → [wall, ntfy]` | `docs/sdd/008-notifications-orchestration.md` | M00114 | composite | true |
| F00565 | Dashboard — engine queue depth + per-channel breakdown | `dashboard/` | M00107 | dashboard | true |
| F00566 | Dashboard — orchestrator routing-rule fire-counts | `dashboard/` | M00114 | dashboard | true |
| F00567 | Dashboard — fan-out parallelism (per envelope: channels dispatched + ack received) | `dashboard/` | M00115 | dashboard | true |
| F00568 | Dashboard — failover transitions (per channel: primary state + backup state + last-failover-at) | `dashboard/` | M00116 | dashboard | true |
| F00569 | Dashboard — escalation chain visualization (which envelopes escalated from warn→error→critical) | `dashboard/` | M00117 | dashboard | true |
| F00570 | Dashboard — durability inspector (in-flight envelopes survived restart count) | `dashboard/` | M00118 | dashboard | true |
| F00571 | Dashboard — F-2031-NNN findings ledger status | `dashboard/` | M00132 | dashboard | true |
| F00572 | Metric `selfdef_notifier_envelopes_processed_total{channel,severity,outcome}` | `crates/selfdef-notifier-engine` | E0046 | observability_metric | true |
| F00573 | Metric `selfdef_notifier_envelopes_pending` | `crates/selfdef-notifier-engine` | M00107 | observability_metric | true |
| F00574 | Metric `selfdef_notifier_route_evaluation_us` | `crates/selfdef-notifier-orchestrator` | M00114 | observability_metric | true |
| F00575 | Metric `selfdef_notifier_template_render_us{channel,severity}` | `crates/selfdef-notifier-engine` | M00108 | observability_metric | true |
| F00576 | Metric `selfdef_notifier_durability_resumed_total` | `crates/selfdef-notifier-orchestrator` | M00118 | observability_metric | true |
| F00577 | Test — engine queue overflow drops with operator-readable warning | tests/ | F00482 | test | false |
| F00578 | Test — engine template render fails with operator-readable error on missing var | tests/ | F00489 | test | false |
| F00579 | Test — engine dedup suppresses second envelope with same key within window | tests/ | M00109 | test | false |
| F00580 | Test — engine retry honors max_retries + exponential backoff + jitter + Retry-After | tests/ | M00110 | test | false |
| F00581 | Test — engine rate-limit caps per-second / per-minute / per-hour | tests/ | M00111 | test | false |
| F00582 | Test — engine digest hourly roll-up aggregates correctly | tests/ | M00112 | test | false |
| F00583 | Test — engine silence window suppresses non-critical during quiet hours | tests/ | M00113 | test | false |
| F00584 | Test — orchestrator routing rule fires correct channel set for synthetic envelope | tests/ | M00114 | test | false |
| F00585 | Test — orchestrator routing rule hot-reload swaps atomically (no half-loaded state) | tests/ | F00513 | test | false |
| F00586 | Test — orchestrator fan-out dispatches to N integrations in parallel | tests/ | M00115 | test | false |
| F00587 | Test — orchestrator failover routes to backup when primary fails 3x | tests/ | M00116 | test | false |
| F00588 | Test — orchestrator escalation bumps severity after N occurrences | tests/ | M00117 | test | false |
| F00589 | Test — orchestrator durability resumes un-acked envelopes after daemon restart | tests/ | M00118 | test | false |
| F00590 | Test — orchestrator shutdown drain blocks SIGTERM until queue empty or deadline | tests/ | M00119 | test | false |
| F00591 | Test — D-4 HTTP ack receiver acknowledges delivery within 30s | tests/ | M00124 | test | false |
| F00592 | Test — D-5e third-party adapter loads via stable trait | tests/ | M00126 | test | false |
| F00593 | Test — D-8 wall adapter end-to-end on real TTY (Debian 13 VM) | tests/ | M00129 | test | false |
| F00594 | Test — D-024 write(1) adapter end-to-end on real TTY user (Debian 13 VM) | tests/ | M00130 | test | false |
| F00595 | Test — `selfdefctl notify resend` re-dispatches with operator-readable preview | tests/ | M00131 | test | false |
| F00596 | UX — operator-discoverable next-step when route rule matches zero channels | `crates/selfdef-cli` | F00515 | composite | true |
| F00597 | UX — operator-readable hot-reload diff (rules added / removed / changed) | `crates/selfdef-cli` | F00513 | composite | true |
| F00598 | UX — dashboard surfaces routing-rule fire-rate as live tile | `dashboard/` | M00114 | dashboard | true |
| F00599 | UX — dashboard surfaces orchestrator drain progress during SIGTERM | `dashboard/` | M00119 | dashboard | true |
| F00600 | Composite — Notifier engine + orchestrator implement SDD-008 D-1..D-8 + D-5e + D-4 HTTP ack + D-024 verbatim; MS004 14 integrations are the channel-adapter surface this milestone orchestrates | SDD-008 + MS004 | E0046 | composite | false |

## Requirements (R00961–R01200)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R00961 | Notifier engine is implemented as `selfdef-notifier-engine` Rust crate | repo | E0046 | non-negotiable | false | 10 |
| R00962 | Notifier orchestrator is implemented as `selfdef-notifier-orchestrator` Rust crate | repo | E0047 | non-negotiable | false | 10 |
| R00963 | Notifier core trait + envelope/receipt schemas live in `selfdef-notifier` crate | repo | E0048 | non-negotiable | false | 10 |
| R00964 | Notifier engine implements queue + template + dedup + retry + rate-limit + digest + silence | `crates/selfdef-notifier-engine` | E0046 | non-negotiable | false | 10 |
| R00965 | Notifier orchestrator implements fan-out + failover + escalation + routing-rules + durability + drain + dispatcher | `crates/selfdef-notifier-orchestrator` | E0047 | non-negotiable | false | 10 |
| R00966 | Engine queue capacity operator-tunable | `crates/selfdef-config` | F00481 | non-negotiable | true | 10 |
| R00967 | Engine queue overflow policy operator-selectable (drop-with-warning / block) | `crates/selfdef-config` | F00482 | non-negotiable | true | 10 |
| R00968 | Engine queue emits `selfdef_notifier_queue_depth` Prometheus metric | `crates/selfdef-notifier-engine` | F00483 | non-negotiable | true | 10 |
| R00969 | Engine queue emits `selfdef_notifier_queue_overflow_total` Prometheus metric | `crates/selfdef-notifier-engine` | F00484 | non-negotiable | true | 10 |
| R00970 | Engine template registry stores handlebars-style templates per (channel, severity) tuple | `crates/selfdef-notifier-engine` | M00108 | non-negotiable | true | 10 |
| R00971 | Engine ships built-in default template per severity (info / warn / error / critical) | `crates/selfdef-notifier-engine` | F00486 | non-negotiable | true | 10 |
| R00972 | Engine accepts operator-supplied template overrides at `/etc/selfdef/notifier-templates/<channel>-<severity>.hbs` | `crates/selfdef-config` | F00487 | non-negotiable | true | 10 |
| R00973 | Engine template vars include severity / title / body / verdict_id / action_id / source / urgency / metadata.* | `crates/selfdef-notifier-engine` | F00488 | non-negotiable | true | 10 |
| R00974 | Engine template refuses on missing required var with operator-readable error | `crates/selfdef-notifier-engine` | F00489 | non-negotiable | false | 10 |
| R00975 | Engine dedup window operator-tunable per-channel (default 5m for non-critical) | `crates/selfdef-config` | F00490 | non-negotiable | true | 10 |
| R00976 | Engine dedup default key is `verdict_id` | `crates/selfdef-notifier-engine` | F00491 | non-negotiable | false | 10 |
| R00977 | Engine dedup supports `verdict_id + channel` key (per-channel dedup) | `crates/selfdef-notifier-engine` | F00492 | non-negotiable | true | 10 |
| R00978 | Engine dedup supports operator-extensible expression | `crates/selfdef-notifier-engine` | F00493 | non-negotiable | true | 10 |
| R00979 | Engine emits `selfdef_notifier_dedup_suppressed_total{channel}` metric | `crates/selfdef-notifier-engine` | F00494 | non-negotiable | true | 10 |
| R00980 | Engine retry max_retries operator-tunable (default 3) | `crates/selfdef-config` | F00495 | non-negotiable | true | 10 |
| R00981 | Engine retry backoff_base_ms operator-tunable (default 500) | `crates/selfdef-config` | F00496 | non-negotiable | true | 10 |
| R00982 | Engine retry backoff_max_ms operator-tunable (default 60000) | `crates/selfdef-config` | F00497 | non-negotiable | true | 10 |
| R00983 | Engine retry jitter operator-tunable (default 25%) | `crates/selfdef-config` | F00498 | non-negotiable | true | 10 |
| R00984 | Engine retry honors `Retry-After` header when present | `crates/selfdef-notifier-engine` | F00499 | non-negotiable | true | 10 |
| R00985 | Engine emits `selfdef_notifier_retry_total{channel,attempt}` metric | `crates/selfdef-notifier-engine` | F00500 | non-negotiable | true | 10 |
| R00986 | Engine rate-limit per-second cap operator-tunable | `crates/selfdef-config` | F00501 | non-negotiable | true | 10 |
| R00987 | Engine rate-limit per-minute cap operator-tunable | `crates/selfdef-config` | F00502 | non-negotiable | true | 10 |
| R00988 | Engine rate-limit per-hour cap operator-tunable | `crates/selfdef-config` | F00503 | non-negotiable | true | 10 |
| R00989 | Engine rate-limit uses sliding-window algorithm (not fixed-bucket) | `crates/selfdef-notifier-engine` | F00504 | non-negotiable | false | 10 |
| R00990 | Engine emits `selfdef_notifier_rate_limited_total{channel,window}` metric | `crates/selfdef-notifier-engine` | F00505 | non-negotiable | true | 10 |
| R00991 | Engine digest mode supports hourly roll-up | `crates/selfdef-notifier-engine` | F00506 | non-negotiable | true | 10 |
| R00992 | Engine digest mode supports daily roll-up | `crates/selfdef-notifier-engine` | F00507 | non-negotiable | true | 10 |
| R00993 | Engine digest schedule operator-tunable (cron-style) | `crates/selfdef-config` | F00508 | non-negotiable | true | 10 |
| R00994 | Engine silence window operator-tunable (default 23:00–07:00 disabled) | `crates/selfdef-config` | F00509 | non-negotiable | true | 10 |
| R00995 | Engine silence window per-severity bypass — critical NEVER silenced by default | `crates/selfdef-config` | F00510 | non-negotiable | false | 10 |
| R00996 | Orchestrator routing-rule DSL — boolean expression `(severity ≥ X) AND (source == Y) AND (urgency == Z) → [channels]` | `crates/selfdef-notifier-orchestrator` | F00511 | non-negotiable | true | 10 |
| R00997 | Orchestrator routing rules operator-supplied at `/etc/selfdef/notifier-routes.toml` | `crates/selfdef-config` | F00512 | non-negotiable | true | 10 |
| R00998 | Orchestrator routing rules hot-reloadable without daemon restart | `crates/selfdef-notifier-orchestrator` | F00513 | non-negotiable | true | 10 |
| R00999 | Orchestrator routing-rule validation refuses malformed rules with operator-readable error | `crates/selfdef-notifier-orchestrator` | F00514 | non-negotiable | false | 10 |
| R01000 | Orchestrator routing has operator-supplied default fallback route when no rule matches | `crates/selfdef-config` | F00515 | non-negotiable | true | 10 |
| R01001 | Orchestrator routing-rule DSL supports wildcard `*` for source/severity/urgency | `crates/selfdef-notifier-orchestrator` | F00516 | non-negotiable | true | 10 |
| R01002 | Orchestrator routing-rule DSL supports recipient-list overrides per rule | `crates/selfdef-notifier-orchestrator` | F00517 | non-negotiable | true | 10 |
| R01003 | Orchestrator fan-out dispatches to N integrations in parallel | `crates/selfdef-notifier-orchestrator` | F00518 | non-negotiable | false | 10 |
| R01004 | Orchestrator fan-out per-channel parallelism cap operator-tunable | `crates/selfdef-config` | F00519 | non-negotiable | true | 10 |
| R01005 | Orchestrator emits `selfdef_notifier_fanout_total{rule_id,channels_count}` metric | `crates/selfdef-notifier-orchestrator` | F00520 | non-negotiable | true | 10 |
| R01006 | Orchestrator failover routes primary → backup when primary fails | `crates/selfdef-notifier-orchestrator` | F00521 | non-negotiable | true | 10 |
| R01007 | Orchestrator failover threshold operator-tunable (default 3 consecutive failures) | `crates/selfdef-config` | F00522 | non-negotiable | true | 10 |
| R01008 | Orchestrator failover auto-recovers when primary recovers | `crates/selfdef-notifier-orchestrator` | F00523 | non-negotiable | true | 10 |
| R01009 | Orchestrator emits `selfdef_notifier_failover_total{primary,backup}` metric | `crates/selfdef-notifier-orchestrator` | F00524 | non-negotiable | true | 10 |
| R01010 | Orchestrator escalation bumps warn → error after N occurrences within window | `crates/selfdef-config` | F00525 | non-negotiable | true | 10 |
| R01011 | Orchestrator escalation bumps error → critical after N occurrences within window | `crates/selfdef-config` | F00526 | non-negotiable | true | 10 |
| R01012 | Orchestrator escalation supports per-recipient escalation list (different recipients per severity) | `crates/selfdef-config` | F00527 | non-negotiable | true | 10 |
| R01013 | Orchestrator emits `selfdef_notifier_escalation_total{from_sev,to_sev}` metric | `crates/selfdef-notifier-orchestrator` | F00528 | non-negotiable | true | 10 |
| R01014 | Orchestrator durability — DeliveryReceipts persisted to selfdef-store actions table | `crates/selfdef-store` | F00529 | non-negotiable | false | 10 |
| R01015 | Orchestrator durability — un-acked envelopes resume after daemon restart | `crates/selfdef-notifier-orchestrator` | F00530 | non-negotiable | false | 10 |
| R01016 | Orchestrator shutdown drain blocks SIGTERM until queue empty or hard-deadline | `crates/selfdef-notifier-orchestrator` | F00531 | non-negotiable | false | 10 |
| R01017 | Orchestrator drain timeout operator-tunable (default 30s) | `crates/selfdef-config` | F00532 | non-negotiable | true | 10 |
| R01018 | Orchestrator dispatcher pulls from engine queue and maps envelope to channel adapter | `crates/selfdef-notifier-orchestrator` | F00533 | non-negotiable | false | 10 |
| R01019 | Orchestrator dispatcher worker pool size operator-tunable | `crates/selfdef-config` | F00534 | non-negotiable | true | 10 |
| R01020 | D-1 NotifyEnvelope schema honored verbatim from MS004 R00728-R00735 | SDD-008 D-1 + MS004 | F00535 | non-negotiable | false | 10 |
| R01021 | D-2 DeliveryReceipt schema honored verbatim from MS004 R00736-R00740 | SDD-008 D-2 + MS004 | F00536 | non-negotiable | false | 10 |
| R01022 | D-3 Channel adapter trait — every integration in MS004 implements this | SDD-008 D-3 + MS004 | F00537 | non-negotiable | false | 10 |
| R01023 | D-4 HTTP ack — webhook endpoint receives delivery confirmation | SDD-008 D-4 | F00538 | non-negotiable | true | 10 |
| R01024 | D-4 HTTP ack — expected ack URL operator-tunable per integration | `crates/selfdef-config` | F00539 | non-negotiable | true | 10 |
| R01025 | D-4 HTTP ack — TLS verification required by default | `crates/selfdef-config` | F00540 | non-negotiable | false | 10 |
| R01026 | D-4 HTTP ack — ack timeout operator-tunable (default 30s) | `crates/selfdef-config` | F00541 | non-negotiable | true | 10 |
| R01027 | D-4 HTTP ack emits `selfdef_notifier_http_ack_total{channel,status}` metric | `crates/selfdef-notifier-engine` | F00542 | non-negotiable | true | 10 |
| R01028 | D-5 Routing-rule DSL formal grammar documented | `docs/sdd/008-notifications-orchestration.md` | F00543 | non-negotiable | true | 10 |
| R01029 | D-5e Operator-extensible adapter pattern shipped 4 Q-G adapter pattern-instances (PRs #140-#146) | SDD-008 D-5e | F00544 | non-negotiable | true | 10 |
| R01030 | D-5e — third-party adapter via stable `Channel` trait | `crates/selfdef-notifier` | F00545 | non-negotiable | true | 10 |
| R01031 | D-5e — adapter registry hot-loadable at daemon start | `crates/selfdef-notifier-orchestrator` | F00546 | non-negotiable | true | 10 |
| R01032 | D-6 Engine queue + scheduler implementation matches charter | SDD-008 D-6 | F00547 | non-negotiable | false | 10 |
| R01033 | D-7 Orchestrator fan-out + failover + escalation implementation matches charter | SDD-008 D-7 | F00548 | non-negotiable | false | 10 |
| R01034 | D-8 Wall adapter implements MS004 Wall integration end-to-end | SDD-008 D-8 + MS004 E0044 | F00549 | non-negotiable | true | 10 |
| R01035 | D-024 Write(1) adapter implements MS004 Write integration end-to-end (PR #170) | SDD-008 D-024 + MS004 E0045 | F00550 | non-negotiable | true | 10 |
| R01036 | CLI `selfdefctl notify list` lists all 14 integrations + engine queue depth + orchestrator state | `crates/selfdef-cli` | F00551 | non-negotiable | true | 10 |
| R01037 | CLI `selfdefctl notify test <channel>` sends synthetic test envelope | `crates/selfdef-cli` | F00552 | non-negotiable | true | 10 |
| R01038 | CLI `selfdefctl notify deliveries [--channel <name>]` lists recent deliveries | `crates/selfdef-cli` | F00553 | non-negotiable | true | 10 |
| R01039 | CLI `selfdefctl notify resend --receipt-id <id>` re-dispatches previously-delivered envelope (PR #173) | `crates/selfdef-cli` | F00554 | non-negotiable | true | 10 |
| R01040 | API `POST /v1/notifier/test/<channel>` operator-triggered test | `crates/selfdef-api` | F00555 | non-negotiable | true | 10 |
| R01041 | API `POST /v1/notifier/resend` operator-triggered resend | `crates/selfdef-api` | F00556 | non-negotiable | true | 10 |
| R01042 | API `GET /v1/notifier/queue` engine queue depth + per-channel breakdown | `crates/selfdef-api` | F00557 | non-negotiable | true | 10 |
| R01043 | API `GET /v1/notifier/rules` lists active routing rules + last reload time | `crates/selfdef-api` | F00558 | non-negotiable | true | 10 |
| R01044 | API `POST /v1/notifier/rules/reload` hot-reloads rules without daemon restart | `crates/selfdef-api` | F00559 | non-negotiable | true | 10 |
| R01045 | Routing-rule example — `severity=critical AND urgency=immediate → [pagerduty, twilio, signal]` | `docs/sdd/008-notifications-orchestration.md` | F00560 | non-negotiable | true | 10 |
| R01046 | Routing-rule example — `severity=warn AND urgency=batched → [slack, discord, smtp]` | `docs/sdd/008-notifications-orchestration.md` | F00561 | non-negotiable | true | 10 |
| R01047 | Routing-rule example — `severity=info AND source=canary → [shared-audit-summary, loki]` | `docs/sdd/008-notifications-orchestration.md` | F00562 | non-negotiable | true | 10 |
| R01048 | Routing-rule example — `urgency=digest → [smtp]` | `docs/sdd/008-notifications-orchestration.md` | F00563 | non-negotiable | true | 10 |
| R01049 | Routing-rule example — `source=tetragon AND severity≥error → [wall, ntfy]` | `docs/sdd/008-notifications-orchestration.md` | F00564 | non-negotiable | true | 10 |
| R01050 | Dashboard surface — engine queue depth + per-channel breakdown | `dashboard/` | F00565 | non-negotiable | true | 10 |
| R01051 | Dashboard surface — orchestrator routing-rule fire-counts | `dashboard/` | F00566 | non-negotiable | true | 10 |
| R01052 | Dashboard surface — fan-out parallelism per envelope | `dashboard/` | F00567 | non-negotiable | true | 10 |
| R01053 | Dashboard surface — failover transitions per channel | `dashboard/` | F00568 | non-negotiable | true | 10 |
| R01054 | Dashboard surface — escalation chain visualization | `dashboard/` | F00569 | non-negotiable | true | 10 |
| R01055 | Dashboard surface — durability inspector (in-flight envelopes survived restart) | `dashboard/` | F00570 | non-negotiable | true | 10 |
| R01056 | Dashboard surface — F-2031-NNN findings ledger status | `dashboard/` | F00571 | non-negotiable | true | 10 |
| R01057 | Metric `selfdef_notifier_envelopes_processed_total{channel,severity,outcome}` | `crates/selfdef-notifier-engine` | F00572 | non-negotiable | true | 10 |
| R01058 | Metric `selfdef_notifier_envelopes_pending` | `crates/selfdef-notifier-engine` | F00573 | non-negotiable | true | 10 |
| R01059 | Metric `selfdef_notifier_route_evaluation_us` | `crates/selfdef-notifier-orchestrator` | F00574 | non-negotiable | true | 10 |
| R01060 | Metric `selfdef_notifier_template_render_us{channel,severity}` | `crates/selfdef-notifier-engine` | F00575 | non-negotiable | true | 10 |
| R01061 | Metric `selfdef_notifier_durability_resumed_total` | `crates/selfdef-notifier-orchestrator` | F00576 | non-negotiable | true | 10 |
| R01062 | Test — engine queue overflow drops with operator-readable warning | tests/ | F00577 | non-negotiable | false | 10 |
| R01063 | Test — engine template render fails with operator-readable error on missing var | tests/ | F00578 | non-negotiable | false | 10 |
| R01064 | Test — engine dedup suppresses second envelope with same key within window | tests/ | F00579 | non-negotiable | false | 10 |
| R01065 | Test — engine retry honors max_retries + exponential backoff + jitter + Retry-After | tests/ | F00580 | non-negotiable | false | 10 |
| R01066 | Test — engine rate-limit caps per-second / per-minute / per-hour | tests/ | F00581 | non-negotiable | false | 10 |
| R01067 | Test — engine digest hourly roll-up aggregates correctly | tests/ | F00582 | non-negotiable | false | 10 |
| R01068 | Test — engine silence window suppresses non-critical during quiet hours | tests/ | F00583 | non-negotiable | false | 10 |
| R01069 | Test — orchestrator routing rule fires correct channel set for synthetic envelope | tests/ | F00584 | non-negotiable | false | 10 |
| R01070 | Test — orchestrator routing rule hot-reload swaps atomically | tests/ | F00585 | non-negotiable | false | 10 |
| R01071 | Test — orchestrator fan-out dispatches to N integrations in parallel | tests/ | F00586 | non-negotiable | false | 10 |
| R01072 | Test — orchestrator failover routes to backup when primary fails 3x | tests/ | F00587 | non-negotiable | false | 10 |
| R01073 | Test — orchestrator escalation bumps severity after N occurrences | tests/ | F00588 | non-negotiable | false | 10 |
| R01074 | Test — orchestrator durability resumes un-acked envelopes after daemon restart | tests/ | F00589 | non-negotiable | false | 10 |
| R01075 | Test — orchestrator shutdown drain blocks SIGTERM until queue empty or deadline | tests/ | F00590 | non-negotiable | false | 10 |
| R01076 | Test — D-4 HTTP ack receiver acknowledges delivery within 30s | tests/ | F00591 | non-negotiable | false | 10 |
| R01077 | Test — D-5e third-party adapter loads via stable trait | tests/ | F00592 | non-negotiable | false | 10 |
| R01078 | Test — D-8 wall adapter end-to-end on real TTY (Debian 13 VM) | tests/ | F00593 | non-negotiable | false | 10 |
| R01079 | Test — D-024 write(1) adapter end-to-end on real TTY user (Debian 13 VM) | tests/ | F00594 | non-negotiable | false | 10 |
| R01080 | Test — `selfdefctl notify resend` re-dispatches with operator-readable preview | tests/ | F00595 | non-negotiable | false | 10 |
| R01081 | UX — operator-discoverable next-step when route rule matches zero channels | `crates/selfdef-cli` | F00596 | non-negotiable | true | 10 |
| R01082 | UX — operator-readable hot-reload diff (rules added / removed / changed) | `crates/selfdef-cli` | F00597 | non-negotiable | true | 10 |
| R01083 | UX — dashboard surfaces routing-rule fire-rate as live tile | `dashboard/` | F00598 | non-negotiable | true | 10 |
| R01084 | UX — dashboard surfaces orchestrator drain progress during SIGTERM | `dashboard/` | F00599 | non-negotiable | true | 10 |
| R01085 | Notifier engine integrates with `selfdef-bus` (consumes events that trigger NotifyEnvelopes) | `crates/selfdef-bus` | E0046 | non-negotiable | false | 10 |
| R01086 | Notifier engine integrates with `selfdef-correlator` (consumes Verdicts that trigger NotifyEnvelopes) | `crates/selfdef-correlator` | E0046 | non-negotiable | false | 10 |
| R01087 | Notifier engine integrates with `selfdef-responder` (Action `notify` lands here) | `crates/selfdef-responder` | E0046 | non-negotiable | false | 10 |
| R01088 | Notifier orchestrator integrates with `selfdef-store` (DeliveryReceipt persistence) | `crates/selfdef-store` | E0047 | non-negotiable | false | 10 |
| R01089 | Notifier orchestrator integrates with all 14 channel adapters from MS004 | `crates/selfdef-integration-*` | E0047 | non-negotiable | false | 10 |
| R01090 | Notifier engine integrates with SDD-005 L1–L5 layered test harness | SDD-005 | E0046 | non-negotiable | false | 10 |
| R01091 | Notifier engine integrates with SDD-006 shared module-script lib | SDD-006 | E0046 | non-negotiable | false | 10 |
| R01092 | Notifier engine integrates with SDD-016 oracle-triage channel | SDD-016 | E0046 | non-negotiable | false | 10 |
| R01093 | Notifier orchestrator integrates with SDD-014 shared audit summary channel | SDD-014 | E0047 | non-negotiable | false | 10 |
| R01094 | Notifier orchestrator integrates with SDD-029 round-ledger doctrine | SDD-029 | E0047 | non-negotiable | false | 10 |
| R01095 | Project boundary — notifier engine + orchestrator are selfdef-scope (IPS); sovereign-os runtime has its own observability stack (M013) | this milestone | E0047 | non-negotiable | false | 10 |
| R01096 | Project boundary — notifier orchestrator NEVER imports sovereign-os crate code (cross-repo only via SDD-038 typed-mirror crates) | architecture | E0047 | non-negotiable | false | 10 |
| R01097 | Project boundary — only the Oracle-Triage channel (MS004 E0036) crosses to sovereign-os; orchestrator treats it as just another channel | architecture | E0047 | non-negotiable | false | 10 |
| R01098 | Notifier engine emits journald-recognizable structured logs | `crates/selfdef-notifier-engine` | E0046 | non-negotiable | false | 10 |
| R01099 | Notifier orchestrator emits journald-recognizable structured logs | `crates/selfdef-notifier-orchestrator` | E0047 | non-negotiable | false | 10 |
| R01100 | Notifier engine emits OpenTelemetry traces per envelope-lifecycle | `crates/selfdef-notifier-engine` | E0046 | preferable | true | 10 |
| R01101 | Notifier orchestrator emits OpenTelemetry traces per route-decision | `crates/selfdef-notifier-orchestrator` | E0047 | preferable | true | 10 |
| R01102 | Engine queue is bounded MPMC (not unbounded — prevents memory exhaustion) | `crates/selfdef-notifier-engine` | M00107 | non-negotiable | false | 10 |
| R01103 | Engine template caches rendered output for identical (channel, severity, body) tuples | `crates/selfdef-notifier-engine` | M00108 | preferable | true | 10 |
| R01104 | Engine retry adds positive jitter (not symmetric — prevents synchronized retry stampedes) | `crates/selfdef-notifier-engine` | M00110 | non-negotiable | false | 10 |
| R01105 | Engine rate-limit per-channel is independent (one channel rate-limited does NOT impact others) | `crates/selfdef-notifier-engine` | M00111 | non-negotiable | false | 10 |
| R01106 | Engine digest accumulates without losing individual envelopes (digest is summary; originals still in store) | `crates/selfdef-notifier-engine` | M00112 | non-negotiable | false | 10 |
| R01107 | Engine silence window does NOT silently drop — silenced envelopes queue for post-silence digest | `crates/selfdef-notifier-engine` | M00113 | non-negotiable | true | 10 |
| R01108 | Orchestrator routing-rule DSL supports per-rule `priority` field (higher priority wins on conflict) | `crates/selfdef-notifier-orchestrator` | M00114 | non-negotiable | true | 10 |
| R01109 | Orchestrator routing-rule DSL supports `disabled = bool` per rule (without removing the rule) | `crates/selfdef-notifier-orchestrator` | M00114 | non-negotiable | true | 10 |
| R01110 | Orchestrator routing-rule DSL supports per-rule `cooldown_s` (prevents same-rule firing within window) | `crates/selfdef-notifier-orchestrator` | M00114 | non-negotiable | true | 10 |
| R01111 | Orchestrator fan-out collects DeliveryReceipts asynchronously (does not block dispatcher) | `crates/selfdef-notifier-orchestrator` | M00115 | non-negotiable | false | 10 |
| R01112 | Orchestrator failover order operator-supplied per channel (NOT alphabetical) | `crates/selfdef-config` | M00116 | non-negotiable | true | 10 |
| R01113 | Orchestrator escalation NEVER auto-escalates `critical` (already at top) | `crates/selfdef-notifier-orchestrator` | M00117 | non-negotiable | false | 10 |
| R01114 | Orchestrator escalation cooldown operator-tunable (prevents oscillation) | `crates/selfdef-config` | M00117 | non-negotiable | true | 10 |
| R01115 | Orchestrator durability — un-acked envelopes capped at operator-tunable max-replay-window (prevents replay storms on long downtime) | `crates/selfdef-config` | M00118 | non-negotiable | true | 10 |
| R01116 | Orchestrator shutdown drain emits operator-readable summary at completion | `crates/selfdef-notifier-orchestrator` | M00119 | non-negotiable | true | 10 |
| R01117 | Orchestrator dispatcher worker-pool stalls when all channels are rate-limited (not busy-loops) | `crates/selfdef-notifier-orchestrator` | M00120 | non-negotiable | false | 10 |
| R01118 | D-4 HTTP ack — refuses unsigned ack when integration requires signing (per integration config) | `crates/selfdef-notifier-engine` | M00124 | preferable | true | 10 |
| R01119 | D-4 HTTP ack — supports HMAC-SHA256 ack signature per integration | `crates/selfdef-notifier-engine` | M00124 | preferable | true | 10 |
| R01120 | D-5e — adapter trait stability covered by `tests/lint/test_channel_trait_stability.py` | tests/lint | M00126 | non-negotiable | false | 10 |
| R01121 | D-5e — adapter discovery via `crates/selfdef-integration-*/Cargo.toml` `[package.metadata.selfdef.adapter]` block | architecture | M00126 | non-negotiable | true | 10 |
| R01122 | Notifier engine refuses to start with un-renderable required template (no silent fallback) | `crates/selfdef-notifier-engine` | M00108 | non-negotiable | false | 10 |
| R01123 | Notifier orchestrator refuses to start with un-parseable routing-rules.toml (no silent fallback) | `crates/selfdef-notifier-orchestrator` | M00114 | non-negotiable | false | 10 |
| R01124 | Notifier engine + orchestrator survive daemon restart with no loss of in-flight envelopes when durability=true | tests/ | M00118 | non-negotiable | false | 10 |
| R01125 | Notifier engine + orchestrator emit operator-readable startup log with active rules + active integrations + queue depth | `crates/selfdef-notifier-engine` + orchestrator | E0046 | non-negotiable | true | 10 |
| R01126 | Notifier engine + orchestrator emit operator-readable shutdown log with final stats (envelopes delivered / queued / dropped) | `crates/selfdef-notifier-engine` + orchestrator | M00119 | non-negotiable | true | 10 |
| R01127 | Notifier engine + orchestrator support `--dry-run` mode (probes templates + rules + adapters, emits no actual deliveries) | `crates/selfdef-cli` | E0046 | non-negotiable | true | 10 |
| R01128 | Notifier engine + orchestrator support `--diag` mode (verbose lifecycle output) | `crates/selfdef-cli` | E0046 | non-negotiable | true | 10 |
| R01129 | Notifier engine + orchestrator respect `RUST_LOG=selfdef_notifier=debug` filter | `crates/selfdef-notifier-engine` + orchestrator | E0046 | non-negotiable | true | 10 |
| R01130 | Notifier engine + orchestrator expose per-component health probe via `GET /v1/notifier/healthz` | `crates/selfdef-api` | E0046 | non-negotiable | true | 10 |
| R01131 | UX — `selfdefctl notify list` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00551 | preferable | true | 10 |
| R01132 | UX — `selfdefctl notify list` groups channels by enabled / disabled / errored / rate-limited / silenced | `crates/selfdef-cli` | F00551 | non-negotiable | true | 10 |
| R01133 | UX — `selfdefctl notify test <channel>` returns operator-readable success or actionable error in ≤ 5s | `crates/selfdef-cli` | F00552 | non-negotiable | true | 10 |
| R01134 | UX — `selfdefctl notify deliveries` shows most recent 50 with timestamp + status + dedup-suppressed flag + retry count | `crates/selfdef-cli` | F00553 | non-negotiable | true | 10 |
| R01135 | UX — `selfdefctl notify resend` requires `--apply` confirm flag + shows preview-then-prompt | `crates/selfdef-cli` | F00554 | non-negotiable | true | 10 |
| R01136 | UX — `selfdefctl --json` output available for every notify verb | `crates/selfdef-cli` | E0053 | non-negotiable | true | 10 |
| R01137 | UX — dashboard surfaces template-render-failure as red tile with operator-next-step | `dashboard/` | M00108 | non-negotiable | true | 10 |
| R01138 | UX — dashboard surfaces routing-rule-no-match as yellow tile with operator-next-step | `dashboard/` | F00515 | non-negotiable | true | 10 |
| R01139 | UX — dashboard surfaces failover-active as yellow tile with primary-channel + backup-channel + last-failover-time | `dashboard/` | M00116 | non-negotiable | true | 10 |
| R01140 | UX — dashboard surfaces escalation-active as red tile with from-severity + to-severity + count-within-window | `dashboard/` | M00117 | non-negotiable | true | 10 |
| R01141 | F-2031-NNN ledger — every Phase-6-audit finding has a tracked remediation status | `docs/review/phase-6/` | M00132 | non-negotiable | true | 10 |
| R01142 | F-2031-NNN ledger — closed findings reference PR + commit | `docs/review/phase-6/` | M00132 | non-negotiable | false | 10 |
| R01143 | F-2031-NNN ledger — open findings carry operator-discoverable next-step | `docs/review/phase-6/` | M00132 | non-negotiable | true | 10 |
| R01144 | Documentation — notifier engine + orchestrator at `docs/sdd/008-notifications-orchestration.md` | `docs/sdd/008-notifications-orchestration.md` | E0049 | non-negotiable | false | 10 |
| R01145 | Documentation — per-D status table maintained in SDD-008 | `docs/sdd/008-notifications-orchestration.md` | E0049 | non-negotiable | false | 10 |
| R01146 | Documentation — operator-facing notifier-routes.toml example at top-level docs/ | `docs/` | F00512 | non-negotiable | true | 10 |
| R01147 | Anti-pattern — Notifier engine NEVER auto-renders un-validated template (template validation precedes render) | `crates/selfdef-notifier-engine` | M00108 | non-negotiable | false | 10 |
| R01148 | Anti-pattern — Notifier orchestrator NEVER dispatches envelope when matching rule has `disabled=true` | `crates/selfdef-notifier-orchestrator` | R01109 | non-negotiable | false | 10 |
| R01149 | Anti-pattern — Notifier orchestrator NEVER auto-promotes severity above critical | `crates/selfdef-notifier-orchestrator` | R01113 | non-negotiable | false | 10 |
| R01150 | Anti-pattern — Notifier engine NEVER mutates DeliveryReceipt after status=delivered (append-only) | `crates/selfdef-notifier-engine` | M00118 | non-negotiable | false | 10 |
| R01151 | Anti-pattern — Notifier engine NEVER logs operator secrets in journal (secrets are masked) | `crates/selfdef-notifier-engine` | E0046 | non-negotiable | false | 10 |
| R01152 | Anti-pattern — Notifier orchestrator NEVER blocks dispatcher waiting for ack (ack received async) | `crates/selfdef-notifier-orchestrator` | R01111 | non-negotiable | false | 10 |
| R01153 | Anti-pattern — Notifier engine NEVER silently drops an envelope (every drop has operator-readable warning + metric) | `crates/selfdef-notifier-engine` | R00967 | non-negotiable | false | 10 |
| R01154 | Anti-pattern — Notifier orchestrator NEVER routes to a disabled integration (modules.toml gate honored) | `crates/selfdef-notifier-orchestrator` | M00114 | non-negotiable | false | 10 |
| R01155 | Default — engine queue capacity = 10000 envelopes | `crates/selfdef-config` | F00481 | non-negotiable | true | 10 |
| R01156 | Default — engine queue overflow = drop-with-warning | `crates/selfdef-config` | F00482 | non-negotiable | true | 10 |
| R01157 | Default — engine dedup window = 5m for severities ≤ warn | `crates/selfdef-config` | F00490 | non-negotiable | true | 10 |
| R01158 | Default — engine retry max_retries = 3 (matches MS004 R00820 baseline) | `crates/selfdef-config` | F00495 | non-negotiable | true | 10 |
| R01159 | Default — engine rate-limit per-second = 10 (matches MS004 R00926 baseline) | `crates/selfdef-config` | F00501 | non-negotiable | true | 10 |
| R01160 | Default — engine silence window disabled on fresh install (operator opts in) | `crates/selfdef-config` | F00509 | non-negotiable | true | 10 |
| R01161 | Default — orchestrator fan-out parallelism = 4 per channel | `crates/selfdef-config` | F00519 | non-negotiable | true | 10 |
| R01162 | Default — orchestrator failover threshold = 3 consecutive failures | `crates/selfdef-config` | F00522 | non-negotiable | true | 10 |
| R01163 | Default — orchestrator escalation warn→error threshold = 5 within 10m | `crates/selfdef-config` | F00525 | non-negotiable | true | 10 |
| R01164 | Default — orchestrator escalation error→critical threshold = 3 within 5m | `crates/selfdef-config` | F00526 | non-negotiable | true | 10 |
| R01165 | Default — orchestrator drain timeout = 30s | `crates/selfdef-config` | F00532 | non-negotiable | true | 10 |
| R01166 | Default — orchestrator dispatcher worker-pool size = 8 | `crates/selfdef-config` | F00534 | non-negotiable | true | 10 |
| R01167 | Default — D-4 HTTP ack TLS verification required | `crates/selfdef-config` | F00540 | non-negotiable | false | 10 |
| R01168 | Default — D-4 HTTP ack timeout = 30s | `crates/selfdef-config` | F00541 | non-negotiable | true | 10 |
| R01169 | Composite — Notifier engine + orchestrator implement SDD-008 D-1..D-8 + D-5e + D-4 HTTP ack + D-024 verbatim | SDD-008 + this milestone | E0046 | non-negotiable | false | 10 |
| R01170 | Composite — MS004's 14 channel adapters ARE the channel-adapter surface this milestone orchestrates | MS004 | E0047 | non-negotiable | false | 10 |
| R01171 | Composite — End-to-end IPS pipeline — collectors (MS002) → correlator (MS003) → responder (MS003) → notifier-engine + orchestrator (THIS) → 14 channel adapters (MS004) | this milestone | E0046 | non-negotiable | false | 10 |
| R01172 | Composite — Notifier engine + orchestrator are the canonical SDD-008 implementation; other SDDs (014, 016) integrate THROUGH this layer (not around it) | SDD-008 + SDD-014 + SDD-016 | E0046 | non-negotiable | false | 10 |
| R01173 | L1 lint — every notifier-engine + orchestrator public API has at least one assertion | tests/lint | E0046 | non-negotiable | false | 10 |
| R01174 | L1 lint — every Channel trait method has a per-implementation test | tests/lint | M00123 | non-negotiable | false | 10 |
| R01175 | L1 lint — every routing-rule example in SDD-008 round-trips through DSL parser | tests/lint | M00114 | non-negotiable | false | 10 |
| R01176 | L3 smoke — daemon starts with notifier engine + orchestrator + 14 integrations + 5 routing-rule examples loaded in ≤ 5s | tests/ | E0046 | non-negotiable | false | 10 |
| R01177 | L3 smoke — synthetic Verdict → routing-rule match → fan-out to 3 channels → dedup + retry + rate-limit honored → 3 DeliveryReceipts in ≤ 3s | tests/ | E0046 | non-negotiable | false | 10 |
| R01178 | L5 real-substrate — notifier engine + orchestrator + 14 integrations run on real Debian 13 VM with cycle-fire under load | tests/ | E0046 | non-negotiable | false | 10 |
| R01179 | Cross-repo binding — SDD-038 typed-mirror crate covers any new sovereign-os instrument that notifier orchestrator integrates with | SDD-038 | R01096 | non-negotiable | false | 10 |
| R01180 | Cross-repo binding — Oracle-Triage routes flow via typed-mirror crate (no direct sovereign-os crate import) | SDD-038 | R01097 | non-negotiable | false | 10 |
| R01181 | Operator config — `notifier-engine.toml` operator-discoverable via `selfdefctl notify config show` | `crates/selfdef-cli` | E0046 | non-negotiable | true | 10 |
| R01182 | Operator config — `notifier-routes.toml` operator-discoverable via `selfdefctl notify rules show` | `crates/selfdef-cli` | E0054 | non-negotiable | true | 10 |
| R01183 | Operator config — `notifier-templates/*.hbs` operator-discoverable via `selfdefctl notify templates list` | `crates/selfdef-cli` | E0046 | non-negotiable | true | 10 |
| R01184 | Operator config — every config file backed up to `/var/backup/selfdef/notifier-<timestamp>.tar.gz` before hot-reload | `crates/selfdef-config` | E0046 | preferable | true | 10 |
| R01185 | Operator UX — first-run wizard offers preset routing-rules (immediate-only / batched / digest) | `crates/selfdef-cli` | M00114 | preferable | true | 10 |
| R01186 | Operator UX — first-run wizard offers preset template sets (terse / verbose / forensic) | `crates/selfdef-cli` | M00108 | preferable | true | 10 |
| R01187 | Operator UX — first-run wizard validates connection to each enabled integration before proceeding | `crates/selfdef-cli` | E0047 | preferable | true | 10 |
| R01188 | Operator UX — `selfdefctl notify simulate <verdict-id>` previews routing decision without dispatch | `crates/selfdef-cli` | M00114 | non-negotiable | true | 10 |
| R01189 | Operator UX — `selfdefctl notify silence start --duration 4h --severity warn` operator-discoverable on-call silence | `crates/selfdef-cli` | M00113 | preferable | true | 10 |
| R01190 | Operator UX — `selfdefctl notify silence stop` ends active silence | `crates/selfdef-cli` | M00113 | preferable | true | 10 |
| R01191 | Operator UX — `selfdefctl notify silence status` lists active silences | `crates/selfdef-cli` | M00113 | preferable | true | 10 |
| R01192 | Operator UX — `selfdefctl notify silence preset --preset weekend` toggles weekend-silence preset | `crates/selfdef-cli` | M00113 | preferable | true | 10 |
| R01193 | Operator UX — every notifier verb supports `--json` for scripting | `crates/selfdef-cli` | E0053 | non-negotiable | true | 10 |
| R01194 | Operator UX — every notifier verb supports `--quiet` for silent operation | `crates/selfdef-cli` | E0053 | non-negotiable | true | 10 |
| R01195 | Operator UX — every notifier verb supports `--verbose` for diagnostic output | `crates/selfdef-cli` | E0053 | non-negotiable | true | 10 |
| R01196 | Composite — Notifier engine + orchestrator are the deterministic layer that converts Verdicts into operator-perceptible notifications across 14 channels | this milestone | E0046 | non-negotiable | false | 10 |
| R01197 | Composite — Notifier engine + orchestrator make the IPS pipeline operator-observable (the operator's "ears" of selfdef) | this milestone | E0046 | non-negotiable | false | 10 |
| R01198 | Composite — Notifier engine + orchestrator integrate with `selfdef-store` (MS003) for durability + with `selfdef-responder` (MS003) as the canonical Action `notify` target | MS003 | E0046 | non-negotiable | false | 10 |
| R01199 | Composite — Notifier engine + orchestrator integrate with collector fabric (MS002) ONLY transitively (Events → Verdicts → Notifications) | MS002 + MS003 | E0046 | non-negotiable | false | 10 |
| R01200 | Composite — End of SDD-008 implementation; finds-ledger F-2031-NNN tracks any remaining open findings | SDD-008 + F-2031-NNN | E0046 | non-negotiable | false | 10 |

— End of MS005 milestone file.
