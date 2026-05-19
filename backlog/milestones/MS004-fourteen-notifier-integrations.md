# MS004 — 14 notifier integrations — Discord / Loki / ntfy / OpenSearch / Oracle-Triage / PagerDuty / Shared-Audit-Summary / Signal / Slack / SMTP / TheHive / Twilio / Wall / Write

> Parent: `backlog/milestones/INDEX.md` row MS004.
> Source: existing repo crates `crates/selfdef-integration-{discord,loki,ntfy,opensearch,oracle-triage,pagerduty,shared-audit-summary,signal,slack,smtp,thehive,twilio,wall,write}` (14 crates, empirically verified via `ls crates/ | grep integration`) + SDD-008 notification orchestration + SDD-014 shared audit summary channel + SDD-016 oracle triage channel.

## Epics (E0031–E0045)

| Epic ID | Phrase | Source |
|---|---|---|
| E0031 | 14-notifier integration fabric — operator-selectable per-channel delivery | `crates/selfdef-integration-*` (14 crates) |
| E0032 | Discord integration — channel webhook delivery | `crates/selfdef-integration-discord` |
| E0033 | Loki integration — log aggregation push (operator's existing observability stack) | `crates/selfdef-integration-loki` |
| E0034 | ntfy integration — push notifications via ntfy.sh or self-hosted | `crates/selfdef-integration-ntfy` |
| E0035 | OpenSearch integration — SIEM index push (events / verdicts / actions) | `crates/selfdef-integration-opensearch` |
| E0036 | Oracle-triage integration — high-severity AI-routed triage channel | `crates/selfdef-integration-oracle-triage` + SDD-016 |
| E0037 | PagerDuty integration — on-call escalation | `crates/selfdef-integration-pagerduty` |
| E0038 | Shared-audit-summary integration — operator-stated cross-host audit summary channel | `crates/selfdef-integration-shared-audit-summary` + SDD-014 |
| E0039 | Signal integration — encrypted messenger via signal-cli | `crates/selfdef-integration-signal` |
| E0040 | Slack integration — channel webhook + Block Kit | `crates/selfdef-integration-slack` |
| E0041 | SMTP integration — email delivery via SMTP server | `crates/selfdef-integration-smtp` |
| E0042 | TheHive integration — SOAR case creation | `crates/selfdef-integration-thehive` |
| E0043 | Twilio integration — SMS + voice call escalation | `crates/selfdef-integration-twilio` |
| E0044 | Wall integration — `wall` broadcast to all TTY (local-host operator-on-machine notification) | `crates/selfdef-integration-wall` |
| E0045 | Write integration — `write` direct message to specific TTY user | `crates/selfdef-integration-write` |

## Modules (M00079–M00106)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00079 | Per-integration trait — `Notify::send(NotifyEnvelope) -> Result<DeliveryReceipt>` | every integration crate | E0031 |
| M00080 | NotifyEnvelope schema — severity / title / body / verdict_id / action_id / source / urgency / metadata | `crates/selfdef-core` + `crates/selfdef-notifier` | E0031 |
| M00081 | DeliveryReceipt schema — delivered_at / channel / status / channel_message_id / error_kind | `crates/selfdef-core` + `crates/selfdef-notifier` | E0031 |
| M00082 | Per-integration auth — operator-supplied secret (env var / file / vault); NEVER in repo | `crates/selfdef-config` | E0031 |
| M00083 | Discord webhook client — POST to channel webhook URL | `crates/selfdef-integration-discord` | E0032 |
| M00084 | Discord embed formatter — color-coded severity (red/yellow/green) + title + fields | `crates/selfdef-integration-discord` | E0032 |
| M00085 | Loki push client — `/loki/api/v1/push` with labels (host / severity / source / collector) | `crates/selfdef-integration-loki` | E0033 |
| M00086 | Loki streaming mode — batch push every N seconds | `crates/selfdef-integration-loki` | E0033 |
| M00087 | ntfy publish client — POST to `/<topic>` with priority + tags | `crates/selfdef-integration-ntfy` | E0034 |
| M00088 | ntfy self-host mode vs ntfy.sh-hosted toggle | `crates/selfdef-integration-ntfy` | E0034 |
| M00089 | OpenSearch index client — bulk POST `/<index>/_bulk` | `crates/selfdef-integration-opensearch` | E0035 |
| M00090 | OpenSearch index template — `selfdef-events-YYYY.MM.DD` rolling | `crates/selfdef-integration-opensearch` | E0035 |
| M00091 | Oracle-triage AI router — high-severity verdict → Blackwell oracle (sovereign-os) for triage summarization | `crates/selfdef-integration-oracle-triage` + SDD-016 | E0036 |
| M00092 | Oracle-triage cross-repo binding — selfdef calls sovereign-os runtime via typed-mirror crate per SDD-038 | `crates/selfdef-integration-oracle-triage` + SDD-038 | E0036 |
| M00093 | PagerDuty Events API v2 client — POST `/v2/enqueue` with routing key | `crates/selfdef-integration-pagerduty` | E0037 |
| M00094 | PagerDuty incident dedupe — `dedup_key` per verdict_id | `crates/selfdef-integration-pagerduty` | E0037 |
| M00095 | Shared-audit-summary writer — per-cycle audit summary aggregation across collectors + correlator + responder | `crates/selfdef-integration-shared-audit-summary` + SDD-014 | E0038 |
| M00096 | Signal client — `signal-cli send -m <body> +<recipient>` subprocess wrap | `crates/selfdef-integration-signal` | E0039 |
| M00097 | Slack webhook client — POST to channel webhook URL with Block Kit JSON | `crates/selfdef-integration-slack` | E0040 |
| M00098 | SMTP client — `lettre` crate; STARTTLS / TLS-on-connect; SMTP-AUTH | `crates/selfdef-integration-smtp` | E0041 |
| M00099 | TheHive API client — POST `/api/case` with case_template / TLP / severity | `crates/selfdef-integration-thehive` | E0042 |
| M00100 | Twilio SMS client — POST `Messages.json` REST API | `crates/selfdef-integration-twilio` | E0043 |
| M00101 | Twilio voice call client — POST `Calls.json` with TwiML URL | `crates/selfdef-integration-twilio` | E0043 |
| M00102 | Wall client — invoke `/usr/bin/wall` subprocess with message body | `crates/selfdef-integration-wall` | E0044 |
| M00103 | Write client — invoke `/usr/bin/write <user> <tty>` subprocess | `crates/selfdef-integration-write` | E0045 |
| M00104 | Per-integration template engine — operator-overrideable message templates (handlebars-style) | `crates/selfdef-notifier` | E0031 |
| M00105 | Per-integration retry policy — exponential backoff + max-retries + jitter | `crates/selfdef-notifier` | E0031 |
| M00106 | Per-integration rate-limit — operator-tunable max notifications per second / per minute / per hour | `crates/selfdef-config` | E0031 |

## Features (F00361–F00480)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00361 | Toggle integration — Discord | modules.toml | E0032 | mode | true |
| F00362 | Toggle integration — Loki | modules.toml | E0033 | mode | true |
| F00363 | Toggle integration — ntfy | modules.toml | E0034 | mode | true |
| F00364 | Toggle integration — OpenSearch | modules.toml | E0035 | mode | true |
| F00365 | Toggle integration — Oracle-Triage | modules.toml | E0036 | mode | true |
| F00366 | Toggle integration — PagerDuty | modules.toml | E0037 | mode | true |
| F00367 | Toggle integration — Shared-Audit-Summary | modules.toml | E0038 | mode | true |
| F00368 | Toggle integration — Signal | modules.toml | E0039 | mode | true |
| F00369 | Toggle integration — Slack | modules.toml | E0040 | mode | true |
| F00370 | Toggle integration — SMTP | modules.toml | E0041 | mode | true |
| F00371 | Toggle integration — TheHive | modules.toml | E0042 | mode | true |
| F00372 | Toggle integration — Twilio | modules.toml | E0043 | mode | true |
| F00373 | Toggle integration — Wall | modules.toml | E0044 | mode | true |
| F00374 | Toggle integration — Write | modules.toml | E0045 | mode | true |
| F00375 | Profile knob — `integrations.enabled = csv` | `crates/selfdef-config` | E0031 | profile | true |
| F00376 | Env var `SELFDEF_INTEGRATIONS_ENABLED` | `crates/selfdef-config` | E0031 | env_var | true |
| F00377 | CLI `--integrations <csv>` | `crates/selfdef-cli` | E0031 | cli_verb | true |
| F00378 | NotifyEnvelope field — `severity` (info / warn / error / critical) | `crates/selfdef-core` | M00080 | data_model | false |
| F00379 | NotifyEnvelope field — `title` | `crates/selfdef-core` | M00080 | data_model | false |
| F00380 | NotifyEnvelope field — `body` | `crates/selfdef-core` | M00080 | data_model | false |
| F00381 | NotifyEnvelope field — `verdict_id` | `crates/selfdef-core` | M00080 | data_model | false |
| F00382 | NotifyEnvelope field — `action_id` | `crates/selfdef-core` | M00080 | data_model | false |
| F00383 | NotifyEnvelope field — `source` (collector / correlator / responder / canary / module) | `crates/selfdef-core` | M00080 | data_model | false |
| F00384 | NotifyEnvelope field — `urgency` (immediate / batched / digest) | `crates/selfdef-core` | M00080 | data_model | false |
| F00385 | NotifyEnvelope field — `metadata` (free-form key-value) | `crates/selfdef-core` | M00080 | data_model | true |
| F00386 | DeliveryReceipt field — `delivered_at` | `crates/selfdef-core` | M00081 | data_model | false |
| F00387 | DeliveryReceipt field — `channel` | `crates/selfdef-core` | M00081 | data_model | false |
| F00388 | DeliveryReceipt field — `status` (delivered / failed / rate_limited / dedup_suppressed) | `crates/selfdef-core` | M00081 | data_model | false |
| F00389 | DeliveryReceipt field — `channel_message_id` | `crates/selfdef-core` | M00081 | data_model | false |
| F00390 | DeliveryReceipt field — `error_kind` | `crates/selfdef-core` | M00081 | data_model | false |
| F00391 | Discord — webhook URL config (`integrations.discord.webhook_url`) | `crates/selfdef-config` | M00083 | profile | true |
| F00392 | Discord — env var `SELFDEF_DISCORD_WEBHOOK_URL` | `crates/selfdef-config` | M00083 | env_var | true |
| F00393 | Discord — embed color per severity | `crates/selfdef-integration-discord` | M00084 | composite | true |
| F00394 | Discord — embed fields (verdict_id / source / urgency / metadata) | `crates/selfdef-integration-discord` | M00084 | composite | true |
| F00395 | Loki — endpoint URL config (`integrations.loki.url`) | `crates/selfdef-config` | M00085 | profile | true |
| F00396 | Loki — env var `SELFDEF_LOKI_URL` | `crates/selfdef-config` | M00085 | env_var | true |
| F00397 | Loki — labels (host / severity / source / collector) | `crates/selfdef-integration-loki` | M00085 | composite | false |
| F00398 | Loki — batch push interval tunable (`integrations.loki.batch_interval_s`) | `crates/selfdef-config` | M00086 | profile | true |
| F00399 | ntfy — topic config (`integrations.ntfy.topic`) | `crates/selfdef-config` | M00087 | profile | true |
| F00400 | ntfy — env var `SELFDEF_NTFY_TOPIC` | `crates/selfdef-config` | M00087 | env_var | true |
| F00401 | ntfy — server URL config (`integrations.ntfy.server`, default `https://ntfy.sh`) | `crates/selfdef-config` | M00088 | profile | true |
| F00402 | ntfy — env var `SELFDEF_NTFY_SERVER` | `crates/selfdef-config` | M00088 | env_var | true |
| F00403 | ntfy — auth token config (`integrations.ntfy.token`) | `crates/selfdef-config` | M00087 | profile | true |
| F00404 | ntfy — priority mapping (info=2 / warn=3 / error=4 / critical=5) | `crates/selfdef-integration-ntfy` | M00087 | composite | true |
| F00405 | OpenSearch — endpoint URL config (`integrations.opensearch.url`) | `crates/selfdef-config` | M00089 | profile | true |
| F00406 | OpenSearch — env var `SELFDEF_OPENSEARCH_URL` | `crates/selfdef-config` | M00089 | env_var | true |
| F00407 | OpenSearch — username + password config (`integrations.opensearch.{user,pass}`) | `crates/selfdef-config` | M00089 | profile | true |
| F00408 | OpenSearch — env var `SELFDEF_OPENSEARCH_USER` + `SELFDEF_OPENSEARCH_PASS` | `crates/selfdef-config` | M00089 | env_var | true |
| F00409 | OpenSearch — index template `selfdef-events-YYYY.MM.DD` | `crates/selfdef-integration-opensearch` | M00090 | composite | false |
| F00410 | OpenSearch — TLS verify toggle (`integrations.opensearch.tls_verify`) | `crates/selfdef-config` | M00089 | profile | true |
| F00411 | Oracle-Triage — sovereign-os gateway URL config (`integrations.oracle_triage.gateway_url`) | `crates/selfdef-config` | M00091 | profile | true |
| F00412 | Oracle-Triage — env var `SELFDEF_ORACLE_TRIAGE_GATEWAY_URL` | `crates/selfdef-config` | M00091 | env_var | true |
| F00413 | Oracle-Triage — severity threshold for routing (`integrations.oracle_triage.min_severity`) | `crates/selfdef-config` | M00091 | profile | true |
| F00414 | Oracle-Triage — cross-repo binding typed-mirror crate enforces SDD-038 invariant | `crates/selfdef-integration-oracle-triage` | M00092 | composite | false |
| F00415 | PagerDuty — routing key config (`integrations.pagerduty.routing_key`) | `crates/selfdef-config` | M00093 | profile | true |
| F00416 | PagerDuty — env var `SELFDEF_PAGERDUTY_ROUTING_KEY` | `crates/selfdef-config` | M00093 | env_var | true |
| F00417 | PagerDuty — dedup_key per verdict_id (incident dedupe) | `crates/selfdef-integration-pagerduty` | M00094 | composite | false |
| F00418 | PagerDuty — event_action mapping (trigger / acknowledge / resolve) | `crates/selfdef-integration-pagerduty` | M00093 | composite | true |
| F00419 | Shared-Audit-Summary — output path config (`integrations.shared_audit_summary.path`) | `crates/selfdef-config` | M00095 | profile | true |
| F00420 | Shared-Audit-Summary — cycle interval tunable (`integrations.shared_audit_summary.cycle_s`) | `crates/selfdef-config` | M00095 | profile | true |
| F00421 | Shared-Audit-Summary — aggregation source — collectors | `crates/selfdef-integration-shared-audit-summary` | M00095 | composite | false |
| F00422 | Shared-Audit-Summary — aggregation source — correlator | `crates/selfdef-integration-shared-audit-summary` | M00095 | composite | false |
| F00423 | Shared-Audit-Summary — aggregation source — responder | `crates/selfdef-integration-shared-audit-summary` | M00095 | composite | false |
| F00424 | Signal — recipient list config (`integrations.signal.recipients = csv`) | `crates/selfdef-config` | M00096 | profile | true |
| F00425 | Signal — env var `SELFDEF_SIGNAL_RECIPIENTS` | `crates/selfdef-config` | M00096 | env_var | true |
| F00426 | Signal — signal-cli binary path config (`integrations.signal.cli_path`) | `crates/selfdef-config` | M00096 | profile | true |
| F00427 | Slack — webhook URL config (`integrations.slack.webhook_url`) | `crates/selfdef-config` | M00097 | profile | true |
| F00428 | Slack — env var `SELFDEF_SLACK_WEBHOOK_URL` | `crates/selfdef-config` | M00097 | env_var | true |
| F00429 | Slack — Block Kit JSON template per severity | `crates/selfdef-integration-slack` | M00097 | composite | true |
| F00430 | SMTP — server host config (`integrations.smtp.host`) | `crates/selfdef-config` | M00098 | profile | true |
| F00431 | SMTP — server port config (`integrations.smtp.port`) | `crates/selfdef-config` | M00098 | profile | true |
| F00432 | SMTP — username + password config (`integrations.smtp.{user,pass}`) | `crates/selfdef-config` | M00098 | profile | true |
| F00433 | SMTP — env var `SELFDEF_SMTP_{HOST,PORT,USER,PASS}` | `crates/selfdef-config` | M00098 | env_var | true |
| F00434 | SMTP — STARTTLS toggle | `crates/selfdef-integration-smtp` | M00098 | mode | true |
| F00435 | SMTP — TLS-on-connect toggle | `crates/selfdef-integration-smtp` | M00098 | mode | true |
| F00436 | SMTP — from address config (`integrations.smtp.from`) | `crates/selfdef-config` | M00098 | profile | true |
| F00437 | SMTP — to addresses config (`integrations.smtp.to = csv`) | `crates/selfdef-config` | M00098 | profile | true |
| F00438 | TheHive — endpoint URL config (`integrations.thehive.url`) | `crates/selfdef-config` | M00099 | profile | true |
| F00439 | TheHive — API token config (`integrations.thehive.token`) | `crates/selfdef-config` | M00099 | profile | true |
| F00440 | TheHive — env var `SELFDEF_THEHIVE_{URL,TOKEN}` | `crates/selfdef-config` | M00099 | env_var | true |
| F00441 | TheHive — case template config (`integrations.thehive.case_template`) | `crates/selfdef-config` | M00099 | profile | true |
| F00442 | TheHive — TLP mapping (info=WHITE / warn=GREEN / error=AMBER / critical=RED) | `crates/selfdef-integration-thehive` | M00099 | composite | true |
| F00443 | Twilio — account SID config (`integrations.twilio.account_sid`) | `crates/selfdef-config` | M00100 | profile | true |
| F00444 | Twilio — auth token config (`integrations.twilio.auth_token`) | `crates/selfdef-config` | M00100 | profile | true |
| F00445 | Twilio — env var `SELFDEF_TWILIO_{ACCOUNT_SID,AUTH_TOKEN}` | `crates/selfdef-config` | M00100 | env_var | true |
| F00446 | Twilio — from phone number config (`integrations.twilio.from`) | `crates/selfdef-config` | M00100 | profile | true |
| F00447 | Twilio — to phone numbers config (`integrations.twilio.to = csv`) | `crates/selfdef-config` | M00100 | profile | true |
| F00448 | Twilio — voice TwiML URL config (`integrations.twilio.voice_twiml_url`) | `crates/selfdef-config` | M00101 | profile | true |
| F00449 | Twilio — SMS-vs-voice mode per severity (`integrations.twilio.mode_map`) | `crates/selfdef-config` | M00100 | profile | true |
| F00450 | Wall — TTY allow-list (which TTYs receive wall, default all) | `crates/selfdef-config` | M00102 | profile | true |
| F00451 | Write — target user config (`integrations.write.user`) | `crates/selfdef-config` | M00103 | profile | true |
| F00452 | Write — target tty config (`integrations.write.tty`) | `crates/selfdef-config` | M00103 | profile | true |
| F00453 | Per-integration template — operator-overrideable handlebars-style template per severity | `crates/selfdef-notifier` | M00104 | profile | true |
| F00454 | Per-integration retry — max_retries (default 3) | `crates/selfdef-notifier` | M00105 | profile | true |
| F00455 | Per-integration retry — backoff_base_ms (default 500) | `crates/selfdef-notifier` | M00105 | profile | true |
| F00456 | Per-integration retry — backoff_max_ms (default 60000) | `crates/selfdef-notifier` | M00105 | profile | true |
| F00457 | Per-integration retry — jitter (default 25%) | `crates/selfdef-notifier` | M00105 | profile | true |
| F00458 | Per-integration rate-limit — per-second cap | `crates/selfdef-config` | M00106 | profile | true |
| F00459 | Per-integration rate-limit — per-minute cap | `crates/selfdef-config` | M00106 | profile | true |
| F00460 | Per-integration rate-limit — per-hour cap | `crates/selfdef-config` | M00106 | profile | true |
| F00461 | Dashboard — per-integration delivery rate + success/failure ratio | `dashboard/` | E0031 | dashboard | true |
| F00462 | Dashboard — per-integration last-N deliveries log (with operator-readable error on failure) | `dashboard/` | E0031 | dashboard | true |
| F00463 | Dashboard — Oracle-Triage routing decisions (which verdicts routed to sovereign-os) | `dashboard/` | E0036 | dashboard | true |
| F00464 | Dashboard — Shared-Audit-Summary latest cycle preview | `dashboard/` | E0038 | dashboard | true |
| F00465 | API `GET /v1/integrations` (lists all 14 with state + last delivery) | `crates/selfdef-api` | E0031 | api_endpoint | true |
| F00466 | API `POST /v1/integrations/{name}/test` (operator-triggered test notification) | `crates/selfdef-api` | E0031 | api_endpoint | true |
| F00467 | API `GET /v1/integrations/{name}/deliveries` (paginated delivery history) | `crates/selfdef-api` | E0031 | api_endpoint | true |
| F00468 | CLI `selfdefctl notify list` (lists all 14 integrations + state) | `crates/selfdef-cli` | E0031 | cli_verb | true |
| F00469 | CLI `selfdefctl notify test <name>` (send a synthetic test) | `crates/selfdef-cli` | E0031 | cli_verb | true |
| F00470 | CLI `selfdefctl notify deliveries <name>` (recent delivery history) | `crates/selfdef-cli` | E0031 | cli_verb | true |
| F00471 | Metric `selfdef_notifier_delivery_total{channel,status,severity}` | `crates/selfdef-notifier` | E0031 | observability_metric | true |
| F00472 | Metric `selfdef_notifier_delivery_latency_seconds{channel,severity}` | `crates/selfdef-notifier` | E0031 | observability_metric | true |
| F00473 | Metric `selfdef_notifier_rate_limited_total{channel,window}` | `crates/selfdef-notifier` | E0031 | observability_metric | true |
| F00474 | Metric `selfdef_notifier_retries_total{channel}` | `crates/selfdef-notifier` | E0031 | observability_metric | true |
| F00475 | Test — each of 14 integrations dispatches a synthetic NotifyEnvelope without panic | tests/ | E0031 | test | false |
| F00476 | Test — each of 14 integrations honors enabled/disabled toggle from modules.toml | tests/ | F00375 | test | false |
| F00477 | Test — each of 14 integrations rejects request when credentials absent (no silent failure) | tests/ | M00082 | test | false |
| F00478 | Test — each of 14 integrations respects rate-limit cap | tests/ | M00106 | test | false |
| F00479 | Test — Oracle-Triage cross-repo binding refuses route when sovereign-os gateway unreachable + emits operator-actionable error | tests/ | M00092 | test | false |
| F00480 | Test — Shared-Audit-Summary aggregates across all 3 sources (collectors / correlator / responder) without dropping events | tests/ | M00095 | test | false |

## Requirements (R00721–R00960)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R00721 | Notifier integration fabric has exactly 14 channels (Discord / Loki / ntfy / OpenSearch / Oracle-Triage / PagerDuty / Shared-Audit-Summary / Signal / Slack / SMTP / TheHive / Twilio / Wall / Write) | repo `crates/selfdef-integration-*` | E0031 | non-negotiable | false | 10 |
| R00722 | Each integration lives in its own `crates/selfdef-integration-<name>` Rust crate | repo | E0031 | non-negotiable | false | 10 |
| R00723 | Each integration implements `Notify::send(NotifyEnvelope) -> Result<DeliveryReceipt>` trait | every integration crate | M00079 | non-negotiable | false | 10 |
| R00724 | Each integration is operator-toggleable via `modules.toml` | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00725 | Each integration honors operator-supplied auth secret (env var / file / vault); NEVER reads keys from repo | `crates/selfdef-config` | M00082 | non-negotiable | false | 10 |
| R00726 | Each integration emits `selfdef_notifier_delivery_total{channel,status,severity}` Prometheus metric | every integration crate | F00471 | non-negotiable | true | 10 |
| R00727 | Each integration emits `selfdef_notifier_delivery_latency_seconds{channel,severity}` Prometheus metric | every integration crate | F00472 | non-negotiable | true | 10 |
| R00728 | NotifyEnvelope carries `severity` field (info / warn / error / critical) | `crates/selfdef-core` | F00378 | non-negotiable | false | 10 |
| R00729 | NotifyEnvelope carries `title` field | `crates/selfdef-core` | F00379 | non-negotiable | false | 10 |
| R00730 | NotifyEnvelope carries `body` field | `crates/selfdef-core` | F00380 | non-negotiable | false | 10 |
| R00731 | NotifyEnvelope carries `verdict_id` field | `crates/selfdef-core` | F00381 | non-negotiable | false | 10 |
| R00732 | NotifyEnvelope carries `action_id` field | `crates/selfdef-core` | F00382 | non-negotiable | false | 10 |
| R00733 | NotifyEnvelope carries `source` field | `crates/selfdef-core` | F00383 | non-negotiable | false | 10 |
| R00734 | NotifyEnvelope carries `urgency` field (immediate / batched / digest) | `crates/selfdef-core` | F00384 | non-negotiable | false | 10 |
| R00735 | NotifyEnvelope carries `metadata` field (free-form key-value) | `crates/selfdef-core` | F00385 | non-negotiable | true | 10 |
| R00736 | DeliveryReceipt carries `delivered_at` field | `crates/selfdef-core` | F00386 | non-negotiable | false | 10 |
| R00737 | DeliveryReceipt carries `channel` field | `crates/selfdef-core` | F00387 | non-negotiable | false | 10 |
| R00738 | DeliveryReceipt carries `status` field (delivered / failed / rate_limited / dedup_suppressed) | `crates/selfdef-core` | F00388 | non-negotiable | false | 10 |
| R00739 | DeliveryReceipt carries `channel_message_id` field | `crates/selfdef-core` | F00389 | non-negotiable | false | 10 |
| R00740 | DeliveryReceipt carries `error_kind` field | `crates/selfdef-core` | F00390 | non-negotiable | false | 10 |
| R00741 | Discord integration delivers via channel webhook URL | `crates/selfdef-integration-discord` | M00083 | non-negotiable | true | 10 |
| R00742 | Discord webhook URL operator-supplied via `integrations.discord.webhook_url` | `crates/selfdef-config` | F00391 | non-negotiable | true | 10 |
| R00743 | Discord webhook URL operator-supplied via `SELFDEF_DISCORD_WEBHOOK_URL` env | `crates/selfdef-config` | F00392 | non-negotiable | true | 10 |
| R00744 | Discord embed color matches severity (red/yellow/green) | `crates/selfdef-integration-discord` | F00393 | non-negotiable | true | 10 |
| R00745 | Discord embed fields include verdict_id / source / urgency / metadata | `crates/selfdef-integration-discord` | F00394 | non-negotiable | true | 10 |
| R00746 | Loki integration delivers via `/loki/api/v1/push` HTTP endpoint | `crates/selfdef-integration-loki` | M00085 | non-negotiable | true | 10 |
| R00747 | Loki endpoint URL operator-supplied via `integrations.loki.url` | `crates/selfdef-config` | F00395 | non-negotiable | true | 10 |
| R00748 | Loki endpoint URL operator-supplied via `SELFDEF_LOKI_URL` env | `crates/selfdef-config` | F00396 | non-negotiable | true | 10 |
| R00749 | Loki labels include host / severity / source / collector | `crates/selfdef-integration-loki` | F00397 | non-negotiable | false | 10 |
| R00750 | Loki batch push interval operator-tunable via `integrations.loki.batch_interval_s` | `crates/selfdef-config` | F00398 | non-negotiable | true | 10 |
| R00751 | ntfy integration delivers via POST to `/<topic>` | `crates/selfdef-integration-ntfy` | M00087 | non-negotiable | true | 10 |
| R00752 | ntfy topic operator-supplied via `integrations.ntfy.topic` | `crates/selfdef-config` | F00399 | non-negotiable | true | 10 |
| R00753 | ntfy topic operator-supplied via `SELFDEF_NTFY_TOPIC` env | `crates/selfdef-config` | F00400 | non-negotiable | true | 10 |
| R00754 | ntfy server URL operator-overrideable (default `https://ntfy.sh`; supports self-hosted) | `crates/selfdef-config` | F00401 | non-negotiable | true | 10 |
| R00755 | ntfy server URL operator-overrideable via `SELFDEF_NTFY_SERVER` env | `crates/selfdef-config` | F00402 | non-negotiable | true | 10 |
| R00756 | ntfy auth token operator-supplied via `integrations.ntfy.token` | `crates/selfdef-config` | F00403 | non-negotiable | true | 10 |
| R00757 | ntfy priority maps from severity (info=2 / warn=3 / error=4 / critical=5) | `crates/selfdef-integration-ntfy` | F00404 | non-negotiable | true | 10 |
| R00758 | OpenSearch integration delivers via bulk POST `/<index>/_bulk` | `crates/selfdef-integration-opensearch` | M00089 | non-negotiable | true | 10 |
| R00759 | OpenSearch endpoint URL operator-supplied via `integrations.opensearch.url` | `crates/selfdef-config` | F00405 | non-negotiable | true | 10 |
| R00760 | OpenSearch endpoint URL operator-supplied via `SELFDEF_OPENSEARCH_URL` env | `crates/selfdef-config` | F00406 | non-negotiable | true | 10 |
| R00761 | OpenSearch credentials operator-supplied via `integrations.opensearch.{user,pass}` | `crates/selfdef-config` | F00407 | non-negotiable | true | 10 |
| R00762 | OpenSearch credentials operator-supplied via env vars | `crates/selfdef-config` | F00408 | non-negotiable | true | 10 |
| R00763 | OpenSearch index template — `selfdef-events-YYYY.MM.DD` rolling | `crates/selfdef-integration-opensearch` | F00409 | non-negotiable | false | 10 |
| R00764 | OpenSearch TLS verify operator-toggleable | `crates/selfdef-config` | F00410 | non-negotiable | true | 10 |
| R00765 | Oracle-Triage integration routes high-severity verdicts to sovereign-os Blackwell oracle | `crates/selfdef-integration-oracle-triage` | M00091 | non-negotiable | true | 10 |
| R00766 | Oracle-Triage gateway URL operator-supplied via `integrations.oracle_triage.gateway_url` | `crates/selfdef-config` | F00411 | non-negotiable | true | 10 |
| R00767 | Oracle-Triage gateway URL operator-supplied via `SELFDEF_ORACLE_TRIAGE_GATEWAY_URL` env | `crates/selfdef-config` | F00412 | non-negotiable | true | 10 |
| R00768 | Oracle-Triage severity threshold operator-tunable via `integrations.oracle_triage.min_severity` | `crates/selfdef-config` | F00413 | non-negotiable | true | 10 |
| R00769 | Oracle-Triage cross-repo binding enforces SDD-038 typed-mirror crate invariant | `crates/selfdef-integration-oracle-triage` | F00414 | non-negotiable | false | 10 |
| R00770 | Oracle-Triage governed by SDD-016 | SDD-016 | E0036 | non-negotiable | false | 10 |
| R00771 | PagerDuty integration delivers via Events API v2 (`/v2/enqueue`) | `crates/selfdef-integration-pagerduty` | M00093 | non-negotiable | true | 10 |
| R00772 | PagerDuty routing key operator-supplied via `integrations.pagerduty.routing_key` | `crates/selfdef-config` | F00415 | non-negotiable | true | 10 |
| R00773 | PagerDuty routing key operator-supplied via `SELFDEF_PAGERDUTY_ROUTING_KEY` env | `crates/selfdef-config` | F00416 | non-negotiable | true | 10 |
| R00774 | PagerDuty incident dedupe by `dedup_key=verdict_id` | `crates/selfdef-integration-pagerduty` | F00417 | non-negotiable | false | 10 |
| R00775 | PagerDuty event_action supports trigger / acknowledge / resolve | `crates/selfdef-integration-pagerduty` | F00418 | non-negotiable | true | 10 |
| R00776 | Shared-Audit-Summary integration emits per-cycle audit summary across collectors + correlator + responder | `crates/selfdef-integration-shared-audit-summary` | M00095 | non-negotiable | true | 10 |
| R00777 | Shared-Audit-Summary output path operator-supplied via `integrations.shared_audit_summary.path` | `crates/selfdef-config` | F00419 | non-negotiable | true | 10 |
| R00778 | Shared-Audit-Summary cycle interval operator-tunable via `integrations.shared_audit_summary.cycle_s` | `crates/selfdef-config` | F00420 | non-negotiable | true | 10 |
| R00779 | Shared-Audit-Summary aggregates collectors source | `crates/selfdef-integration-shared-audit-summary` | F00421 | non-negotiable | false | 10 |
| R00780 | Shared-Audit-Summary aggregates correlator source | `crates/selfdef-integration-shared-audit-summary` | F00422 | non-negotiable | false | 10 |
| R00781 | Shared-Audit-Summary aggregates responder source | `crates/selfdef-integration-shared-audit-summary` | F00423 | non-negotiable | false | 10 |
| R00782 | Shared-Audit-Summary governed by SDD-014 | SDD-014 | E0038 | non-negotiable | false | 10 |
| R00783 | Signal integration delivers via signal-cli subprocess | `crates/selfdef-integration-signal` | M00096 | non-negotiable | true | 10 |
| R00784 | Signal recipient list operator-supplied via `integrations.signal.recipients` | `crates/selfdef-config` | F00424 | non-negotiable | true | 10 |
| R00785 | Signal recipient list operator-supplied via `SELFDEF_SIGNAL_RECIPIENTS` env | `crates/selfdef-config` | F00425 | non-negotiable | true | 10 |
| R00786 | Signal signal-cli binary path operator-supplied via `integrations.signal.cli_path` | `crates/selfdef-config` | F00426 | non-negotiable | true | 10 |
| R00787 | Slack integration delivers via channel webhook URL with Block Kit JSON | `crates/selfdef-integration-slack` | M00097 | non-negotiable | true | 10 |
| R00788 | Slack webhook URL operator-supplied via `integrations.slack.webhook_url` | `crates/selfdef-config` | F00427 | non-negotiable | true | 10 |
| R00789 | Slack webhook URL operator-supplied via `SELFDEF_SLACK_WEBHOOK_URL` env | `crates/selfdef-config` | F00428 | non-negotiable | true | 10 |
| R00790 | Slack Block Kit template per severity | `crates/selfdef-integration-slack` | F00429 | non-negotiable | true | 10 |
| R00791 | SMTP integration delivers via `lettre` crate | `crates/selfdef-integration-smtp` | M00098 | non-negotiable | true | 10 |
| R00792 | SMTP server host operator-supplied via `integrations.smtp.host` | `crates/selfdef-config` | F00430 | non-negotiable | true | 10 |
| R00793 | SMTP server port operator-supplied via `integrations.smtp.port` | `crates/selfdef-config` | F00431 | non-negotiable | true | 10 |
| R00794 | SMTP credentials operator-supplied via `integrations.smtp.{user,pass}` | `crates/selfdef-config` | F00432 | non-negotiable | true | 10 |
| R00795 | SMTP credentials operator-supplied via env vars | `crates/selfdef-config` | F00433 | non-negotiable | true | 10 |
| R00796 | SMTP STARTTLS operator-toggleable | `crates/selfdef-integration-smtp` | F00434 | non-negotiable | true | 10 |
| R00797 | SMTP TLS-on-connect operator-toggleable | `crates/selfdef-integration-smtp` | F00435 | non-negotiable | true | 10 |
| R00798 | SMTP from address operator-supplied via `integrations.smtp.from` | `crates/selfdef-config` | F00436 | non-negotiable | true | 10 |
| R00799 | SMTP to addresses operator-supplied via `integrations.smtp.to = csv` | `crates/selfdef-config` | F00437 | non-negotiable | true | 10 |
| R00800 | TheHive integration delivers via POST `/api/case` | `crates/selfdef-integration-thehive` | M00099 | non-negotiable | true | 10 |
| R00801 | TheHive endpoint URL operator-supplied via `integrations.thehive.url` | `crates/selfdef-config` | F00438 | non-negotiable | true | 10 |
| R00802 | TheHive API token operator-supplied via `integrations.thehive.token` | `crates/selfdef-config` | F00439 | non-negotiable | true | 10 |
| R00803 | TheHive credentials operator-supplied via env vars | `crates/selfdef-config` | F00440 | non-negotiable | true | 10 |
| R00804 | TheHive case template operator-supplied via `integrations.thehive.case_template` | `crates/selfdef-config` | F00441 | non-negotiable | true | 10 |
| R00805 | TheHive TLP mapping (info=WHITE / warn=GREEN / error=AMBER / critical=RED) | `crates/selfdef-integration-thehive` | F00442 | non-negotiable | true | 10 |
| R00806 | Twilio SMS integration delivers via POST `Messages.json` | `crates/selfdef-integration-twilio` | M00100 | non-negotiable | true | 10 |
| R00807 | Twilio voice call delivers via POST `Calls.json` | `crates/selfdef-integration-twilio` | M00101 | non-negotiable | true | 10 |
| R00808 | Twilio credentials operator-supplied via `integrations.twilio.{account_sid,auth_token}` | `crates/selfdef-config` | F00443 | non-negotiable | true | 10 |
| R00809 | Twilio credentials operator-supplied via env vars | `crates/selfdef-config` | F00445 | non-negotiable | true | 10 |
| R00810 | Twilio from phone operator-supplied via `integrations.twilio.from` | `crates/selfdef-config` | F00446 | non-negotiable | true | 10 |
| R00811 | Twilio to phones operator-supplied via `integrations.twilio.to = csv` | `crates/selfdef-config` | F00447 | non-negotiable | true | 10 |
| R00812 | Twilio voice TwiML URL operator-supplied via `integrations.twilio.voice_twiml_url` | `crates/selfdef-config` | F00448 | non-negotiable | true | 10 |
| R00813 | Twilio SMS-vs-voice mode per severity operator-supplied via `integrations.twilio.mode_map` | `crates/selfdef-config` | F00449 | non-negotiable | true | 10 |
| R00814 | Wall integration delivers via `/usr/bin/wall` subprocess | `crates/selfdef-integration-wall` | M00102 | non-negotiable | true | 10 |
| R00815 | Wall TTY allow-list operator-supplied (default all TTYs) | `crates/selfdef-config` | F00450 | non-negotiable | true | 10 |
| R00816 | Write integration delivers via `/usr/bin/write` subprocess | `crates/selfdef-integration-write` | M00103 | non-negotiable | true | 10 |
| R00817 | Write target user operator-supplied via `integrations.write.user` | `crates/selfdef-config` | F00451 | non-negotiable | true | 10 |
| R00818 | Write target tty operator-supplied via `integrations.write.tty` | `crates/selfdef-config` | F00452 | non-negotiable | true | 10 |
| R00819 | Each integration template engine — operator-overrideable handlebars-style template per severity | `crates/selfdef-notifier` | F00453 | non-negotiable | true | 10 |
| R00820 | Each integration retry policy — operator-tunable max_retries (default 3) | `crates/selfdef-notifier` | F00454 | non-negotiable | true | 10 |
| R00821 | Each integration retry policy — operator-tunable backoff_base_ms (default 500) | `crates/selfdef-notifier` | F00455 | non-negotiable | true | 10 |
| R00822 | Each integration retry policy — operator-tunable backoff_max_ms (default 60000) | `crates/selfdef-notifier` | F00456 | non-negotiable | true | 10 |
| R00823 | Each integration retry policy — operator-tunable jitter (default 25%) | `crates/selfdef-notifier` | F00457 | non-negotiable | true | 10 |
| R00824 | Each integration rate-limit — operator-tunable per-second cap | `crates/selfdef-config` | F00458 | non-negotiable | true | 10 |
| R00825 | Each integration rate-limit — operator-tunable per-minute cap | `crates/selfdef-config` | F00459 | non-negotiable | true | 10 |
| R00826 | Each integration rate-limit — operator-tunable per-hour cap | `crates/selfdef-config` | F00460 | non-negotiable | true | 10 |
| R00827 | Each integration NEVER fails silently — error_kind is always populated on failure | `crates/selfdef-core` | F00390 | non-negotiable | false | 10 |
| R00828 | Each integration emits operator-readable startup log with channel/auth/template state | each integration crate | E0031 | non-negotiable | false | 10 |
| R00829 | Each integration survives daemon restart (delivery queue persisted) | `crates/selfdef-notifier` | E0031 | non-negotiable | false | 10 |
| R00830 | Each integration honors `selfdef-notifier-orchestrator` ordering (per SDD-008) | SDD-008 | E0031 | non-negotiable | false | 10 |
| R00831 | Each integration logs every delivery to Store `actions` table | `crates/selfdef-store` | E0031 | non-negotiable | false | 10 |
| R00832 | Each integration honors `urgency` field — immediate dispatches now; batched queues; digest waits for cycle | `crates/selfdef-notifier` | F00384 | non-negotiable | true | 10 |
| R00833 | Each integration honors `severity` filter — operator can drop info-level on a per-channel basis | `crates/selfdef-config` | F00378 | non-negotiable | true | 10 |
| R00834 | Each integration provides `selfdefctl notify test <name>` operator-facing test verb | `crates/selfdef-cli` | F00469 | non-negotiable | true | 10 |
| R00835 | API `GET /v1/integrations` lists all 14 integrations with state + last delivery | `crates/selfdef-api` | F00465 | non-negotiable | true | 10 |
| R00836 | API `POST /v1/integrations/{name}/test` operator-triggered test notification | `crates/selfdef-api` | F00466 | non-negotiable | true | 10 |
| R00837 | API `GET /v1/integrations/{name}/deliveries` paginated delivery history | `crates/selfdef-api` | F00467 | non-negotiable | true | 10 |
| R00838 | Dashboard surface — per-integration delivery rate + success/failure ratio | `dashboard/` | F00461 | non-negotiable | true | 10 |
| R00839 | Dashboard surface — per-integration last-N deliveries log | `dashboard/` | F00462 | non-negotiable | true | 10 |
| R00840 | Dashboard surface — Oracle-Triage routing decisions | `dashboard/` | F00463 | non-negotiable | true | 10 |
| R00841 | Dashboard surface — Shared-Audit-Summary latest cycle preview | `dashboard/` | F00464 | non-negotiable | true | 10 |
| R00842 | Metric — `selfdef_notifier_delivery_total{channel,status,severity}` | `crates/selfdef-notifier` | F00471 | non-negotiable | true | 10 |
| R00843 | Metric — `selfdef_notifier_delivery_latency_seconds{channel,severity}` | `crates/selfdef-notifier` | F00472 | non-negotiable | true | 10 |
| R00844 | Metric — `selfdef_notifier_rate_limited_total{channel,window}` | `crates/selfdef-notifier` | F00473 | non-negotiable | true | 10 |
| R00845 | Metric — `selfdef_notifier_retries_total{channel}` | `crates/selfdef-notifier` | F00474 | non-negotiable | true | 10 |
| R00846 | Operator can disable all 14 integrations and daemon remains healthy (no notifications dispatched) | `crates/selfdef-config` | F00375 | non-negotiable | false | 10 |
| R00847 | Operator can enable any subset of 14 integrations independently | `crates/selfdef-config` | F00375 | non-negotiable | true | 10 |
| R00848 | Operator can hot-reload integration config without daemon restart | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00849 | Integration fabric integrates with `selfdef-notifier-orchestrator` (per SDD-008) | `crates/selfdef-notifier-orchestrator` | E0031 | non-negotiable | false | 10 |
| R00850 | Integration fabric integrates with `selfdef-notifier-engine` (template + queue management) | `crates/selfdef-notifier-engine` | E0031 | non-negotiable | false | 10 |
| R00851 | Integration fabric integrates with `selfdef-responder` (Action `notify` routes here) | `crates/selfdef-responder` | E0031 | non-negotiable | false | 10 |
| R00852 | Integration fabric integrates with `selfdef-store` (delivery receipts persisted) | `crates/selfdef-store` | E0031 | non-negotiable | false | 10 |
| R00853 | Oracle-Triage integration is the ONLY integration that crosses to sovereign-os; all 13 others are pure selfdef-domain | `crates/selfdef-integration-oracle-triage` | M00091 | non-negotiable | false | 10 |
| R00854 | Project boundary — integrations.oracle_triage routes via typed-mirror crate per SDD-038 (no direct sovereign-os crate import) | SDD-038 | M00092 | non-negotiable | false | 10 |
| R00855 | Project boundary — sovereign-os runtime NEVER imports any selfdef-integration crate directly | architecture | E0031 | non-negotiable | false | 10 |
| R00856 | Project boundary — integrations are IPS / host-security scope (selfdef); sovereign-os has its own observability stack (OTel / DCGM / Prometheus per M013) | this milestone | E0031 | non-negotiable | false | 10 |
| R00857 | Test — each of 14 integrations dispatches a synthetic NotifyEnvelope without panic | tests/ | F00475 | non-negotiable | false | 10 |
| R00858 | Test — each of 14 integrations honors enabled/disabled toggle | tests/ | F00476 | non-negotiable | false | 10 |
| R00859 | Test — each of 14 integrations rejects when credentials absent (no silent failure) | tests/ | F00477 | non-negotiable | false | 10 |
| R00860 | Test — each of 14 integrations respects rate-limit cap | tests/ | F00478 | non-negotiable | false | 10 |
| R00861 | Test — Oracle-Triage refuses route when sovereign-os gateway unreachable + emits operator-actionable error | tests/ | F00479 | non-negotiable | false | 10 |
| R00862 | Test — Shared-Audit-Summary aggregates across 3 sources without dropping events | tests/ | F00480 | non-negotiable | false | 10 |
| R00863 | Test — NotifyEnvelope round-trips through JSON serde with all 8 fields | tests/ | M00080 | non-negotiable | false | 10 |
| R00864 | Test — DeliveryReceipt round-trips through JSON serde with all 5 fields | tests/ | M00081 | non-negotiable | false | 10 |
| R00865 | Test — Discord webhook integration delivers Test envelope to operator-configured URL | tests/ | M00083 | non-negotiable | false | 10 |
| R00866 | Test — Loki push integration emits payload matching `/loki/api/v1/push` schema | tests/ | M00085 | non-negotiable | false | 10 |
| R00867 | Test — ntfy publish integration sets priority header per severity | tests/ | M00087 | non-negotiable | false | 10 |
| R00868 | Test — OpenSearch bulk POST emits NDJSON with action-meta lines | tests/ | M00089 | non-negotiable | false | 10 |
| R00869 | Test — PagerDuty Events API v2 payload matches schema (routing_key + event_action + dedup_key + payload) | tests/ | M00093 | non-negotiable | false | 10 |
| R00870 | Test — Signal subprocess wraps signal-cli without shell-injection on operator-supplied recipients | tests/ | M00096 | non-negotiable | false | 10 |
| R00871 | Test — Slack Block Kit JSON validates against schema per severity | tests/ | M00097 | non-negotiable | false | 10 |
| R00872 | Test — SMTP STARTTLS handshake succeeds against test server | tests/ | F00434 | non-negotiable | false | 10 |
| R00873 | Test — SMTP TLS-on-connect handshake succeeds against test server | tests/ | F00435 | non-negotiable | false | 10 |
| R00874 | Test — TheHive case creation produces case with TLP mapped per severity | tests/ | F00442 | non-negotiable | false | 10 |
| R00875 | Test — Twilio SMS payload includes account_sid + from + to + body | tests/ | M00100 | non-negotiable | false | 10 |
| R00876 | Test — Twilio voice call payload includes voice TwiML URL | tests/ | M00101 | non-negotiable | false | 10 |
| R00877 | Test — Wall subprocess writes to all allowed TTYs only | tests/ | M00102 | non-negotiable | false | 10 |
| R00878 | Test — Write subprocess writes to single user/tty only | tests/ | M00103 | non-negotiable | false | 10 |
| R00879 | Test — per-integration template engine renders handlebars per severity | tests/ | M00104 | non-negotiable | false | 10 |
| R00880 | Test — per-integration retry policy honors max_retries + exponential backoff + jitter | tests/ | M00105 | non-negotiable | false | 10 |
| R00881 | Test — per-integration rate-limit caps deliveries at configured per-window thresholds | tests/ | M00106 | non-negotiable | false | 10 |
| R00882 | UX — `selfdefctl notify list` output ≤ 1 screen for 14 integrations on green case | `crates/selfdef-cli` | F00468 | preferable | true | 10 |
| R00883 | UX — `selfdefctl notify list` groups integrations by enabled / disabled / errored | `crates/selfdef-cli` | F00468 | non-negotiable | true | 10 |
| R00884 | UX — `selfdefctl notify test <name>` produces operator-readable success or actionable error in ≤ 5s | `crates/selfdef-cli` | F00469 | non-negotiable | true | 10 |
| R00885 | UX — `selfdefctl notify deliveries <name>` shows most recent 50 with timestamp + status + dedup-suppressed flag | `crates/selfdef-cli` | F00470 | non-negotiable | true | 10 |
| R00886 | UX — `selfdefctl --json` output available for every notify verb | `crates/selfdef-cli` | E0031 | non-negotiable | true | 10 |
| R00887 | UX — Dashboard surfaces integration credential-absent as red tile with operator-next-step ("set SELFDEF_<NAME>_<FIELD>") | `dashboard/` | M00082 | non-negotiable | true | 10 |
| R00888 | UX — Dashboard surfaces integration rate-limited state with operator-readable cap + window | `dashboard/` | F00473 | non-negotiable | true | 10 |
| R00889 | UX — Dashboard surfaces integration retry-loop with operator-readable backoff + next-attempt-at | `dashboard/` | F00474 | non-negotiable | true | 10 |
| R00890 | Each integration crate has README.md documenting envelope mapping + auth requirements + per-severity rendering | `crates/selfdef-integration-*/README.md` | E0031 | non-negotiable | true | 10 |
| R00891 | Integration fabric overview at `docs/sdd/008-notifications-orchestration.md` | `docs/sdd/008-notifications-orchestration.md` | E0031 | non-negotiable | false | 10 |
| R00892 | Operator quick-start at top-level README.md describes setup for at least the 3 simplest integrations (Wall / SMTP / Discord) | `README.md` | E0031 | non-negotiable | true | 10 |
| R00893 | Operator secrets — keys NEVER in repo (architecture invariant) | architecture | M00082 | non-negotiable | false | 10 |
| R00894 | Operator secrets — env-var or file-on-disk per integration (operator's choice) | `crates/selfdef-config` | M00082 | non-negotiable | true | 10 |
| R00895 | Operator secrets — daemon refuses to start if `integrations.<name>.enabled = true` and required secret absent | `crates/selfdef-config` | M00082 | non-negotiable | false | 10 |
| R00896 | Each integration handles transient errors (HTTP 5xx / connection reset / timeout) with retry policy | `crates/selfdef-notifier` | M00105 | non-negotiable | false | 10 |
| R00897 | Each integration handles permanent errors (HTTP 4xx / auth failure / not-found) WITHOUT retry; surfaces as DeliveryReceipt.status=failed | `crates/selfdef-notifier` | F00388 | non-negotiable | false | 10 |
| R00898 | Each integration honors `Retry-After` header when present | `crates/selfdef-notifier` | M00105 | non-negotiable | true | 10 |
| R00899 | Each integration honors per-platform rate-limit headers (Discord `X-RateLimit-*` / Slack `Retry-After` / etc) | `crates/selfdef-notifier` | M00105 | non-negotiable | true | 10 |
| R00900 | Each integration emits OpenTelemetry span per delivery attempt (operator-toggleable) | `crates/selfdef-integration-*` | E0031 | preferable | true | 10 |
| R00901 | Integration fabric supports SDD-005 L1–L5 layered test harness | SDD-005 | E0031 | non-negotiable | false | 10 |
| R00902 | Integration fabric supports SDD-006 shared module-script lib | SDD-006 | E0031 | non-negotiable | false | 10 |
| R00903 | Integration fabric supports SDD-008 notification orchestration (canonical) | SDD-008 | E0031 | non-negotiable | false | 10 |
| R00904 | Integration fabric supports SDD-014 shared audit summary channel | SDD-014 | E0038 | non-negotiable | false | 10 |
| R00905 | Integration fabric supports SDD-016 oracle triage channel | SDD-016 | E0036 | non-negotiable | false | 10 |
| R00906 | Integration fabric supports SDD-029 round-ledger doctrine | SDD-029 | E0031 | non-negotiable | false | 10 |
| R00907 | Integration fabric supports SDD-038 cross-repo binding doctrine (Oracle-Triage only) | SDD-038 | M00092 | non-negotiable | false | 10 |
| R00908 | L1 lint — every integration crate has README.md | tests/lint | R00890 | non-negotiable | false | 10 |
| R00909 | L1 lint — every integration crate exports `Notify` trait | tests/lint | M00079 | non-negotiable | false | 10 |
| R00910 | L1 lint — every integration crate has per-channel `*_test.rs` | tests/lint | E0031 | non-negotiable | false | 10 |
| R00911 | L3 smoke — daemon starts with all 14 integrations enabled + healthy | tests/ | E0031 | non-negotiable | false | 10 |
| R00912 | L3 smoke — daemon starts with all 14 integrations disabled + healthy | tests/ | E0031 | non-negotiable | false | 10 |
| R00913 | L5 real-substrate — Wall + SMTP + Discord deliver on real Debian 13 VM | tests/ | E0031 | non-negotiable | false | 10 |
| R00914 | Severity filter — operator can drop `info` notifications per-channel | `crates/selfdef-config` | R00833 | non-negotiable | true | 10 |
| R00915 | Severity filter — operator can drop `warn` notifications per-channel | `crates/selfdef-config` | R00833 | non-negotiable | true | 10 |
| R00916 | Severity filter — `error` and `critical` notifications NEVER droppable per-channel (operator-confirmed only via disabling integration entirely) | `crates/selfdef-config` | R00833 | non-negotiable | false | 10 |
| R00917 | Default — Wall integration enabled on fresh install (local-host operator-on-machine notification is the safest default) | `crates/selfdef-config` | F00373 | preferable | true | 10 |
| R00918 | Default — SMTP integration disabled on fresh install (requires operator config) | `crates/selfdef-config` | F00370 | non-negotiable | true | 10 |
| R00919 | Default — all external-network integrations (Discord/Loki/ntfy/OpenSearch/PagerDuty/Slack/Signal/Twilio/TheHive) disabled on fresh install | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00920 | Default — Oracle-Triage integration disabled on fresh install (requires sovereign-os gateway URL) | `crates/selfdef-config` | F00365 | non-negotiable | true | 10 |
| R00921 | Default — Shared-Audit-Summary writes to `/var/lib/selfdef/audit-summary.jsonl` (path operator-overridable) | `crates/selfdef-config` | F00419 | non-negotiable | true | 10 |
| R00922 | Default — per-integration retry max_retries = 3 | `crates/selfdef-config` | F00454 | non-negotiable | true | 10 |
| R00923 | Default — per-integration backoff_base_ms = 500 | `crates/selfdef-config` | F00455 | non-negotiable | true | 10 |
| R00924 | Default — per-integration backoff_max_ms = 60000 | `crates/selfdef-config` | F00456 | non-negotiable | true | 10 |
| R00925 | Default — per-integration jitter = 25% | `crates/selfdef-config` | F00457 | non-negotiable | true | 10 |
| R00926 | Default — per-integration per-second rate cap = 10 (operator-tunable) | `crates/selfdef-config` | F00458 | non-negotiable | true | 10 |
| R00927 | Default — per-integration per-minute rate cap = 100 | `crates/selfdef-config` | F00459 | non-negotiable | true | 10 |
| R00928 | Default — per-integration per-hour rate cap = 1000 | `crates/selfdef-config` | F00460 | non-negotiable | true | 10 |
| R00929 | Per-integration timeout — operator-tunable (default 10s HTTP / 30s subprocess) | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00930 | Per-integration backoff — re-orders DeliveryReceipt status to `failed` after exhausting retries | `crates/selfdef-notifier` | M00105 | non-negotiable | false | 10 |
| R00931 | Per-integration dedup window — operator-tunable (default 5m for high-severity, infinite for verdict_id-based) | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00932 | Per-integration max-payload-size — operator-tunable; truncates with operator-readable marker when exceeded | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00933 | Per-integration redaction — operator-tunable PII redaction (hash uid / strip path tails / mask IP) | `crates/selfdef-config` | E0031 | preferable | true | 10 |
| R00934 | Per-integration message digest — operator-toggleable hourly/daily digest mode | `crates/selfdef-config` | F00384 | non-negotiable | true | 10 |
| R00935 | Per-integration silence window — operator-tunable (e.g. silence non-critical between 23:00 and 07:00) | `crates/selfdef-config` | E0031 | preferable | true | 10 |
| R00936 | Per-integration test-mode — `--test-mode` flag emits dry-run output without actual delivery | `crates/selfdef-cli` | F00469 | non-negotiable | true | 10 |
| R00937 | Per-integration verbose-diag — `--diag` flag emits operator-readable trace of delivery decision | `crates/selfdef-cli` | E0031 | non-negotiable | true | 10 |
| R00938 | Operator can rotate any integration's secret without daemon restart | `crates/selfdef-config` | M00082 | non-negotiable | true | 10 |
| R00939 | Operator can switch any integration's primary/backup endpoint without daemon restart | `crates/selfdef-config` | E0031 | preferable | true | 10 |
| R00940 | Operator can configure multi-recipient lists (e.g. multiple Signal recipients; multiple SMTP `to` addresses) | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00941 | Operator can configure per-recipient severity filter (e.g. critical-only for off-hours Twilio) | `crates/selfdef-config` | E0031 | preferable | true | 10 |
| R00942 | Operator can configure custom routing rules (verdict_severity X + source Y → channel Z) | `crates/selfdef-config` | E0031 | preferable | true | 10 |
| R00943 | Notifier orchestrator handles channel-fan-out (one NotifyEnvelope → multiple integrations) | `crates/selfdef-notifier-orchestrator` | E0031 | non-negotiable | false | 10 |
| R00944 | Notifier orchestrator handles failover (if primary channel fails, try backup) | `crates/selfdef-notifier-orchestrator` | E0031 | preferable | true | 10 |
| R00945 | Notifier orchestrator handles escalation (warn → error → critical chains different recipients) | `crates/selfdef-notifier-orchestrator` | E0031 | preferable | true | 10 |
| R00946 | Notifier orchestrator emits operator-readable delivery summary at daemon shutdown | `crates/selfdef-notifier-orchestrator` | E0031 | non-negotiable | true | 10 |
| R00947 | Notifier orchestrator integrates with `/v1/responder/commit` flow (Action `notify` always routes through orchestrator) | `crates/selfdef-responder` + `crates/selfdef-notifier-orchestrator` | R00851 | non-negotiable | false | 10 |
| R00948 | Notifier orchestrator queue durability — DeliveryReceipts persisted across daemon restart | `crates/selfdef-store` | R00829 | non-negotiable | false | 10 |
| R00949 | Notifier orchestrator queue overflow — drops with operator-readable warning (NOT silent) | `crates/selfdef-notifier-orchestrator` | E0031 | non-negotiable | false | 10 |
| R00950 | Notifier orchestrator queue size — operator-tunable | `crates/selfdef-config` | E0031 | non-negotiable | true | 10 |
| R00951 | Anti-pattern — Each integration NEVER reads operator-private data without explicit consent (no /etc/shadow / no .ssh keys / no credentials.json) | every integration crate | E0031 | non-negotiable | false | 10 |
| R00952 | Anti-pattern — Each integration NEVER inflates payload with non-redacted PII | every integration crate | R00933 | non-negotiable | false | 10 |
| R00953 | Anti-pattern — Each integration NEVER opens listening ports (outbound-only delivery) | every integration crate | E0031 | non-negotiable | false | 10 |
| R00954 | Anti-pattern — Each integration NEVER persists secrets in journal logs (operator-supplied secrets are masked in log output) | every integration crate | M00082 | non-negotiable | false | 10 |
| R00955 | Anti-pattern — Each integration NEVER bypasses notifier-orchestrator (no direct sends from collector/correlator/responder) | every integration crate | R00943 | non-negotiable | false | 10 |
| R00956 | Anti-pattern — Each integration NEVER includes selfdef daemon binary path / config path / private key path in payload (forensic-evidence reduction) | every integration crate | R00951 | non-negotiable | false | 10 |
| R00957 | Cross-repo binding — Oracle-Triage typed-mirror crate documented at `docs/sdd/016-oracle-triage-channel.md` | SDD-016 | M00092 | non-negotiable | false | 10 |
| R00958 | Cross-repo binding — Oracle-Triage saturation invariant — any new sovereign-os instrument requires its typed-mirror counterpart in this crate per SDD-038 | SDD-038 | M00092 | non-negotiable | false | 10 |
| R00959 | Documentation — top-level README.md lists all 14 integrations with one-line description + config-path reference | `README.md` | E0031 | non-negotiable | true | 10 |
| R00960 | Composite — 14-notifier integration fabric is selfdef-scope; integrates via `selfdef-notifier-orchestrator` (MS005) which feeds from `selfdef-responder` (MS003) which consumes Verdicts from `selfdef-correlator` (MS003) which consumes Events from `selfdef-collector-*` (MS002) — the complete IPS pipeline | this milestone | E0031 | non-negotiable | false | 10 |

— End of MS004 milestone file.
