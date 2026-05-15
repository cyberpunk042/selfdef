# Phase 7 inventory — what changed during the post-Phase-6 cycle

Hand-counted from `git log` covering the 7 PRs that landed
between Phase 6 wrap (`#139`, commit `a0ec78f`) and the Phase
7 charter (`#147`, commit `cdc9265`). Used by the seven Phase
7 explorers as the starting point for "what's the new surface
I'm auditing?".

## New crates

**4 new workspace members**, all channel integrations
following the `docs/dev/integrations.md` template.

| Crate | LOC | Tests | Q-G | PR |
| --- | ---: | ---: | --- | --- |
| `selfdef-integration-pagerduty` | 559 | 12 | Q-G PagerDuty | `#143` |
| `selfdef-integration-loki` | 600 | 16 | Q-G Loki | `#144` |
| `selfdef-integration-opensearch` | 792 | 22 | Q-G OpenSearch | `#145` |
| `selfdef-integration-thehive` | 578 | 16 | Q-G TheHive | `#146` |
| **Total** | **2,529** | **66** | — | — |

All four implement both `Notifier` (legacy chain) and
`Channel` (orchestrator) ABIs, follow the secret-elision
`Debug` posture, refuse plaintext (`http://`) endpoints, and
ship wiremock end-to-end tests.

## New SDD design points shipped

- **D-4 HTTP ack** (`GET /notify/ack/<token>`) — the
  long-standing follow-up complement to D-4's CLI ack. PR
  `#142`.

## SDDs not modified

No new SDDs. SDD-008's Implementation-status table gained
four Q-G rows and one D-4 HTTP-ack row, but the
design-document body itself didn't change.

## Modified crates

### selfdef-notifier-orchestrator

- `Payload.event_kind: Option<String>` (PR #140 D-5e) —
  populated from `Event::class_uid::name()` so the engine
  path's subscription filter can match on event kind.
- `Payload.ack_token: Option<String>` (PR #142 D-4) — the
  token DispatcherAdapter mints when `ack_link_base` is set.
- `Subscription` struct + `Subscription::matches(&Payload)`
  (PR #140 D-5e) — operates on Payload (vs. the legacy
  `selfdef_notifier::Subscription` which operates on Event).

### selfdef-notifier-engine

- **Schema migrations**:
  - **v2** (PR #140 D-5e): `ALTER TABLE notification_escalations
    ADD COLUMN event_kind TEXT NULL`.
  - **v3** (PR #142 D-4): `ALTER TABLE notification_escalations
    ADD COLUMN ack_token TEXT NULL` + back-fill via
    `lower(hex(randomblob(16)))` + `CREATE UNIQUE INDEX IF
    NOT EXISTS idx_escalations_ack_token`.
- `PendingEscalation` + `StoredRow` gain `event_kind` and
  `ack_token` fields.
- New `PayloadDispatcher::with_subscriptions(HashMap<String,
  Subscription>)` builder + `subscriptions()` accessor (PR
  #140).
- New `EscalationEngine::record_ack_by_token(token, now) ->
  Option<(EventId, title)>` (PR #142) with explicit
  `unchecked_transaction` for the UPDATE+SELECT atomicity.
- `wake_task::process_due_at(dispatcher, now)` promoted to
  `pub` (PR #141) — drives wake iterations deterministically
  in tests; production code still uses the private
  `process_due()` which defaults to `unix_now()`.

### selfdef-config

- New `[notifier].ack_link_base: Option<String>` knob (PR
  #142).
- New `LokiConfig` + `[notifier.loki]` block (PR #144) —
  endpoint, tenant_id, auth_token_file, source.
- New `OpenSearchConfig` + `[notifier.opensearch]` block (PR
  #145) — endpoint, index, auth_kind, username,
  auth_token_file, source.
- New `PagerDutyConfig` + `[notifier.pagerduty]` block (PR
  #143) — routing_key_file, endpoint, source.
- New `TheHiveConfig` + `[notifier.thehive]` block (PR #146)
  — endpoint, api_key_file, source, alert_type.

### selfdef-api

- `ApiState.escalation_engine: Option<Arc<EscalationEngine>>`
  (PR #142) — wired in by daemon when `escalations_path` is
  set; `with_escalation_engine()` builder.
- New `GET /notify/ack/:token` handler (PR #142) returning
  200 / 404 / 503.
- `selfdef-notifier-engine` + `-orchestrator` added to
  `Cargo.toml` deps.

### selfdef-daemon

- `build_notifier_path` signature extended to return
  `(Arc<dyn Notifier>, Option<JoinHandle>,
  Option<Arc<EscalationEngine>>)` (PR #142). `clippy::type_complexity`
  allowed with explicit attribute.
- New `build_channel_subscriptions(cfg)` helper (PR #140) —
  produces the dispatcher's subscription map.
- `DispatcherAdapter::with_ack_link_base(base)` builder (PR
  #142) — when set, mints UUIDv7 tokens + renders ack_link
  URLs.
- `build_notifier_chain` + `build_channel_set` each gain 4
  new channel arms for the Q-G adapters.
- F-2031-009 stopgap warn from PR #135 removed (PR #140).

### selfdef-cli

- `init.rs` STARTER_CONFIG gains 5 new commented blocks:
  `ack_link_base`, `[notifier.pagerduty]`,
  `[notifier.loki]`, `[notifier.opensearch]`,
  `[notifier.thehive]`. F-2031-009 caveat removed.

## Module-side machinery

None. The post-Phase-6 cycle was entirely daemon-side; no
module template (`modules/*/install/`) was touched.

## Configuration surface

**New TOML elements** (under `[notifier]`):

- `ack_link_base: Option<String>` (D-4 HTTP ack URL base).
- `[notifier.pagerduty]`: `routing_key_file`, `endpoint`,
  `source` (3 fields).
- `[notifier.loki]`: `endpoint`, `tenant_id`, `auth_token_file`,
  `source` (4 fields).
- `[notifier.opensearch]`: `endpoint`, `index`, `auth_kind`,
  `username`, `auth_token_file`, `source` (6 fields).
- `[notifier.thehive]`: `endpoint`, `api_key_file`, `source`,
  `alert_type` (4 fields).

**Totals**: 4 new channel sub-sections + 1 top-level knob +
17 leaf fields = **18 new TOML surface elements**.

## Documentation surface

- **SDD-008 Implementation-status table**: 6 row updates (D-3
  scope clarification, D-4 HTTP ack added, D-5e added, 4 Q-G
  rows added) + 1 wording revision ("ALL Q-G COMPLETE"
  on TheHive).
- **STARTER_CONFIG** gained 5 new blocks + lost 1 F-2031-009
  caveat.
- **SECURITY.md** notification-credentials row absorbed 4 new
  credential paths (PD routing key, Loki bearer, OS Basic/
  ApiKey, Hive API key). One row, four new mentions.
- **`docs/review/phase-7/`** new directory (charter + ledger
  ship via PR #147).
- No new contributor-template doc; the four Q-G adapters
  follow `docs/dev/integrations.md` unchanged.

## Test surface (post-Phase-6 additions)

| File | New tests | PR |
| --- | ---: | --- |
| `crates/selfdef-notifier-orchestrator/src/lib.rs::tests` | 6 (Subscription) | #140 |
| `crates/selfdef-notifier-engine/src/dispatcher.rs::tests` | 7 (D-5e subscription) | #140 |
| `crates/selfdef-notifier-engine/src/lib.rs::tests` | 7 (D-4 ack_token) | #142 |
| `crates/selfdef-daemon/tests/m_notify_engine.rs` (new file) | 3 (engine pipeline) | #141 |
| `crates/selfdef-api/tests/m12_api.rs` | 4 (D-4 HTTP ack) | #142 |
| `crates/selfdef-integration-pagerduty/src/lib.rs::tests` | 12 | #143 |
| `crates/selfdef-integration-loki/src/lib.rs::tests` | 16 | #144 |
| `crates/selfdef-integration-opensearch/src/lib.rs::tests` | 22 | #145 |
| `crates/selfdef-integration-thehive/src/lib.rs::tests` | 16 | #146 |
| **Total** | **93** | — |

## Numbers

- **7 PRs** merged during the post-Phase-6 cycle
  (`#140`..`#146`).
- **4 new crates** (all Q-G channel integrations).
- **2 schema migrations** (v2 `event_kind`, v3 `ack_token`).
- **1 new SDD design point shipped** (D-4 HTTP ack).
- **2 Phase 6 SDD-debt findings closed** (F-2031-009 via
  D-5e PR, F-2031-013 via SDD-005 impl PR).
- **18 new TOML surface elements**.
- **1 new public API route** (`GET /notify/ack/:token`).
- **1 new test pattern** (`EngineHarness` +
  `process_due_at` in `m_notify_engine.rs`).
- **93 new tests** across the cycle.
- **37 files changed**, **4,847 lines added net** per
  `git diff --stat 8008a41..e91d0ed`.

## Channel inventory after this cycle

The total `selfdef-integration-*` crate count is now **11**:

1. `selfdef-integration-ntfy` (SDD-008 D-2b)
2. `selfdef-integration-signal` (D-2c)
3. `selfdef-integration-smtp` (D-7 Q-E, PR #114-mislabeled-
   per-F-2031-001)
4. `selfdef-integration-twilio` (Q-D)
5. `selfdef-integration-slack` (Q-C)
6. `selfdef-integration-discord` (no Q-letter — pattern
   instance under D-2)
7. `selfdef-integration-wall` (D-8)
8. `selfdef-integration-pagerduty` (Q-G — this cycle)
9. `selfdef-integration-loki` (Q-G — this cycle)
10. `selfdef-integration-opensearch` (Q-G — this cycle)
11. `selfdef-integration-thehive` (Q-G — this cycle)

The Q-G section of SDD-008 is **fully realized**.
