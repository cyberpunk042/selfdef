# Phase 6 inventory — what changed during the SDD-008 cycle

Hand-counted from `git log` covering the 22 PRs that
implemented SDD-008 end-to-end (commits `f85ba78` SDD-008
charter → `28fc63b` D-6c custom-profile TOML, on `main`
prior to the Phase 6 charter PR `#131`). Used by the seven
Phase 6 explorers as the starting point for "what's the new
surface I'm auditing?"

## New crates

**9 new workspace members.** All depend on `tokio` + `async-trait`
and most depend on `selfdef-core` for the `SeverityId` /
`Event` re-exports.

### Trait layer

- **`selfdef-notifier-orchestrator`** (346 LOC) — public types
  for the new dispatch ABI: `Channel` async-trait, `Payload`
  struct, `PayloadId(uuid::Uuid v7)`, `EventId(Uuid)`,
  `DeliveryReceipt`, `ChannelError` taxonomy, `AckReplyHint`
  enum. 8 unit tests pinning constructor / Debug-elision /
  error-classification shapes.

### Persistence + dispatch layer

- **`selfdef-notifier-engine`** (2,631 LOC across 4 modules)
  - `src/lib.rs` (701 LOC, 16 tests) — `EscalationEngine`
    around an `Arc<Mutex<rusqlite::Connection>>`; schema
    `notification_escalations(event_id PK, payload_id, title,
    body, severity, ack_link, rung_index, deadline_at,
    acked_at, created_at)`; APIs `open`, `enqueue`,
    `record_ack`, `close_event`, `next_pending_at`,
    `take_due`, `advance_rung` (with monotonic +
    `acked_at IS NULL` guards).
  - `src/dispatcher.rs` (1,048 LOC, 31 tests) — `PayloadDispatcher`
    façade composing engine + channel set; `Mode::{Enforce,
    Audit}`; profile; panic-floor; APIs `submit`,
    `dispatch_payload`, `dispatch_payload_for_rung`,
    `record_ack`, `close_event`; `crosses_panic_floor`
    predicate.
  - `src/profile.rs` (346 LOC, 13 tests) — `Rung` +
    `Profile`; builtins `auto` / `aggressive` / `patient`;
    `Profile::custom`; `Rung::with_channels` per-rung filter
    (empty = WUPHF); `ProfileBuildError::EmptyRungs`.
  - `src/wake_task.rs` (536 LOC, 11 tests) — background loop
    with biased `tokio::select` on cancel; `compute_sleep`,
    `process_due`, `handle_row`; calls
    `dispatch_payload_for_rung` for D-6c.

### Channel integrations (7 crates, 2,905 LOC, 67 tests)

- **`selfdef-integration-ntfy`** (284 LOC, 4 tests) — HTTP
  push channel; auth via optional bearer-token from file.
- **`selfdef-integration-signal`** (229 LOC, 3 tests) —
  Signal-CLI JSON-RPC over local subprocess.
- **`selfdef-integration-smtp`** (445 LOC, 7 tests) — lettre
  SMTP; STARTTLS + Basic-Auth; envelope-from validation.
- **`selfdef-integration-twilio`** (589 LOC, 12 tests) —
  Programmable-Messaging adapter; Basic-Auth; per-recipient
  POST; wiremock end-to-end tests.
- **`selfdef-integration-slack`** (432 LOC, 12 tests) —
  incoming-webhook adapter; Block-Kit-light payload; wiremock
  tests.
- **`selfdef-integration-discord`** (443 LOC, 13 tests) —
  webhook adapter; embed-style payload; wiremock tests.
- **`selfdef-integration-wall`** (483 LOC, 16 tests) — wall(1)
  session-attention channel via `tokio::process::Command`;
  PATH-resolution-only (no shell), stdin-pipe-only.

## New SDDs

- **`docs/sdd/008-notifications-orchestration.md`** (440 LOC)
  — design points D-1..D-9, open questions Q-A..Q-G,
  modules-vs-integrations taxonomy, escalation semantics,
  modes, profiles, panic-floor, ack model, dashboard
  deferred to D-9.

## Modified crates

### selfdef-cli

- **`src/init.rs`** (+194 LOC) — `STARTER_CONFIG` rewritten
  to document every new operator knob inline (escalations
  path, mode, profile, panic-floor, profiles map,
  subscriptions map, per-channel sections for all 7
  integrations).
- **`src/main.rs`** (+69 LOC) — `notify {ack,forget,list}`
  subcommand cluster.
- **`src/notify.rs`** (329 LOC, 9 tests, new file) — D-4
  implementation; opens `EscalationEngine` directly (WAL
  permits concurrent daemon read); severity-emoji prefix
  matching Slack/Discord conventions; JSON-vs-tabular output.

### selfdef-config

- **`src/lib.rs`** (+286 LOC) — schema extensions:
  - `NotifierConfig` grows: `ntfy`, `signal`, `smtp`,
    `twilio`, `slack`, `discord`, `wall`, `escalations_path`,
    `mode`, `profile`, `panic_floor`, `profiles`
    (`HashMap<String, ProfileConfig>`), `subscriptions`
    (`HashMap<String, SubscriptionConfig>`).
  - `ProfileConfig { rungs: Vec<RungConfig> }`.
  - `RungConfig { channels: Vec<String>, ack_window_secs:
    i64 }`.
  - `SubscriptionConfig { severity_floor: Option<String>,
    event_kinds: Vec<String> }`.

### selfdef-daemon

- **`src/main.rs`** (+520 LOC) — wires everything together:
  - `build_notifier_path(cfg, shutdown)` returns
    `(Arc<dyn Notifier>, Option<JoinHandle>)`.
  - Branches on `cfg.notifier.escalations_path`:
    `Some` → engine + dispatcher + wake-task spawn; `None`
    → legacy M4 `NotifierChain`.
  - `build_channel_set` parallels `build_notifier_chain` for
    the orchestrator `Vec<Arc<dyn Channel>>`.
  - `parse_dispatcher_mode`, `parse_dispatcher_profile` (with
    custom-profile lookup), `parse_severity_floor`.
  - Wake-task lifecycle joined into the shutdown sequence.
- **`src/dispatcher_adapter.rs`** (227 LOC, 4 tests, new) —
  `DispatcherAdapter` bridges legacy `Notifier` ABI →
  `PayloadDispatcher::submit`; Event → Payload conversion.

### selfdef-notifier

- **`src/lib.rs`** (delta against ~422 LOC of existing
  surface) — config-to-notifier construction now opens 7
  channel paths; subscription filtering applied in
  `NotifierChain`.

## Module-side machinery

None. The SDD-008 cycle was entirely daemon-side; no module
template (`modules/*/install/`) was touched.

## Configuration surface

**New TOML knobs** (`[notifier]` section unless noted):

- `escalations_path: PathBuf` — opt-in switch from legacy M4
  notifier chain to the escalation engine + dispatcher path.
- `mode: "enforce" | "audit"` — dispatcher operating mode
  (audit = dry-run).
- `profile: String` — `auto` / `aggressive` / `patient` or a
  custom-profile name.
- `panic_floor: String` — severity name above which audit
  mode is bypassed (case-insensitive match against
  `SeverityId`).
- `[notifier.profiles.<name>]` — custom profile definition;
  contains `rungs: [{ channels: [...], ack_window_secs: N
  }]`.
- `[notifier.subscriptions.<channel>]` — per-channel
  `severity_floor` + `event_kinds` filter.
- `[notifier.ntfy]` — `url`, `topic`, optional `token_file`.
- `[notifier.signal]` — `binary`, `account`, `recipient`.
- `[notifier.smtp]` — `host`, `port`, `username`,
  `password_file`, `from`, `to`, `starttls`.
- `[notifier.twilio]` — `account_sid`, `auth_token_file`,
  `from`, `to`, `base_url`.
- `[notifier.slack]` — `webhook_url_file`.
- `[notifier.discord]` — `webhook_url_file`.
- `[notifier.wall]` — `enabled`, `binary`.

**Totals**: 7 channel sub-sections + 4 top-level dispatcher
knobs + 2 multi-key sub-maps = **13 new TOML surface
elements**.

## Supply-chain surface

- **`deny.toml`** (+4 LOC) — `0BSD` added to
  `licenses.allow` with justification comment, to permit
  `quoted_printable` (transitive via `lettre`).
- **`Cargo.toml`** (workspace, +12 LOC) — adds `lettre`,
  path-deps for all 9 new crates.

## Documentation surface

- **`ARCHITECTURE.md`** (+66 LOC) — new "Integrations layer"
  section codifying the modules-vs-integrations boundary.
- **`docs/dev/integrations.md`** (291 LOC, new) — contributor
  template for new integration crates.
- **`SECURITY.md`** (+3 LOC) — rows for notification
  credentials (all channels) and TTY broadcast (wall).
- **`docs/dev/README.md`** (+8 LOC) — links the new
  integrations doc.

## Test surface (post-SDD-008 additions)

- `selfdef-notifier-orchestrator/src/lib.rs` — 8 tests
- `selfdef-notifier-engine/src/lib.rs` — 16 tests
- `selfdef-notifier-engine/src/dispatcher.rs` — 31 tests
- `selfdef-notifier-engine/src/profile.rs` — 13 tests
- `selfdef-notifier-engine/src/wake_task.rs` — 11 tests
- `selfdef-integration-ntfy` — 4 tests
- `selfdef-integration-signal` — 3 tests
- `selfdef-integration-smtp` — 7 tests
- `selfdef-integration-twilio` — 12 tests
- `selfdef-integration-slack` — 12 tests
- `selfdef-integration-discord` — 13 tests
- `selfdef-integration-wall` — 16 tests
- `selfdef-cli/src/notify.rs` — 9 tests
- `selfdef-daemon/src/dispatcher_adapter.rs` — 4 tests

Total: **159 new tests** across the SDD-008 cycle.

## In-cycle fix-up commits

Two non-PR fix-up commits landed during the cycle, both as
direct CI-driven correctness fixes:

- **`3ab3b21`** (under PR #114) — `chore(deny): allow 0BSD for
  lettre's quoted_printable transitive`. The auditor should
  re-check the `0BSD` allow-list decision in the security
  explorer.
- **`3b80a85`** (under PR #127) — `chore(fmt): collapse
  panic_floor parsing chain (rustfmt CI fix)`. Cosmetic; local
  rustfmt missed a chain-collapse on the panic-floor `Option`
  pipeline that CI's 1.88.0 enforced.

## Numbers

- **22 PRs** merged during the SDD-008 closure cycle
  (`#109`..`#130`).
- **9 new crates** (1 trait, 1 engine, 7 integrations).
- **1 new SDD** (SDD-008).
- **13 new TOML surface elements** (7 channel sections + 4
  top-level dispatcher knobs + 2 multi-key sub-maps).
- **2 new operator-facing doc sections** (ARCHITECTURE.md
  integrations-layer, `docs/dev/integrations.md`).
- **1 supply-chain license addition** (`0BSD` in
  `deny.toml`).
- **159 new tests** across the cycle.
- **~9,700 lines added net** per `git diff --stat
  f85ba78..28fc63b` (the vast majority is the 9 new crates).
