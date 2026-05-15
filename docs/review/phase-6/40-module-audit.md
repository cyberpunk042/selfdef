# Phase 6 — module audit

Walks the SDD-008 dispatcher path end-to-end and the daemon
wiring that ties it to the existing M4 notifier ABI. Raises 3
findings: 2 closed in-place (one important production bug,
one nice doc-drift), and one important / SDD-debt that hand
off to a follow-up PR.

## Methodology

Trace one Event from the bus through the dispatcher path to
a channel and back, in two configurations:

1. **Legacy path** (`cfg.notifier.escalations_path` unset):
   responder → `NotifierChain` → channels. Bypass the engine
   entirely.
2. **Engine path** (`escalations_path` set): responder →
   `DispatcherAdapter` → `PayloadDispatcher::submit` →
   `EscalationEngine::enqueue` + `fire_channels` → channels;
   plus the wake-task loop driving rung advancement.

Look for:

- **Path equivalence** — what the two paths see for the same
  event should be observably identical from a channel's
  point of view.
- **Operator-config seams** — every `[notifier]` knob should
  produce the visible effect SDD-008 documents.
- **State-machine invariants** — engine rows transition only
  in directions the SDD permits.
- **Test-vs-prod call-site asymmetry** — `pub` APIs that no
  production caller invokes (smell of dead surface or
  unstated contract).
- **Doc-vs-code drift** — comments describing different code
  than what exists.

## Module list (audit-surface inventory)

| Module | LOC | Role |
| --- | --- | --- |
| `selfdef-daemon/src/dispatcher_adapter.rs` | 227 | Event → Payload bridging; `Notifier` ABI shim. |
| `selfdef-notifier-engine/src/dispatcher.rs` | 1,048 | `PayloadDispatcher` façade; mode + profile + panic-floor. |
| `selfdef-notifier-engine/src/wake_task.rs` | 536 | Background rung-advance loop. |
| `selfdef-notifier-engine/src/lib.rs` | 701 | `EscalationEngine` + SQLite persistence. |
| `selfdef-daemon/src/main.rs` (subset) | ~270 (in scope) | `build_notifier_path`, `build_channel_set`, parse helpers, wake-task lifecycle. |

## Path 1: legacy (escalations_path unset)

The daemon's `build_notifier_path` finds no `escalations_path`
and returns `(Arc<NotifierChain>, None)`. The responder calls
`chain.notify(event)`. `NotifierChain` iterates configured
notifiers (ntfy, signal, smtp, twilio, slack, discord) in
config order, applies per-channel `severity_floor` +
`event_kinds` filtering (D-3 → built into the chain), and
calls each `Notifier::notify`. Wake task is not spawned.

Audited: this is the pre-SDD-008 M4 flow + the D-3
subscription-filter addition. The per-channel filter is the
operator's principal noise-reduction lever. **Clean.**

## Path 2: engine (escalations_path set)

`build_notifier_path` opens the SQLite engine, builds the
channel set via `build_channel_set`, parses
`mode`/`profile`/`panic_floor`, wires a `PayloadDispatcher`,
spawns the wake task, and returns a `DispatcherAdapter`
wrapped as an `Arc<dyn Notifier>`. The responder calls
`adapter.notify(event)`, which:

1. **Event → Payload conversion**. `render_title` /
   `render_body` are the same helpers the legacy channels
   use — byte-identical wire output regardless of which path
   the event travelled.
2. **Initial deadline computation**. `now +
   profile.ack_window_for(0)` (after the F-2031-007 fix; see
   below). Before the fix, this was a hardcoded constant
   (`DEFAULT_RUNG_INTERVAL_SECS = 300`); operators picking
   the `aggressive` profile (rung-0 ack window = 60s)
   silently saw a 5-minute first-rung delay.
3. **Submit**. `PayloadDispatcher::submit(&payload,
   deadline, now)`:
   - `engine.enqueue(payload, deadline, now)` — persist
     first (so even an all-channels-fail outcome still
     leaves a row the wake task can retry).
   - Mode check: `Audit` AND not over panic-floor → log
     "would have fired" per channel, return
     `Delivered { channel: "audit" }`.
   - Else: `fire_channels(payload)` — first-success-wins
     channel walk. Audit + panic-floor crossed logs the
     bypass and falls through.
4. **DispatcherAdapter** converts `DispatchOutcome` →
   `Result<(), NotifierError>`:
   - `Delivered { .. }` → `Ok(())`.
   - `PersistedButAllChannelsFailed(err)` →
     `Err(NotifierError::Http(...))`. The row IS in the
     engine; the wake task retries.
   - `PersistFailed(err)` → `Err(NotifierError::Http(...))`.
     SQLite is wedged; operator gets the upstream chain-
     style error.
5. **Wake task loop**. Independent of the responder. On
   each iteration:
   - `compute_sleep` reads `engine.next_pending_at()` and
     sleeps until the earliest deadline (or
     `IDLE_POLL_INTERVAL_SECS=60s` if no rows).
   - On wake: `engine.take_due(now, TAKE_DUE_LIMIT)`.
   - For each row: if `rung_index >= profile.max_rung()`
     → `close_event`; else `dispatch_payload_for_rung`
     (D-6c rung filter applied) + `advance_rung(next_rung,
     now + profile.ack_window_for(next_rung))`.
6. **Operator-ack path**. `selfdefctl notify ack <id>`
   opens the engine directly (WAL permits concurrent daemon
   reads), calls `engine.record_ack(event_id, now)` — sets
   `acked_at` so the wake task's `advance_rung` query
   (`WHERE acked_at IS NULL AND rung_index < ?`) loses the
   race correctly.

Audited path-by-path. Notes below.

## Findings

### F-2031-007 (important, closed-in-place)

**Surface**: `selfdef-daemon/src/dispatcher_adapter.rs`,
`DispatcherAdapter::notify`.

**Pre-fix code**:

```rust
let deadline = now + wake_task::DEFAULT_RUNG_INTERVAL_SECS;
```

`DEFAULT_RUNG_INTERVAL_SECS` is the legacy D-5c hardcoded
5-minute constant. After D-6b shipped named profiles
(`auto` / `aggressive` / `patient`), the adapter continued
to use the legacy constant instead of `profile.ack_window_
for(0)`. The wake_task module's own doc-comment on
`DEFAULT_RUNG_INTERVAL_SECS` explicitly flagged the
follow-up:

> Kept exported for the [`DispatcherAdapter`] in
> selfdef-daemon, which still uses it as the initial-submit
> deadline. D-6c will tie that to `profile.ack_window_for(0)`.

D-6c shipped (PR #129); the adapter wasn't updated.

**Concrete impact**: an operator selecting the `aggressive`
profile (rung 0 = 60s) sees the first rung-advance fire
~300s after submit instead of ~60s. The profile's purpose
("wake the on-call person, missed alerts worse than extra
pages") is defeated on the *first* escalation rung — exactly
the rung the operator cared most about being snappy. The
remaining rungs use the profile's `ack_window_for(next_rung)`
correctly, so the bug compounds: rung 0 fires immediately,
nothing happens for 5min (instead of 60s), then rung 1 fires
and waits 180s (correct), then rung 2 fires at the right
time. The operator's UX is "the alert fires twice, with the
right gaps... 5 min from now."

**Severity = important** — degrades operator-facing
correctness on a primary tuning knob. Not a crash, not
silent data loss, but the configured behaviour materially
differs from the documented behaviour.

**Closed in this PR**:

- `dispatcher_adapter.rs`: replace
  `wake_task::DEFAULT_RUNG_INTERVAL_SECS` with
  `self.dispatcher.profile().ack_window_for(0)`.
- Drop the now-unused `wake_task` import.
- Update the adapter's module/struct doc-comments.
- New test
  `deadline_uses_active_profile_rung_0_ack_window`: builds
  an adapter wrapping a `Profile::aggressive`-configured
  dispatcher, calls `adapter.notify(event)`, asserts the
  persisted row's `deadline_at` is in
  `[now_before + 60, now_after + 60]`. Pinpoints the new
  contract bytewise.

The legacy `DEFAULT_RUNG_INTERVAL_SECS` constant remains
exported as a defensible default for ad-hoc callers, but
the daemon's prod path no longer uses it.

### F-2031-008 (nice, closed-in-place)

**Surface**:
`selfdef-notifier-engine/src/wake_task.rs`, top-level
doc-comment on `pub async fn run`.

**Pre-fix doc**:

```
/// 3. For each row:
///    - If `rung_index >= MAX_RUNG`: close (max attempts hit).
///    - Else: re-fire via `dispatcher.dispatch_payload`, then
///      `engine.advance_rung(rung_index + 1, now + RUNG_INTERVAL)`.
```

`MAX_RUNG` is the legacy `pub const MAX_RUNG: u32 = 1`
(D-5c), since deprecated by `profile.max_rung()`.
`dispatch_payload` is the no-rung-filter API; the actual
code calls `dispatch_payload_for_rung` (D-6c). `RUNG_INTERVAL`
is the legacy constant; the actual code uses
`profile.ack_window_for(next_rung)`.

**Concrete impact**: a contributor reading the doc-comment
would form an incorrect model of how the wake task drives
escalation. Three out of three named functions/constants in
the bullet list have been replaced.

**Severity = nice** — pure doc-vs-code drift; the code is
correct, only the comment is stale.

**Closed in this PR**: updated bullet 3 to reference
`profile.max_rung()`, `dispatch_payload_for_rung`, and
`profile.ack_window_for(rung_index + 1)`.

### F-2031-009 (important, SDD-debt — defer to follow-up)

**Surface**: `selfdef-daemon/src/main.rs::build_channel_set`
(D-5d wiring); `selfdef-notifier-engine/src/dispatcher.rs::
fire_channels_filtered`.

**Defect**: when an operator switches from the legacy
notifier chain to the engine path (by setting
`escalations_path`), the per-channel subscription model
(D-3: `[notifier.subscriptions.<channel>]` with
`severity_floor` + `event_kinds`) **silently stops being
applied**. `build_channel_set` builds a `Vec<Arc<dyn
Channel>>` with no subscription metadata attached; the
dispatcher's `fire_channels_filtered` walks every
configured channel regardless of the operator's
per-channel filter.

The code itself flags the gap:

```rust
// Per-channel subscription filtering (D-3) is **not** applied
// here in v1 — the dispatcher fires every channel in operator-
// supplied order. Subscription-aware dispatching lands in a
// follow-up D-5e / D-6 once `PayloadDispatcher::new` grows a
// subscription-pair input.
fn build_channel_set(cfg: &Config) -> Vec<Arc<dyn Channel>> { … }
```

**Concrete impact**: a real operator-facing trap. The
sequence "set escalations_path → discover wake-task
escalation is great → leave the same `[notifier.subscriptions]`
table in place" silently widens the alert surface. The
discord channel that was previously gated to
`severity_floor = "critical"` now fires on every event,
including `Informational` health-checks. Path equivalence
(see Methodology) breaks here: the same Event produces
different observable wire output on the two paths.

**Severity = important** — degrades operator-facing
correctness on the principal noise-reduction lever (D-3 was
the headline operator-config knob of the cycle). Not a
crash; not silent data loss; **silent broadening of channel
firing** on a config-key the operator believed was active.

**SDD-debt because**: the fix is design-shaped, not a
one-line patch. `PayloadDispatcher` needs a subscription
input (probably a `HashMap<String, SubscriptionConfig>`
keyed by channel name), `fire_channels_filtered` needs to
consult it before each `channel.send`, and `build_channel_set`
needs to pass the config through. The SDD-008 D-5e
follow-up (referenced in the code comment) is the right
home for this.

**Recommendation**:

- Open a `feat(sdd-008): D-5e — wire subscription filter
  into dispatcher path` PR with the design described above.
- Until that PR lands, the daemon should at minimum emit a
  loud warning at startup when **both** `escalations_path`
  is set **and** `[notifier.subscriptions]` is non-empty,
  so the operator notices the configuration isn't being
  enforced.

The warning is a one-line `build_notifier_path` change;
worth shipping as a stopgap. I'm not closing F-2031-009 in
this PR because the principled fix is design-shaped (see
SDD-debt) — but the integration explorer (next PR) should
ship the startup warning as the bridge.

## Wake-task state machine — invariants verified

Manually traced through:

- **Monotonic rung advance** — `EscalationEngine::advance_
  rung` uses `WHERE event_id = ?1 AND acked_at IS NULL AND
  rung_index < ?2`. An ack landed via `record_ack` between
  `take_due` and `advance_rung` correctly causes
  `advance_rung` to return `Ok(false)` (row unchanged).
- **Wake-task close vs ack race** — same query semantics
  apply to `close_event`. An ack racing against
  `rung_index >= max_rung` close still wins because
  `record_ack` sets `acked_at` and the close path observes
  it... wait, let me re-check. `close_event` deletes the
  row outright, not gated on `acked_at`. So if the wake
  task's "max rungs reached → close" runs concurrently with
  an operator ack, the close wins and the ack returns
  `Ok(false)` ("unknown event"). That's the right outcome
  semantically (closing because max rungs hit already
  means we gave up; an ack at that moment is moot). **Clean.**
- **Take-due idempotence** — `take_due` does not mark rows
  as in-flight; if two wake-task iterations overlap (they
  can't by construction — `tokio::select` biased + no spawn
  inside `process_due`), they'd both pull the same row. The
  guard against double-fire is the `advance_rung` monotonic
  check. **Clean by structure**, defensive in implementation.

## Channel walk — first-success-wins semantics

`fire_channels_filtered` returns `DispatchOutcome::Delivered`
on the **first** channel that returns `Ok`. Subsequent
channels are not called. This is by design — escalation is
one-message-per-rung, and the first channel to accept means
the alert has been delivered.

A latent edge case: if channel order is `[ntfy, slack]` and
ntfy returns `Ok` but the underlying ntfy server actually
dropped the message (a half-broken ntfy server), slack never
gets the message. Today the channels' transports treat HTTP
2xx as success — there's no end-to-end delivery proof. This
is fine within SDD-008's scope (escalation rungs catch the
"first channel falsely claimed success" case; the operator
acks → no rung advance, or doesn't → wake task re-fires
through later channels).

**Not a finding** — operating-as-designed. Worth mentioning
in the integration audit for completeness.

## Tests-vs-prod surface check

- `PayloadDispatcher::dispatch_payload` is `pub` but has **no
  production caller** (verified by grep). Only the test
  module and `dispatch_payload_for_rung` (which calls
  `fire_channels_filtered` with empty filter, semantically
  equivalent) use it. Kept because the test module exercises
  a wide matrix through it; could be `pub(crate)` if the
  trait crate's test isolation needed weren't a concern. **Not a
  finding** — the public API is convenient for downstream
  embedders that don't know about rungs; flagging in case the
  docs explorer (PR 6) wants to add a doc-comment caveat.

## Status

- Two findings closed in-place:
  - **F-2031-007 (important)**: DispatcherAdapter
    initial deadline ignored profile rung-0 ack window.
  - **F-2031-008 (nice)**: wake_task::run doc-comment
    drifted from code (referenced legacy `MAX_RUNG` /
    `dispatch_payload` / `RUNG_INTERVAL`).
- One finding raised as **open**:
  - **F-2031-009 (important, SDD-debt)**: per-channel
    subscription filter silently stops applying when the
    operator switches to the engine path.
- Engine state machine, channel walk semantics, and operator-
  ack race all audit clean.

## Hand-off

- **Integration explorer (next PR)**: ship the startup-
  warning stopgap for F-2031-009 (loud warn when
  `escalations_path` is set AND `[notifier.subscriptions]`
  is non-empty). The principled fix (D-5e wiring) ships as
  a separate `feat(sdd-008): D-5e` PR outside the audit
  programme.
- **Docs explorer**: consider documenting the
  `dispatch_payload` vs `dispatch_payload_for_rung`
  distinction in SDD-008 or in the dispatcher module's
  rustdoc. No finding raised — the inline rustdoc on each
  function is already clear.
