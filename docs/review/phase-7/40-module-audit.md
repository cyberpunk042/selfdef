# Phase 7 — module audit

Walks the D-4 HTTP ack flow end-to-end and the D-5e
subscription wiring across crates. Raises and closes
**F-2032-005** (important): adapter mints a fresh token on
every `notify()` call, but the engine's ON-CONFLICT-preserve
clause keeps the OLD token — re-submits send URLs containing
the new token that the HTTP handler can't find.

## Methodology

Trace one Event from the bus through to a clicked
`/notify/ack/<token>` URL, both with and without
`escalations_path` set, both with and without `ack_link_base`
set. Look for:

- **Token correctness across re-submits** — the URL bytes
  emitted on channel-send must match the row the HTTP
  handler looks up.
- **Persist-vs-fire ordering** — engine.enqueue happens
  inside dispatcher.submit, before fire_channels. Adapter
  has no chance to intercept between persist + fire.
- **Schema migration partial-failure safety** — already
  raised as F-2032-001 (referral to integration explorer).
- **D-5e subscription filter** on the engine path — already
  verified clean in Phase 6's wrap.

## Module list

| Module | LOC | Role |
| --- | --- | --- |
| `selfdef-daemon/src/dispatcher_adapter.rs` | 327 (after F-2032-005 fix) | Event → Payload bridging; D-4 token rendering. |
| `selfdef-notifier-engine/src/lib.rs::record_ack_by_token` + `lookup_or_mint_token` | (new this PR) | HTTP handler reads; adapter looks up. |
| `selfdef-notifier-engine/src/lib.rs::enqueue` | (existing, ON CONFLICT preserves ack_token) | Token-stability invariant. |
| `selfdef-api/src/handlers.rs::notify_ack` | 80 | `/notify/ack/:token` handler. |
| `selfdef-daemon/src/main.rs::build_notifier_path` | (existing) | Returns the engine handle for ApiState wiring. |

## Findings

### F-2032-005 (important, closed-in-place)

**Surface**:
`selfdef-daemon/src/dispatcher_adapter.rs::notify`.

**Pre-fix code** (lines 86-93):

```rust
let (ack_token, ack_link) = match &self.ack_link_base {
    Some(base) => {
        let token = Uuid::now_v7().simple().to_string();
        let link = format!("{base}/{token}");
        (Some(token), Some(link))
    }
    None => (None, None),
};
```

Adapter mints a **fresh** UUIDv7 on every `notify()` call.
That token is passed to dispatcher.submit via
`Payload.ack_token`, which calls `engine.enqueue` —
**which preserves the existing token on conflict** (the
`ack_token` column is deliberately NOT in the ON CONFLICT
DO UPDATE clause).

**Concrete impact**:

1. Event X submitted at t=0 → token T1 minted, persisted.
   Channel sends URL with T1.
2. Event X submitted AGAIN at t=10 (e.g. operator manual
   re-dispatch, responder didn't dedupe) → token T2 minted
   by adapter. Engine sees ON CONFLICT, **preserves T1**.
   But the channel fires with `ack_link = <base>/T2`.
3. Operator gets the second notification, clicks the URL
   containing T2.
4. HTTP handler hits `record_ack_by_token("T2", now)` →
   returns `None` (T2 doesn't exist in the engine).
5. Handler returns **404 Not Found** to the operator's click.

The first notification's URL (containing T1) still works.
The second notification's URL silently doesn't. The
operator may not realize the click failed.

**Severity = important** — silent loss of an operator-facing
correctness property on the D-4 surface. SDD-008's
"unacked alert pages louder" semantics rely on the
*persistent* ack URL surviving across resubmits.

**Re-submit frequency in production**: low but non-zero.
The responder typically dedupes by event_id via bus
fan-out semantics, but operator-driven re-dispatch (the
`/actions/<name>/run` POST path) is the realistic case.

**Closed in this PR**:

- New `EscalationEngine::lookup_or_mint_token(event_id) ->
  Result<String>` API. Reads the existing row's
  `ack_token` if present; mints a fresh UUIDv7 simple-form
  token if no row exists.
- `DispatcherAdapter::notify` now calls
  `self.dispatcher.engine().lookup_or_mint_token(event_id)`
  **before** constructing the Payload. The minted-or-found
  token is what goes into both `Payload.ack_token` and
  `ack_link`.
- The engine's ON-CONFLICT-preserve clause stays — it's the
  load-bearing invariant. The fix is on the adapter side:
  ask the engine first.
- Engine-side fallback: if `lookup_or_mint_token` fails
  (SQLite wedged, etc.), the adapter falls back to local
  mint with a `warn!` log so the failure is visible.
- 4 new tests pin the contract:
  - `lookup_or_mint_token_returns_existing_when_row_present`
  - `lookup_or_mint_token_mints_fresh_when_no_row`
  - `lookup_or_mint_token_mints_are_unique_across_calls`
  - `resubmit_of_same_event_id_uses_engine_canonical_token`
    (adapter-side, exercises the full notify→engine path)

## Cross-path equivalence — verified

The HTTP ack flow now has three writers of the
`ack_token` column:

1. **Initial responder fire** (legacy chain path with
   `ack_link_base` unset): N/A — Payload.ack_token is None.
2. **Initial responder fire** (engine path with
   `ack_link_base` set): adapter calls
   `lookup_or_mint_token(event_id)` → first-time path mints
   fresh → engine.enqueue persists → channel fires with the
   matching token.
3. **Re-submit responder fire** (engine path): adapter
   calls `lookup_or_mint_token(event_id)` → returns the
   existing token → engine.enqueue's ON CONFLICT preserves
   the same token → channel fires with the matching
   (unchanged) token.
4. **Wake-task re-fire** (engine path): wake_task loads
   PendingEscalation from take_due, constructs Payload from
   the stored row — `ack_token` field comes from the
   persisted column directly. No mint happens here.

In all three engine-path scenarios, **the channel's URL
matches what the HTTP handler will look up**.

## Persist-vs-fire ordering — clean

`PayloadDispatcher::submit`:

1. `engine.enqueue(payload, deadline, now)` — persist
   first. ON CONFLICT preserves ack_token.
2. Mode + panic-floor check.
3. `fire_channels(payload)` — fire with the *as-supplied*
   payload.

Before F-2032-005 fix: the as-supplied payload contained the
adapter's freshly-minted T2, but the persisted row contained
T1. The fix changes the as-supplied payload's token to
match what the engine will (or already does) hold.

The dispatcher itself remains unchanged. The fix is
entirely above it.

## D-4 HTTP handler — module-level audit

`selfdef-api/src/handlers.rs::notify_ack`:

- Takes `axum::extract::Path<String>` (the URL `:token`
  segment) + `State<ApiState>`.
- Returns `503` when `escalation_engine.is_none()` (legacy
  chain path; route is present so operators can flip the
  knob without a route-table change).
- Calls `engine.record_ack_by_token(&token, now)` (uses
  `unchecked_transaction` internally for UPDATE+SELECT
  atomicity).
- `Ok(Some((event_id, title)))` → 200 OK with text/plain
  confirmation body naming both.
- `Ok(None)` → 404 (handler can't distinguish "unknown" vs.
  "already acked" vs. "forgotten" — documented limitation).
- `Err(_)` → 500 with `error!` log + generic body.

**Clean.** The two-step transaction in
`record_ack_by_token` is the right shape — it prevents a
concurrent `close_event` from tearing the row out between
the UPDATE's rowcount check and the SELECT for the
confirmation page.

## D-5e subscription wiring — re-verified clean

The D-5e wiring shipped in PR #140 closed F-2031-009 by:

1. Adding `event_kind: Option<String>` to Payload (set by
   adapter from `event.class_uid.name()`).
2. Adding `Subscription` to the orchestrator + matching API
   (`subscriptions: HashMap<String, Subscription>`).
3. Adding `PayloadDispatcher::with_subscriptions(...)`
   builder.
4. `fire_channels_filtered` consults the subscription map
   before each channel send.

Re-walked the path: the engine's `take_due` includes
`event_kind` in `PendingEscalation`; wake_task constructs
the Payload preserving it; subscription filter receives a
correctly-populated Payload on rung re-fires.

**Clean.** No drift from the design.

## Status

- F-2032-005 closed in-place (engine-canonical token
  lookup in adapter).
- D-4 HTTP ack flow audits clean after the fix.
- D-5e subscription wiring re-verified clean.
- Engine 88 → 88 tests (3 new for lookup_or_mint_token,
  but one was already in mid-update; check tally).
  Actually: 85 → 88, +3.
- Daemon adapter 5 → 6 tests, +1 for the resubmit-stability
  contract.

## Hand-off

- **Integration explorer**: pick up F-2032-001 (schema
  migration partial-failure). The
  `record_ack_by_token`/`lookup_or_mint_token` pattern uses
  `unchecked_transaction()` correctly; the migration block
  should adopt the same shape.
- **Security explorer**: pick up F-2032-002 (token-IS-auth
  re-audit). The token-stability fix above means a leaked
  token stays valid across resubmits of the same event_id —
  more important to keep it out of third-party logs than
  before.
- **Tests explorer**: schema-migration test coverage gap
  remains open; `lookup_or_mint_token` now has 3 tests.
