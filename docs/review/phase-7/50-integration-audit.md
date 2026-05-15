# Phase 7 — integration audit

Walks the post-Phase-6 startup-time and config-time seams:
schema migrations on disk (v1 → v2 → v3 sequence,
back-fill + index), `ack_link_base` round-trip, `ApiState`'s
new optional engine handle, the 4 Q-G channel config blocks'
round-trip. Closes **F-2032-001** (schema-migration partial-
failure recovery) in-place.

## Methodology

For each post-Phase-6 operator-facing knob and on-disk state
transition:

1. **Schema migrations** — exercise the v1 → v2 → v3 path on
   a tempdir; verify each block is idempotent on re-open;
   verify partial-failure recovery (in theory, since we can't
   easily simulate disk-full in unit tests).
2. **Config round-trip** — TOML → `Config::load` → typed
   struct, plus the defaults-when-unset contract.
3. **ApiState engine handle** — daemon's `build_notifier_path`
   returns the engine; `main` calls
   `ApiState::with_escalation_engine(...)` only when set.
4. **Wake-task ↔ engine ↔ adapter triangle** — already
   verified clean in the module explorer.

## Findings

### F-2032-001 (nice, closed-in-place)

**Surface**:
`selfdef-notifier-engine/src/lib.rs::migrate`.

**Pre-fix shape**: each `if current < N` block ran the ALTER
+ back-fill + index + `user_version` bump as separate
statements outside a transaction. A failure between steps
(e.g. disk-full on the back-fill UPDATE) left the column
added but `user_version` at the prior level — and the next
daemon restart's migration retry would hit `ALTER TABLE ADD
COLUMN` which is non-idempotent in SQLite → "duplicate
column name" → daemon refuses startup.

**Closed in this PR**: each `if current < N` block now opens
an explicit `unchecked_transaction()`, runs every statement
through `tx.execute_batch(...)`, runs the `user_version`
bump through `tx.pragma_update(...)`, and commits at the
end. A mid-block failure rolls back atomically.

Same pattern `record_ack_by_token` already uses (see the
module explorer's analysis).

Two new tests pin the contract:

- `migration_idempotent_when_re_opening_at_current_version`
  — open + drop + re-open; the post-fix transactional wrap
  shouldn't make idempotent re-runs regress.
- `migration_handles_existing_rows_during_v3_backfill` —
  enqueue with an explicit token, drop, re-open, verify the
  token survives + the v3 back-fill UPDATE is a no-op on
  the already-populated row.

**Why the in-codebase fix is safe**:

- `unchecked_transaction` is the same shape the existing
  `record_ack_by_token` uses. The "unchecked" qualifier
  refers to **not borrowing the Connection** (which is fine
  because the engine's mutex-guarded connection model
  prevents concurrent transactions on the same handle).
- Each migration block stays scoped to one transaction;
  successive blocks (v1 → v2 → v3) run in **separate**
  transactions, so a v1 success + v2 failure leaves the
  database at v1 (correct state, recoverable on retry).
- Production fresh-install path remains the same: first
  open hits all three blocks in three transactions, no
  observable difference.

## Config round-trip — post-Phase-6 surface

Added two new `selfdef-config` tests to pin the
post-Phase-6 TOML shape:

- `sdd_008_post_phase_6_surface_round_trips_from_toml`:
  end-to-end TOML covering `ack_link_base` + all 4 Q-G
  channel blocks (PagerDuty / Loki / OpenSearch / TheHive)
  with realistic values; verifies every field round-trips.
- `sdd_008_post_phase_6_surface_defaults_when_unset`: pins
  the unset-defaults contract — `ack_link_base = None`,
  every Q-G `endpoint = ""` / file-path `None`, all
  defaults-to-disabled.

**`selfdef-config` test count: 6 → 8.**

## ApiState engine handle — re-verified clean

The daemon's `build_notifier_path` returns
`(Arc<dyn Notifier>, Option<JoinHandle<()>>,
Option<Arc<EscalationEngine>>)`. The third tuple element
is non-None only when `[notifier].escalations_path` is set.
`main` then conditionally calls
`ApiState::with_escalation_engine(engine)` only when the
Option is `Some`:

```rust
if let Some(engine) = escalation_engine_for_api.clone() {
    state = state.with_escalation_engine(engine);
}
```

When the daemon is on the legacy chain path, the API state
has `escalation_engine = None`, and the `/notify/ack/:token`
route returns 503. Operators can flip
`[notifier].escalations_path` on at any time without
restarting the API server (well — daemon restart still
applies, but the route table doesn't change).

**Clean.** F-2031-009-class "silent broadening of channel
firing on the wrong path" hazard does not apply here:
the route 503s explicitly rather than silently degrading.

## Schema migration walk

After F-2032-001 fix, the migration flow on a fresh
install:

1. `open(path)` → SQLite creates an empty file.
2. `pragma_query_value("user_version")` → `0`.
3. `if current < 1` block: tx begins; CREATE TABLE +
   CREATE INDEX execute_batch; `user_version = 1`; commit.
4. `if current < 2` block: tx begins; ALTER ADD
   `event_kind`; `user_version = 2`; commit.
5. `if current < 3` block: tx begins; ALTER ADD
   `ack_token`; back-fill UPDATE (no-op on fresh install,
   zero rows); CREATE UNIQUE INDEX; `user_version = 3`;
   commit.
6. Engine returns to caller.

On second open (no changes):

1. `pragma_query_value("user_version")` → `3`.
2. All three `if current < N` guards short-circuit.
3. Engine returns.

On upgrade-from-v2-daemon path (e.g. operator was on D-5e
without D-4 ack, now updates daemon):

1. `pragma_query_value` → `2`.
2. v3 block runs: ALTER + back-fill (any existing rows get
   freshly minted tokens) + index + commit.
3. Engine returns. URLs work for both old and new rows.

## ack_link_base + DispatcherAdapter wiring

Walked the daemon-side wire-up:

- `build_notifier_path` reads `cfg.notifier.ack_link_base`
  and passes it to
  `DispatcherAdapter::new(dispatcher).with_ack_link_base(base)`.
- Adapter's `with_ack_link_base` filters out empty / blank
  strings (`base.filter(|s| !s.trim().is_empty())`), so an
  operator writing `ack_link_base = ""` ends up with
  `None` (HTTP ack disabled, same as omitting the key).
- After F-2032-005 fix, adapter calls
  `engine.lookup_or_mint_token` to get the canonical token
  before constructing the Payload.

**Clean.** The empty-string trimming is operator-friendly:
operators who copy-paste a sample config and forget to
delete the empty value don't accidentally get a half-
configured ack endpoint.

## What's clean

- Schema migrations now transactional (F-2032-001 closure).
- Q-G config blocks round-trip cleanly with sensible
  defaults.
- ApiState engine-handle wiring is conditional, route 503s
  explicitly when handle is missing.
- DispatcherAdapter empty-string trimming for
  `ack_link_base` matches operator-friendly precedent.
- F-2032-005's `lookup_or_mint_token` pattern uses the
  same `unchecked_transaction` shape now applied to
  migrations.

## Status

- F-2032-001 closed in-place (each `if current < N`
  migration block wrapped in `unchecked_transaction()`).
- 2 new engine tests pinning migration idempotency.
- 2 new selfdef-config tests pinning the post-Phase-6
  surface round-trip + defaults.
- Engine 88 → 90 tests; selfdef-config 6 → 8 tests.

## Hand-off

- **Docs explorer** (next): pick up F-2032-003 (Q-G
  commit-label pedantry); verify SDD-008's
  "PR labels — appendix" covers the 4 Q-G commits.
- **Tests explorer**: schema-migration coverage just grew
  (2 new tests); verify the tests-audit posture on
  upgrade-path coverage.
- **Security explorer**: F-2032-002 (token-IS-auth audit).
  Note that the migration now uses transactions like
  `record_ack_by_token` does — consistent style for
  reviewer-facing rigor.
