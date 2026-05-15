# Phase 7 — tests audit

Audits the **93 new tests** added by the post-Phase-6 cycle
(plus the 4 tests added during Phase 7's prior explorers)
against SDD-005's four-category contract (translation /
pipeline / module-script / seam). Closes **F-2032-006**
(nice — schema-migration upgrade-path coverage gap) in-place
with 2 new tests.

## Methodology

For each post-Phase-6 + Phase-7-explorer test:

1. Sort against SDD-005's four categories.
2. Check for real-time sleeps (SDD-005 prefers
   `tokio::time::pause()` or explicit-`now` driving).
3. Spot-check the test surface against the contract it
   claims to pin.
4. Look for coverage gaps the cycle-as-shipped didn't
   close.

## Test inventory across the post-Phase-6 + Phase-7 cycle

The post-Phase-6 cycle (PRs #140-#146) shipped 93 new tests
(see Phase 7 inventory). Phase 7 explorers added more:

| Surface | New tests | Cycle |
| --- | --- | --- |
| `selfdef-notifier-orchestrator::Subscription` | 6 | PR #140 |
| `selfdef-notifier-engine::dispatcher` (D-5e) | 7 | PR #140 |
| `selfdef-notifier-engine::lib` (D-4 ack_token) | 7 | PR #142 |
| `selfdef-notifier-engine::lib` (`lookup_or_mint_token`) | 3 | PR #150 (Phase 7 module explorer) |
| `selfdef-notifier-engine::lib` (migration idempotency) | 2 | PR #151 (Phase 7 integration explorer) |
| `selfdef-notifier-engine::lib` (migration v1→v3 + v2→v3 upgrade) | 2 | **this PR** |
| `selfdef-daemon::tests::m_notify_engine` | 3 | PR #141 |
| `selfdef-daemon::dispatcher_adapter` (resubmit-stability) | 1 | PR #150 |
| `selfdef-api::tests::m12_api` (D-4 HTTP ack) | 4 | PR #142 |
| `selfdef-config` (post-Phase-6 round-trip) | 2 | PR #151 |
| `selfdef-integration-pagerduty` | 12 | PR #143 |
| `selfdef-integration-loki` | 16 | PR #144 |
| `selfdef-integration-opensearch` | 22 | PR #145 |
| `selfdef-integration-thehive` | 16 | PR #146 |
| **Total** | **103** | — |

(The cycle had 93 tests; Phase 7 explorers added 10 more
including the 2 in this PR.)

## Category-1 (translation) coverage

The 4 Q-G adapters cover translation tests proportionally
to their auth-mode complexity:

- `from_config` rejection tests for every error variant
- `from_config` happy-path round-trip tests
- Severity-map / label tests
- `name_parity` tests (Notifier ↔ Channel ABI agreement)

**Coverage parity is real and proportional.** Confirmed
by Phase 7 recent-PRs explorer's pattern-uniformity table
and Phase 7 crate explorer's cross-crate severity-map
consistency analysis.

## Category-2 (pipeline) coverage

The `EngineHarness` pattern (from PR #141, closing
F-2031-013) is the canonical engine-path pipeline test
scaffolding. Currently used by 3 tests in
`crates/selfdef-daemon/tests/m_notify_engine.rs`:

1. `unacked_notification_refires_at_rung_deadline`
2. `ack_from_separate_process_stops_refires`
3. `audit_mode_persists_but_does_not_fire`

**Gap**: no Category-2 test exercises the **D-4 HTTP ack
flow** end-to-end (submit → channel sends URL with token →
HTTP handler acks via token → take_due returns nothing).
The closest coverage is split between:

- `dispatcher_adapter::tests::resubmit_of_same_event_id_uses_engine_canonical_token`
  (Phase 7 module explorer) — pins adapter ↔ engine
  token-stability, but doesn't go through the HTTP handler.
- `m12_api::notify_ack_known_token_returns_200_and_acks`
  — pins HTTP handler ↔ engine, but doesn't go through the
  adapter mint path.

A full Category-2 test would compose `EngineHarness` +
`ApiState::with_escalation_engine(...)` + `axum::oneshot`.
**No finding** at the tests-audit level — the existing
isolated tests cover all the seams; the composition would
be incremental coverage rather than gap-closure. The
`EngineHarness` rustdoc anticipates graduating it to
`crates/selfdef-daemon/tests/common/` if a second engine-
path follow-up needs it; SDD-008 D-9 (dashboard) would be
the natural trigger.

## Category-4 (seam) coverage

Strong:

- Q-G channel ↔ wiremock seams: 12-16-22-16 tests across
  the 4 adapters, exercising happy-path Notifier + Channel
  ABIs plus auth-header attachment + non-success status
  mapping.
- Engine ↔ HTTP handler seam: `m12_api` 4 D-4 tests
  (503 when unwired / 404 unknown / 200 + ack happy / 404
  on second click).
- Engine ↔ adapter seam: 1 new adapter test from F-2032-005
  closure.

**No finding.**

## Findings

### F-2032-006 (nice, closed-in-place)

**Surface**: `selfdef-notifier-engine` migration tests.

**Pre-fix coverage**: the existing migration tests
(`migration_idempotent_when_re_opening_at_current_version`,
`migration_handles_existing_rows_during_v3_backfill`,
`open_creates_empty_engine`) all start from a **fresh DB**.
The v0 → v1 → v2 → v3 sequence runs on every fresh test,
but no test exercises:

- A v1-shaped DB on disk getting upgraded to v3 (real
  operator-side scenario: an older daemon's database file
  surviving across versions).
- A v2-shaped DB on disk getting upgraded to v3 (same, but
  partial upgrade).

In practice, daemons running v1 or v2 in production are
short-lived (D-5e + D-4 HTTP shipped within days of D-5a).
But the post-Phase-7-F-2032-001 transactional-wrap fix
specifically benefits the upgrade path; without explicit
upgrade-path tests, the integration explorer's fix lives or
dies on the fresh-install tests + manual reasoning.

**Severity = nice**. Coverage gap, not a bug. Closing
makes the F-2032-001 fix's behavior on upgrade paths
test-pinned rather than reasoning-pinned.

**Closed in this PR**:

- `migration_upgrades_v1_database_to_current_schema` —
  hand-writes a v1 schema + a row, sets `user_version = 1`,
  re-opens the engine, verifies the v2 + v3 migrations run
  in their own transactions and the row gets back-filled
  with a 32-char hex `ack_token` while keeping its other
  v1 columns intact.
- `migration_upgrades_v2_database_to_v3` — same shape but
  starting at v2 (with `event_kind` column), verifies the
  v3-only back-fill works without re-running the v2
  migration.

Engine `migration_*` test count: 2 → 4.

## Cross-cycle test-style observations (no findings)

### Real-time sleep usage

`grep -nE 'tokio::time::sleep|thread::sleep'` across the
post-Phase-6 cycle's new crates and tests: **zero hits**
(the only reference is in `m_notify_engine.rs`'s docstring
explaining why the file *avoids* paused-time). The
`process_due_at` pattern + explicit-`now` argument
satisfies SDD-005's pipeline-determinism contract.

### Q-G test-count variance: re-confirmed

| Crate | Tests | Auth modes |
| --- | --- | --- |
| pagerduty | 12 | 1 |
| loki | 16 | 0-1-2 combinations |
| thehive | 16 | 1 |
| opensearch | 22 | 3 (none / basic / apikey) |

Variance tracks auth-mode complexity, not test-style drift.
Phase 7 recent-PRs + crate explorers both verified.

### `EngineHarness` pattern reusability

The harness's `submit_event(event, now)` mirrors the
DispatcherAdapter's `notify` path. Operator-visible surface
not exposed: `ack_link_base`, `subscriptions` map. Future
engine-path tests needing those would extend the harness;
no current test does. **Not a finding** — the harness's
rustdoc explicitly says it's "scoped to this file at v1"
and will graduate to `common/` when a second user appears.

## Status

- F-2032-006 closed in-place (2 new upgrade-path migration
  tests).
- 4 of 8 Phase 7 findings now closed (F-2032-001 schema
  txn, F-2032-003 docs PR-labels, F-2032-004 PD client-
  builder, F-2032-005 adapter token-stability, F-2032-006
  migration upgrade tests).
- Engine 90 → 92 tests; total post-Phase-6 + Phase-7 cycle
  contribution to test surface: 105 tests.

## Hand-off

- **Security explorer**: F-2032-002 token-IS-auth audit.
  Note that the migration upgrade-path is now test-pinned
  — a hostile-input scenario where an attacker controls
  the on-disk DB file would still trip the schema-
  migration safety net (SchemaTooNew error refuses to
  clobber if user_version > 3).
