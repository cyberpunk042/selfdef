# SDD-081 — Hot-store retention sweep (enforce `hot_retention_days`)

**Status:** implemented
**Author:** selfdef IPS authority chain
**Closes:** F-2026-016 (findings ledger — *was C-003*) — "Dead knob:
`StoreConfig::hot_retention_days` exposed but no sweeper enforces it."
**Owner:** `selfdef-store` (the prune primitive) + `selfdef-daemon` (the
periodic sweep task).
**Last updated:** 2026-06-08.

## Problem

`StoreConfig` exposes `hot_retention_days` (default 30) and the
operator-facing config documents it as the hot-store retention horizon.
But nothing ever enforced it: `selfdef-store` had `insert` / `count` /
`recent` / `get` but **no delete path**, and the daemon never pruned. The
hot SQLite store at `/var/lib/selfdef/state.sqlite` therefore grew
without bound on every deployment — a dead config knob and a real
production-readiness/operability gap (unbounded disk growth on the IPS
host, eventual `state.sqlite` bloat → slow queries → disk pressure that
the disk-usage watchdog would eventually page on, all avoidable).

## Goals

1. Make `hot_retention_days` actually bound the store.
2. Operator-visible enforcement — log the pruned count so retention is
   observable, not silent.
3. Safe defaults: `0` = explicit opt-out (keep forever), never an
   accidental delete-everything.
4. No behavioural change to the hot path (insert/query) and no schema
   change.

## Non-goals

- Cold-store / archival tiering. This SDD bounds the *hot* store only;
  shipping aged events to a cold tier before deletion is a separate
  milestone.
- A per-severity or per-class retention policy. The horizon is a single
  global `hot_retention_days`; differentiated retention is future work.
- A Prometheus gauge for pruned counts — logged for now (journald-
  queryable); a `selfdef_store_retention_pruned_total` counter is a
  cheap follow-up (§ Open questions D-1).

## Design

### Store primitive (`selfdef-store`)

```rust
pub async fn prune_older_than(&self, cutoff_ns: i64) -> Result<u64, StoreError>
```

A single `DELETE FROM events WHERE time_ns < ?1` via the same
`Arc<Mutex<Connection>>` + `spawn_blocking` pattern as `insert`. Returns
the deleted row count. `time_ns` already exists and is indexed-ordered
by the recent queries, so no schema change. Unit test asserts: 3 aged +
2 fresh events → cutoff at 30d prunes exactly the 3, and a second prune
at the same cutoff is idempotent (deletes 0).

### Daemon sweep task (`selfdef-daemon`)

`retention_sweep_loop::run_retention_sweep_loop(store, hot_retention_days,
shutdown)` — a background task spawned alongside the store sink in
`main.rs`, observing the same `CancellationToken` as the other loops.

- `hot_retention_days == 0` → logs the opt-out and exits (retention
  disabled, events kept forever).
- otherwise: an **initial sweep at startup** (bounds a store that may
  already be oversized from a pre-retention deployment), then every
  `SWEEP_INTERVAL_SECS` (6h). Each tick computes
  `cutoff = now - hot_retention_days` (i128 math, clamped to i64) and
  calls `prune_older_than`, logging `deleted` + `remaining` when it
  removes anything. `MissedTickBehavior::Skip` so a slow prune never
  piles up ticks.

`sweep_once` is factored out and unit-tested directly (prunes past the
horizon, keeps fresh events).

## Verification

```
$ cargo test -p selfdef-store --lib
# prune_older_than_deletes_only_events_before_cutoff ... ok  (5 passed)

$ cargo test -p selfdef-daemon --bins retention
# sweep_once_prunes_past_horizon_keeps_fresh ... ok
# sweep_once_keeps_everything_when_all_fresh ... ok          (2 passed)

$ cargo fmt --check && cargo clippy -p selfdef-store -p selfdef-daemon
# clean
```

## Open questions

- **D-1**: Emit a retention counter so Grafana can chart retention
  working? **answered — implemented.** `selfdef-api::Metrics` gained
  `selfdef_store_retention_sweeps_total` + `selfdef_store_retention_pruned_total`
  (cumulative) at `/metrics`, recorded by the sweep loop via
  `record_retention_sweep(pruned)`. `main.rs` now constructs ONE shared
  Metrics handle before the retention + mirror loops (the "small ordering
  tweak") so retention, mirror, and the API ingest task all record into
  the same Arc. With `selfdef_store_events` (live size), an operator can
  chart the store being bounded rather than trust the log line.
- **D-2**: Make `SWEEP_INTERVAL_SECS` configurable via a `[store]`
  field? **Recommendation:** not yet — 6h is fine for a days-granularity
  horizon; add a knob only if an operator needs it.
