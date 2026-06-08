//! SD-R retention sweep loop (SDD-081) — enforces
//! `StoreConfig::hot_retention_days`.
//!
//! Before this loop the retention horizon was dead config: the knob was
//! parsed but nothing ever deleted aged events, so the hot SQLite store
//! grew without bound (finding F-2026-016; see SDD-081).
//! This task periodically deletes events older than the configured
//! horizon and logs the pruned count so the operator can see retention
//! actually working (observability over the enforcement).
//!
//! Semantics:
//! - `hot_retention_days == 0` → retention DISABLED (keep forever). The
//!   loop logs once and exits; no events are ever deleted. This makes
//!   "0" an explicit operator opt-out rather than an accidental
//!   delete-everything.
//! - otherwise the cutoff each tick is `now - hot_retention_days`, and
//!   every event strictly older than the cutoff is removed.
//!
//! Cadence: an initial sweep shortly after startup (to bound a store
//! that may already be oversized from a pre-retention deployment), then
//! every `SWEEP_INTERVAL_SECS`. Observes the same shutdown token as the
//! other background tasks.

use std::sync::Arc;
use std::time::Duration;

use selfdef_store::SqliteStore;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How often the retention horizon is re-applied. Retention is a
/// coarse-grained horizon (days), so a 6-hour sweep cadence keeps the
/// store bounded without churning the DB.
const SWEEP_INTERVAL_SECS: u64 = 6 * 3600;

/// Nanoseconds in one day.
const NANOS_PER_DAY: i128 = 86_400 * 1_000_000_000;

pub(crate) async fn run_retention_sweep_loop(
    store: Arc<SqliteStore>,
    hot_retention_days: u32,
    shutdown: CancellationToken,
) {
    if hot_retention_days == 0 {
        info!("SD-R retention: hot_retention_days=0 → retention disabled (events kept forever)");
        return;
    }

    info!(
        hot_retention_days,
        sweep_interval_secs = SWEEP_INTERVAL_SECS,
        "SD-R retention: sweep loop running"
    );

    let mut tick = tokio::time::interval(Duration::from_secs(SWEEP_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Do NOT skip the first tick — run an initial sweep at startup so a
    // store that was oversized before retention shipped gets bounded
    // immediately rather than after the first interval.
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("SD-R retention: shutdown signalled; exiting sweep loop");
                return;
            }
            _ = tick.tick() => {
                sweep_once(&store, hot_retention_days).await;
            }
        }
    }
}

/// One retention pass. Isolated for unit testing.
async fn sweep_once(store: &SqliteStore, hot_retention_days: u32) {
    let now_ns = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let cutoff_ns_i128 = now_ns - (i128::from(hot_retention_days) * NANOS_PER_DAY);
    // The store column is i64 nanos; clamp defensively (a cutoff that
    // underflows i64 simply means "delete nothing older than the epoch
    // floor", which is the safe direction).
    let cutoff_ns = cutoff_ns_i128.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;

    match store.prune_older_than(cutoff_ns).await {
        Ok(0) => {
            info!(
                hot_retention_days,
                "SD-R retention: sweep complete; 0 events past horizon"
            );
        }
        Ok(deleted) => {
            let remaining = store.count().await.unwrap_or(0);
            info!(
                hot_retention_days,
                deleted, remaining, "SD-R retention: pruned aged events past horizon"
            );
        }
        Err(e) => {
            warn!(error = %e, "SD-R retention: prune failed; will retry next sweep");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;
    use tempfile::tempdir;
    use time::Duration as TimeDuration;

    fn aged_event(seq: u64, age_days: i64) -> Event {
        let mut e = Event::new(ClassUid::AUTHENTICATION, 1, SeverityId::Low, "h", "t", seq);
        e.time_dt = OffsetDateTime::now_utc() - TimeDuration::days(age_days);
        e
    }

    #[tokio::test]
    async fn sweep_once_prunes_past_horizon_keeps_fresh() {
        let dir = tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("s.sqlite")).unwrap();
        for i in 0..3 {
            store.insert(&aged_event(i, 45)).await.unwrap(); // old
        }
        for i in 3..5 {
            store.insert(&aged_event(i, 2)).await.unwrap(); // fresh
        }
        assert_eq!(store.count().await.unwrap(), 5);

        sweep_once(&store, 30).await;
        assert_eq!(
            store.count().await.unwrap(),
            2,
            "only the 3 aged events pruned"
        );
    }

    #[tokio::test]
    async fn sweep_once_keeps_everything_when_all_fresh() {
        let dir = tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("s.sqlite")).unwrap();
        for i in 0..4 {
            store.insert(&aged_event(i, 1)).await.unwrap();
        }
        sweep_once(&store, 30).await;
        assert_eq!(store.count().await.unwrap(), 4);
    }
}
