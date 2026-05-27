//! `selfdef-event-bus-stats` — per-subscriber dispatch counters.
//!
//! Snapshot of per-Subscriber (delivered, dropped, throttled) counts
//! within a window. The daemon emits one snapshot per cadence;
//! consumers can compute deltas across snapshots for rates.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_bus_subscriber_registry::Subscriber;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-subscriber counter triple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberStats {
    /// Subscriber.
    pub subscriber: Subscriber,
    /// Events delivered.
    pub delivered: u64,
    /// Events dropped (over fan-out budget).
    pub dropped: u64,
    /// Events throttled (delayed but not dropped).
    pub throttled: u64,
}

/// Snapshot envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventBusStats {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC window start.
    pub window_start: String,
    /// ISO-8601 UTC window end.
    pub window_end: String,
    /// Per-subscriber stats (must contain all 9).
    pub per_subscriber: Vec<SubscriberStats>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BusStatsError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 9.
    #[error("per_subscriber count {0} != 9 canonical")]
    CountInvalid(usize),
    /// Missing subscriber.
    #[error("missing subscriber: {0:?}")]
    Missing(Subscriber),
    /// Empty timestamp.
    #[error("missing timestamp: {0}")]
    MissingTimestamp(&'static str),
    /// window_end < window_start.
    #[error("window_end {end} precedes window_start {start}")]
    WindowInverted {
        /// start.
        start: String,
        /// end.
        end: String,
    },
}

const REQUIRED: [Subscriber; 9] = [
    Subscriber::AuditLog,
    Subscriber::Quarantine,
    Subscriber::Notifier,
    Subscriber::EvidenceLedger,
    Subscriber::HistorySink,
    Subscriber::PolicyBus,
    Subscriber::TrustScore,
    Subscriber::ProfileAuthority,
    Subscriber::DashboardManifest,
];

impl EventBusStats {
    /// Canonical empty snapshot.
    pub fn empty_canonical(window_start: &str, window_end: &str) -> Self {
        let per_subscriber = REQUIRED
            .iter()
            .map(|s| SubscriberStats {
                subscriber: *s,
                delivered: 0,
                dropped: 0,
                throttled: 0,
            })
            .collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_start: window_start.into(),
            window_end: window_end.into(),
            per_subscriber,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BusStatsError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BusStatsError::SchemaMismatch);
        }
        if self.window_start.is_empty() {
            return Err(BusStatsError::MissingTimestamp("window_start"));
        }
        if self.window_end.is_empty() {
            return Err(BusStatsError::MissingTimestamp("window_end"));
        }
        if self.window_end < self.window_start {
            return Err(BusStatsError::WindowInverted {
                start: self.window_start.clone(),
                end: self.window_end.clone(),
            });
        }
        if self.per_subscriber.len() != 9 {
            return Err(BusStatsError::CountInvalid(self.per_subscriber.len()));
        }
        for s in REQUIRED {
            if !self.per_subscriber.iter().any(|x| x.subscriber == s) {
                return Err(BusStatsError::Missing(s));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: Subscriber) -> Option<&SubscriberStats> {
        self.per_subscriber.iter().find(|x| x.subscriber == s)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, s: Subscriber) -> Option<&mut SubscriberStats> {
        self.per_subscriber.iter_mut().find(|x| x.subscriber == s)
    }

    /// Total events delivered.
    pub fn total_delivered(&self) -> u64 {
        self.per_subscriber.iter().map(|x| x.delivered).sum()
    }

    /// Total events dropped.
    pub fn total_dropped(&self) -> u64 {
        self.per_subscriber.iter().map(|x| x.dropped).sum()
    }

    /// Drop rate basis points (0..=10_000).
    pub fn drop_rate_bps(&self) -> u32 {
        let delivered = self.total_delivered();
        let dropped = self.total_dropped();
        let denom = delivered + dropped;
        if denom == 0 {
            return 0;
        }
        ((dropped * 10_000) / denom) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_canonical_validates() {
        EventBusStats::empty_canonical("2026-05-19T03:00:00Z", "2026-05-19T03:01:00Z")
            .validate()
            .unwrap();
    }

    #[test]
    fn nine_subscribers_present() {
        let s = EventBusStats::empty_canonical("t", "t");
        for sub in REQUIRED {
            assert!(s.get(sub).is_some(), "missing {sub:?}");
        }
    }

    #[test]
    fn totals_sum() {
        let mut s = EventBusStats::empty_canonical("t", "t");
        s.get_mut(Subscriber::AuditLog).unwrap().delivered = 100;
        s.get_mut(Subscriber::AuditLog).unwrap().dropped = 5;
        s.get_mut(Subscriber::PolicyBus).unwrap().delivered = 50;
        assert_eq!(s.total_delivered(), 150);
        assert_eq!(s.total_dropped(), 5);
    }

    #[test]
    fn drop_rate_zero_when_nothing_delivered() {
        let s = EventBusStats::empty_canonical("t", "t");
        assert_eq!(s.drop_rate_bps(), 0);
    }

    #[test]
    fn drop_rate_computed() {
        let mut s = EventBusStats::empty_canonical("t", "t");
        s.get_mut(Subscriber::AuditLog).unwrap().delivered = 90;
        s.get_mut(Subscriber::AuditLog).unwrap().dropped = 10;
        // 10/100 = 0.1 = 1000 bps
        assert_eq!(s.drop_rate_bps(), 1000);
    }

    #[test]
    fn count_invalid_caught() {
        let mut s = EventBusStats::empty_canonical("t", "t");
        s.per_subscriber.pop();
        assert!(matches!(
            s.validate().unwrap_err(),
            BusStatsError::CountInvalid(8)
        ));
    }

    #[test]
    fn window_inverted_caught() {
        let s = EventBusStats::empty_canonical("2026-05-19T03:00:05Z", "2026-05-19T03:00:00Z");
        assert!(matches!(
            s.validate().unwrap_err(),
            BusStatsError::WindowInverted { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = EventBusStats::empty_canonical("t", "t");
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            BusStatsError::SchemaMismatch
        ));
    }

    #[test]
    fn stats_serde_roundtrip() {
        let s = EventBusStats::empty_canonical("2026-05-19T03:00:00Z", "2026-05-19T03:01:00Z");
        let j = serde_json::to_string(&s).unwrap();
        let back: EventBusStats = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
