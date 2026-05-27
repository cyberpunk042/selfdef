//! `selfdef-clock-skew-tolerance` — event timestamp gating.
//!
//! `accept(event_ts_ms, now_ms)` returns:
//!   * `InWindow { skew_ms }` — within tolerance.
//!   * `TooFarFuture { skew_ms, max_ahead_ms }` — event_ts > now +
//!     max_ahead.
//!   * `TooFarPast { skew_ms, max_behind_ms }` — event_ts < now -
//!     max_behind.
//!
//! Tracks rolling max/min skew observed via `observe(skew_ms)`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClockSkewTolerance {
    /// Schema version.
    pub schema_version: String,
    /// Max ahead.
    pub max_ahead_ms: u64,
    /// Max behind.
    pub max_behind_ms: u64,
    /// Largest positive skew observed.
    pub max_observed_ahead_ms: i64,
    /// Largest negative skew observed.
    pub max_observed_behind_ms: i64,
    /// Total in-window.
    pub accepted_count: u64,
    /// Total rejected.
    pub rejected_count: u64,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SkewVerdict {
    /// Accepted.
    InWindow {
        /// signed skew: event_ts - now (positive = future).
        skew_ms: i64,
    },
    /// Future skew too large.
    TooFarFuture {
        /// skew.
        skew_ms: i64,
        /// limit.
        max_ahead_ms: u64,
    },
    /// Past skew too large.
    TooFarPast {
        /// skew (negative).
        skew_ms: i64,
        /// limit.
        max_behind_ms: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum SkewError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl ClockSkewTolerance {
    /// New.
    pub fn new(max_ahead_ms: u64, max_behind_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_ahead_ms,
            max_behind_ms,
            max_observed_ahead_ms: 0,
            max_observed_behind_ms: 0,
            accepted_count: 0,
            rejected_count: 0,
        }
    }

    /// Pure decision.
    pub fn accept(&self, event_ts_ms: u64, now_ms: u64) -> SkewVerdict {
        let skew = event_ts_ms as i64 - now_ms as i64;
        if skew >= 0 {
            if (skew as u64) > self.max_ahead_ms {
                SkewVerdict::TooFarFuture {
                    skew_ms: skew,
                    max_ahead_ms: self.max_ahead_ms,
                }
            } else {
                SkewVerdict::InWindow { skew_ms: skew }
            }
        } else {
            let behind = (-skew) as u64;
            if behind > self.max_behind_ms {
                SkewVerdict::TooFarPast {
                    skew_ms: skew,
                    max_behind_ms: self.max_behind_ms,
                }
            } else {
                SkewVerdict::InWindow { skew_ms: skew }
            }
        }
    }

    /// Observe (records counters + min/max).
    pub fn observe(&mut self, event_ts_ms: u64, now_ms: u64) -> SkewVerdict {
        let v = self.accept(event_ts_ms, now_ms);
        let skew = event_ts_ms as i64 - now_ms as i64;
        if skew > self.max_observed_ahead_ms {
            self.max_observed_ahead_ms = skew;
        }
        if skew < self.max_observed_behind_ms {
            self.max_observed_behind_ms = skew;
        }
        match v {
            SkewVerdict::InWindow { .. } => {
                self.accepted_count = self.accepted_count.saturating_add(1)
            }
            _ => self.rejected_count = self.rejected_count.saturating_add(1),
        }
        v
    }

    /// Reset stats.
    pub fn reset_stats(&mut self) {
        self.max_observed_ahead_ms = 0;
        self.max_observed_behind_ms = 0;
        self.accepted_count = 0;
        self.rejected_count = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SkewError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SkewError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for ClockSkewTolerance {
    fn default() -> Self {
        Self::new(60_000, 60_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_window_zero_skew() {
        let s = ClockSkewTolerance::new(1000, 1000);
        assert!(matches!(
            s.accept(500, 500),
            SkewVerdict::InWindow { skew_ms: 0 }
        ));
    }

    #[test]
    fn future_within() {
        let s = ClockSkewTolerance::new(1000, 1000);
        match s.accept(1500, 1000) {
            SkewVerdict::InWindow { skew_ms } => assert_eq!(skew_ms, 500),
            _ => panic!(),
        }
    }

    #[test]
    fn past_within() {
        let s = ClockSkewTolerance::new(1000, 1000);
        match s.accept(500, 1000) {
            SkewVerdict::InWindow { skew_ms } => assert_eq!(skew_ms, -500),
            _ => panic!(),
        }
    }

    #[test]
    fn too_far_future() {
        let s = ClockSkewTolerance::new(1000, 1000);
        match s.accept(5000, 1000) {
            SkewVerdict::TooFarFuture {
                skew_ms,
                max_ahead_ms,
            } => {
                assert_eq!(skew_ms, 4000);
                assert_eq!(max_ahead_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn too_far_past() {
        let s = ClockSkewTolerance::new(1000, 1000);
        match s.accept(0, 5000) {
            SkewVerdict::TooFarPast {
                skew_ms,
                max_behind_ms,
            } => {
                assert_eq!(skew_ms, -5000);
                assert_eq!(max_behind_ms, 1000);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn observe_tracks_max_ahead_behind() {
        let mut s = ClockSkewTolerance::new(10_000, 10_000);
        s.observe(5000, 1000); // skew +4000
        s.observe(0, 3000); // skew -3000
        s.observe(7000, 1000); // skew +6000
        assert_eq!(s.max_observed_ahead_ms, 6000);
        assert_eq!(s.max_observed_behind_ms, -3000);
    }

    #[test]
    fn observe_counters() {
        let mut s = ClockSkewTolerance::new(1000, 1000);
        s.observe(500, 1000); // in window
        s.observe(5000, 1000); // too far future
        assert_eq!(s.accepted_count, 1);
        assert_eq!(s.rejected_count, 1);
    }

    #[test]
    fn reset_clears() {
        let mut s = ClockSkewTolerance::new(1000, 1000);
        s.observe(500, 1000);
        s.reset_stats();
        assert_eq!(s.accepted_count, 0);
        assert_eq!(s.max_observed_ahead_ms, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ClockSkewTolerance::new(1, 1);
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SkewError::SchemaMismatch
        ));
    }

    #[test]
    fn skew_serde_roundtrip() {
        let mut s = ClockSkewTolerance::new(1000, 1000);
        s.observe(500, 1000);
        let j = serde_json::to_string(&s).unwrap();
        let back: ClockSkewTolerance = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
