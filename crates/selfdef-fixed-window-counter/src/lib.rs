//! `selfdef-fixed-window-counter` — fixed-window rate counter.
//!
//! Window of width window_ms; current_count is the count within
//! the current window-bucket. observe(n, now) advances the bucket
//! (resets to 0) if now crossed into a new bucket, then adds n.
//! Different from sliding-window: bucket boundaries are hard;
//! a burst at the bucket edge can briefly exceed the nominal rate.
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
pub struct FixedWindowCounter {
    /// Schema version.
    pub schema_version: String,
    /// Window width ms.
    pub window_ms: u64,
    /// Start of current bucket ms.
    pub bucket_start_ms: u64,
    /// Count within current bucket.
    pub current_count: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FwcError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero window.
    #[error("window_ms must be >= 1")]
    ZeroWindow,
}

impl FixedWindowCounter {
    /// New.
    pub fn new(window_ms: u64, start_ms: u64) -> Result<Self, FwcError> {
        if window_ms == 0 {
            return Err(FwcError::ZeroWindow);
        }
        let bucket_start_ms = (start_ms / window_ms) * window_ms;
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            bucket_start_ms,
            current_count: 0,
        })
    }

    fn realign(&mut self, now_ms: u64) {
        // Defend against a zero window (serde bypasses new()/validate()): the
        // `now_ms / self.window_ms` below would divide by zero — a panic in
        // debug, crashing the counter. Skip realignment instead, which leaves
        // the count un-reset → the limiter stays at whatever it has accrued
        // (fail-CLOSED: an over-limit corrupt counter keeps denying rather than
        // crashing or silently resetting).
        if self.window_ms == 0 {
            return;
        }
        let cur_bucket = (now_ms / self.window_ms) * self.window_ms;
        if cur_bucket != self.bucket_start_ms {
            self.bucket_start_ms = cur_bucket;
            self.current_count = 0;
        }
    }

    /// Observe n events at now_ms.
    pub fn observe(&mut self, n: u64, now_ms: u64) {
        self.realign(now_ms);
        self.current_count = self.current_count.saturating_add(n);
    }

    /// Current count at now_ms (also advances bucket if crossed).
    pub fn count(&mut self, now_ms: u64) -> u64 {
        self.realign(now_ms);
        self.current_count
    }

    /// Reset.
    pub fn reset(&mut self, now_ms: u64) {
        // Same div-by-zero defense as realign() (serde bypasses new()/validate(),
        // so window_ms can be 0): `now_ms / self.window_ms` would panic in EVERY
        // build. Fail-closed: a corrupt counter is NOT silently cleared to a
        // permissive state (zeroing the count would open a rate limiter); the
        // reset is a no-op rather than a crash or a fail-open clear.
        if self.window_ms == 0 {
            return;
        }
        self.bucket_start_ms = (now_ms / self.window_ms) * self.window_ms;
        self.current_count = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FwcError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FwcError::SchemaMismatch);
        }
        if self.window_ms == 0 {
            return Err(FwcError::ZeroWindow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_accumulates_in_bucket() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.observe(3, 100);
        c.observe(5, 500);
        assert_eq!(c.count(900), 8);
    }

    #[test]
    fn crossing_boundary_resets() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.observe(10, 100);
        // Cross to next bucket [1000, 2000).
        c.observe(2, 1500);
        assert_eq!(c.count(1500), 2);
    }

    #[test]
    fn count_alone_realigns() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.observe(7, 100);
        // No observe in next bucket, but count must read 0 there.
        assert_eq!(c.count(1500), 0);
    }

    #[test]
    fn zero_window_does_not_divide_by_zero() {
        // new()/validate() reject window_ms==0, but serde can construct one
        // directly. realign must not divide by zero (debug panic / crash);
        // it skips realignment, leaving the count intact (fail-closed).
        let mut c = FixedWindowCounter {
            schema_version: SCHEMA_VERSION.into(),
            window_ms: 0,
            bucket_start_ms: 0,
            current_count: 5,
        };
        c.observe(3, 1000); // must not panic
        // No realign happened (window 0) → count accrues, never silently resets.
        assert_eq!(c.count(9_999_999), 8);
    }

    #[test]
    fn zero_window_reset_does_not_divide_by_zero() {
        // Sibling of zero_window_does_not_divide_by_zero, for reset(): new()/
        // validate() reject window_ms==0, but serde can construct one directly.
        // reset() computes `now_ms / self.window_ms` just like realign() — it
        // must not divide by zero (div-by-zero panics in EVERY build, not just
        // debug). Fail-closed like realign: a corrupt counter is NOT silently
        // cleared to a permissive state (which would open a rate limiter); the
        // reset is a no-op rather than a crash or a fail-open clear.
        let mut c = FixedWindowCounter {
            schema_version: SCHEMA_VERSION.into(),
            window_ms: 0,
            bucket_start_ms: 0,
            current_count: 5,
        };
        c.reset(1000); // must not panic
        // Fail-closed: the over-limit count is retained, not reset to 0.
        assert_eq!(c.current_count, 5);
    }

    #[test]
    fn bucket_aligned_to_window_width() {
        let mut c = FixedWindowCounter::new(1000, 1234).unwrap();
        assert_eq!(c.bucket_start_ms, 1000);
        c.observe(1, 1999);
        assert_eq!(c.current_count, 1);
        c.observe(1, 2000);
        // Crossed into [2000, 3000).
        assert_eq!(c.count(2000), 1);
    }

    #[test]
    fn reset_clears() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.observe(10, 100);
        c.reset(500);
        assert_eq!(c.count(500), 0);
    }

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(
            FixedWindowCounter::new(0, 0).unwrap_err(),
            FwcError::ZeroWindow
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            FwcError::SchemaMismatch
        ));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = FixedWindowCounter::new(1000, 0).unwrap();
        c.observe(5, 100);
        let j = serde_json::to_string(&c).unwrap();
        let back: FixedWindowCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
