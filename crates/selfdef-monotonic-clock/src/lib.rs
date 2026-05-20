//! `selfdef-monotonic-clock` — clock-advance guard.
//!
//! observe(now_ms) records last_ms iff now_ms >= last_ms. Strict
//! mode (Strict::Yes) rejects equal; otherwise equal is allowed
//! (idempotent re-read). regressions counter bumps on rejection.
//! since_last(now) returns delta (saturating).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Strictness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Strict {
    /// Equal allowed.
    No,
    /// Equal rejected (strict advance).
    Yes,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonotonicClock {
    /// Schema version.
    pub schema_version: String,
    /// Strictness.
    pub strict: Strict,
    /// Last accepted ms.
    pub last_ms: u64,
    /// Advances.
    pub advances: u64,
    /// Regressions.
    pub regressions: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ClockError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Regression.
    #[error("clock regression: {now} <= {last}")]
    Regression {
        /// Submitted.
        now: u64,
        /// Last.
        last: u64,
    },
}

impl MonotonicClock {
    /// New.
    pub fn new(strict: Strict) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            strict,
            last_ms: 0,
            advances: 0,
            regressions: 0,
        }
    }

    /// Observe a clock value.
    pub fn observe(&mut self, now_ms: u64) -> Result<(), ClockError> {
        let regress = match self.strict {
            Strict::Yes => now_ms <= self.last_ms,
            Strict::No => now_ms < self.last_ms,
        };
        if regress {
            self.regressions = self.regressions.saturating_add(1);
            return Err(ClockError::Regression { now: now_ms, last: self.last_ms });
        }
        if now_ms > self.last_ms {
            self.advances = self.advances.saturating_add(1);
        }
        self.last_ms = now_ms;
        Ok(())
    }

    /// Delta from last to now (saturating).
    pub fn since_last(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_ms)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ClockError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ClockError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_advance_only() {
        let mut c = MonotonicClock::new(Strict::Yes);
        c.observe(100).unwrap();
        assert!(matches!(c.observe(100).unwrap_err(), ClockError::Regression { .. }));
        c.observe(101).unwrap();
    }

    #[test]
    fn non_strict_allows_equal() {
        let mut c = MonotonicClock::new(Strict::No);
        c.observe(100).unwrap();
        c.observe(100).unwrap();
        assert_eq!(c.advances, 1);
    }

    #[test]
    fn regression_rejected() {
        let mut c = MonotonicClock::new(Strict::No);
        c.observe(200).unwrap();
        assert!(matches!(c.observe(100).unwrap_err(), ClockError::Regression { .. }));
    }

    #[test]
    fn counters_track() {
        let mut c = MonotonicClock::new(Strict::No);
        c.observe(100).unwrap();
        c.observe(200).unwrap();
        let _ = c.observe(50);
        assert_eq!(c.advances, 2);
        assert_eq!(c.regressions, 1);
    }

    #[test]
    fn since_last() {
        let mut c = MonotonicClock::new(Strict::No);
        c.observe(100).unwrap();
        assert_eq!(c.since_last(150), 50);
        assert_eq!(c.since_last(50), 0); // saturating.
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = MonotonicClock::new(Strict::No);
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), ClockError::SchemaMismatch));
    }

    #[test]
    fn clock_serde_roundtrip() {
        let mut c = MonotonicClock::new(Strict::Yes);
        c.observe(100).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: MonotonicClock = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
