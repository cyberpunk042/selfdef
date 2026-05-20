//! `selfdef-monotonic-counter` — advance-only u64 with rollback
//! rejection.
//!
//! observe(value) accepts iff value > last; sets last and counts
//! the advance. observe_eq(value) accepts iff value >= last
//! (idempotent re-delivery). bump() returns last+1 and records.
//! Rejections are counted but do not mutate state.
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
pub struct MonotonicCounter {
    /// Schema version.
    pub schema_version: String,
    /// Last accepted value.
    pub last: u64,
    /// Accepted advances.
    pub advances: u64,
    /// Rejected regressions.
    pub regressions: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Regression.
    #[error("regression: {value} <= {last}")]
    Regression {
        /// Submitted value.
        value: u64,
        /// Current last.
        last: u64,
    },
    /// Overflow.
    #[error("overflow at u64::MAX")]
    Overflow,
}

impl MonotonicCounter {
    /// New (starts at 0).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: 0,
            advances: 0,
            regressions: 0,
        }
    }

    /// Observe strict-advance value.
    pub fn observe(&mut self, value: u64) -> Result<(), CounterError> {
        if value <= self.last {
            self.regressions = self.regressions.saturating_add(1);
            return Err(CounterError::Regression { value, last: self.last });
        }
        self.last = value;
        self.advances = self.advances.saturating_add(1);
        Ok(())
    }

    /// Observe with equality allowed (idempotent re-delivery).
    pub fn observe_eq(&mut self, value: u64) -> Result<bool, CounterError> {
        if value < self.last {
            self.regressions = self.regressions.saturating_add(1);
            return Err(CounterError::Regression { value, last: self.last });
        }
        if value == self.last {
            return Ok(false); // idempotent — no advance recorded
        }
        self.last = value;
        self.advances = self.advances.saturating_add(1);
        Ok(true)
    }

    /// Increment by one.
    pub fn bump(&mut self) -> Result<u64, CounterError> {
        let next = self.last.checked_add(1).ok_or(CounterError::Overflow)?;
        self.last = next;
        self.advances = self.advances.saturating_add(1);
        Ok(next)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CounterError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_accepted() {
        let mut c = MonotonicCounter::new();
        c.observe(1).unwrap();
        c.observe(2).unwrap();
        c.observe(10).unwrap();
        assert_eq!(c.last, 10);
        assert_eq!(c.advances, 3);
    }

    #[test]
    fn equal_rejected_in_strict() {
        let mut c = MonotonicCounter::new();
        c.observe(5).unwrap();
        assert!(matches!(c.observe(5).unwrap_err(), CounterError::Regression { .. }));
        assert_eq!(c.regressions, 1);
        assert_eq!(c.last, 5);
    }

    #[test]
    fn regression_rejected() {
        let mut c = MonotonicCounter::new();
        c.observe(10).unwrap();
        assert!(matches!(c.observe(5).unwrap_err(), CounterError::Regression { .. }));
    }

    #[test]
    fn observe_eq_idempotent() {
        let mut c = MonotonicCounter::new();
        c.observe_eq(5).unwrap();
        assert_eq!(c.observe_eq(5).unwrap(), false);
        assert_eq!(c.advances, 1);
    }

    #[test]
    fn observe_eq_advance() {
        let mut c = MonotonicCounter::new();
        assert_eq!(c.observe_eq(3).unwrap(), true);
        assert_eq!(c.observe_eq(5).unwrap(), true);
    }

    #[test]
    fn observe_eq_regression() {
        let mut c = MonotonicCounter::new();
        c.observe_eq(10).unwrap();
        assert!(c.observe_eq(5).is_err());
    }

    #[test]
    fn bump_increments() {
        let mut c = MonotonicCounter::new();
        assert_eq!(c.bump().unwrap(), 1);
        assert_eq!(c.bump().unwrap(), 2);
        assert_eq!(c.last, 2);
    }

    #[test]
    fn bump_overflow_rejected() {
        let mut c = MonotonicCounter::new();
        c.last = u64::MAX;
        assert!(matches!(c.bump().unwrap_err(), CounterError::Overflow));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = MonotonicCounter::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CounterError::SchemaMismatch));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = MonotonicCounter::new();
        c.observe(42).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: MonotonicCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
