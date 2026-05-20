//! `selfdef-decay-counter` — time-decayed counter.
//!
//! observe(n, now) advances last_ts: value = max(0, value -
//! decay_per_sec*(now-last)/1000); then value += n.
//! value(now) returns the decayed value without mutating.
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
pub struct DecayCounter {
    /// Schema version.
    pub schema_version: String,
    /// Decay rate (units per second).
    pub decay_per_sec: u64,
    /// Last update ts ms.
    pub last_ts_ms: u64,
    /// Last stored value.
    pub stored: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DecayError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero rate.
    #[error("decay_per_sec must be >= 1")]
    ZeroRate,
}

impl DecayCounter {
    /// New.
    pub fn new(decay_per_sec: u64, start_ms: u64) -> Result<Self, DecayError> {
        if decay_per_sec == 0 { return Err(DecayError::ZeroRate); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            decay_per_sec,
            last_ts_ms: start_ms,
            stored: 0,
        })
    }

    fn decayed_value(&self, now_ms: u64) -> u64 {
        let elapsed_ms = now_ms.saturating_sub(self.last_ts_ms);
        let decay = (self.decay_per_sec as u128 * elapsed_ms as u128 / 1000) as u64;
        self.stored.saturating_sub(decay)
    }

    /// Observe new contribution.
    pub fn observe(&mut self, n: u64, now_ms: u64) {
        let decayed = self.decayed_value(now_ms);
        self.stored = decayed.saturating_add(n);
        self.last_ts_ms = now_ms;
    }

    /// Current decayed value (does not mutate).
    pub fn value(&self, now_ms: u64) -> u64 {
        self.decayed_value(now_ms)
    }

    /// Reset.
    pub fn reset(&mut self, now_ms: u64) {
        self.stored = 0;
        self.last_ts_ms = now_ms;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DecayError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DecayError::SchemaMismatch); }
        if self.decay_per_sec == 0 { return Err(DecayError::ZeroRate); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_no_decay_yet() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(100, 0);
        assert_eq!(c.value(0), 100);
    }

    #[test]
    fn linear_decay() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(100, 0);
        // After 5s at 10/s decay → 50.
        assert_eq!(c.value(5000), 50);
    }

    #[test]
    fn saturates_at_zero() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(100, 0);
        assert_eq!(c.value(1_000_000), 0);
    }

    #[test]
    fn observe_advances_with_decay() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(100, 0);
        c.observe(50, 5000); // 100 decayed to 50, then +50 = 100.
        assert_eq!(c.value(5000), 100);
    }

    #[test]
    fn reset_clears() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(100, 0);
        c.reset(0);
        assert_eq!(c.value(0), 0);
    }

    #[test]
    fn zero_rate_rejected() {
        assert!(matches!(DecayCounter::new(0, 0).unwrap_err(), DecayError::ZeroRate));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), DecayError::SchemaMismatch));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = DecayCounter::new(10, 0).unwrap();
        c.observe(50, 100);
        let j = serde_json::to_string(&c).unwrap();
        let back: DecayCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
