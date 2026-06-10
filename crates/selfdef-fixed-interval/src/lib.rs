//! `selfdef-fixed-interval` — fixed-period scheduler.
//!
//! poll(now_ms) returns the count of `period_ms` elapsed since
//! last poll; advances last_tick_ms by that many periods (so
//! drift is bounded). reset(now) restarts.
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
pub struct FixedInterval {
    /// Schema version.
    pub schema_version: String,
    /// Period ms.
    pub period_ms: u64,
    /// Last tick ts ms.
    pub last_tick_ms: u64,
    /// Lifetime ticks.
    pub ticks: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IntervalError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero period.
    #[error("period_ms must be >= 1")]
    ZeroPeriod,
}

impl FixedInterval {
    /// New starting at start_ms.
    pub fn new(period_ms: u64, start_ms: u64) -> Result<Self, IntervalError> {
        if period_ms == 0 {
            return Err(IntervalError::ZeroPeriod);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            period_ms,
            last_tick_ms: start_ms,
            ticks: 0,
        })
    }

    /// Poll; returns count of elapsed periods.
    pub fn poll(&mut self, now_ms: u64) -> u32 {
        // new()/validate() reject period_ms==0, but serde deserialization can
        // set it directly; `elapsed / self.period_ms` would then panic in every
        // build (integer div-by-zero is never masked). A zero period defines no
        // tick cadence — report zero elapsed periods rather than crash.
        if self.period_ms == 0 {
            return 0;
        }
        let elapsed = now_ms.saturating_sub(self.last_tick_ms);
        let n = (elapsed / self.period_ms) as u32;
        if n > 0 {
            self.last_tick_ms = self.last_tick_ms.saturating_add(n as u64 * self.period_ms);
            self.ticks = self.ticks.saturating_add(n as u64);
        }
        n
    }

    /// Reset to start at now_ms.
    pub fn reset(&mut self, now_ms: u64) {
        self.last_tick_ms = now_ms;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IntervalError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IntervalError::SchemaMismatch);
        }
        if self.period_ms == 0 {
            return Err(IntervalError::ZeroPeriod);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_period_serde_bypass_does_not_panic() {
        // new()/validate() reject period_ms==0, but serde can construct it.
        // `elapsed / self.period_ms` would panic in every build. Guard returns
        // 0 elapsed periods instead of crashing.
        let mut i = FixedInterval {
            schema_version: SCHEMA_VERSION.into(),
            period_ms: 0,
            last_tick_ms: 0,
            ticks: 0,
        };
        assert_eq!(i.poll(10_000), 0); // must not panic
    }

    #[test]
    fn no_ticks_within_period() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        assert_eq!(i.poll(500), 0);
    }

    #[test]
    fn one_tick() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        assert_eq!(i.poll(1500), 1);
        assert_eq!(i.last_tick_ms, 1000);
    }

    #[test]
    fn multiple_ticks() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        assert_eq!(i.poll(3500), 3);
        assert_eq!(i.last_tick_ms, 3000);
        assert_eq!(i.ticks, 3);
    }

    #[test]
    fn bounded_drift() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        i.poll(2500);
        assert_eq!(i.last_tick_ms, 2000);
        // Next poll at 3500 picks up 1 more.
        assert_eq!(i.poll(3500), 1);
    }

    #[test]
    fn reset_to_now() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        i.poll(2500);
        i.reset(5000);
        assert_eq!(i.poll(5500), 0);
    }

    #[test]
    fn zero_period_rejected() {
        assert!(matches!(
            FixedInterval::new(0, 0).unwrap_err(),
            IntervalError::ZeroPeriod
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut i = FixedInterval::new(1000, 0).unwrap();
        i.schema_version = "9.9.9".into();
        assert!(matches!(
            i.validate().unwrap_err(),
            IntervalError::SchemaMismatch
        ));
    }

    #[test]
    fn interval_serde_roundtrip() {
        let i = FixedInterval::new(1000, 0).unwrap();
        let j = serde_json::to_string(&i).unwrap();
        let back: FixedInterval = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }
}
