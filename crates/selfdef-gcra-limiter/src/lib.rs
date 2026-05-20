//! `selfdef-gcra-limiter` — GCRA rate limiter.
//!
//! GCRA tracks a Theoretical Arrival Time (TAT). emission_interval
//! = period_ms / capacity, delay_tolerance = burst_ms. arrive(now)
//! is allowed iff now >= TAT - delay_tolerance; on success TAT is
//! advanced by emission_interval (anchored to max(TAT, now)).
//! Otherwise rejected with retry_after = TAT - delay_tolerance - now.
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
pub struct GcraLimiter {
    /// Schema version.
    pub schema_version: String,
    /// Period ms (e.g. 1000 for /sec).
    pub period_ms: u64,
    /// Capacity per period.
    pub capacity: u64,
    /// Allowed burst ms.
    pub burst_ms: u64,
    /// Theoretical Arrival Time ms.
    pub tat_ms: u64,
}

/// Outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "retry_after_ms")]
pub enum Outcome {
    /// Allowed.
    Allow,
    /// Rejected.
    Reject(u64),
}

/// Errors.
#[derive(Debug, Error)]
pub enum GcraError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad config.
    #[error("period_ms and capacity must be >= 1")]
    BadConfig,
}

impl GcraLimiter {
    /// New.
    pub fn new(period_ms: u64, capacity: u64, burst_ms: u64) -> Result<Self, GcraError> {
        if period_ms == 0 || capacity == 0 { return Err(GcraError::BadConfig); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            period_ms, capacity, burst_ms,
            tat_ms: 0,
        })
    }

    fn emission_interval(&self) -> u64 {
        // period / capacity (rounded down; at least 1).
        let i = self.period_ms / self.capacity;
        i.max(1)
    }

    /// Try to admit a cell at now_ms.
    pub fn arrive(&mut self, now_ms: u64) -> Outcome {
        let interval = self.emission_interval();
        // Allowed iff now + burst >= tat.
        if now_ms.saturating_add(self.burst_ms) >= self.tat_ms {
            let base = self.tat_ms.max(now_ms);
            self.tat_ms = base.saturating_add(interval);
            Outcome::Allow
        } else {
            let wait = self.tat_ms - self.burst_ms - now_ms;
            Outcome::Reject(wait)
        }
    }

    /// Peek (does not mutate).
    pub fn peek(&self, now_ms: u64) -> Outcome {
        if now_ms.saturating_add(self.burst_ms) >= self.tat_ms { Outcome::Allow }
        else { Outcome::Reject(self.tat_ms - self.burst_ms - now_ms) }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GcraError> {
        if self.schema_version != SCHEMA_VERSION { return Err(GcraError::SchemaMismatch); }
        if self.period_ms == 0 || self.capacity == 0 { return Err(GcraError::BadConfig); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_arrival_allowed() {
        // 10 per sec → emission = 100ms.
        let mut g = GcraLimiter::new(1000, 10, 0).unwrap();
        assert_eq!(g.arrive(0), Outcome::Allow);
    }

    #[test]
    fn second_immediate_rejected_no_burst() {
        let mut g = GcraLimiter::new(1000, 10, 0).unwrap();
        g.arrive(0);
        match g.arrive(0) {
            Outcome::Reject(retry) => assert_eq!(retry, 100),
            Outcome::Allow => panic!("expected reject"),
        }
    }

    #[test]
    fn after_emission_interval_allowed() {
        let mut g = GcraLimiter::new(1000, 10, 0).unwrap();
        g.arrive(0);
        assert_eq!(g.arrive(100), Outcome::Allow);
    }

    #[test]
    fn burst_allows_multiple() {
        // burst 300ms with emission 100ms → allow 4 cells in burst
        // (0..400 covers TAT 100→200→300→400, all <= now+burst=300
        // for first 4; 5th would need TAT=500 which exceeds now+burst).
        let mut g = GcraLimiter::new(1000, 10, 300).unwrap();
        assert_eq!(g.arrive(0), Outcome::Allow);
        assert_eq!(g.arrive(0), Outcome::Allow);
        assert_eq!(g.arrive(0), Outcome::Allow);
        assert_eq!(g.arrive(0), Outcome::Allow);
        // 5th exceeds burst window.
        assert!(matches!(g.arrive(0), Outcome::Reject(_)));
    }

    #[test]
    fn peek_does_not_consume() {
        let mut g = GcraLimiter::new(1000, 10, 0).unwrap();
        g.arrive(0);
        let p1 = g.peek(50);
        let p2 = g.peek(50);
        assert_eq!(p1, p2);
        assert!(matches!(p1, Outcome::Reject(_)));
    }

    #[test]
    fn bad_config_rejected() {
        assert!(matches!(GcraLimiter::new(0, 10, 0).unwrap_err(), GcraError::BadConfig));
        assert!(matches!(GcraLimiter::new(1000, 0, 0).unwrap_err(), GcraError::BadConfig));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = GcraLimiter::new(1000, 10, 0).unwrap();
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), GcraError::SchemaMismatch));
    }

    #[test]
    fn gcra_serde_roundtrip() {
        let mut g = GcraLimiter::new(1000, 10, 100).unwrap();
        g.arrive(0);
        let j = serde_json::to_string(&g).unwrap();
        let back: GcraLimiter = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
