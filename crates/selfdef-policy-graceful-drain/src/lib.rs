//! `selfdef-policy-graceful-drain` — drain window for policy swap.
//!
//! `begin_drain(now, deadline_ms)` records the start of the drain
//! and the absolute deadline. `observe(in_flight_count, now)`:
//!   * in_flight_count == 0 → `DrainReadyToSwap { reason: Idle }`.
//!   * now >= deadline → `DrainReadyToSwap { reason: TimedOut,
//!     leftover_count: in_flight_count }`.
//!   * else → `DrainContinue { in_flight, remaining_ms }`.
//!
//! `cancel()` aborts the drain.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyGracefulDrain {
    /// Schema version filler — but for Copy compatibility, we use a small marker.
    /// Real schema_version comes from the impl wrapper.
    pub deadline_ms: Option<u64>,
}

/// Wrapper with schema version (separate to keep state Copy-friendly).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GracefulDrain {
    /// Schema version.
    pub schema_version: String,
    /// Inner.
    pub state: PolicyGracefulDrain,
}

/// Drain-ready reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadyReason {
    /// Reached idle count.
    Idle,
    /// Deadline passed with non-zero in-flight.
    TimedOut,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DrainVerdict {
    /// Not currently draining.
    NotDraining,
    /// Continue.
    DrainContinue {
        /// in-flight.
        in_flight: u32,
        /// remaining ms until deadline.
        remaining_ms: u64,
    },
    /// Ready to swap.
    DrainReadyToSwap {
        /// reason.
        reason: ReadyReason,
        /// leftover count when timed out (0 for Idle).
        leftover_count: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum DrainError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl GracefulDrain {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            state: PolicyGracefulDrain { deadline_ms: None },
        }
    }

    /// Begin draining.
    pub fn begin_drain(&mut self, now_ms: u64, drain_ms: u64) {
        self.state.deadline_ms = Some(now_ms.saturating_add(drain_ms));
    }

    /// Cancel.
    pub fn cancel(&mut self) {
        self.state.deadline_ms = None;
    }

    /// Observe.
    pub fn observe(&self, in_flight_count: u32, now_ms: u64) -> DrainVerdict {
        let deadline = match self.state.deadline_ms {
            Some(d) => d,
            None => return DrainVerdict::NotDraining,
        };
        if in_flight_count == 0 {
            return DrainVerdict::DrainReadyToSwap { reason: ReadyReason::Idle, leftover_count: 0 };
        }
        if now_ms >= deadline {
            return DrainVerdict::DrainReadyToSwap {
                reason: ReadyReason::TimedOut,
                leftover_count: in_flight_count,
            };
        }
        DrainVerdict::DrainContinue {
            in_flight: in_flight_count,
            remaining_ms: deadline - now_ms,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DrainError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DrainError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for GracefulDrain {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_draining_by_default() {
        let d = GracefulDrain::new();
        assert_eq!(d.observe(5, 100), DrainVerdict::NotDraining);
    }

    #[test]
    fn idle_ready() {
        let mut d = GracefulDrain::new();
        d.begin_drain(0, 1000);
        let v = d.observe(0, 100);
        assert_eq!(v, DrainVerdict::DrainReadyToSwap {
            reason: ReadyReason::Idle, leftover_count: 0,
        });
    }

    #[test]
    fn continue_during_drain() {
        let mut d = GracefulDrain::new();
        d.begin_drain(0, 1000);
        let v = d.observe(3, 200);
        assert_eq!(v, DrainVerdict::DrainContinue {
            in_flight: 3,
            remaining_ms: 800,
        });
    }

    #[test]
    fn timeout_with_leftover() {
        let mut d = GracefulDrain::new();
        d.begin_drain(0, 1000);
        let v = d.observe(3, 5000);
        assert_eq!(v, DrainVerdict::DrainReadyToSwap {
            reason: ReadyReason::TimedOut,
            leftover_count: 3,
        });
    }

    #[test]
    fn cancel_returns_not_draining() {
        let mut d = GracefulDrain::new();
        d.begin_drain(0, 1000);
        d.cancel();
        assert_eq!(d.observe(5, 100), DrainVerdict::NotDraining);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = GracefulDrain::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DrainError::SchemaMismatch));
    }

    #[test]
    fn drain_serde_roundtrip() {
        let mut d = GracefulDrain::new();
        d.begin_drain(0, 1000);
        let j = serde_json::to_string(&d).unwrap();
        let back: GracefulDrain = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
