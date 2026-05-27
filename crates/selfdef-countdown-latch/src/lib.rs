//! `selfdef-countdown-latch` — open-once latch on N arrivals.
//!
//! Initial count N. arrive(by) decrements (saturating at 0). Once
//! count reaches 0, status flips to Open and stays. Open is
//! irreversible. Excess arrivals are counted but ignored.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Waiting.
    Waiting,
    /// Open.
    Open,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountdownLatch {
    /// Schema version.
    pub schema_version: String,
    /// Initial count.
    pub initial: u32,
    /// Remaining.
    pub remaining: u32,
    /// Total arrivals.
    pub arrivals: u64,
    /// Excess arrivals after open.
    pub excess: u64,
    /// When opened (ms).
    pub opened_at_ms: Option<u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LatchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad count.
    #[error("initial must be >= 1")]
    BadInitial,
    /// Bad arrive.
    #[error("arrive amount must be >= 1")]
    ZeroArrive,
}

impl CountdownLatch {
    /// New.
    pub fn new(initial: u32) -> Result<Self, LatchError> {
        if initial == 0 {
            return Err(LatchError::BadInitial);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            initial,
            remaining: initial,
            arrivals: 0,
            excess: 0,
            opened_at_ms: None,
        })
    }

    /// Arrive once (by N) — returns new Status.
    pub fn arrive(&mut self, by: u32, now_ms: u64) -> Result<Status, LatchError> {
        if by == 0 {
            return Err(LatchError::ZeroArrive);
        }
        self.arrivals = self.arrivals.saturating_add(by as u64);
        if self.remaining == 0 {
            // Already open — excess arrivals counted.
            self.excess = self.excess.saturating_add(by as u64);
            return Ok(Status::Open);
        }
        let new_remaining = self.remaining.saturating_sub(by);
        if new_remaining < self.remaining && self.opened_at_ms.is_none() && new_remaining == 0 {
            self.opened_at_ms = Some(now_ms);
        }
        self.remaining = new_remaining;
        Ok(self.status())
    }

    /// Current status.
    pub fn status(&self) -> Status {
        if self.remaining == 0 {
            Status::Open
        } else {
            Status::Waiting
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LatchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(LatchError::SchemaMismatch);
        }
        if self.initial == 0 {
            return Err(LatchError::BadInitial);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_is_waiting() {
        let l = CountdownLatch::new(3).unwrap();
        assert_eq!(l.status(), Status::Waiting);
    }

    #[test]
    fn opens_at_zero() {
        let mut l = CountdownLatch::new(3).unwrap();
        l.arrive(1, 0).unwrap();
        l.arrive(1, 10).unwrap();
        assert_eq!(l.status(), Status::Waiting);
        l.arrive(1, 20).unwrap();
        assert_eq!(l.status(), Status::Open);
        assert_eq!(l.opened_at_ms, Some(20));
    }

    #[test]
    fn arrive_by_n_at_once() {
        let mut l = CountdownLatch::new(5).unwrap();
        l.arrive(5, 100).unwrap();
        assert_eq!(l.status(), Status::Open);
        assert_eq!(l.opened_at_ms, Some(100));
    }

    #[test]
    fn over_arrival_caps_remaining_at_zero() {
        let mut l = CountdownLatch::new(3).unwrap();
        l.arrive(10, 100).unwrap();
        assert_eq!(l.remaining, 0);
        assert_eq!(l.arrivals, 10);
    }

    #[test]
    fn excess_after_open_counted() {
        let mut l = CountdownLatch::new(2).unwrap();
        l.arrive(2, 0).unwrap();
        l.arrive(1, 100).unwrap();
        l.arrive(2, 200).unwrap();
        assert_eq!(l.excess, 3);
    }

    #[test]
    fn open_is_one_way() {
        let mut l = CountdownLatch::new(1).unwrap();
        l.arrive(1, 50).unwrap();
        // Subsequent arrivals don't reset opened_at.
        l.arrive(5, 200).unwrap();
        assert_eq!(l.opened_at_ms, Some(50));
    }

    #[test]
    fn bad_initial_rejected() {
        assert!(matches!(
            CountdownLatch::new(0).unwrap_err(),
            LatchError::BadInitial
        ));
    }

    #[test]
    fn zero_arrive_rejected() {
        let mut l = CountdownLatch::new(3).unwrap();
        assert!(matches!(
            l.arrive(0, 0).unwrap_err(),
            LatchError::ZeroArrive
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = CountdownLatch::new(3).unwrap();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            LatchError::SchemaMismatch
        ));
    }

    #[test]
    fn latch_serde_roundtrip() {
        let mut l = CountdownLatch::new(3).unwrap();
        l.arrive(2, 50).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: CountdownLatch = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
