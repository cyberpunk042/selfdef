//! `selfdef-warmup-ramp` — linear cold-start capacity ramp.
//!
//! cap(now) returns
//!   floor + (target - floor) * elapsed / warmup_ms
//! clamped to [floor, target]. elapsed = now - start_ms (saturating).
//! When elapsed >= warmup_ms the ramp is complete and full target
//! capacity is allowed. Used to avoid thundering-herd retries
//! immediately after restart.
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
pub struct WarmupRamp {
    /// Schema version.
    pub schema_version: String,
    /// Start ts ms.
    pub start_ms: u64,
    /// Warmup window ms.
    pub warmup_ms: u64,
    /// Initial capacity (>= 0).
    pub floor: u64,
    /// Target capacity (>= floor).
    pub target: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WarmupError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero warmup.
    #[error("warmup_ms must be >= 1")]
    ZeroWarmup,
    /// Invalid bounds.
    #[error("target must be >= floor")]
    BadBounds,
}

impl WarmupRamp {
    /// New.
    pub fn new(
        start_ms: u64,
        warmup_ms: u64,
        floor: u64,
        target: u64,
    ) -> Result<Self, WarmupError> {
        if warmup_ms == 0 {
            return Err(WarmupError::ZeroWarmup);
        }
        if target < floor {
            return Err(WarmupError::BadBounds);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            start_ms,
            warmup_ms,
            floor,
            target,
        })
    }

    /// Capacity at now_ms.
    pub fn cap(&self, now_ms: u64) -> u64 {
        let elapsed = now_ms.saturating_sub(self.start_ms);
        if elapsed >= self.warmup_ms {
            return self.target;
        }
        let span = self.target - self.floor;
        // floor + span * elapsed / warmup_ms, integer math.
        let bump = (span as u128 * elapsed as u128 / self.warmup_ms as u128) as u64;
        self.floor + bump
    }

    /// Has ramp completed?
    pub fn ramped(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.start_ms) >= self.warmup_ms
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WarmupError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WarmupError::SchemaMismatch);
        }
        if self.warmup_ms == 0 {
            return Err(WarmupError::ZeroWarmup);
        }
        if self.target < self.floor {
            return Err(WarmupError::BadBounds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_starts_at_floor() {
        let r = WarmupRamp::new(0, 1000, 10, 110).unwrap();
        assert_eq!(r.cap(0), 10);
    }

    #[test]
    fn cap_linear_midway() {
        let r = WarmupRamp::new(0, 1000, 0, 100).unwrap();
        assert_eq!(r.cap(500), 50);
    }

    #[test]
    fn cap_reaches_target_at_end() {
        let r = WarmupRamp::new(0, 1000, 10, 110).unwrap();
        assert_eq!(r.cap(1000), 110);
    }

    #[test]
    fn cap_stays_at_target_after() {
        let r = WarmupRamp::new(0, 1000, 10, 110).unwrap();
        assert_eq!(r.cap(2000), 110);
        assert!(r.ramped(2000));
    }

    #[test]
    fn zero_warmup_rejected() {
        assert!(matches!(
            WarmupRamp::new(0, 0, 0, 1).unwrap_err(),
            WarmupError::ZeroWarmup
        ));
    }

    #[test]
    fn bad_bounds_rejected() {
        assert!(matches!(
            WarmupRamp::new(0, 100, 50, 10).unwrap_err(),
            WarmupError::BadBounds
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = WarmupRamp::new(0, 100, 0, 10).unwrap();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            WarmupError::SchemaMismatch
        ));
    }

    #[test]
    fn ramp_serde_roundtrip() {
        let r = WarmupRamp::new(0, 1000, 5, 100).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: WarmupRamp = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
