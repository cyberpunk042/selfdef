//! `selfdef-saturation-meter` — load classifier.
//!
//! Tracks held / capacity (bp 0..=10000+). classify():
//! Low <= medium_bp; Medium <= high_bp; High <= saturated_bp;
//! Saturated otherwise. Thresholds must be strictly
//! increasing. set_held(n) recomputes.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Saturated.
    Saturated,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SaturationMeter {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Held.
    pub held: u32,
    /// Boundary: <=medium_bp → Low.
    pub medium_bp: u32,
    /// Boundary: <=high_bp → Medium.
    pub high_bp: u32,
    /// Boundary: <=saturated_bp → High; above → Saturated.
    pub saturated_bp: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MeterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be >= 1")]
    ZeroCapacity,
    /// Bad thresholds.
    #[error("thresholds must be strictly increasing")]
    BadThresholds,
}

impl SaturationMeter {
    /// New.
    pub fn new(
        capacity: u32,
        medium_bp: u32,
        high_bp: u32,
        saturated_bp: u32,
    ) -> Result<Self, MeterError> {
        if capacity == 0 {
            return Err(MeterError::ZeroCapacity);
        }
        if !(medium_bp < high_bp && high_bp < saturated_bp) {
            return Err(MeterError::BadThresholds);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            held: 0,
            medium_bp,
            high_bp,
            saturated_bp,
        })
    }

    /// Set held.
    pub fn set_held(&mut self, held: u32) {
        self.held = held;
    }

    /// Utilization in basis points (may exceed 10000 if held > capacity).
    pub fn utilization_bp(&self) -> u32 {
        // new()/validate() reject capacity==0, but serde deserialization can
        // set it directly; the division below would then panic in every build
        // (integer div-by-zero is never masked). A zero-capacity meter admits
        // nothing, so any state is fully saturated — report max (fail-CLOSED,
        // drives backpressure / classify()->Saturated) rather than crash.
        if self.capacity == 0 {
            return u32::MAX;
        }
        let ratio = (self.held as u64 * 10_000) / self.capacity as u64;
        ratio.min(u32::MAX as u64) as u32
    }

    /// Classify current level.
    pub fn classify(&self) -> Level {
        let u = self.utilization_bp();
        if u <= self.medium_bp {
            Level::Low
        } else if u <= self.high_bp {
            Level::Medium
        } else if u <= self.saturated_bp {
            Level::High
        } else {
            Level::Saturated
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MeterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(MeterError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(MeterError::ZeroCapacity);
        }
        if !(self.medium_bp < self.high_bp && self.high_bp < self.saturated_bp) {
            return Err(MeterError::BadThresholds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_serde_bypass_does_not_panic() {
        // new()/validate() reject capacity==0, but serde can construct it. The
        // `/ self.capacity` would panic in every build. Guard reports fully
        // saturated (fail-closed) instead of crashing.
        let m = SaturationMeter {
            schema_version: SCHEMA_VERSION.into(),
            capacity: 0,
            held: 5,
            medium_bp: 5000,
            high_bp: 8000,
            saturated_bp: 9500,
        };
        assert_eq!(m.utilization_bp(), u32::MAX); // must not panic
        assert_eq!(m.classify(), Level::Saturated);
    }

    fn meter() -> SaturationMeter {
        // Thresholds at 25%, 50%, 75%.
        SaturationMeter::new(100, 2500, 5000, 7500).unwrap()
    }

    #[test]
    fn low() {
        let mut m = meter();
        m.set_held(10);
        assert_eq!(m.classify(), Level::Low);
    }

    #[test]
    fn medium() {
        let mut m = meter();
        m.set_held(40);
        assert_eq!(m.classify(), Level::Medium);
    }

    #[test]
    fn high() {
        let mut m = meter();
        m.set_held(70);
        assert_eq!(m.classify(), Level::High);
    }

    #[test]
    fn saturated() {
        let mut m = meter();
        m.set_held(90);
        assert_eq!(m.classify(), Level::Saturated);
    }

    #[test]
    fn over_capacity_is_saturated() {
        let mut m = meter();
        m.set_held(200);
        assert!(m.utilization_bp() > 10_000);
        assert_eq!(m.classify(), Level::Saturated);
    }

    #[test]
    fn at_exact_boundary() {
        let mut m = meter();
        m.set_held(25); // 2500 bp = medium_bp → Low (<=)
        assert_eq!(m.classify(), Level::Low);
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(matches!(
            SaturationMeter::new(0, 10, 20, 30).unwrap_err(),
            MeterError::ZeroCapacity
        ));
        assert!(matches!(
            SaturationMeter::new(10, 50, 30, 40).unwrap_err(),
            MeterError::BadThresholds
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = meter();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            MeterError::SchemaMismatch
        ));
    }

    #[test]
    fn meter_serde_roundtrip() {
        let mut m = meter();
        m.set_held(50);
        let j = serde_json::to_string(&m).unwrap();
        let back: SaturationMeter = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
