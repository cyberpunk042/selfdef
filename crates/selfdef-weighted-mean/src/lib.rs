//! `selfdef-weighted-mean` — streaming weighted mean.
//!
//! observe(value, weight) accumulates Σ(v*w) + Σw (i128).
//! mean returns Σ(v*w) / Σw when Σw > 0; else None. reset
//! clears state.
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
pub struct WeightedMean {
    /// Schema version.
    pub schema_version: String,
    /// Σ(value × weight).
    pub weighted_sum: i128,
    /// Σ weight.
    pub total_weight: u128,
    /// Observations.
    pub observations: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MeanError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero weight.
    #[error("weight must be >= 1")]
    ZeroWeight,
}

impl WeightedMean {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            weighted_sum: 0,
            total_weight: 0,
            observations: 0,
        }
    }

    /// Observe.
    pub fn observe(&mut self, value: i64, weight: u32) -> Result<(), MeanError> {
        if weight == 0 { return Err(MeanError::ZeroWeight); }
        self.weighted_sum += value as i128 * weight as i128;
        self.total_weight = self.total_weight.saturating_add(weight as u128);
        self.observations = self.observations.saturating_add(1);
        Ok(())
    }

    /// Weighted mean (None if total_weight == 0).
    pub fn mean(&self) -> Option<i64> {
        if self.total_weight == 0 { return None; }
        Some((self.weighted_sum / self.total_weight as i128) as i64)
    }

    /// Reset.
    pub fn reset(&mut self) {
        self.weighted_sum = 0;
        self.total_weight = 0;
        self.observations = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MeanError> {
        if self.schema_version != SCHEMA_VERSION { return Err(MeanError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for WeightedMean {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_mean_none() {
        let m = WeightedMean::new();
        assert!(m.mean().is_none());
    }

    #[test]
    fn equal_weights_mean() {
        let mut m = WeightedMean::new();
        m.observe(10, 1).unwrap();
        m.observe(20, 1).unwrap();
        m.observe(30, 1).unwrap();
        assert_eq!(m.mean(), Some(20));
    }

    #[test]
    fn unequal_weights() {
        let mut m = WeightedMean::new();
        m.observe(10, 1).unwrap();
        m.observe(20, 3).unwrap();
        // (10 + 60) / 4 = 70/4 = 17 (integer).
        assert_eq!(m.mean(), Some(17));
    }

    #[test]
    fn negative_values() {
        let mut m = WeightedMean::new();
        m.observe(-10, 1).unwrap();
        m.observe(10, 1).unwrap();
        assert_eq!(m.mean(), Some(0));
    }

    #[test]
    fn zero_weight_rejected() {
        let mut m = WeightedMean::new();
        assert!(matches!(m.observe(1, 0).unwrap_err(), MeanError::ZeroWeight));
    }

    #[test]
    fn reset_clears() {
        let mut m = WeightedMean::new();
        m.observe(5, 1).unwrap();
        m.reset();
        assert!(m.mean().is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = WeightedMean::new();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), MeanError::SchemaMismatch));
    }

    #[test]
    fn mean_serde_roundtrip() {
        let mut m = WeightedMean::new();
        m.observe(5, 2).unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: WeightedMean = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
