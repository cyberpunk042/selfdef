//! `selfdef-bp-math` — basis-points (1/10000) arithmetic.
//!
//! apply(value, bp) = value × bp / 10000 (i128, rounds toward 0).
//! ratio_bp(numer, denom) = numer × 10000 / denom, clamped to
//! u32 max (errors on zero denom). clamp_bp clamps to [0, 10000].
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum BpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero denom.
    #[error("denominator must be != 0")]
    ZeroDenominator,
}

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BpMathState {
    /// Schema version.
    pub schema_version: String,
}

/// value × bp / 10000.
pub fn apply(value: i64, bp: u32) -> i64 {
    let r = (value as i128 * bp as i128) / 10_000;
    r.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// numer × 10000 / denom; saturating to u32::MAX on overflow.
pub fn ratio_bp(numer: u64, denom: u64) -> Result<u32, BpError> {
    if denom == 0 { return Err(BpError::ZeroDenominator); }
    let r = (numer as u128 * 10_000) / denom as u128;
    Ok(r.min(u32::MAX as u128) as u32)
}

/// Clamp to [0, 10000].
pub fn clamp_bp(bp: u32) -> u32 {
    bp.min(10_000)
}

impl BpMathState {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into() }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BpError> {
        if self.schema_version != SCHEMA_VERSION { return Err(BpError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for BpMathState {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_half() {
        assert_eq!(apply(1000, 5000), 500);
    }

    #[test]
    fn apply_full() {
        assert_eq!(apply(1000, 10_000), 1000);
    }

    #[test]
    fn apply_zero() {
        assert_eq!(apply(1000, 0), 0);
    }

    #[test]
    fn apply_negative_value() {
        assert_eq!(apply(-1000, 5000), -500);
    }

    #[test]
    fn ratio_basic() {
        assert_eq!(ratio_bp(500, 1000).unwrap(), 5000);
        assert_eq!(ratio_bp(1000, 1000).unwrap(), 10_000);
        assert_eq!(ratio_bp(0, 1000).unwrap(), 0);
    }

    #[test]
    fn ratio_over_100pct() {
        assert_eq!(ratio_bp(2000, 1000).unwrap(), 20_000);
    }

    #[test]
    fn ratio_zero_denom_rejected() {
        assert!(matches!(ratio_bp(100, 0).unwrap_err(), BpError::ZeroDenominator));
    }

    #[test]
    fn clamp_bp_basic() {
        assert_eq!(clamp_bp(5000), 5000);
        assert_eq!(clamp_bp(15_000), 10_000);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = BpMathState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), BpError::SchemaMismatch));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = BpMathState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: BpMathState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
