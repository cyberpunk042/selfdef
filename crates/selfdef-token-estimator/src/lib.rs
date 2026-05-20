//! `selfdef-token-estimator` — rough chars→tokens estimator.
//!
//! Estimate tokens as ceiling(chars / divisor); default divisor
//! is 4. accumulate(text) adds estimate to running total + bumps
//! observation counter. is_over_budget(limit) compares to total.
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
pub struct TokenEstimator {
    /// Schema version.
    pub schema_version: String,
    /// Divisor (default 4).
    pub divisor: u32,
    /// Running total of estimated tokens.
    pub total: u64,
    /// Observations.
    pub observations: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EstError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero divisor.
    #[error("divisor must be >= 1")]
    ZeroDivisor,
}

/// One-shot estimate.
pub fn estimate(text: &str, divisor: u32) -> Result<u64, EstError> {
    if divisor == 0 { return Err(EstError::ZeroDivisor); }
    let chars = text.chars().count() as u64;
    Ok(chars.div_ceil(divisor as u64))
}

impl TokenEstimator {
    /// New (divisor must be >= 1).
    pub fn new(divisor: u32) -> Result<Self, EstError> {
        if divisor == 0 { return Err(EstError::ZeroDivisor); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            divisor,
            total: 0,
            observations: 0,
        })
    }

    /// Accumulate text estimate; returns the estimate for this call.
    pub fn accumulate(&mut self, text: &str) -> Result<u64, EstError> {
        let n = estimate(text, self.divisor)?;
        self.total = self.total.saturating_add(n);
        self.observations = self.observations.saturating_add(1);
        Ok(n)
    }

    /// Over budget?
    pub fn is_over_budget(&self, limit: u64) -> bool {
        self.total > limit
    }

    /// Reset running total.
    pub fn reset(&mut self) {
        self.total = 0;
        self.observations = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EstError> {
        if self.schema_version != SCHEMA_VERSION { return Err(EstError::SchemaMismatch); }
        if self.divisor == 0 { return Err(EstError::ZeroDivisor); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_basic() {
        assert_eq!(estimate("abcd", 4).unwrap(), 1);
        assert_eq!(estimate("abcdefgh", 4).unwrap(), 2);
        // 7 chars / 4 = 1.75 → ceil = 2.
        assert_eq!(estimate("abcdefg", 4).unwrap(), 2);
    }

    #[test]
    fn estimate_empty() {
        assert_eq!(estimate("", 4).unwrap(), 0);
    }

    #[test]
    fn estimate_unicode_chars() {
        // 4 graphemes (chars), not bytes.
        assert_eq!(estimate("αβγδ", 4).unwrap(), 1);
    }

    #[test]
    fn accumulate_tracks_total() {
        let mut e = TokenEstimator::new(4).unwrap();
        e.accumulate("abcd").unwrap();
        e.accumulate("abcdefgh").unwrap();
        assert_eq!(e.total, 3);
        assert_eq!(e.observations, 2);
    }

    #[test]
    fn over_budget() {
        let mut e = TokenEstimator::new(4).unwrap();
        e.accumulate("abcdabcd").unwrap();
        assert!(e.is_over_budget(1));
        assert!(!e.is_over_budget(2));
    }

    #[test]
    fn reset_clears() {
        let mut e = TokenEstimator::new(4).unwrap();
        e.accumulate("abcd").unwrap();
        e.reset();
        assert_eq!(e.total, 0);
        assert_eq!(e.observations, 0);
    }

    #[test]
    fn zero_divisor_rejected() {
        assert!(matches!(TokenEstimator::new(0).unwrap_err(), EstError::ZeroDivisor));
        assert!(matches!(estimate("x", 0).unwrap_err(), EstError::ZeroDivisor));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = TokenEstimator::new(4).unwrap();
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), EstError::SchemaMismatch));
    }

    #[test]
    fn estimator_serde_roundtrip() {
        let mut e = TokenEstimator::new(4).unwrap();
        e.accumulate("abcd").unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: TokenEstimator = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
