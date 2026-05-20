//! `selfdef-clock-skew` — pairwise clock-skew tracker.
//!
//! observe(local_ms, remote_ms) computes skew = remote - local
//! and updates running mean (i128 sum) + count + min + max.
//! mean returns sum/count, min/max accessors. Pure data.
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
pub struct ClockSkew {
    /// Schema version.
    pub schema_version: String,
    /// Σ skew (i128 to avoid overflow).
    pub sum_skew: i128,
    /// Count of observations.
    pub count: u64,
    /// Min observed.
    pub min: Option<i64>,
    /// Max observed.
    pub max: Option<i64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SkewError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl ClockSkew {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            sum_skew: 0,
            count: 0,
            min: None,
            max: None,
        }
    }

    /// Observe a pair of timestamps.
    pub fn observe(&mut self, local_ms: i64, remote_ms: i64) {
        let skew = remote_ms - local_ms;
        self.sum_skew += skew as i128;
        self.count = self.count.saturating_add(1);
        self.min = Some(match self.min { Some(m) => m.min(skew), None => skew });
        self.max = Some(match self.max { Some(m) => m.max(skew), None => skew });
    }

    /// Mean skew (None if empty).
    pub fn mean(&self) -> Option<i64> {
        if self.count == 0 { return None; }
        Some((self.sum_skew / self.count as i128) as i64)
    }

    /// Range = max - min (0 if empty).
    pub fn range(&self) -> i64 {
        match (self.min, self.max) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => 0,
        }
    }

    /// Reset.
    pub fn reset(&mut self) {
        self.sum_skew = 0;
        self.count = 0;
        self.min = None;
        self.max = None;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SkewError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SkewError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for ClockSkew {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state() {
        let s = ClockSkew::new();
        assert!(s.mean().is_none());
        assert_eq!(s.range(), 0);
    }

    #[test]
    fn skew_mean() {
        let mut s = ClockSkew::new();
        // remote ahead by 100, 200, 300 ms.
        s.observe(0, 100);
        s.observe(0, 200);
        s.observe(0, 300);
        assert_eq!(s.mean(), Some(200));
        assert_eq!(s.min, Some(100));
        assert_eq!(s.max, Some(300));
        assert_eq!(s.range(), 200);
    }

    #[test]
    fn negative_skew() {
        let mut s = ClockSkew::new();
        s.observe(100, 0); // skew = -100
        s.observe(50, 0);  // skew = -50
        assert_eq!(s.mean(), Some(-75));
    }

    #[test]
    fn reset_clears() {
        let mut s = ClockSkew::new();
        s.observe(0, 100);
        s.reset();
        assert!(s.mean().is_none());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ClockSkew::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SkewError::SchemaMismatch));
    }

    #[test]
    fn skew_serde_roundtrip() {
        let mut s = ClockSkew::new();
        s.observe(0, 100);
        let j = serde_json::to_string(&s).unwrap();
        let back: ClockSkew = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
