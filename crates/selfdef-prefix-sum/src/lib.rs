//! `selfdef-prefix-sum` — cumulative sums + O(1) range queries.
//!
//! push(value) appends and updates cum_sum. sum_range(lo, hi)
//! returns sum of values[lo..hi] (lo<=hi<=len). total returns
//! the full sum.
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
pub struct PrefixSum {
    /// Schema version.
    pub schema_version: String,
    /// Original values.
    pub values: Vec<i64>,
    /// Cumulative sums: cum[0]=0, cum[i+1] = cum[i] + values[i].
    pub cum: Vec<i128>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SumError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad range.
    #[error("bad range: lo {lo} hi {hi} len {len}")]
    BadRange {
        /// Low.
        lo: usize,
        /// High.
        hi: usize,
        /// Length.
        len: usize,
    },
}

impl PrefixSum {
    /// New (empty).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            values: Vec::new(),
            cum: vec![0],
        }
    }

    /// Push a value.
    pub fn push(&mut self, value: i64) {
        let last = *self.cum.last().unwrap_or(&0);
        self.cum.push(last + value as i128);
        self.values.push(value);
    }

    /// sum of values[lo..hi].
    pub fn sum_range(&self, lo: usize, hi: usize) -> Result<i128, SumError> {
        if lo > hi || hi > self.values.len() {
            return Err(SumError::BadRange { lo, hi, len: self.values.len() });
        }
        Ok(self.cum[hi] - self.cum[lo])
    }

    /// Total.
    pub fn total(&self) -> i128 {
        *self.cum.last().unwrap_or(&0)
    }

    /// Length.
    pub fn len(&self) -> usize { self.values.len() }

    /// Empty?
    pub fn is_empty(&self) -> bool { self.values.is_empty() }

    /// Validate.
    pub fn validate(&self) -> Result<(), SumError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SumError::SchemaMismatch); }
        if self.cum.len() != self.values.len() + 1 {
            return Err(SumError::BadRange { lo: 0, hi: 0, len: self.values.len() });
        }
        Ok(())
    }
}

impl Default for PrefixSum {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_total_zero() {
        let p = PrefixSum::new();
        assert_eq!(p.total(), 0);
    }

    #[test]
    fn push_and_sum_range() {
        let mut p = PrefixSum::new();
        for v in [1, 2, 3, 4, 5] { p.push(v); }
        assert_eq!(p.total(), 15);
        assert_eq!(p.sum_range(0, 5).unwrap(), 15);
        assert_eq!(p.sum_range(1, 4).unwrap(), 9); // 2+3+4
        assert_eq!(p.sum_range(0, 0).unwrap(), 0);
    }

    #[test]
    fn negative_values() {
        let mut p = PrefixSum::new();
        for v in [-5, 10, -3] { p.push(v); }
        assert_eq!(p.total(), 2);
        assert_eq!(p.sum_range(0, 2).unwrap(), 5);
    }

    #[test]
    fn bad_range_rejected() {
        let mut p = PrefixSum::new();
        p.push(1);
        assert!(matches!(p.sum_range(2, 5).unwrap_err(), SumError::BadRange { .. }));
        assert!(matches!(p.sum_range(1, 0).unwrap_err(), SumError::BadRange { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PrefixSum::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), SumError::SchemaMismatch));
    }

    #[test]
    fn prefix_serde_roundtrip() {
        let mut p = PrefixSum::new();
        p.push(1); p.push(2);
        let j = serde_json::to_string(&p).unwrap();
        let back: PrefixSum = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
