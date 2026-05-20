//! `selfdef-metric-quantile-sketch` — bounded-bucket quantile sketch.
//!
//! Observations are bucketed by exponential boundaries:
//! `(0, 1], (1, 2], (2, 4], (4, 8], ...`. The bucket count is fixed
//! at construction. `record(v)` updates the bucket; `quantile(q)`
//! returns the bucket upper-bound at the q-th rank.
//!
//! Approximation: returned values overshoot true values by at most
//! a factor of 2 (the bucket width). Suitable for latency P50/P99
//! visualization, not for exact accounting.
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
pub struct QuantileSketch {
    /// Schema version.
    pub schema_version: String,
    /// Bucket counts. Bucket i covers (2^i - 1, 2^i] for i ≥ 0;
    /// bucket 0 covers (0, 1], bucket 1 covers (1, 2], etc.
    pub buckets: Vec<u64>,
    /// Counts at 0 (or below — saturating).
    pub zero_count: u64,
    /// Observations above the highest bucket's upper bound.
    pub overflow_count: u64,
    /// Total observations.
    pub total: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SketchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero buckets.
    #[error("must have ≥1 bucket")]
    NoBuckets,
    /// Bad quantile.
    #[error("quantile must be in 0.0..=1.0, got {0}")]
    BadQuantile(f64),
}

impl QuantileSketch {
    /// New with given bucket count.
    pub fn new(bucket_count: usize) -> Result<Self, SketchError> {
        if bucket_count == 0 { return Err(SketchError::NoBuckets); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: vec![0; bucket_count],
            zero_count: 0,
            overflow_count: 0,
            total: 0,
        })
    }

    /// Top bound of bucket i: 2^i.
    pub fn bucket_upper(&self, i: usize) -> u64 {
        1u64 << (i.min(63))
    }

    /// Pick bucket index for a value (None = zero, Some(i) = bucket, or overflow).
    fn bucket_for(&self, v: u64) -> BucketSelection {
        if v == 0 {
            return BucketSelection::Zero;
        }
        // ceil(log2(v))
        let i = 64 - (v - 1).leading_zeros() as usize;
        if i < self.buckets.len() {
            BucketSelection::Bucket(i)
        } else {
            BucketSelection::Overflow
        }
    }

    /// Record an observation.
    pub fn record(&mut self, v: u64) {
        self.total = self.total.saturating_add(1);
        match self.bucket_for(v) {
            BucketSelection::Zero => self.zero_count = self.zero_count.saturating_add(1),
            BucketSelection::Overflow => self.overflow_count = self.overflow_count.saturating_add(1),
            BucketSelection::Bucket(i) => {
                self.buckets[i] = self.buckets[i].saturating_add(1);
            }
        }
    }

    /// Quantile estimate (upper bound of the bucket containing the q-th observation).
    pub fn quantile(&self, q: f64) -> Result<u64, SketchError> {
        if !(0.0..=1.0).contains(&q) {
            return Err(SketchError::BadQuantile(q));
        }
        if self.total == 0 { return Ok(0); }
        let target = ((self.total as f64) * q).ceil() as u64;
        let target = target.max(1);
        let mut acc = self.zero_count;
        if acc >= target { return Ok(0); }
        for (i, &n) in self.buckets.iter().enumerate() {
            acc = acc.saturating_add(n);
            if acc >= target {
                return Ok(self.bucket_upper(i));
            }
        }
        // Overflow bucket — return u64::MAX-ish marker = top bucket bound + 1.
        let top = self.bucket_upper(self.buckets.len() - 1);
        Ok(top.saturating_mul(2))
    }

    /// Reset.
    pub fn reset(&mut self) {
        for b in self.buckets.iter_mut() { *b = 0; }
        self.zero_count = 0;
        self.overflow_count = 0;
        self.total = 0;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SketchError> {
        if self.schema_version != SCHEMA_VERSION { return Err(SketchError::SchemaMismatch); }
        if self.buckets.is_empty() { return Err(SketchError::NoBuckets); }
        Ok(())
    }
}

enum BucketSelection {
    Zero,
    Bucket(usize),
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_upper_powers_of_two() {
        let s = QuantileSketch::new(10).unwrap();
        assert_eq!(s.bucket_upper(0), 1);
        assert_eq!(s.bucket_upper(1), 2);
        assert_eq!(s.bucket_upper(5), 32);
    }

    #[test]
    fn record_and_p50() {
        let mut s = QuantileSketch::new(20).unwrap();
        for v in 1..=100 { s.record(v); }
        let p50 = s.quantile(0.5).unwrap();
        // 50th value is 50; bucket containing 50 covers (32, 64].
        assert_eq!(p50, 64);
    }

    #[test]
    fn p99_estimate() {
        let mut s = QuantileSketch::new(20).unwrap();
        for v in 1..=100 { s.record(v); }
        let p99 = s.quantile(0.99).unwrap();
        // 99th value is 99; bucket covers (64, 128].
        assert_eq!(p99, 128);
    }

    #[test]
    fn p100_returns_top_bucket() {
        let mut s = QuantileSketch::new(20).unwrap();
        for _ in 0..10 { s.record(1000); }
        let p100 = s.quantile(1.0).unwrap();
        // 1000 fits in bucket 10 (upper 1024).
        assert_eq!(p100, 1024);
    }

    #[test]
    fn zero_observations() {
        let mut s = QuantileSketch::new(10).unwrap();
        for _ in 0..5 { s.record(0); }
        assert_eq!(s.quantile(0.5).unwrap(), 0);
        assert_eq!(s.zero_count, 5);
    }

    #[test]
    fn overflow_bucket() {
        let mut s = QuantileSketch::new(4).unwrap(); // covers up to 16
        s.record(100);
        assert_eq!(s.overflow_count, 1);
    }

    #[test]
    fn reset_clears() {
        let mut s = QuantileSketch::new(10).unwrap();
        for v in 1..=10 { s.record(v); }
        s.reset();
        assert_eq!(s.total, 0);
        assert_eq!(s.quantile(0.5).unwrap(), 0);
    }

    #[test]
    fn empty_quantile_zero() {
        let s = QuantileSketch::new(10).unwrap();
        assert_eq!(s.quantile(0.99).unwrap(), 0);
    }

    #[test]
    fn bad_quantile_rejected() {
        let s = QuantileSketch::new(10).unwrap();
        assert!(matches!(s.quantile(-0.1).unwrap_err(), SketchError::BadQuantile(_)));
        assert!(matches!(s.quantile(1.5).unwrap_err(), SketchError::BadQuantile(_)));
    }

    #[test]
    fn no_buckets_rejected() {
        assert!(matches!(QuantileSketch::new(0).unwrap_err(), SketchError::NoBuckets));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = QuantileSketch::new(10).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), SketchError::SchemaMismatch));
    }

    #[test]
    fn sketch_serde_roundtrip() {
        let mut s = QuantileSketch::new(10).unwrap();
        for v in 1..=20 { s.record(v); }
        let j = serde_json::to_string(&s).unwrap();
        let back: QuantileSketch = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
