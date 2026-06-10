//! `selfdef-metric-histogram` — bucketed IPS-metric histogram.
//!
//! Buckets are operator-chosen upper-bounds (strictly increasing).
//! `observe(value)` increments the lowest bucket whose `upper_bound`
//! is ≥ value (or the implicit overflow bucket at the end if value
//! exceeds the last bucket). `quantile(q_x100)` walks cumulative
//! counts to return the upper-bound of the bucket containing
//! quantile `q / 100` (Prometheus-style approximation).
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
pub struct MetricHistogram {
    /// Schema version.
    pub schema_version: String,
    /// Strictly increasing upper bounds.
    pub bucket_upper_bounds: Vec<u64>,
    /// Counts per bucket; last entry is the +Inf overflow bucket.
    pub counts: Vec<u64>,
    /// Total observations.
    pub total: u64,
    /// Sum of observed values (saturating).
    pub sum: u128,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HistogramError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bucket bounds not strictly increasing.
    #[error("bucket bounds not strictly increasing")]
    BadBuckets,
    /// Empty bucket bounds.
    #[error("bucket bounds empty")]
    NoBuckets,
    /// q out of range.
    #[error("q {0} > 100")]
    QuantileOver100(u16),
    /// counts length doesn't match bounds+1 (corrupt/serde-bypassed state).
    #[error("counts len {counts} must equal bucket_upper_bounds len + 1 ({expected})")]
    BadCountsLen {
        /// Actual counts length.
        counts: usize,
        /// Expected (bounds + 1).
        expected: usize,
    },
}

impl MetricHistogram {
    /// New.
    pub fn new(bucket_upper_bounds: Vec<u64>) -> Result<Self, HistogramError> {
        if bucket_upper_bounds.is_empty() {
            return Err(HistogramError::NoBuckets);
        }
        for w in bucket_upper_bounds.windows(2) {
            if w[0] >= w[1] {
                return Err(HistogramError::BadBuckets);
            }
        }
        let n = bucket_upper_bounds.len() + 1;
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            bucket_upper_bounds,
            counts: vec![0; n],
            total: 0,
            sum: 0,
        })
    }

    /// Observe.
    pub fn observe(&mut self, value: u64) {
        let idx = self
            .bucket_upper_bounds
            .iter()
            .position(|b| *b >= value)
            .unwrap_or(self.bucket_upper_bounds.len()); // overflow
        // new() builds counts with len == bounds.len() + 1, so idx is always a
        // valid index — but serde deserialization can desync the two vecs so
        // idx >= counts.len(). A direct `self.counts[idx]` would then panic
        // (OOB, every build). get_mut drops the observation on a corrupt
        // histogram (fail-safe) and keeps total/sum consistent with what was
        // actually bucketed. In a well-formed histogram the index always hits.
        if let Some(c) = self.counts.get_mut(idx) {
            *c = c.saturating_add(1);
            self.total = self.total.saturating_add(1);
            self.sum = self.sum.saturating_add(value as u128);
        }
    }

    /// Quantile q (0..=100). Returns the upper-bound of the chosen bucket.
    /// For the overflow bucket, returns u64::MAX.
    pub fn quantile(&self, q_x100: u16) -> Result<u64, HistogramError> {
        if q_x100 > 100 {
            return Err(HistogramError::QuantileOver100(q_x100));
        }
        if self.total == 0 {
            return Ok(0);
        }
        let target = (self.total as u128) * (q_x100 as u128) / 100;
        let mut acc: u128 = 0;
        for (i, c) in self.counts.iter().enumerate() {
            acc += *c as u128;
            if acc >= target {
                if i < self.bucket_upper_bounds.len() {
                    return Ok(self.bucket_upper_bounds[i]);
                }
                return Ok(u64::MAX);
            }
        }
        // Fall-through shouldn't happen (target ≤ total).
        Ok(u64::MAX)
    }

    /// Mean (sum / total). Returns 0 when total = 0.
    pub fn mean(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            (self.sum / self.total as u128) as u64
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HistogramError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HistogramError::SchemaMismatch);
        }
        if self.bucket_upper_bounds.is_empty() {
            return Err(HistogramError::NoBuckets);
        }
        for w in self.bucket_upper_bounds.windows(2) {
            if w[0] >= w[1] {
                return Err(HistogramError::BadBuckets);
            }
        }
        let expected = self.bucket_upper_bounds.len() + 1;
        if self.counts.len() != expected {
            return Err(HistogramError::BadCountsLen {
                counts: self.counts.len(),
                expected,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desynced_counts_serde_bypass_does_not_panic() {
        // new() builds counts with len == bounds.len()+1; serde can desync them.
        // observe() computed idx up to bounds.len() then did counts[idx] — a
        // serde-bypassed too-short counts panicked (OOB). get_mut drops the
        // observation (fail-safe); validate() rejects the desync.
        let mut h = MetricHistogram {
            schema_version: SCHEMA_VERSION.into(),
            bucket_upper_bounds: vec![10, 20, 30],
            counts: Vec::new(), // desynced: should be len 4
            total: 0,
            sum: 0,
        };
        h.observe(25); // must not panic
        assert_eq!(h.total, 0); // dropped — nothing bucketed
        assert!(matches!(
            h.validate().unwrap_err(),
            HistogramError::BadCountsLen {
                counts: 0,
                expected: 4
            }
        ));
    }

    #[test]
    fn empty_buckets_rejected() {
        assert!(matches!(
            MetricHistogram::new(vec![]).unwrap_err(),
            HistogramError::NoBuckets
        ));
    }

    #[test]
    fn bad_order_rejected() {
        assert!(matches!(
            MetricHistogram::new(vec![100, 50]).unwrap_err(),
            HistogramError::BadBuckets
        ));
    }

    #[test]
    fn observe_lands_in_bucket() {
        let mut h = MetricHistogram::new(vec![10, 100, 1000]).unwrap();
        h.observe(5); // bucket 0 (≤ 10).
        h.observe(50); // bucket 1.
        h.observe(500); // bucket 2.
        h.observe(5000); // overflow.
        assert_eq!(h.counts, vec![1, 1, 1, 1]);
        assert_eq!(h.total, 4);
    }

    #[test]
    fn quantile_finds_bucket() {
        let mut h = MetricHistogram::new(vec![10, 100, 1000]).unwrap();
        for v in [5, 5, 5, 5, 50, 500] {
            h.observe(v);
        }
        // 6 observations; q=50 → target 3 → bucket 0 (count 4) → upper 10.
        assert_eq!(h.quantile(50).unwrap(), 10);
        // q=100 → target 6 → cumulate to bucket 2 → upper 1000.
        assert_eq!(h.quantile(100).unwrap(), 1000);
    }

    #[test]
    fn quantile_overflow_max() {
        let mut h = MetricHistogram::new(vec![10]).unwrap();
        h.observe(100); // overflow.
        // total=1; q=100 → target 1 → all in overflow → u64::MAX.
        assert_eq!(h.quantile(100).unwrap(), u64::MAX);
    }

    #[test]
    fn quantile_over_100_rejected() {
        let h = MetricHistogram::new(vec![1]).unwrap();
        assert!(matches!(
            h.quantile(150).unwrap_err(),
            HistogramError::QuantileOver100(_)
        ));
    }

    #[test]
    fn empty_returns_zero() {
        let h = MetricHistogram::new(vec![10, 100]).unwrap();
        assert_eq!(h.quantile(50).unwrap(), 0);
        assert_eq!(h.mean(), 0);
    }

    #[test]
    fn mean_correct() {
        let mut h = MetricHistogram::new(vec![10, 100, 1000]).unwrap();
        h.observe(50);
        h.observe(150);
        assert_eq!(h.mean(), 100);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = MetricHistogram::new(vec![10]).unwrap();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HistogramError::SchemaMismatch
        ));
    }

    #[test]
    fn histogram_serde_roundtrip() {
        let mut h = MetricHistogram::new(vec![10, 100, 1000]).unwrap();
        h.observe(50);
        let j = serde_json::to_string(&h).unwrap();
        let back: MetricHistogram = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
