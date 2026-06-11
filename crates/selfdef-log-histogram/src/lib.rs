//! `selfdef-log-histogram` — log-bucketed histogram of u64.
//!
//! 64 buckets indexed by floor(log2(value+1)). observe(v) bumps
//! the corresponding bucket. quantile(p_bp) walks buckets in
//! order until cumulative count ≥ p_bp * total / 10000;
//! returns the bucket's lower bound. total / count.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

const N_BUCKETS: usize = 64;

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogHistogram {
    /// Schema version.
    pub schema_version: String,
    /// 64 buckets [bucket_i].
    pub buckets: Vec<u64>,
    /// Total observations.
    pub count: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HistError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad p.
    #[error("p_bp must be 0..=10000")]
    BadPercentile,
    /// Bucket vector is not exactly N_BUCKETS long (corrupt/forged state).
    #[error("buckets must have exactly 64 entries")]
    BadBucketCount,
}

/// Bucket index for a value.
pub fn bucket_for(value: u64) -> usize {
    // value 0 → bucket 0; value 1..=1 → bucket 1 (log2(2)=1); etc.
    let v = value.saturating_add(1);
    let n = 64 - v.leading_zeros() as usize - 1;
    n.min(N_BUCKETS - 1)
}

/// Bucket lower bound (inverse of bucket_for).
pub fn bucket_lower_bound(i: usize) -> u64 {
    if i == 0 {
        0
    } else {
        // Clamp the shift exponent: a valid bucket index is 0..N_BUCKETS (< 64),
        // but this is a `pub fn` and quantile() walks a public, Deserialize-fed
        // `buckets` Vec whose length serde can forge past 64. A raw `1u64 << i`
        // with i >= 64 overflows — debug-panics (DoS) and in release masks to
        // `1u64 << (i % 64)` (silently wrong bound). Clamp to the top bucket.
        (1u64 << i.min(N_BUCKETS - 1)).saturating_sub(1)
    }
}

impl LogHistogram {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: vec![0u64; N_BUCKETS],
            count: 0,
        }
    }

    /// Observe a value.
    pub fn observe(&mut self, value: u64) {
        let b = bucket_for(value);
        self.buckets[b] = self.buckets[b].saturating_add(1);
        self.count = self.count.saturating_add(1);
    }

    /// Quantile in basis points (0..=10000); returns bucket lower bound.
    pub fn quantile(&self, p_bp: u32) -> Result<u64, HistError> {
        if p_bp > 10_000 {
            return Err(HistError::BadPercentile);
        }
        if self.count == 0 {
            return Ok(0);
        }
        let target = (self.count as u128 * p_bp as u128).div_ceil(10_000) as u64;
        let mut cum: u64 = 0;
        for (i, &c) in self.buckets.iter().enumerate() {
            cum = cum.saturating_add(c);
            if cum >= target {
                return Ok(bucket_lower_bound(i));
            }
        }
        Ok(bucket_lower_bound(N_BUCKETS - 1))
    }

    /// Total count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HistError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HistError::SchemaMismatch);
        }
        // new() establishes exactly N_BUCKETS buckets, but serde bypasses the
        // constructor — a restored/forged state can carry any length. Catch the
        // malformed count at the gate (quantile() also self-defends the shift
        // independently, in case validate() is never called).
        if self.buckets.len() != N_BUCKETS {
            return Err(HistError::BadBucketCount);
        }
        Ok(())
    }
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_quantile_is_zero() {
        let h = LogHistogram::new();
        assert_eq!(h.quantile(5000).unwrap(), 0);
    }

    #[test]
    fn bucket_layout() {
        assert_eq!(bucket_for(0), 0); // log2(1)=0
        assert_eq!(bucket_for(1), 1); // log2(2)=1
        assert_eq!(bucket_for(2), 1); // log2(3)=1 (floor)
        assert_eq!(bucket_for(3), 2); // log2(4)=2
        assert_eq!(bucket_for(7), 3); // log2(8)=3
        assert_eq!(bucket_for(8), 3); // log2(9)=3
        assert_eq!(bucket_for(15), 4); // log2(16)=4
    }

    #[test]
    fn quantile_median() {
        let mut h = LogHistogram::new();
        for v in [10u64, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            h.observe(v);
        }
        // 5 in bucket(log2(11..101)) — varies; check non-zero.
        let q = h.quantile(5000).unwrap();
        assert!(q > 0);
    }

    #[test]
    fn quantile_zero_and_full() {
        let mut h = LogHistogram::new();
        for v in 0..10u64 {
            h.observe(v);
        }
        assert_eq!(h.quantile(0).unwrap(), 0);
        // 100th percentile = highest bucket lower bound observed.
        let max_b = h.quantile(10_000).unwrap();
        assert!(max_b > 0);
    }

    #[test]
    fn observe_counts() {
        let mut h = LogHistogram::new();
        h.observe(100);
        h.observe(100);
        assert_eq!(h.count, 2);
    }

    #[test]
    fn bad_percentile_rejected() {
        let h = LogHistogram::new();
        assert!(matches!(
            h.quantile(10_001).unwrap_err(),
            HistError::BadPercentile
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = LogHistogram::new();
        h.schema_version = "9.9.9".into();
        assert!(matches!(
            h.validate().unwrap_err(),
            HistError::SchemaMismatch
        ));
    }

    #[test]
    fn hist_serde_roundtrip() {
        let mut h = LogHistogram::new();
        h.observe(50);
        let j = serde_json::to_string(&h).unwrap();
        let back: LogHistogram = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn quantile_self_defends_against_deserialized_oversized_bucket_vec() {
        // new() builds exactly 64 buckets, but `buckets` is a public field on a
        // Deserialize struct — a restored/forged state can carry more. quantile()
        // calls bucket_lower_bound(i); for i >= 64 the `1u64 << i` shift overflows
        // (debug-panic / release wrong-bound). validate() must also catch the
        // malformed count. Must return a clamped bound without panic.
        let mut buckets = vec![0u64; 100];
        buckets[70] = 5; // mass past index 64
        let h = LogHistogram {
            schema_version: SCHEMA_VERSION.into(),
            buckets,
            count: 5,
        };
        let j = serde_json::to_string(&h).unwrap();
        let restored: LogHistogram = serde_json::from_str(&j).unwrap();
        let q = restored.quantile(5000).expect("quantile ok");
        assert_eq!(q, (1u64 << 63) - 1, "out-of-range index must clamp, not overflow-shift");
        assert!(matches!(restored.validate().unwrap_err(), HistError::BadBucketCount));
        // A well-formed histogram still validates + quantiles correctly.
        let mut ok = LogHistogram::new();
        ok.observe(8);
        assert!(ok.validate().is_ok());
        assert_eq!(ok.quantile(10000).unwrap(), bucket_lower_bound(bucket_for(8)));
    }
}
