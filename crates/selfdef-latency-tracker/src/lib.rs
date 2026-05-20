//! `selfdef-latency-tracker` — bounded-window p50/p99 estimator.
//!
//! Stores up to capacity recent latency_us samples in a ring
//! (front-evicted). p50()/p99()/pN(p) sort a clone of the buffer
//! and return the bucket — O(n log n) per query, intended for
//! windows in the hundreds to low-thousands. Faster sketches
//! exist for larger windows.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatencyTracker {
    /// Schema version.
    pub schema_version: String,
    /// Window capacity.
    pub capacity: u32,
    /// Samples in arrival order.
    pub samples: VecDeque<u64>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LatError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero cap.
    #[error("capacity must be >= 1")]
    ZeroCap,
    /// Bad p.
    #[error("p must be in 0..=100")]
    BadP,
    /// Empty.
    #[error("no samples")]
    Empty,
}

impl LatencyTracker {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, LatError> {
        if capacity == 0 { return Err(LatError::ZeroCap); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            samples: VecDeque::new(),
        })
    }

    /// Observe a sample.
    pub fn observe(&mut self, latency_us: u64) {
        self.samples.push_back(latency_us);
        while self.samples.len() > self.capacity as usize {
            self.samples.pop_front();
        }
    }

    /// Reset.
    pub fn reset(&mut self) { self.samples.clear(); }

    /// Count.
    pub fn count(&self) -> usize { self.samples.len() }

    /// Percentile (0..=100). Uses nearest-rank.
    pub fn percentile(&self, p: u8) -> Result<u64, LatError> {
        if p > 100 { return Err(LatError::BadP); }
        if self.samples.is_empty() { return Err(LatError::Empty); }
        let mut sorted: Vec<u64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        // Nearest-rank: ceil(p/100 * n) - 1, clamped to [0, n-1].
        let n = sorted.len() as u128;
        let rank = ((p as u128) * n + 99) / 100;
        let idx = if rank == 0 { 0 } else { (rank - 1) as usize };
        Ok(sorted[idx.min(sorted.len() - 1)])
    }

    /// p50.
    pub fn p50(&self) -> Result<u64, LatError> { self.percentile(50) }
    /// p99.
    pub fn p99(&self) -> Result<u64, LatError> { self.percentile(99) }

    /// Mean.
    pub fn mean(&self) -> Result<u64, LatError> {
        if self.samples.is_empty() { return Err(LatError::Empty); }
        let sum: u128 = self.samples.iter().map(|x| *x as u128).sum();
        Ok((sum / self.samples.len() as u128) as u64)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LatError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LatError::SchemaMismatch); }
        if self.capacity == 0 { return Err(LatError::ZeroCap); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p50_basic() {
        let mut t = LatencyTracker::new(100).unwrap();
        for i in 1..=100u64 { t.observe(i); }
        assert_eq!(t.p50().unwrap(), 50);
    }

    #[test]
    fn p99_basic() {
        let mut t = LatencyTracker::new(100).unwrap();
        for i in 1..=100u64 { t.observe(i); }
        assert_eq!(t.p99().unwrap(), 99);
    }

    #[test]
    fn mean_basic() {
        let mut t = LatencyTracker::new(100).unwrap();
        for i in 1..=100u64 { t.observe(i); }
        assert_eq!(t.mean().unwrap(), 50);
    }

    #[test]
    fn ring_evicts_old() {
        let mut t = LatencyTracker::new(3).unwrap();
        t.observe(10);
        t.observe(20);
        t.observe(30);
        t.observe(40);
        assert_eq!(t.count(), 3);
        assert_eq!(t.p50().unwrap(), 30);
    }

    #[test]
    fn empty_errors() {
        let t = LatencyTracker::new(10).unwrap();
        assert!(matches!(t.p50().unwrap_err(), LatError::Empty));
    }

    #[test]
    fn bad_p_rejected() {
        let mut t = LatencyTracker::new(10).unwrap();
        t.observe(1);
        assert!(matches!(t.percentile(101).unwrap_err(), LatError::BadP));
    }

    #[test]
    fn zero_cap_rejected() {
        assert!(matches!(LatencyTracker::new(0).unwrap_err(), LatError::ZeroCap));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = LatencyTracker::new(10).unwrap();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), LatError::SchemaMismatch));
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut t = LatencyTracker::new(10).unwrap();
        for i in 1..=5u64 { t.observe(i); }
        let j = serde_json::to_string(&t).unwrap();
        let back: LatencyTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
