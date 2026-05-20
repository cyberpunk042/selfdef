//! `selfdef-leaky-bucket-shaper` — leaky-bucket smoother.
//!
//! Bucket has capacity (max queued units) + drain_per_sec rate.
//! offer(units, now) drains first, then accepts if fits; else
//! returns Rejected{overflow}. Used to smooth bursty traffic.
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
pub struct LeakyBucketShaper {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u64,
    /// Drain rate per second.
    pub drain_per_sec: u64,
    /// Current level.
    pub level: u64,
    /// Last drain ts.
    pub last_drain_ms: u64,
    /// Sub-second remainder (ms).
    pub remainder_ms: u64,
    /// Accepted count.
    pub accepted_total: u64,
    /// Rejected count.
    pub rejected_total: u64,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OfferVerdict {
    /// Accepted.
    Accepted,
    /// Rejected.
    Rejected {
        /// overflow units.
        overflow: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum ShaperError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero capacity.
    #[error("capacity must be > 0")]
    ZeroCapacity,
}

impl LeakyBucketShaper {
    /// New.
    pub fn new(capacity: u64, drain_per_sec: u64) -> Result<Self, ShaperError> {
        if capacity == 0 { return Err(ShaperError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            drain_per_sec,
            level: 0,
            last_drain_ms: 0,
            remainder_ms: 0,
            accepted_total: 0,
            rejected_total: 0,
        })
    }

    fn drain(&mut self, now_ms: u64) {
        if now_ms <= self.last_drain_ms { return; }
        let elapsed_ms = now_ms - self.last_drain_ms;
        let total_ms = elapsed_ms.saturating_add(self.remainder_ms);
        let drained = total_ms.saturating_mul(self.drain_per_sec) / 1000;
        let consumed_ms = if self.drain_per_sec == 0 {
            total_ms
        } else {
            drained.saturating_mul(1000) / self.drain_per_sec
        };
        self.remainder_ms = total_ms.saturating_sub(consumed_ms);
        self.level = self.level.saturating_sub(drained);
        self.last_drain_ms = now_ms;
    }

    /// Offer units.
    pub fn offer(&mut self, units: u64, now_ms: u64) -> OfferVerdict {
        self.drain(now_ms);
        let available = self.capacity.saturating_sub(self.level);
        if units > available {
            self.rejected_total = self.rejected_total.saturating_add(1);
            OfferVerdict::Rejected { overflow: units - available }
        } else {
            self.level = self.level.saturating_add(units);
            self.accepted_total = self.accepted_total.saturating_add(1);
            OfferVerdict::Accepted
        }
    }

    /// Current level.
    pub fn level(&self) -> u64 {
        self.level
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ShaperError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ShaperError::SchemaMismatch); }
        if self.capacity == 0 { return Err(ShaperError::ZeroCapacity); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_within_capacity() {
        let mut s = LeakyBucketShaper::new(10, 1).unwrap();
        assert_eq!(s.offer(5, 0), OfferVerdict::Accepted);
        assert_eq!(s.level(), 5);
    }

    #[test]
    fn reject_when_full() {
        let mut s = LeakyBucketShaper::new(10, 1).unwrap();
        s.offer(10, 0);
        match s.offer(5, 0) {
            OfferVerdict::Rejected { overflow } => assert_eq!(overflow, 5),
            _ => panic!(),
        }
    }

    #[test]
    fn drain_over_time() {
        let mut s = LeakyBucketShaper::new(10, 5).unwrap(); // 5/sec
        s.offer(10, 0);
        // After 1 second, 5 drained.
        assert_eq!(s.offer(0, 1000), OfferVerdict::Accepted);
        assert_eq!(s.level(), 5);
    }

    #[test]
    fn counters_track() {
        let mut s = LeakyBucketShaper::new(5, 0).unwrap();
        s.offer(3, 0);
        s.offer(10, 0); // rejected
        assert_eq!(s.accepted_total, 1);
        assert_eq!(s.rejected_total, 1);
    }

    #[test]
    fn zero_capacity_rejected() {
        assert!(matches!(LeakyBucketShaper::new(0, 1).unwrap_err(), ShaperError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = LeakyBucketShaper::new(10, 1).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), ShaperError::SchemaMismatch));
    }

    #[test]
    fn shaper_serde_roundtrip() {
        let mut s = LeakyBucketShaper::new(10, 5).unwrap();
        s.offer(3, 0);
        let j = serde_json::to_string(&s).unwrap();
        let back: LeakyBucketShaper = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
