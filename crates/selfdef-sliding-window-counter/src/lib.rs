//! `selfdef-sliding-window-counter` — bucketed sliding window.
//!
//! State holds `bucket_ms` (per-bucket duration) and `bucket_count`
//! buckets covering `window_ms = bucket_ms × bucket_count` of history.
//! `record(n, now)` adds n to the current bucket. `total(now)`
//! rotates buckets if needed, then sums remaining.
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
pub struct SlidingWindowCounter {
    /// Schema version.
    pub schema_version: String,
    /// Per-bucket duration.
    pub bucket_ms: u64,
    /// Bucket count.
    pub bucket_count: usize,
    /// Bucket values (front = oldest).
    pub buckets: VecDeque<u64>,
    /// Start ts of front bucket.
    pub window_start_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero.
    #[error("bucket_ms and bucket_count must be > 0")]
    ZeroSize,
}

impl SlidingWindowCounter {
    /// New.
    pub fn new(bucket_ms: u64, bucket_count: usize, start_ms: u64) -> Result<Self, CounterError> {
        if bucket_ms == 0 || bucket_count == 0 {
            return Err(CounterError::ZeroSize);
        }
        let mut buckets = VecDeque::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            buckets.push_back(0);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            bucket_ms,
            bucket_count,
            buckets,
            window_start_ms: start_ms,
        })
    }

    /// Window length in ms.
    pub fn window_ms(&self) -> u64 {
        self.bucket_ms.saturating_mul(self.bucket_count as u64)
    }

    /// Rotate buckets if time has advanced past the window.
    fn rotate(&mut self, now_ms: u64) {
        // Defend against a zero bucket width (serde bypasses new()/validate()):
        // the `elapsed_past_window_end / self.bucket_ms` below would divide by
        // zero — a panic in debug, crashing the counter. Skip rotation; the
        // window stops sliding so counts accrue (fail-CLOSED) rather than crash.
        if self.bucket_ms == 0 {
            return;
        }
        let last_bucket_end = self
            .window_start_ms
            .saturating_add(self.bucket_ms.saturating_mul(self.bucket_count as u64));
        if now_ms < last_bucket_end {
            // Within current window — no rotation needed.
            return;
        }
        let elapsed_past_window_end = now_ms.saturating_sub(last_bucket_end);
        // Number of new buckets to rotate in (at least 1 since now >= last_end).
        let to_rotate = (elapsed_past_window_end / self.bucket_ms).saturating_add(1) as usize;
        if to_rotate >= self.bucket_count {
            // Whole window is stale — clear all.
            for b in self.buckets.iter_mut() {
                *b = 0;
            }
            // Snap start to current bucket.
            let buckets_since_start =
                (now_ms.saturating_sub(self.window_start_ms)) / self.bucket_ms;
            let advance = buckets_since_start.saturating_sub(self.bucket_count as u64 - 1);
            self.window_start_ms = self
                .window_start_ms
                .saturating_add(advance.saturating_mul(self.bucket_ms));
        } else {
            for _ in 0..to_rotate {
                self.buckets.pop_front();
                self.buckets.push_back(0);
            }
            self.window_start_ms = self
                .window_start_ms
                .saturating_add((to_rotate as u64).saturating_mul(self.bucket_ms));
        }
    }

    /// Record n at now.
    pub fn record(&mut self, n: u64, now_ms: u64) {
        self.rotate(now_ms);
        // The "current" bucket is the last one.
        if let Some(b) = self.buckets.back_mut() {
            *b = b.saturating_add(n);
        }
    }

    /// Total over window (rotates first).
    pub fn total(&mut self, now_ms: u64) -> u64 {
        self.rotate(now_ms);
        self.buckets.iter().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Reset all buckets.
    pub fn reset(&mut self, now_ms: u64) {
        for b in self.buckets.iter_mut() {
            *b = 0;
        }
        self.window_start_ms = now_ms;
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CounterError::SchemaMismatch);
        }
        if self.bucket_ms == 0 || self.bucket_count == 0 {
            return Err(CounterError::ZeroSize);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_in_current() {
        let mut c = SlidingWindowCounter::new(1000, 5, 0).unwrap();
        c.record(10, 0);
        assert_eq!(c.total(0), 10);
    }

    #[test]
    fn rotation_drops_old_buckets() {
        let mut c = SlidingWindowCounter::new(1000, 3, 0).unwrap();
        c.record(10, 0);
        c.record(20, 1500);
        // 0..1000 has 10; 1000..2000 has 20.
        assert_eq!(c.total(2500), 30);
        // After 5000ms, 0..1000 bucket has rolled off.
        c.record(0, 5000);
        let t = c.total(5000);
        // 10 from oldest should be gone.
        assert!(t < 30);
    }

    #[test]
    fn whole_window_clears_after_long_idle() {
        let mut c = SlidingWindowCounter::new(1000, 3, 0).unwrap();
        c.record(50, 100);
        // Skip 60 seconds.
        assert_eq!(c.total(60_000), 0);
    }

    #[test]
    fn window_ms_helper() {
        let c = SlidingWindowCounter::new(1000, 5, 0).unwrap();
        assert_eq!(c.window_ms(), 5000);
    }

    #[test]
    fn reset_clears_all() {
        let mut c = SlidingWindowCounter::new(1000, 3, 0).unwrap();
        c.record(10, 0);
        c.reset(100);
        assert_eq!(c.total(100), 0);
    }

    #[test]
    fn zero_sizes_rejected() {
        assert!(matches!(
            SlidingWindowCounter::new(0, 5, 0).unwrap_err(),
            CounterError::ZeroSize
        ));
        assert!(matches!(
            SlidingWindowCounter::new(1000, 0, 0).unwrap_err(),
            CounterError::ZeroSize
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = SlidingWindowCounter::new(1000, 3, 0).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CounterError::SchemaMismatch
        ));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = SlidingWindowCounter::new(1000, 3, 0).unwrap();
        c.record(10, 0);
        let j = serde_json::to_string(&c).unwrap();
        let back: SlidingWindowCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn zero_bucket_ms_does_not_divide_by_zero() {
        // new()/validate() reject bucket_ms==0, but serde can construct one
        // directly. rotate must not divide by zero (debug panic / crash); it
        // skips rotation, so counts accrue (fail-closed) rather than crash.
        let mut c = SlidingWindowCounter {
            schema_version: SCHEMA_VERSION.into(),
            bucket_ms: 0,
            bucket_count: 4,
            buckets: std::collections::VecDeque::from(vec![0u64; 4]),
            window_start_ms: 0,
        };
        c.record(7, 1000); // must not panic
        assert_eq!(c.total(9_999_999), 7); // must not panic; count retained
    }
}
