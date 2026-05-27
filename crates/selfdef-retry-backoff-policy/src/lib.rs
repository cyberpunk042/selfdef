//! `selfdef-retry-backoff-policy` — exp-backoff with deterministic jitter.
//!
//! `delay_for_attempt(n, base_ms, max_ms, seed)` returns `(base *
//! 2^(n-1)) capped at max_ms` plus deterministic jitter derived
//! from `seed` (so the same seed always produces the same retry
//! schedule). Pure math.
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
pub struct RetryBackoffPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Jitter ceiling (ms).
    pub jitter_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BackoffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// attempt zero.
    #[error("attempt must be > 0")]
    AttemptZero,
}

fn fnv1a64(s: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let bytes = s.to_le_bytes();
    for b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl RetryBackoffPolicy {
    /// New.
    pub fn new(jitter_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            jitter_ms,
        }
    }

    /// Delay for attempt n (1-based).
    pub fn delay_for_attempt(
        &self,
        n: u32,
        base_ms: u64,
        max_ms: u64,
        seed: u64,
    ) -> Result<u64, BackoffError> {
        if n == 0 {
            return Err(BackoffError::AttemptZero);
        }
        let shift = (n - 1).min(63) as u32;
        let raw = base_ms.checked_shl(shift).unwrap_or(u64::MAX);
        let core = raw.min(max_ms);
        let jitter = if self.jitter_ms == 0 {
            0
        } else {
            let h = fnv1a64(seed.wrapping_add(n as u64));
            h % self.jitter_ms
        };
        Ok(core
            .saturating_add(jitter)
            .min(max_ms.saturating_add(self.jitter_ms)))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BackoffError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BackoffError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for RetryBackoffPolicy {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempt_zero_rejected() {
        let p = RetryBackoffPolicy::new(0);
        assert!(matches!(
            p.delay_for_attempt(0, 100, 10_000, 0).unwrap_err(),
            BackoffError::AttemptZero
        ));
    }

    #[test]
    fn doubles_per_attempt_until_max() {
        let p = RetryBackoffPolicy::new(0);
        assert_eq!(p.delay_for_attempt(1, 100, 10_000, 0).unwrap(), 100);
        assert_eq!(p.delay_for_attempt(2, 100, 10_000, 0).unwrap(), 200);
        assert_eq!(p.delay_for_attempt(3, 100, 10_000, 0).unwrap(), 400);
        // Past max:
        assert_eq!(p.delay_for_attempt(20, 100, 10_000, 0).unwrap(), 10_000);
    }

    #[test]
    fn jitter_deterministic() {
        let p = RetryBackoffPolicy::new(500);
        let a = p.delay_for_attempt(3, 100, 10_000, 42).unwrap();
        let b = p.delay_for_attempt(3, 100, 10_000, 42).unwrap();
        assert_eq!(a, b);
        assert!(a >= 400 && a < 400 + 500);
    }

    #[test]
    fn distinct_seeds_distinct_jitter() {
        let p = RetryBackoffPolicy::new(500);
        let a = p.delay_for_attempt(3, 100, 10_000, 1).unwrap();
        let b = p.delay_for_attempt(3, 100, 10_000, 2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RetryBackoffPolicy::new(0);
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            BackoffError::SchemaMismatch
        ));
    }

    #[test]
    fn backoff_serde_roundtrip() {
        let p = RetryBackoffPolicy::new(100);
        let j = serde_json::to_string(&p).unwrap();
        let back: RetryBackoffPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
