//! `selfdef-decision-throttle` — per-subject token-bucket gate.
//!
//! Each subject has a token bucket. `try_consume` consumes a token if
//! available; tokens refill at `refill_per_second` rate, capped at
//! `bucket_capacity`. Caller passes `now_ms`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-subject bucket state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Bucket {
    /// Current token count (float for fractional refill).
    pub tokens: f32,
    /// Last refill epoch-ms.
    pub last_refill_ms: u64,
}

/// Throttle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionThrottle {
    /// Schema version.
    pub schema_version: String,
    /// Bucket capacity.
    pub bucket_capacity: f32,
    /// Refill tokens/sec.
    pub refill_per_second: f32,
    /// Per-subject buckets.
    pub buckets: HashMap<String, Bucket>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ThrottleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// capacity / refill 0.
    #[error("zero capacity or refill")]
    ZeroParams,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Bucket empty.
    #[error("subject {subject} throttled: tokens={tokens:.2}")]
    Throttled {
        /// subject.
        subject: String,
        /// tokens.
        tokens: f32,
    },
}

impl DecisionThrottle {
    /// New throttle.
    pub fn new(bucket_capacity: f32, refill_per_second: f32) -> Result<Self, ThrottleError> {
        if bucket_capacity <= 0.0 || refill_per_second <= 0.0 {
            return Err(ThrottleError::ZeroParams);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            bucket_capacity,
            refill_per_second,
            buckets: HashMap::new(),
        })
    }

    /// Try to consume one token.
    pub fn try_consume(&mut self, subject: &str, now_ms: u64) -> Result<(), ThrottleError> {
        if subject.is_empty() {
            return Err(ThrottleError::EmptySubject);
        }
        let cap = self.bucket_capacity;
        let refill_per_ms = self.refill_per_second / 1000.0;
        let b = self.buckets.entry(subject.into()).or_insert(Bucket {
            tokens: cap,
            last_refill_ms: now_ms,
        });
        // Refill.
        let delta_ms = now_ms.saturating_sub(b.last_refill_ms);
        b.tokens = (b.tokens + delta_ms as f32 * refill_per_ms).min(cap);
        b.last_refill_ms = now_ms;
        if b.tokens < 1.0 {
            return Err(ThrottleError::Throttled {
                subject: subject.into(),
                tokens: b.tokens,
            });
        }
        b.tokens -= 1.0;
        Ok(())
    }

    /// Inspect current tokens (without refilling).
    pub fn tokens(&self, subject: &str) -> Option<f32> {
        self.buckets.get(subject).map(|b| b.tokens)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ThrottleError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ThrottleError::SchemaMismatch);
        }
        if self.bucket_capacity <= 0.0 || self.refill_per_second <= 0.0 {
            return Err(ThrottleError::ZeroParams);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_params_rejected() {
        assert!(matches!(
            DecisionThrottle::new(0.0, 1.0).unwrap_err(),
            ThrottleError::ZeroParams
        ));
        assert!(matches!(
            DecisionThrottle::new(1.0, 0.0).unwrap_err(),
            ThrottleError::ZeroParams
        ));
    }

    #[test]
    fn first_consume_succeeds() {
        let mut t = DecisionThrottle::new(5.0, 1.0).unwrap();
        t.try_consume("alice", 1000).unwrap();
    }

    #[test]
    fn capacity_consumed_then_throttled() {
        let mut t = DecisionThrottle::new(3.0, 0.1).unwrap();
        // Consume 3 quickly.
        t.try_consume("alice", 100).unwrap();
        t.try_consume("alice", 100).unwrap();
        t.try_consume("alice", 100).unwrap();
        assert!(matches!(
            t.try_consume("alice", 100).unwrap_err(),
            ThrottleError::Throttled { .. }
        ));
    }

    #[test]
    fn refill_restores_tokens() {
        let mut t = DecisionThrottle::new(3.0, 10.0).unwrap();
        t.try_consume("alice", 0).unwrap();
        t.try_consume("alice", 0).unwrap();
        t.try_consume("alice", 0).unwrap();
        // 500ms later, ~5 tokens refilled (capped at 3).
        t.try_consume("alice", 500).unwrap();
    }

    #[test]
    fn distinct_subjects_separate() {
        let mut t = DecisionThrottle::new(2.0, 1.0).unwrap();
        t.try_consume("alice", 0).unwrap();
        t.try_consume("alice", 0).unwrap();
        t.try_consume("bob", 0).unwrap();
    }

    #[test]
    fn empty_subject_rejected() {
        let mut t = DecisionThrottle::new(1.0, 1.0).unwrap();
        assert!(matches!(
            t.try_consume("", 0).unwrap_err(),
            ThrottleError::EmptySubject
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = DecisionThrottle::new(1.0, 1.0).unwrap();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            ThrottleError::SchemaMismatch
        ));
    }

    #[test]
    fn throttle_serde_roundtrip() {
        let mut t = DecisionThrottle::new(5.0, 1.0).unwrap();
        t.try_consume("alice", 0).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: DecisionThrottle = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
