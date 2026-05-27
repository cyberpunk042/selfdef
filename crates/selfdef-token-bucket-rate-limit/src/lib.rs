//! `selfdef-token-bucket-rate-limit` — token bucket rate limiter.
//!
//! Each `Bucket { capacity, refill_per_sec, tokens, last_refill_ms }`
//! tracks a single token bucket. `try_acquire(bucket, cost, now_ms)`
//! refills based on elapsed time (capped at `capacity`), then
//! returns:
//!   * `Granted` — `cost` tokens consumed.
//!   * `Throttled { available, requested }` — insufficient tokens.
//!   * `Unknown` — bucket not registered.
//!
//! All math is integer; partial-token accrual carries via a `remainder_ms`
//! field per bucket. This makes the limiter deterministic and easy
//! to test.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bucket {
    /// Capacity (max tokens).
    pub capacity: u64,
    /// Refill per second.
    pub refill_per_sec: u64,
    /// Current tokens.
    pub tokens: u64,
    /// Last refill ts.
    pub last_refill_ms: u64,
    /// Sub-second remainder (ms not yet converted to a token).
    pub remainder_ms: u64,
    /// Granted total.
    pub granted_total: u64,
    /// Throttled total.
    pub throttled_total: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenBucketRateLimit {
    /// Schema version.
    pub schema_version: String,
    /// bucket id → bucket.
    pub buckets: BTreeMap<String, Bucket>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AcquireVerdict {
    /// Granted.
    Granted,
    /// Throttled.
    Throttled {
        /// available.
        available: u64,
        /// requested.
        requested: u64,
    },
    /// Unknown.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BucketError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("bucket id empty")]
    EmptyId,
    /// Zero capacity.
    #[error("capacity must be > 0")]
    ZeroCapacity,
}

fn refill(b: &mut Bucket, now_ms: u64) {
    if now_ms <= b.last_refill_ms {
        return;
    }
    let elapsed_ms = now_ms - b.last_refill_ms;
    let total_ms = elapsed_ms.saturating_add(b.remainder_ms);
    // tokens to add = total_ms × refill / 1000
    let added = total_ms.saturating_mul(b.refill_per_sec) / 1000;
    let consumed_ms = if b.refill_per_sec == 0 {
        // No refill — keep current remainder, advance clock.
        total_ms
    } else {
        added.saturating_mul(1000) / b.refill_per_sec
    };
    b.remainder_ms = total_ms.saturating_sub(consumed_ms);
    b.tokens = b.tokens.saturating_add(added).min(b.capacity);
    b.last_refill_ms = now_ms;
}

impl TokenBucketRateLimit {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            buckets: BTreeMap::new(),
        }
    }

    /// Register / reset a bucket.
    pub fn register(
        &mut self,
        id: &str,
        capacity: u64,
        refill_per_sec: u64,
        now_ms: u64,
    ) -> Result<(), BucketError> {
        if id.is_empty() {
            return Err(BucketError::EmptyId);
        }
        if capacity == 0 {
            return Err(BucketError::ZeroCapacity);
        }
        self.buckets.insert(
            id.into(),
            Bucket {
                capacity,
                refill_per_sec,
                tokens: capacity, // start full
                last_refill_ms: now_ms,
                remainder_ms: 0,
                granted_total: 0,
                throttled_total: 0,
            },
        );
        Ok(())
    }

    /// Try to acquire `cost` tokens.
    pub fn try_acquire(&mut self, id: &str, cost: u64, now_ms: u64) -> AcquireVerdict {
        let Some(b) = self.buckets.get_mut(id) else {
            return AcquireVerdict::Unknown;
        };
        refill(b, now_ms);
        if cost > b.tokens {
            b.throttled_total = b.throttled_total.saturating_add(1);
            return AcquireVerdict::Throttled {
                available: b.tokens,
                requested: cost,
            };
        }
        b.tokens -= cost;
        b.granted_total = b.granted_total.saturating_add(1);
        AcquireVerdict::Granted
    }

    /// Current tokens.
    pub fn tokens(&self, id: &str) -> u64 {
        self.buckets.get(id).map(|b| b.tokens).unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BucketError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BucketError::SchemaMismatch);
        }
        for (id, b) in &self.buckets {
            if id.is_empty() {
                return Err(BucketError::EmptyId);
            }
            if b.capacity == 0 {
                return Err(BucketError::ZeroCapacity);
            }
        }
        Ok(())
    }
}

impl Default for TokenBucketRateLimit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_full() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 1, 0).unwrap();
        assert_eq!(l.tokens("b"), 10);
    }

    #[test]
    fn grant_consumes_tokens() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 1, 0).unwrap();
        assert_eq!(l.try_acquire("b", 3, 0), AcquireVerdict::Granted);
        assert_eq!(l.tokens("b"), 7);
    }

    #[test]
    fn throttle_when_insufficient() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 1, 0).unwrap();
        l.try_acquire("b", 10, 0);
        match l.try_acquire("b", 5, 0) {
            AcquireVerdict::Throttled {
                available,
                requested,
            } => {
                assert_eq!(available, 0);
                assert_eq!(requested, 5);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn refill_over_time() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 5, 0).unwrap(); // 5 tokens/sec
        l.try_acquire("b", 10, 0); // drain
        // After 2 seconds → 10 tokens added, capped at capacity.
        l.try_acquire("b", 0, 2000);
        assert_eq!(l.tokens("b"), 10);
    }

    #[test]
    fn partial_refill() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 10, 0).unwrap(); // 10/sec → 1 token / 100ms
        l.try_acquire("b", 10, 0);
        // After 500ms → 5 tokens.
        l.try_acquire("b", 0, 500);
        assert_eq!(l.tokens("b"), 5);
    }

    #[test]
    fn cap_holds() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 5, 100, 0).unwrap();
        // Long elapse, but cap is 5.
        l.try_acquire("b", 0, 60_000);
        assert_eq!(l.tokens("b"), 5);
    }

    #[test]
    fn zero_refill_no_recovery() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 5, 0, 0).unwrap();
        l.try_acquire("b", 5, 0);
        l.try_acquire("b", 0, 60_000);
        assert_eq!(l.tokens("b"), 0);
    }

    #[test]
    fn unknown_bucket() {
        let mut l = TokenBucketRateLimit::new();
        assert_eq!(l.try_acquire("nope", 1, 0), AcquireVerdict::Unknown);
    }

    #[test]
    fn telemetry_counts() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 1, 0, 0).unwrap();
        l.try_acquire("b", 1, 0); // grant
        l.try_acquire("b", 1, 0); // throttle
        let b = l.buckets.get("b").unwrap();
        assert_eq!(b.granted_total, 1);
        assert_eq!(b.throttled_total, 1);
    }

    #[test]
    fn empty_id_rejected() {
        let mut l = TokenBucketRateLimit::new();
        assert!(matches!(
            l.register("", 1, 1, 0).unwrap_err(),
            BucketError::EmptyId
        ));
    }

    #[test]
    fn zero_capacity_rejected() {
        let mut l = TokenBucketRateLimit::new();
        assert!(matches!(
            l.register("b", 0, 1, 0).unwrap_err(),
            BucketError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = TokenBucketRateLimit::new();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            BucketError::SchemaMismatch
        ));
    }

    #[test]
    fn limiter_serde_roundtrip() {
        let mut l = TokenBucketRateLimit::new();
        l.register("b", 10, 5, 0).unwrap();
        l.try_acquire("b", 3, 100);
        let j = serde_json::to_string(&l).unwrap();
        let back: TokenBucketRateLimit = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
