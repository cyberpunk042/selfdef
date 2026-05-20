//! `selfdef-keyed-rate-limit` — per-key token buckets.
//!
//! New keys auto-create with default cap/refill. try_acquire returns
//! Granted/Throttled{available, requested}.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-key bucket.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bucket {
    /// Tokens.
    pub tokens: u64,
    /// Cap.
    pub capacity: u64,
    /// Refill per second.
    pub refill_per_sec: u64,
    /// Last refill ts.
    pub last_refill_ms: u64,
    /// Sub-second remainder.
    pub remainder_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyedRateLimit {
    /// Schema version.
    pub schema_version: String,
    /// Default capacity.
    pub default_capacity: u64,
    /// Default refill per second.
    pub default_refill_per_sec: u64,
    /// key → bucket.
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
}

/// Errors.
#[derive(Debug, Error)]
pub enum LimitError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Zero default capacity.
    #[error("default_capacity must be > 0")]
    ZeroCapacity,
}

fn refill(b: &mut Bucket, now_ms: u64) {
    if now_ms <= b.last_refill_ms { return; }
    let elapsed = now_ms - b.last_refill_ms;
    let total_ms = elapsed.saturating_add(b.remainder_ms);
    let added = total_ms.saturating_mul(b.refill_per_sec) / 1000;
    let consumed_ms = if b.refill_per_sec == 0 { total_ms } else { added.saturating_mul(1000) / b.refill_per_sec };
    b.remainder_ms = total_ms.saturating_sub(consumed_ms);
    b.tokens = b.tokens.saturating_add(added).min(b.capacity);
    b.last_refill_ms = now_ms;
}

impl KeyedRateLimit {
    /// New.
    pub fn new(default_capacity: u64, default_refill_per_sec: u64) -> Result<Self, LimitError> {
        if default_capacity == 0 { return Err(LimitError::ZeroCapacity); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            default_capacity,
            default_refill_per_sec,
            buckets: BTreeMap::new(),
        })
    }

    /// Try acquire.
    pub fn try_acquire(&mut self, key: &str, cost: u64, now_ms: u64) -> Result<AcquireVerdict, LimitError> {
        if key.is_empty() { return Err(LimitError::EmptyKey); }
        let dcap = self.default_capacity;
        let drefill = self.default_refill_per_sec;
        let b = self.buckets.entry(key.into()).or_insert(Bucket {
            tokens: dcap,
            capacity: dcap,
            refill_per_sec: drefill,
            last_refill_ms: now_ms,
            remainder_ms: 0,
        });
        refill(b, now_ms);
        if cost > b.tokens {
            return Ok(AcquireVerdict::Throttled { available: b.tokens, requested: cost });
        }
        b.tokens -= cost;
        Ok(AcquireVerdict::Granted)
    }

    /// Set per-key override.
    pub fn set_override(&mut self, key: &str, capacity: u64, refill_per_sec: u64, now_ms: u64) -> Result<(), LimitError> {
        if key.is_empty() { return Err(LimitError::EmptyKey); }
        if capacity == 0 { return Err(LimitError::ZeroCapacity); }
        self.buckets.insert(key.into(), Bucket {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill_ms: now_ms,
            remainder_ms: 0,
        });
        Ok(())
    }

    /// Drop a key.
    pub fn forget(&mut self, key: &str) -> bool {
        self.buckets.remove(key).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LimitError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LimitError::SchemaMismatch); }
        if self.default_capacity == 0 { return Err(LimitError::ZeroCapacity); }
        for k in self.buckets.keys() {
            if k.is_empty() { return Err(LimitError::EmptyKey); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_auto_creates() {
        let mut l = KeyedRateLimit::new(10, 1).unwrap();
        assert_eq!(l.try_acquire("a", 5, 0).unwrap(), AcquireVerdict::Granted);
    }

    #[test]
    fn throttle_when_exhausted() {
        let mut l = KeyedRateLimit::new(10, 0).unwrap();
        l.try_acquire("a", 10, 0).unwrap();
        match l.try_acquire("a", 5, 0).unwrap() {
            AcquireVerdict::Throttled { available, requested } => {
                assert_eq!(available, 0);
                assert_eq!(requested, 5);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn keys_independent() {
        let mut l = KeyedRateLimit::new(10, 0).unwrap();
        l.try_acquire("a", 10, 0).unwrap();
        // "b" has its own bucket.
        assert_eq!(l.try_acquire("b", 5, 0).unwrap(), AcquireVerdict::Granted);
    }

    #[test]
    fn override_changes_cap() {
        let mut l = KeyedRateLimit::new(10, 0).unwrap();
        l.set_override("a", 100, 0, 0).unwrap();
        assert_eq!(l.try_acquire("a", 50, 0).unwrap(), AcquireVerdict::Granted);
    }

    #[test]
    fn forget_resets_next_acquire() {
        let mut l = KeyedRateLimit::new(10, 0).unwrap();
        l.try_acquire("a", 10, 0).unwrap();
        l.forget("a");
        assert_eq!(l.try_acquire("a", 5, 0).unwrap(), AcquireVerdict::Granted);
    }

    #[test]
    fn refill_over_time() {
        let mut l = KeyedRateLimit::new(10, 5).unwrap();
        l.try_acquire("a", 10, 0).unwrap();
        assert_eq!(l.try_acquire("a", 5, 1000).unwrap(), AcquireVerdict::Granted);
    }

    #[test]
    fn empty_key_rejected() {
        let mut l = KeyedRateLimit::new(10, 1).unwrap();
        assert!(matches!(l.try_acquire("", 1, 0).unwrap_err(), LimitError::EmptyKey));
    }

    #[test]
    fn zero_default_rejected() {
        assert!(matches!(KeyedRateLimit::new(0, 1).unwrap_err(), LimitError::ZeroCapacity));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = KeyedRateLimit::new(10, 1).unwrap();
        l.schema_version = "9.9.9".into();
        assert!(matches!(l.validate().unwrap_err(), LimitError::SchemaMismatch));
    }

    #[test]
    fn limit_serde_roundtrip() {
        let mut l = KeyedRateLimit::new(10, 5).unwrap();
        l.try_acquire("a", 3, 0).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: KeyedRateLimit = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
