//! `selfdef-collector-jitter-policy` — deterministic poll jitter.
//!
//! `next_at(collector_id, scheduled_ms)` returns `scheduled_ms +
//! jitter` where `jitter` lies in
//! `[-max_jitter_ms/2, +max_jitter_ms/2]`. Jitter is derived
//! deterministically from FNV-1a of `collector_id`, so the same
//! collector always lands in the same per-tick slot but distinct
//! collectors spread across the window.
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
pub struct CollectorJitterPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Jitter window (ms).
    pub max_jitter_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum JitterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty collector id.
    #[error("collector id empty")]
    EmptyId,
}

fn hash_fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl CollectorJitterPolicy {
    /// New.
    pub fn new(max_jitter_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_jitter_ms,
        }
    }

    /// Signed jitter in [-max/2, +max/2].
    pub fn jitter(&self, collector_id: &str) -> Result<i64, JitterError> {
        if collector_id.is_empty() {
            return Err(JitterError::EmptyId);
        }
        if self.max_jitter_ms == 0 {
            return Ok(0);
        }
        let h = hash_fnv1a64(collector_id);
        let bucket = (h % self.max_jitter_ms) as i64;
        let half = (self.max_jitter_ms as i64) / 2;
        Ok(bucket - half)
    }

    /// Apply jitter (saturating).
    pub fn next_at(&self, collector_id: &str, scheduled_ms: u64) -> Result<u64, JitterError> {
        let j = self.jitter(collector_id)?;
        Ok(if j >= 0 {
            scheduled_ms.saturating_add(j as u64)
        } else {
            scheduled_ms.saturating_sub((-j) as u64)
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), JitterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(JitterError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_zero_when_max_zero() {
        let p = CollectorJitterPolicy::new(0);
        assert_eq!(p.jitter("anything").unwrap(), 0);
    }

    #[test]
    fn jitter_inside_window() {
        let p = CollectorJitterPolicy::new(1000);
        for id in ["a", "b", "c", "foo", "bar"] {
            let j = p.jitter(id).unwrap();
            assert!(j >= -500 && j <= 500, "id={id} j={j}");
        }
    }

    #[test]
    fn deterministic_same_id() {
        let p = CollectorJitterPolicy::new(1000);
        assert_eq!(p.jitter("a").unwrap(), p.jitter("a").unwrap());
    }

    #[test]
    fn distinct_collectors_spread() {
        let p = CollectorJitterPolicy::new(1000);
        let a = p.jitter("a").unwrap();
        let b = p.jitter("b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn next_at_applies_jitter() {
        let p = CollectorJitterPolicy::new(1000);
        let n = p.next_at("a", 100_000).unwrap();
        // Within window.
        assert!(n >= 99_500 && n <= 100_500);
    }

    #[test]
    fn empty_id_rejected() {
        let p = CollectorJitterPolicy::new(1000);
        assert!(matches!(p.jitter("").unwrap_err(), JitterError::EmptyId));
        assert!(matches!(
            p.next_at("", 0).unwrap_err(),
            JitterError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = CollectorJitterPolicy::new(1000);
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            JitterError::SchemaMismatch
        ));
    }

    #[test]
    fn jitter_serde_roundtrip() {
        let p = CollectorJitterPolicy::new(500);
        let j = serde_json::to_string(&p).unwrap();
        let back: CollectorJitterPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
