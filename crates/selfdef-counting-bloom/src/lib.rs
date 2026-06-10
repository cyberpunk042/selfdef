//! `selfdef-counting-bloom` — counting bloom filter.
//!
//! m 8-bit counters, k hash positions per key. add(key) increments
//! each of k positions; remove(key) decrements. contains(key)
//! returns true iff all k positions are non-zero (with possible
//! false positives). Counters saturate at 255 — once saturated,
//! removes are no-ops for that cell (lossy under heavy churn).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Filter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountingBloom {
    /// Schema version.
    pub schema_version: String,
    /// Bit-count m (= len of counters).
    pub m: u32,
    /// Hash count k.
    pub k: u32,
    /// 8-bit counters.
    pub counters: Vec<u8>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BloomError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero dim.
    #[error("m and k must be >= 1")]
    ZeroDim,
    /// Geometry.
    #[error("counters length must equal m")]
    BadCounters,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl CountingBloom {
    /// New.
    pub fn new(m: u32, k: u32) -> Result<Self, BloomError> {
        if m == 0 || k == 0 {
            return Err(BloomError::ZeroDim);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            m,
            k,
            counters: vec![0; m as usize],
        })
    }

    fn pos(&self, i: u32, key: &str) -> usize {
        let mut buf = format!("{i}:").into_bytes();
        buf.extend_from_slice(key.as_bytes());
        (fnv1a_64(&buf) % self.m as u64) as usize
    }

    /// Add (increment each of k positions, saturating at 255).
    pub fn add(&mut self, key: &str) {
        // pos() computes `% self.m`; a serde-bypassed zero m (new()/validate()
        // reject it) would panic that modulo in every build. A zero-cell
        // filter can store nothing — no-op.
        if self.m == 0 || self.counters.is_empty() {
            return;
        }
        for i in 0..self.k {
            let p = self.pos(i, key);
            self.counters[p] = self.counters[p].saturating_add(1);
        }
    }

    /// Remove (decrement each of k positions; saturates at 0). Note
    /// that cells which previously saturated at 255 lose accuracy.
    pub fn remove(&mut self, key: &str) {
        // Same serde-bypass guard as add(): nothing to remove from a
        // zero-cell filter, and pos()'s modulo would otherwise panic.
        if self.m == 0 || self.counters.is_empty() {
            return;
        }
        for i in 0..self.k {
            let p = self.pos(i, key);
            // Don't decrement saturated cells (they're already lossy).
            if self.counters[p] > 0 && self.counters[p] < 255 {
                self.counters[p] -= 1;
            }
        }
    }

    /// Contains.
    pub fn contains(&self, key: &str) -> bool {
        // Same serde-bypass guard as add(): a zero-cell filter holds nothing,
        // so report absent rather than panic in pos()'s modulo.
        if self.m == 0 || self.counters.is_empty() {
            return false;
        }
        for i in 0..self.k {
            let p = self.pos(i, key);
            if self.counters[p] == 0 {
                return false;
            }
        }
        true
    }

    /// Reset.
    pub fn clear(&mut self) {
        for c in self.counters.iter_mut() {
            *c = 0;
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BloomError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BloomError::SchemaMismatch);
        }
        if self.m == 0 || self.k == 0 {
            return Err(BloomError::ZeroDim);
        }
        if self.counters.len() != self.m as usize {
            return Err(BloomError::BadCounters);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_m_serde_bypass_does_not_panic() {
        // new()/validate() reject m==0, but serde can construct it. pos()'s
        // `% self.m` would panic in every build. Guard makes add/remove no-ops
        // and contains return false (empty filter) instead of crashing.
        let mut c = CountingBloom {
            schema_version: SCHEMA_VERSION.into(),
            m: 0,
            k: 3,
            counters: Vec::new(),
        };
        c.add("k"); // must not panic
        assert!(!c.contains("k")); // must not panic
        c.remove("k"); // must not panic
    }

    #[test]
    fn add_then_contains() {
        let mut b = CountingBloom::new(128, 4).unwrap();
        b.add("hello");
        assert!(b.contains("hello"));
    }

    #[test]
    fn remove_then_absent() {
        let mut b = CountingBloom::new(256, 4).unwrap();
        b.add("hello");
        b.remove("hello");
        assert!(!b.contains("hello"));
    }

    #[test]
    fn add_twice_remove_once_still_present() {
        let mut b = CountingBloom::new(256, 4).unwrap();
        b.add("hello");
        b.add("hello");
        b.remove("hello");
        assert!(b.contains("hello"));
    }

    #[test]
    fn unknown_is_absent() {
        let b = CountingBloom::new(128, 4).unwrap();
        assert!(!b.contains("nope"));
    }

    #[test]
    fn clear_zeros_all() {
        let mut b = CountingBloom::new(64, 3).unwrap();
        b.add("x");
        b.clear();
        assert!(!b.contains("x"));
    }

    #[test]
    fn zero_dim_rejected() {
        assert!(matches!(
            CountingBloom::new(0, 4).unwrap_err(),
            BloomError::ZeroDim
        ));
        assert!(matches!(
            CountingBloom::new(64, 0).unwrap_err(),
            BloomError::ZeroDim
        ));
    }

    #[test]
    fn bad_counters_rejected() {
        let mut b = CountingBloom::new(8, 2).unwrap();
        b.counters.pop();
        assert!(matches!(b.validate().unwrap_err(), BloomError::BadCounters));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = CountingBloom::new(8, 2).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BloomError::SchemaMismatch
        ));
    }

    #[test]
    fn bloom_serde_roundtrip() {
        let mut b = CountingBloom::new(64, 3).unwrap();
        b.add("a");
        b.add("b");
        let j = serde_json::to_string(&b).unwrap();
        let back: CountingBloom = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
        assert!(back.contains("a"));
        assert!(back.contains("b"));
    }
}
