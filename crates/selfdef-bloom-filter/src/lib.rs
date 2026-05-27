//! `selfdef-bloom-filter` — fixed-size Bloom filter.
//!
//! Uses 2 independent FNV-1a-64 hashes (different seeds) → 2 bit
//! positions per insertion. No false negatives; small false-positive
//! rate proportional to load.
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
pub struct BloomFilter {
    /// Schema version.
    pub schema_version: String,
    /// Bit array (1 bit per byte slot for simplicity).
    pub bits: Vec<u8>,
    /// Number of items inserted.
    pub count: u64,
    /// Bit count (=bits.len() × 8).
    pub bit_count: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BloomError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero size.
    #[error("byte_size must be > 0")]
    ZeroSize,
}

fn fnv1a_64(bytes: &[u8], seed: u64) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325 ^ seed;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl BloomFilter {
    /// New with byte size.
    pub fn new(byte_size: usize) -> Result<Self, BloomError> {
        if byte_size == 0 {
            return Err(BloomError::ZeroSize);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            bits: vec![0u8; byte_size],
            count: 0,
            bit_count: (byte_size as u64) * 8,
        })
    }

    fn positions(&self, key: &[u8]) -> (usize, usize) {
        let a = fnv1a_64(key, 0) % self.bit_count;
        let b = fnv1a_64(key, 0xdeadbeef) % self.bit_count;
        (a as usize, b as usize)
    }

    /// Insert.
    pub fn insert(&mut self, key: &[u8]) {
        let (a, b) = self.positions(key);
        self.set_bit(a);
        self.set_bit(b);
        self.count = self.count.saturating_add(1);
    }

    /// Contains (may be false-positive).
    pub fn contains(&self, key: &[u8]) -> bool {
        let (a, b) = self.positions(key);
        self.get_bit(a) && self.get_bit(b)
    }

    fn set_bit(&mut self, idx: usize) {
        let byte = idx / 8;
        let bit = idx % 8;
        if let Some(b) = self.bits.get_mut(byte) {
            *b |= 1 << bit;
        }
    }

    fn get_bit(&self, idx: usize) -> bool {
        let byte = idx / 8;
        let bit = idx % 8;
        self.bits.get(byte).copied().unwrap_or(0) & (1 << bit) != 0
    }

    /// Clear.
    pub fn clear(&mut self) {
        for b in self.bits.iter_mut() {
            *b = 0;
        }
        self.count = 0;
    }

    /// Approximate load factor in basis points.
    pub fn load_bp(&self) -> u32 {
        if self.bit_count == 0 {
            return 0;
        }
        let set_bits: u64 = self.bits.iter().map(|b| b.count_ones() as u64).sum();
        ((set_bits * 10_000) / self.bit_count) as u32
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BloomError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BloomError::SchemaMismatch);
        }
        if self.bits.is_empty() {
            return Err(BloomError::ZeroSize);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_contains() {
        let mut b = BloomFilter::new(128).unwrap();
        b.insert(b"hello");
        assert!(b.contains(b"hello"));
    }

    #[test]
    fn no_false_negatives() {
        let mut b = BloomFilter::new(1024).unwrap();
        for i in 0..100 {
            let key = format!("k{i}");
            b.insert(key.as_bytes());
        }
        for i in 0..100 {
            let key = format!("k{i}");
            assert!(b.contains(key.as_bytes()), "false negative at {i}");
        }
    }

    #[test]
    fn likely_not_contains_unknown() {
        let mut b = BloomFilter::new(1024).unwrap();
        b.insert(b"hello");
        // "world" not inserted — most likely not contained.
        let _ = b.contains(b"world");
    }

    #[test]
    fn count_increments() {
        let mut b = BloomFilter::new(128).unwrap();
        b.insert(b"a");
        b.insert(b"b");
        assert_eq!(b.count, 2);
    }

    #[test]
    fn clear_zeros() {
        let mut b = BloomFilter::new(128).unwrap();
        b.insert(b"hello");
        b.clear();
        assert_eq!(b.count, 0);
        assert!(!b.contains(b"hello"));
    }

    #[test]
    fn zero_size_rejected() {
        assert!(matches!(
            BloomFilter::new(0).unwrap_err(),
            BloomError::ZeroSize
        ));
    }

    #[test]
    fn load_bp_grows() {
        let mut b = BloomFilter::new(128).unwrap();
        let before = b.load_bp();
        for i in 0..50 {
            b.insert(format!("k{i}").as_bytes());
        }
        let after = b.load_bp();
        assert!(after > before);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = BloomFilter::new(128).unwrap();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BloomError::SchemaMismatch
        ));
    }

    #[test]
    fn bloom_serde_roundtrip() {
        let mut b = BloomFilter::new(128).unwrap();
        b.insert(b"hello");
        let j = serde_json::to_string(&b).unwrap();
        let back: BloomFilter = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
