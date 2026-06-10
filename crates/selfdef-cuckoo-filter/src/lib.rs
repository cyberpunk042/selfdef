//! `selfdef-cuckoo-filter` — simplified cuckoo filter.
//!
//! Each bucket has 4 slots; each slot stores an 8-bit fingerprint
//! (0 = empty). Two candidate buckets per key:
//!   i1 = h1(key) mod n_buckets
//!   i2 = i1 XOR h(fp), still mod n_buckets
//! Insert places fp into i1 or i2 if empty; otherwise relocates
//! a victim up to max_relocations times.
//! Contains/remove check both i1 and i2.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Slots per bucket.
pub const SLOTS_PER_BUCKET: usize = 4;

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuckooFilter {
    /// Schema version.
    pub schema_version: String,
    /// Number of buckets.
    pub n_buckets: u32,
    /// Max relocations on insert.
    pub max_relocations: u32,
    /// Flattened buckets: n_buckets * 4 cells (u8 fingerprints).
    pub cells: Vec<u8>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CuckooError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero buckets.
    #[error("n_buckets and max_relocations must be >= 1")]
    BadConfig,
    /// n_buckets not a power of two — the XOR-based alternate-bucket function
    /// (`alt(i) = (i XOR h(fp)) mod n`) is only an involution when `n` is a
    /// power of two. With any other `n`, `alt(alt(i)) != i`, so a relocated
    /// fingerprint can land outside an item's two candidate buckets and become
    /// unfindable — a silent FALSE NEGATIVE (a present key reported absent),
    /// which breaks the filter's no-false-negative contract.
    #[error("n_buckets {0} must be a power of two")]
    NBucketsNotPowerOfTwo(u32),
    /// Geometry.
    #[error("cells length must equal n_buckets * 4")]
    BadGeometry,
    /// Filter full (insertion failure).
    #[error("filter full (insertion failure)")]
    Full,
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn fp_byte(key: &str) -> u8 {
    let h = fnv1a_64(key.as_bytes());
    // Map to non-zero u8 (0 reserved for empty).
    let b = (h & 0xff) as u8;
    if b == 0 { 1 } else { b }
}

impl CuckooFilter {
    /// New.
    pub fn new(n_buckets: u32, max_relocations: u32) -> Result<Self, CuckooError> {
        if n_buckets == 0 || max_relocations == 0 {
            return Err(CuckooError::BadConfig);
        }
        if !n_buckets.is_power_of_two() {
            return Err(CuckooError::NBucketsNotPowerOfTwo(n_buckets));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            n_buckets,
            max_relocations,
            cells: vec![0u8; (n_buckets as usize) * SLOTS_PER_BUCKET],
        })
    }

    fn i1(&self, key: &str) -> usize {
        let mut buf = b"1:".to_vec();
        buf.extend_from_slice(key.as_bytes());
        (fnv1a_64(&buf) % self.n_buckets as u64) as usize
    }

    fn alt(&self, i: usize, fp: u8) -> usize {
        let buf = vec![fp];
        let h = fnv1a_64(&buf) % self.n_buckets as u64;
        ((i as u64 ^ h) % self.n_buckets as u64) as usize
    }

    fn bucket(&mut self, i: usize) -> &mut [u8] {
        let s = i * SLOTS_PER_BUCKET;
        &mut self.cells[s..s + SLOTS_PER_BUCKET]
    }

    fn try_insert_into(&mut self, i: usize, fp: u8) -> bool {
        for s in self.bucket(i).iter_mut() {
            if *s == 0 {
                *s = fp;
                return true;
            }
        }
        false
    }

    /// Insert.
    pub fn insert(&mut self, key: &str) -> Result<(), CuckooError> {
        // i1()/alt() compute `% self.n_buckets`; a serde-bypassed zero
        // n_buckets (new()/validate() reject it) would panic that modulo in
        // every build. A zero-bucket filter can hold nothing — refuse.
        if self.n_buckets == 0 {
            return Err(CuckooError::Full);
        }
        let fp = fp_byte(key);
        let i1 = self.i1(key);
        if self.try_insert_into(i1, fp) {
            return Ok(());
        }
        let i2 = self.alt(i1, fp);
        if self.try_insert_into(i2, fp) {
            return Ok(());
        }
        // Relocate victims; choose i2 as starting bucket.
        let mut i = i2;
        let mut victim_fp = fp;
        for _ in 0..self.max_relocations {
            // Evict slot 0 of current bucket and try to place evicted
            // fingerprint in its alternate location.
            let evicted = {
                let b = self.bucket(i);
                let e = b[0];
                b[0] = victim_fp;
                e
            };
            victim_fp = evicted;
            let alt_i = self.alt(i, victim_fp);
            if self.try_insert_into(alt_i, victim_fp) {
                return Ok(());
            }
            i = alt_i;
        }
        Err(CuckooError::Full)
    }

    /// Contains.
    pub fn contains(&self, key: &str) -> bool {
        // Same serde-bypass guard as insert(): a zero-bucket filter holds
        // nothing, so report absent rather than panic in i1()/alt()'s modulo.
        if self.n_buckets == 0 {
            return false;
        }
        let fp = fp_byte(key);
        let i1 = self.i1(key);
        let i2 = self.alt(i1, fp);
        let in_i = |i: usize| {
            let s = i * SLOTS_PER_BUCKET;
            self.cells[s..s + SLOTS_PER_BUCKET].contains(&fp)
        };
        in_i(i1) || in_i(i2)
    }

    /// Remove.
    pub fn remove(&mut self, key: &str) -> bool {
        // Same serde-bypass guard as insert(): nothing to remove from a
        // zero-bucket filter, and the modulo would otherwise panic.
        if self.n_buckets == 0 {
            return false;
        }
        let fp = fp_byte(key);
        let i1 = self.i1(key);
        if let Some(slot) = self.bucket(i1).iter_mut().find(|s| **s == fp) {
            *slot = 0;
            return true;
        }
        let i2 = self.alt(i1, fp);
        if let Some(slot) = self.bucket(i2).iter_mut().find(|s| **s == fp) {
            *slot = 0;
            return true;
        }
        false
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CuckooError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CuckooError::SchemaMismatch);
        }
        if self.n_buckets == 0 || self.max_relocations == 0 {
            return Err(CuckooError::BadConfig);
        }
        if !self.n_buckets.is_power_of_two() {
            return Err(CuckooError::NBucketsNotPowerOfTwo(self.n_buckets));
        }
        if self.cells.len() != (self.n_buckets as usize) * SLOTS_PER_BUCKET {
            return Err(CuckooError::BadGeometry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_buckets_serde_bypass_does_not_panic() {
        // new()/validate() reject n_buckets==0, but serde can construct it.
        // i1()/alt()'s `% self.n_buckets` would panic in every build. Guard
        // makes the ops fail-closed (refuse / absent) instead of crashing.
        let mut c = CuckooFilter {
            schema_version: SCHEMA_VERSION.into(),
            n_buckets: 0,
            max_relocations: 8,
            cells: Vec::new(),
        };
        assert!(c.insert("k").is_err()); // must not panic
        assert!(!c.contains("k")); // must not panic
        assert!(!c.remove("k")); // must not panic
    }

    #[test]
    fn insert_then_contains() {
        let mut f = CuckooFilter::new(64, 100).unwrap();
        f.insert("a").unwrap();
        assert!(f.contains("a"));
    }

    #[test]
    fn non_power_of_two_n_buckets_rejected() {
        // The XOR-based alternate-bucket function is only an involution for a
        // power-of-two bucket count. A non-power-of-two count silently breaks
        // `alt(alt(i)) == i`, letting relocated fingerprints escape their
        // candidate buckets — a false negative that defeats a replay/dedup
        // filter. Such configs must be refused at construction, and a
        // deserialized filter carrying one must fail validation.
        for n in [3u32, 6, 10, 100, 1000] {
            assert!(
                matches!(
                    CuckooFilter::new(n, 100).unwrap_err(),
                    CuckooError::NBucketsNotPowerOfTwo(_)
                ),
                "n_buckets={n} must be rejected"
            );
        }
        // Powers of two still construct fine.
        for n in [1u32, 2, 4, 64, 256] {
            CuckooFilter::new(n, 100).unwrap();
        }
        // A deserialized non-power-of-two filter fails validate().
        let mut bad = CuckooFilter::new(4, 10).unwrap();
        bad.n_buckets = 6;
        assert!(matches!(
            bad.validate().unwrap_err(),
            CuckooError::NBucketsNotPowerOfTwo(6)
        ));
    }

    #[test]
    fn unknown_absent() {
        let f = CuckooFilter::new(64, 100).unwrap();
        assert!(!f.contains("nope"));
    }

    #[test]
    fn remove_makes_absent() {
        let mut f = CuckooFilter::new(64, 100).unwrap();
        f.insert("a").unwrap();
        assert!(f.remove("a"));
        assert!(!f.contains("a"));
    }

    #[test]
    fn many_inserts() {
        let mut f = CuckooFilter::new(256, 500).unwrap();
        for i in 0..200 {
            f.insert(&format!("k{i}")).unwrap();
        }
        // All inserted keys should be present.
        for i in 0..200 {
            assert!(f.contains(&format!("k{i}")));
        }
    }

    #[test]
    fn bad_config_rejected() {
        assert!(matches!(
            CuckooFilter::new(0, 1).unwrap_err(),
            CuckooError::BadConfig
        ));
        assert!(matches!(
            CuckooFilter::new(1, 0).unwrap_err(),
            CuckooError::BadConfig
        ));
    }

    #[test]
    fn bad_geometry_rejected() {
        let mut f = CuckooFilter::new(4, 10).unwrap();
        f.cells.pop();
        assert!(matches!(
            f.validate().unwrap_err(),
            CuckooError::BadGeometry
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = CuckooFilter::new(4, 10).unwrap();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            CuckooError::SchemaMismatch
        ));
    }

    #[test]
    fn filter_serde_roundtrip() {
        let mut f = CuckooFilter::new(32, 50).unwrap();
        f.insert("a").unwrap();
        f.insert("b").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: CuckooFilter = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
