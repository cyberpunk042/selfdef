//! `selfdef-jump-hash` — Google Jump Consistent Hash.
//!
//! bucket(key, num_buckets) returns a bucket index in 0..num_buckets
//! using the algorithm from Lamping & Veach 2014 ("A Fast,
//! Minimal Memory, Consistent Hash Algorithm"). Adding a bucket
//! moves only ~1/n of keys; no per-key state. Suitable for shard
//! placement.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum JumpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero buckets.
    #[error("num_buckets must be >= 1")]
    ZeroBuckets,
}

/// Jump Consistent Hash. Returns bucket in [0, num_buckets).
pub fn bucket(mut key: u64, num_buckets: u32) -> Result<u32, JumpError> {
    if num_buckets == 0 {
        return Err(JumpError::ZeroBuckets);
    }
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < num_buckets as i64 {
        b = j;
        // Linear-congruential step (constants per Lamping & Veach).
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        // 31-bit double in [0, 1): (key>>33)+1) / 2^31. We instead
        // use the integer form: j = (b+1) * 2^31 / ((key >> 33) + 1).
        let denom = ((key >> 33) as i64) + 1;
        j = ((b + 1) * (1i64 << 31)) / denom;
    }
    Ok(b as u32)
}

/// FNV-1a-64 (helper for callers that want to hash strings).
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Validate.
pub fn validate_schema_version(s: &str) -> Result<(), JumpError> {
    if s != SCHEMA_VERSION {
        return Err(JumpError::SchemaMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn returns_in_range() {
        for k in 0u64..1000 {
            let b = bucket(k, 64).unwrap();
            assert!(b < 64);
        }
    }

    #[test]
    fn single_bucket_always_zero() {
        for k in 0u64..100 {
            assert_eq!(bucket(k, 1).unwrap(), 0);
        }
    }

    #[test]
    fn zero_buckets_rejected() {
        assert!(matches!(bucket(0, 0).unwrap_err(), JumpError::ZeroBuckets));
    }

    #[test]
    fn stable_for_same_input() {
        let a = bucket(0xdeadbeef, 100).unwrap();
        let b = bucket(0xdeadbeef, 100).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distribution_is_reasonable() {
        let n = 10_000u64;
        let buckets = 16u32;
        let mut histo: BTreeMap<u32, u64> = BTreeMap::new();
        for k in 0..n {
            let b = bucket(k, buckets).unwrap();
            *histo.entry(b).or_default() += 1;
        }
        let expected = (n as f64) / (buckets as f64);
        for (_, count) in histo.iter() {
            let ratio = (*count as f64) / expected;
            // Within +/-50% of expected.
            assert!(ratio > 0.5 && ratio < 1.5, "skew: {}", ratio);
        }
    }

    #[test]
    fn growth_moves_minimal_keys() {
        // Adding 1 bucket should move ~1/(n+1) of keys.
        let n = 10_000u64;
        let from = 10u32;
        let to = 11u32;
        let mut moved = 0u64;
        for k in 0..n {
            if bucket(k, from).unwrap() != bucket(k, to).unwrap() {
                moved += 1;
            }
        }
        let expected = (n as f64) / (to as f64);
        let ratio = (moved as f64) / expected;
        assert!(ratio > 0.5 && ratio < 1.5);
    }

    #[test]
    fn schema_check() {
        assert!(validate_schema_version("1.0.0").is_ok());
        assert!(matches!(
            validate_schema_version("9.9.9").unwrap_err(),
            JumpError::SchemaMismatch
        ));
    }

    #[test]
    fn fnv_helper_is_deterministic() {
        assert_eq!(fnv1a_64(b"hello"), fnv1a_64(b"hello"));
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"hellx"));
    }
}
