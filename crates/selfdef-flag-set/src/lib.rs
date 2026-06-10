//! `selfdef-flag-set` — named 64-bit flag set.
//!
//! register(name) assigns the next-free bit (0..=63); already-
//! registered names re-use existing bit. set/clear/contains use
//! bit ops; union/intersection/difference combine bitmasks.
//! names() lists registered names in bit-order.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlagSet {
    /// Schema version.
    pub schema_version: String,
    /// name → bit index (0..=63).
    pub bits: BTreeMap<String, u8>,
    /// Current bitmask.
    pub mask: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FlagError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("flag name empty")]
    EmptyName,
    /// Full.
    #[error("flag set full (64 max)")]
    Full,
    /// Unknown.
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    /// Bit index outside the representable 0..=63 range (corrupt/serde-bypassed state).
    #[error("bit index {0} out of range (must be 0..=63)")]
    BitOutOfRange(u8),
}

/// Bit mask for index `b`, defending against an out-of-range index.
///
/// `register()` only ever assigns `0..=63`, but serde deserialization
/// bypasses it and can persist `b >= 64`. A raw `1u64 << b` would then
/// overflow — a debug panic (DoS), and in release Rust masks the shift
/// amount (`1u64 << 64 == 1u64 << 0`) so the out-of-range flag *aliases*
/// bit 0, cross-talking with a distinct registered flag. Returning 0 for
/// an unrepresentable index makes every bit op fail-CLOSED: the flag reads
/// as not-set and cannot be set (`|= 0` / `&= !0` are both no-ops).
fn bit_mask(b: u8) -> u64 {
    if b < 64 { 1u64 << b } else { 0 }
}

impl FlagSet {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            bits: BTreeMap::new(),
            mask: 0,
        }
    }

    /// Register a flag (idempotent).
    pub fn register(&mut self, name: &str) -> Result<u8, FlagError> {
        if name.is_empty() {
            return Err(FlagError::EmptyName);
        }
        if let Some(&b) = self.bits.get(name) {
            return Ok(b);
        }
        if self.bits.len() >= 64 {
            return Err(FlagError::Full);
        }
        // Next free bit. Out-of-range (serde-bypassed) indices contribute 0
        // via bit_mask, so they neither alias nor block a fresh assignment.
        let used: u64 = self.bits.values().map(|b| bit_mask(*b)).sum();
        let mut idx = 0u8;
        while idx < 64 && (used & (1u64 << idx)) != 0 {
            idx += 1;
        }
        self.bits.insert(name.into(), idx);
        Ok(idx)
    }

    /// Set flag.
    pub fn set(&mut self, name: &str) -> Result<(), FlagError> {
        let &b = self
            .bits
            .get(name)
            .ok_or_else(|| FlagError::UnknownFlag(name.into()))?;
        self.mask |= bit_mask(b);
        Ok(())
    }

    /// Clear flag.
    pub fn clear(&mut self, name: &str) -> Result<(), FlagError> {
        let &b = self
            .bits
            .get(name)
            .ok_or_else(|| FlagError::UnknownFlag(name.into()))?;
        self.mask &= !bit_mask(b);
        Ok(())
    }

    /// Contains flag?
    pub fn contains(&self, name: &str) -> Result<bool, FlagError> {
        let &b = self
            .bits
            .get(name)
            .ok_or_else(|| FlagError::UnknownFlag(name.into()))?;
        Ok((self.mask & bit_mask(b)) != 0)
    }

    /// Union with another (same name table required).
    pub fn union_with(&mut self, other: &FlagSet) {
        self.mask |= other.mask;
    }

    /// Intersection.
    pub fn intersect_with(&mut self, other: &FlagSet) {
        self.mask &= other.mask;
    }

    /// Difference (self - other).
    pub fn subtract(&mut self, other: &FlagSet) {
        self.mask &= !other.mask;
    }

    /// Count of set bits.
    pub fn count(&self) -> u32 {
        self.mask.count_ones()
    }

    /// Names of currently-set flags (bit-order ascending).
    pub fn active_names(&self) -> Vec<String> {
        let mut pairs: Vec<(u8, String)> = self
            .bits
            .iter()
            .filter(|&(_, &b)| (self.mask & bit_mask(b)) != 0)
            .map(|(k, &b)| (b, k.clone()))
            .collect();
        pairs.sort_by_key(|(b, _)| *b);
        pairs.into_iter().map(|(_, n)| n).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FlagError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FlagError::SchemaMismatch);
        }
        for (k, &b) in self.bits.iter() {
            if k.is_empty() {
                return Err(FlagError::EmptyName);
            }
            if b >= 64 {
                return Err(FlagError::BitOutOfRange(b));
            }
        }
        Ok(())
    }
}

impl Default for FlagSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_assigns_low_bits() {
        let mut s = FlagSet::new();
        assert_eq!(s.register("a").unwrap(), 0);
        assert_eq!(s.register("b").unwrap(), 1);
        assert_eq!(s.register("a").unwrap(), 0); // idempotent
    }

    #[test]
    fn set_clear_contains() {
        let mut s = FlagSet::new();
        s.register("x").unwrap();
        assert!(!s.contains("x").unwrap());
        s.set("x").unwrap();
        assert!(s.contains("x").unwrap());
        s.clear("x").unwrap();
        assert!(!s.contains("x").unwrap());
    }

    #[test]
    fn union_combines() {
        let mut a = FlagSet::new();
        a.register("x").unwrap();
        a.register("y").unwrap();
        a.set("x").unwrap();
        let mut b = a.clone();
        b.set("y").unwrap();
        a.union_with(&b);
        assert!(a.contains("x").unwrap());
        assert!(a.contains("y").unwrap());
    }

    #[test]
    fn intersect_filters() {
        let mut a = FlagSet::new();
        a.register("x").unwrap();
        a.register("y").unwrap();
        a.set("x").unwrap();
        a.set("y").unwrap();
        let mut b = a.clone();
        b.clear("y").unwrap();
        a.intersect_with(&b);
        assert!(a.contains("x").unwrap());
        assert!(!a.contains("y").unwrap());
    }

    #[test]
    fn subtract_removes() {
        let mut a = FlagSet::new();
        a.register("x").unwrap();
        a.register("y").unwrap();
        a.set("x").unwrap();
        a.set("y").unwrap();
        let mut b = a.clone();
        b.clear("x").unwrap();
        a.subtract(&b); // remove "y" from a
        assert!(a.contains("x").unwrap());
        assert!(!a.contains("y").unwrap());
    }

    #[test]
    fn active_names_sorted_by_bit() {
        let mut s = FlagSet::new();
        s.register("a").unwrap();
        s.register("b").unwrap();
        s.register("c").unwrap();
        s.set("c").unwrap();
        s.set("a").unwrap();
        assert_eq!(s.active_names(), vec!["a", "c"]);
    }

    #[test]
    fn full_set_rejected() {
        let mut s = FlagSet::new();
        for i in 0..64 {
            s.register(&format!("f{i}")).unwrap();
        }
        assert!(matches!(s.register("f64").unwrap_err(), FlagError::Full));
    }

    #[test]
    fn unknown_set_rejected() {
        let mut s = FlagSet::new();
        assert!(matches!(
            s.set("nope").unwrap_err(),
            FlagError::UnknownFlag(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = FlagSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            FlagError::SchemaMismatch
        ));
    }

    #[test]
    fn out_of_range_bit_does_not_overflow_or_alias() {
        // register() keeps indices in 0..=63, but serde can construct a state
        // with b >= 64. A raw `1u64 << b` would panic in debug (DoS) and in
        // release alias bit 0 (`1u64 << 64 == 1u64 << 0`), cross-talking with
        // a distinct registered flag. bit_mask() forces fail-closed: the
        // out-of-range flag reads as not-set and cannot be set, and it must
        // not corrupt the genuine bit-0 flag.
        let mut bits = BTreeMap::new();
        bits.insert("real_low".to_string(), 0u8); // genuine bit 0
        bits.insert("aliased".to_string(), 64u8); // serde-bypassed, would alias bit 0
        let mut s = FlagSet {
            schema_version: SCHEMA_VERSION.into(),
            bits,
            mask: 0,
        };
        // Setting the out-of-range flag must not panic and must not light bit 0.
        s.set("aliased").unwrap();
        assert!(!s.contains("aliased").unwrap()); // unrepresentable → fail-closed
        assert!(!s.contains("real_low").unwrap()); // genuine flag untouched (no alias)
        // The genuine flag still works independently.
        s.set("real_low").unwrap();
        assert!(s.contains("real_low").unwrap());
        assert!(!s.contains("aliased").unwrap());
        // Clearing the out-of-range flag must not clear bit 0 either.
        s.clear("aliased").unwrap();
        assert!(s.contains("real_low").unwrap());
        assert_eq!(s.active_names(), vec!["real_low"]);
    }

    #[test]
    fn out_of_range_bit_rejected_by_validate() {
        let mut bits = BTreeMap::new();
        bits.insert("x".to_string(), 200u8);
        let s = FlagSet {
            schema_version: SCHEMA_VERSION.into(),
            bits,
            mask: 0,
        };
        assert!(matches!(
            s.validate().unwrap_err(),
            FlagError::BitOutOfRange(200)
        ));
    }

    #[test]
    fn flagset_serde_roundtrip() {
        let mut s = FlagSet::new();
        s.register("a").unwrap();
        s.set("a").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: FlagSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
