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
        // Next free bit.
        let used: u64 = self.bits.values().map(|b| 1u64 << b).sum();
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
        self.mask |= 1u64 << b;
        Ok(())
    }

    /// Clear flag.
    pub fn clear(&mut self, name: &str) -> Result<(), FlagError> {
        let &b = self
            .bits
            .get(name)
            .ok_or_else(|| FlagError::UnknownFlag(name.into()))?;
        self.mask &= !(1u64 << b);
        Ok(())
    }

    /// Contains flag?
    pub fn contains(&self, name: &str) -> Result<bool, FlagError> {
        let &b = self
            .bits
            .get(name)
            .ok_or_else(|| FlagError::UnknownFlag(name.into()))?;
        Ok((self.mask & (1u64 << b)) != 0)
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
            .filter(|&(_, &b)| (self.mask & (1u64 << b)) != 0)
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
        for k in self.bits.keys() {
            if k.is_empty() {
                return Err(FlagError::EmptyName);
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
    fn flagset_serde_roundtrip() {
        let mut s = FlagSet::new();
        s.register("a").unwrap();
        s.set("a").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: FlagSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
