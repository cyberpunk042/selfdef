//! `selfdef-kv-store` — versioned key→value store.
//!
//! Entry{value, generation}. set(key, value) increments
//! generation per-key. cas(key, expected_gen, value) succeeds
//! iff current generation == expected; else GenerationMismatch.
//! get_with_gen returns (value, gen). delete bumps generation
//! and removes value.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Value (None when tombstoned).
    pub value: Option<String>,
    /// Generation (advances on every mutation).
    pub generation: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KvStore {
    /// Schema version.
    pub schema_version: String,
    /// key → entry.
    pub entries: BTreeMap<String, Entry>,
    /// Lifetime mutations.
    pub mutations: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum KvError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// CAS mismatch.
    #[error("generation mismatch: expected {expected}, current {current}")]
    GenerationMismatch {
        /// Expected.
        expected: u64,
        /// Current.
        current: u64,
    },
}

impl KvStore {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
            mutations: 0,
        }
    }

    /// Set (returns new generation).
    pub fn set(&mut self, key: &str, value: &str) -> Result<u64, KvError> {
        if key.is_empty() {
            return Err(KvError::EmptyKey);
        }
        let e = self.entries.entry(key.into()).or_insert(Entry {
            value: None,
            generation: 0,
        });
        e.generation = e.generation.saturating_add(1);
        e.value = Some(value.into());
        self.mutations = self.mutations.saturating_add(1);
        Ok(e.generation)
    }

    /// CAS update.
    pub fn cas(&mut self, key: &str, expected_gen: u64, value: &str) -> Result<u64, KvError> {
        if key.is_empty() {
            return Err(KvError::EmptyKey);
        }
        let current = self.entries.get(key).map(|e| e.generation).unwrap_or(0);
        if current != expected_gen {
            return Err(KvError::GenerationMismatch {
                expected: expected_gen,
                current,
            });
        }
        let e = self.entries.entry(key.into()).or_insert(Entry {
            value: None,
            generation: 0,
        });
        e.generation = e.generation.saturating_add(1);
        e.value = Some(value.into());
        self.mutations = self.mutations.saturating_add(1);
        Ok(e.generation)
    }

    /// Get value (None when absent or tombstoned).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).and_then(|e| e.value.as_deref())
    }

    /// Get (value, gen).
    pub fn get_with_gen(&self, key: &str) -> Option<(&str, u64)> {
        self.entries
            .get(key)
            .and_then(|e| e.value.as_deref().map(|v| (v, e.generation)))
    }

    /// Delete (tombstones; generation advances).
    pub fn delete(&mut self, key: &str) -> Option<u64> {
        let e = self.entries.get_mut(key)?;
        e.generation = e.generation.saturating_add(1);
        e.value = None;
        self.mutations = self.mutations.saturating_add(1);
        Some(e.generation)
    }

    /// Count of live entries.
    pub fn live_count(&self) -> usize {
        self.entries.values().filter(|e| e.value.is_some()).count()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), KvError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KvError::SchemaMismatch);
        }
        for k in self.entries.keys() {
            if k.is_empty() {
                return Err(KvError::EmptyKey);
            }
        }
        Ok(())
    }
}

impl Default for KvStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut s = KvStore::new();
        let g = s.set("k", "v").unwrap();
        assert_eq!(g, 1);
        assert_eq!(s.get("k"), Some("v"));
    }

    #[test]
    fn set_increments_generation() {
        let mut s = KvStore::new();
        s.set("k", "v1").unwrap();
        let g = s.set("k", "v2").unwrap();
        assert_eq!(g, 2);
        assert_eq!(s.get("k"), Some("v2"));
    }

    #[test]
    fn cas_success() {
        let mut s = KvStore::new();
        s.set("k", "v1").unwrap();
        let g = s.cas("k", 1, "v2").unwrap();
        assert_eq!(g, 2);
        assert_eq!(s.get("k"), Some("v2"));
    }

    #[test]
    fn cas_mismatch_rejected() {
        let mut s = KvStore::new();
        s.set("k", "v1").unwrap();
        assert!(matches!(
            s.cas("k", 99, "v2").unwrap_err(),
            KvError::GenerationMismatch { .. }
        ));
        assert_eq!(s.get("k"), Some("v1"));
    }

    #[test]
    fn cas_on_missing_uses_gen_zero() {
        let mut s = KvStore::new();
        let g = s.cas("k", 0, "v1").unwrap();
        assert_eq!(g, 1);
    }

    #[test]
    fn delete_tombstones() {
        let mut s = KvStore::new();
        s.set("k", "v").unwrap();
        let g = s.delete("k").unwrap();
        assert_eq!(g, 2);
        assert!(s.get("k").is_none());
        assert_eq!(s.live_count(), 0);
    }

    #[test]
    fn get_with_gen_returns_pair() {
        let mut s = KvStore::new();
        s.set("k", "v").unwrap();
        assert_eq!(s.get_with_gen("k"), Some(("v", 1)));
    }

    #[test]
    fn empty_key_rejected() {
        let mut s = KvStore::new();
        assert!(matches!(s.set("", "v").unwrap_err(), KvError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = KvStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), KvError::SchemaMismatch));
    }

    #[test]
    fn store_serde_roundtrip() {
        let mut s = KvStore::new();
        s.set("k", "v").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: KvStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
