//! `selfdef-policy-cas-store` — compare-and-swap policy values.
//!
//! Each policy key has a `Versioned { value, version }`. Every
//! `put_cas(key, value, expected_version)` succeeds only if the
//! current version equals `expected_version`; on success, version
//! is bumped by 1. New keys are created with `expected_version = 0`.
//!
//! `get(key)` returns the current Versioned (or None). `force(key,
//! value)` is a non-CAS write — should be rare; bumps the version.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Versioned value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Versioned {
    /// Value bytes (caller-encoded).
    pub value: Vec<u8>,
    /// Monotonic version.
    pub version: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCasStore {
    /// Schema version.
    pub schema_version: String,
    /// key → versioned value.
    pub keys: BTreeMap<String, Versioned>,
}

/// CAS verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CasVerdict {
    /// Wrote — returns new version.
    Wrote {
        /// new version.
        new_version: u64,
    },
    /// Version mismatch.
    Conflict {
        /// what we saw.
        observed_version: u64,
        /// what caller expected.
        expected_version: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CasError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty key.
    #[error("key empty")]
    EmptyKey,
}

impl PolicyCasStore {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            keys: BTreeMap::new(),
        }
    }

    /// Get.
    pub fn get(&self, key: &str) -> Option<&Versioned> {
        self.keys.get(key)
    }

    /// CAS put. New keys require expected_version = 0.
    pub fn put_cas(
        &mut self,
        key: &str,
        value: Vec<u8>,
        expected_version: u64,
    ) -> Result<CasVerdict, CasError> {
        if key.is_empty() {
            return Err(CasError::EmptyKey);
        }
        let current = self.keys.get(key);
        let observed = current.map(|v| v.version).unwrap_or(0);
        if observed != expected_version {
            return Ok(CasVerdict::Conflict {
                observed_version: observed,
                expected_version,
            });
        }
        let new_version = observed.saturating_add(1);
        self.keys.insert(
            key.into(),
            Versioned {
                value,
                version: new_version,
            },
        );
        Ok(CasVerdict::Wrote { new_version })
    }

    /// Forced write (non-CAS); bumps version.
    pub fn force(&mut self, key: &str, value: Vec<u8>) -> Result<u64, CasError> {
        if key.is_empty() {
            return Err(CasError::EmptyKey);
        }
        let current = self.keys.get(key);
        let new_version = current.map(|v| v.version).unwrap_or(0).saturating_add(1);
        self.keys.insert(
            key.into(),
            Versioned {
                value,
                version: new_version,
            },
        );
        Ok(new_version)
    }

    /// Delete (returns true if removed).
    pub fn delete(&mut self, key: &str) -> bool {
        self.keys.remove(key).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CasError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CasError::SchemaMismatch);
        }
        for k in self.keys.keys() {
            if k.is_empty() {
                return Err(CasError::EmptyKey);
            }
        }
        Ok(())
    }
}

impl Default for PolicyCasStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_key() {
        let mut s = PolicyCasStore::new();
        match s.put_cas("k", b"v1".to_vec(), 0).unwrap() {
            CasVerdict::Wrote { new_version } => assert_eq!(new_version, 1),
            _ => panic!(),
        }
    }

    #[test]
    fn update_with_correct_version() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v1".to_vec(), 0).unwrap();
        match s.put_cas("k", b"v2".to_vec(), 1).unwrap() {
            CasVerdict::Wrote { new_version } => assert_eq!(new_version, 2),
            _ => panic!(),
        }
        assert_eq!(s.get("k").unwrap().value, b"v2");
    }

    #[test]
    fn conflict_on_stale_version() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v1".to_vec(), 0).unwrap();
        match s.put_cas("k", b"v2".to_vec(), 0).unwrap() {
            CasVerdict::Conflict {
                observed_version,
                expected_version,
            } => {
                assert_eq!(observed_version, 1);
                assert_eq!(expected_version, 0);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn conflict_creating_existing() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v1".to_vec(), 0).unwrap();
        // Try to create again (expected=0, observed=1).
        assert!(matches!(
            s.put_cas("k", b"v2".to_vec(), 0).unwrap(),
            CasVerdict::Conflict { .. }
        ));
    }

    #[test]
    fn force_bumps_version() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v1".to_vec(), 0).unwrap();
        let v = s.force("k", b"v2".to_vec()).unwrap();
        assert_eq!(v, 2);
        assert_eq!(s.get("k").unwrap().version, 2);
    }

    #[test]
    fn delete_works() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v".to_vec(), 0).unwrap();
        assert!(s.delete("k"));
        assert!(s.get("k").is_none());
        // Now creating fresh requires expected=0 again.
        assert!(matches!(
            s.put_cas("k", b"v".to_vec(), 0).unwrap(),
            CasVerdict::Wrote { new_version: 1 }
        ));
    }

    #[test]
    fn empty_key_rejected() {
        let mut s = PolicyCasStore::new();
        assert!(matches!(
            s.put_cas("", b"v".to_vec(), 0).unwrap_err(),
            CasError::EmptyKey
        ));
        assert!(matches!(
            s.force("", b"v".to_vec()).unwrap_err(),
            CasError::EmptyKey
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PolicyCasStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            CasError::SchemaMismatch
        ));
    }

    #[test]
    fn cas_serde_roundtrip() {
        let mut s = PolicyCasStore::new();
        s.put_cas("k", b"v".to_vec(), 0).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: PolicyCasStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
