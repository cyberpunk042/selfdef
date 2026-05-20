//! `selfdef-patch-set` — patch ops over a string→string map.
//!
//! Op{Set(k,v) / Remove(k) / Test(k, expected)}. apply(ops)
//! validates Test ops first (any mismatch → all-or-none
//! rejection without mutating). Then applies Set/Remove in
//! order. Pure data.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Op.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum Op {
    /// Set k=v.
    Set {
        /// Key.
        key: String,
        /// Value.
        value: String,
    },
    /// Remove key (idempotent).
    Remove {
        /// Key.
        key: String,
    },
    /// Test that key has expected value.
    Test {
        /// Key.
        key: String,
        /// Expected value.
        expected: String,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchTarget {
    /// Schema version.
    pub schema_version: String,
    /// Underlying map.
    pub entries: BTreeMap<String, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PatchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("value empty")]
    EmptyValue,
    /// Test failed.
    #[error("test failed: key {key} value mismatch")]
    TestFailed {
        /// Key.
        key: String,
    },
    /// Test on missing.
    #[error("test failed: key {key} missing")]
    TestMissing {
        /// Key.
        key: String,
    },
}

impl PatchTarget {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Validate ops (basic shape checks).
    fn check_ops(ops: &[Op]) -> Result<(), PatchError> {
        for o in ops {
            match o {
                Op::Set { key, value } => {
                    if key.is_empty() { return Err(PatchError::EmptyKey); }
                    if value.is_empty() { return Err(PatchError::EmptyValue); }
                }
                Op::Remove { key } | Op::Test { key, .. } => {
                    if key.is_empty() { return Err(PatchError::EmptyKey); }
                }
            }
        }
        Ok(())
    }

    /// Apply patch (all-or-none).
    pub fn apply(&mut self, ops: &[Op]) -> Result<(), PatchError> {
        Self::check_ops(ops)?;
        // Pre-validate all Test ops against current state.
        for o in ops {
            if let Op::Test { key, expected } = o {
                match self.entries.get(key) {
                    Some(v) if v == expected => {}
                    Some(_) => return Err(PatchError::TestFailed { key: key.clone() }),
                    None => return Err(PatchError::TestMissing { key: key.clone() }),
                }
            }
        }
        // Apply Set/Remove (skip Test).
        for o in ops {
            match o {
                Op::Set { key, value } => {
                    self.entries.insert(key.clone(), value.clone());
                }
                Op::Remove { key } => {
                    self.entries.remove(key);
                }
                Op::Test { .. } => {}
            }
        }
        Ok(())
    }

    /// Get.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PatchError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PatchError::SchemaMismatch); }
        for (k, v) in &self.entries {
            if k.is_empty() { return Err(PatchError::EmptyKey); }
            if v.is_empty() { return Err(PatchError::EmptyValue); }
        }
        Ok(())
    }
}

impl Default for PatchTarget {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_applies() {
        let mut t = PatchTarget::new();
        t.apply(&[Op::Set { key: "a".into(), value: "1".into() }]).unwrap();
        assert_eq!(t.get("a"), Some("1"));
    }

    #[test]
    fn remove_applies() {
        let mut t = PatchTarget::new();
        t.apply(&[Op::Set { key: "a".into(), value: "1".into() }]).unwrap();
        t.apply(&[Op::Remove { key: "a".into() }]).unwrap();
        assert!(t.get("a").is_none());
    }

    #[test]
    fn test_pass_allows_apply() {
        let mut t = PatchTarget::new();
        t.apply(&[Op::Set { key: "a".into(), value: "1".into() }]).unwrap();
        t.apply(&[
            Op::Test { key: "a".into(), expected: "1".into() },
            Op::Set { key: "b".into(), value: "2".into() },
        ]).unwrap();
        assert_eq!(t.get("b"), Some("2"));
    }

    #[test]
    fn test_fail_aborts_all() {
        let mut t = PatchTarget::new();
        t.apply(&[Op::Set { key: "a".into(), value: "1".into() }]).unwrap();
        let r = t.apply(&[
            Op::Test { key: "a".into(), expected: "OTHER".into() },
            Op::Set { key: "b".into(), value: "2".into() },
        ]);
        assert!(matches!(r.unwrap_err(), PatchError::TestFailed { .. }));
        assert!(t.get("b").is_none());
        assert_eq!(t.get("a"), Some("1"));
    }

    #[test]
    fn test_missing_aborts() {
        let mut t = PatchTarget::new();
        let r = t.apply(&[
            Op::Test { key: "absent".into(), expected: "x".into() },
            Op::Set { key: "b".into(), value: "2".into() },
        ]);
        assert!(matches!(r.unwrap_err(), PatchError::TestMissing { .. }));
        assert!(t.get("b").is_none());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = PatchTarget::new();
        assert!(matches!(
            t.apply(&[Op::Set { key: "".into(), value: "v".into() }]).unwrap_err(),
            PatchError::EmptyKey
        ));
        assert!(matches!(
            t.apply(&[Op::Set { key: "k".into(), value: "".into() }]).unwrap_err(),
            PatchError::EmptyValue
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = PatchTarget::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), PatchError::SchemaMismatch));
    }

    #[test]
    fn target_serde_roundtrip() {
        let mut t = PatchTarget::new();
        t.apply(&[Op::Set { key: "a".into(), value: "1".into() }]).unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: PatchTarget = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
