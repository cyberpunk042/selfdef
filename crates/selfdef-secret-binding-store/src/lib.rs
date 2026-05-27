//! `selfdef-secret-binding-store` — per-actor secret bindings.
//!
//! Binding{actor, name, ref_path}. bind/unbind manage; resolve
//! returns ref_path. No raw secret material is stored; ref_path
//! points to vault location.
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
pub struct SecretBindingStore {
    /// Schema version.
    pub schema_version: String,
    /// actor → (name → ref_path).
    pub bindings: BTreeMap<String, BTreeMap<String, String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BindError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("ref_path empty")]
    EmptyRefPath,
}

impl SecretBindingStore {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            bindings: BTreeMap::new(),
        }
    }

    /// Bind.
    pub fn bind(&mut self, actor: &str, name: &str, ref_path: &str) -> Result<bool, BindError> {
        if actor.is_empty() {
            return Err(BindError::EmptyActor);
        }
        if name.is_empty() {
            return Err(BindError::EmptyName);
        }
        if ref_path.is_empty() {
            return Err(BindError::EmptyRefPath);
        }
        let prev = self
            .bindings
            .entry(actor.into())
            .or_default()
            .insert(name.into(), ref_path.into());
        Ok(prev.is_none())
    }

    /// Unbind.
    pub fn unbind(&mut self, actor: &str, name: &str) -> bool {
        let Some(m) = self.bindings.get_mut(actor) else {
            return false;
        };
        let removed = m.remove(name).is_some();
        if m.is_empty() {
            self.bindings.remove(actor);
        }
        removed
    }

    /// Resolve.
    pub fn resolve(&self, actor: &str, name: &str) -> Option<String> {
        self.bindings.get(actor).and_then(|m| m.get(name)).cloned()
    }

    /// Names bound for actor.
    pub fn names_of(&self, actor: &str) -> Vec<String> {
        self.bindings
            .get(actor)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BindError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BindError::SchemaMismatch);
        }
        for (a, m) in &self.bindings {
            if a.is_empty() {
                return Err(BindError::EmptyActor);
            }
            for (n, p) in m {
                if n.is_empty() {
                    return Err(BindError::EmptyName);
                }
                if p.is_empty() {
                    return Err(BindError::EmptyRefPath);
                }
            }
        }
        Ok(())
    }
}

impl Default for SecretBindingStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_resolve() {
        let mut s = SecretBindingStore::new();
        s.bind("alice", "api-key", "vault://alice/api-key").unwrap();
        assert_eq!(
            s.resolve("alice", "api-key").as_deref(),
            Some("vault://alice/api-key")
        );
    }

    #[test]
    fn rebind_replaces() {
        let mut s = SecretBindingStore::new();
        assert!(s.bind("alice", "k", "v1").unwrap());
        assert!(!s.bind("alice", "k", "v2").unwrap());
        assert_eq!(s.resolve("alice", "k").as_deref(), Some("v2"));
    }

    #[test]
    fn unbind_works() {
        let mut s = SecretBindingStore::new();
        s.bind("alice", "k", "v").unwrap();
        assert!(s.unbind("alice", "k"));
        assert!(!s.unbind("alice", "k"));
        assert!(s.names_of("alice").is_empty());
    }

    #[test]
    fn names_of() {
        let mut s = SecretBindingStore::new();
        s.bind("alice", "a", "v").unwrap();
        s.bind("alice", "b", "v").unwrap();
        let mut n = s.names_of("alice");
        n.sort();
        assert_eq!(n, vec!["a", "b"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = SecretBindingStore::new();
        assert!(matches!(
            s.bind("", "k", "v").unwrap_err(),
            BindError::EmptyActor
        ));
        assert!(matches!(
            s.bind("a", "", "v").unwrap_err(),
            BindError::EmptyName
        ));
        assert!(matches!(
            s.bind("a", "k", "").unwrap_err(),
            BindError::EmptyRefPath
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = SecretBindingStore::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            BindError::SchemaMismatch
        ));
    }

    #[test]
    fn binding_serde_roundtrip() {
        let mut s = SecretBindingStore::new();
        s.bind("alice", "k", "vault://x").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: SecretBindingStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
