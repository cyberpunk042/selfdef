//! `selfdef-policy-namespace-policy` — namespace tree with inheritance.
//!
//! Namespace forms a tree. resolve walks leaf→root looking for a
//! key. Sealed namespaces refuse writes.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Namespace {
    /// Stable id.
    pub id: String,
    /// Parent id (None = root).
    pub parent_id: Option<String>,
    /// Mutable (operator may set values)?
    pub mutable: bool,
    /// Stored key→value.
    pub values: BTreeMap<String, String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyNamespacePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Namespaces.
    pub namespaces: Vec<Namespace>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum NamespaceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("namespace id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate namespace id: {0}")]
    DuplicateId(String),
    /// Unknown parent.
    #[error("namespace {ns} unknown parent: {parent}")]
    UnknownParent {
        /// ns.
        ns: String,
        /// parent.
        parent: String,
    },
    /// Cycle in namespace tree.
    #[error("cycle involving namespace {0}")]
    Cycle(String),
    /// Unknown namespace.
    #[error("unknown namespace: {0}")]
    Unknown(String),
    /// Namespace sealed.
    #[error("namespace {0} sealed (immutable)")]
    Sealed(String),
}

impl PolicyNamespacePolicy {
    /// New.
    pub fn new(namespaces: Vec<Namespace>) -> Result<Self, NamespaceError> {
        check_namespaces(&namespaces)?;
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            namespaces,
        })
    }

    /// Set value in a namespace.
    pub fn set(&mut self, ns_id: &str, key: &str, value: &str) -> Result<(), NamespaceError> {
        let ns = self
            .namespaces
            .iter_mut()
            .find(|n| n.id == ns_id)
            .ok_or_else(|| NamespaceError::Unknown(ns_id.into()))?;
        if !ns.mutable {
            return Err(NamespaceError::Sealed(ns_id.into()));
        }
        ns.values.insert(key.into(), value.into());
        Ok(())
    }

    /// Resolve key by walking leaf→root.
    pub fn resolve(&self, ns_id: &str, key: &str) -> Option<&str> {
        let mut current: Option<&Namespace> = self.namespaces.iter().find(|n| n.id == ns_id);
        while let Some(ns) = current {
            if let Some(v) = ns.values.get(key) {
                return Some(v.as_str());
            }
            current = ns
                .parent_id
                .as_ref()
                .and_then(|p| self.namespaces.iter().find(|n| &n.id == p));
        }
        None
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), NamespaceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(NamespaceError::SchemaMismatch);
        }
        check_namespaces(&self.namespaces)
    }
}

fn check_namespaces(ns: &[Namespace]) -> Result<(), NamespaceError> {
    use std::collections::{HashMap, HashSet};
    let mut ids: HashSet<&str> = HashSet::new();
    let mut parents: HashMap<&str, Option<&str>> = HashMap::new();
    for n in ns {
        if n.id.is_empty() {
            return Err(NamespaceError::EmptyId);
        }
        if !ids.insert(n.id.as_str()) {
            return Err(NamespaceError::DuplicateId(n.id.clone()));
        }
        parents.insert(n.id.as_str(), n.parent_id.as_deref());
    }
    for n in ns {
        if let Some(p) = &n.parent_id {
            if !ids.contains(p.as_str()) {
                return Err(NamespaceError::UnknownParent {
                    ns: n.id.clone(),
                    parent: p.clone(),
                });
            }
        }
    }
    // Cycle detection.
    for n in ns {
        let mut seen: HashSet<&str> = HashSet::new();
        let mut cur = n.parent_id.as_deref();
        while let Some(c) = cur {
            if c == n.id || !seen.insert(c) {
                return Err(NamespaceError::Cycle(n.id.clone()));
            }
            cur = parents.get(c).and_then(|p| *p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(id: &str, parent: Option<&str>, mutable: bool) -> Namespace {
        Namespace {
            id: id.into(),
            parent_id: parent.map(|s| s.into()),
            mutable,
            values: BTreeMap::new(),
        }
    }

    #[test]
    fn empty_validates() {
        PolicyNamespacePolicy::new(vec![])
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn set_in_mutable() {
        let mut p = PolicyNamespacePolicy::new(vec![ns("a", None, true)]).unwrap();
        p.set("a", "k", "v").unwrap();
        assert_eq!(p.resolve("a", "k"), Some("v"));
    }

    #[test]
    fn set_in_sealed_rejected() {
        let mut p = PolicyNamespacePolicy::new(vec![ns("a", None, false)]).unwrap();
        assert!(matches!(
            p.set("a", "k", "v").unwrap_err(),
            NamespaceError::Sealed(_)
        ));
    }

    #[test]
    fn resolve_walks_to_parent() {
        let mut p = PolicyNamespacePolicy::new(vec![
            ns("root", None, true),
            ns("child", Some("root"), true),
        ])
        .unwrap();
        p.set("root", "shared", "v-root").unwrap();
        assert_eq!(p.resolve("child", "shared"), Some("v-root"));
    }

    #[test]
    fn child_overrides_parent() {
        let mut p = PolicyNamespacePolicy::new(vec![
            ns("root", None, true),
            ns("child", Some("root"), true),
        ])
        .unwrap();
        p.set("root", "shared", "v-root").unwrap();
        p.set("child", "shared", "v-child").unwrap();
        assert_eq!(p.resolve("child", "shared"), Some("v-child"));
    }

    #[test]
    fn unknown_namespace_rejected() {
        let mut p = PolicyNamespacePolicy::new(vec![]).unwrap();
        assert!(matches!(
            p.set("ghost", "k", "v").unwrap_err(),
            NamespaceError::Unknown(_)
        ));
    }

    #[test]
    fn unknown_parent_rejected_on_construction() {
        assert!(matches!(
            PolicyNamespacePolicy::new(vec![ns("a", Some("ghost"), true)]).unwrap_err(),
            NamespaceError::UnknownParent { .. }
        ));
    }

    #[test]
    fn cycle_detected() {
        let nss = vec![ns("a", Some("b"), true), ns("b", Some("a"), true)];
        assert!(matches!(
            PolicyNamespacePolicy::new(nss).unwrap_err(),
            NamespaceError::Cycle(_)
        ));
    }

    #[test]
    fn duplicate_rejected() {
        assert!(matches!(
            PolicyNamespacePolicy::new(vec![ns("a", None, true), ns("a", None, true)]).unwrap_err(),
            NamespaceError::DuplicateId(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicyNamespacePolicy::new(vec![ns("a", None, true)]).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            NamespaceError::SchemaMismatch
        ));
    }

    #[test]
    fn ns_serde_roundtrip() {
        let mut p = PolicyNamespacePolicy::new(vec![ns("a", None, true)]).unwrap();
        p.set("a", "k", "v").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicyNamespacePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
