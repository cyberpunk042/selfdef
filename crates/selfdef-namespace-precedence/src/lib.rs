//! `selfdef-namespace-precedence` — namespace-priority resolver.
//!
//! `set(namespace, priority)` records. `resolve(&[namespace_ids])`
//! returns the namespace with the highest priority among those
//! registered (tiebreaker = lexicographic id ascending). Returns
//! None when none of the candidates are registered.
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
pub struct NamespacePrecedence {
    /// Schema version.
    pub schema_version: String,
    /// namespace → priority (higher wins).
    pub priorities: BTreeMap<String, u32>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PrecError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty namespace.
    #[error("namespace empty")]
    EmptyNamespace,
}

impl NamespacePrecedence {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            priorities: BTreeMap::new(),
        }
    }

    /// Set.
    pub fn set(&mut self, namespace: &str, priority: u32) -> Result<(), PrecError> {
        if namespace.is_empty() {
            return Err(PrecError::EmptyNamespace);
        }
        self.priorities.insert(namespace.into(), priority);
        Ok(())
    }

    /// Resolve.
    pub fn resolve(&self, candidates: &[&str]) -> Option<String> {
        let mut best: Option<(u32, &str)> = None;
        for ns in candidates {
            let p = self.priorities.get(*ns).copied();
            if let Some(p) = p {
                match best {
                    None => best = Some((p, ns)),
                    Some((bp, bns)) => {
                        if p > bp || (p == bp && *ns < bns) {
                            best = Some((p, ns));
                        }
                    }
                }
            }
        }
        best.map(|(_, ns)| ns.to_string())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PrecError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PrecError::SchemaMismatch);
        }
        for k in self.priorities.keys() {
            if k.is_empty() {
                return Err(PrecError::EmptyNamespace);
            }
        }
        Ok(())
    }
}

impl Default for NamespacePrecedence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_wins() {
        let mut p = NamespacePrecedence::new();
        p.set("ns/a", 10).unwrap();
        p.set("ns/b", 100).unwrap();
        assert_eq!(p.resolve(&["ns/a", "ns/b"]), Some("ns/b".into()));
    }

    #[test]
    fn tiebreak_lex() {
        let mut p = NamespacePrecedence::new();
        p.set("ns/zz", 5).unwrap();
        p.set("ns/aa", 5).unwrap();
        assert_eq!(p.resolve(&["ns/zz", "ns/aa"]), Some("ns/aa".into()));
    }

    #[test]
    fn unknown_namespaces_skipped() {
        let mut p = NamespacePrecedence::new();
        p.set("ns/a", 1).unwrap();
        assert_eq!(p.resolve(&["nope", "ns/a"]), Some("ns/a".into()));
    }

    #[test]
    fn empty_candidates_none() {
        let p = NamespacePrecedence::new();
        assert!(p.resolve(&[]).is_none());
    }

    #[test]
    fn no_registered_none() {
        let p = NamespacePrecedence::new();
        assert!(p.resolve(&["nope"]).is_none());
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = NamespacePrecedence::new();
        assert!(matches!(
            p.set("", 1).unwrap_err(),
            PrecError::EmptyNamespace
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = NamespacePrecedence::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PrecError::SchemaMismatch
        ));
    }

    #[test]
    fn prec_serde_roundtrip() {
        let mut p = NamespacePrecedence::new();
        p.set("ns/a", 10).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: NamespacePrecedence = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
