//! `selfdef-route-table` — exact + longest-prefix routing.
//!
//! Per route: kind (Exact | Prefix), handler_id. resolve(key)
//! walks Exact map first; if no hit, scans Prefix map for the
//! longest matching prefix. Returns handler_id + match kind.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Match kind for resolution result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MatchKind {
    /// Exact.
    Exact,
    /// Prefix.
    Prefix,
}

/// Resolution result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// Handler id.
    pub handler_id: &'a str,
    /// Match kind.
    pub kind: MatchKind,
    /// Match length (for prefix; key length for exact).
    pub matched_len: usize,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteTable {
    /// Schema version.
    pub schema_version: String,
    /// exact_key → handler_id.
    pub exact: BTreeMap<String, String>,
    /// prefix → handler_id.
    pub prefix: BTreeMap<String, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RouteError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Empty.
    #[error("handler_id empty")]
    EmptyHandler,
    /// Duplicate.
    #[error("duplicate exact route: {0}")]
    DuplicateExact(String),
    /// Duplicate.
    #[error("duplicate prefix route: {0}")]
    DuplicatePrefix(String),
}

impl RouteTable {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            exact: BTreeMap::new(),
            prefix: BTreeMap::new(),
        }
    }

    /// Add exact route.
    pub fn add_exact(&mut self, key: &str, handler_id: &str) -> Result<(), RouteError> {
        if key.is_empty() {
            return Err(RouteError::EmptyKey);
        }
        if handler_id.is_empty() {
            return Err(RouteError::EmptyHandler);
        }
        if self.exact.contains_key(key) {
            return Err(RouteError::DuplicateExact(key.into()));
        }
        self.exact.insert(key.into(), handler_id.into());
        Ok(())
    }

    /// Add prefix route.
    pub fn add_prefix(&mut self, prefix: &str, handler_id: &str) -> Result<(), RouteError> {
        if prefix.is_empty() {
            return Err(RouteError::EmptyKey);
        }
        if handler_id.is_empty() {
            return Err(RouteError::EmptyHandler);
        }
        if self.prefix.contains_key(prefix) {
            return Err(RouteError::DuplicatePrefix(prefix.into()));
        }
        self.prefix.insert(prefix.into(), handler_id.into());
        Ok(())
    }

    /// Resolve a key.
    pub fn resolve(&self, key: &str) -> Option<Resolution<'_>> {
        if let Some(h) = self.exact.get(key) {
            return Some(Resolution {
                handler_id: h.as_str(),
                kind: MatchKind::Exact,
                matched_len: key.len(),
            });
        }
        let mut best: Option<(&str, &str)> = None; // (prefix, handler)
        for (p, h) in &self.prefix {
            if key.starts_with(p.as_str()) {
                if best.map(|(bp, _)| p.len() > bp.len()).unwrap_or(true) {
                    best = Some((p.as_str(), h.as_str()));
                }
            }
        }
        best.map(|(p, h)| Resolution {
            handler_id: h,
            kind: MatchKind::Prefix,
            matched_len: p.len(),
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RouteError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RouteError::SchemaMismatch);
        }
        for (k, v) in self.exact.iter().chain(self.prefix.iter()) {
            if k.is_empty() {
                return Err(RouteError::EmptyKey);
            }
            if v.is_empty() {
                return Err(RouteError::EmptyHandler);
            }
        }
        Ok(())
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_takes_precedence() {
        let mut t = RouteTable::new();
        t.add_exact("/api/users", "users").unwrap();
        t.add_prefix("/api/", "api-fallback").unwrap();
        let r = t.resolve("/api/users").unwrap();
        assert_eq!(r.handler_id, "users");
        assert_eq!(r.kind, MatchKind::Exact);
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = RouteTable::new();
        t.add_prefix("/api/", "api-base").unwrap();
        t.add_prefix("/api/v1/", "api-v1").unwrap();
        let r = t.resolve("/api/v1/users").unwrap();
        assert_eq!(r.handler_id, "api-v1");
        assert_eq!(r.matched_len, 8); // "/api/v1/"
    }

    #[test]
    fn no_match_returns_none() {
        let t = RouteTable::new();
        assert!(t.resolve("/anything").is_none());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut t = RouteTable::new();
        assert!(matches!(
            t.add_exact("", "h").unwrap_err(),
            RouteError::EmptyKey
        ));
        assert!(matches!(
            t.add_exact("/k", "").unwrap_err(),
            RouteError::EmptyHandler
        ));
        assert!(matches!(
            t.add_prefix("", "h").unwrap_err(),
            RouteError::EmptyKey
        ));
    }

    #[test]
    fn duplicate_exact_rejected() {
        let mut t = RouteTable::new();
        t.add_exact("/a", "h1").unwrap();
        assert!(matches!(
            t.add_exact("/a", "h2").unwrap_err(),
            RouteError::DuplicateExact(_)
        ));
    }

    #[test]
    fn duplicate_prefix_rejected() {
        let mut t = RouteTable::new();
        t.add_prefix("/a/", "h1").unwrap();
        assert!(matches!(
            t.add_prefix("/a/", "h2").unwrap_err(),
            RouteError::DuplicatePrefix(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = RouteTable::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            RouteError::SchemaMismatch
        ));
    }

    #[test]
    fn table_serde_roundtrip() {
        let mut t = RouteTable::new();
        t.add_exact("/a", "h").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: RouteTable = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
