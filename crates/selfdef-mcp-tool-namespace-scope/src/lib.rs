//! `selfdef-mcp-tool-namespace-scope` — per-tool caller-namespace allowlist.
//!
//! `allow(tool_id, namespace)` records. `classify(tool_id, namespace)`
//! returns `Allowed` if the namespace (or `*`) is in the set,
//! `Denied{allowed}` otherwise, `UnknownTool` if the tool wasn't
//! registered at all.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolNamespaceScope {
    /// Schema version.
    pub schema_version: String,
    /// tool_id → allowed namespaces.
    pub scopes: BTreeMap<String, BTreeSet<String>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScopeVerdict {
    /// Allowed.
    Allowed,
    /// Denied.
    Denied {
        /// allowed list.
        allowed: Vec<String>,
    },
    /// Tool not registered.
    UnknownTool,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ScopeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty tool id.
    #[error("tool id empty")]
    EmptyTool,
    /// Empty namespace.
    #[error("namespace empty")]
    EmptyNamespace,
}

impl McpToolNamespaceScope {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            scopes: BTreeMap::new(),
        }
    }

    /// Allow a namespace for a tool.
    pub fn allow(&mut self, tool_id: &str, namespace: &str) -> Result<(), ScopeError> {
        if tool_id.is_empty() { return Err(ScopeError::EmptyTool); }
        if namespace.is_empty() { return Err(ScopeError::EmptyNamespace); }
        self.scopes.entry(tool_id.into()).or_default().insert(namespace.into());
        Ok(())
    }

    /// Revoke a namespace for a tool.
    pub fn revoke(&mut self, tool_id: &str, namespace: &str) -> bool {
        if let Some(s) = self.scopes.get_mut(tool_id) {
            if s.remove(namespace) {
                if s.is_empty() { self.scopes.remove(tool_id); }
                return true;
            }
        }
        false
    }

    /// Classify.
    pub fn classify(&self, tool_id: &str, namespace: &str) -> ScopeVerdict {
        let set = match self.scopes.get(tool_id) {
            Some(s) => s,
            None => return ScopeVerdict::UnknownTool,
        };
        if set.contains("*") || set.contains(namespace) {
            ScopeVerdict::Allowed
        } else {
            ScopeVerdict::Denied { allowed: set.iter().cloned().collect() }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.schema_version != SCHEMA_VERSION { return Err(ScopeError::SchemaMismatch); }
        for (t, s) in &self.scopes {
            if t.is_empty() { return Err(ScopeError::EmptyTool); }
            for n in s {
                if n.is_empty() { return Err(ScopeError::EmptyNamespace); }
            }
        }
        Ok(())
    }
}

impl Default for McpToolNamespaceScope {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tool() {
        let s = McpToolNamespaceScope::new();
        assert_eq!(s.classify("read-file", "ns/a"), ScopeVerdict::UnknownTool);
    }

    #[test]
    fn explicit_allow() {
        let mut s = McpToolNamespaceScope::new();
        s.allow("read-file", "ns/a").unwrap();
        assert_eq!(s.classify("read-file", "ns/a"), ScopeVerdict::Allowed);
        assert!(matches!(s.classify("read-file", "ns/b"), ScopeVerdict::Denied { .. }));
    }

    #[test]
    fn wildcard_allows_all() {
        let mut s = McpToolNamespaceScope::new();
        s.allow("read-file", "*").unwrap();
        assert_eq!(s.classify("read-file", "any-namespace"), ScopeVerdict::Allowed);
    }

    #[test]
    fn revoke_returns_to_denied() {
        let mut s = McpToolNamespaceScope::new();
        s.allow("read-file", "ns/a").unwrap();
        assert!(s.revoke("read-file", "ns/a"));
        // After revoke, tool has no scopes → UnknownTool.
        assert_eq!(s.classify("read-file", "ns/a"), ScopeVerdict::UnknownTool);
    }

    #[test]
    fn revoke_unknown_false() {
        let mut s = McpToolNamespaceScope::new();
        assert!(!s.revoke("read-file", "ns/a"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = McpToolNamespaceScope::new();
        assert!(matches!(s.allow("", "ns").unwrap_err(), ScopeError::EmptyTool));
        assert!(matches!(s.allow("t", "").unwrap_err(), ScopeError::EmptyNamespace));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = McpToolNamespaceScope::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), ScopeError::SchemaMismatch));
    }

    #[test]
    fn scope_serde_roundtrip() {
        let mut s = McpToolNamespaceScope::new();
        s.allow("read-file", "ns/a").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: McpToolNamespaceScope = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
