//! `selfdef-handler-registry` — kind → handler routing.
//!
//! Register named handlers per kind with priority; resolve(kind)
//! returns highest-priority handler.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One handler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handler {
    /// Id.
    pub id: String,
    /// Priority (higher wins).
    pub priority: u32,
    /// Enabled.
    pub enabled: bool,
}

/// Per-kind list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KindEntry {
    /// Handlers (sorted descending by priority).
    pub handlers: Vec<Handler>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandlerRegistry {
    /// Schema version.
    pub schema_version: String,
    /// kind → entry.
    pub kinds: BTreeMap<String, KindEntry>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("kind empty")]
    EmptyKind,
    /// Empty.
    #[error("handler id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate handler for kind {kind}: {id}")]
    DuplicateHandler {
        /// kind.
        kind: String,
        /// id.
        id: String,
    },
    /// Unknown.
    #[error("unknown handler for kind {kind}: {id}")]
    UnknownHandler {
        /// kind.
        kind: String,
        /// id.
        id: String,
    },
}

impl HandlerRegistry {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            kinds: BTreeMap::new(),
        }
    }

    /// Register.
    pub fn register(&mut self, kind: &str, id: &str, priority: u32) -> Result<(), RegistryError> {
        if kind.is_empty() {
            return Err(RegistryError::EmptyKind);
        }
        if id.is_empty() {
            return Err(RegistryError::EmptyId);
        }
        let entry = self.kinds.entry(kind.into()).or_default();
        if entry.handlers.iter().any(|h| h.id == id) {
            return Err(RegistryError::DuplicateHandler {
                kind: kind.into(),
                id: id.into(),
            });
        }
        entry.handlers.push(Handler {
            id: id.into(),
            priority,
            enabled: true,
        });
        entry
            .handlers
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
        Ok(())
    }

    /// Set enabled.
    pub fn set_enabled(
        &mut self,
        kind: &str,
        id: &str,
        enabled: bool,
    ) -> Result<(), RegistryError> {
        let entry = self
            .kinds
            .get_mut(kind)
            .ok_or_else(|| RegistryError::UnknownHandler {
                kind: kind.into(),
                id: id.into(),
            })?;
        let h = entry
            .handlers
            .iter_mut()
            .find(|h| h.id == id)
            .ok_or_else(|| RegistryError::UnknownHandler {
                kind: kind.into(),
                id: id.into(),
            })?;
        h.enabled = enabled;
        Ok(())
    }

    /// Resolve top handler for kind.
    pub fn resolve(&self, kind: &str) -> Option<String> {
        self.kinds
            .get(kind)?
            .handlers
            .iter()
            .find(|h| h.enabled)
            .map(|h| h.id.clone())
    }

    /// All enabled handlers for kind in priority order.
    pub fn handlers_for(&self, kind: &str) -> Vec<Handler> {
        self.kinds
            .get(kind)
            .map(|e| e.handlers.iter().filter(|h| h.enabled).cloned().collect())
            .unwrap_or_default()
    }

    /// Remove handler.
    pub fn unregister(&mut self, kind: &str, id: &str) -> bool {
        let Some(entry) = self.kinds.get_mut(kind) else {
            return false;
        };
        let before = entry.handlers.len();
        entry.handlers.retain(|h| h.id != id);
        let removed = entry.handlers.len() != before;
        if entry.handlers.is_empty() {
            self.kinds.remove(kind);
        }
        removed
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RegistryError::SchemaMismatch);
        }
        for (k, entry) in &self.kinds {
            if k.is_empty() {
                return Err(RegistryError::EmptyKind);
            }
            for h in &entry.handlers {
                if h.id.is_empty() {
                    return Err(RegistryError::EmptyId);
                }
            }
        }
        Ok(())
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_priority_wins() {
        let mut r = HandlerRegistry::new();
        r.register("kind1", "low", 1).unwrap();
        r.register("kind1", "high", 10).unwrap();
        assert_eq!(r.resolve("kind1").as_deref(), Some("high"));
    }

    #[test]
    fn disabled_skipped() {
        let mut r = HandlerRegistry::new();
        r.register("k", "a", 10).unwrap();
        r.register("k", "b", 5).unwrap();
        r.set_enabled("k", "a", false).unwrap();
        assert_eq!(r.resolve("k").as_deref(), Some("b"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut r = HandlerRegistry::new();
        r.register("k", "a", 1).unwrap();
        assert!(matches!(
            r.register("k", "a", 1).unwrap_err(),
            RegistryError::DuplicateHandler { .. }
        ));
    }

    #[test]
    fn unknown_handler_rejected() {
        let mut r = HandlerRegistry::new();
        assert!(matches!(
            r.set_enabled("k", "nope", false).unwrap_err(),
            RegistryError::UnknownHandler { .. }
        ));
    }

    #[test]
    fn unregister_cleans_empty_kind() {
        let mut r = HandlerRegistry::new();
        r.register("k", "a", 1).unwrap();
        assert!(r.unregister("k", "a"));
        assert!(r.resolve("k").is_none());
    }

    #[test]
    fn handlers_for_priority_order() {
        let mut r = HandlerRegistry::new();
        r.register("k", "a", 1).unwrap();
        r.register("k", "b", 10).unwrap();
        let v = r.handlers_for("k");
        assert_eq!(v[0].id, "b");
        assert_eq!(v[1].id, "a");
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut r = HandlerRegistry::new();
        assert!(matches!(
            r.register("", "x", 1).unwrap_err(),
            RegistryError::EmptyKind
        ));
        assert!(matches!(
            r.register("k", "", 1).unwrap_err(),
            RegistryError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = HandlerRegistry::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RegistryError::SchemaMismatch
        ));
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = HandlerRegistry::new();
        r.register("k", "a", 1).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: HandlerRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
