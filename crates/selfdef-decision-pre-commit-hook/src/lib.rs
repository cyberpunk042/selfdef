//! `selfdef-decision-pre-commit-hook` — pre-commit hook registry.
//!
//! Each hook is `(id, priority, on_block)`. `fire_order()` returns
//! the hooks sorted by priority descending then by registration
//! order (FIFO). The orchestrator invokes them in order; hooks with
//! `on_block=true` are veto-capable.
//!
//! Pure descriptor: no I/O, no callback execution — the orchestrator
//! owns invocation.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One hook entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hook {
    /// Stable id.
    pub id: String,
    /// Priority (higher fires first).
    pub priority: u32,
    /// Veto-capable?
    pub on_block: bool,
    /// FIFO registration sequence number (tie-break).
    pub seq: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionPreCommitHook {
    /// Schema version.
    pub schema_version: String,
    /// id → hook.
    pub hooks: BTreeMap<String, Hook>,
    /// Next seq.
    pub next_seq: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HookError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("hook id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate hook id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown hook id: {0}")]
    UnknownHook(String),
}

impl DecisionPreCommitHook {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            hooks: BTreeMap::new(),
            next_seq: 1,
        }
    }

    /// Register.
    pub fn register(&mut self, id: &str, priority: u32, on_block: bool) -> Result<(), HookError> {
        if id.is_empty() { return Err(HookError::EmptyId); }
        if self.hooks.contains_key(id) {
            return Err(HookError::DuplicateId(id.into()));
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.hooks.insert(id.into(), Hook {
            id: id.into(),
            priority,
            on_block,
            seq,
        });
        Ok(())
    }

    /// Deregister.
    pub fn deregister(&mut self, id: &str) -> Result<(), HookError> {
        self.hooks.remove(id).ok_or_else(|| HookError::UnknownHook(id.into()))?;
        Ok(())
    }

    /// Fire order.
    pub fn fire_order(&self) -> Vec<Hook> {
        let mut v: Vec<Hook> = self.hooks.values().cloned().collect();
        v.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.seq.cmp(&b.seq)));
        v
    }

    /// Subset of veto-capable hooks in fire order.
    pub fn veto_capable(&self) -> Vec<Hook> {
        self.fire_order().into_iter().filter(|h| h.on_block).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HookError> {
        if self.schema_version != SCHEMA_VERSION { return Err(HookError::SchemaMismatch); }
        for (k, _) in &self.hooks {
            if k.is_empty() { return Err(HookError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for DecisionPreCommitHook {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_order_by_priority() {
        let mut r = DecisionPreCommitHook::new();
        r.register("low", 1, false).unwrap();
        r.register("high", 100, false).unwrap();
        r.register("mid", 50, false).unwrap();
        let order: Vec<_> = r.fire_order().into_iter().map(|h| h.id).collect();
        assert_eq!(order, vec!["high", "mid", "low"]);
    }

    #[test]
    fn fifo_tiebreak() {
        let mut r = DecisionPreCommitHook::new();
        r.register("a", 5, false).unwrap();
        r.register("b", 5, false).unwrap();
        let order: Vec<_> = r.fire_order().into_iter().map(|h| h.id).collect();
        assert_eq!(order, vec!["a", "b"]);
    }

    #[test]
    fn veto_capable_subset() {
        let mut r = DecisionPreCommitHook::new();
        r.register("audit", 10, false).unwrap();
        r.register("policy-block", 5, true).unwrap();
        let veto: Vec<_> = r.veto_capable().into_iter().map(|h| h.id).collect();
        assert_eq!(veto, vec!["policy-block"]);
    }

    #[test]
    fn duplicate_rejected() {
        let mut r = DecisionPreCommitHook::new();
        r.register("a", 1, false).unwrap();
        assert!(matches!(r.register("a", 5, false).unwrap_err(), HookError::DuplicateId(_)));
    }

    #[test]
    fn deregister_unknown() {
        let mut r = DecisionPreCommitHook::new();
        assert!(matches!(r.deregister("nope").unwrap_err(), HookError::UnknownHook(_)));
    }

    #[test]
    fn deregister_removes() {
        let mut r = DecisionPreCommitHook::new();
        r.register("a", 1, false).unwrap();
        r.deregister("a").unwrap();
        assert!(r.hooks.is_empty());
    }

    #[test]
    fn empty_id_rejected() {
        let mut r = DecisionPreCommitHook::new();
        assert!(matches!(r.register("", 1, false).unwrap_err(), HookError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = DecisionPreCommitHook::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), HookError::SchemaMismatch));
    }

    #[test]
    fn hook_serde_roundtrip() {
        let mut r = DecisionPreCommitHook::new();
        r.register("a", 10, true).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: DecisionPreCommitHook = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
