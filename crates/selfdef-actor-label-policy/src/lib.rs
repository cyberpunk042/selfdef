//! `selfdef-actor-label-policy` — actor labels.
//!
//! Each actor has a small key→value label map. Keys with the
//! reserved prefix `selfdef.` may only be set/cleared via
//! `set_system_label(...)`; operator calls to `set_user_label(...)`
//! refuse them.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Reserved prefix.
pub const RESERVED_PREFIX: &str = "selfdef.";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorLabelPolicy {
    /// Schema version.
    pub schema_version: String,
    /// actor → label map.
    pub labels: BTreeMap<String, BTreeMap<String, String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum LabelError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor id empty")]
    EmptyActor,
    /// Empty key.
    #[error("key empty")]
    EmptyKey,
    /// Reserved key.
    #[error("key uses reserved prefix \"{0}\" — use set_system_label")]
    ReservedKey(String),
    /// Unknown actor.
    #[error("unknown actor: {0}")]
    UnknownActor(String),
}

impl ActorLabelPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            labels: BTreeMap::new(),
        }
    }

    /// Set a user label (refuses reserved prefix).
    pub fn set_user_label(&mut self, actor: &str, key: &str, value: &str) -> Result<(), LabelError> {
        if actor.is_empty() { return Err(LabelError::EmptyActor); }
        if key.is_empty() { return Err(LabelError::EmptyKey); }
        if key.starts_with(RESERVED_PREFIX) {
            return Err(LabelError::ReservedKey(RESERVED_PREFIX.into()));
        }
        self.labels.entry(actor.into()).or_default().insert(key.into(), value.into());
        Ok(())
    }

    /// Set a system label (any key).
    pub fn set_system_label(&mut self, actor: &str, key: &str, value: &str) -> Result<(), LabelError> {
        if actor.is_empty() { return Err(LabelError::EmptyActor); }
        if key.is_empty() { return Err(LabelError::EmptyKey); }
        self.labels.entry(actor.into()).or_default().insert(key.into(), value.into());
        Ok(())
    }

    /// Get.
    pub fn get(&self, actor: &str, key: &str) -> Option<&str> {
        self.labels.get(actor).and_then(|m| m.get(key)).map(|s| s.as_str())
    }

    /// Remove (user-only — refuses reserved).
    pub fn remove_user_label(&mut self, actor: &str, key: &str) -> Result<bool, LabelError> {
        if key.starts_with(RESERVED_PREFIX) {
            return Err(LabelError::ReservedKey(RESERVED_PREFIX.into()));
        }
        let Some(m) = self.labels.get_mut(actor) else { return Ok(false); };
        let removed = m.remove(key).is_some();
        if m.is_empty() { self.labels.remove(actor); }
        Ok(removed)
    }

    /// Remove (system — any key).
    pub fn remove_system_label(&mut self, actor: &str, key: &str) -> bool {
        let Some(m) = self.labels.get_mut(actor) else { return false; };
        let removed = m.remove(key).is_some();
        if m.is_empty() { self.labels.remove(actor); }
        removed
    }

    /// All labels of an actor (sorted by key).
    pub fn labels_of(&self, actor: &str) -> Vec<(String, String)> {
        self.labels.get(actor).map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
    }

    /// Drop an actor entirely.
    pub fn drop_actor(&mut self, actor: &str) -> bool {
        self.labels.remove(actor).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), LabelError> {
        if self.schema_version != SCHEMA_VERSION { return Err(LabelError::SchemaMismatch); }
        for (a, m) in &self.labels {
            if a.is_empty() { return Err(LabelError::EmptyActor); }
            for k in m.keys() {
                if k.is_empty() { return Err(LabelError::EmptyKey); }
            }
        }
        Ok(())
    }
}

impl Default for ActorLabelPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_user_label_works() {
        let mut p = ActorLabelPolicy::new();
        p.set_user_label("alice", "team", "platform").unwrap();
        assert_eq!(p.get("alice", "team"), Some("platform"));
    }

    #[test]
    fn user_cannot_set_reserved() {
        let mut p = ActorLabelPolicy::new();
        assert!(matches!(p.set_user_label("alice", "selfdef.trust", "high").unwrap_err(), LabelError::ReservedKey(_)));
    }

    #[test]
    fn system_can_set_reserved() {
        let mut p = ActorLabelPolicy::new();
        p.set_system_label("alice", "selfdef.trust", "high").unwrap();
        assert_eq!(p.get("alice", "selfdef.trust"), Some("high"));
    }

    #[test]
    fn user_remove_refuses_reserved() {
        let mut p = ActorLabelPolicy::new();
        p.set_system_label("alice", "selfdef.x", "v").unwrap();
        assert!(matches!(p.remove_user_label("alice", "selfdef.x").unwrap_err(), LabelError::ReservedKey(_)));
    }

    #[test]
    fn system_remove_works_on_any_key() {
        let mut p = ActorLabelPolicy::new();
        p.set_system_label("alice", "selfdef.x", "v").unwrap();
        assert!(p.remove_system_label("alice", "selfdef.x"));
    }

    #[test]
    fn labels_of_sorted() {
        let mut p = ActorLabelPolicy::new();
        p.set_user_label("alice", "z", "1").unwrap();
        p.set_user_label("alice", "a", "2").unwrap();
        let v = p.labels_of("alice");
        assert_eq!(v[0].0, "a");
        assert_eq!(v[1].0, "z");
    }

    #[test]
    fn drop_actor() {
        let mut p = ActorLabelPolicy::new();
        p.set_user_label("alice", "k", "v").unwrap();
        assert!(p.drop_actor("alice"));
        assert!(p.labels_of("alice").is_empty());
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = ActorLabelPolicy::new();
        assert!(matches!(p.set_user_label("", "k", "v").unwrap_err(), LabelError::EmptyActor));
        assert!(matches!(p.set_user_label("a", "", "v").unwrap_err(), LabelError::EmptyKey));
    }

    #[test]
    fn empty_value_allowed() {
        // Empty value is operator's choice (tag rather than k=v).
        let mut p = ActorLabelPolicy::new();
        p.set_user_label("alice", "tag", "").unwrap();
        assert_eq!(p.get("alice", "tag"), Some(""));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActorLabelPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), LabelError::SchemaMismatch));
    }

    #[test]
    fn label_serde_roundtrip() {
        let mut p = ActorLabelPolicy::new();
        p.set_user_label("alice", "team", "platform").unwrap();
        p.set_system_label("alice", "selfdef.t", "high").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActorLabelPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
