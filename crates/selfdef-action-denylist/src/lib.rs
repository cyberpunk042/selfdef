//! `selfdef-action-denylist` — explicit deny-list.
//!
//! Each entry is `Deny { action, scope, reason }` where Scope can
//! be `Global` (applies to all actors) or `Actor(id)` (applies only
//! to one actor).
//!
//! `decide(action, actor)` returns `Allow` if no matching deny
//! exists, otherwise `Deny { reason }` with the first matching
//! reason (Global first, then Actor-specific).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Scope {
    /// Global.
    Global,
    /// Per-actor.
    Actor {
        /// id.
        actor_id: String,
    },
}

/// Deny entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyEntry {
    /// Action name.
    pub action: String,
    /// Scope.
    pub scope: Scope,
    /// Reason.
    pub reason: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionDenylist {
    /// Schema version.
    pub schema_version: String,
    /// Global denies: action → reason.
    pub global: BTreeMap<String, String>,
    /// Per-actor: (actor, action) → reason — stored as
    /// `BTreeMap<actor, BTreeMap<action, reason>>` for indexing.
    pub per_actor: BTreeMap<String, BTreeMap<String, String>>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DenyVerdict {
    /// Allow.
    Allow,
    /// Deny.
    Deny {
        /// reason.
        reason: String,
        /// scope kind.
        scope: ScopeKind,
    },
}

/// Scope kind (subset of Scope; sub-type for verdict).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeKind {
    /// Global.
    Global,
    /// Actor.
    Actor,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DenyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("action empty")]
    EmptyAction,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Empty.
    #[error("reason empty")]
    EmptyReason,
}

impl ActionDenylist {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            global: BTreeMap::new(),
            per_actor: BTreeMap::new(),
        }
    }

    /// Deny globally.
    pub fn deny_global(&mut self, action: &str, reason: &str) -> Result<bool, DenyError> {
        if action.is_empty() {
            return Err(DenyError::EmptyAction);
        }
        if reason.is_empty() {
            return Err(DenyError::EmptyReason);
        }
        let prev = self.global.insert(action.into(), reason.into());
        Ok(prev.is_none())
    }

    /// Deny per actor.
    pub fn deny_for_actor(
        &mut self,
        actor: &str,
        action: &str,
        reason: &str,
    ) -> Result<bool, DenyError> {
        if actor.is_empty() {
            return Err(DenyError::EmptyActor);
        }
        if action.is_empty() {
            return Err(DenyError::EmptyAction);
        }
        if reason.is_empty() {
            return Err(DenyError::EmptyReason);
        }
        let prev = self
            .per_actor
            .entry(actor.into())
            .or_default()
            .insert(action.into(), reason.into());
        Ok(prev.is_none())
    }

    /// Remove global deny.
    pub fn allow_global(&mut self, action: &str) -> bool {
        self.global.remove(action).is_some()
    }

    /// Remove per-actor deny.
    pub fn allow_for_actor(&mut self, actor: &str, action: &str) -> bool {
        let Some(m) = self.per_actor.get_mut(actor) else {
            return false;
        };
        let removed = m.remove(action).is_some();
        if m.is_empty() {
            self.per_actor.remove(actor);
        }
        removed
    }

    /// Decide.
    pub fn decide(&self, action: &str, actor: &str) -> Result<DenyVerdict, DenyError> {
        if action.is_empty() {
            return Err(DenyError::EmptyAction);
        }
        if actor.is_empty() {
            return Err(DenyError::EmptyActor);
        }
        if let Some(reason) = self.global.get(action) {
            return Ok(DenyVerdict::Deny {
                reason: reason.clone(),
                scope: ScopeKind::Global,
            });
        }
        if let Some(m) = self.per_actor.get(actor) {
            if let Some(reason) = m.get(action) {
                return Ok(DenyVerdict::Deny {
                    reason: reason.clone(),
                    scope: ScopeKind::Actor,
                });
            }
        }
        Ok(DenyVerdict::Allow)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DenyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DenyError::SchemaMismatch);
        }
        for (a, r) in &self.global {
            if a.is_empty() {
                return Err(DenyError::EmptyAction);
            }
            if r.is_empty() {
                return Err(DenyError::EmptyReason);
            }
        }
        for (actor, m) in &self.per_actor {
            if actor.is_empty() {
                return Err(DenyError::EmptyActor);
            }
            for (a, r) in m {
                if a.is_empty() {
                    return Err(DenyError::EmptyAction);
                }
                if r.is_empty() {
                    return Err(DenyError::EmptyReason);
                }
            }
        }
        Ok(())
    }
}

impl Default for ActionDenylist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_deny_applies_to_all_actors() {
        let mut d = ActionDenylist::new();
        d.deny_global("delete-all", "destructive").unwrap();
        let v = d.decide("delete-all", "alice").unwrap();
        assert_eq!(
            v,
            DenyVerdict::Deny {
                reason: "destructive".into(),
                scope: ScopeKind::Global
            }
        );
        let v = d.decide("delete-all", "bob").unwrap();
        assert!(matches!(v, DenyVerdict::Deny { .. }));
    }

    #[test]
    fn per_actor_deny_isolated() {
        let mut d = ActionDenylist::new();
        d.deny_for_actor("alice", "send-email", "no email this week")
            .unwrap();
        assert!(matches!(
            d.decide("send-email", "alice").unwrap(),
            DenyVerdict::Deny {
                scope: ScopeKind::Actor,
                ..
            }
        ));
        assert_eq!(d.decide("send-email", "bob").unwrap(), DenyVerdict::Allow);
    }

    #[test]
    fn global_beats_actor() {
        let mut d = ActionDenylist::new();
        d.deny_global("delete-all", "global").unwrap();
        d.deny_for_actor("alice", "delete-all", "actor-only")
            .unwrap();
        match d.decide("delete-all", "alice").unwrap() {
            DenyVerdict::Deny { reason, scope } => {
                assert_eq!(reason, "global");
                assert_eq!(scope, ScopeKind::Global);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn allow_global_clears() {
        let mut d = ActionDenylist::new();
        d.deny_global("x", "r").unwrap();
        assert!(d.allow_global("x"));
        assert_eq!(d.decide("x", "alice").unwrap(), DenyVerdict::Allow);
    }

    #[test]
    fn allow_for_actor_clears() {
        let mut d = ActionDenylist::new();
        d.deny_for_actor("alice", "x", "r").unwrap();
        assert!(d.allow_for_actor("alice", "x"));
        assert!(!d.per_actor.contains_key("alice"));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut d = ActionDenylist::new();
        assert!(matches!(
            d.deny_global("", "r").unwrap_err(),
            DenyError::EmptyAction
        ));
        assert!(matches!(
            d.deny_global("a", "").unwrap_err(),
            DenyError::EmptyReason
        ));
        assert!(matches!(
            d.deny_for_actor("", "a", "r").unwrap_err(),
            DenyError::EmptyActor
        ));
        assert!(matches!(
            d.decide("", "alice").unwrap_err(),
            DenyError::EmptyAction
        ));
        assert!(matches!(
            d.decide("a", "").unwrap_err(),
            DenyError::EmptyActor
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = ActionDenylist::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(
            d.validate().unwrap_err(),
            DenyError::SchemaMismatch
        ));
    }

    #[test]
    fn deny_serde_roundtrip() {
        let mut d = ActionDenylist::new();
        d.deny_global("x", "r").unwrap();
        d.deny_for_actor("alice", "y", "r2").unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: ActionDenylist = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
