//! `selfdef-actor-group-membership` — group ↔ actor membership.
//!
//! Forward + reverse index. `add(group, actor)` records;
//! `remove(group, actor)` unrecords; `members_of(group)` returns
//! actors in a group; `groups_of(actor)` returns the actor's
//! groups. `is_member(group, actor)` is O(log n).
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
pub struct ActorGroupMembership {
    /// Schema version.
    pub schema_version: String,
    /// group → members.
    pub by_group: BTreeMap<String, BTreeSet<String>>,
    /// actor → groups (reverse index).
    pub by_actor: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum MembershipError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty group.
    #[error("group empty")]
    EmptyGroup,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
}

impl ActorGroupMembership {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_group: BTreeMap::new(),
            by_actor: BTreeMap::new(),
        }
    }

    /// Add.
    pub fn add(&mut self, group: &str, actor: &str) -> Result<(), MembershipError> {
        if group.is_empty() { return Err(MembershipError::EmptyGroup); }
        if actor.is_empty() { return Err(MembershipError::EmptyActor); }
        self.by_group.entry(group.into()).or_default().insert(actor.into());
        self.by_actor.entry(actor.into()).or_default().insert(group.into());
        Ok(())
    }

    /// Remove.
    pub fn remove(&mut self, group: &str, actor: &str) -> bool {
        let mut changed = false;
        if let Some(set) = self.by_group.get_mut(group) {
            if set.remove(actor) {
                changed = true;
                if set.is_empty() { self.by_group.remove(group); }
            }
        }
        if let Some(set) = self.by_actor.get_mut(actor) {
            if set.remove(group) {
                changed = true;
                if set.is_empty() { self.by_actor.remove(actor); }
            }
        }
        changed
    }

    /// Members of a group.
    pub fn members_of(&self, group: &str) -> Vec<String> {
        self.by_group.get(group).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Groups of an actor.
    pub fn groups_of(&self, actor: &str) -> Vec<String> {
        self.by_actor.get(actor).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Is member?
    pub fn is_member(&self, group: &str, actor: &str) -> bool {
        self.by_group.get(group).is_some_and(|s| s.contains(actor))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), MembershipError> {
        if self.schema_version != SCHEMA_VERSION { return Err(MembershipError::SchemaMismatch); }
        for (g, set) in &self.by_group {
            if g.is_empty() { return Err(MembershipError::EmptyGroup); }
            for a in set {
                if a.is_empty() { return Err(MembershipError::EmptyActor); }
            }
        }
        Ok(())
    }
}

impl Default for ActorGroupMembership {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_indexes_both_ways() {
        let mut m = ActorGroupMembership::new();
        m.add("oncall", "alice").unwrap();
        assert!(m.is_member("oncall", "alice"));
        assert_eq!(m.members_of("oncall"), vec!["alice"]);
        assert_eq!(m.groups_of("alice"), vec!["oncall"]);
    }

    #[test]
    fn remove_clears_both_indices() {
        let mut m = ActorGroupMembership::new();
        m.add("oncall", "alice").unwrap();
        assert!(m.remove("oncall", "alice"));
        assert!(!m.is_member("oncall", "alice"));
        assert!(m.members_of("oncall").is_empty());
        assert!(m.groups_of("alice").is_empty());
    }

    #[test]
    fn remove_unknown_false() {
        let mut m = ActorGroupMembership::new();
        assert!(!m.remove("oncall", "alice"));
    }

    #[test]
    fn actor_in_multiple_groups() {
        let mut m = ActorGroupMembership::new();
        m.add("oncall", "alice").unwrap();
        m.add("security", "alice").unwrap();
        let mut groups = m.groups_of("alice");
        groups.sort();
        assert_eq!(groups, vec!["oncall", "security"]);
    }

    #[test]
    fn group_with_multiple_actors() {
        let mut m = ActorGroupMembership::new();
        m.add("oncall", "alice").unwrap();
        m.add("oncall", "bob").unwrap();
        let mut members = m.members_of("oncall");
        members.sort();
        assert_eq!(members, vec!["alice", "bob"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut m = ActorGroupMembership::new();
        assert!(matches!(m.add("", "a").unwrap_err(), MembershipError::EmptyGroup));
        assert!(matches!(m.add("g", "").unwrap_err(), MembershipError::EmptyActor));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = ActorGroupMembership::new();
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), MembershipError::SchemaMismatch));
    }

    #[test]
    fn membership_serde_roundtrip() {
        let mut m = ActorGroupMembership::new();
        m.add("oncall", "alice").unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: ActorGroupMembership = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
