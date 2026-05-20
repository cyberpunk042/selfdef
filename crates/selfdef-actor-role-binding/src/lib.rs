//! `selfdef-actor-role-binding` — actor ↔ role ↔ permission.
//!
//! Each `Role` carries a permission set. An actor may be bound to
//! many roles; the actor's effective permission set is the union of
//! their roles' permissions.
//!
//! `define_role(role, permissions)` registers a role.
//! `bind(actor, role)` records membership; `unbind(actor, role)`
//! removes. `effective_permissions(actor)` returns the union;
//! `has_permission(actor, perm)` is O(log n × roles).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    /// Role id.
    pub id: String,
    /// Permissions granted.
    pub permissions: BTreeSet<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRoleBinding {
    /// Schema version.
    pub schema_version: String,
    /// role id → role.
    pub roles: BTreeMap<String, Role>,
    /// actor → set of bound role ids.
    pub bindings: BTreeMap<String, BTreeSet<String>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RoleError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty role.
    #[error("role id empty")]
    EmptyRole,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty permission.
    #[error("permission empty")]
    EmptyPermission,
    /// Unknown role.
    #[error("unknown role: {0}")]
    UnknownRole(String),
}

impl ActorRoleBinding {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            roles: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Define (or replace) a role.
    pub fn define_role(&mut self, role_id: &str, permissions: &[&str]) -> Result<(), RoleError> {
        if role_id.is_empty() { return Err(RoleError::EmptyRole); }
        let mut set = BTreeSet::new();
        for p in permissions {
            if p.is_empty() { return Err(RoleError::EmptyPermission); }
            set.insert((*p).into());
        }
        self.roles.insert(role_id.into(), Role { id: role_id.into(), permissions: set });
        Ok(())
    }

    /// Grant a permission on an existing role.
    pub fn grant_to_role(&mut self, role_id: &str, permission: &str) -> Result<bool, RoleError> {
        if permission.is_empty() { return Err(RoleError::EmptyPermission); }
        let role = self.roles.get_mut(role_id).ok_or_else(|| RoleError::UnknownRole(role_id.into()))?;
        Ok(role.permissions.insert(permission.into()))
    }

    /// Revoke a permission from an existing role.
    pub fn revoke_from_role(&mut self, role_id: &str, permission: &str) -> Result<bool, RoleError> {
        let role = self.roles.get_mut(role_id).ok_or_else(|| RoleError::UnknownRole(role_id.into()))?;
        Ok(role.permissions.remove(permission))
    }

    /// Bind actor → role.
    pub fn bind(&mut self, actor: &str, role_id: &str) -> Result<bool, RoleError> {
        if actor.is_empty() { return Err(RoleError::EmptyActor); }
        if !self.roles.contains_key(role_id) {
            return Err(RoleError::UnknownRole(role_id.into()));
        }
        Ok(self.bindings.entry(actor.into()).or_default().insert(role_id.into()))
    }

    /// Unbind actor from role.
    pub fn unbind(&mut self, actor: &str, role_id: &str) -> bool {
        let Some(set) = self.bindings.get_mut(actor) else { return false; };
        let removed = set.remove(role_id);
        if set.is_empty() { self.bindings.remove(actor); }
        removed
    }

    /// Effective permissions (union across actor's bound roles).
    pub fn effective_permissions(&self, actor: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let Some(role_ids) = self.bindings.get(actor) else { return out; };
        for rid in role_ids {
            if let Some(role) = self.roles.get(rid) {
                for p in &role.permissions {
                    out.insert(p.clone());
                }
            }
        }
        out
    }

    /// Has permission?
    pub fn has_permission(&self, actor: &str, permission: &str) -> bool {
        let Some(role_ids) = self.bindings.get(actor) else { return false; };
        for rid in role_ids {
            if let Some(role) = self.roles.get(rid) {
                if role.permissions.contains(permission) {
                    return true;
                }
            }
        }
        false
    }

    /// Roles bound to an actor.
    pub fn roles_of(&self, actor: &str) -> Vec<String> {
        self.bindings.get(actor).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RoleError> {
        if self.schema_version != SCHEMA_VERSION { return Err(RoleError::SchemaMismatch); }
        for (rid, r) in &self.roles {
            if rid.is_empty() { return Err(RoleError::EmptyRole); }
            for p in &r.permissions {
                if p.is_empty() { return Err(RoleError::EmptyPermission); }
            }
        }
        for (a, set) in &self.bindings {
            if a.is_empty() { return Err(RoleError::EmptyActor); }
            for rid in set {
                if !self.roles.contains_key(rid) {
                    return Err(RoleError::UnknownRole(rid.clone()));
                }
            }
        }
        Ok(())
    }
}

impl Default for ActorRoleBinding {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_permissions_union() {
        let mut b = ActorRoleBinding::new();
        b.define_role("reader", &["read"]).unwrap();
        b.define_role("writer", &["read", "write"]).unwrap();
        b.bind("alice", "reader").unwrap();
        b.bind("alice", "writer").unwrap();
        let p = b.effective_permissions("alice");
        assert!(p.contains("read"));
        assert!(p.contains("write"));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn has_permission_lookup() {
        let mut b = ActorRoleBinding::new();
        b.define_role("ops", &["restart"]).unwrap();
        b.bind("alice", "ops").unwrap();
        assert!(b.has_permission("alice", "restart"));
        assert!(!b.has_permission("alice", "delete"));
        assert!(!b.has_permission("bob", "restart"));
    }

    #[test]
    fn unbind_works() {
        let mut b = ActorRoleBinding::new();
        b.define_role("r", &["p"]).unwrap();
        b.bind("a", "r").unwrap();
        assert!(b.unbind("a", "r"));
        assert!(!b.has_permission("a", "p"));
        assert!(!b.unbind("a", "r"));
    }

    #[test]
    fn grant_to_existing_role_adds_for_bound_actors() {
        let mut b = ActorRoleBinding::new();
        b.define_role("r", &["p1"]).unwrap();
        b.bind("a", "r").unwrap();
        b.grant_to_role("r", "p2").unwrap();
        assert!(b.has_permission("a", "p2"));
    }

    #[test]
    fn revoke_from_role_removes_for_bound_actors() {
        let mut b = ActorRoleBinding::new();
        b.define_role("r", &["p1", "p2"]).unwrap();
        b.bind("a", "r").unwrap();
        b.revoke_from_role("r", "p1").unwrap();
        assert!(!b.has_permission("a", "p1"));
        assert!(b.has_permission("a", "p2"));
    }

    #[test]
    fn bind_unknown_role_rejected() {
        let mut b = ActorRoleBinding::new();
        assert!(matches!(b.bind("a", "nope").unwrap_err(), RoleError::UnknownRole(_)));
    }

    #[test]
    fn roles_of_lists() {
        let mut b = ActorRoleBinding::new();
        b.define_role("r1", &["p"]).unwrap();
        b.define_role("r2", &["q"]).unwrap();
        b.bind("a", "r1").unwrap();
        b.bind("a", "r2").unwrap();
        let mut roles = b.roles_of("a");
        roles.sort();
        assert_eq!(roles, vec!["r1", "r2"]);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut b = ActorRoleBinding::new();
        assert!(matches!(b.define_role("", &[]).unwrap_err(), RoleError::EmptyRole));
        assert!(matches!(b.define_role("r", &[""]).unwrap_err(), RoleError::EmptyPermission));
        b.define_role("r", &["p"]).unwrap();
        assert!(matches!(b.bind("", "r").unwrap_err(), RoleError::EmptyActor));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = ActorRoleBinding::new();
        b.schema_version = "9.9.9".into();
        assert!(matches!(b.validate().unwrap_err(), RoleError::SchemaMismatch));
    }

    #[test]
    fn role_serde_roundtrip() {
        let mut b = ActorRoleBinding::new();
        b.define_role("r", &["p1", "p2"]).unwrap();
        b.bind("a", "r").unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: ActorRoleBinding = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
