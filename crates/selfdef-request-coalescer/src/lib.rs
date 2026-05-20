//! `selfdef-request-coalescer` — single-flight per-key elector.
//!
//! Role{Leader, Follower}. enter(key) returns Leader for the
//! first caller (and registers their handle), Follower for
//! subsequent callers with a count. complete(key) clears the
//! key and reports follower count.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Role.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Leader.
    Leader,
    /// Follower.
    Follower,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestCoalescer {
    /// Schema version.
    pub schema_version: String,
    /// key → follower count (Leader is implicit: existence of the entry).
    pub inflight: BTreeMap<String, u32>,
    /// Lifetime leaders.
    pub leaders: u64,
    /// Lifetime followers.
    pub followers: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CoalesceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Unknown key.
    #[error("unknown inflight: {0}")]
    UnknownKey(String),
}

impl RequestCoalescer {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            inflight: BTreeMap::new(),
            leaders: 0,
            followers: 0,
        }
    }

    /// Enter; returns Role.
    pub fn enter(&mut self, key: &str) -> Result<Role, CoalesceError> {
        if key.is_empty() { return Err(CoalesceError::EmptyKey); }
        if let Some(c) = self.inflight.get_mut(key) {
            *c = c.saturating_add(1);
            self.followers = self.followers.saturating_add(1);
            return Ok(Role::Follower);
        }
        self.inflight.insert(key.into(), 0);
        self.leaders = self.leaders.saturating_add(1);
        Ok(Role::Leader)
    }

    /// Complete; returns follower count when leader was registered.
    pub fn complete(&mut self, key: &str) -> Result<u32, CoalesceError> {
        match self.inflight.remove(key) {
            Some(c) => Ok(c),
            None => Err(CoalesceError::UnknownKey(key.into())),
        }
    }

    /// Inflight check.
    pub fn is_inflight(&self, key: &str) -> bool {
        self.inflight.contains_key(key)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CoalesceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CoalesceError::SchemaMismatch); }
        for k in self.inflight.keys() {
            if k.is_empty() { return Err(CoalesceError::EmptyKey); }
        }
        Ok(())
    }
}

impl Default for RequestCoalescer {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_caller_leader() {
        let mut c = RequestCoalescer::new();
        assert_eq!(c.enter("k").unwrap(), Role::Leader);
        assert_eq!(c.leaders, 1);
    }

    #[test]
    fn followers_after_leader() {
        let mut c = RequestCoalescer::new();
        c.enter("k").unwrap();
        assert_eq!(c.enter("k").unwrap(), Role::Follower);
        assert_eq!(c.enter("k").unwrap(), Role::Follower);
        assert_eq!(c.followers, 2);
    }

    #[test]
    fn complete_returns_count() {
        let mut c = RequestCoalescer::new();
        c.enter("k").unwrap();
        c.enter("k").unwrap();
        c.enter("k").unwrap();
        let n = c.complete("k").unwrap();
        assert_eq!(n, 2); // followers
    }

    #[test]
    fn next_enter_is_leader_again() {
        let mut c = RequestCoalescer::new();
        c.enter("k").unwrap();
        c.complete("k").unwrap();
        assert_eq!(c.enter("k").unwrap(), Role::Leader);
    }

    #[test]
    fn complete_unknown_rejected() {
        let mut c = RequestCoalescer::new();
        assert!(matches!(c.complete("nope").unwrap_err(), CoalesceError::UnknownKey(_)));
    }

    #[test]
    fn empty_key_rejected() {
        let mut c = RequestCoalescer::new();
        assert!(matches!(c.enter("").unwrap_err(), CoalesceError::EmptyKey));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = RequestCoalescer::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CoalesceError::SchemaMismatch));
    }

    #[test]
    fn coalescer_serde_roundtrip() {
        let mut c = RequestCoalescer::new();
        c.enter("k").unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: RequestCoalescer = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
