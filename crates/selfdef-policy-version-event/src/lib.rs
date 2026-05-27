//! `selfdef-policy-version-event` — first-touch version banner emitter.
//!
//! `observe(actor, policy_id, version)` returns:
//!   * `FirstSeen` — actor has never observed this policy before.
//!   * `UnchangedVersion` — same version they saw last time.
//!   * `NewVersion { old, new }` — version changed; banner should
//!     fire exactly once for this (actor, policy, version) tuple.
//!
//! Once observed, repeated calls with the same version return
//! `UnchangedVersion`.
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
pub struct PolicyVersionEvent {
    /// Schema version.
    pub schema_version: String,
    /// actor → policy_id → last observed version.
    pub last: BTreeMap<String, BTreeMap<String, String>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum VersionVerdict {
    /// First touch.
    FirstSeen,
    /// Same as last observation.
    UnchangedVersion,
    /// Version bumped.
    NewVersion {
        /// old.
        old: String,
        /// new.
        new: String,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum EventError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyPolicy,
    /// Empty version.
    #[error("version empty")]
    EmptyVersion,
}

impl PolicyVersionEvent {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            last: BTreeMap::new(),
        }
    }

    /// Observe.
    pub fn observe(
        &mut self,
        actor: &str,
        policy_id: &str,
        version: &str,
    ) -> Result<VersionVerdict, EventError> {
        if actor.is_empty() {
            return Err(EventError::EmptyActor);
        }
        if policy_id.is_empty() {
            return Err(EventError::EmptyPolicy);
        }
        if version.is_empty() {
            return Err(EventError::EmptyVersion);
        }
        let by_policy = self.last.entry(actor.into()).or_default();
        let prev = by_policy.get(policy_id).cloned();
        by_policy.insert(policy_id.into(), version.into());
        Ok(match prev {
            None => VersionVerdict::FirstSeen,
            Some(p) if p == version => VersionVerdict::UnchangedVersion,
            Some(p) => VersionVerdict::NewVersion {
                old: p,
                new: version.into(),
            },
        })
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EventError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EventError::SchemaMismatch);
        }
        for (a, m) in &self.last {
            if a.is_empty() {
                return Err(EventError::EmptyActor);
            }
            for (p, v) in m {
                if p.is_empty() {
                    return Err(EventError::EmptyPolicy);
                }
                if v.is_empty() {
                    return Err(EventError::EmptyVersion);
                }
            }
        }
        Ok(())
    }
}

impl Default for PolicyVersionEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_seen_then_unchanged() {
        let mut e = PolicyVersionEvent::new();
        assert_eq!(
            e.observe("a", "p", "1.0.0").unwrap(),
            VersionVerdict::FirstSeen
        );
        assert_eq!(
            e.observe("a", "p", "1.0.0").unwrap(),
            VersionVerdict::UnchangedVersion
        );
    }

    #[test]
    fn new_version_emits_once() {
        let mut e = PolicyVersionEvent::new();
        e.observe("a", "p", "1.0.0").unwrap();
        match e.observe("a", "p", "2.0.0").unwrap() {
            VersionVerdict::NewVersion { old, new } => {
                assert_eq!(old, "1.0.0");
                assert_eq!(new, "2.0.0");
            }
            _ => panic!(),
        }
        // Second observe at the same new version → Unchanged.
        assert_eq!(
            e.observe("a", "p", "2.0.0").unwrap(),
            VersionVerdict::UnchangedVersion
        );
    }

    #[test]
    fn distinct_actors_distinct_state() {
        let mut e = PolicyVersionEvent::new();
        e.observe("a", "p", "1.0.0").unwrap();
        assert_eq!(
            e.observe("b", "p", "1.0.0").unwrap(),
            VersionVerdict::FirstSeen
        );
    }

    #[test]
    fn distinct_policies_distinct_state() {
        let mut e = PolicyVersionEvent::new();
        e.observe("a", "p1", "1.0.0").unwrap();
        assert_eq!(
            e.observe("a", "p2", "1.0.0").unwrap(),
            VersionVerdict::FirstSeen
        );
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut e = PolicyVersionEvent::new();
        assert!(matches!(
            e.observe("", "p", "v").unwrap_err(),
            EventError::EmptyActor
        ));
        assert!(matches!(
            e.observe("a", "", "v").unwrap_err(),
            EventError::EmptyPolicy
        ));
        assert!(matches!(
            e.observe("a", "p", "").unwrap_err(),
            EventError::EmptyVersion
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = PolicyVersionEvent::new();
        e.schema_version = "9.9.9".into();
        assert!(matches!(
            e.validate().unwrap_err(),
            EventError::SchemaMismatch
        ));
    }

    #[test]
    fn event_serde_roundtrip() {
        let mut e = PolicyVersionEvent::new();
        e.observe("a", "p", "1.0.0").unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: PolicyVersionEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
