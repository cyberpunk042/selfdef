//! `selfdef-actor-handoff-policy` — delegated scope handoff.
//!
//! Actor A grants actor B the right to act on a scope until a
//! bounded `expires_at_ms`. `revoke` ends it immediately and marks
//! the entry Revoked (kept for audit). `classify` returns the
//! current status: Active / Expired / Revoked / Unknown.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One handoff entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handoff {
    /// Granted at.
    pub granted_at_ms: u64,
    /// Expires at.
    pub expires_at_ms: u64,
    /// Revoked?
    pub revoked: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorHandoffPolicy {
    /// Schema version.
    pub schema_version: String,
    /// from → to → scope → handoff.
    pub by_from: BTreeMap<String, BTreeMap<String, BTreeMap<String, Handoff>>>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HandoffVerdict {
    /// Active.
    Active {
        /// expires at.
        expires_at_ms: u64,
    },
    /// Past expiry.
    Expired,
    /// Operator-revoked.
    Revoked,
    /// No record.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HandoffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor or scope.
    #[error("empty id field")]
    EmptyId,
    /// Bad window.
    #[error("granted_at {0} >= expires_at {1}")]
    BadWindow(u64, u64),
}

impl ActorHandoffPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_from: BTreeMap::new(),
        }
    }

    /// Grant.
    pub fn grant(
        &mut self,
        from: &str,
        to: &str,
        scope: &str,
        granted_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<(), HandoffError> {
        if from.is_empty() || to.is_empty() || scope.is_empty() {
            return Err(HandoffError::EmptyId);
        }
        if granted_at_ms >= expires_at_ms {
            return Err(HandoffError::BadWindow(granted_at_ms, expires_at_ms));
        }
        self.by_from
            .entry(from.into())
            .or_default()
            .entry(to.into())
            .or_default()
            .insert(
                scope.into(),
                Handoff {
                    granted_at_ms,
                    expires_at_ms,
                    revoked: false,
                },
            );
        Ok(())
    }

    /// Revoke.
    pub fn revoke(&mut self, from: &str, to: &str, scope: &str) -> bool {
        if let Some(byto) = self.by_from.get_mut(from) {
            if let Some(scopes) = byto.get_mut(to) {
                if let Some(h) = scopes.get_mut(scope) {
                    h.revoked = true;
                    return true;
                }
            }
        }
        false
    }

    /// Classify.
    pub fn classify(&self, from: &str, to: &str, scope: &str, now_ms: u64) -> HandoffVerdict {
        let h = match self
            .by_from
            .get(from)
            .and_then(|m| m.get(to))
            .and_then(|s| s.get(scope))
        {
            Some(h) => h,
            None => return HandoffVerdict::Unknown,
        };
        if h.revoked {
            return HandoffVerdict::Revoked;
        }
        if now_ms >= h.expires_at_ms {
            return HandoffVerdict::Expired;
        }
        HandoffVerdict::Active {
            expires_at_ms: h.expires_at_ms,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HandoffError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HandoffError::SchemaMismatch);
        }
        for (from, byto) in &self.by_from {
            if from.is_empty() {
                return Err(HandoffError::EmptyId);
            }
            for (to, scopes) in byto {
                if to.is_empty() {
                    return Err(HandoffError::EmptyId);
                }
                for (s, h) in scopes {
                    if s.is_empty() {
                        return Err(HandoffError::EmptyId);
                    }
                    if h.granted_at_ms >= h.expires_at_ms {
                        return Err(HandoffError::BadWindow(h.granted_at_ms, h.expires_at_ms));
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for ActorHandoffPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_not_granted() {
        let p = ActorHandoffPolicy::new();
        assert_eq!(p.classify("a", "b", "deploy", 0), HandoffVerdict::Unknown);
    }

    #[test]
    fn grant_then_active() {
        let mut p = ActorHandoffPolicy::new();
        p.grant("a", "b", "deploy", 0, 1000).unwrap();
        match p.classify("a", "b", "deploy", 500) {
            HandoffVerdict::Active { expires_at_ms } => assert_eq!(expires_at_ms, 1000),
            _ => panic!(),
        }
    }

    #[test]
    fn expired_past_window() {
        let mut p = ActorHandoffPolicy::new();
        p.grant("a", "b", "deploy", 0, 1000).unwrap();
        assert_eq!(
            p.classify("a", "b", "deploy", 2000),
            HandoffVerdict::Expired
        );
    }

    #[test]
    fn revoke_marks_revoked() {
        let mut p = ActorHandoffPolicy::new();
        p.grant("a", "b", "deploy", 0, 1000).unwrap();
        assert!(p.revoke("a", "b", "deploy"));
        assert_eq!(p.classify("a", "b", "deploy", 500), HandoffVerdict::Revoked);
    }

    #[test]
    fn revoke_unknown_false() {
        let mut p = ActorHandoffPolicy::new();
        assert!(!p.revoke("a", "b", "deploy"));
    }

    #[test]
    fn bad_window_rejected() {
        let mut p = ActorHandoffPolicy::new();
        assert!(matches!(
            p.grant("a", "b", "deploy", 1000, 1000).unwrap_err(),
            HandoffError::BadWindow(_, _)
        ));
    }

    #[test]
    fn empty_ids_rejected() {
        let mut p = ActorHandoffPolicy::new();
        assert!(matches!(
            p.grant("", "b", "s", 0, 1).unwrap_err(),
            HandoffError::EmptyId
        ));
        assert!(matches!(
            p.grant("a", "", "s", 0, 1).unwrap_err(),
            HandoffError::EmptyId
        ));
        assert!(matches!(
            p.grant("a", "b", "", 0, 1).unwrap_err(),
            HandoffError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActorHandoffPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            HandoffError::SchemaMismatch
        ));
    }

    #[test]
    fn handoff_serde_roundtrip() {
        let mut p = ActorHandoffPolicy::new();
        p.grant("a", "b", "deploy", 0, 1000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActorHandoffPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
