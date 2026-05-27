//! `selfdef-actor-introduction-policy` — first-touch handshake gate.
//!
//! Before any action, an actor must complete an introduction step.
//! `record_introduction(actor, ts, attested_fingerprint)` marks it
//! complete. `classify(actor)` returns Allowed (introduction
//! recorded) or NeedsIntroduction.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Introduction record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Introduction {
    /// when.
    pub ts_ms: u64,
    /// the substrate fingerprint the actor attested to.
    pub attested_fingerprint: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorIntroductionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// actor → introduction.
    pub introductions: BTreeMap<String, Introduction>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum IntroVerdict {
    /// Already introduced.
    Allowed,
    /// First-touch must run.
    NeedsIntroduction,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IntroError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Empty fingerprint.
    #[error("attested_fingerprint empty")]
    EmptyFingerprint,
}

impl ActorIntroductionPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            introductions: BTreeMap::new(),
        }
    }

    /// Record introduction.
    pub fn record_introduction(
        &mut self,
        actor: &str,
        ts_ms: u64,
        attested_fingerprint: &str,
    ) -> Result<(), IntroError> {
        if actor.is_empty() {
            return Err(IntroError::EmptyActor);
        }
        if attested_fingerprint.is_empty() {
            return Err(IntroError::EmptyFingerprint);
        }
        self.introductions.insert(
            actor.into(),
            Introduction {
                ts_ms,
                attested_fingerprint: attested_fingerprint.into(),
            },
        );
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, actor: &str) -> IntroVerdict {
        if self.introductions.contains_key(actor) {
            IntroVerdict::Allowed
        } else {
            IntroVerdict::NeedsIntroduction
        }
    }

    /// Revoke an actor's introduction (operator-triggered).
    pub fn revoke(&mut self, actor: &str) -> bool {
        self.introductions.remove(actor).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IntroError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IntroError::SchemaMismatch);
        }
        for (a, i) in &self.introductions {
            if a.is_empty() {
                return Err(IntroError::EmptyActor);
            }
            if i.attested_fingerprint.is_empty() {
                return Err(IntroError::EmptyFingerprint);
            }
        }
        Ok(())
    }
}

impl Default for ActorIntroductionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_needs_intro() {
        let p = ActorIntroductionPolicy::new();
        assert_eq!(p.classify("actor"), IntroVerdict::NeedsIntroduction);
    }

    #[test]
    fn after_intro_allowed() {
        let mut p = ActorIntroductionPolicy::new();
        p.record_introduction("actor", 100, "fp1").unwrap();
        assert_eq!(p.classify("actor"), IntroVerdict::Allowed);
    }

    #[test]
    fn revoke_returns_to_needs() {
        let mut p = ActorIntroductionPolicy::new();
        p.record_introduction("actor", 100, "fp1").unwrap();
        assert!(p.revoke("actor"));
        assert_eq!(p.classify("actor"), IntroVerdict::NeedsIntroduction);
    }

    #[test]
    fn revoke_unknown_false() {
        let mut p = ActorIntroductionPolicy::new();
        assert!(!p.revoke("missing"));
    }

    #[test]
    fn empty_actor_or_fingerprint_rejected() {
        let mut p = ActorIntroductionPolicy::new();
        assert!(matches!(
            p.record_introduction("", 0, "fp").unwrap_err(),
            IntroError::EmptyActor
        ));
        assert!(matches!(
            p.record_introduction("a", 0, "").unwrap_err(),
            IntroError::EmptyFingerprint
        ));
    }

    #[test]
    fn re_record_overwrites() {
        let mut p = ActorIntroductionPolicy::new();
        p.record_introduction("actor", 100, "fp1").unwrap();
        p.record_introduction("actor", 200, "fp2").unwrap();
        assert_eq!(p.introductions["actor"].attested_fingerprint, "fp2");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = ActorIntroductionPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            IntroError::SchemaMismatch
        ));
    }

    #[test]
    fn intro_serde_roundtrip() {
        let mut p = ActorIntroductionPolicy::new();
        p.record_introduction("actor", 100, "fp1").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: ActorIntroductionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
