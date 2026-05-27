//! `selfdef-key-rotation-set` — signing-key set with grace overlap.
//!
//! Key{kid, phase Verifying/Signing/Retired, valid_from_ms,
//! valid_until_ms}. One Signing key at any time (active issuer);
//! multiple Verifying keys allowed during rotation grace; Retired
//! keys are kept for late-audit verification but rejected for new
//! verify. promote(kid, now) advances Verifying → Signing (and
//! demotes the prior Signing to Verifying). retire(kid) → Retired.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Accepted for verify but not yet active issuer.
    Verifying,
    /// Active issuer for new signatures.
    Signing,
    /// Late-audit only; not accepted for new verify.
    Retired,
}

/// Key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Key {
    /// Key id.
    pub kid: String,
    /// Phase.
    pub phase: Phase,
    /// Active from (informational).
    pub valid_from_ms: u64,
    /// Active until (informational, 0 = open).
    pub valid_until_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotationSet {
    /// Schema version.
    pub schema_version: String,
    /// Keys by kid.
    pub keys: BTreeMap<String, Key>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("kid empty")]
    EmptyKid,
    /// Unknown.
    #[error("unknown kid: {0}")]
    Unknown(String),
    /// Duplicate.
    #[error("duplicate kid: {0}")]
    Duplicate(String),
    /// Invalid transition.
    #[error("invalid transition")]
    BadTransition,
}

impl KeyRotationSet {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            keys: BTreeMap::new(),
        }
    }

    /// Add a key in Verifying phase.
    pub fn add(&mut self, kid: &str, now_ms: u64) -> Result<(), KeyError> {
        if kid.is_empty() {
            return Err(KeyError::EmptyKid);
        }
        if self.keys.contains_key(kid) {
            return Err(KeyError::Duplicate(kid.into()));
        }
        self.keys.insert(
            kid.into(),
            Key {
                kid: kid.into(),
                phase: Phase::Verifying,
                valid_from_ms: now_ms,
                valid_until_ms: 0,
            },
        );
        Ok(())
    }

    /// Promote Verifying → Signing; demote prior Signing → Verifying.
    pub fn promote(&mut self, kid: &str, now_ms: u64) -> Result<(), KeyError> {
        let target_exists = self.keys.contains_key(kid);
        if !target_exists {
            return Err(KeyError::Unknown(kid.into()));
        }
        // Cannot promote a Retired key.
        if self.keys.get(kid).unwrap().phase == Phase::Retired {
            return Err(KeyError::BadTransition);
        }
        for (k, key) in self.keys.iter_mut() {
            if k != kid && key.phase == Phase::Signing {
                key.phase = Phase::Verifying;
            }
        }
        let target = self.keys.get_mut(kid).unwrap();
        target.phase = Phase::Signing;
        target.valid_from_ms = now_ms;
        Ok(())
    }

    /// Retire a key.
    pub fn retire(&mut self, kid: &str, now_ms: u64) -> Result<(), KeyError> {
        let k = self
            .keys
            .get_mut(kid)
            .ok_or_else(|| KeyError::Unknown(kid.into()))?;
        if k.phase == Phase::Retired {
            return Err(KeyError::BadTransition);
        }
        k.phase = Phase::Retired;
        k.valid_until_ms = now_ms;
        Ok(())
    }

    /// Current Signing key, if any.
    pub fn signing(&self) -> Option<&Key> {
        self.keys.values().find(|k| k.phase == Phase::Signing)
    }

    /// True iff kid is accepted for verify (Verifying or Signing).
    pub fn accepts_verify(&self, kid: &str) -> bool {
        match self.keys.get(kid) {
            Some(k) => matches!(k.phase, Phase::Verifying | Phase::Signing),
            None => false,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), KeyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(KeyError::SchemaMismatch);
        }
        let signing = self
            .keys
            .values()
            .filter(|k| k.phase == Phase::Signing)
            .count();
        if signing > 1 {
            return Err(KeyError::BadTransition);
        }
        for (k, _) in &self.keys {
            if k.is_empty() {
                return Err(KeyError::EmptyKid);
            }
        }
        Ok(())
    }
}

impl Default for KeyRotationSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_starts_verifying() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        assert_eq!(s.keys.get("k1").unwrap().phase, Phase::Verifying);
        assert!(s.accepts_verify("k1"));
    }

    #[test]
    fn promote_makes_signing_and_demotes_old() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        s.promote("k1", 100).unwrap();
        assert_eq!(s.signing().unwrap().kid, "k1");
        s.add("k2", 200).unwrap();
        s.promote("k2", 300).unwrap();
        assert_eq!(s.signing().unwrap().kid, "k2");
        assert_eq!(s.keys.get("k1").unwrap().phase, Phase::Verifying);
    }

    #[test]
    fn retire_blocks_verify() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        s.retire("k1", 100).unwrap();
        assert!(!s.accepts_verify("k1"));
    }

    #[test]
    fn cannot_promote_retired() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        s.retire("k1", 100).unwrap();
        assert!(matches!(
            s.promote("k1", 200).unwrap_err(),
            KeyError::BadTransition
        ));
    }

    #[test]
    fn duplicate_add_rejected() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        assert!(matches!(
            s.add("k1", 0).unwrap_err(),
            KeyError::Duplicate(_)
        ));
    }

    #[test]
    fn unknown_rejected() {
        let mut s = KeyRotationSet::new();
        assert!(matches!(
            s.promote("nope", 0).unwrap_err(),
            KeyError::Unknown(_)
        ));
        assert!(matches!(
            s.retire("nope", 0).unwrap_err(),
            KeyError::Unknown(_)
        ));
    }

    #[test]
    fn empty_kid_rejected() {
        let mut s = KeyRotationSet::new();
        assert!(matches!(s.add("", 0).unwrap_err(), KeyError::EmptyKid));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = KeyRotationSet::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            KeyError::SchemaMismatch
        ));
    }

    #[test]
    fn rotation_serde_roundtrip() {
        let mut s = KeyRotationSet::new();
        s.add("k1", 0).unwrap();
        s.promote("k1", 100).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: KeyRotationSet = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
