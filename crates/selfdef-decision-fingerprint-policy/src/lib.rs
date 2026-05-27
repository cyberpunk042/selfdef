//! `selfdef-decision-fingerprint-policy` — canonical-fingerprint.
//!
//! Computes a stable u64 fingerprint of a decision's input tuple.
//! Two callers with identical inputs always produce the same hex.
//! Drives decision-cache keys + replay correlation.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision input tuple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionInput {
    /// Subject id (operator, agent, anonymous, etc.).
    pub subject: String,
    /// Action id (canonical).
    pub action: String,
    /// Active profile id.
    pub profile: String,
    /// Active execution mode (string).
    pub mode: String,
    /// Tool version fingerprint hex (or empty when N/A).
    pub tool_version_digest: String,
    /// Prompt template id (or empty when N/A).
    pub prompt_template_id: String,
}

/// Output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionFingerprint {
    /// Schema version.
    pub schema_version: String,
    /// FNV-1a u64 of canonical bytes.
    pub fingerprint_hex: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FpError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Empty action.
    #[error("action empty")]
    EmptyAction,
    /// Empty profile.
    #[error("profile empty")]
    EmptyProfile,
    /// Empty mode.
    #[error("mode empty")]
    EmptyMode,
}

/// Stateless computer.
#[derive(Debug, Clone, Default)]
pub struct DecisionFingerprintPolicy;

impl DecisionFingerprintPolicy {
    /// Compute.
    pub fn compute(input: &DecisionInput) -> Result<DecisionFingerprint, FpError> {
        if input.subject.is_empty() {
            return Err(FpError::EmptySubject);
        }
        if input.action.is_empty() {
            return Err(FpError::EmptyAction);
        }
        if input.profile.is_empty() {
            return Err(FpError::EmptyProfile);
        }
        if input.mode.is_empty() {
            return Err(FpError::EmptyMode);
        }
        let mut h: u64 = 0xcbf29ce484222325;
        fn upd(mut h: u64, bytes: &[u8]) -> u64 {
            for &b in bytes {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
        h = upd(h, input.subject.as_bytes());
        h = upd(h, b"\x1f");
        h = upd(h, input.action.as_bytes());
        h = upd(h, b"\x1f");
        h = upd(h, input.profile.as_bytes());
        h = upd(h, b"\x1f");
        h = upd(h, input.mode.as_bytes());
        h = upd(h, b"\x1f");
        h = upd(h, input.tool_version_digest.as_bytes());
        h = upd(h, b"\x1f");
        h = upd(h, input.prompt_template_id.as_bytes());
        Ok(DecisionFingerprint {
            schema_version: SCHEMA_VERSION.into(),
            fingerprint_hex: format!("{h:016x}"),
        })
    }
}

impl DecisionFingerprint {
    /// Validate.
    pub fn validate(&self) -> Result<(), FpError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FpError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(subj: &str, act: &str) -> DecisionInput {
        DecisionInput {
            subject: subj.into(),
            action: act.into(),
            profile: "production".into(),
            mode: "execute".into(),
            tool_version_digest: String::new(),
            prompt_template_id: String::new(),
        }
    }

    #[test]
    fn same_input_same_fingerprint() {
        let a = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        let b = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        assert_eq!(a.fingerprint_hex, b.fingerprint_hex);
    }

    #[test]
    fn different_subject_different_fingerprint() {
        let a = DecisionFingerprintPolicy::compute(&input("op-1", "deploy")).unwrap();
        let b = DecisionFingerprintPolicy::compute(&input("op-2", "deploy")).unwrap();
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex);
    }

    #[test]
    fn different_action_different_fingerprint() {
        let a = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        let b = DecisionFingerprintPolicy::compute(&input("op", "rollback")).unwrap();
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex);
    }

    #[test]
    fn tool_digest_affects_fingerprint() {
        let mut a_input = input("op", "deploy");
        a_input.tool_version_digest = "abc".into();
        let mut b_input = input("op", "deploy");
        b_input.tool_version_digest = "def".into();
        let a = DecisionFingerprintPolicy::compute(&a_input).unwrap();
        let b = DecisionFingerprintPolicy::compute(&b_input).unwrap();
        assert_ne!(a.fingerprint_hex, b.fingerprint_hex);
    }

    #[test]
    fn empty_subject_rejected() {
        assert!(matches!(
            DecisionFingerprintPolicy::compute(&input("", "x")).unwrap_err(),
            FpError::EmptySubject
        ));
    }

    #[test]
    fn empty_action_rejected() {
        assert!(matches!(
            DecisionFingerprintPolicy::compute(&input("subj", "")).unwrap_err(),
            FpError::EmptyAction
        ));
    }

    #[test]
    fn empty_profile_rejected() {
        let mut x = input("a", "b");
        x.profile = String::new();
        assert!(matches!(
            DecisionFingerprintPolicy::compute(&x).unwrap_err(),
            FpError::EmptyProfile
        ));
    }

    #[test]
    fn empty_mode_rejected() {
        let mut x = input("a", "b");
        x.mode = String::new();
        assert!(matches!(
            DecisionFingerprintPolicy::compute(&x).unwrap_err(),
            FpError::EmptyMode
        ));
    }

    #[test]
    fn hex_is_16_chars() {
        let a = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        assert_eq!(a.fingerprint_hex.len(), 16);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), FpError::SchemaMismatch));
    }

    #[test]
    fn fingerprint_serde_roundtrip() {
        let a = DecisionFingerprintPolicy::compute(&input("op", "deploy")).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: DecisionFingerprint = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
