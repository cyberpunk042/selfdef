//! `selfdef-actor-rotation` — operator key-rotation history.
//!
//! Rotations form a chain: old → new. Each rotation must carry double
//! signature (old + new) to prove the operator still holds the new
//! key. `is_current` + `is_retired` answer "which epoch is this fp from?"
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One rotation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rotation {
    /// Previously-current MS003 fingerprint.
    pub old_fp: String,
    /// New MS003 fingerprint.
    pub new_fp: String,
    /// ISO-8601 UTC.
    pub at: String,
    /// Signature by old key over the rotation envelope.
    pub old_sig: String,
    /// Signature by new key over the rotation envelope.
    pub new_sig: String,
}

/// Rotation log envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRotationLog {
    /// Schema version.
    pub schema_version: String,
    /// Genesis (first ever) MS003 fingerprint.
    pub genesis_fp: String,
    /// Rotations in chronological order.
    pub rotations: Vec<Rotation>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty genesis.
    #[error("genesis_fp empty")]
    EmptyGenesis,
    /// Self-rotation.
    #[error("rotation {idx} self-rotates {fp}")]
    SelfRotation {
        /// idx.
        idx: usize,
        /// fp.
        fp: String,
    },
    /// Old fp doesn't match previous epoch's new fp.
    #[error("rotation {idx} old_fp {got} doesn't match prior epoch's {expected}")]
    ChainBroken {
        /// idx.
        idx: usize,
        /// got.
        got: String,
        /// expected.
        expected: String,
    },
    /// Missing sig.
    #[error("rotation {idx} missing {field}")]
    MissingSig {
        /// idx.
        idx: usize,
        /// field.
        field: &'static str,
    },
    /// Empty timestamp.
    #[error("rotation {idx} missing at")]
    MissingTimestamp {
        /// idx.
        idx: usize,
    },
}

impl ActorRotationLog {
    /// New with a genesis fingerprint.
    pub fn new(genesis_fp: &str) -> Result<Self, RotationError> {
        if genesis_fp.is_empty() { return Err(RotationError::EmptyGenesis); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            genesis_fp: genesis_fp.into(),
            rotations: Vec::new(),
        })
    }

    /// Record a rotation. old_fp must equal `current_fp()` of the log
    /// before the call; new_fp must differ; both sigs required.
    pub fn record(&mut self, rotation: Rotation) -> Result<(), RotationError> {
        let idx = self.rotations.len();
        if rotation.old_fp == rotation.new_fp {
            return Err(RotationError::SelfRotation { idx, fp: rotation.old_fp });
        }
        if rotation.at.is_empty() {
            return Err(RotationError::MissingTimestamp { idx });
        }
        if rotation.old_sig.is_empty() {
            return Err(RotationError::MissingSig { idx, field: "old_sig" });
        }
        if rotation.new_sig.is_empty() {
            return Err(RotationError::MissingSig { idx, field: "new_sig" });
        }
        let expected_old = self.current_fp().to_string();
        if rotation.old_fp != expected_old {
            return Err(RotationError::ChainBroken {
                idx, got: rotation.old_fp, expected: expected_old,
            });
        }
        self.rotations.push(rotation);
        Ok(())
    }

    /// Current MS003 fingerprint (after all rotations applied).
    pub fn current_fp(&self) -> &str {
        match self.rotations.last() {
            Some(r) => &r.new_fp,
            None => &self.genesis_fp,
        }
    }

    /// True if fp is the current one.
    pub fn is_current(&self, fp: &str) -> bool { self.current_fp() == fp }

    /// True if fp appeared in rotation history but is not current.
    pub fn is_retired(&self, fp: &str) -> bool {
        if self.is_current(fp) { return false; }
        if fp == self.genesis_fp { return !self.rotations.is_empty(); }
        self.rotations.iter().any(|r| r.old_fp == fp)
    }

    /// Full chain of fingerprints from genesis to current.
    pub fn chain(&self) -> Vec<String> {
        let mut v = vec![self.genesis_fp.clone()];
        for r in &self.rotations { v.push(r.new_fp.clone()); }
        v
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RotationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RotationError::SchemaMismatch);
        }
        if self.genesis_fp.is_empty() { return Err(RotationError::EmptyGenesis); }
        let mut expected_old = self.genesis_fp.clone();
        for (idx, r) in self.rotations.iter().enumerate() {
            if r.old_fp == r.new_fp {
                return Err(RotationError::SelfRotation { idx, fp: r.old_fp.clone() });
            }
            if r.at.is_empty() { return Err(RotationError::MissingTimestamp { idx }); }
            if r.old_sig.is_empty() { return Err(RotationError::MissingSig { idx, field: "old_sig" }); }
            if r.new_sig.is_empty() { return Err(RotationError::MissingSig { idx, field: "new_sig" }); }
            if r.old_fp != expected_old {
                return Err(RotationError::ChainBroken {
                    idx, got: r.old_fp.clone(), expected: expected_old,
                });
            }
            expected_old = r.new_fp.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(old: &str, new: &str) -> Rotation {
        Rotation {
            old_fp: old.into(), new_fp: new.into(),
            at: "2026-05-19T03:00:00Z".into(),
            old_sig: "old-sig".into(), new_sig: "new-sig".into(),
        }
    }

    #[test]
    fn new_empty_genesis_rejected() {
        assert!(matches!(ActorRotationLog::new("").unwrap_err(), RotationError::EmptyGenesis));
    }

    #[test]
    fn current_is_genesis_at_start() {
        let log = ActorRotationLog::new("op-fp-v1").unwrap();
        assert_eq!(log.current_fp(), "op-fp-v1");
    }

    #[test]
    fn rotation_updates_current() {
        let mut log = ActorRotationLog::new("op-fp-v1").unwrap();
        log.record(r("op-fp-v1", "op-fp-v2")).unwrap();
        assert_eq!(log.current_fp(), "op-fp-v2");
    }

    #[test]
    fn is_current_and_retired() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        log.record(r("v1", "v2")).unwrap();
        log.record(r("v2", "v3")).unwrap();
        assert!(log.is_current("v3"));
        assert!(log.is_retired("v1"));
        assert!(log.is_retired("v2"));
        assert!(!log.is_current("v1"));
        assert!(!log.is_retired("v3"));
    }

    #[test]
    fn self_rotation_rejected() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        assert!(matches!(log.record(r("v1", "v1")).unwrap_err(), RotationError::SelfRotation { .. }));
    }

    #[test]
    fn chain_broken_rejected() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        assert!(matches!(log.record(r("other", "v2")).unwrap_err(), RotationError::ChainBroken { .. }));
    }

    #[test]
    fn missing_sig_rejected() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        let mut rot = r("v1", "v2");
        rot.new_sig = String::new();
        assert!(matches!(log.record(rot).unwrap_err(), RotationError::MissingSig { .. }));
    }

    #[test]
    fn chain_returns_full_history() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        log.record(r("v1", "v2")).unwrap();
        log.record(r("v2", "v3")).unwrap();
        let c = log.chain();
        assert_eq!(c, vec!["v1".to_string(), "v2".into(), "v3".into()]);
    }

    #[test]
    fn validate_ok_chain() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        log.record(r("v1", "v2")).unwrap();
        log.record(r("v2", "v3")).unwrap();
        log.validate().unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        log.schema_version = "9.9.9".into();
        assert!(matches!(log.validate().unwrap_err(), RotationError::SchemaMismatch));
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut log = ActorRotationLog::new("v1").unwrap();
        log.record(r("v1", "v2")).unwrap();
        let j = serde_json::to_string(&log).unwrap();
        let back: ActorRotationLog = serde_json::from_str(&j).unwrap();
        assert_eq!(log, back);
    }
}
