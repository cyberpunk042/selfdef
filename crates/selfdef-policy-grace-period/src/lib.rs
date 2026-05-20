//! `selfdef-policy-grace-period` — post-install grace gate.
//!
//! `install(policy_id, installed_at, grace_ms)` records the install
//! time + grace window. `classify(policy_id, now)` returns:
//!   * `InGrace { installed_at, grace_ms, remaining_ms }` — still in
//!     window.
//!   * `InEffect` — past grace.
//!   * `Unknown` — no record.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One install entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Install {
    /// Installed at (ms).
    pub installed_at_ms: u64,
    /// Grace window (ms).
    pub grace_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyGracePeriod {
    /// Schema version.
    pub schema_version: String,
    /// policy_id → install.
    pub installs: BTreeMap<String, Install>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GraceVerdict {
    /// In grace.
    InGrace {
        /// installed at.
        installed_at_ms: u64,
        /// grace window.
        grace_ms: u64,
        /// remaining ms.
        remaining_ms: u64,
    },
    /// Past grace.
    InEffect,
    /// Not recorded.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GraceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyId,
}

impl PolicyGracePeriod {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            installs: BTreeMap::new(),
        }
    }

    /// Install.
    pub fn install(&mut self, policy_id: &str, installed_at_ms: u64, grace_ms: u64) -> Result<(), GraceError> {
        if policy_id.is_empty() { return Err(GraceError::EmptyId); }
        self.installs.insert(policy_id.into(), Install { installed_at_ms, grace_ms });
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, policy_id: &str, now_ms: u64) -> GraceVerdict {
        let inst = match self.installs.get(policy_id) {
            Some(i) => *i,
            None => return GraceVerdict::Unknown,
        };
        let elapsed = now_ms.saturating_sub(inst.installed_at_ms);
        if elapsed >= inst.grace_ms {
            GraceVerdict::InEffect
        } else {
            GraceVerdict::InGrace {
                installed_at_ms: inst.installed_at_ms,
                grace_ms: inst.grace_ms,
                remaining_ms: inst.grace_ms - elapsed,
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GraceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(GraceError::SchemaMismatch); }
        for k in self.installs.keys() {
            if k.is_empty() { return Err(GraceError::EmptyId); }
        }
        Ok(())
    }
}

impl Default for PolicyGracePeriod {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_when_not_installed() {
        let p = PolicyGracePeriod::new();
        assert_eq!(p.classify("x", 0), GraceVerdict::Unknown);
    }

    #[test]
    fn in_grace_then_in_effect() {
        let mut p = PolicyGracePeriod::new();
        p.install("x", 0, 1000).unwrap();
        match p.classify("x", 200) {
            GraceVerdict::InGrace { remaining_ms, .. } => assert_eq!(remaining_ms, 800),
            _ => panic!(),
        }
        assert_eq!(p.classify("x", 1000), GraceVerdict::InEffect);
        assert_eq!(p.classify("x", 10_000), GraceVerdict::InEffect);
    }

    #[test]
    fn zero_grace_immediately_in_effect() {
        let mut p = PolicyGracePeriod::new();
        p.install("x", 0, 0).unwrap();
        assert_eq!(p.classify("x", 0), GraceVerdict::InEffect);
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PolicyGracePeriod::new();
        assert!(matches!(p.install("", 0, 0).unwrap_err(), GraceError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PolicyGracePeriod::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), GraceError::SchemaMismatch));
    }

    #[test]
    fn grace_serde_roundtrip() {
        let mut p = PolicyGracePeriod::new();
        p.install("x", 0, 1000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PolicyGracePeriod = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
