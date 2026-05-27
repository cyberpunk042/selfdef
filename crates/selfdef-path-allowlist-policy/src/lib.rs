//! `selfdef-path-allowlist-policy` — filesystem path access control.
//!
//! Each substrate has a list of allowed path prefixes, each annotated
//! with a Mode (Read, ReadWrite, WriteOnly). `decide(substrate,
//! path, mode_requested)` returns:
//!   * `Allowed` — a prefix matches AND grants the requested mode.
//!   * `DeniedMode { prefix, granted }` — prefix matches but mode
//!     insufficient.
//!   * `DeniedNoMatch` — no prefix matches.
//!   * `Unknown` — substrate not registered.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Access mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Read-only.
    Read,
    /// Write-only.
    WriteOnly,
    /// Read+Write.
    ReadWrite,
}

impl Mode {
    /// Does this grant satisfy the requested mode?
    pub fn satisfies(self, requested: Mode) -> bool {
        matches!(
            (self, requested),
            (Mode::ReadWrite, _) | (Mode::Read, Mode::Read) | (Mode::WriteOnly, Mode::WriteOnly)
        )
    }
}

/// One prefix grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixGrant {
    /// Path prefix.
    pub prefix: String,
    /// Granted mode.
    pub mode: Mode,
}

/// Per-substrate allowlist.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstratePaths {
    /// Ordered grants — first matching prefix wins.
    pub grants: Vec<PrefixGrant>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathAllowlistPolicy {
    /// Schema version.
    pub schema_version: String,
    /// substrate_id → paths.
    pub substrates: BTreeMap<String, SubstratePaths>,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PathVerdict {
    /// Allowed.
    Allowed,
    /// Prefix matched but mode insufficient.
    DeniedMode {
        /// matched prefix.
        prefix: String,
        /// the prefix's actual mode.
        granted: Mode,
    },
    /// No prefix matched.
    DeniedNoMatch,
    /// Unknown substrate.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PathPolicyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty substrate.
    #[error("substrate id empty")]
    EmptySubstrate,
    /// Empty prefix.
    #[error("prefix empty")]
    EmptyPrefix,
    /// Unknown substrate.
    #[error("unknown substrate: {0}")]
    UnknownSubstrate(String),
}

impl PathAllowlistPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            substrates: BTreeMap::new(),
        }
    }

    /// Register substrate.
    pub fn register(&mut self, substrate_id: &str) -> Result<(), PathPolicyError> {
        if substrate_id.is_empty() {
            return Err(PathPolicyError::EmptySubstrate);
        }
        self.substrates.entry(substrate_id.into()).or_default();
        Ok(())
    }

    /// Add a grant. Later grants are checked after earlier ones; if
    /// the same prefix is added twice, the new mode replaces.
    pub fn grant(
        &mut self,
        substrate_id: &str,
        prefix: &str,
        mode: Mode,
    ) -> Result<(), PathPolicyError> {
        if prefix.is_empty() {
            return Err(PathPolicyError::EmptyPrefix);
        }
        let s = self
            .substrates
            .get_mut(substrate_id)
            .ok_or_else(|| PathPolicyError::UnknownSubstrate(substrate_id.into()))?;
        if let Some(g) = s.grants.iter_mut().find(|g| g.prefix == prefix) {
            g.mode = mode;
        } else {
            s.grants.push(PrefixGrant {
                prefix: prefix.into(),
                mode,
            });
        }
        Ok(())
    }

    /// Revoke a prefix.
    pub fn revoke(&mut self, substrate_id: &str, prefix: &str) -> Result<bool, PathPolicyError> {
        let s = self
            .substrates
            .get_mut(substrate_id)
            .ok_or_else(|| PathPolicyError::UnknownSubstrate(substrate_id.into()))?;
        let before = s.grants.len();
        s.grants.retain(|g| g.prefix != prefix);
        Ok(s.grants.len() != before)
    }

    /// Decide.
    pub fn decide(&self, substrate_id: &str, path: &str, requested: Mode) -> PathVerdict {
        let Some(s) = self.substrates.get(substrate_id) else {
            return PathVerdict::Unknown;
        };
        for g in &s.grants {
            if path.starts_with(&g.prefix) {
                if g.mode.satisfies(requested) {
                    return PathVerdict::Allowed;
                }
                return PathVerdict::DeniedMode {
                    prefix: g.prefix.clone(),
                    granted: g.mode,
                };
            }
        }
        PathVerdict::DeniedNoMatch
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PathPolicyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PathPolicyError::SchemaMismatch);
        }
        for (id, s) in &self.substrates {
            if id.is_empty() {
                return Err(PathPolicyError::EmptySubstrate);
            }
            for g in &s.grants {
                if g.prefix.is_empty() {
                    return Err(PathPolicyError::EmptyPrefix);
                }
            }
        }
        Ok(())
    }
}

impl Default for PathAllowlistPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_prefix_read() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        assert_eq!(
            p.decide("box", "/etc/hosts", Mode::Read),
            PathVerdict::Allowed
        );
    }

    #[test]
    fn deny_mode_when_read_only() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        match p.decide("box", "/etc/hosts", Mode::WriteOnly) {
            PathVerdict::DeniedMode { prefix, granted } => {
                assert_eq!(prefix, "/etc/");
                assert_eq!(granted, Mode::Read);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn deny_no_match() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        assert_eq!(
            p.decide("box", "/var/log", Mode::Read),
            PathVerdict::DeniedNoMatch
        );
    }

    #[test]
    fn rw_satisfies_read_and_write() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/tmp/", Mode::ReadWrite).unwrap();
        assert_eq!(p.decide("box", "/tmp/a", Mode::Read), PathVerdict::Allowed);
        assert_eq!(
            p.decide("box", "/tmp/a", Mode::WriteOnly),
            PathVerdict::Allowed
        );
    }

    #[test]
    fn unknown_substrate() {
        let p = PathAllowlistPolicy::new();
        assert_eq!(p.decide("nope", "/a", Mode::Read), PathVerdict::Unknown);
    }

    #[test]
    fn first_prefix_wins() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        // More specific prefix added first, broader after.
        p.grant("box", "/etc/secret/", Mode::WriteOnly).unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        // /etc/secret/x matches the specific first → WriteOnly grant,
        // read request fails.
        match p.decide("box", "/etc/secret/key", Mode::Read) {
            PathVerdict::DeniedMode { prefix, .. } => assert_eq!(prefix, "/etc/secret/"),
            _ => panic!(),
        }
    }

    #[test]
    fn regrant_replaces_mode() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        p.grant("box", "/etc/", Mode::ReadWrite).unwrap();
        assert_eq!(
            p.decide("box", "/etc/x", Mode::WriteOnly),
            PathVerdict::Allowed
        );
    }

    #[test]
    fn revoke_removes() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        assert!(p.revoke("box", "/etc/").unwrap());
        assert_eq!(
            p.decide("box", "/etc/x", Mode::Read),
            PathVerdict::DeniedNoMatch
        );
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = PathAllowlistPolicy::new();
        assert!(matches!(
            p.register("").unwrap_err(),
            PathPolicyError::EmptySubstrate
        ));
        p.register("s").unwrap();
        assert!(matches!(
            p.grant("s", "", Mode::Read).unwrap_err(),
            PathPolicyError::EmptyPrefix
        ));
    }

    #[test]
    fn unknown_substrate_grant_rejected() {
        let mut p = PathAllowlistPolicy::new();
        assert!(matches!(
            p.grant("nope", "/a", Mode::Read).unwrap_err(),
            PathPolicyError::UnknownSubstrate(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PathAllowlistPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PathPolicyError::SchemaMismatch
        ));
    }

    #[test]
    fn path_serde_roundtrip() {
        let mut p = PathAllowlistPolicy::new();
        p.register("box").unwrap();
        p.grant("box", "/etc/", Mode::Read).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PathAllowlistPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
