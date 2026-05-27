//! `selfdef-sandbox-fs-isolation` — sandbox-tier filesystem authority.
//!
//! Each tier declares max allowed PathClass + write_mode (ReadOnly /
//! ReadWrite). decide(tier, path_class, op) returns Allow when
//! path_class ≤ tier's max AND op respects write_mode.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sandbox tier (0..4, monotonically widening).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxTier {
    /// Tier 0 — no filesystem.
    Tier0,
    /// Tier 1 — jail dir only.
    Tier1,
    /// Tier 2 — workspace only.
    Tier2,
    /// Tier 3 — user home.
    Tier3,
    /// Tier 4 — host (full).
    Tier4,
}

/// Path class (ordered by privilege).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathClass {
    /// No path (in-memory only).
    None,
    /// Per-session jail dir.
    JailDir,
    /// Project workspace.
    Workspace,
    /// User home directory.
    UserHome,
    /// Anywhere on the host.
    Host,
}

/// Operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsOp {
    /// Read.
    Read,
    /// Write/create/modify.
    Write,
    /// Delete.
    Delete,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FsDecision {
    /// Allowed.
    Allow,
    /// Denied (path class beyond tier).
    DeniedClass,
    /// Denied (read-only tier).
    DeniedReadOnly,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxFsIsolation {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FsIsolationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SandboxFsIsolation {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Tier's max allowed PathClass.
    pub fn max_path(tier: SandboxTier) -> PathClass {
        match tier {
            SandboxTier::Tier0 => PathClass::None,
            SandboxTier::Tier1 => PathClass::JailDir,
            SandboxTier::Tier2 => PathClass::Workspace,
            SandboxTier::Tier3 => PathClass::UserHome,
            SandboxTier::Tier4 => PathClass::Host,
        }
    }

    /// Per-tier write capability:
    /// * Tier0/1 → ReadOnly even within jail.
    /// * Tier2..4 → ReadWrite.
    /// * Host writes only at Tier4.
    pub fn writes_allowed(tier: SandboxTier, path: PathClass) -> bool {
        match tier {
            SandboxTier::Tier0 | SandboxTier::Tier1 => false,
            SandboxTier::Tier2 | SandboxTier::Tier3 => path < PathClass::Host,
            SandboxTier::Tier4 => true,
        }
    }

    /// Decide.
    pub fn decide(&self, tier: SandboxTier, path: PathClass, op: FsOp) -> FsDecision {
        if path > Self::max_path(tier) {
            return FsDecision::DeniedClass;
        }
        let is_write = matches!(op, FsOp::Write | FsOp::Delete);
        if is_write && !Self::writes_allowed(tier, path) {
            return FsDecision::DeniedReadOnly;
        }
        FsDecision::Allow
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FsIsolationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FsIsolationError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for SandboxFsIsolation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> SandboxFsIsolation {
        SandboxFsIsolation::new()
    }

    #[test]
    fn tier0_only_none() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier0, PathClass::None, FsOp::Read),
            FsDecision::Allow
        );
        assert_eq!(
            x.decide(SandboxTier::Tier0, PathClass::JailDir, FsOp::Read),
            FsDecision::DeniedClass
        );
    }

    #[test]
    fn tier1_jail_read_only() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier1, PathClass::JailDir, FsOp::Read),
            FsDecision::Allow
        );
        assert_eq!(
            x.decide(SandboxTier::Tier1, PathClass::JailDir, FsOp::Write),
            FsDecision::DeniedReadOnly
        );
    }

    #[test]
    fn tier2_workspace_rw() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier2, PathClass::Workspace, FsOp::Write),
            FsDecision::Allow
        );
        assert_eq!(
            x.decide(SandboxTier::Tier2, PathClass::UserHome, FsOp::Read),
            FsDecision::DeniedClass
        );
    }

    #[test]
    fn tier3_home_rw_no_host_write() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier3, PathClass::UserHome, FsOp::Write),
            FsDecision::Allow
        );
        assert_eq!(
            x.decide(SandboxTier::Tier3, PathClass::Host, FsOp::Read),
            FsDecision::DeniedClass
        );
    }

    #[test]
    fn tier4_host_writes_allowed() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier4, PathClass::Host, FsOp::Delete),
            FsDecision::Allow
        );
    }

    #[test]
    fn delete_treated_as_write() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier1, PathClass::JailDir, FsOp::Delete),
            FsDecision::DeniedReadOnly
        );
    }

    #[test]
    fn higher_tiers_subsume_lower_classes() {
        let x = p();
        assert_eq!(
            x.decide(SandboxTier::Tier4, PathClass::JailDir, FsOp::Read),
            FsDecision::Allow
        );
        assert_eq!(
            x.decide(SandboxTier::Tier3, PathClass::Workspace, FsOp::Write),
            FsDecision::Allow
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut x = p();
        x.schema_version = "9.9.9".into();
        assert!(matches!(
            x.validate().unwrap_err(),
            FsIsolationError::SchemaMismatch
        ));
    }

    #[test]
    fn tier_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&SandboxTier::Tier0).unwrap(),
            "\"tier0\""
        );
    }

    #[test]
    fn path_class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PathClass::JailDir).unwrap(),
            "\"jail-dir\""
        );
        assert_eq!(
            serde_json::to_string(&PathClass::UserHome).unwrap(),
            "\"user-home\""
        );
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&FsDecision::DeniedClass).unwrap(),
            "\"denied-class\""
        );
        assert_eq!(
            serde_json::to_string(&FsDecision::DeniedReadOnly).unwrap(),
            "\"denied-read-only\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let x = p();
        let j = serde_json::to_string(&x).unwrap();
        let back: SandboxFsIsolation = serde_json::from_str(&j).unwrap();
        assert_eq!(x, back);
    }
}
