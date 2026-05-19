//! `selfdef-blast-radius-classifier` — operation blast-radius authority.
//!
//! Maps an operation's primitive features (target scope,
//! reversibility, visibility) onto a 5-level blast-radius enum. The
//! mapping is deterministic and serves as IPS input for downstream
//! gates (operator approval, quorum, time window). Pure classifier.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Where the effect lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetScope {
    /// In-memory only, this session.
    InMemorySession,
    /// On-disk under the engine sandbox.
    LocalDisk,
    /// User home directory (outside sandbox).
    UserHome,
    /// System-wide files (outside user home).
    System,
    /// Across machines (network / fleet).
    NetworkPeer,
    /// Public internet (uploads, posts).
    PublicInternet,
}

/// Reversibility of the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reversibility {
    /// Fully revertable (in-memory or snapshot-backed).
    Reversible,
    /// Reversible only via backup restore.
    BackupRestore,
    /// Irreversible (deleted, sent, published).
    Irreversible,
}

/// Visibility of the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    /// Only the engine sees it.
    EngineOnly,
    /// The operator sees it.
    Operator,
    /// Other operators / agents on the fleet.
    Fleet,
    /// External observers (public).
    Public,
}

/// 5-level blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlastRadius {
    /// Local & ephemeral — disappears on session close.
    LocalEphemeral,
    /// Local & persistent — survives session but stays on this host.
    LocalPersistent,
    /// Crosses sessions on this host (other operators see it).
    CrossSession,
    /// Crosses machines (fleet, peers).
    CrossMachine,
    /// Publicly visible (irreversible exposure).
    Public,
}

/// Input features for an operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationFeatures {
    /// Where it lands.
    pub target: TargetScope,
    /// Reversibility.
    pub reversibility: Reversibility,
    /// Visibility.
    pub visibility: Visibility,
}

/// Classification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlastClassification {
    /// Schema version.
    pub schema_version: String,
    /// Computed radius.
    pub radius: BlastRadius,
    /// Bumped flags (which input pushed the radius up).
    pub notes: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BlastError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Pure classifier.
#[derive(Debug, Clone, Default)]
pub struct BlastRadiusClassifier;

impl BlastRadiusClassifier {
    /// Classify a single operation.
    pub fn classify(f: OperationFeatures) -> BlastClassification {
        use BlastRadius as BR;
        let mut notes: Vec<String> = Vec::new();
        // Base from target scope.
        let mut r = match f.target {
            TargetScope::InMemorySession => BR::LocalEphemeral,
            TargetScope::LocalDisk => BR::LocalPersistent,
            TargetScope::UserHome | TargetScope::System => BR::CrossSession,
            TargetScope::NetworkPeer => BR::CrossMachine,
            TargetScope::PublicInternet => BR::Public,
        };
        // Bump by reversibility.
        if f.reversibility == Reversibility::Irreversible
            && matches!(r, BR::LocalEphemeral | BR::LocalPersistent)
        {
            notes.push("bumped: irreversible".into());
            r = BR::CrossSession;
        }
        // Bump by visibility.
        match f.visibility {
            Visibility::Public
                if matches!(r, BR::LocalEphemeral | BR::LocalPersistent | BR::CrossSession | BR::CrossMachine) =>
            {
                notes.push("bumped: visibility public".into());
                r = BR::Public;
            }
            Visibility::Fleet
                if matches!(r, BR::LocalEphemeral | BR::LocalPersistent | BR::CrossSession) =>
            {
                notes.push("bumped: visibility fleet".into());
                r = BR::CrossMachine;
            }
            _ => {}
        }
        // Bump: System + Irreversible always at least CrossMachine.
        if matches!(f.target, TargetScope::System) && f.reversibility == Reversibility::Irreversible {
            notes.push("bumped: system+irreversible".into());
            if matches!(r, BR::LocalEphemeral | BR::LocalPersistent | BR::CrossSession) {
                r = BR::CrossMachine;
            }
        }
        BlastClassification {
            schema_version: SCHEMA_VERSION.into(),
            radius: r,
            notes,
        }
    }
}

impl BlastClassification {
    /// Validate.
    pub fn validate(&self) -> Result<(), BlastError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BlastError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Reversibility::*;
    use TargetScope::*;
    use Visibility::*;

    fn feat(t: TargetScope, r: Reversibility, v: Visibility) -> OperationFeatures {
        OperationFeatures { target: t, reversibility: r, visibility: v }
    }

    #[test]
    fn in_memory_reversible_engine_only_is_ephemeral() {
        let c = BlastRadiusClassifier::classify(feat(InMemorySession, Reversible, EngineOnly));
        assert_eq!(c.radius, BlastRadius::LocalEphemeral);
        assert!(c.notes.is_empty());
    }

    #[test]
    fn local_disk_reversible_operator_is_persistent() {
        let c = BlastRadiusClassifier::classify(feat(LocalDisk, Reversible, Operator));
        assert_eq!(c.radius, BlastRadius::LocalPersistent);
    }

    #[test]
    fn user_home_cross_session() {
        let c = BlastRadiusClassifier::classify(feat(UserHome, BackupRestore, Operator));
        assert_eq!(c.radius, BlastRadius::CrossSession);
    }

    #[test]
    fn network_peer_cross_machine() {
        let c = BlastRadiusClassifier::classify(feat(NetworkPeer, Reversible, Fleet));
        assert_eq!(c.radius, BlastRadius::CrossMachine);
    }

    #[test]
    fn public_internet_is_public() {
        let c = BlastRadiusClassifier::classify(feat(PublicInternet, Irreversible, Public));
        assert_eq!(c.radius, BlastRadius::Public);
    }

    #[test]
    fn irreversible_bumps_local() {
        let c = BlastRadiusClassifier::classify(feat(LocalDisk, Irreversible, Operator));
        assert_eq!(c.radius, BlastRadius::CrossSession);
        assert!(c.notes.iter().any(|n| n.contains("irreversible")));
    }

    #[test]
    fn public_visibility_bumps_to_public() {
        let c = BlastRadiusClassifier::classify(feat(LocalDisk, Reversible, Public));
        assert_eq!(c.radius, BlastRadius::Public);
    }

    #[test]
    fn fleet_visibility_bumps_to_cross_machine() {
        let c = BlastRadiusClassifier::classify(feat(LocalDisk, Reversible, Fleet));
        assert_eq!(c.radius, BlastRadius::CrossMachine);
    }

    #[test]
    fn system_irreversible_bumps_cross_machine() {
        let c = BlastRadiusClassifier::classify(feat(System, Irreversible, Operator));
        assert_eq!(c.radius, BlastRadius::CrossMachine);
        assert!(c.notes.iter().any(|n| n.contains("system+irreversible")));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = BlastRadiusClassifier::classify(feat(InMemorySession, Reversible, EngineOnly));
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), BlastError::SchemaMismatch));
    }

    #[test]
    fn target_serde_kebab() {
        assert_eq!(serde_json::to_string(&InMemorySession).unwrap(), "\"in-memory-session\"");
        assert_eq!(serde_json::to_string(&PublicInternet).unwrap(), "\"public-internet\"");
    }

    #[test]
    fn radius_serde_kebab() {
        assert_eq!(serde_json::to_string(&BlastRadius::LocalEphemeral).unwrap(), "\"local-ephemeral\"");
        assert_eq!(serde_json::to_string(&BlastRadius::CrossMachine).unwrap(), "\"cross-machine\"");
    }

    #[test]
    fn classification_serde_roundtrip() {
        let c = BlastRadiusClassifier::classify(feat(LocalDisk, Irreversible, Operator));
        let j = serde_json::to_string(&c).unwrap();
        let back: BlastClassification = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
