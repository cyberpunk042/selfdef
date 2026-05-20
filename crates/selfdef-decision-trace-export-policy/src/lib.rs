//! `selfdef-decision-trace-export-policy` — trace-export sensitivity gate.
//!
//! Each TraceField has a Sensitivity (Public/Internal/Confidential/
//! TopSecret). decide(field_sens, export_class) returns Allow / Deny
//! based on a strict tier ladder.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    /// Public.
    Public,
    /// Internal.
    Internal,
    /// Confidential.
    Confidential,
    /// TopSecret.
    TopSecret,
}

/// Export destination class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportClass {
    /// Same engine instance — debug pane.
    InEngine,
    /// Operator's local disk (encrypted).
    OperatorDisk,
    /// Fleet peer (other engine instance under same operator).
    FleetPeer,
    /// External (vendor support, bug report).
    External,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportDecision {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionTraceExportPolicy {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ExportError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl DecisionTraceExportPolicy {
    /// New.
    pub fn new() -> Self { Self { schema_version: SCHEMA_VERSION.into() } }

    /// Decide.
    pub fn decide(&self, sens: Sensitivity, dest: ExportClass) -> ExportDecision {
        use ExportClass::*;
        use ExportDecision::*;
        use Sensitivity::*;
        match (sens, dest) {
            // TopSecret never leaves the engine.
            (TopSecret, InEngine) => Allow,
            (TopSecret, _) => Deny,
            // Confidential up to operator disk; not fleet, not external.
            (Confidential, InEngine | OperatorDisk) => Allow,
            (Confidential, _) => Deny,
            // Internal up to fleet peer; not external.
            (Internal, InEngine | OperatorDisk | FleetPeer) => Allow,
            (Internal, External) => Deny,
            // Public anywhere.
            (Public, _) => Allow,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ExportError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ExportError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for DecisionTraceExportPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExportClass::*;
    use ExportDecision::*;
    use Sensitivity::*;

    #[test]
    fn public_anywhere() {
        let p = DecisionTraceExportPolicy::new();
        for d in [InEngine, OperatorDisk, FleetPeer, External] {
            assert_eq!(p.decide(Public, d), Allow);
        }
    }

    #[test]
    fn top_secret_only_in_engine() {
        let p = DecisionTraceExportPolicy::new();
        assert_eq!(p.decide(TopSecret, InEngine), Allow);
        assert_eq!(p.decide(TopSecret, OperatorDisk), Deny);
        assert_eq!(p.decide(TopSecret, FleetPeer), Deny);
        assert_eq!(p.decide(TopSecret, External), Deny);
    }

    #[test]
    fn confidential_up_to_disk() {
        let p = DecisionTraceExportPolicy::new();
        assert_eq!(p.decide(Confidential, OperatorDisk), Allow);
        assert_eq!(p.decide(Confidential, FleetPeer), Deny);
    }

    #[test]
    fn internal_up_to_fleet() {
        let p = DecisionTraceExportPolicy::new();
        assert_eq!(p.decide(Internal, FleetPeer), Allow);
        assert_eq!(p.decide(Internal, External), Deny);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = DecisionTraceExportPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), ExportError::SchemaMismatch));
    }

    #[test]
    fn sensitivity_serde_kebab() {
        assert_eq!(serde_json::to_string(&Sensitivity::TopSecret).unwrap(), "\"top-secret\"");
    }

    #[test]
    fn export_class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ExportClass::FleetPeer).unwrap(), "\"fleet-peer\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = DecisionTraceExportPolicy::new();
        let j = serde_json::to_string(&p).unwrap();
        let back: DecisionTraceExportPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
