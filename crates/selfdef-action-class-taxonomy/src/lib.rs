//! `selfdef-action-class-taxonomy` — 10 canonical action classes.
//!
//! Each class declares default `RiskClass` + `SideEffectClass` +
//! minimum `Profile`. The cockpit + the policy decision engine
//! consume these for consistent labelling.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{RiskClass, SideEffectClass};
use selfdef_profile_authority_gate::Profile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 10 canonical action classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionClass {
    /// Read a file or directory.
    FsRead,
    /// Write a file.
    FsWrite,
    /// Delete or unlink.
    FsDelete,
    /// HTTP GET / network fetch.
    NetFetch,
    /// HTTP POST / network publish.
    NetPost,
    /// Spawn a subprocess.
    ProcSpawn,
    /// Send signal / kill a process.
    ProcKill,
    /// Mutate operator configuration.
    ConfigChange,
    /// Read secrets directory.
    SecretRead,
    /// Administer IPS itself.
    IpsAdmin,
}

/// Per-class policy defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionClassDefaults {
    /// Class.
    pub class: ActionClass,
    /// Default risk.
    pub risk: RiskClass,
    /// Default side-effect.
    pub side_effect: SideEffectClass,
    /// Minimum profile required.
    pub min_profile: Profile,
}

/// Taxonomy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionClassTaxonomy {
    /// Schema version.
    pub schema_version: String,
    /// 10 defaults.
    pub defaults: Vec<ActionClassDefaults>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ActionClassError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 10.
    #[error("default count {0} != 10")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing class: {0:?}")]
    Missing(ActionClass),
}

const REQUIRED: [ActionClass; 10] = [
    ActionClass::FsRead, ActionClass::FsWrite, ActionClass::FsDelete,
    ActionClass::NetFetch, ActionClass::NetPost,
    ActionClass::ProcSpawn, ActionClass::ProcKill,
    ActionClass::ConfigChange, ActionClass::SecretRead, ActionClass::IpsAdmin,
];

impl ActionClassTaxonomy {
    /// Canonical taxonomy.
    pub fn canonical() -> Self {
        let defaults = vec![
            ActionClassDefaults { class: ActionClass::FsRead,       risk: RiskClass::Low,      side_effect: SideEffectClass::ReadOnly,      min_profile: Profile::Private },
            ActionClassDefaults { class: ActionClass::FsWrite,      risk: RiskClass::Medium,   side_effect: SideEffectClass::FsWrite,       min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::FsDelete,     risk: RiskClass::High,     side_effect: SideEffectClass::FsWrite,       min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::NetFetch,     risk: RiskClass::Low,      side_effect: SideEffectClass::NetworkEgress, min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::NetPost,      risk: RiskClass::Medium,   side_effect: SideEffectClass::NetworkEgress, min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::ProcSpawn,    risk: RiskClass::Medium,   side_effect: SideEffectClass::Process,       min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::ProcKill,     risk: RiskClass::High,     side_effect: SideEffectClass::Process,       min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::ConfigChange, risk: RiskClass::High,     side_effect: SideEffectClass::Persistent,    min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::SecretRead,   risk: RiskClass::High,     side_effect: SideEffectClass::ReadOnly,      min_profile: Profile::Careful },
            ActionClassDefaults { class: ActionClass::IpsAdmin,     risk: RiskClass::Critical, side_effect: SideEffectClass::Persistent,    min_profile: Profile::Production },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            defaults,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ActionClassError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ActionClassError::SchemaMismatch);
        }
        if self.defaults.len() != 10 {
            return Err(ActionClassError::CountInvalid(self.defaults.len()));
        }
        for c in REQUIRED {
            if !self.defaults.iter().any(|d| d.class == c) {
                return Err(ActionClassError::Missing(c));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, class: ActionClass) -> Option<&ActionClassDefaults> {
        self.defaults.iter().find(|d| d.class == class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        ActionClassTaxonomy::canonical().validate().unwrap();
    }

    #[test]
    fn ten_classes_present() {
        let t = ActionClassTaxonomy::canonical();
        for c in REQUIRED { assert!(t.get(c).is_some(), "missing {c:?}"); }
    }

    #[test]
    fn ips_admin_is_critical_production() {
        let t = ActionClassTaxonomy::canonical();
        let d = t.get(ActionClass::IpsAdmin).unwrap();
        assert_eq!(d.risk, RiskClass::Critical);
        assert_eq!(d.side_effect, SideEffectClass::Persistent);
        assert_eq!(d.min_profile, Profile::Production);
    }

    #[test]
    fn fs_read_minimal() {
        let t = ActionClassTaxonomy::canonical();
        let d = t.get(ActionClass::FsRead).unwrap();
        assert_eq!(d.risk, RiskClass::Low);
        assert_eq!(d.side_effect, SideEffectClass::ReadOnly);
        assert_eq!(d.min_profile, Profile::Private);
    }

    #[test]
    fn fs_delete_higher_than_write() {
        let t = ActionClassTaxonomy::canonical();
        let write = t.get(ActionClass::FsWrite).unwrap();
        let del = t.get(ActionClass::FsDelete).unwrap();
        assert!(del.risk > write.risk);
    }

    #[test]
    fn proc_kill_higher_than_spawn() {
        let t = ActionClassTaxonomy::canonical();
        let spawn = t.get(ActionClass::ProcSpawn).unwrap();
        let kill = t.get(ActionClass::ProcKill).unwrap();
        assert!(kill.risk > spawn.risk);
    }

    #[test]
    fn secret_read_high_risk() {
        let t = ActionClassTaxonomy::canonical();
        assert_eq!(t.get(ActionClass::SecretRead).unwrap().risk, RiskClass::High);
    }

    #[test]
    fn config_change_persistent() {
        let t = ActionClassTaxonomy::canonical();
        assert_eq!(t.get(ActionClass::ConfigChange).unwrap().side_effect, SideEffectClass::Persistent);
    }

    #[test]
    fn count_invalid_caught() {
        let mut t = ActionClassTaxonomy::canonical();
        t.defaults.pop();
        assert!(matches!(t.validate().unwrap_err(), ActionClassError::CountInvalid(9)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = ActionClassTaxonomy::canonical();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), ActionClassError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&ActionClass::FsRead).unwrap(), "\"fs-read\"");
        assert_eq!(serde_json::to_string(&ActionClass::ConfigChange).unwrap(), "\"config-change\"");
        assert_eq!(serde_json::to_string(&ActionClass::IpsAdmin).unwrap(), "\"ips-admin\"");
    }

    #[test]
    fn taxonomy_serde_roundtrip() {
        let t = ActionClassTaxonomy::canonical();
        let j = serde_json::to_string(&t).unwrap();
        let back: ActionClassTaxonomy = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
