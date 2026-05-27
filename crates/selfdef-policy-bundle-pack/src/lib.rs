//! `selfdef-policy-bundle-pack` — atomic policy bundle.
//!
//! Each `BundlePack` declares (name, rule_pack_manifest, description,
//! created_at, signature). Swapping bundles is atomic: the daemon
//! validates the entire new pack before any rule is applied.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_rule_pack_version::RulePackManifest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One bundle pack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePack {
    /// Schema version.
    pub schema_version: String,
    /// Operator-readable name (unique within registry).
    pub name: String,
    /// Operator-readable description.
    pub description: String,
    /// Embedded rule pack manifest.
    pub rule_packs: RulePackManifest,
    /// ISO-8601 UTC.
    pub created_at: String,
    /// MS003 signature (non-empty).
    pub signature: String,
}

/// Registry of named bundle packs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePackRegistry {
    /// Schema version.
    pub schema_version: String,
    /// Active bundle pack name.
    pub active: String,
    /// All registered bundle packs (by name).
    pub packs: Vec<BundlePack>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BundlePackError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty name.
    #[error("bundle name empty")]
    EmptyName,
    /// Empty description.
    #[error("bundle {0} description empty")]
    EmptyDescription(String),
    /// Empty created_at.
    #[error("bundle {0} created_at empty")]
    EmptyCreatedAt(String),
    /// Unsigned.
    #[error("bundle {0} unsigned")]
    Unsigned(String),
    /// Invalid embedded rule pack manifest.
    #[error("bundle {0} rule_packs invalid: {1}")]
    InvalidRulePacks(String, String),
    /// Duplicate.
    #[error("duplicate bundle name: {0}")]
    Duplicate(String),
    /// Unknown.
    #[error("unknown bundle name: {0}")]
    Unknown(String),
    /// Empty active.
    #[error("active bundle name empty")]
    EmptyActive,
}

impl BundlePack {
    /// Validate one bundle.
    pub fn validate(&self) -> Result<(), BundlePackError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundlePackError::SchemaMismatch);
        }
        if self.name.is_empty() {
            return Err(BundlePackError::EmptyName);
        }
        if self.description.is_empty() {
            return Err(BundlePackError::EmptyDescription(self.name.clone()));
        }
        if self.created_at.is_empty() {
            return Err(BundlePackError::EmptyCreatedAt(self.name.clone()));
        }
        if self.signature.is_empty() {
            return Err(BundlePackError::Unsigned(self.name.clone()));
        }
        self.rule_packs
            .validate()
            .map_err(|e| BundlePackError::InvalidRulePacks(self.name.clone(), e.to_string()))?;
        Ok(())
    }
}

impl BundlePackRegistry {
    /// New with no packs.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            active: String::new(),
            packs: Vec::new(),
        }
    }

    /// Register a new pack.
    pub fn register(&mut self, pack: BundlePack) -> Result<(), BundlePackError> {
        pack.validate()?;
        if self.packs.iter().any(|p| p.name == pack.name) {
            return Err(BundlePackError::Duplicate(pack.name));
        }
        // First pack auto-activates.
        if self.packs.is_empty() && self.active.is_empty() {
            self.active = pack.name.clone();
        }
        self.packs.push(pack);
        Ok(())
    }

    /// Atomic swap of active bundle. Validates the target before swapping.
    pub fn swap_active(&mut self, name: &str) -> Result<(), BundlePackError> {
        let pack = self
            .packs
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| BundlePackError::Unknown(name.into()))?;
        pack.validate()?;
        self.active = name.into();
        Ok(())
    }

    /// Lookup the active pack.
    pub fn active_pack(&self) -> Option<&BundlePack> {
        self.packs.iter().find(|p| p.name == self.active)
    }

    /// Lookup by name.
    pub fn get(&self, name: &str) -> Option<&BundlePack> {
        self.packs.iter().find(|p| p.name == name)
    }

    /// Validate the registry.
    pub fn validate(&self) -> Result<(), BundlePackError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundlePackError::SchemaMismatch);
        }
        if !self.packs.is_empty() && self.active.is_empty() {
            return Err(BundlePackError::EmptyActive);
        }
        if !self.active.is_empty() && !self.packs.iter().any(|p| p.name == self.active) {
            return Err(BundlePackError::Unknown(self.active.clone()));
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for p in &self.packs {
            p.validate()?;
            if !seen.insert(p.name.as_str()) {
                return Err(BundlePackError::Duplicate(p.name.clone()));
            }
        }
        Ok(())
    }
}

impl Default for BundlePackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_rule_pack_version::{PackKind, RulePack};

    fn rule_manifest() -> RulePackManifest {
        let kinds = [
            PackKind::Filesystem,
            PackKind::Network,
            PackKind::Capability,
            PackKind::Sandbox,
            PackKind::Communication,
            PackKind::CollectorBudget,
            PackKind::Quarantine,
            PackKind::CommitAuthority,
        ];
        RulePackManifest {
            schema_version: "1.0.0".into(),
            packs: kinds
                .iter()
                .map(|k| RulePack {
                    kind: *k,
                    semver: "1.0.0".into(),
                    signature: "sig".into(),
                    loaded_at: "t".into(),
                })
                .collect(),
        }
    }

    fn pack(name: &str) -> BundlePack {
        BundlePack {
            schema_version: SCHEMA_VERSION.into(),
            name: name.into(),
            description: format!("Bundle {name}"),
            rule_packs: rule_manifest(),
            created_at: "2026-05-19T03:00:00Z".into(),
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn pack_validates() {
        pack("baseline").validate().unwrap();
    }

    #[test]
    fn first_pack_auto_activates() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        assert_eq!(r.active, "baseline");
    }

    #[test]
    fn second_pack_does_not_auto_activate() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        r.register(pack("red-team")).unwrap();
        assert_eq!(r.active, "baseline");
    }

    #[test]
    fn swap_active_changes_pointer() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        r.register(pack("red-team")).unwrap();
        r.swap_active("red-team").unwrap();
        assert_eq!(r.active, "red-team");
        assert_eq!(r.active_pack().unwrap().name, "red-team");
    }

    #[test]
    fn swap_unknown_rejected() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        assert!(matches!(
            r.swap_active("none").unwrap_err(),
            BundlePackError::Unknown(_)
        ));
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        assert!(matches!(
            r.register(pack("baseline")).unwrap_err(),
            BundlePackError::Duplicate(_)
        ));
    }

    #[test]
    fn unsigned_pack_rejected() {
        let mut p = pack("x");
        p.signature = String::new();
        assert!(matches!(
            p.validate().unwrap_err(),
            BundlePackError::Unsigned(_)
        ));
    }

    #[test]
    fn empty_name_rejected() {
        let p = pack("");
        assert!(matches!(
            p.validate().unwrap_err(),
            BundlePackError::EmptyName
        ));
    }

    #[test]
    fn invalid_rule_packs_rejected() {
        let mut p = pack("x");
        p.rule_packs.packs.pop();
        assert!(matches!(
            p.validate().unwrap_err(),
            BundlePackError::InvalidRulePacks(_, _)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = BundlePackRegistry::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            BundlePackError::SchemaMismatch
        ));
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = BundlePackRegistry::new();
        r.register(pack("baseline")).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: BundlePackRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
