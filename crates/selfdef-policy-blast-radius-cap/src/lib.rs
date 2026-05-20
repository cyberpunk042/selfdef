//! `selfdef-policy-blast-radius-cap` — per-Profile cap on BlastRadius.
//!
//! `set_cap(profile, blast)` configures; `classify(profile, observed)`
//! returns Allowed / OverCap{cap, observed} / Unconfigured.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_blast_radius_classifier::BlastRadius;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBlastRadiusCap {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile cap.
    pub caps: BTreeMap<Profile, BlastRadius>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CapVerdict {
    /// observed ≤ cap.
    Allowed,
    /// observed > cap.
    OverCap {
        /// cap.
        cap: BlastRadius,
        /// observed.
        observed: BlastRadius,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CapError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

fn rank(b: BlastRadius) -> u8 {
    match b {
        BlastRadius::LocalEphemeral => 0,
        BlastRadius::LocalPersistent => 1,
        BlastRadius::CrossSession => 2,
        BlastRadius::CrossMachine => 3,
        BlastRadius::Public => 4,
    }
}

impl PolicyBlastRadiusCap {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut c = BTreeMap::new();
        c.insert(Profile::Private,      BlastRadius::LocalPersistent);
        c.insert(Profile::Fast,         BlastRadius::CrossSession);
        c.insert(Profile::Careful,      BlastRadius::LocalPersistent);
        c.insert(Profile::Autonomous,   BlastRadius::CrossMachine);
        c.insert(Profile::Experimental, BlastRadius::Public);
        c.insert(Profile::Production,   BlastRadius::CrossSession);
        Self {
            schema_version: SCHEMA_VERSION.into(),
            caps: c,
        }
    }

    /// Set.
    pub fn set_cap(&mut self, profile: Profile, blast: BlastRadius) {
        self.caps.insert(profile, blast);
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, observed: BlastRadius) -> CapVerdict {
        let cap = match self.caps.get(&profile).copied() {
            Some(c) => c,
            None => return CapVerdict::Unconfigured,
        };
        if rank(observed) <= rank(cap) {
            CapVerdict::Allowed
        } else {
            CapVerdict::OverCap { cap, observed }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CapError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CapError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        PolicyBlastRadiusCap::canonical().validate().unwrap();
    }

    #[test]
    fn under_cap_allowed() {
        let c = PolicyBlastRadiusCap::canonical();
        assert_eq!(c.classify(Profile::Production, BlastRadius::LocalEphemeral), CapVerdict::Allowed);
        assert_eq!(c.classify(Profile::Production, BlastRadius::CrossSession), CapVerdict::Allowed);
    }

    #[test]
    fn over_cap_rejected() {
        let c = PolicyBlastRadiusCap::canonical();
        let v = c.classify(Profile::Production, BlastRadius::Public);
        match v {
            CapVerdict::OverCap { cap, observed } => {
                assert_eq!(cap, BlastRadius::CrossSession);
                assert_eq!(observed, BlastRadius::Public);
            }
            _ => panic!("expected over-cap"),
        }
    }

    #[test]
    fn experimental_admits_public() {
        let c = PolicyBlastRadiusCap::canonical();
        assert_eq!(c.classify(Profile::Experimental, BlastRadius::Public), CapVerdict::Allowed);
    }

    #[test]
    fn private_is_strictest() {
        let c = PolicyBlastRadiusCap::canonical();
        assert!(matches!(c.classify(Profile::Private, BlastRadius::CrossMachine), CapVerdict::OverCap { .. }));
    }

    #[test]
    fn unconfigured_profile() {
        let mut c = PolicyBlastRadiusCap::canonical();
        c.caps.clear();
        assert_eq!(c.classify(Profile::Fast, BlastRadius::LocalEphemeral), CapVerdict::Unconfigured);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PolicyBlastRadiusCap::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CapError::SchemaMismatch));
    }

    #[test]
    fn cap_serde_roundtrip() {
        let c = PolicyBlastRadiusCap::canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: PolicyBlastRadiusCap = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
