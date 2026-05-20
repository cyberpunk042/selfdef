//! `selfdef-grant-template-allowlist` — per-Profile template gate.
//!
//! Each Profile carries a `BTreeSet<String>` of grant template ids
//! permitted in that Profile. The literal `"*"` wildcards allow all
//! templates. `classify(profile, template_id)` returns:
//!
//!   * `Allowed`        — explicit match or `"*"` present.
//!   * `Denied { allowed_count }` — not in set.
//!   * `Unconfigured`   — Profile not registered.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
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
pub struct GrantTemplateAllowlist {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile sets.
    pub profiles: BTreeMap<Profile, BTreeSet<String>>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AllowVerdict {
    /// Allowed.
    Allowed,
    /// Denied.
    Denied {
        /// allowed entry count in profile set.
        allowed_count: usize,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AllowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty template id.
    #[error("template id empty")]
    EmptyId,
}

impl GrantTemplateAllowlist {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(Profile::Private,      ["read-local".into(), "watch-fs".into()].into_iter().collect());
        p.insert(Profile::Fast,         ["read-local".into(), "watch-fs".into(), "write-tmp".into(), "outbound-http-readonly".into()].into_iter().collect());
        p.insert(Profile::Careful,      ["read-local".into(), "watch-fs".into(), "write-tmp".into()].into_iter().collect());
        p.insert(Profile::Autonomous,   ["read-local".into(), "watch-fs".into(), "write-tmp".into(), "outbound-http-readonly".into(), "outbound-http-write".into(), "spawn-child".into()].into_iter().collect());
        p.insert(Profile::Experimental, ["*".into()].into_iter().collect());
        p.insert(Profile::Production,   ["read-local".into(), "watch-fs".into(), "write-tmp".into(), "outbound-http-readonly".into()].into_iter().collect());
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, template_id: &str) -> Result<AllowVerdict, AllowError> {
        if template_id.is_empty() { return Err(AllowError::EmptyId); }
        let set = match self.profiles.get(&profile) {
            Some(s) => s,
            None => return Ok(AllowVerdict::Unconfigured),
        };
        if set.contains("*") || set.contains(template_id) {
            Ok(AllowVerdict::Allowed)
        } else {
            Ok(AllowVerdict::Denied { allowed_count: set.len() })
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AllowError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AllowError::SchemaMismatch); }
        for set in self.profiles.values() {
            for id in set {
                if id.is_empty() { return Err(AllowError::EmptyId); }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        GrantTemplateAllowlist::canonical().validate().unwrap();
    }

    #[test]
    fn allowed_in_profile() {
        let a = GrantTemplateAllowlist::canonical();
        assert_eq!(a.classify(Profile::Production, "read-local").unwrap(), AllowVerdict::Allowed);
    }

    #[test]
    fn denied_when_not_in_set() {
        let a = GrantTemplateAllowlist::canonical();
        match a.classify(Profile::Production, "spawn-child").unwrap() {
            AllowVerdict::Denied { allowed_count } => assert!(allowed_count > 0),
            _ => panic!(),
        }
    }

    #[test]
    fn wildcard_admits_all() {
        let a = GrantTemplateAllowlist::canonical();
        assert_eq!(a.classify(Profile::Experimental, "weird-new-grant").unwrap(), AllowVerdict::Allowed);
    }

    #[test]
    fn unconfigured_profile() {
        let mut a = GrantTemplateAllowlist::canonical();
        a.profiles.clear();
        assert_eq!(a.classify(Profile::Production, "read-local").unwrap(), AllowVerdict::Unconfigured);
    }

    #[test]
    fn empty_id_rejected() {
        let a = GrantTemplateAllowlist::canonical();
        assert!(matches!(a.classify(Profile::Production, "").unwrap_err(), AllowError::EmptyId));
    }

    #[test]
    fn autonomous_has_more_than_production() {
        let a = GrantTemplateAllowlist::canonical();
        // spawn-child is allowed in Autonomous but not Production.
        assert_eq!(a.classify(Profile::Autonomous, "spawn-child").unwrap(), AllowVerdict::Allowed);
        assert!(matches!(a.classify(Profile::Production, "spawn-child").unwrap(), AllowVerdict::Denied { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut a = GrantTemplateAllowlist::canonical();
        a.schema_version = "9.9.9".into();
        assert!(matches!(a.validate().unwrap_err(), AllowError::SchemaMismatch));
    }

    #[test]
    fn allowlist_serde_roundtrip() {
        let a = GrantTemplateAllowlist::canonical();
        let j = serde_json::to_string(&a).unwrap();
        let back: GrantTemplateAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
