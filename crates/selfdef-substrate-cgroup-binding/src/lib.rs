//! `selfdef-substrate-cgroup-binding` — Profile → cgroup name.
//!
//! Each Profile maps to a cgroup name. `classify(profile)` returns
//! `Bound{cgroup_name}` when set, `Unconfigured` otherwise.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
pub struct SubstrateCgroupBinding {
    /// Schema version.
    pub schema_version: String,
    /// profile → cgroup name.
    pub bindings: BTreeMap<Profile, String>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CgroupVerdict {
    /// Bound.
    Bound {
        /// cgroup name.
        cgroup_name: String,
    },
    /// Unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BindingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty name.
    #[error("cgroup name empty")]
    EmptyName,
}

impl SubstrateCgroupBinding {
    /// Canonical.
    pub fn canonical() -> Self {
        let mut b = BTreeMap::new();
        b.insert(Profile::Private, "selfdef/private".into());
        b.insert(Profile::Fast, "selfdef/fast".into());
        b.insert(Profile::Careful, "selfdef/careful".into());
        b.insert(Profile::Autonomous, "selfdef/autonomous".into());
        b.insert(Profile::Experimental, "selfdef/experimental".into());
        b.insert(Profile::Production, "selfdef/production".into());
        Self {
            schema_version: SCHEMA_VERSION.into(),
            bindings: b,
        }
    }

    /// Set.
    pub fn set(&mut self, profile: Profile, cgroup_name: &str) -> Result<(), BindingError> {
        if cgroup_name.is_empty() {
            return Err(BindingError::EmptyName);
        }
        self.bindings.insert(profile, cgroup_name.into());
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, profile: Profile) -> CgroupVerdict {
        match self.bindings.get(&profile) {
            Some(s) => CgroupVerdict::Bound {
                cgroup_name: s.clone(),
            },
            None => CgroupVerdict::Unconfigured,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BindingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BindingError::SchemaMismatch);
        }
        for s in self.bindings.values() {
            if s.is_empty() {
                return Err(BindingError::EmptyName);
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
        SubstrateCgroupBinding::canonical().validate().unwrap();
    }

    #[test]
    fn canonical_each_profile_bound() {
        let b = SubstrateCgroupBinding::canonical();
        for &p in &[
            Profile::Private,
            Profile::Fast,
            Profile::Careful,
            Profile::Autonomous,
            Profile::Experimental,
            Profile::Production,
        ] {
            assert!(matches!(b.classify(p), CgroupVerdict::Bound { .. }));
        }
    }

    #[test]
    fn unconfigured_when_cleared() {
        let mut b = SubstrateCgroupBinding::canonical();
        b.bindings.clear();
        assert_eq!(b.classify(Profile::Fast), CgroupVerdict::Unconfigured);
    }

    #[test]
    fn set_replaces() {
        let mut b = SubstrateCgroupBinding::canonical();
        b.set(Profile::Fast, "custom/fast").unwrap();
        match b.classify(Profile::Fast) {
            CgroupVerdict::Bound { cgroup_name } => assert_eq!(cgroup_name, "custom/fast"),
            _ => panic!(),
        }
    }

    #[test]
    fn empty_name_rejected() {
        let mut b = SubstrateCgroupBinding::canonical();
        assert!(matches!(
            b.set(Profile::Fast, "").unwrap_err(),
            BindingError::EmptyName
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = SubstrateCgroupBinding::canonical();
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BindingError::SchemaMismatch
        ));
    }

    #[test]
    fn binding_serde_roundtrip() {
        let b = SubstrateCgroupBinding::canonical();
        let j = serde_json::to_string(&b).unwrap();
        let back: SubstrateCgroupBinding = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
