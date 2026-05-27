//! `selfdef-substrate-cpu-affinity` — per-Profile CPU-affinity mask.
//!
//! Each Profile carries a `BTreeSet<u32>` of permitted logical-core
//! ids. `classify(profile, core)` returns `Allowed` / `Denied{allowed}`
//! / `Unconfigured`. `core_count(profile)` reports how many cores are
//! permitted.
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
pub struct SubstrateCpuAffinity {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile permitted cores.
    pub profiles: BTreeMap<Profile, BTreeSet<u32>>,
}

/// Verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AffinityVerdict {
    /// Allowed.
    Allowed,
    /// Denied.
    Denied {
        /// allowed cores snapshot.
        allowed: Vec<u32>,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AffinityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl SubstrateCpuAffinity {
    /// Canonical 16-core split: Production cores 0..=3, Careful 4..=5,
    /// Fast 6..=9, Autonomous 10..=11, Experimental 12..=15, Private 0.
    pub fn canonical() -> Self {
        let mut p = BTreeMap::new();
        p.insert(Profile::Production, (0u32..=3).collect());
        p.insert(Profile::Careful, (4u32..=5).collect());
        p.insert(Profile::Fast, (6u32..=9).collect());
        p.insert(Profile::Autonomous, (10u32..=11).collect());
        p.insert(Profile::Experimental, (12u32..=15).collect());
        p.insert(Profile::Private, [0u32].into_iter().collect());
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles: p,
        }
    }

    /// Classify.
    pub fn classify(&self, profile: Profile, core: u32) -> AffinityVerdict {
        let set = match self.profiles.get(&profile) {
            Some(s) => s,
            None => return AffinityVerdict::Unconfigured,
        };
        if set.contains(&core) {
            AffinityVerdict::Allowed
        } else {
            AffinityVerdict::Denied {
                allowed: set.iter().copied().collect(),
            }
        }
    }

    /// Core count.
    pub fn core_count(&self, profile: Profile) -> Option<usize> {
        self.profiles.get(&profile).map(|s| s.len())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AffinityError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AffinityError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateCpuAffinity::canonical().validate().unwrap();
    }

    #[test]
    fn production_owns_low_cores() {
        let c = SubstrateCpuAffinity::canonical();
        assert_eq!(c.classify(Profile::Production, 0), AffinityVerdict::Allowed);
        assert_eq!(c.classify(Profile::Production, 3), AffinityVerdict::Allowed);
        assert!(matches!(
            c.classify(Profile::Production, 4),
            AffinityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn experimental_owns_top_cores() {
        let c = SubstrateCpuAffinity::canonical();
        assert_eq!(
            c.classify(Profile::Experimental, 15),
            AffinityVerdict::Allowed
        );
        assert!(matches!(
            c.classify(Profile::Experimental, 0),
            AffinityVerdict::Denied { .. }
        ));
    }

    #[test]
    fn private_one_core() {
        let c = SubstrateCpuAffinity::canonical();
        assert_eq!(c.core_count(Profile::Private), Some(1));
    }

    #[test]
    fn unconfigured_profile() {
        let mut c = SubstrateCpuAffinity::canonical();
        c.profiles.clear();
        assert_eq!(c.classify(Profile::Fast, 0), AffinityVerdict::Unconfigured);
        assert_eq!(c.core_count(Profile::Fast), None);
    }

    #[test]
    fn denied_includes_allowed_snapshot() {
        let c = SubstrateCpuAffinity::canonical();
        let v = c.classify(Profile::Careful, 99);
        match v {
            AffinityVerdict::Denied { allowed } => assert_eq!(allowed, vec![4, 5]),
            _ => panic!("expected denied"),
        }
    }

    #[test]
    fn no_overlap_between_profiles_except_private() {
        let c = SubstrateCpuAffinity::canonical();
        let prod: BTreeSet<u32> = c.profiles[&Profile::Production].clone();
        let careful: BTreeSet<u32> = c.profiles[&Profile::Careful].clone();
        let fast: BTreeSet<u32> = c.profiles[&Profile::Fast].clone();
        let auto: BTreeSet<u32> = c.profiles[&Profile::Autonomous].clone();
        let exp: BTreeSet<u32> = c.profiles[&Profile::Experimental].clone();
        assert!(prod.is_disjoint(&careful));
        assert!(prod.is_disjoint(&fast));
        assert!(prod.is_disjoint(&auto));
        assert!(prod.is_disjoint(&exp));
        // Private (core 0) intentionally overlaps Production.
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = SubstrateCpuAffinity::canonical();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            AffinityError::SchemaMismatch
        ));
    }

    #[test]
    fn affinity_serde_roundtrip() {
        let c = SubstrateCpuAffinity::canonical();
        let j = serde_json::to_string(&c).unwrap();
        let back: SubstrateCpuAffinity = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
