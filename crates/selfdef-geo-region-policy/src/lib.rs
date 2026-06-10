//! `selfdef-geo-region-policy` — region allow/deny.
//!
//! Each actor has a `Mode { AllowList | DenyList }` and a set of
//! regions (ISO country codes). `decide(actor, region)`:
//!   * AllowList → `Allow` if region in set, else `Deny`.
//!   * DenyList → `Deny` if region in set, else `Allow`.
//!   * Unknown actor → falls back to `default_mode` + `default_set`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Allow only listed regions.
    AllowList,
    /// Deny only listed regions.
    DenyList,
}

/// Per-actor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRegions {
    /// Mode.
    pub mode: Mode,
    /// Regions.
    pub regions: BTreeSet<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoRegionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Default fallback mode.
    pub default_mode: Mode,
    /// Default region set.
    pub default_regions: BTreeSet<String>,
    /// actor → regions.
    pub actors: BTreeMap<String, ActorRegions>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GeoVerdict {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GeoError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("actor empty")]
    EmptyActor,
    /// Empty.
    #[error("region empty")]
    EmptyRegion,
}

impl GeoRegionPolicy {
    /// New.
    pub fn new(default_mode: Mode) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            default_mode,
            default_regions: BTreeSet::new(),
            actors: BTreeMap::new(),
        }
    }

    /// Set default regions.
    pub fn set_default_regions(&mut self, regions: &[&str]) -> Result<(), GeoError> {
        let mut set = BTreeSet::new();
        for r in regions {
            if r.is_empty() {
                return Err(GeoError::EmptyRegion);
            }
            set.insert((*r).into());
        }
        self.default_regions = set;
        Ok(())
    }

    /// Configure actor.
    pub fn set_actor(&mut self, actor: &str, mode: Mode, regions: &[&str]) -> Result<(), GeoError> {
        if actor.is_empty() {
            return Err(GeoError::EmptyActor);
        }
        let mut set = BTreeSet::new();
        for r in regions {
            if r.is_empty() {
                return Err(GeoError::EmptyRegion);
            }
            set.insert((*r).into());
        }
        self.actors
            .insert(actor.into(), ActorRegions { mode, regions: set });
        Ok(())
    }

    /// Remove actor config (falls back to default).
    pub fn remove_actor(&mut self, actor: &str) -> bool {
        self.actors.remove(actor).is_some()
    }

    /// Decide.
    pub fn decide(&self, actor: &str, region: &str) -> Result<GeoVerdict, GeoError> {
        if actor.is_empty() {
            return Err(GeoError::EmptyActor);
        }
        if region.is_empty() {
            return Err(GeoError::EmptyRegion);
        }
        let (mode, regions) = match self.actors.get(actor) {
            Some(a) => (a.mode, &a.regions),
            None => (self.default_mode, &self.default_regions),
        };
        // ISO country codes are case-insensitive (canonically uppercase). Match
        // case-insensitively so a resolver/config emitting a different case
        // cannot bypass a DenyList block (`cn` vs `CN`) or be wrongly denied by
        // an AllowList.
        let in_set = regions.iter().any(|r| r.eq_ignore_ascii_case(region));
        let v = match (mode, in_set) {
            (Mode::AllowList, true) => GeoVerdict::Allow,
            (Mode::AllowList, false) => GeoVerdict::Deny,
            (Mode::DenyList, true) => GeoVerdict::Deny,
            (Mode::DenyList, false) => GeoVerdict::Allow,
        };
        Ok(v)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GeoError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GeoError::SchemaMismatch);
        }
        for r in &self.default_regions {
            if r.is_empty() {
                return Err(GeoError::EmptyRegion);
            }
        }
        for (a, ar) in &self.actors {
            if a.is_empty() {
                return Err(GeoError::EmptyActor);
            }
            for r in &ar.regions {
                if r.is_empty() {
                    return Err(GeoError::EmptyRegion);
                }
            }
        }
        Ok(())
    }
}

impl Default for GeoRegionPolicy {
    fn default() -> Self {
        Self::new(Mode::AllowList)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_allows_listed() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_actor("a", Mode::AllowList, &["US", "CA"]).unwrap();
        assert_eq!(p.decide("a", "US").unwrap(), GeoVerdict::Allow);
        assert_eq!(p.decide("a", "FR").unwrap(), GeoVerdict::Deny);
    }

    #[test]
    fn denylist_denies_listed() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_actor("a", Mode::DenyList, &["KP"]).unwrap();
        assert_eq!(p.decide("a", "KP").unwrap(), GeoVerdict::Deny);
        assert_eq!(p.decide("a", "US").unwrap(), GeoVerdict::Allow);
    }

    #[test]
    fn unknown_actor_uses_default() {
        let mut p = GeoRegionPolicy::new(Mode::DenyList);
        p.set_default_regions(&["RU"]).unwrap();
        assert_eq!(p.decide("nobody", "RU").unwrap(), GeoVerdict::Deny);
        assert_eq!(p.decide("nobody", "US").unwrap(), GeoVerdict::Allow);
    }

    #[test]
    fn remove_actor_falls_back() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_default_regions(&["US"]).unwrap();
        p.set_actor("a", Mode::DenyList, &["US"]).unwrap();
        // Before removal: a's DenyList denies US.
        assert_eq!(p.decide("a", "US").unwrap(), GeoVerdict::Deny);
        p.remove_actor("a");
        // After: falls back to default AllowList[US].
        assert_eq!(p.decide("a", "US").unwrap(), GeoVerdict::Allow);
    }

    #[test]
    fn region_matching_is_case_insensitive_iso() {
        // Regions are ISO country codes — case-insensitive (canonically
        // uppercase). A geo-resolver or config emitting a different case must
        // NOT bypass a DenyList block: `cn` is the same country as `CN`.
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_actor("a", Mode::DenyList, &["CN"]).unwrap();
        assert_eq!(p.decide("a", "cn").unwrap(), GeoVerdict::Deny);
        assert_eq!(p.decide("a", "Cn").unwrap(), GeoVerdict::Deny);
        assert_eq!(p.decide("a", "CN").unwrap(), GeoVerdict::Deny);
        assert_eq!(p.decide("a", "US").unwrap(), GeoVerdict::Allow);
        // AllowList: a case-varied allowed region is admitted, not wrongly denied.
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_actor("b", Mode::AllowList, &["US"]).unwrap();
        assert_eq!(p.decide("b", "us").unwrap(), GeoVerdict::Allow);
        assert_eq!(p.decide("b", "FR").unwrap(), GeoVerdict::Deny);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        assert!(matches!(
            p.set_actor("", Mode::AllowList, &[]).unwrap_err(),
            GeoError::EmptyActor
        ));
        assert!(matches!(
            p.set_actor("a", Mode::AllowList, &[""]).unwrap_err(),
            GeoError::EmptyRegion
        ));
        assert!(matches!(
            p.decide("", "X").unwrap_err(),
            GeoError::EmptyActor
        ));
        assert!(matches!(
            p.decide("a", "").unwrap_err(),
            GeoError::EmptyRegion
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            GeoError::SchemaMismatch
        ));
    }

    #[test]
    fn geo_serde_roundtrip() {
        let mut p = GeoRegionPolicy::new(Mode::AllowList);
        p.set_actor("a", Mode::DenyList, &["KP", "RU"]).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: GeoRegionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
