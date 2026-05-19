//! `selfdef-rate-limit-policy` — IPS-side per-profile rate ceilings.
//!
//! Each profile declares (rps_ceiling, rpm_ceiling, rph_ceiling).
//! Caller passes counts observed in last second/minute/hour; this
//! crate returns `RateVerdict::Within | Warn | Breach`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_profile_authority_gate::Profile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Rate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RateVerdict {
    /// Below 80% of all ceilings.
    Within,
    /// Above 80% but below 100% of some ceiling.
    Warn,
    /// At or above 100% of some ceiling.
    Breach,
}

/// Per-profile ceiling tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceiling {
    /// Requests per second.
    pub rps: u32,
    /// Requests per minute.
    pub rpm: u32,
    /// Requests per hour.
    pub rph: u32,
}

/// Per-profile entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileRule {
    /// Profile.
    pub profile: Profile,
    /// Ceilings.
    pub ceiling: Ceiling,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 6 rules (one per profile).
    pub rules: Vec<ProfileRule>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 6.
    #[error("rule count {0} != 6 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing profile: {0:?}")]
    Missing(Profile),
    /// Zero ceiling.
    #[error("profile {0:?} has zero ceiling")]
    ZeroCeiling(Profile),
    /// rps > rpm/60 or rpm > rph/60.
    #[error("profile {0:?} ceilings not monotonically consistent")]
    Inconsistent(Profile),
}

const REQUIRED: [Profile; 6] = [
    Profile::Private, Profile::Fast, Profile::Careful,
    Profile::Autonomous, Profile::Experimental, Profile::Production,
];

impl RateLimitPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let rules = vec![
            ProfileRule { profile: Profile::Private,      ceiling: Ceiling { rps:  5,  rpm:  60,   rph:  600   } },
            ProfileRule { profile: Profile::Fast,         ceiling: Ceiling { rps: 30,  rpm:  900,  rph:  20_000 } },
            ProfileRule { profile: Profile::Careful,      ceiling: Ceiling { rps: 10,  rpm:  300,  rph:  5_000  } },
            ProfileRule { profile: Profile::Autonomous,   ceiling: Ceiling { rps: 40,  rpm:  1_500, rph: 30_000 } },
            ProfileRule { profile: Profile::Experimental, ceiling: Ceiling { rps: 20,  rpm:  600,  rph:  10_000 } },
            ProfileRule { profile: Profile::Production,   ceiling: Ceiling { rps: 50,  rpm:  2_000, rph: 50_000 } },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rules,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RateLimitError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RateLimitError::SchemaMismatch);
        }
        if self.rules.len() != 6 {
            return Err(RateLimitError::CountInvalid(self.rules.len()));
        }
        for p in REQUIRED {
            if !self.rules.iter().any(|r| r.profile == p) {
                return Err(RateLimitError::Missing(p));
            }
        }
        for r in &self.rules {
            if r.ceiling.rps == 0 || r.ceiling.rpm == 0 || r.ceiling.rph == 0 {
                return Err(RateLimitError::ZeroCeiling(r.profile));
            }
            // Sustained-rate consistency: rpm must be <= rph (per-minute can't exceed per-hour)
            // and rps must be <= rpm (per-second can't exceed per-minute).
            if r.ceiling.rps as u64 > r.ceiling.rpm as u64 {
                return Err(RateLimitError::Inconsistent(r.profile));
            }
            if r.ceiling.rpm as u64 > r.ceiling.rph as u64 {
                return Err(RateLimitError::Inconsistent(r.profile));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, p: Profile) -> Option<&Ceiling> {
        self.rules.iter().find(|r| r.profile == p).map(|r| &r.ceiling)
    }

    /// Evaluate. `(observed_rps, observed_rpm, observed_rph)`.
    pub fn evaluate(&self, profile: Profile, observed_rps: u32, observed_rpm: u32, observed_rph: u32) -> RateVerdict {
        let Some(c) = self.get(profile) else { return RateVerdict::Breach; };
        let max_ratio_pct = [
            (observed_rps as u64 * 100) / (c.rps as u64).max(1),
            (observed_rpm as u64 * 100) / (c.rpm as u64).max(1),
            (observed_rph as u64 * 100) / (c.rph as u64).max(1),
        ].into_iter().max().unwrap_or(0);
        if max_ratio_pct >= 100 { RateVerdict::Breach }
        else if max_ratio_pct >= 80 { RateVerdict::Warn }
        else { RateVerdict::Within }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        RateLimitPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn six_profiles_present() {
        let p = RateLimitPolicy::canonical();
        for r in REQUIRED { assert!(p.get(r).is_some(), "missing {r:?}"); }
    }

    #[test]
    fn within_below_80pct() {
        let p = RateLimitPolicy::canonical();
        // Private: rps=5 → 3 = 60% → within.
        assert_eq!(p.evaluate(Profile::Private, 3, 30, 300), RateVerdict::Within);
    }

    #[test]
    fn warn_between_80_and_100() {
        let p = RateLimitPolicy::canonical();
        // Private: rps=5 → 4 = 80% → warn.
        assert_eq!(p.evaluate(Profile::Private, 4, 30, 300), RateVerdict::Warn);
    }

    #[test]
    fn breach_at_ceiling() {
        let p = RateLimitPolicy::canonical();
        assert_eq!(p.evaluate(Profile::Private, 5, 30, 300), RateVerdict::Breach);
        // Above ceiling.
        assert_eq!(p.evaluate(Profile::Private, 50, 30, 300), RateVerdict::Breach);
    }

    #[test]
    fn rpm_can_trigger_breach_alone() {
        let p = RateLimitPolicy::canonical();
        // Private: rpm=60 → 70 → breach.
        assert_eq!(p.evaluate(Profile::Private, 1, 70, 100), RateVerdict::Breach);
    }

    #[test]
    fn production_higher_ceilings() {
        let p = RateLimitPolicy::canonical();
        let priv_c = p.get(Profile::Private).unwrap();
        let prod_c = p.get(Profile::Production).unwrap();
        assert!(prod_c.rps > priv_c.rps);
        assert!(prod_c.rph > priv_c.rph);
    }

    #[test]
    fn zero_ceiling_caught() {
        let mut p = RateLimitPolicy::canonical();
        p.rules[0].ceiling.rps = 0;
        assert!(matches!(p.validate().unwrap_err(), RateLimitError::ZeroCeiling(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RateLimitPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), RateLimitError::SchemaMismatch));
    }

    #[test]
    fn verdict_serde_kebab() {
        assert_eq!(serde_json::to_string(&RateVerdict::Within).unwrap(), "\"within\"");
        assert_eq!(serde_json::to_string(&RateVerdict::Warn).unwrap(), "\"warn\"");
        assert_eq!(serde_json::to_string(&RateVerdict::Breach).unwrap(), "\"breach\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = RateLimitPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: RateLimitPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
