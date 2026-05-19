//! `selfdef-subject-cohort` — 5-tier trust cohort taxonomy.
//!
//! Each subject is in exactly one cohort. Cohort defines:
//! - `default_trust_band`: (min, max) score
//! - `grant_ttl_ceiling_seconds`: max TTL the cohort can request on grants
//! - `max_risk`: highest RiskClass an Allow can carry for this cohort
//!
//! Promotion direction: Newcomer → Probationary → Trusted → Staff → Admin.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::RiskClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 cohorts (ordered low → high trust).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cohort {
    /// New subject (just enrolled).
    Newcomer,
    /// Earned baseline trust.
    Probationary,
    /// Operator-vouched.
    Trusted,
    /// Staff (operator's own role).
    Staff,
    /// Admin (full authority).
    Admin,
}

/// Per-cohort policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohortPolicy {
    /// Cohort.
    pub cohort: Cohort,
    /// Min/max default trust band (0..=100).
    pub default_trust_band: (u8, u8),
    /// Grant TTL ceiling in seconds.
    pub grant_ttl_ceiling_seconds: u32,
    /// Highest RiskClass an Allow may carry.
    pub max_risk: RiskClass,
}

/// Taxonomy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohortTaxonomy {
    /// Schema version.
    pub schema_version: String,
    /// 5 policies.
    pub policies: Vec<CohortPolicy>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CohortError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 5.
    #[error("cohort count {0} != 5 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing cohort: {0:?}")]
    Missing(Cohort),
    /// Band inverted.
    #[error("cohort {cohort:?} band inverted: min {min} > max {max}")]
    BandInverted {
        /// cohort.
        cohort: Cohort,
        /// min.
        min: u8,
        /// max.
        max: u8,
    },
    /// Band out of range.
    #[error("cohort {cohort:?} band out of 0..=100: ({min}, {max})")]
    BandOutOfRange {
        /// cohort.
        cohort: Cohort,
        /// min.
        min: u8,
        /// max.
        max: u8,
    },
    /// Illegal promotion direction.
    #[error("illegal promotion: {from:?} -> {to:?}")]
    IllegalPromotion {
        /// from.
        from: Cohort,
        /// to.
        to: Cohort,
    },
}

const REQUIRED: [Cohort; 5] = [
    Cohort::Newcomer, Cohort::Probationary, Cohort::Trusted, Cohort::Staff, Cohort::Admin,
];

impl CohortTaxonomy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let policies = vec![
            CohortPolicy {
                cohort: Cohort::Newcomer,
                default_trust_band: (0, 20),
                grant_ttl_ceiling_seconds: 60,
                max_risk: RiskClass::Low,
            },
            CohortPolicy {
                cohort: Cohort::Probationary,
                default_trust_band: (20, 50),
                grant_ttl_ceiling_seconds: 600,
                max_risk: RiskClass::Medium,
            },
            CohortPolicy {
                cohort: Cohort::Trusted,
                default_trust_band: (50, 80),
                grant_ttl_ceiling_seconds: 3_600,
                max_risk: RiskClass::High,
            },
            CohortPolicy {
                cohort: Cohort::Staff,
                default_trust_band: (70, 95),
                grant_ttl_ceiling_seconds: 14_400,
                max_risk: RiskClass::High,
            },
            CohortPolicy {
                cohort: Cohort::Admin,
                default_trust_band: (80, 100),
                grant_ttl_ceiling_seconds: 86_400,
                max_risk: RiskClass::Critical,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            policies,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CohortError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CohortError::SchemaMismatch);
        }
        if self.policies.len() != 5 {
            return Err(CohortError::CountInvalid(self.policies.len()));
        }
        for c in REQUIRED {
            if !self.policies.iter().any(|p| p.cohort == c) {
                return Err(CohortError::Missing(c));
            }
        }
        for p in &self.policies {
            let (min, max) = p.default_trust_band;
            if min > 100 || max > 100 {
                return Err(CohortError::BandOutOfRange { cohort: p.cohort, min, max });
            }
            if min > max {
                return Err(CohortError::BandInverted { cohort: p.cohort, min, max });
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, c: Cohort) -> Option<&CohortPolicy> {
        self.policies.iter().find(|p| p.cohort == c)
    }

    /// Promote a subject one tier; refuses if at Admin.
    pub fn promote(&self, current: Cohort) -> Result<Cohort, CohortError> {
        let next = match current {
            Cohort::Newcomer => Cohort::Probationary,
            Cohort::Probationary => Cohort::Trusted,
            Cohort::Trusted => Cohort::Staff,
            Cohort::Staff => Cohort::Admin,
            Cohort::Admin => return Err(CohortError::IllegalPromotion { from: current, to: current }),
        };
        Ok(next)
    }

    /// Whether the cohort permits an Allow at the given RiskClass.
    pub fn permits_risk(&self, cohort: Cohort, risk: RiskClass) -> bool {
        match self.get(cohort) {
            Some(p) => risk <= p.max_risk,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        CohortTaxonomy::canonical().validate().unwrap();
    }

    #[test]
    fn five_cohorts_present() {
        let t = CohortTaxonomy::canonical();
        for c in REQUIRED {
            assert!(t.get(c).is_some(), "missing {c:?}");
        }
    }

    #[test]
    fn promote_walks_up() {
        let t = CohortTaxonomy::canonical();
        assert_eq!(t.promote(Cohort::Newcomer).unwrap(), Cohort::Probationary);
        assert_eq!(t.promote(Cohort::Probationary).unwrap(), Cohort::Trusted);
        assert_eq!(t.promote(Cohort::Trusted).unwrap(), Cohort::Staff);
        assert_eq!(t.promote(Cohort::Staff).unwrap(), Cohort::Admin);
    }

    #[test]
    fn admin_cannot_promote() {
        let t = CohortTaxonomy::canonical();
        assert!(matches!(t.promote(Cohort::Admin).unwrap_err(), CohortError::IllegalPromotion { .. }));
    }

    #[test]
    fn permits_risk_increases_with_cohort() {
        let t = CohortTaxonomy::canonical();
        // Newcomer max Low → Medium/High refused
        assert!(t.permits_risk(Cohort::Newcomer, RiskClass::Low));
        assert!(!t.permits_risk(Cohort::Newcomer, RiskClass::Medium));
        // Probationary max Medium
        assert!(t.permits_risk(Cohort::Probationary, RiskClass::Medium));
        assert!(!t.permits_risk(Cohort::Probationary, RiskClass::High));
        // Trusted max High
        assert!(t.permits_risk(Cohort::Trusted, RiskClass::High));
        assert!(!t.permits_risk(Cohort::Trusted, RiskClass::Critical));
        // Admin permits Critical
        assert!(t.permits_risk(Cohort::Admin, RiskClass::Critical));
    }

    #[test]
    fn cohort_ordering() {
        assert!(Cohort::Newcomer < Cohort::Probationary);
        assert!(Cohort::Probationary < Cohort::Trusted);
        assert!(Cohort::Trusted < Cohort::Staff);
        assert!(Cohort::Staff < Cohort::Admin);
    }

    #[test]
    fn band_inverted_caught() {
        let mut t = CohortTaxonomy::canonical();
        t.policies[0].default_trust_band = (60, 20); // inverted
        assert!(matches!(t.validate().unwrap_err(), CohortError::BandInverted { .. }));
    }

    #[test]
    fn band_out_of_range_caught() {
        let mut t = CohortTaxonomy::canonical();
        t.policies[0].default_trust_band = (0, 200);
        assert!(matches!(t.validate().unwrap_err(), CohortError::BandOutOfRange { .. }));
    }

    #[test]
    fn ttl_ceiling_climbs_with_cohort() {
        let t = CohortTaxonomy::canonical();
        let n = t.get(Cohort::Newcomer).unwrap().grant_ttl_ceiling_seconds;
        let s = t.get(Cohort::Staff).unwrap().grant_ttl_ceiling_seconds;
        let a = t.get(Cohort::Admin).unwrap().grant_ttl_ceiling_seconds;
        assert!(n < s && s < a);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = CohortTaxonomy::canonical();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), CohortError::SchemaMismatch));
    }

    #[test]
    fn count_invalid_caught() {
        let mut t = CohortTaxonomy::canonical();
        t.policies.pop();
        assert!(matches!(t.validate().unwrap_err(), CohortError::CountInvalid(4)));
    }

    #[test]
    fn cohort_serde_kebab() {
        assert_eq!(serde_json::to_string(&Cohort::Newcomer).unwrap(), "\"newcomer\"");
        assert_eq!(serde_json::to_string(&Cohort::Probationary).unwrap(), "\"probationary\"");
        assert_eq!(serde_json::to_string(&Cohort::Admin).unwrap(), "\"admin\"");
    }

    #[test]
    fn taxonomy_serde_roundtrip() {
        let t = CohortTaxonomy::canonical();
        let j = serde_json::to_string(&t).unwrap();
        let back: CohortTaxonomy = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
