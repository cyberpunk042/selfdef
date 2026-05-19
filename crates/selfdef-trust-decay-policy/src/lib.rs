//! `selfdef-trust-decay-policy` — per-cohort trust time-decay.
//!
//! Each cohort declares (half_life_days, floor_score). A subject's
//! trust score halves toward the floor every half_life_days of
//! inactivity.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_subject_cohort::Cohort;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-cohort decay record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecayRule {
    /// Cohort.
    pub cohort: Cohort,
    /// Half-life days.
    pub half_life_days: u32,
    /// Floor score (decay never goes below).
    pub floor_score: u8,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustDecayPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 5 rules.
    pub rules: Vec<DecayRule>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DecayError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 5.
    #[error("rule count {0} != 5 canonical")]
    CountInvalid(usize),
    /// Missing cohort.
    #[error("missing cohort: {0:?}")]
    Missing(Cohort),
    /// Zero half-life.
    #[error("cohort {0:?} half_life_days zero")]
    ZeroHalfLife(Cohort),
    /// Floor > 100.
    #[error("cohort {0:?} floor_score > 100")]
    FloorOutOfRange(Cohort),
    /// Current score > 100.
    #[error("current score {0} > 100")]
    ScoreOutOfRange(u8),
}

const REQUIRED: [Cohort; 5] = [
    Cohort::Newcomer, Cohort::Probationary, Cohort::Trusted, Cohort::Staff, Cohort::Admin,
];

impl TrustDecayPolicy {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let rules = vec![
            DecayRule { cohort: Cohort::Newcomer,     half_life_days: 7,   floor_score: 0  },
            DecayRule { cohort: Cohort::Probationary, half_life_days: 14,  floor_score: 20 },
            DecayRule { cohort: Cohort::Trusted,      half_life_days: 30,  floor_score: 50 },
            DecayRule { cohort: Cohort::Staff,        half_life_days: 60,  floor_score: 70 },
            DecayRule { cohort: Cohort::Admin,        half_life_days: 180, floor_score: 80 },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rules,
        }
    }

    /// Lookup.
    pub fn get(&self, cohort: Cohort) -> Option<&DecayRule> {
        self.rules.iter().find(|r| r.cohort == cohort)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DecayError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DecayError::SchemaMismatch);
        }
        if self.rules.len() != 5 {
            return Err(DecayError::CountInvalid(self.rules.len()));
        }
        for c in REQUIRED {
            if !self.rules.iter().any(|r| r.cohort == c) {
                return Err(DecayError::Missing(c));
            }
        }
        for r in &self.rules {
            if r.half_life_days == 0 { return Err(DecayError::ZeroHalfLife(r.cohort)); }
            if r.floor_score > 100 { return Err(DecayError::FloorOutOfRange(r.cohort)); }
        }
        Ok(())
    }

    /// Apply decay: returns the new score after `elapsed_days` days
    /// of inactivity. Score halves toward floor every half_life_days.
    pub fn apply_decay(&self, cohort: Cohort, current_score: u8, elapsed_days: u32) -> Result<u8, DecayError> {
        if current_score > 100 { return Err(DecayError::ScoreOutOfRange(current_score)); }
        let rule = self.get(cohort).ok_or(DecayError::Missing(cohort))?;
        if elapsed_days == 0 { return Ok(current_score); }
        if current_score <= rule.floor_score { return Ok(current_score); }
        let above_floor = (current_score - rule.floor_score) as f32;
        let half_lives = elapsed_days as f32 / rule.half_life_days as f32;
        let factor = (0.5f32).powf(half_lives);
        let decayed = rule.floor_score as f32 + above_floor * factor;
        Ok(decayed.round().max(rule.floor_score as f32) as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        TrustDecayPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn no_decay_at_zero_elapsed() {
        let p = TrustDecayPolicy::canonical();
        assert_eq!(p.apply_decay(Cohort::Trusted, 80, 0).unwrap(), 80);
    }

    #[test]
    fn one_half_life_halves_toward_floor() {
        let p = TrustDecayPolicy::canonical();
        // Trusted: half_life=30, floor=50. Start 80 (30 above floor).
        // After 30 days → 30/2 + 50 = 65.
        let r = p.apply_decay(Cohort::Trusted, 80, 30).unwrap();
        assert_eq!(r, 65);
    }

    #[test]
    fn never_below_floor() {
        let p = TrustDecayPolicy::canonical();
        let r = p.apply_decay(Cohort::Trusted, 80, 10_000).unwrap();
        assert_eq!(r, 50);
    }

    #[test]
    fn at_floor_stays_at_floor() {
        let p = TrustDecayPolicy::canonical();
        let r = p.apply_decay(Cohort::Trusted, 50, 100).unwrap();
        assert_eq!(r, 50);
    }

    #[test]
    fn admin_has_long_half_life() {
        let p = TrustDecayPolicy::canonical();
        assert_eq!(p.get(Cohort::Admin).unwrap().half_life_days, 180);
    }

    #[test]
    fn newcomer_floor_zero() {
        let p = TrustDecayPolicy::canonical();
        assert_eq!(p.get(Cohort::Newcomer).unwrap().floor_score, 0);
    }

    #[test]
    fn score_out_of_range_caught() {
        let p = TrustDecayPolicy::canonical();
        assert!(matches!(p.apply_decay(Cohort::Trusted, 150, 1).unwrap_err(),
            DecayError::ScoreOutOfRange(150)));
    }

    #[test]
    fn zero_half_life_caught() {
        let mut p = TrustDecayPolicy::canonical();
        p.rules[0].half_life_days = 0;
        assert!(matches!(p.validate().unwrap_err(), DecayError::ZeroHalfLife(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TrustDecayPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), DecayError::SchemaMismatch));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = TrustDecayPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: TrustDecayPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
