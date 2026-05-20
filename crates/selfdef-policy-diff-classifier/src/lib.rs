//! `selfdef-policy-diff-classifier` — label a policy diff.
//!
//! `classify(before, after)` walks counts in the supplied
//! `DiffSummary` (caller already extracted the structural deltas)
//! and returns:
//!   * `effects` — every kind that fired, in canonical order.
//!   * `worst` — single highest-risk kind, used as headline label.
//!
//! Risk order (descending): NewDeny < RemovesDeny < TightensCap <
//! LoosensCap < RemovesAllow < NewAllow < SchemaBump < Neutral.
//! Lower = higher risk. (Yes — adding a deny is *safer* than removing
//! a deny in a defensive default-deny stance.)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Caller-supplied diff summary (post-extraction).
#[derive(Debug, Clone, Default, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffSummary {
    /// Number of new deny rules.
    pub new_deny_count: u32,
    /// Number of removed deny rules.
    pub removed_deny_count: u32,
    /// Number of new allow rules.
    pub new_allow_count: u32,
    /// Number of removed allow rules.
    pub removed_allow_count: u32,
    /// Number of cap thresholds that got stricter.
    pub tightens_cap_count: u32,
    /// Number of cap thresholds that got laxer.
    pub loosens_cap_count: u32,
    /// True if schema_version changed.
    pub schema_bump: bool,
}

/// One effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    /// Added a deny — *safer*.
    NewDeny,
    /// Removed a deny — risk-up.
    RemovesDeny,
    /// Tightened a cap — *safer*.
    TightensCap,
    /// Loosened a cap — risk-up.
    LoosensCap,
    /// Removed an allow — *safer*.
    RemovesAllow,
    /// Added an allow — risk-up.
    NewAllow,
    /// Schema-version bump.
    SchemaBump,
    /// No structural change.
    Neutral,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDiffClassifier {
    /// Schema version.
    pub schema_version: String,
}

/// Classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Classification {
    /// Every effect that fired.
    pub effects: Vec<EffectKind>,
    /// Worst (highest-risk).
    pub worst: EffectKind,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DiffError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

fn risk_rank(k: EffectKind) -> u8 {
    // Higher number = riskier.
    match k {
        EffectKind::NewAllow => 6,
        EffectKind::LoosensCap => 5,
        EffectKind::RemovesDeny => 4,
        EffectKind::SchemaBump => 3,
        EffectKind::RemovesAllow => 2,
        EffectKind::TightensCap => 1,
        EffectKind::NewDeny => 1,
        EffectKind::Neutral => 0,
    }
}

impl PolicyDiffClassifier {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into() }
    }

    /// Classify.
    pub fn classify(&self, s: &DiffSummary) -> Classification {
        let mut effects = Vec::new();
        if s.new_deny_count > 0 { effects.push(EffectKind::NewDeny); }
        if s.removed_deny_count > 0 { effects.push(EffectKind::RemovesDeny); }
        if s.new_allow_count > 0 { effects.push(EffectKind::NewAllow); }
        if s.removed_allow_count > 0 { effects.push(EffectKind::RemovesAllow); }
        if s.tightens_cap_count > 0 { effects.push(EffectKind::TightensCap); }
        if s.loosens_cap_count > 0 { effects.push(EffectKind::LoosensCap); }
        if s.schema_bump { effects.push(EffectKind::SchemaBump); }
        if effects.is_empty() { effects.push(EffectKind::Neutral); }
        let worst = effects.iter()
            .copied()
            .max_by_key(|k| risk_rank(*k))
            .unwrap_or(EffectKind::Neutral);
        Classification { effects, worst }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DiffError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DiffError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for PolicyDiffClassifier {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_neutral() {
        let c = PolicyDiffClassifier::new();
        let v = c.classify(&DiffSummary::default());
        assert_eq!(v.worst, EffectKind::Neutral);
        assert_eq!(v.effects, vec![EffectKind::Neutral]);
    }

    #[test]
    fn add_allow_is_riskiest() {
        let c = PolicyDiffClassifier::new();
        let s = DiffSummary {
            new_allow_count: 1, tightens_cap_count: 1,
            ..Default::default()
        };
        let v = c.classify(&s);
        assert_eq!(v.worst, EffectKind::NewAllow);
    }

    #[test]
    fn loosens_cap_outranks_removes_allow() {
        let c = PolicyDiffClassifier::new();
        let s = DiffSummary {
            removed_allow_count: 1, loosens_cap_count: 1,
            ..Default::default()
        };
        let v = c.classify(&s);
        assert_eq!(v.worst, EffectKind::LoosensCap);
    }

    #[test]
    fn removes_deny_outranks_schema_bump() {
        let c = PolicyDiffClassifier::new();
        let s = DiffSummary {
            removed_deny_count: 1, schema_bump: true,
            ..Default::default()
        };
        let v = c.classify(&s);
        assert_eq!(v.worst, EffectKind::RemovesDeny);
    }

    #[test]
    fn new_deny_safer_than_neutral_floor() {
        let c = PolicyDiffClassifier::new();
        let s = DiffSummary { new_deny_count: 1, ..Default::default() };
        let v = c.classify(&s);
        assert_eq!(v.worst, EffectKind::NewDeny);
    }

    #[test]
    fn multiple_effects_listed() {
        let c = PolicyDiffClassifier::new();
        let s = DiffSummary {
            new_deny_count: 1,
            new_allow_count: 1,
            tightens_cap_count: 1,
            schema_bump: true,
            ..Default::default()
        };
        let v = c.classify(&s);
        assert!(v.effects.contains(&EffectKind::NewDeny));
        assert!(v.effects.contains(&EffectKind::NewAllow));
        assert!(v.effects.contains(&EffectKind::TightensCap));
        assert!(v.effects.contains(&EffectKind::SchemaBump));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = PolicyDiffClassifier::new();
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), DiffError::SchemaMismatch));
    }

    #[test]
    fn classifier_serde_roundtrip() {
        let c = PolicyDiffClassifier::new();
        let j = serde_json::to_string(&c).unwrap();
        let back: PolicyDiffClassifier = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
