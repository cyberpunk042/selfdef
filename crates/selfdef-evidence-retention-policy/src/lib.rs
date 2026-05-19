//! `selfdef-evidence-retention-policy` — per-class retention authority.
//!
//! Each EvidenceClass has a `days_to_keep`. Items older than that
//! are sweep candidates UNLESS the class is in `never_delete`,
//! which short-circuits to "always kept".
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Evidence class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceClass {
    /// IPS audit entries.
    Audit,
    /// Distributed-trace spans.
    Trace,
    /// Policy decisions.
    Decision,
    /// Anomaly observations.
    Anomaly,
    /// Canary-tripwire firings.
    CanaryTrip,
    /// Operator actions.
    Operator,
}

/// One evidence item (for sweep candidate filtering).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceItem {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: EvidenceClass,
    /// Age in whole days.
    pub age_days: u32,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRetentionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Audit retention (days).
    pub audit_days: u32,
    /// Trace retention.
    pub trace_days: u32,
    /// Decision retention.
    pub decision_days: u32,
    /// Anomaly retention.
    pub anomaly_days: u32,
    /// Canary-trip retention.
    pub canary_trip_days: u32,
    /// Operator-action retention.
    pub operator_days: u32,
    /// Classes that are never deleted (overrides days_to_keep).
    pub never_delete: Vec<EvidenceClass>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RetentionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Per-class days zero.
    #[error("class {0:?} days_to_keep zero")]
    DaysZero(EvidenceClass),
}

impl EvidenceRetentionPolicy {
    /// Canonical defaults:
    /// Audit 365, Trace 30, Decision 180, Anomaly 90, CanaryTrip 365,
    /// Operator 365; never_delete = [CanaryTrip, Operator].
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            audit_days: 365,
            trace_days: 30,
            decision_days: 180,
            anomaly_days: 90,
            canary_trip_days: 365,
            operator_days: 365,
            never_delete: vec![EvidenceClass::CanaryTrip, EvidenceClass::Operator],
        }
    }

    /// Days for a class.
    pub fn days_for(&self, c: EvidenceClass) -> u32 {
        match c {
            EvidenceClass::Audit => self.audit_days,
            EvidenceClass::Trace => self.trace_days,
            EvidenceClass::Decision => self.decision_days,
            EvidenceClass::Anomaly => self.anomaly_days,
            EvidenceClass::CanaryTrip => self.canary_trip_days,
            EvidenceClass::Operator => self.operator_days,
        }
    }

    /// Should this item be swept?
    pub fn is_expired(&self, c: EvidenceClass, age_days: u32) -> bool {
        if self.never_delete.contains(&c) { return false; }
        age_days > self.days_for(c)
    }

    /// Filter sweep candidates.
    pub fn sweep_candidates<'a>(&self, items: &'a [EvidenceItem]) -> Vec<&'a EvidenceItem> {
        items.iter().filter(|i| self.is_expired(i.class, i.age_days)).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RetentionError::SchemaMismatch);
        }
        for (c, d) in [
            (EvidenceClass::Audit, self.audit_days),
            (EvidenceClass::Trace, self.trace_days),
            (EvidenceClass::Decision, self.decision_days),
            (EvidenceClass::Anomaly, self.anomaly_days),
            (EvidenceClass::CanaryTrip, self.canary_trip_days),
            (EvidenceClass::Operator, self.operator_days),
        ] {
            if d == 0 {
                return Err(RetentionError::DaysZero(c));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, c: EvidenceClass, age: u32) -> EvidenceItem {
        EvidenceItem { id: id.into(), class: c, age_days: age }
    }

    #[test]
    fn canonical_validates() {
        EvidenceRetentionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn under_retention_kept() {
        let p = EvidenceRetentionPolicy::canonical();
        assert!(!p.is_expired(EvidenceClass::Audit, 200));
        assert!(!p.is_expired(EvidenceClass::Trace, 5));
    }

    #[test]
    fn over_retention_expired() {
        let p = EvidenceRetentionPolicy::canonical();
        assert!(p.is_expired(EvidenceClass::Audit, 400));
        assert!(p.is_expired(EvidenceClass::Trace, 31));
    }

    #[test]
    fn never_delete_kept_forever() {
        let p = EvidenceRetentionPolicy::canonical();
        assert!(!p.is_expired(EvidenceClass::CanaryTrip, 10_000));
        assert!(!p.is_expired(EvidenceClass::Operator, 10_000));
    }

    #[test]
    fn sweep_candidates_filtered() {
        let p = EvidenceRetentionPolicy::canonical();
        let items = vec![
            item("a", EvidenceClass::Audit, 400),    // expired
            item("b", EvidenceClass::Trace, 5),      // kept
            item("c", EvidenceClass::CanaryTrip, 9999), // never_delete
            item("d", EvidenceClass::Decision, 200), // expired
        ];
        let cands = p.sweep_candidates(&items);
        let ids: Vec<&str> = cands.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"d"));
        assert!(!ids.contains(&"b"));
        assert!(!ids.contains(&"c"));
    }

    #[test]
    fn days_zero_rejected() {
        let mut p = EvidenceRetentionPolicy::canonical();
        p.audit_days = 0;
        assert!(matches!(p.validate().unwrap_err(), RetentionError::DaysZero(EvidenceClass::Audit)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = EvidenceRetentionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), RetentionError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&EvidenceClass::CanaryTrip).unwrap(), "\"canary-trip\"");
    }

    #[test]
    fn boundary_equal_age_kept() {
        // age == retention -> kept (only > is expired).
        let p = EvidenceRetentionPolicy::canonical();
        assert!(!p.is_expired(EvidenceClass::Audit, 365));
        assert!(p.is_expired(EvidenceClass::Audit, 366));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = EvidenceRetentionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: EvidenceRetentionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
