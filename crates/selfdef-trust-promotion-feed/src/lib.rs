//! `selfdef-trust-promotion-feed` — automatic promotion/demotion suggestions.
//!
//! Given per-subject input metrics (consecutive_allows, recent_denies,
//! anomaly_hits, current_cohort), proposes `Suggestion`s the operator
//! can rubber-stamp. Rules:
//!
//! - 20 consecutive Allow + 0 deny + 0 anomaly + not Admin → promote
//! - 5+ recent denies OR 3+ anomalies in window → demote (not below Newcomer)
//! - Otherwise → no suggestion
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_subject_cohort::{Cohort, CohortTaxonomy};
use selfdef_trust_promotion_event::{PromotionKind, PromotionReason};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-subject metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectMetrics {
    /// Subject id.
    pub subject: String,
    /// Consecutive Allow outcomes since last reset.
    pub consecutive_allows: u32,
    /// Recent deny count in window.
    pub recent_denies: u32,
    /// Recent anomaly hits in window.
    pub anomaly_hits: u32,
    /// Current cohort.
    pub current_cohort: Cohort,
}

/// One suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suggestion {
    /// Subject.
    pub subject: String,
    /// Direction.
    pub kind: PromotionKind,
    /// From cohort.
    pub from: Cohort,
    /// Suggested target cohort.
    pub to: Cohort,
    /// Reason classifier.
    pub reason: PromotionReason,
    /// Human-readable rationale.
    pub rationale: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FeedError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Generate a suggestion for one subject's metrics.
/// Returns `None` if no action recommended.
pub fn evaluate(metrics: &SubjectMetrics, taxonomy: &CohortTaxonomy) -> Option<Suggestion> {
    // Demotion path takes precedence.
    if metrics.recent_denies >= 5 || metrics.anomaly_hits >= 3 {
        let demoted = match metrics.current_cohort {
            Cohort::Admin => Cohort::Staff,
            Cohort::Staff => Cohort::Trusted,
            Cohort::Trusted => Cohort::Probationary,
            Cohort::Probationary => Cohort::Newcomer,
            Cohort::Newcomer => return None, // already at floor
        };
        let reason = if metrics.recent_denies >= 5 {
            PromotionReason::RepeatedDenies
        } else {
            PromotionReason::PostIncident
        };
        return Some(Suggestion {
            subject: metrics.subject.clone(),
            kind: PromotionKind::Demotion,
            from: metrics.current_cohort,
            to: demoted,
            reason,
            rationale: format!(
                "{} denies, {} anomalies (window)",
                metrics.recent_denies, metrics.anomaly_hits
            ),
        });
    }
    // Promotion path: 20 consecutive allow, 0 deny, 0 anomaly.
    if metrics.consecutive_allows >= 20
        && metrics.recent_denies == 0
        && metrics.anomaly_hits == 0
        && metrics.current_cohort != Cohort::Admin
    {
        let promoted = match taxonomy.promote(metrics.current_cohort).ok()? {
            x => x,
        };
        return Some(Suggestion {
            subject: metrics.subject.clone(),
            kind: PromotionKind::Promotion,
            from: metrics.current_cohort,
            to: promoted,
            reason: PromotionReason::Earned,
            rationale: format!(
                "{} consecutive allows, 0 denies, 0 anomalies",
                metrics.consecutive_allows
            ),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tax() -> CohortTaxonomy {
        CohortTaxonomy::canonical()
    }

    fn m(c: Cohort, allows: u32, denies: u32, anomalies: u32) -> SubjectMetrics {
        SubjectMetrics {
            subject: "alice".into(),
            current_cohort: c,
            consecutive_allows: allows,
            recent_denies: denies,
            anomaly_hits: anomalies,
        }
    }

    #[test]
    fn promote_after_20_clean_allows() {
        let s = evaluate(&m(Cohort::Newcomer, 25, 0, 0), &tax()).unwrap();
        assert_eq!(s.kind, PromotionKind::Promotion);
        assert_eq!(s.from, Cohort::Newcomer);
        assert_eq!(s.to, Cohort::Probationary);
        assert_eq!(s.reason, PromotionReason::Earned);
    }

    #[test]
    fn no_promote_below_20_allows() {
        assert!(evaluate(&m(Cohort::Newcomer, 19, 0, 0), &tax()).is_none());
    }

    #[test]
    fn no_promote_with_any_denies() {
        assert!(evaluate(&m(Cohort::Newcomer, 25, 1, 0), &tax()).is_none());
    }

    #[test]
    fn admin_cannot_promote() {
        assert!(evaluate(&m(Cohort::Admin, 100, 0, 0), &tax()).is_none());
    }

    #[test]
    fn demote_on_repeated_denies() {
        let s = evaluate(&m(Cohort::Trusted, 0, 7, 0), &tax()).unwrap();
        assert_eq!(s.kind, PromotionKind::Demotion);
        assert_eq!(s.to, Cohort::Probationary);
        assert_eq!(s.reason, PromotionReason::RepeatedDenies);
    }

    #[test]
    fn demote_on_anomalies() {
        let s = evaluate(&m(Cohort::Staff, 0, 0, 5), &tax()).unwrap();
        assert_eq!(s.kind, PromotionKind::Demotion);
        assert_eq!(s.to, Cohort::Trusted);
        assert_eq!(s.reason, PromotionReason::PostIncident);
    }

    #[test]
    fn newcomer_cannot_demote() {
        assert!(evaluate(&m(Cohort::Newcomer, 0, 10, 0), &tax()).is_none());
    }

    #[test]
    fn demotion_takes_precedence_over_promotion() {
        // 25 allows but also 7 denies → demote
        let s = evaluate(&m(Cohort::Trusted, 25, 7, 0), &tax()).unwrap();
        assert_eq!(s.kind, PromotionKind::Demotion);
    }

    #[test]
    fn no_change_when_quiet() {
        assert!(evaluate(&m(Cohort::Trusted, 5, 0, 0), &tax()).is_none());
    }

    #[test]
    fn suggestion_serde_roundtrip() {
        let s = evaluate(&m(Cohort::Newcomer, 25, 0, 0), &tax()).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: Suggestion = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
