//! `selfdef-policy-conflict-detector` — scan decisions for inconsistencies.
//!
//! 3 conflict classes:
//! - `TraceIdSplit`: two decisions share trace_id but differ in outcome.
//! - `OutcomeFlip`: same (subject, action) Allow then Deny (or vice
//!   versa) within the supplied vec window.
//! - `RiskSideEffectMismatch`: side-effect Persistent / Process with
//!   risk Negligible — sniff for under-classification.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, PolicyDecision, RiskClass, SideEffectClass};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Conflict class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictClass {
    /// Same trace_id, different outcomes.
    TraceIdSplit,
    /// (subject, action) flipped between Allow and Deny.
    OutcomeFlip,
    /// Risk class doesn't match side-effect severity.
    RiskSideEffectMismatch,
}

/// One detected conflict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conflict {
    /// Class.
    pub class: ConflictClass,
    /// Relevant trace_id (or pair).
    pub trace_id: String,
    /// Operator-readable summary.
    pub summary: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Scan a slice of decisions for conflicts.
pub fn scan(decisions: &[PolicyDecision]) -> Vec<Conflict> {
    let mut conflicts = Vec::new();
    let mut by_trace: HashMap<&str, Outcome> = HashMap::new();
    for d in decisions {
        // TraceIdSplit
        match by_trace.get(d.trace_id.as_str()) {
            Some(prev) if *prev != d.outcome => {
                conflicts.push(Conflict {
                    class: ConflictClass::TraceIdSplit,
                    trace_id: d.trace_id.clone(),
                    summary: format!("trace_id {} has {prev:?} then {:?}", d.trace_id, d.outcome),
                });
            }
            None => {
                by_trace.insert(d.trace_id.as_str(), d.outcome);
            }
            _ => {}
        }
        // RiskSideEffectMismatch
        if d.risk == RiskClass::Negligible
            && matches!(
                d.side_effect_class,
                SideEffectClass::Persistent | SideEffectClass::Process
            )
        {
            conflicts.push(Conflict {
                class: ConflictClass::RiskSideEffectMismatch,
                trace_id: d.trace_id.clone(),
                summary: format!(
                    "risk Negligible with side-effect {:?} — under-classified",
                    d.side_effect_class
                ),
            });
        }
    }
    // OutcomeFlip: walk pairs of (subject, action).
    let mut last: HashMap<(String, String), Outcome> = HashMap::new();
    for d in decisions {
        let k = (d.subject.clone(), d.action.clone());
        if let Some(prev) = last.get(&k) {
            let prev = *prev;
            let now = d.outcome;
            let flipped = matches!(
                (prev, now),
                (Outcome::Allow, Outcome::Deny) | (Outcome::Deny, Outcome::Allow)
            );
            if flipped {
                conflicts.push(Conflict {
                    class: ConflictClass::OutcomeFlip,
                    trace_id: d.trace_id.clone(),
                    summary: format!(
                        "subject {} action {}: outcome flipped {prev:?} -> {now:?}",
                        d.subject, d.action
                    ),
                });
            }
        }
        last.insert(k, d.outcome);
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, UserApprovalState};

    fn d(
        subject: &str,
        action: &str,
        outcome: Outcome,
        sec: SideEffectClass,
        risk: RiskClass,
        trace: &str,
    ) -> PolicyDecision {
        let approval = if outcome == Outcome::Allow
            && (sec == SideEffectClass::Persistent || risk == RiskClass::Critical)
        {
            UserApprovalState::Approved
        } else {
            UserApprovalState::NotRequired
        };
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: subject.into(),
            action: action.into(),
            resource: "/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: sec,
            user_approval: approval,
            outcome,
            reason: "ok".into(),
            trace_id: trace.into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn no_conflicts_in_clean_run() {
        let v = vec![
            d(
                "alice",
                "fs.read",
                Outcome::Allow,
                SideEffectClass::ReadOnly,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "alice",
                "fs.read",
                Outcome::Allow,
                SideEffectClass::ReadOnly,
                RiskClass::Low,
                "tr-2",
            ),
        ];
        assert!(scan(&v).is_empty());
    }

    #[test]
    fn trace_id_split_detected() {
        let v = vec![
            d(
                "alice",
                "fs.read",
                Outcome::Allow,
                SideEffectClass::ReadOnly,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "alice",
                "fs.read",
                Outcome::Deny,
                SideEffectClass::ReadOnly,
                RiskClass::Low,
                "tr-1",
            ),
        ];
        let c = scan(&v);
        assert!(c.iter().any(|x| x.class == ConflictClass::TraceIdSplit));
    }

    #[test]
    fn outcome_flip_detected() {
        let v = vec![
            d(
                "alice",
                "fs.write",
                Outcome::Allow,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "alice",
                "fs.write",
                Outcome::Deny,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-2",
            ),
        ];
        let c = scan(&v);
        assert!(c.iter().any(|x| x.class == ConflictClass::OutcomeFlip));
    }

    #[test]
    fn risk_underclassification_detected() {
        let v = vec![d(
            "alice",
            "proc.spawn",
            Outcome::Allow,
            SideEffectClass::Process,
            RiskClass::Negligible,
            "tr-1",
        )];
        let c = scan(&v);
        assert!(
            c.iter()
                .any(|x| x.class == ConflictClass::RiskSideEffectMismatch)
        );
    }

    #[test]
    fn allow_to_ask_not_a_flip() {
        let v = vec![
            d(
                "alice",
                "fs.write",
                Outcome::Allow,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "alice",
                "fs.write",
                Outcome::Ask,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-2",
            ),
        ];
        let c = scan(&v);
        assert!(c.iter().all(|x| x.class != ConflictClass::OutcomeFlip));
    }

    #[test]
    fn distinct_subjects_no_flip() {
        let v = vec![
            d(
                "alice",
                "fs.write",
                Outcome::Allow,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "bob",
                "fs.write",
                Outcome::Deny,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-2",
            ),
        ];
        let c = scan(&v);
        assert!(c.iter().all(|x| x.class != ConflictClass::OutcomeFlip));
    }

    #[test]
    fn three_conflicts_in_one_scan() {
        let v = vec![
            d(
                "alice",
                "fs.write",
                Outcome::Allow,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-1",
            ),
            d(
                "alice",
                "fs.write",
                Outcome::Deny,
                SideEffectClass::FsWrite,
                RiskClass::Low,
                "tr-1",
            ), // split + flip
            d(
                "alice",
                "proc.spawn",
                Outcome::Allow,
                SideEffectClass::Process,
                RiskClass::Negligible,
                "tr-2",
            ), // mismatch
        ];
        let c = scan(&v);
        let classes: Vec<_> = c.iter().map(|x| x.class).collect();
        assert!(classes.contains(&ConflictClass::TraceIdSplit));
        assert!(classes.contains(&ConflictClass::OutcomeFlip));
        assert!(classes.contains(&ConflictClass::RiskSideEffectMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ConflictClass::TraceIdSplit).unwrap(),
            "\"trace-id-split\""
        );
        assert_eq!(
            serde_json::to_string(&ConflictClass::OutcomeFlip).unwrap(),
            "\"outcome-flip\""
        );
        assert_eq!(
            serde_json::to_string(&ConflictClass::RiskSideEffectMismatch).unwrap(),
            "\"risk-side-effect-mismatch\""
        );
    }

    #[test]
    fn conflict_serde_roundtrip() {
        let c = Conflict {
            class: ConflictClass::TraceIdSplit,
            trace_id: "tr-1".into(),
            summary: "x".into(),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: Conflict = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
