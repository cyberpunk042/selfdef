//! `selfdef-audit-summary-digest` — hourly rollup digest.
//!
//! Aggregates `PolicyDecision` counts per hour into outcome counts +
//! top-N actors + top-N action verbs. Top-N uses count-then-name.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, PolicyDecision};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Top-N depth.
pub const TOP_N: usize = 3;

/// One labeled count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LabeledCount {
    /// Label.
    pub label: String,
    /// Count.
    pub count: u64,
}

/// Digest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSummaryDigest {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC window start.
    pub window_start: String,
    /// ISO-8601 UTC window end (window_end > window_start).
    pub window_end: String,
    /// Allow count.
    pub allow: u64,
    /// Deny count.
    pub deny: u64,
    /// Ask count.
    pub ask: u64,
    /// Sandbox count.
    pub sandbox: u64,
    /// Top-3 actor fingerprints.
    pub top_actors: Vec<LabeledCount>,
    /// Top-3 action verbs.
    pub top_actions: Vec<LabeledCount>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DigestError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty timestamp.
    #[error("missing timestamp: {0}")]
    MissingTimestamp(&'static str),
    /// window_end <= window_start.
    #[error("window_end {end} <= window_start {start}")]
    BadWindow {
        /// start.
        start: String,
        /// end.
        end: String,
    },
}

fn top_n(counts: HashMap<String, u64>) -> Vec<LabeledCount> {
    let mut v: Vec<LabeledCount> = counts.into_iter()
        .map(|(label, count)| LabeledCount { label, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.label.cmp(&b.label)));
    v.truncate(TOP_N);
    v
}

impl AuditSummaryDigest {
    /// Build a digest from a slice of decisions over a window.
    pub fn build(window_start: &str, window_end: &str, decisions: &[PolicyDecision]) -> Self {
        let mut allow = 0u64;
        let mut deny = 0u64;
        let mut ask = 0u64;
        let mut sandbox = 0u64;
        let mut actor_counts: HashMap<String, u64> = HashMap::new();
        let mut action_counts: HashMap<String, u64> = HashMap::new();
        for d in decisions {
            match d.outcome {
                Outcome::Allow => allow += 1,
                Outcome::Deny => deny += 1,
                Outcome::Ask => ask += 1,
                Outcome::Sandbox => sandbox += 1,
            }
            *actor_counts.entry(d.subject.clone()).or_insert(0) += 1;
            *action_counts.entry(d.action.clone()).or_insert(0) += 1;
        }
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_start: window_start.into(),
            window_end: window_end.into(),
            allow, deny, ask, sandbox,
            top_actors: top_n(actor_counts),
            top_actions: top_n(action_counts),
        }
    }

    /// Total decisions in the window.
    pub fn total(&self) -> u64 {
        self.allow + self.deny + self.ask + self.sandbox
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DigestError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DigestError::SchemaMismatch);
        }
        if self.window_start.is_empty() { return Err(DigestError::MissingTimestamp("window_start")); }
        if self.window_end.is_empty() { return Err(DigestError::MissingTimestamp("window_end")); }
        if self.window_end <= self.window_start {
            return Err(DigestError::BadWindow {
                start: self.window_start.clone(),
                end: self.window_end.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, RiskClass, SideEffectClass, UserApprovalState};

    fn d(subject: &str, action: &str, outcome: Outcome) -> PolicyDecision {
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: subject.into(),
            action: action.into(),
            resource: "/x".into(),
            intent: "ship".into(),
            profile: "careful".into(),
            risk: RiskClass::Low,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: SideEffectClass::ReadOnly,
            user_approval: UserApprovalState::NotRequired,
            outcome,
            reason: "ok".into(),
            trace_id: "tr".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn empty_digest_validates() {
        let g = AuditSummaryDigest::build("2026-05-19T03:00:00Z", "2026-05-19T04:00:00Z", &[]);
        g.validate().unwrap();
        assert_eq!(g.total(), 0);
    }

    #[test]
    fn outcome_counts_partition() {
        let v = vec![
            d("a", "x", Outcome::Allow),
            d("a", "x", Outcome::Allow),
            d("b", "y", Outcome::Deny),
            d("c", "z", Outcome::Ask),
            d("d", "x", Outcome::Sandbox),
        ];
        let g = AuditSummaryDigest::build("a", "b", &v);
        assert_eq!(g.allow, 2);
        assert_eq!(g.deny, 1);
        assert_eq!(g.ask, 1);
        assert_eq!(g.sandbox, 1);
        assert_eq!(g.total(), 5);
    }

    #[test]
    fn top_actors_sorted_by_count() {
        let v = vec![
            d("alice", "x", Outcome::Allow),
            d("alice", "x", Outcome::Allow),
            d("alice", "x", Outcome::Allow),
            d("bob", "x", Outcome::Allow),
            d("carol", "x", Outcome::Allow),
        ];
        let g = AuditSummaryDigest::build("a", "b", &v);
        assert_eq!(g.top_actors[0].label, "alice");
        assert_eq!(g.top_actors[0].count, 3);
    }

    #[test]
    fn top_actors_capped_at_three() {
        let v: Vec<PolicyDecision> = (0..10).map(|i| d(&format!("u{i}"), "x", Outcome::Allow)).collect();
        let g = AuditSummaryDigest::build("a", "b", &v);
        assert_eq!(g.top_actors.len(), 3);
    }

    #[test]
    fn top_actions_sorted_by_count() {
        let v = vec![
            d("x", "fs.read", Outcome::Allow),
            d("x", "fs.read", Outcome::Allow),
            d("x", "fs.write", Outcome::Allow),
        ];
        let g = AuditSummaryDigest::build("a", "b", &v);
        assert_eq!(g.top_actions[0].label, "fs.read");
        assert_eq!(g.top_actions[0].count, 2);
    }

    #[test]
    fn bad_window_caught() {
        let g = AuditSummaryDigest::build("2026-05-19T04:00:00Z", "2026-05-19T03:00:00Z", &[]);
        assert!(matches!(g.validate().unwrap_err(), DigestError::BadWindow { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = AuditSummaryDigest::build("a", "b", &[]);
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), DigestError::SchemaMismatch));
    }

    #[test]
    fn digest_serde_roundtrip() {
        let g = AuditSummaryDigest::build("2026-05-19T03:00:00Z", "2026-05-19T04:00:00Z",
            &[d("alice", "fs.read", Outcome::Allow)]);
        let j = serde_json::to_string(&g).unwrap();
        let back: AuditSummaryDigest = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
