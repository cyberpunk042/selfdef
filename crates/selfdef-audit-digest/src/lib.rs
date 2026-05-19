//! `selfdef-audit-digest` — rolling decision-counter digest.
//!
//! A `Digest` accumulates counts of `PolicyDecision`s along four axes:
//! - `outcomes`: per-Outcome counts (4 entries: allow/deny/ask/sandbox)
//! - `side_effects`: per-SideEffectClass counts (6 entries)
//! - `profiles`: per-profile-string counts (operator-defined)
//! - `risks`: per-RiskClass counts (5 entries)
//!
//! The daemon emits one digest at a fixed cadence (default 60s) and
//! resets the counters when the window rolls.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::{Outcome, PolicyDecision, RiskClass, SideEffectClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Digest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Digest {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC window start.
    pub window_start: String,
    /// ISO-8601 UTC window end.
    pub window_end: String,
    /// Per-outcome counts.
    pub outcomes: BTreeMap<String, u64>,
    /// Per-side-effect counts.
    pub side_effects: BTreeMap<String, u64>,
    /// Per-profile counts.
    pub profiles: BTreeMap<String, u64>,
    /// Per-risk-class counts.
    pub risks: BTreeMap<String, u64>,
    /// Total decisions recorded.
    pub total: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DigestError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty window_start.
    #[error("window_start missing")]
    MissingWindowStart,
    /// Empty window_end.
    #[error("window_end missing")]
    MissingWindowEnd,
    /// window_end < window_start.
    #[error("window_end {end} before window_start {start}")]
    WindowEndBeforeStart {
        /// start.
        start: String,
        /// end.
        end: String,
    },
    /// Sum of per-outcome counts != total.
    #[error("outcome sum {sum} != total {total}")]
    OutcomeSumMismatch {
        /// sum.
        sum: u64,
        /// total.
        total: u64,
    },
}

fn outcome_key(o: Outcome) -> &'static str {
    match o {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::Ask => "ask",
        Outcome::Sandbox => "sandbox",
    }
}

fn side_effect_key(s: SideEffectClass) -> &'static str {
    match s {
        SideEffectClass::None => "none",
        SideEffectClass::ReadOnly => "read-only",
        SideEffectClass::FsWrite => "fs-write",
        SideEffectClass::NetworkEgress => "network-egress",
        SideEffectClass::Process => "process",
        SideEffectClass::Persistent => "persistent",
    }
}

fn risk_key(r: RiskClass) -> &'static str {
    match r {
        RiskClass::Negligible => "negligible",
        RiskClass::Low => "low",
        RiskClass::Medium => "medium",
        RiskClass::High => "high",
        RiskClass::Critical => "critical",
    }
}

impl Digest {
    /// New empty digest over a window.
    pub fn new(window_start: &str, window_end: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_start: window_start.into(),
            window_end: window_end.into(),
            outcomes: BTreeMap::new(),
            side_effects: BTreeMap::new(),
            profiles: BTreeMap::new(),
            risks: BTreeMap::new(),
            total: 0,
        }
    }

    /// Record a decision into the digest.
    pub fn record(&mut self, decision: &PolicyDecision) {
        *self.outcomes.entry(outcome_key(decision.outcome).into()).or_insert(0) += 1;
        *self.side_effects.entry(side_effect_key(decision.side_effect_class).into()).or_insert(0) += 1;
        *self.profiles.entry(decision.profile.clone()).or_insert(0) += 1;
        *self.risks.entry(risk_key(decision.risk).into()).or_insert(0) += 1;
        self.total += 1;
    }

    /// Count by outcome key.
    pub fn outcome_count(&self, o: Outcome) -> u64 {
        *self.outcomes.get(outcome_key(o)).unwrap_or(&0)
    }

    /// Count by side-effect.
    pub fn side_effect_count(&self, s: SideEffectClass) -> u64 {
        *self.side_effects.get(side_effect_key(s)).unwrap_or(&0)
    }

    /// Count by profile.
    pub fn profile_count(&self, profile: &str) -> u64 {
        *self.profiles.get(profile).unwrap_or(&0)
    }

    /// Count by risk class.
    pub fn risk_count(&self, r: RiskClass) -> u64 {
        *self.risks.get(risk_key(r)).unwrap_or(&0)
    }

    /// Deny rate as basis points (out of 10_000) of the window; 0 if no decisions.
    pub fn deny_rate_bps(&self) -> u32 {
        if self.total == 0 { return 0; }
        let deny = self.outcome_count(Outcome::Deny);
        ((deny * 10_000) / self.total) as u32
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DigestError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DigestError::SchemaMismatch);
        }
        if self.window_start.is_empty() { return Err(DigestError::MissingWindowStart); }
        if self.window_end.is_empty() { return Err(DigestError::MissingWindowEnd); }
        if self.window_end < self.window_start {
            return Err(DigestError::WindowEndBeforeStart {
                start: self.window_start.clone(),
                end: self.window_end.clone(),
            });
        }
        let sum: u64 = self.outcomes.values().sum();
        if sum != self.total {
            return Err(DigestError::OutcomeSumMismatch { sum, total: self.total });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_policy_decision::{ContextSensitivity, UserApprovalState};

    fn d(outcome: Outcome, sec: SideEffectClass, risk: RiskClass, profile: &str) -> PolicyDecision {
        let user_approval = if outcome == Outcome::Allow
            && (sec == SideEffectClass::Persistent || risk == RiskClass::Critical)
        {
            UserApprovalState::Approved
        } else {
            UserApprovalState::NotRequired
        };
        PolicyDecision {
            schema_version: "1.0.0".into(),
            subject: "op".into(),
            action: "x".into(),
            resource: "/r".into(),
            intent: "ship".into(),
            profile: profile.into(),
            risk,
            model_provider: "local:rocm-3090".into(),
            context_sensitivity: ContextSensitivity::Internal,
            side_effect_class: sec,
            user_approval,
            outcome,
            reason: "ok".into(),
            trace_id: "tr".into(),
            signature: "ms003".into(),
        }
    }

    #[test]
    fn empty_digest_validates() {
        Digest::new("2026-05-19T03:00:00Z", "2026-05-19T03:01:00Z").validate().unwrap();
    }

    #[test]
    fn record_increments_all_axes() {
        let mut g = Digest::new("a", "b");
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        assert_eq!(g.total, 1);
        assert_eq!(g.outcome_count(Outcome::Allow), 1);
        assert_eq!(g.side_effect_count(SideEffectClass::ReadOnly), 1);
        assert_eq!(g.profile_count("careful"), 1);
        assert_eq!(g.risk_count(RiskClass::Low), 1);
    }

    #[test]
    fn outcome_counts_partition() {
        let mut g = Digest::new("a", "b");
        for _ in 0..3 { g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful")); }
        for _ in 0..2 { g.record(&d(Outcome::Deny, SideEffectClass::ReadOnly, RiskClass::Medium, "careful")); }
        g.record(&d(Outcome::Ask, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        assert_eq!(g.total, 6);
        assert_eq!(g.outcome_count(Outcome::Allow), 3);
        assert_eq!(g.outcome_count(Outcome::Deny), 2);
        assert_eq!(g.outcome_count(Outcome::Ask), 1);
        assert_eq!(g.outcome_count(Outcome::Sandbox), 0);
    }

    #[test]
    fn deny_rate_bps() {
        let mut g = Digest::new("a", "b");
        for _ in 0..3 { g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "x")); }
        for _ in 0..1 { g.record(&d(Outcome::Deny, SideEffectClass::ReadOnly, RiskClass::Low, "x")); }
        // 1/4 = 0.25 = 2500 bps
        assert_eq!(g.deny_rate_bps(), 2500);
        let empty = Digest::new("a", "b");
        assert_eq!(empty.deny_rate_bps(), 0);
    }

    #[test]
    fn profile_counts_distinct() {
        let mut g = Digest::new("a", "b");
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "fast"));
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        assert_eq!(g.profile_count("careful"), 2);
        assert_eq!(g.profile_count("fast"), 1);
        assert_eq!(g.profile_count("private"), 0);
    }

    #[test]
    fn window_end_before_start_caught() {
        let g = Digest::new("2026-05-19T03:05:00Z", "2026-05-19T03:00:00Z");
        assert!(matches!(g.validate().unwrap_err(), DigestError::WindowEndBeforeStart { .. }));
    }

    #[test]
    fn missing_window_caught() {
        let g = Digest::new("", "b");
        assert!(matches!(g.validate().unwrap_err(), DigestError::MissingWindowStart));
        let g2 = Digest::new("a", "");
        assert!(matches!(g2.validate().unwrap_err(), DigestError::MissingWindowEnd));
    }

    #[test]
    fn outcome_sum_mismatch_caught() {
        let mut g = Digest::new("a", "b");
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        // Tamper total
        g.total = 5;
        assert!(matches!(g.validate().unwrap_err(), DigestError::OutcomeSumMismatch { sum: 1, total: 5 }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = Digest::new("a", "b");
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), DigestError::SchemaMismatch));
    }

    #[test]
    fn digest_serde_roundtrip() {
        let mut g = Digest::new("2026-05-19T03:00:00Z", "2026-05-19T03:01:00Z");
        g.record(&d(Outcome::Allow, SideEffectClass::ReadOnly, RiskClass::Low, "careful"));
        g.record(&d(Outcome::Deny, SideEffectClass::Process, RiskClass::High, "fast"));
        let j = serde_json::to_string(&g).unwrap();
        let back: Digest = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
