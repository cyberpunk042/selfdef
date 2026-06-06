//! `learning` — policy-update learning + the local learning loop (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Learning As Policy Update"** +
//! **"Learning Loop"** verbatim (dump lines 4193-4312). The system improves by
//! updating *policy*, not model weights — *"Deterministic. Auditable.
//! Reversible."* (4218) — each change captured in a [`PolicyUpdateRecord`]; and
//! the full local cycle is an eight-step loop *"how the system gets better
//! every week"* (4312).
//!
//! Policy update record (dump 4209-4216):
//!
//! ```text
//! condition_mask / old_policy / new_policy / evidence_count /
//! success_delta / approved_by / rollback_ref
//! ```
//!
//! The learning loop (dump 4301-4309):
//!
//! ```text
//! 1. Execute task with branch runtime.
//! 2. Record trace, metrics, outcome.
//! 3. Classify failure/success deterministically.
//! 4. Generate reflection only if useful.
//! 5. Extract possible skill/policy update.
//! 6. Validate against replay.
//! 7. Store in experience memory.
//! 8. Promote after evidence threshold.
//! ```
//!
//! Pairs with [`crate::failure_codes`] (step 3) + [`crate::reflexion`] (step 4).
//! Every field + step is verbatim — none invented (operator rule: "you cannot
//! invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 4205, verbatim).
pub const DOCTRINE: &str = "These are policy updates, not model updates.";

/// The three properties of every policy update (dump 4218, verbatim).
pub const PROPERTIES: [&str; 3] = ["Deterministic", "Auditable", "Reversible"];

/// A policy-update record (dump 4209-4216, verbatim field set). Deterministic,
/// auditable (evidence + approver), and reversible (rollback_ref).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyUpdateRecord {
    /// `condition_mask` — the condition under which the policy applies.
    pub condition_mask: u64,
    /// `old_policy`.
    pub old_policy: String,
    /// `new_policy`.
    pub new_policy: String,
    /// `evidence_count` — how many episodes back this change.
    pub evidence_count: u32,
    /// `success_delta` — measured improvement.
    pub success_delta: f32,
    /// `approved_by` — operator/oracle that approved the change.
    pub approved_by: String,
    /// `rollback_ref` — the reference to revert to.
    pub rollback_ref: String,
}

impl PolicyUpdateRecord {
    /// Whether this update has enough evidence to promote (auditable gate).
    #[must_use]
    pub const fn has_evidence(&self, threshold: u32) -> bool {
        self.evidence_count >= threshold
    }

    /// Whether this update is reversible (has a rollback reference).
    #[must_use]
    pub fn is_reversible(&self) -> bool {
        !self.rollback_ref.is_empty()
    }
}

/// The eight steps of the local learning loop (dump 4301-4309).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LearningStep {
    /// 1. Execute task with branch runtime.
    ExecuteTask,
    /// 2. Record trace, metrics, outcome.
    RecordTrace,
    /// 3. Classify failure/success deterministically.
    ClassifyOutcome,
    /// 4. Generate reflection only if useful.
    GenerateReflection,
    /// 5. Extract possible skill/policy update.
    ExtractUpdate,
    /// 6. Validate against replay.
    ValidateAgainstReplay,
    /// 7. Store in experience memory.
    StoreExperience,
    /// 8. Promote after evidence threshold.
    PromoteOnEvidence,
}

impl LearningStep {
    /// 1-based step order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::ExecuteTask => 1,
            Self::RecordTrace => 2,
            Self::ClassifyOutcome => 3,
            Self::GenerateReflection => 4,
            Self::ExtractUpdate => 5,
            Self::ValidateAgainstReplay => 6,
            Self::StoreExperience => 7,
            Self::PromoteOnEvidence => 8,
        }
    }

    /// The verbatim step text.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::ExecuteTask => "Execute task with branch runtime.",
            Self::RecordTrace => "Record trace, metrics, outcome.",
            Self::ClassifyOutcome => "Classify failure/success deterministically.",
            Self::GenerateReflection => "Generate reflection only if useful.",
            Self::ExtractUpdate => "Extract possible skill/policy update.",
            Self::ValidateAgainstReplay => "Validate against replay.",
            Self::StoreExperience => "Store in experience memory.",
            Self::PromoteOnEvidence => "Promote after evidence threshold.",
        }
    }
}

/// The eight learning-loop steps in order.
#[must_use]
pub fn learning_loop() -> [LearningStep; 8] {
    [
        LearningStep::ExecuteTask,
        LearningStep::RecordTrace,
        LearningStep::ClassifyOutcome,
        LearningStep::GenerateReflection,
        LearningStep::ExtractUpdate,
        LearningStep::ValidateAgainstReplay,
        LearningStep::StoreExperience,
        LearningStep::PromoteOnEvidence,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PolicyUpdateRecord {
        PolicyUpdateRecord {
            condition_mask: 0b1010,
            old_policy: "scout=A".into(),
            new_policy: "scout=B".into(),
            evidence_count: 12,
            success_delta: 0.18,
            approved_by: "operator-kid-1".into(),
            rollback_ref: "policy-snap-0007".into(),
        }
    }

    #[test]
    fn policy_record_carries_seven_fields() {
        let r = record();
        assert_eq!(r.condition_mask, 0b1010);
        assert_eq!(r.old_policy, "scout=A");
        assert_eq!(r.new_policy, "scout=B");
        assert_eq!(r.evidence_count, 12);
        assert!((r.success_delta - 0.18).abs() < 1e-6);
        assert_eq!(r.approved_by, "operator-kid-1");
        assert_eq!(r.rollback_ref, "policy-snap-0007");
    }

    #[test]
    fn evidence_gate_and_reversibility() {
        let r = record();
        assert!(r.has_evidence(10));
        assert!(!r.has_evidence(20));
        assert!(r.is_reversible());
        let mut r2 = record();
        r2.rollback_ref = String::new();
        assert!(!r2.is_reversible());
    }

    #[test]
    fn eight_steps_in_order_verbatim() {
        let l = learning_loop();
        assert_eq!(l.len(), 8);
        for (i, s) in l.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
        assert_eq!(
            LearningStep::ExecuteTask.text(),
            "Execute task with branch runtime."
        );
        assert_eq!(
            LearningStep::PromoteOnEvidence.text(),
            "Promote after evidence threshold."
        );
    }

    #[test]
    fn doctrine_and_properties_verbatim() {
        assert_eq!(DOCTRINE, "These are policy updates, not model updates.");
        assert_eq!(PROPERTIES, ["Deterministic", "Auditable", "Reversible"]);
    }

    #[test]
    fn serde_roundtrip() {
        let r = record();
        let j = serde_json::to_string(&r).unwrap();
        let back: PolicyUpdateRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
        for s in learning_loop() {
            let sj = serde_json::to_string(&s).unwrap();
            let sb: LearningStep = serde_json::from_str(&sj).unwrap();
            assert_eq!(s, sb);
        }
    }
}
