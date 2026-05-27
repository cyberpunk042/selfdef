//! `selfdef-commit-authority` — MS041 durable-change discipline.
//!
//! Per MS041 + dump 17389-17421:
//!
//! - **8 commit types** per R09611..R09648 (file write / memory write /
//!   policy update / profile update / adapter promotion / cloud
//!   exposure log / tool side effect / workflow completion).
//! - **5 mandatory fields** per R09602..R09606 (actor / reason /
//!   policy_decision / rollback_status / trace_ref).
//! - **High-risk triple gate** per R09607..R09609 + E0420 (snapshot +
//!   test/eval + oracle-or-human).
//! - **High-risk classifier** per F04871..F04875 (adapter promotion =
//!   always, L6 Persist = always, cloud exposure = always, production
//!   L5 = always, autonomous L5 outside predeclared gate = always).
//!
//! Doctrinal preservation — verbatim per R09601 dump 17389:
//!
//! > "A commit is any durable change"
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_profile_authority_gate::{AuthorityLevel, Profile};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Doctrine surface preserved verbatim per R09601 dump 17389.
pub const DOCTRINE_COMMIT_IS_DURABLE_CHANGE: &str = "A commit is any durable change";

/// 8 commit types per R09611..R09648 (dump 17391-17398, verbatim count).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitType {
    /// File write (durable filesystem mutation). R09611 dump 17391.
    FileWrite,
    /// Memory write (memory graph / replay / ZFS ARC). R09616 dump 17392.
    MemoryWrite,
    /// Policy update (policy bus state). R09622 dump 17393.
    PolicyUpdate,
    /// Profile update (active-profile transition). R09627 dump 17394.
    ProfileUpdate,
    /// Adapter promotion (LoRA Foundry crystallisation). R09632 dump 17395.
    /// ALWAYS high-risk per F04821 + F04871 + R09636.
    AdapterPromotion,
    /// Cloud exposure log (Ring 4 outbound). R09638 dump 17396.
    /// ALWAYS high-risk per F04873.
    CloudExposureLog,
    /// Tool side effect (MS036 observable). R09643 dump 17397.
    ToolSideEffect,
    /// Workflow completion (M057 12-step final). R09648 dump 17398.
    WorkflowCompletion,
}

/// Rollback availability state per R09605.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackStatus {
    /// Rollback artifact present + signed.
    Available,
    /// Rollback applied (post-rollback record).
    Applied,
    /// Rollback path documented but artifact not yet built.
    Documented,
    /// Rollback unavailable. REJECTED for high-risk per F04852.
    Unavailable,
}

/// 4-state policy outcome per MS033 R07731-R07734.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyOutcome {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
    /// Ask operator (queue D-06).
    Ask,
    /// Escalate to sandbox.
    Sandbox,
}

/// High-risk-gate evidence per E0420 + R09607-R09609.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HighRiskGate {
    /// ZFS snapshot id present pre-commit (R09607 dump 17418).
    pub snapshot_id: String,
    /// Test/eval suite identifier that passed (R09608 dump 17419).
    pub test_eval_id: String,
    /// Oracle/human reviewer fingerprint (R09609 dump 17420).
    pub oracle_or_human: String,
}

impl HighRiskGate {
    /// True iff all three gate elements are present.
    pub fn complete(&self) -> bool {
        !self.snapshot_id.is_empty()
            && !self.test_eval_id.is_empty()
            && !self.oracle_or_human.is_empty()
    }
}

/// One commit envelope: type + 5 mandatory fields + optional high-risk gate + MS003 sig.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitEnvelope {
    /// Commit type.
    pub commit_type: CommitType,
    /// Field 1 — actor MS003 fingerprint (R09602 + R09653-R09656).
    pub actor: String,
    /// Field 2 — human-readable reason (R09603 + R09657 non-empty).
    pub reason: String,
    /// Field 3 — policy decision outcome (R09604).
    pub policy_decision: PolicyOutcome,
    /// Field 4 — rollback status (R09605).
    pub rollback_status: RollbackStatus,
    /// Field 5 — M049 trace reference (R09606).
    pub trace_ref: String,
    /// High-risk gate evidence (set only when classifier marks high-risk).
    pub high_risk_gate: Option<HighRiskGate>,
    /// Profile in force at commit time (drives classifier).
    pub profile: Profile,
    /// Target authority level requested for this commit.
    pub authority_level: AuthorityLevel,
    /// Whether autonomous commit is within its predeclared gate envelope
    /// (False contributes to F04875 high-risk classification).
    pub within_autonomous_gate: bool,
    /// MS003 signature over the canonical-JSON encoding (hex).
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CommitError {
    /// One of the 5 mandatory fields is missing or empty.
    #[error("mandatory field missing: {0}")]
    MandatoryFieldMissing(&'static str),
    /// Rollback status is Unavailable on a high-risk commit (F04852).
    #[error("rollback_status=Unavailable rejected for high-risk commit (F04852)")]
    HighRiskRollbackUnavailable,
    /// Triple gate is incomplete for a high-risk commit.
    #[error("high-risk triple-gate incomplete: missing {missing:?}")]
    TripleGateIncomplete {
        /// List of missing elements.
        missing: Vec<&'static str>,
    },
    /// MS003 signature is empty.
    #[error("MS003 signature missing (commit envelopes MUST be signed)")]
    SignatureMissing,
    /// Doctrine surface tampered.
    #[error("doctrine surface tampered: expected verbatim \"{expected}\", got \"{actual}\"")]
    DoctrineTampered {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
}

/// High-risk classifier per F04871-F04875 + R09636.
pub fn is_high_risk(env: &CommitEnvelope) -> bool {
    // R09636 + F04871 — adapter promotion is always high-risk.
    if env.commit_type == CommitType::AdapterPromotion {
        return true;
    }
    // F04873 — cloud exposure log is always high-risk.
    if env.commit_type == CommitType::CloudExposureLog {
        return true;
    }
    // F04872 — L6 Persist is always high-risk.
    if env.authority_level == AuthorityLevel::L6Persist {
        return true;
    }
    // F04874 — production profile L5 Commit is high-risk.
    if env.profile == Profile::Production && env.authority_level == AuthorityLevel::L5Commit {
        return true;
    }
    // F04875 — autonomous L5 Commit outside the predeclared gate is high-risk.
    if env.profile == Profile::Autonomous
        && env.authority_level == AuthorityLevel::L5Commit
        && !env.within_autonomous_gate
    {
        return true;
    }
    false
}

/// Validate one commit envelope. Returns Ok when the envelope satisfies:
/// - schema invariants (5 fields populated, signature present)
/// - high-risk gate (triple gate + non-Unavailable rollback) when classifier fires
pub fn validate(env: &CommitEnvelope) -> Result<(), CommitError> {
    // Mandatory fields per R09602-R09606.
    if env.actor.is_empty() {
        return Err(CommitError::MandatoryFieldMissing("actor"));
    }
    if env.reason.is_empty() {
        return Err(CommitError::MandatoryFieldMissing("reason"));
    }
    if env.trace_ref.is_empty() {
        return Err(CommitError::MandatoryFieldMissing("trace_ref"));
    }
    if env.signature.is_empty() {
        return Err(CommitError::SignatureMissing);
    }
    // High-risk extras.
    if is_high_risk(env) {
        if env.rollback_status == RollbackStatus::Unavailable {
            return Err(CommitError::HighRiskRollbackUnavailable);
        }
        let mut missing: Vec<&'static str> = Vec::new();
        let gate = match &env.high_risk_gate {
            Some(g) => g,
            None => {
                return Err(CommitError::TripleGateIncomplete {
                    missing: vec!["snapshot_id", "test_eval_id", "oracle_or_human"],
                });
            }
        };
        if gate.snapshot_id.is_empty() {
            missing.push("snapshot_id");
        }
        if gate.test_eval_id.is_empty() {
            missing.push("test_eval_id");
        }
        if gate.oracle_or_human.is_empty() {
            missing.push("oracle_or_human");
        }
        if !missing.is_empty() {
            return Err(CommitError::TripleGateIncomplete { missing });
        }
    }
    Ok(())
}

/// Validate the doctrine constant.
pub fn assert_doctrine_intact(observed: &str) -> Result<(), CommitError> {
    if observed != DOCTRINE_COMMIT_IS_DURABLE_CHANGE {
        return Err(CommitError::DoctrineTampered {
            expected: DOCTRINE_COMMIT_IS_DURABLE_CHANGE.into(),
            actual: observed.into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_env() -> CommitEnvelope {
        CommitEnvelope {
            commit_type: CommitType::FileWrite,
            actor: "operator-fp".into(),
            reason: "ship new feature".into(),
            policy_decision: PolicyOutcome::Allow,
            rollback_status: RollbackStatus::Available,
            trace_ref: "trace-001".into(),
            high_risk_gate: None,
            profile: Profile::Careful,
            authority_level: AuthorityLevel::L5Commit,
            within_autonomous_gate: true,
            signature: "ms003-sig".into(),
        }
    }

    fn high_risk_env() -> CommitEnvelope {
        let mut e = ok_env();
        e.commit_type = CommitType::AdapterPromotion;
        e.high_risk_gate = Some(HighRiskGate {
            snapshot_id: "rpool@pre".into(),
            test_eval_id: "eval-suite-v3".into(),
            oracle_or_human: "operator-fp".into(),
        });
        e
    }

    // --- 8 commit types ---

    #[test]
    fn eight_commit_types_enumerated() {
        // Exhaust the 8 verbatim per R09610 dump 17391-17398.
        for t in [
            CommitType::FileWrite,
            CommitType::MemoryWrite,
            CommitType::PolicyUpdate,
            CommitType::ProfileUpdate,
            CommitType::AdapterPromotion,
            CommitType::CloudExposureLog,
            CommitType::ToolSideEffect,
            CommitType::WorkflowCompletion,
        ] {
            let mut e = ok_env();
            e.commit_type = t;
            // Make sure each type passes validate when not high-risk OR when gate set.
            if is_high_risk(&e) {
                e.high_risk_gate = Some(HighRiskGate {
                    snapshot_id: "s".into(),
                    test_eval_id: "t".into(),
                    oracle_or_human: "o".into(),
                });
            }
            validate(&e).unwrap();
        }
    }

    // --- 5 mandatory fields ---

    #[test]
    fn missing_actor_rejected() {
        let mut e = ok_env();
        e.actor = String::new();
        assert!(matches!(
            validate(&e).unwrap_err(),
            CommitError::MandatoryFieldMissing("actor")
        ));
    }

    #[test]
    fn missing_reason_rejected() {
        let mut e = ok_env();
        e.reason = String::new();
        assert!(matches!(
            validate(&e).unwrap_err(),
            CommitError::MandatoryFieldMissing("reason")
        ));
    }

    #[test]
    fn missing_trace_ref_rejected() {
        let mut e = ok_env();
        e.trace_ref = String::new();
        assert!(matches!(
            validate(&e).unwrap_err(),
            CommitError::MandatoryFieldMissing("trace_ref")
        ));
    }

    #[test]
    fn missing_signature_rejected() {
        let mut e = ok_env();
        e.signature = String::new();
        assert!(matches!(
            validate(&e).unwrap_err(),
            CommitError::SignatureMissing
        ));
    }

    // --- High-risk classifier ---

    #[test]
    fn adapter_promotion_always_high_risk() {
        let mut e = ok_env();
        e.commit_type = CommitType::AdapterPromotion;
        assert!(is_high_risk(&e));
    }

    #[test]
    fn cloud_exposure_log_always_high_risk() {
        let mut e = ok_env();
        e.commit_type = CommitType::CloudExposureLog;
        assert!(is_high_risk(&e));
    }

    #[test]
    fn l6_persist_always_high_risk() {
        let mut e = ok_env();
        e.authority_level = AuthorityLevel::L6Persist;
        assert!(is_high_risk(&e));
    }

    #[test]
    fn production_l5_high_risk() {
        let mut e = ok_env();
        e.profile = Profile::Production;
        e.authority_level = AuthorityLevel::L5Commit;
        assert!(is_high_risk(&e));
    }

    #[test]
    fn autonomous_l5_outside_gate_high_risk() {
        let mut e = ok_env();
        e.profile = Profile::Autonomous;
        e.authority_level = AuthorityLevel::L5Commit;
        e.within_autonomous_gate = false;
        assert!(is_high_risk(&e));
    }

    #[test]
    fn autonomous_l5_within_gate_not_high_risk() {
        let mut e = ok_env();
        e.profile = Profile::Autonomous;
        e.authority_level = AuthorityLevel::L5Commit;
        e.within_autonomous_gate = true;
        assert!(!is_high_risk(&e));
    }

    #[test]
    fn careful_l5_not_high_risk() {
        let mut e = ok_env();
        e.profile = Profile::Careful;
        e.authority_level = AuthorityLevel::L5Commit;
        assert!(!is_high_risk(&e));
    }

    // --- High-risk triple gate enforcement ---

    #[test]
    fn high_risk_without_gate_rejected() {
        let mut e = ok_env();
        e.commit_type = CommitType::AdapterPromotion;
        e.high_risk_gate = None;
        match validate(&e).unwrap_err() {
            CommitError::TripleGateIncomplete { missing } => {
                assert!(missing.contains(&"snapshot_id"));
                assert!(missing.contains(&"test_eval_id"));
                assert!(missing.contains(&"oracle_or_human"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn high_risk_partial_gate_rejected() {
        let mut e = high_risk_env();
        if let Some(g) = e.high_risk_gate.as_mut() {
            g.snapshot_id = String::new();
        }
        match validate(&e).unwrap_err() {
            CommitError::TripleGateIncomplete { missing } => {
                assert_eq!(missing, vec!["snapshot_id"]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn high_risk_rollback_unavailable_rejected() {
        let mut e = high_risk_env();
        e.rollback_status = RollbackStatus::Unavailable;
        assert!(matches!(
            validate(&e).unwrap_err(),
            CommitError::HighRiskRollbackUnavailable
        ));
    }

    #[test]
    fn high_risk_full_evidence_accepted() {
        validate(&high_risk_env()).unwrap();
    }

    #[test]
    fn high_risk_gate_complete_helper() {
        let g = HighRiskGate {
            snapshot_id: "s".into(),
            test_eval_id: "t".into(),
            oracle_or_human: "o".into(),
        };
        assert!(g.complete());

        let g2 = HighRiskGate {
            snapshot_id: "s".into(),
            ..Default::default()
        };
        assert!(!g2.complete());
    }

    // --- Doctrine + serde ---

    #[test]
    fn doctrine_verbatim() {
        assert_eq!(
            DOCTRINE_COMMIT_IS_DURABLE_CHANGE,
            "A commit is any durable change"
        );
        assert_doctrine_intact("A commit is any durable change").unwrap();
    }

    #[test]
    fn doctrine_tamper_caught() {
        let err = assert_doctrine_intact("durable changes are commits").unwrap_err();
        assert!(matches!(err, CommitError::DoctrineTampered { .. }));
    }

    #[test]
    fn commit_type_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&CommitType::AdapterPromotion).unwrap(),
            "\"adapter-promotion\""
        );
        assert_eq!(
            serde_json::to_string(&CommitType::CloudExposureLog).unwrap(),
            "\"cloud-exposure-log\""
        );
        assert_eq!(
            serde_json::to_string(&CommitType::ToolSideEffect).unwrap(),
            "\"tool-side-effect\""
        );
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let original = high_risk_env();
        let j = serde_json::to_string(&original).unwrap();
        let back: CommitEnvelope = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn rollback_status_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&RollbackStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&RollbackStatus::Applied).unwrap(),
            "\"applied\""
        );
    }
}
