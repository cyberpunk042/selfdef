//! `critical_separation` — thought ≠ action: ReAct is a pattern, not authority (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Critical Separation"** verbatim
//! (dump lines 3946-3959), a core IPS safety doctrine complementing
//! [`crate::runtime_law`]. The dump (3948): *"Do not let ReAct-style traces
//! become authority."* ReAct (`reason → act → observe`) is useful as a *model
//! behavior pattern*, but the runtime must enforce four separations so the
//! model never surrenders control:
//!
//! ```text
//! thought is not action
//! action proposal is not execution
//! observation is not trusted until validated
//! commit is deterministic
//! ```
//!
//! The payoff (3959): *"the benefits of agentic reasoning without surrendering
//! control to the model."* Every separation rule + the ReAct pattern is
//! verbatim — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 3948, verbatim).
pub const DOCTRINE: &str = "Do not let ReAct-style traces become authority.";

/// The payoff (dump 3959, verbatim).
pub const PAYOFF: &str =
    "the benefits of agentic reasoning without surrendering control to the model.";

/// The ReAct model-behavior pattern (dump 3952, verbatim) — a *pattern*, NOT
/// authority.
pub const REACT_PATTERN: [&str; 3] = ["reason", "act", "observe"];

/// The four separations the runtime enforces (dump 3955-3958).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeparationRule {
    /// thought is not action.
    ThoughtIsNotAction,
    /// action proposal is not execution.
    ProposalIsNotExecution,
    /// observation is not trusted until validated.
    ObservationNotTrustedUntilValidated,
    /// commit is deterministic.
    CommitIsDeterministic,
}

impl SeparationRule {
    /// The verbatim rule text.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            Self::ThoughtIsNotAction => "thought is not action",
            Self::ProposalIsNotExecution => "action proposal is not execution",
            Self::ObservationNotTrustedUntilValidated => {
                "observation is not trusted until validated"
            }
            Self::CommitIsDeterministic => "commit is deterministic",
        }
    }

    /// The execution-pipeline stage / mechanism that enforces this separation.
    #[must_use]
    pub const fn enforced_by(self) -> &'static str {
        match self {
            // a thought (Decode) is not the Execute stage
            Self::ThoughtIsNotAction => "execution_pipeline (Decode ≠ Execute)",
            // a tool-call proposal must pass the transaction before running
            Self::ProposalIsNotExecution => "tool_call_transaction",
            // the Validate stage gates observations (CPU masks/parses/scans)
            Self::ObservationNotTrustedUntilValidated => "execution_pipeline (Validate)",
            // the Commit stage writes accepted state deterministically
            Self::CommitIsDeterministic => "execution_pipeline (Commit)",
        }
    }
}

/// The four separation rules in dump order.
#[must_use]
pub fn separations() -> [SeparationRule; 4] {
    [
        SeparationRule::ThoughtIsNotAction,
        SeparationRule::ProposalIsNotExecution,
        SeparationRule::ObservationNotTrustedUntilValidated,
        SeparationRule::CommitIsDeterministic,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn react_pattern_is_reason_act_observe() {
        assert_eq!(REACT_PATTERN, ["reason", "act", "observe"]);
    }

    #[test]
    fn four_separations_verbatim() {
        let s = separations();
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].rule(), "thought is not action");
        assert_eq!(s[3].rule(), "commit is deterministic");
        assert_eq!(
            SeparationRule::ObservationNotTrustedUntilValidated.rule(),
            "observation is not trusted until validated"
        );
    }

    #[test]
    fn every_separation_has_an_enforcing_stage() {
        for s in separations() {
            assert!(!s.enforced_by().is_empty(), "{s:?} not enforced");
        }
        assert!(SeparationRule::ProposalIsNotExecution
            .enforced_by()
            .contains("tool_call_transaction"));
    }

    #[test]
    fn separations_distinct() {
        let s = separations();
        for i in 0..4 {
            for j in (i + 1)..4 {
                assert_ne!(s[i], s[j]);
                assert_ne!(s[i].rule(), s[j].rule());
            }
        }
    }

    #[test]
    fn doctrine_and_payoff_verbatim() {
        assert_eq!(DOCTRINE, "Do not let ReAct-style traces become authority.");
        assert!(PAYOFF.contains("without surrendering control to the model"));
    }

    #[test]
    fn serde_roundtrip() {
        for s in separations() {
            let j = serde_json::to_string(&s).unwrap();
            let back: SeparationRule = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
