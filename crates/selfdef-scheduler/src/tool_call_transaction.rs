//! `tool_call_transaction` — the deterministic tool-call transaction (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Tool Calls Become Transactions"**
//! verbatim (dump lines 2408-2418): *"Every model tool call goes through
//! deterministic stages."* Where [`crate::tool_scheduling`] is the WHEN/HOW
//! (run-early / snapshot / human-gate per tool class), this is the per-call
//! VALIDATION transaction every tool call passes through before it may run —
//! the CPU's deterministic gate, ending in commit-or-reject:
//!
//! ```text
//! parse JSON
//! validate schema
//! scan policy
//! check permission bits
//! check workspace bounds
//! check branch budget
//! classify risk
//! commit or reject
//! ```
//!
//! The dump's leap (2421): *"do this everywhere, not just final JSON"* — the
//! token-mask / structured-decoding discipline applies to every tool call, not
//! only the terminal JSON output. Every stage is verbatim — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The dump's leap (line 2421, verbatim).
pub const DOCTRINE: &str = "do this everywhere, not just final JSON";

/// The eight deterministic stages of a tool-call transaction (dump 2410-2418).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCallStage {
    /// 1. parse JSON.
    ParseJson,
    /// 2. validate schema.
    ValidateSchema,
    /// 3. scan policy.
    ScanPolicy,
    /// 4. check permission bits.
    CheckPermissionBits,
    /// 5. check workspace bounds.
    CheckWorkspaceBounds,
    /// 6. check branch budget.
    CheckBranchBudget,
    /// 7. classify risk.
    ClassifyRisk,
    /// 8. commit or reject (the terminal verdict).
    CommitOrReject,
}

impl ToolCallStage {
    /// 1-based stage order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::ParseJson => 1,
            Self::ValidateSchema => 2,
            Self::ScanPolicy => 3,
            Self::CheckPermissionBits => 4,
            Self::CheckWorkspaceBounds => 5,
            Self::CheckBranchBudget => 6,
            Self::ClassifyRisk => 7,
            Self::CommitOrReject => 8,
        }
    }

    /// The verbatim stage name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ParseJson => "parse JSON",
            Self::ValidateSchema => "validate schema",
            Self::ScanPolicy => "scan policy",
            Self::CheckPermissionBits => "check permission bits",
            Self::CheckWorkspaceBounds => "check workspace bounds",
            Self::CheckBranchBudget => "check branch budget",
            Self::ClassifyRisk => "classify risk",
            Self::CommitOrReject => "commit or reject",
        }
    }

    /// Whether this stage is the terminal verdict (commit or reject).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::CommitOrReject)
    }

    /// Whether this stage is a *gate* — a deterministic check that can reject
    /// the call before the terminal verdict (every stage except the terminal
    /// one is a gate).
    #[must_use]
    pub const fn is_gate(self) -> bool {
        !self.is_terminal()
    }
}

/// The eight stages in order (the transaction pipeline).
#[must_use]
pub fn transaction() -> [ToolCallStage; 8] {
    [
        ToolCallStage::ParseJson,
        ToolCallStage::ValidateSchema,
        ToolCallStage::ScanPolicy,
        ToolCallStage::CheckPermissionBits,
        ToolCallStage::CheckWorkspaceBounds,
        ToolCallStage::CheckBranchBudget,
        ToolCallStage::ClassifyRisk,
        ToolCallStage::CommitOrReject,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_stages_in_order() {
        let t = transaction();
        assert_eq!(t.len(), 8);
        for (i, s) in t.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn stage_names_verbatim() {
        assert_eq!(ToolCallStage::ParseJson.name(), "parse JSON");
        assert_eq!(ToolCallStage::CheckPermissionBits.name(), "check permission bits");
        assert_eq!(ToolCallStage::CommitOrReject.name(), "commit or reject");
    }

    #[test]
    fn only_the_last_stage_is_terminal() {
        for s in transaction() {
            assert_eq!(
                s.is_terminal(),
                s == ToolCallStage::CommitOrReject,
                "{s:?} terminal flag wrong"
            );
        }
    }

    #[test]
    fn seven_gates_one_verdict() {
        let gates = transaction().iter().filter(|s| s.is_gate()).count();
        let verdicts = transaction().iter().filter(|s| s.is_terminal()).count();
        assert_eq!(gates, 7);
        assert_eq!(verdicts, 1);
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "do this everywhere, not just final JSON");
    }

    #[test]
    fn serde_roundtrip() {
        for s in transaction() {
            let j = serde_json::to_string(&s).unwrap();
            let back: ToolCallStage = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
