//! `branch_lifecycle` — 8-stage branch execution lifecycle (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Branch Lifecycle"** verbatim (dump
//! lines 1275-1304). Where [`crate::request_lifecycle`] is the request's
//! end-to-end flow, this is the per-**branch** speculative-work transaction:
//! the dump calls the loop *"an AI transaction engine"*.
//!
//! ```text
//! 1. Spawn    — Create root branch from user task.            (CPU)
//! 2. Retrieve — Pull relevant memory/code/context.           (Memory)
//! 3. Draft    — 3090 proposes several continuations or plans. (Scout)
//! 4. Filter   — CPU applies deterministic masks:
//!               grammar, budget, risk, permissions, duplication. (CPU)
//! 5. Verify   — RTX PRO 6000 validates or improves high-value branches. (Oracle)
//! 6. Act      — Tool calls happen only if CPU policy allows them. (CPU)
//! 7. Commit   — Accepted branch state is written to replay log. (Memory)
//! 8. Learn    — Update memory, scores, branch priors, failure records. (Memory)
//! ```
//!
//! The Filter stage's five deterministic masks are exposed as
//! [`FILTER_MASKS`]. Every stage, action, plane, and mask is verbatim — none
//! invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use crate::request_lifecycle::Plane;
use serde::Serialize;

/// Operator doctrine for the branch loop (dump line 1306, verbatim).
pub const DOCTRINE: &str = "It is an AI transaction engine.";

/// The five deterministic masks the Filter stage applies (dump 1290, verbatim).
pub const FILTER_MASKS: [&str; 5] =
    ["grammar", "budget", "risk", "permissions", "duplication"];

/// The eight branch-lifecycle stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum BranchStage {
    /// 1. Spawn — create root branch from user task.
    Spawn,
    /// 2. Retrieve — pull relevant memory/code/context.
    Retrieve,
    /// 3. Draft — scout proposes continuations/plans.
    Draft,
    /// 4. Filter — CPU applies deterministic masks.
    Filter,
    /// 5. Verify — oracle validates/improves high-value branches.
    Verify,
    /// 6. Act — tool calls only if CPU policy allows.
    Act,
    /// 7. Commit — accepted branch state written to replay log.
    Commit,
    /// 8. Learn — update memory, scores, priors, failure records.
    Learn,
}

impl BranchStage {
    /// 1-based stage order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::Spawn => 1,
            Self::Retrieve => 2,
            Self::Draft => 3,
            Self::Filter => 4,
            Self::Verify => 5,
            Self::Act => 6,
            Self::Commit => 7,
            Self::Learn => 8,
        }
    }

    /// The plane that performs the stage.
    #[must_use]
    pub const fn plane(self) -> Plane {
        match self {
            Self::Spawn | Self::Filter | Self::Act => Plane::Cpu,
            Self::Retrieve | Self::Commit | Self::Learn => Plane::Memory,
            Self::Draft => Plane::Scout,
            Self::Verify => Plane::Oracle,
        }
    }

    /// The verbatim action text.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Spawn => "Create root branch from user task.",
            Self::Retrieve => "Pull relevant memory/code/context.",
            Self::Draft => "3090 proposes several continuations or plans.",
            Self::Filter => "CPU applies deterministic masks: grammar, budget, risk, permissions, duplication.",
            Self::Verify => "RTX PRO 6000 validates or improves high-value branches.",
            Self::Act => "Tool calls happen only if CPU policy allows them.",
            Self::Commit => "Accepted branch state is written to replay log.",
            Self::Learn => "Update memory, scores, branch priors, failure records.",
        }
    }
}

/// The eight stages in order.
#[must_use]
pub fn branch_lifecycle() -> [BranchStage; 8] {
    [
        BranchStage::Spawn,
        BranchStage::Retrieve,
        BranchStage::Draft,
        BranchStage::Filter,
        BranchStage::Verify,
        BranchStage::Act,
        BranchStage::Commit,
        BranchStage::Learn,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_stages_in_order() {
        let stages = branch_lifecycle();
        assert_eq!(stages.len(), 8);
        for (i, s) in stages.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn filter_masks_are_verbatim_five() {
        assert_eq!(
            FILTER_MASKS,
            ["grammar", "budget", "risk", "permissions", "duplication"]
        );
        // the Filter stage's action enumerates the same five masks
        let act = BranchStage::Filter.action();
        for m in FILTER_MASKS {
            assert!(act.contains(m), "Filter action missing mask {m}");
        }
    }

    #[test]
    fn draft_is_scout_verify_is_oracle() {
        assert_eq!(BranchStage::Draft.plane(), Plane::Scout);
        assert_eq!(BranchStage::Verify.plane(), Plane::Oracle);
    }

    #[test]
    fn cpu_owns_spawn_filter_act() {
        for s in [BranchStage::Spawn, BranchStage::Filter, BranchStage::Act] {
            assert_eq!(s.plane(), Plane::Cpu, "{s:?} should be CPU");
        }
    }

    #[test]
    fn memory_owns_retrieve_commit_learn() {
        for s in [BranchStage::Retrieve, BranchStage::Commit, BranchStage::Learn] {
            assert_eq!(s.plane(), Plane::Memory, "{s:?} should be Memory");
        }
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "It is an AI transaction engine.");
    }

    #[test]
    fn each_stage_serializes_to_its_name() {
        let j = serde_json::to_string(&BranchStage::Commit).unwrap();
        assert_eq!(j, "\"Commit\"");
    }
}
