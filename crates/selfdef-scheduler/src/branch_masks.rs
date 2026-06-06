//! `branch_masks` — the AVX-512 branch-scheduler tick (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The AVX-512 Scheduler"** per-branch
//! tick verbatim (dump lines 1308-1340). The dump models the CPU branch
//! scheduler as a structure-of-arrays processing 8 branches per AVX-512 vector;
//! each tick computes a set of masks per branch:
//!
//! ```text
//! budget -= cost
//! dead_mask   = budget == 0
//! risk_mask   = risk > threshold
//! oracle_mask = confidence_low & value_high
//! scout_mask  = confidence_medium & cost_low
//! tool_mask   = tool_requested & tool_allowed
//! merge_mask  = similarity_high
//! ```
//!
//! This is the per-branch-per-tick decision (which branches are dead, risky,
//! oracle-bound, scout-bound, may call a tool, or should merge) — the
//! complement to [`crate::scheduling_law::recommend_route`] (the per-request
//! route). The dump calls it *"a branch operating system."* The mask logic is
//! verbatim; only the risk threshold is parameterized (Stage-1 operator-tunable,
//! same pattern as [`crate::BackpressureThresholds`]) — nothing invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Per-branch confidence (the scheduler's estimate of how sure the branch is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    /// Low confidence — oracle verification warranted if value is high.
    Low,
    /// Medium confidence — scout exploration if cheap.
    Medium,
    /// High confidence.
    High,
}

/// Per-branch value (how valuable resolving this branch is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    /// Low value.
    Low,
    /// High value.
    High,
}

/// The per-branch scalar inputs the scheduler tick reads (one "row" of the
/// structure-of-arrays).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BranchScalars {
    /// Remaining budget (decremented by `cost` each tick).
    pub budget: i64,
    /// Cost charged this tick.
    pub cost: i64,
    /// Risk score (compared against the threshold).
    pub risk: f32,
    /// Confidence estimate.
    pub confidence: Confidence,
    /// Value estimate.
    pub value: Value,
    /// Whether this branch's cost is low (for the scout mask).
    pub cost_low: bool,
    /// Whether the branch requested a tool.
    pub tool_requested: bool,
    /// Whether that tool is allowed (capability gate).
    pub tool_allowed: bool,
    /// Whether the branch is highly similar to another (merge candidate).
    pub similarity_high: bool,
}

/// The masks computed per branch per tick (dump 1334-1340).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchMasks {
    /// `budget == 0` after the tick's decrement — branch is dead.
    pub dead: bool,
    /// `risk > threshold`.
    pub risk: bool,
    /// `confidence_low & value_high` — route to oracle.
    pub oracle: bool,
    /// `confidence_medium & cost_low` — route to scout.
    pub scout: bool,
    /// `tool_requested & tool_allowed` — tool call admitted.
    pub tool: bool,
    /// `similarity_high` — merge candidate.
    pub merge: bool,
}

/// Default risk threshold for the `risk_mask` (Stage-1 operator-tunable).
pub const DEFAULT_RISK_THRESHOLD: f32 = 0.5;

/// Run one scheduler tick for a branch: decrement budget by cost (saturating at
/// 0, never negative — a dead branch stays at 0), then compute the masks.
/// Returns the post-decrement budget and the masks.
#[must_use]
pub fn tick(branch: &BranchScalars, risk_threshold: f32) -> (i64, BranchMasks) {
    let new_budget = (branch.budget - branch.cost).max(0);
    let masks = BranchMasks {
        dead: new_budget == 0,
        risk: branch.risk > risk_threshold,
        oracle: matches!(branch.confidence, Confidence::Low) && matches!(branch.value, Value::High),
        scout: matches!(branch.confidence, Confidence::Medium) && branch.cost_low,
        tool: branch.tool_requested && branch.tool_allowed,
        merge: branch.similarity_high,
    };
    (new_budget, masks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BranchScalars {
        BranchScalars {
            budget: 100,
            cost: 10,
            risk: 0.1,
            confidence: Confidence::High,
            value: Value::Low,
            cost_low: false,
            tool_requested: false,
            tool_allowed: false,
            similarity_high: false,
        }
    }

    #[test]
    fn budget_decrements_by_cost() {
        let (b, _) = tick(&base(), DEFAULT_RISK_THRESHOLD);
        assert_eq!(b, 90);
    }

    #[test]
    fn dead_mask_when_budget_exhausted() {
        let s = BranchScalars {
            budget: 10,
            cost: 10,
            ..base()
        };
        let (b, m) = tick(&s, DEFAULT_RISK_THRESHOLD);
        assert_eq!(b, 0);
        assert!(m.dead);
    }

    #[test]
    fn budget_saturates_at_zero_never_negative() {
        let s = BranchScalars {
            budget: 5,
            cost: 10,
            ..base()
        };
        let (b, m) = tick(&s, DEFAULT_RISK_THRESHOLD);
        assert_eq!(b, 0);
        assert!(m.dead);
    }

    #[test]
    fn risk_mask_above_threshold() {
        let s = BranchScalars {
            risk: 0.8,
            ..base()
        };
        let (_, m) = tick(&s, 0.5);
        assert!(m.risk);
        let s2 = BranchScalars {
            risk: 0.3,
            ..base()
        };
        let (_, m2) = tick(&s2, 0.5);
        assert!(!m2.risk);
    }

    #[test]
    fn oracle_mask_low_confidence_high_value() {
        let s = BranchScalars {
            confidence: Confidence::Low,
            value: Value::High,
            ..base()
        };
        let (_, m) = tick(&s, DEFAULT_RISK_THRESHOLD);
        assert!(m.oracle);
        // low confidence but LOW value → not oracle
        let s2 = BranchScalars {
            confidence: Confidence::Low,
            value: Value::Low,
            ..base()
        };
        let (_, m2) = tick(&s2, DEFAULT_RISK_THRESHOLD);
        assert!(!m2.oracle);
    }

    #[test]
    fn scout_mask_medium_confidence_low_cost() {
        let s = BranchScalars {
            confidence: Confidence::Medium,
            cost_low: true,
            ..base()
        };
        let (_, m) = tick(&s, DEFAULT_RISK_THRESHOLD);
        assert!(m.scout);
        // medium confidence but not low cost → not scout
        let s2 = BranchScalars {
            confidence: Confidence::Medium,
            cost_low: false,
            ..base()
        };
        let (_, m2) = tick(&s2, DEFAULT_RISK_THRESHOLD);
        assert!(!m2.scout);
    }

    #[test]
    fn tool_mask_requested_and_allowed() {
        let s = BranchScalars {
            tool_requested: true,
            tool_allowed: true,
            ..base()
        };
        assert!(tick(&s, DEFAULT_RISK_THRESHOLD).1.tool);
        // requested but not allowed → masked off
        let s2 = BranchScalars {
            tool_requested: true,
            tool_allowed: false,
            ..base()
        };
        assert!(!tick(&s2, DEFAULT_RISK_THRESHOLD).1.tool);
    }

    #[test]
    fn merge_mask_on_high_similarity() {
        let s = BranchScalars {
            similarity_high: true,
            ..base()
        };
        assert!(tick(&s, DEFAULT_RISK_THRESHOLD).1.merge);
    }

    #[test]
    fn serde_roundtrip_masks() {
        let (_, m) = tick(&base(), DEFAULT_RISK_THRESHOLD);
        let j = serde_json::to_string(&m).unwrap();
        let back: BranchMasks = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
