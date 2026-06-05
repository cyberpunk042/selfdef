//! `agent_dsl` — the agent-program node taxonomy (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Agent DSL"** verbatim (dump lines
//! 3884-3912). The dump wants *"a small DSL/config format"* so agent programs
//! are defined as graphs of typed nodes *"without burying everything in
//! prompts"*. The canonical example (a `code_patch` workflow) uses five node
//! types, each pinned to the tier/GPU that runs it:
//!
//! ```yaml
//! workflow: code_patch
//! nodes:
//!   classify:     { type: deterministic }                              # CPU
//!   retrieve:     { type: memory, policy: project_context }            # memory plane
//!   draft_patch:  { type: scout, gpu: rtx3090, output: PatchProposal } # RTX 3090
//!   review_patch: { type: oracle, gpu: blackwell, output: VerificationResult } # Blackwell
//!   apply_patch:  { type: tool, requires: [workspace_write, policy_ok, diff_valid] }
//! ```
//!
//! The node taxonomy lines up with the scheduler's tiers (scout→Rtx3090,
//! oracle→Blackwell, deterministic→Cpu) and engines (memory→Memory Router,
//! tool→Tool Gate). The `apply_patch` tool node's three `requires` gates
//! (`workspace_write` / `policy_ok` / `diff_valid`) mirror the
//! [`crate::tool_call_transaction`] checks. Every node type + requires-gate is
//! verbatim — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use crate::Route;
use serde::{Deserialize, Serialize};

/// The five agent-program node types (dump 3892-3910).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    /// `deterministic` — CPU logic (classify / mask / route).
    Deterministic,
    /// `memory` — memory-plane retrieval.
    Memory,
    /// `scout` — RTX 3090 drafting.
    Scout,
    /// `oracle` — Blackwell verification / synthesis.
    Oracle,
    /// `tool` — a gated tool call.
    Tool,
}

impl NodeType {
    /// The verbatim DSL `type:` keyword.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Memory => "memory",
            Self::Scout => "scout",
            Self::Oracle => "oracle",
            Self::Tool => "tool",
        }
    }

    /// The compute [`Route`] this node type runs on, when it pins to one
    /// (memory + tool nodes don't pin to a single compute tier).
    #[must_use]
    pub const fn route(self) -> Option<Route> {
        match self {
            Self::Deterministic => Some(Route::Cpu),
            Self::Scout => Some(Route::Rtx3090),
            Self::Oracle => Some(Route::Blackwell),
            Self::Memory | Self::Tool => None,
        }
    }

    /// Whether this node runs on a GPU (the DSL example carries `gpu:` only on
    /// scout + oracle nodes).
    #[must_use]
    pub const fn is_gpu(self) -> bool {
        matches!(self, Self::Scout | Self::Oracle)
    }
}

/// The three `requires` gates on the example's `apply_patch` tool node
/// (dump 3908-3910, verbatim).
pub const APPLY_PATCH_REQUIRES: [&str; 3] = ["workspace_write", "policy_ok", "diff_valid"];

/// All five node types.
#[must_use]
pub fn node_types() -> [NodeType; 5] {
    [
        NodeType::Deterministic,
        NodeType::Memory,
        NodeType::Scout,
        NodeType::Oracle,
        NodeType::Tool,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_node_types_with_verbatim_keywords() {
        let n = node_types();
        assert_eq!(n.len(), 5);
        assert_eq!(NodeType::Deterministic.keyword(), "deterministic");
        assert_eq!(NodeType::Scout.keyword(), "scout");
        assert_eq!(NodeType::Oracle.keyword(), "oracle");
        assert_eq!(NodeType::Tool.keyword(), "tool");
    }

    #[test]
    fn node_routes_match_the_scheduler_tiers() {
        assert_eq!(NodeType::Deterministic.route(), Some(Route::Cpu));
        assert_eq!(NodeType::Scout.route(), Some(Route::Rtx3090));
        assert_eq!(NodeType::Oracle.route(), Some(Route::Blackwell));
        // memory + tool don't pin to a single compute tier
        assert_eq!(NodeType::Memory.route(), None);
        assert_eq!(NodeType::Tool.route(), None);
    }

    #[test]
    fn only_scout_and_oracle_are_gpu() {
        for n in node_types() {
            assert_eq!(
                n.is_gpu(),
                n == NodeType::Scout || n == NodeType::Oracle,
                "{n:?} gpu flag wrong"
            );
        }
    }

    #[test]
    fn apply_patch_requires_verbatim() {
        assert_eq!(APPLY_PATCH_REQUIRES, ["workspace_write", "policy_ok", "diff_valid"]);
    }

    #[test]
    fn node_types_distinct() {
        let n = node_types();
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(n[i], n[j]);
                assert_ne!(n[i].keyword(), n[j].keyword());
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for n in node_types() {
            let j = serde_json::to_string(&n).unwrap();
            let back: NodeType = serde_json::from_str(&j).unwrap();
            assert_eq!(n, back);
        }
    }
}
