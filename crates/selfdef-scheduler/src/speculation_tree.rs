//! `speculation_tree` — tree-structured speculation (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Speculation Becomes Tree Execution"**
//! section verbatim (dump lines 2574-2606). Where
//! [`crate::speculative_parallelism`] is the *linear* predict/prune/verify
//! pipeline, this is the *tree* form (à la SpecInfer / Medusa / EAGLE): the
//! scout grows a speculative token tree, the oracle verifies chunks of it in
//! parallel, and the CPU commits the accepted path. The dump calls it
//! *"branch-predicted cognition."*
//!
//! The hardware pipeline (dump 2580-2585):
//!
//! ```text
//! 3090 creates speculative tree
//! CPU stores tree as bit-packed branch records
//! Blackwell verifies tree chunks
//! CPU commits accepted path
//! ```
//!
//! The compact node representation (dump 2589-2596, verbatim C struct):
//!
//! ```c
//! struct TokenNode {
//!     uint32_t token;
//!     uint32_t parent;
//!     uint16_t depth;
//!     uint16_t child_mask;
//!     uint16_t score;
//!     uint16_t flags;
//! };
//! ```
//!
//! The five AVX-512 CPU operations over the tree (dump 2600-2605) are
//! [`CPU_TREE_OPS`]. Every stage, field, and op is verbatim — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Operator doctrine (dump line 2607, verbatim).
pub const DOCTRINE: &str = "It is branch-predicted cognition.";

/// The five AVX-512 CPU tree operations (dump 2600-2605, verbatim).
pub const CPU_TREE_OPS: [&str; 5] = [
    "filter invalid nodes",
    "merge identical prefixes",
    "deduplicate token paths",
    "pack verification batches",
    "track accepted subtree",
];

/// The compact speculative-tree node (dump 2589-2596 C struct, verbatim
/// field types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenNode {
    /// `uint32_t token` — the token id.
    pub token: u32,
    /// `uint32_t parent` — parent node index.
    pub parent: u32,
    /// `uint16_t depth` — depth in the tree.
    pub depth: u16,
    /// `uint16_t child_mask` — bitset of present children.
    pub child_mask: u16,
    /// `uint16_t score` — branch score.
    pub score: u16,
    /// `uint16_t flags`.
    pub flags: u16,
}

/// The four-stage tree-execution pipeline (dump 2580-2585).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TreeStage {
    /// "3090 creates speculative tree" (scout).
    ScoutCreatesTree,
    /// "CPU stores tree as bit-packed branch records" (cortex).
    CpuStoresBitPacked,
    /// "Blackwell verifies tree chunks" (oracle).
    OracleVerifiesChunks,
    /// "CPU commits accepted path" (cortex).
    CpuCommitsPath,
}

impl TreeStage {
    /// 1-based pipeline order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::ScoutCreatesTree => 1,
            Self::CpuStoresBitPacked => 2,
            Self::OracleVerifiesChunks => 3,
            Self::CpuCommitsPath => 4,
        }
    }

    /// The verbatim action text.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::ScoutCreatesTree => "3090 creates speculative tree",
            Self::CpuStoresBitPacked => "CPU stores tree as bit-packed branch records",
            Self::OracleVerifiesChunks => "Blackwell verifies tree chunks",
            Self::CpuCommitsPath => "CPU commits accepted path",
        }
    }
}

/// The four stages in pipeline order.
#[must_use]
pub fn pipeline() -> [TreeStage; 4] {
    [
        TreeStage::ScoutCreatesTree,
        TreeStage::CpuStoresBitPacked,
        TreeStage::OracleVerifiesChunks,
        TreeStage::CpuCommitsPath,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_node_roundtrips() {
        let n = TokenNode {
            token: 42,
            parent: 7,
            depth: 3,
            child_mask: 0b1010,
            score: 900,
            flags: 0x01,
        };
        let j = serde_json::to_string(&n).unwrap();
        let back: TokenNode = serde_json::from_str(&j).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn token_node_field_types_match_dump_struct() {
        // u32 token/parent, u16 depth/child_mask/score/flags — exercise the
        // max of each width to confirm the declared types.
        let n = TokenNode {
            token: u32::MAX,
            parent: u32::MAX,
            depth: u16::MAX,
            child_mask: u16::MAX,
            score: u16::MAX,
            flags: u16::MAX,
        };
        assert_eq!(n.token, u32::MAX);
        assert_eq!(n.flags, u16::MAX);
    }

    #[test]
    fn pipeline_is_create_store_verify_commit_in_order() {
        let p = pipeline();
        assert_eq!(
            p,
            [
                TreeStage::ScoutCreatesTree,
                TreeStage::CpuStoresBitPacked,
                TreeStage::OracleVerifiesChunks,
                TreeStage::CpuCommitsPath
            ]
        );
        for (i, s) in p.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn stage_actions_are_verbatim() {
        assert_eq!(
            TreeStage::ScoutCreatesTree.action(),
            "3090 creates speculative tree"
        );
        assert_eq!(
            TreeStage::OracleVerifiesChunks.action(),
            "Blackwell verifies tree chunks"
        );
        assert_eq!(
            TreeStage::CpuCommitsPath.action(),
            "CPU commits accepted path"
        );
    }

    #[test]
    fn cpu_tree_ops_are_verbatim_five() {
        assert_eq!(CPU_TREE_OPS.len(), 5);
        assert_eq!(CPU_TREE_OPS[0], "filter invalid nodes");
        assert_eq!(CPU_TREE_OPS[4], "track accepted subtree");
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "It is branch-predicted cognition.");
    }
}
