//! `branch_kv_fusion` — branch / KV-cache ownership + prefix sharing (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Branch + KV Cache Fusion"** section
//! verbatim (dump lines 2608-2642). It fuses the branch model
//! ([`crate::branch_masks`]) with the KV/context model
//! ([`crate::kv_context_scheduling`]): every branch knows which KV blocks it
//! owns or shares. The dump: *"Every branch should know which KV blocks it
//! owns or shares:"*
//!
//! ```text
//! branch_id
//! parent_branch_id
//! kv_prefix_ref
//! kv_delta_ref
//! control_word
//! budget
//! score
//! ```
//!
//! *"When a branch forks, it shares prefix KV. Only the delta changes."* —
//! sibling branches share their parent's `kv_prefix_ref` and each carry their
//! own `kv_delta_ref`. The CPU detects prefix sharing with hashes/bitsets
//! before asking the GPU. The dump's superpower line: *"many branches, shared
//! context, deterministic commit."* Every field is verbatim — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Operator superpower line (dump line 2642, verbatim).
pub const DOCTRINE: &str = "many branches, shared context, deterministic commit";

/// A branch's KV-ownership record (dump 2614-2620, verbatim field set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchKvRecord {
    /// `branch_id`.
    pub branch_id: u64,
    /// `parent_branch_id` — `None` for the root branch.
    pub parent_branch_id: Option<u64>,
    /// `kv_prefix_ref` — shared prefix KV (system + tools + project + parent plan).
    pub kv_prefix_ref: u64,
    /// `kv_delta_ref` — this branch's own KV delta.
    pub kv_delta_ref: u64,
    /// `control_word` — packed control bits.
    pub control_word: u64,
    /// `budget`.
    pub budget: i64,
    /// `score`.
    pub score: u16,
}

impl BranchKvRecord {
    /// A root branch: no parent, its prefix is the root KV (system+tools+project).
    #[must_use]
    pub const fn root(branch_id: u64, kv_prefix_ref: u64, budget: i64) -> Self {
        Self {
            branch_id,
            parent_branch_id: None,
            kv_prefix_ref,
            kv_delta_ref: 0,
            control_word: 0,
            budget,
            score: 0,
        }
    }

    /// Fork a child branch. Per the dump: *"it shares prefix KV. Only the delta
    /// changes."* The child inherits the parent's `kv_prefix_ref` and budget,
    /// records the parent id, and carries its own `kv_delta_ref`.
    #[must_use]
    pub const fn fork(&self, child_branch_id: u64, child_kv_delta_ref: u64) -> Self {
        Self {
            branch_id: child_branch_id,
            parent_branch_id: Some(self.branch_id),
            kv_prefix_ref: self.kv_prefix_ref, // shared prefix
            kv_delta_ref: child_kv_delta_ref,  // only the delta changes
            control_word: self.control_word,
            budget: self.budget,
            score: 0,
        }
    }

    /// Whether two branches share a prefix (the CPU's pre-GPU prefix-sharing
    /// check, done by comparing `kv_prefix_ref`).
    #[must_use]
    pub const fn shares_prefix_with(&self, other: &BranchKvRecord) -> bool {
        self.kv_prefix_ref == other.kv_prefix_ref
    }

    /// `true` for the root branch (no parent).
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.parent_branch_id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_no_parent_and_zero_delta() {
        let r = BranchKvRecord::root(1, 0xABCD, 1000);
        assert!(r.is_root());
        assert_eq!(r.parent_branch_id, None);
        assert_eq!(r.kv_delta_ref, 0);
        assert_eq!(r.kv_prefix_ref, 0xABCD);
    }

    #[test]
    fn fork_shares_prefix_changes_only_delta() {
        let root = BranchKvRecord::root(1, 0xABCD, 1000);
        let a = root.fork(2, 0x1111);
        let b = root.fork(3, 0x2222);
        // shared prefix
        assert_eq!(a.kv_prefix_ref, root.kv_prefix_ref);
        assert_eq!(b.kv_prefix_ref, root.kv_prefix_ref);
        // distinct deltas
        assert_ne!(a.kv_delta_ref, b.kv_delta_ref);
        // parentage
        assert_eq!(a.parent_branch_id, Some(1));
        assert_eq!(b.parent_branch_id, Some(1));
        assert!(!a.is_root());
    }

    #[test]
    fn siblings_share_prefix() {
        let root = BranchKvRecord::root(1, 0xABCD, 1000);
        let a = root.fork(2, 0x1111);
        let b = root.fork(3, 0x2222);
        assert!(a.shares_prefix_with(&b));
        assert!(a.shares_prefix_with(&root));
    }

    #[test]
    fn branches_with_different_prefixes_do_not_share() {
        let a = BranchKvRecord::root(1, 0xAAAA, 100);
        let c = BranchKvRecord::root(2, 0xCCCC, 100);
        assert!(!a.shares_prefix_with(&c));
    }

    #[test]
    fn fork_inherits_budget_and_resets_score() {
        let root = BranchKvRecord::root(1, 0xABCD, 777);
        let child = root.fork(2, 0x1111);
        assert_eq!(child.budget, 777);
        assert_eq!(child.score, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let root = BranchKvRecord::root(1, 0xABCD, 1000);
        let child = root.fork(2, 0x1111);
        for r in [root, child] {
            let j = serde_json::to_string(&r).unwrap();
            let back: BranchKvRecord = serde_json::from_str(&j).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(
            DOCTRINE,
            "many branches, shared context, deterministic commit"
        );
    }
}
