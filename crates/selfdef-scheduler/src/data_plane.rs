//! `data_plane` — the CPU deterministic data plane (MS048).
//!
//! Encodes the avx-plus-plus dump's **"New Layer: Deterministic Data Plane"**
//! verbatim (dump lines 2268-2296). Beyond scheduling model branches, the CPU
//! owns a high-speed data plane of deterministic operations; the dump's
//! thesis: *"Text is payload. Bits are law."*
//!
//! The eight data-plane operations (dump 2272-2279):
//!
//! ```text
//! JSON/tool-call validation / regex/policy matching / memory-set
//! intersection / token mask fusion / duplicate detection / branch
//! compaction / context filtering / trace/replay indexing
//! ```
//!
//! The eight hot objects the data plane operates on — *not* text (dump
//! 2290-2298):
//!
//! ```text
//! bitsets / masks / branch ids / token classes / memory ids /
//! permission flags / grammar states / routing states
//! ```
//!
//! These operations realize the data side of the [`crate::runtime_shape`]
//! engines (e.g. JSON/tool-call validation feeds the Grammar Engine + Tool
//! Gate; memory-set intersection + trace/replay indexing feed the Memory
//! Router + Replay Log). Every op, object, and doctrine is verbatim — none
//! invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump line 2298, verbatim).
pub const DOCTRINE: &str = "Text is payload. Bits are law.";

/// The eight hot objects the data plane operates on (dump 2290-2298, verbatim).
pub const HOT_OBJECTS: [&str; 8] = [
    "bitsets",
    "masks",
    "branch ids",
    "token classes",
    "memory ids",
    "permission flags",
    "grammar states",
    "routing states",
];

/// The eight CPU deterministic data-plane operations (dump 2272-2279).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataPlaneOp {
    /// JSON/tool-call validation.
    JsonToolCallValidation,
    /// regex/policy matching.
    RegexPolicyMatching,
    /// memory-set intersection.
    MemorySetIntersection,
    /// token mask fusion.
    TokenMaskFusion,
    /// duplicate detection.
    DuplicateDetection,
    /// branch compaction.
    BranchCompaction,
    /// context filtering.
    ContextFiltering,
    /// trace/replay indexing.
    TraceReplayIndexing,
}

impl DataPlaneOp {
    /// The verbatim operation name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JsonToolCallValidation => "JSON/tool-call validation",
            Self::RegexPolicyMatching => "regex/policy matching",
            Self::MemorySetIntersection => "memory-set intersection",
            Self::TokenMaskFusion => "token mask fusion",
            Self::DuplicateDetection => "duplicate detection",
            Self::BranchCompaction => "branch compaction",
            Self::ContextFiltering => "context filtering",
            Self::TraceReplayIndexing => "trace/replay indexing",
        }
    }
}

/// All eight operations in dump order.
#[must_use]
pub fn all_ops() -> [DataPlaneOp; 8] {
    [
        DataPlaneOp::JsonToolCallValidation,
        DataPlaneOp::RegexPolicyMatching,
        DataPlaneOp::MemorySetIntersection,
        DataPlaneOp::TokenMaskFusion,
        DataPlaneOp::DuplicateDetection,
        DataPlaneOp::BranchCompaction,
        DataPlaneOp::ContextFiltering,
        DataPlaneOp::TraceReplayIndexing,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_ops_with_verbatim_names() {
        let ops = all_ops();
        assert_eq!(ops.len(), 8);
        assert_eq!(ops[0].name(), "JSON/tool-call validation");
        assert_eq!(ops[7].name(), "trace/replay indexing");
        assert_eq!(
            DataPlaneOp::MemorySetIntersection.name(),
            "memory-set intersection"
        );
    }

    #[test]
    fn eight_hot_objects_verbatim() {
        assert_eq!(HOT_OBJECTS.len(), 8);
        assert_eq!(HOT_OBJECTS[0], "bitsets");
        assert_eq!(HOT_OBJECTS[7], "routing states");
        assert!(HOT_OBJECTS.contains(&"permission flags"));
    }

    #[test]
    fn ops_are_distinct() {
        let ops = all_ops();
        for i in 0..8 {
            for j in (i + 1)..8 {
                assert_ne!(ops[i], ops[j]);
                assert_ne!(ops[i].name(), ops[j].name());
            }
        }
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "Text is payload. Bits are law.");
    }

    #[test]
    fn serde_roundtrip() {
        for op in all_ops() {
            let j = serde_json::to_string(&op).unwrap();
            let back: DataPlaneOp = serde_json::from_str(&j).unwrap();
            assert_eq!(op, back);
        }
    }
}
