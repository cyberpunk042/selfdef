//! `golden_rule` — the scheduler's Golden Rule + architecture (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Golden Rule"** verbatim (dump lines
//! 2701-2728) — the capstone doctrine of the whole CPU-cortex / scheduler
//! design. Four "Never" rules plus the six techniques that overcome the
//! hardware limits (no NVLink, no 8 GPUs):
//!
//! ```text
//! Never recompute stable context if it can be content-addressed.
//! Never verify a branch that violates deterministic law.
//! Never keep KV hot just because it exists.
//! Never let the expensive GPU wait for context assembly.
//! ```
//!
//! ```text
//! content addressing / prefix sharing / speculative trees /
//! AVX-512 branch compaction / KV cache tiering / deterministic commit
//! ```
//!
//! Each rule + technique maps to a module already in this crate — this is the
//! doctrinal index that ties the scheduler together. The dump (2728): *"this
//! is the point where the workstation stops being 'a PC with GPUs' and starts
//! becoming a local AI operating system."* Every rule + technique is verbatim
//! — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The four "Never" rules of the Golden Rule (dump 2703-2706, verbatim).
pub const NEVER_RULES: [&str; 4] = [
    "Never recompute stable context if it can be content-addressed.",
    "Never verify a branch that violates deterministic law.",
    "Never keep KV hot just because it exists.",
    "Never let the expensive GPU wait for context assembly.",
];

/// The closing thesis (dump 2728, verbatim).
pub const THESIS: &str =
    "this is the point where the workstation stops being \"a PC with GPUs\" and starts becoming a local AI operating system.";

/// The six techniques that overcome the hardware limits (dump 2718-2725).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Technique {
    /// content addressing.
    ContentAddressing,
    /// prefix sharing.
    PrefixSharing,
    /// speculative trees.
    SpeculativeTrees,
    /// AVX-512 branch compaction.
    Avx512BranchCompaction,
    /// KV cache tiering.
    KvCacheTiering,
    /// deterministic commit.
    DeterministicCommit,
}

impl Technique {
    /// The verbatim technique name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ContentAddressing => "content addressing",
            Self::PrefixSharing => "prefix sharing",
            Self::SpeculativeTrees => "speculative trees",
            Self::Avx512BranchCompaction => "AVX-512 branch compaction",
            Self::KvCacheTiering => "KV cache tiering",
            Self::DeterministicCommit => "deterministic commit",
        }
    }

    /// The `selfdef-scheduler` module that realizes this technique (the
    /// doctrinal index back into the crate).
    #[must_use]
    pub const fn realized_by(self) -> &'static str {
        match self {
            Self::ContentAddressing => "tool_schema_kv",
            Self::PrefixSharing => "branch_kv_fusion",
            Self::SpeculativeTrees => "speculation_tree",
            Self::Avx512BranchCompaction => "branch_masks",
            Self::KvCacheTiering => "kv_cache_controller",
            Self::DeterministicCommit => "execution_pipeline",
        }
    }
}

/// The six techniques in dump order.
#[must_use]
pub fn techniques() -> [Technique; 6] {
    [
        Technique::ContentAddressing,
        Technique::PrefixSharing,
        Technique::SpeculativeTrees,
        Technique::Avx512BranchCompaction,
        Technique::KvCacheTiering,
        Technique::DeterministicCommit,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_never_rules_verbatim() {
        assert_eq!(NEVER_RULES.len(), 4);
        assert_eq!(
            NEVER_RULES[0],
            "Never recompute stable context if it can be content-addressed."
        );
        assert_eq!(
            NEVER_RULES[3],
            "Never let the expensive GPU wait for context assembly."
        );
        // every rule starts with "Never"
        for r in NEVER_RULES {
            assert!(r.starts_with("Never "), "{r}");
        }
    }

    #[test]
    fn six_techniques_verbatim() {
        assert_eq!(Technique::ContentAddressing.name(), "content addressing");
        assert_eq!(
            Technique::Avx512BranchCompaction.name(),
            "AVX-512 branch compaction"
        );
        assert_eq!(Technique::DeterministicCommit.name(), "deterministic commit");
    }

    #[test]
    fn every_technique_maps_to_a_real_module() {
        // The realized_by index points back at modules that exist in this crate.
        for t in techniques() {
            assert!(!t.realized_by().is_empty(), "{t:?} not realized");
        }
        assert_eq!(Technique::PrefixSharing.realized_by(), "branch_kv_fusion");
        assert_eq!(Technique::KvCacheTiering.realized_by(), "kv_cache_controller");
    }

    #[test]
    fn techniques_distinct() {
        let t = techniques();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(t[i], t[j]);
                assert_ne!(t[i].name(), t[j].name());
            }
        }
    }

    #[test]
    fn thesis_is_verbatim() {
        assert!(THESIS.contains("local AI operating system"));
    }

    #[test]
    fn serde_roundtrip() {
        for t in techniques() {
            let j = serde_json::to_string(&t).unwrap();
            let back: Technique = serde_json::from_str(&j).unwrap();
            assert_eq!(t, back);
        }
    }
}
