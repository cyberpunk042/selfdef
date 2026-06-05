//! `data_plane_services` — the 6 CPU data-plane runtime services (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Concrete Design Upgrade"** verbatim
//! (dump lines 2350-2375): the six services to add to the runtime. Where
//! [`crate::data_plane`] is the *operations* and [`crate::avx512_features`] is
//! the *instructions*, these are the *services* that compose them. The dump's
//! key phrase (2373, verbatim): *"The CPU should transform language into
//! constrained sets before GPUs reason over it."*
//!
//! ```text
//! 1. Token Law Engine     combines grammar/schema/tool/safety masks over vocab bitsets
//! 2. Policy Scanner        Hyperscan-style multi-pattern matching over tool intents and outputs
//! 3. JSON Commit Validator simdjson-style validation before any structured output is accepted
//! 4. Memory Bitmap Index   CRoaring-style memory sets: project ∩ topic ∩ freshness ∩ trust ∩ permissions
//! 5. Branch Compactor      AVX-512 compresses surviving branches into dense oracle/scout batches
//! 6. Replay Index          bitset/searchable trace log for debugging and self-improvement
//! ```
//!
//! Every service + description is verbatim — none invented (operator rule:
//! "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Key phrase (dump line 2373, verbatim).
pub const KEY_PHRASE: &str =
    "The CPU should transform language into constrained sets before GPUs reason over it.";

/// The Memory Bitmap Index intersection dimensions (dump 2364, verbatim):
/// `project ∩ topic ∩ freshness ∩ trust ∩ permissions`.
pub const MEMORY_SET_DIMENSIONS: [&str; 5] =
    ["project", "topic", "freshness", "trust", "permissions"];

/// The six data-plane runtime services (dump 2354-2371).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataPlaneService {
    /// 1. Token Law Engine.
    TokenLawEngine,
    /// 2. Policy Scanner.
    PolicyScanner,
    /// 3. JSON Commit Validator.
    JsonCommitValidator,
    /// 4. Memory Bitmap Index.
    MemoryBitmapIndex,
    /// 5. Branch Compactor.
    BranchCompactor,
    /// 6. Replay Index.
    ReplayIndex,
}

impl DataPlaneService {
    /// 1-based service number per the dump list.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::TokenLawEngine => 1,
            Self::PolicyScanner => 2,
            Self::JsonCommitValidator => 3,
            Self::MemoryBitmapIndex => 4,
            Self::BranchCompactor => 5,
            Self::ReplayIndex => 6,
        }
    }

    /// Verbatim service name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TokenLawEngine => "Token Law Engine",
            Self::PolicyScanner => "Policy Scanner",
            Self::JsonCommitValidator => "JSON Commit Validator",
            Self::MemoryBitmapIndex => "Memory Bitmap Index",
            Self::BranchCompactor => "Branch Compactor",
            Self::ReplayIndex => "Replay Index",
        }
    }

    /// Verbatim service description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::TokenLawEngine => {
                "combines grammar/schema/tool/safety masks over vocab bitsets"
            }
            Self::PolicyScanner => {
                "Hyperscan-style multi-pattern matching over tool intents and outputs"
            }
            Self::JsonCommitValidator => {
                "simdjson-style validation before any structured output is accepted"
            }
            Self::MemoryBitmapIndex => {
                "CRoaring-style memory sets: project ∩ topic ∩ freshness ∩ trust ∩ permissions"
            }
            Self::BranchCompactor => {
                "AVX-512 compresses surviving branches into dense oracle/scout batches"
            }
            Self::ReplayIndex => "bitset/searchable trace log for debugging and self-improvement",
        }
    }
}

/// All six services in dump order.
#[must_use]
pub fn all_services() -> [DataPlaneService; 6] {
    [
        DataPlaneService::TokenLawEngine,
        DataPlaneService::PolicyScanner,
        DataPlaneService::JsonCommitValidator,
        DataPlaneService::MemoryBitmapIndex,
        DataPlaneService::BranchCompactor,
        DataPlaneService::ReplayIndex,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_services_in_order() {
        let s = all_services();
        assert_eq!(s.len(), 6);
        for (i, svc) in s.iter().enumerate() {
            assert_eq!(svc.number(), (i + 1) as u8);
        }
    }

    #[test]
    fn service_names_verbatim() {
        assert_eq!(DataPlaneService::TokenLawEngine.name(), "Token Law Engine");
        assert_eq!(DataPlaneService::JsonCommitValidator.name(), "JSON Commit Validator");
        assert_eq!(DataPlaneService::ReplayIndex.name(), "Replay Index");
    }

    #[test]
    fn descriptions_verbatim() {
        assert_eq!(
            DataPlaneService::MemoryBitmapIndex.description(),
            "CRoaring-style memory sets: project ∩ topic ∩ freshness ∩ trust ∩ permissions"
        );
        assert!(DataPlaneService::BranchCompactor
            .description()
            .contains("AVX-512 compresses surviving branches"));
    }

    #[test]
    fn memory_set_dimensions_verbatim_five() {
        assert_eq!(
            MEMORY_SET_DIMENSIONS,
            ["project", "topic", "freshness", "trust", "permissions"]
        );
        // and they appear in the Memory Bitmap Index description
        let d = DataPlaneService::MemoryBitmapIndex.description();
        for dim in MEMORY_SET_DIMENSIONS {
            assert!(d.contains(dim), "description missing dimension {dim}");
        }
    }

    #[test]
    fn key_phrase_verbatim() {
        assert_eq!(
            KEY_PHRASE,
            "The CPU should transform language into constrained sets before GPUs reason over it."
        );
    }

    #[test]
    fn services_distinct() {
        let s = all_services();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(s[i], s[j]);
                assert_ne!(s[i].name(), s[j].name());
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for svc in all_services() {
            let j = serde_json::to_string(&svc).unwrap();
            let back: DataPlaneService = serde_json::from_str(&j).unwrap();
            assert_eq!(svc, back);
        }
    }
}
