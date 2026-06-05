//! `memory_scheduling` — M01153: staged memory-retrieval pipeline.
//!
//! Encodes the avx-plus-plus dump's **"Memory Scheduling"** stage list
//! verbatim (dump lines 18140-18152), inside the Goldilocks scheduler
//! section. The dump: *"Memory retrieval should be staged:"*
//!
//! ```text
//! 1. metadata bitset filter
//! 2. sketch/popcount relevance
//! 3. embedding/rerank
//! 4. graph expansion
//! 5. oracle synthesis only if needed
//! ```
//!
//! followed by the doctrine *"Do not throw every memory query at a model."*
//!
//! The pipeline is cheapest-first: the two deterministic CPU stages (metadata
//! bitset, sketch/popcount) filter before any model is touched; the embedding/
//! rerank and oracle-synthesis stages — the ones that *"throw the query at a
//! model"* — come later, and oracle synthesis runs only when the cheaper
//! stages did not resolve the query (*"only if needed"*). No stage is invented;
//! each maps to one numbered dump line (operator rule: "you cannot invent
//! crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Operator-binding doctrine for this pipeline (dump line 18152, verbatim).
pub const DOCTRINE: &str = "Do not throw every memory query at a model.";

/// The five ordered memory-retrieval stages (dump 18145-18149).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryStage {
    /// 1. metadata bitset filter (deterministic CPU bitset intersect).
    MetadataBitsetFilter,
    /// 2. sketch/popcount relevance (deterministic CPU, AVX popcount).
    SketchPopcountRelevance,
    /// 3. embedding/rerank (model: embedding + reranker).
    EmbeddingRerank,
    /// 4. graph expansion (deterministic memory-graph walk).
    GraphExpansion,
    /// 5. oracle synthesis only if needed (model: oracle; conditional).
    OracleSynthesis,
}

impl MemoryStage {
    /// 1-based stage order per the dump's numbered list.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::MetadataBitsetFilter => 1,
            Self::SketchPopcountRelevance => 2,
            Self::EmbeddingRerank => 3,
            Self::GraphExpansion => 4,
            Self::OracleSynthesis => 5,
        }
    }

    /// Whether the stage "throws the query at a model" (embedding/rerank or
    /// oracle synthesis). The deterministic stages (1, 2, 4) do not.
    #[must_use]
    pub const fn uses_model(self) -> bool {
        matches!(self, Self::EmbeddingRerank | Self::OracleSynthesis)
    }

    /// Whether the stage runs only when cheaper stages did not resolve the
    /// query (dump: "oracle synthesis only if needed").
    #[must_use]
    pub const fn is_conditional(self) -> bool {
        matches!(self, Self::OracleSynthesis)
    }
}

/// The five stages in dump order (the canonical retrieval pipeline).
#[must_use]
pub fn stages_in_order() -> [MemoryStage; 5] {
    [
        MemoryStage::MetadataBitsetFilter,
        MemoryStage::SketchPopcountRelevance,
        MemoryStage::EmbeddingRerank,
        MemoryStage::GraphExpansion,
        MemoryStage::OracleSynthesis,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_are_in_ascending_dump_order() {
        let stages = stages_in_order();
        for (i, s) in stages.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8, "{s:?} out of order");
        }
    }

    #[test]
    fn deterministic_stages_precede_first_model_stage() {
        // Per "Do not throw every memory query at a model": the cheap
        // deterministic stages must come before the first model stage.
        let first_model_order = stages_in_order()
            .iter()
            .filter(|s| s.uses_model())
            .map(|s| s.order())
            .min()
            .unwrap();
        // stages 1 and 2 are deterministic and precede the first model stage (3).
        assert_eq!(first_model_order, 3);
        assert!(!MemoryStage::MetadataBitsetFilter.uses_model());
        assert!(!MemoryStage::SketchPopcountRelevance.uses_model());
    }

    #[test]
    fn only_oracle_synthesis_is_conditional() {
        for s in stages_in_order() {
            assert_eq!(
                s.is_conditional(),
                s == MemoryStage::OracleSynthesis,
                "{s:?} conditional flag wrong"
            );
        }
    }

    #[test]
    fn model_stages_are_embedding_and_oracle() {
        let model: Vec<MemoryStage> =
            stages_in_order().into_iter().filter(|s| s.uses_model()).collect();
        assert_eq!(
            model,
            vec![MemoryStage::EmbeddingRerank, MemoryStage::OracleSynthesis]
        );
    }

    #[test]
    fn doctrine_is_verbatim() {
        assert_eq!(DOCTRINE, "Do not throw every memory query at a model.");
    }

    #[test]
    fn serde_roundtrip() {
        for s in stages_in_order() {
            let j = serde_json::to_string(&s).unwrap();
            let back: MemoryStage = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
