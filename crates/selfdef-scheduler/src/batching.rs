//! `batching` — the executable batching rules + queue catalog (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Queue Design"** + **"Batching Rules"**
//! verbatim (dump lines 4845-4892). Unlike the pure doctrine catalogs, the
//! batching rules are *executable*: [`can_batch`] implements the dump's
//! batch-if / do-not-batch-if predicates so the scheduler can decide, per pair,
//! whether two entries share a GPU batch — *"The CPU can decide this with
//! bitfields."*
//!
//! Batch together if (dump 4874-4881): same model / same tokenizer / same
//! output schema / compatible max tokens / similar context length / same cache
//! affinity. Do NOT batch if (dump 4883-4889): one is latency-critical and one
//! is huge / different grammar masks cause overhead / one has a high-risk tool
//! boundary / one will evict valuable KV.
//!
//! Queue catalog (dump 4847-4870): nine queues, each with six attributes.
//! Every queue + rule is verbatim; the only modelled choice is representing
//! "compatible max tokens" + "similar context length" as caller-assigned
//! buckets (same bucket = compatible), which avoids inventing a threshold —
//! the caller decides the bucketing (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The nine scheduler queues (dump 4849-4858).
pub const QUEUES: [&str; 9] = [
    "oracle_prefill_queue",
    "oracle_decode_queue",
    "oracle_verify_queue",
    "scout_draft_queue",
    "scout_rerank_queue",
    "perception_queue",
    "embedding_queue",
    "tool_intent_queue",
    "human_gate_queue",
];

/// The six per-queue-entry attributes (dump 4862-4868).
pub const QUEUE_ATTRS: [&str; 6] = [
    "priority",
    "deadline",
    "batchability",
    "risk",
    "cache affinity",
    "model affinity",
];

/// The six "batch together if" rules (dump 4875-4881, verbatim).
pub const BATCH_IF: [&str; 6] = [
    "same model",
    "same tokenizer",
    "same output schema",
    "compatible max tokens",
    "similar context length",
    "same cache affinity",
];

/// The four "do not batch together if" rules (dump 4884-4889, verbatim).
pub const DO_NOT_BATCH_IF: [&str; 4] = [
    "one is latency critical and one is huge",
    "different grammar masks cause overhead",
    "one has high-risk tool boundary",
    "one will evict valuable KV",
];

/// A candidate entry for batching — the fields the dump's rules inspect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCandidate {
    /// Model id (batch-if "same model").
    pub model_id: String,
    /// Tokenizer id (batch-if "same tokenizer").
    pub tokenizer_id: String,
    /// Output schema id (batch-if "same output schema").
    pub output_schema: String,
    /// Max-tokens bucket (batch-if "compatible max tokens" = same bucket).
    pub max_tokens_bucket: u32,
    /// Context-length bucket (batch-if "similar context length" = same bucket).
    pub context_len_bucket: u32,
    /// Cache-affinity key (batch-if "same cache affinity").
    pub cache_affinity: u64,
    /// Grammar-mask id (do-not-batch "different grammar masks").
    pub grammar_mask: u64,
    /// `true` if latency-critical (do-not-batch with a huge one).
    pub latency_critical: bool,
    /// `true` if huge (do-not-batch with a latency-critical one).
    pub is_huge: bool,
    /// `true` if this entry crosses a high-risk tool boundary.
    pub high_risk_tool_boundary: bool,
    /// `true` if batching this entry would evict valuable KV.
    pub evicts_valuable_kv: bool,
}

/// Decide whether two candidates may share a GPU batch, per the dump's rules:
/// ALL six batch-if predicates must hold AND NONE of the four do-not-batch
/// predicates may hold.
#[must_use]
pub fn can_batch(a: &BatchCandidate, b: &BatchCandidate) -> bool {
    // batch-if: all six must hold
    let batchable = a.model_id == b.model_id
        && a.tokenizer_id == b.tokenizer_id
        && a.output_schema == b.output_schema
        && a.max_tokens_bucket == b.max_tokens_bucket // compatible max tokens
        && a.context_len_bucket == b.context_len_bucket // similar context length
        && a.cache_affinity == b.cache_affinity;
    if !batchable {
        return false;
    }
    // do-not-batch: any one forbids
    let forbidden = (a.latency_critical && b.is_huge)
        || (b.latency_critical && a.is_huge)
        || (a.grammar_mask != b.grammar_mask) // different grammar masks
        || a.high_risk_tool_boundary
        || b.high_risk_tool_boundary
        || a.evicts_valuable_kv
        || b.evicts_valuable_kv;
    !forbidden
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BatchCandidate {
        BatchCandidate {
            model_id: "ling-2.6".into(),
            tokenizer_id: "tok-v1".into(),
            output_schema: "PatchProposal".into(),
            max_tokens_bucket: 1,
            context_len_bucket: 2,
            cache_affinity: 42,
            grammar_mask: 7,
            latency_critical: false,
            is_huge: false,
            high_risk_tool_boundary: false,
            evicts_valuable_kv: false,
        }
    }

    #[test]
    fn catalog_sizes_match_dump() {
        assert_eq!(QUEUES.len(), 9);
        assert_eq!(QUEUE_ATTRS.len(), 6);
        assert_eq!(BATCH_IF.len(), 6);
        assert_eq!(DO_NOT_BATCH_IF.len(), 4);
        assert_eq!(QUEUES[0], "oracle_prefill_queue");
        assert_eq!(QUEUES[8], "human_gate_queue");
    }

    #[test]
    fn identical_compatible_candidates_batch() {
        assert!(can_batch(&base(), &base()));
    }

    #[test]
    fn different_model_does_not_batch() {
        let mut b = base();
        b.model_id = "nemotron-3".into();
        assert!(!can_batch(&base(), &b));
    }

    #[test]
    fn different_max_tokens_bucket_does_not_batch() {
        let mut b = base();
        b.max_tokens_bucket = 9;
        assert!(!can_batch(&base(), &b));
    }

    #[test]
    fn latency_critical_plus_huge_does_not_batch() {
        let mut a = base();
        a.latency_critical = true;
        let mut b = base();
        b.is_huge = true;
        assert!(!can_batch(&a, &b));
        // symmetric
        assert!(!can_batch(&b, &a));
    }

    #[test]
    fn different_grammar_masks_do_not_batch() {
        let mut b = base();
        b.grammar_mask = 99;
        assert!(!can_batch(&base(), &b));
    }

    #[test]
    fn high_risk_tool_boundary_blocks_batch() {
        let mut a = base();
        a.high_risk_tool_boundary = true;
        assert!(!can_batch(&a, &base()));
    }

    #[test]
    fn valuable_kv_eviction_blocks_batch() {
        let mut b = base();
        b.evicts_valuable_kv = true;
        assert!(!can_batch(&base(), &b));
    }

    #[test]
    fn serde_roundtrip() {
        let c = base();
        let j = serde_json::to_string(&c).unwrap();
        let back: BatchCandidate = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
