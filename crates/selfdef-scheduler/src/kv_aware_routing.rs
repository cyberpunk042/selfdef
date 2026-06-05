//! `kv_aware_routing` — cache-aware routing request descriptor (MS048).
//!
//! Encodes the avx-plus-plus dump's **"KV-Aware Routing"** verbatim (dump lines
//! 4787-4810). The dump's optimization: *"the CPU routes based on cache, not
//! just load."* The scheduler asks five questions and the request carries six
//! fields so a request can be routed to whichever server already has its prefix
//! hot. Complements [`crate::tool_schema_kv`] (content addressing) and
//! [`crate::kv_cache_controller`] (the cache hierarchy).
//!
//! The five questions the scheduler asks (dump 4793-4798):
//!
//! ```text
//! Which server already has this prefix hot?
//! Which model has matching tokenizer?
//! Which KV blocks are reusable?
//! Which branch shares parent context?
//! Which context block is expensive to rebuild?
//! ```
//!
//! The six fields a request carries (dump 4802-4808):
//!
//! ```text
//! model_id / tokenizer_id / prompt_hashes / kv_ref_candidates /
//! branch_parent / cache_policy
//! ```
//!
//! Every question + field is verbatim — none invented (operator rule: "you
//! cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Doctrine (dump 4810, verbatim).
pub const DOCTRINE: &str = "the CPU routes based on cache, not just load.";

/// The five cache-aware routing questions (dump 4793-4798, verbatim).
pub const ROUTING_QUESTIONS: [&str; 5] = [
    "Which server already has this prefix hot?",
    "Which model has matching tokenizer?",
    "Which KV blocks are reusable?",
    "Which branch shares parent context?",
    "Which context block is expensive to rebuild?",
];

/// The six fields a cache-aware routing request carries (dump 4802-4808).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvRoutingRequest {
    /// `model_id`.
    pub model_id: String,
    /// `tokenizer_id`.
    pub tokenizer_id: String,
    /// `prompt_hashes` — content hashes of the prompt blocks.
    pub prompt_hashes: Vec<u64>,
    /// `kv_ref_candidates` — KV blocks that might already be resident.
    pub kv_ref_candidates: Vec<u64>,
    /// `branch_parent` — parent branch id (for shared-context routing), if any.
    pub branch_parent: Option<u64>,
    /// `cache_policy` — the cache-admission policy tag.
    pub cache_policy: String,
}

impl KvRoutingRequest {
    /// Whether this request shares any prompt-hash with `resident` (a server's
    /// resident hot prefixes) — answers "Which server already has this prefix
    /// hot?". Routing prefers a server with overlap (cache, not just load).
    #[must_use]
    pub fn prefix_overlap(&self, resident: &[u64]) -> bool {
        self.prompt_hashes.iter().any(|h| resident.contains(h))
    }

    /// Whether this request can reuse any of `resident_kv` (answers "Which KV
    /// blocks are reusable?").
    #[must_use]
    pub fn has_reusable_kv(&self, resident_kv: &[u64]) -> bool {
        self.kv_ref_candidates.iter().any(|k| resident_kv.contains(k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> KvRoutingRequest {
        KvRoutingRequest {
            model_id: "ling-2.6".into(),
            tokenizer_id: "tok-v1".into(),
            prompt_hashes: vec![1, 2, 3],
            kv_ref_candidates: vec![10, 20],
            branch_parent: Some(7),
            cache_policy: "project_base".into(),
        }
    }

    #[test]
    fn five_questions_verbatim() {
        assert_eq!(ROUTING_QUESTIONS.len(), 5);
        assert_eq!(ROUTING_QUESTIONS[0], "Which server already has this prefix hot?");
        assert_eq!(ROUTING_QUESTIONS[4], "Which context block is expensive to rebuild?");
    }

    #[test]
    fn request_carries_six_fields() {
        let r = req();
        assert_eq!(r.model_id, "ling-2.6");
        assert_eq!(r.tokenizer_id, "tok-v1");
        assert_eq!(r.prompt_hashes, vec![1, 2, 3]);
        assert_eq!(r.kv_ref_candidates, vec![10, 20]);
        assert_eq!(r.branch_parent, Some(7));
        assert_eq!(r.cache_policy, "project_base");
    }

    #[test]
    fn prefix_overlap_detects_hot_server() {
        let r = req();
        assert!(r.prefix_overlap(&[99, 2, 50])); // shares hash 2
        assert!(!r.prefix_overlap(&[99, 50, 60]));
    }

    #[test]
    fn reusable_kv_detected() {
        let r = req();
        assert!(r.has_reusable_kv(&[20, 30])); // shares kv 20
        assert!(!r.has_reusable_kv(&[30, 40]));
    }

    #[test]
    fn doctrine_verbatim() {
        assert_eq!(DOCTRINE, "the CPU routes based on cache, not just load.");
    }

    #[test]
    fn serde_roundtrip() {
        let r = req();
        let j = serde_json::to_string(&r).unwrap();
        let back: KvRoutingRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
