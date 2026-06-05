//! `kv_context_scheduling` — M01152: KV/context routing signals + preferences.
//!
//! Encodes the avx-plus-plus dump's **"KV/Context Scheduling"** section
//! verbatim (dump lines 18117-18138, Goldilocks scheduler section). The dump
//! opens *"This is important. Every model call has prefill/decode cost."* and
//! gives two lists.
//!
//! The five signals *"the scheduler should know"* (dump 18124-18130):
//!
//! ```text
//! is prefix cached?
//! is context already resident?
//! can this branch share parent context?
//! is the request decode-heavy or prefill-heavy?
//! will this evict valuable KV?
//! ```
//!
//! The four *"Routing should prefer"* preferences (dump 18134-18138):
//!
//! ```text
//! reuse hot context
//! avoid unnecessary prefill
//! batch similar context shapes
//! keep stable prefixes resident
//! ```
//!
//! [`KvContextSignals`] is the typed answer to the five questions;
//! [`routing_hint`] applies the verbatim preferences to those signals. Each
//! derived hint cites the preference it comes from — no preference invented
//! (operator rule: "you cannot invent crap"). "batch similar context shapes"
//! is a cross-request preference (needs sibling requests to compare), so it is
//! exposed as a documented constant rather than derived from one request.
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Whether a request is dominated by prefill or decode cost (dump:
/// "is the request decode-heavy or prefill-heavy?").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadShape {
    /// Prefill-heavy (large prompt, short generation).
    PrefillHeavy,
    /// Decode-heavy (short prompt, long generation).
    DecodeHeavy,
}

/// The five signals the scheduler should know before a model call
/// (dump 18124-18130).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvContextSignals {
    /// "is prefix cached?"
    pub prefix_cached: bool,
    /// "is context already resident?"
    pub context_resident: bool,
    /// "can this branch share parent context?"
    pub can_share_parent_context: bool,
    /// "is the request decode-heavy or prefill-heavy?"
    pub load_shape: LoadShape,
    /// "will this evict valuable KV?"
    pub will_evict_valuable_kv: bool,
}

/// The four verbatim routing preferences (dump 18134-18138).
pub const ROUTING_PREFERENCES: [&str; 4] = [
    "reuse hot context",
    "avoid unnecessary prefill",
    "batch similar context shapes",
    "keep stable prefixes resident",
];

/// The cross-request preference (dump: "batch similar context shapes") — not
/// derivable from a single request's signals; consumed by the batch planner
/// when grouping concurrent requests.
pub const BATCH_SIMILAR_CONTEXT_SHAPES: &str = "batch similar context shapes";

/// A routing hint derived from [`KvContextSignals`] by applying the verbatim
/// preferences. Every field cites the preference it comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvRoutingHint {
    /// "reuse hot context" + "avoid unnecessary prefill": prefer reusing the
    /// cached/resident context rather than re-prefilling.
    pub prefer_reuse: bool,
    /// "reuse hot context": this branch can share its parent's context.
    pub prefer_parent_share: bool,
    /// "keep stable prefixes resident": the context is resident and should be
    /// kept rather than evicted.
    pub keep_resident: bool,
    /// derived from "will this evict valuable KV?": routing should avoid a
    /// placement that evicts valuable KV.
    pub avoid_valuable_eviction: bool,
}

/// Apply the verbatim KV/context routing preferences to a request's signals.
#[must_use]
pub fn routing_hint(s: &KvContextSignals) -> KvRoutingHint {
    KvRoutingHint {
        // "reuse hot context" / "avoid unnecessary prefill"
        prefer_reuse: s.prefix_cached || s.context_resident,
        prefer_parent_share: s.can_share_parent_context,
        // "keep stable prefixes resident"
        keep_resident: s.context_resident,
        avoid_valuable_eviction: s.will_evict_valuable_kv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(
        prefix_cached: bool,
        context_resident: bool,
        can_share: bool,
        load: LoadShape,
        evict: bool,
    ) -> KvContextSignals {
        KvContextSignals {
            prefix_cached,
            context_resident,
            can_share_parent_context: can_share,
            load_shape: load,
            will_evict_valuable_kv: evict,
        }
    }

    #[test]
    fn cached_prefix_prefers_reuse() {
        let h = routing_hint(&signals(true, false, false, LoadShape::PrefillHeavy, false));
        assert!(h.prefer_reuse, "cached prefix should prefer reuse (avoid prefill)");
    }

    #[test]
    fn resident_context_prefers_reuse_and_keeps_resident() {
        let h = routing_hint(&signals(false, true, false, LoadShape::DecodeHeavy, false));
        assert!(h.prefer_reuse);
        assert!(h.keep_resident);
    }

    #[test]
    fn cold_request_does_not_prefer_reuse() {
        let h = routing_hint(&signals(false, false, false, LoadShape::PrefillHeavy, false));
        assert!(!h.prefer_reuse);
        assert!(!h.keep_resident);
    }

    #[test]
    fn parent_share_flows_through() {
        let h = routing_hint(&signals(false, false, true, LoadShape::DecodeHeavy, false));
        assert!(h.prefer_parent_share);
    }

    #[test]
    fn valuable_eviction_is_flagged() {
        let h = routing_hint(&signals(false, false, false, LoadShape::PrefillHeavy, true));
        assert!(h.avoid_valuable_eviction);
    }

    #[test]
    fn routing_preferences_are_verbatim() {
        assert_eq!(
            ROUTING_PREFERENCES,
            [
                "reuse hot context",
                "avoid unnecessary prefill",
                "batch similar context shapes",
                "keep stable prefixes resident",
            ]
        );
        assert!(ROUTING_PREFERENCES.contains(&BATCH_SIMILAR_CONTEXT_SHAPES));
    }

    #[test]
    fn serde_roundtrip() {
        let s = signals(true, true, true, LoadShape::DecodeHeavy, true);
        let j = serde_json::to_string(&s).unwrap();
        let back: KvContextSignals = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        let h = routing_hint(&s);
        let hj = serde_json::to_string(&h).unwrap();
        let hback: KvRoutingHint = serde_json::from_str(&hj).unwrap();
        assert_eq!(h, hback);
    }
}
