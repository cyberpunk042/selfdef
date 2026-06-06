//! `scheduler_reactions` — reactive feedback loop (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Scheduler Should React"** feedback
//! table verbatim (dump lines 3158-3183). Where
//! [`crate::backpressure_response`] reacts to *hardware* surfaces (PSI / VRAM /
//! queue), this reacts to *scheduler-internal* derived signals — oracle
//! idleness, draft acceptance rate, grammar-mask time, tool-rejection rate.
//! The dump calls it *"the real AI DevOps layer."*
//!
//! ```text
//! if oracle_idle_ms > threshold:        increase branch packing /
//!                                       lower scout confidence threshold /
//!                                       prefetch likely KV blocks
//! if oracle_vram_pressure high:         reduce active branches /
//!                                       evict low-heat KV /
//!                                       lower max context for scout-generated branches
//! if draft_acceptance_rate low:         reduce speculation depth /
//!                                       switch draft model /
//!                                       use n-gram/suffix speculation instead
//! if grammar_mask_time high:            cache masks by grammar state /
//!                                       reduce structured branches per tick /
//!                                       relax structure until final output
//! if tool_rejection_rate high:          route more planning to oracle /
//!                                       tighten prompt/tool schema
//! ```
//!
//! Every trigger + response action is verbatim — none invented (operator rule:
//! "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Operator doctrine (dump line 3185, verbatim).
pub const DOCTRINE: &str = "This is the real \"AI DevOps\" layer.";

/// The five scheduler-internal feedback triggers (dump 3162-3182).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReactionTrigger {
    /// `oracle_idle_ms > threshold`.
    OracleIdle,
    /// `oracle_vram_pressure high`.
    OracleVramPressure,
    /// `draft_acceptance_rate low`.
    DraftAcceptanceLow,
    /// `grammar_mask_time high`.
    GrammarMaskTimeHigh,
    /// `tool_rejection_rate high`.
    ToolRejectionHigh,
}

impl ReactionTrigger {
    /// The verbatim response actions for this trigger (dump 3163-3182).
    #[must_use]
    pub const fn responses(self) -> &'static [&'static str] {
        match self {
            Self::OracleIdle => &[
                "increase branch packing",
                "lower scout confidence threshold",
                "prefetch likely KV blocks",
            ],
            Self::OracleVramPressure => &[
                "reduce active branches",
                "evict low-heat KV",
                "lower max context for scout-generated branches",
            ],
            Self::DraftAcceptanceLow => &[
                "reduce speculation depth",
                "switch draft model",
                "use n-gram/suffix speculation instead",
            ],
            Self::GrammarMaskTimeHigh => &[
                "cache masks by grammar state",
                "reduce structured branches per tick",
                "relax structure until final output",
            ],
            Self::ToolRejectionHigh => &[
                "route more planning to oracle",
                "tighten prompt/tool schema",
            ],
        }
    }
}

/// All five triggers in dump order.
#[must_use]
pub fn all_triggers() -> [ReactionTrigger; 5] {
    [
        ReactionTrigger::OracleIdle,
        ReactionTrigger::OracleVramPressure,
        ReactionTrigger::DraftAcceptanceLow,
        ReactionTrigger::GrammarMaskTimeHigh,
        ReactionTrigger::ToolRejectionHigh,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_trigger_has_responses() {
        for t in all_triggers() {
            assert!(!t.responses().is_empty(), "{t:?} has no responses");
        }
    }

    #[test]
    fn oracle_idle_responses_verbatim() {
        assert_eq!(
            ReactionTrigger::OracleIdle.responses(),
            &[
                "increase branch packing",
                "lower scout confidence threshold",
                "prefetch likely KV blocks"
            ]
        );
    }

    #[test]
    fn draft_acceptance_low_switches_speculation() {
        let r = ReactionTrigger::DraftAcceptanceLow.responses();
        assert!(r.contains(&"reduce speculation depth"));
        assert!(r.contains(&"use n-gram/suffix speculation instead"));
    }

    #[test]
    fn tool_rejection_routes_to_oracle() {
        assert!(
            ReactionTrigger::ToolRejectionHigh
                .responses()
                .contains(&"route more planning to oracle")
        );
    }

    #[test]
    fn five_distinct_triggers() {
        let all = all_triggers();
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for t in all_triggers() {
            let j = serde_json::to_string(&t).unwrap();
            let back: ReactionTrigger = serde_json::from_str(&j).unwrap();
            assert_eq!(t, back);
        }
    }
}
