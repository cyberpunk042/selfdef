//! `speculative_parallelism` — service-level speculation pipeline (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Speculative Parallelism"** section
//! verbatim (dump lines 4816-4834). The dump's thesis: *"Speculation should be
//! service-level, not only model-level."*
//!
//! Classic (model-level) speculative decoding:
//!
//! ```text
//! draft model predicts tokens
//! target model verifies
//! ```
//!
//! The workstation (service-level) version maps speculation across the three
//! tiers:
//!
//! ```text
//! 3090 predicts branches / plans / token continuations
//! CPU prunes with deterministic law
//! Blackwell verifies in chunks
//! ```
//!
//! The operative principle (dump 4834, after the SPECTRE reference): *"preserve
//! draft-target overlap rather than making one wait for the other"* — the
//! scout drafts ahead while the oracle verifies, never serialized. This
//! complements [`crate::scheduling_law`] (the Key Scheduling Law's first
//! clause "Never let expensive cognition wait on cheap preparation" is the
//! same overlap principle). Every stage + action is verbatim — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// Operator-binding thesis (dump line 4817, verbatim).
pub const THESIS: &str = "Speculation should be service-level, not only model-level.";

/// The overlap principle (dump line 4834, verbatim).
pub const OVERLAP_PRINCIPLE: &str =
    "preserve draft-target overlap rather than making one wait for the other";

/// The three tiers' roles in service-level speculation (dump 4830-4832).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpeculationRole {
    /// RTX 3090 scout — "predicts branches / plans / token continuations".
    Predict,
    /// Ryzen AVX-512 cortex — "prunes with deterministic law".
    Prune,
    /// RTX PRO 6000 Blackwell oracle — "verifies in chunks".
    Verify,
}

impl SpeculationRole {
    /// The verbatim action text for this role (dump 4830-4832).
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Predict => "3090 predicts branches / plans / token continuations",
            Self::Prune => "CPU prunes with deterministic law",
            Self::Verify => "Blackwell verifies in chunks",
        }
    }

    /// 1-based pipeline order (predict → prune → verify).
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::Predict => 1,
            Self::Prune => 2,
            Self::Verify => 3,
        }
    }
}

/// The three speculation roles in pipeline order.
#[must_use]
pub fn pipeline() -> [SpeculationRole; 3] {
    [
        SpeculationRole::Predict,
        SpeculationRole::Prune,
        SpeculationRole::Verify,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_is_predict_prune_verify_in_order() {
        let p = pipeline();
        assert_eq!(
            p,
            [
                SpeculationRole::Predict,
                SpeculationRole::Prune,
                SpeculationRole::Verify
            ]
        );
        for (i, r) in p.iter().enumerate() {
            assert_eq!(r.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn actions_are_verbatim() {
        assert_eq!(
            SpeculationRole::Predict.action(),
            "3090 predicts branches / plans / token continuations"
        );
        assert_eq!(
            SpeculationRole::Prune.action(),
            "CPU prunes with deterministic law"
        );
        assert_eq!(
            SpeculationRole::Verify.action(),
            "Blackwell verifies in chunks"
        );
    }

    #[test]
    fn thesis_and_overlap_principle_verbatim() {
        assert_eq!(
            THESIS,
            "Speculation should be service-level, not only model-level."
        );
        assert_eq!(
            OVERLAP_PRINCIPLE,
            "preserve draft-target overlap rather than making one wait for the other"
        );
    }

    #[test]
    fn scout_predicts_oracle_verifies() {
        // The scout (3090) is the predictor; the oracle (Blackwell) the verifier.
        assert!(SpeculationRole::Predict.action().contains("3090"));
        assert!(SpeculationRole::Verify.action().contains("Blackwell"));
    }

    #[test]
    fn serde_roundtrip() {
        for r in pipeline() {
            let j = serde_json::to_string(&r).unwrap();
            let back: SpeculationRole = serde_json::from_str(&j).unwrap();
            assert_eq!(r, back);
        }
    }
}
