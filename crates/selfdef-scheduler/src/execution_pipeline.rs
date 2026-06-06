//! `execution_pipeline` — the runtime as a CPU pipeline (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Revolutionary Shape"** verbatim
//! (dump lines 2427-2453): *"The runtime should be closer to a CPU
//! pipeline."* Six stages, mirroring a CPU instruction pipeline, ending in
//! deterministic commit. Distinct from [`crate::request_lifecycle`] (the
//! request's 10-step flow) and [`crate::branch_lifecycle`] (the branch's
//! 8-stage transaction) — this is the *execution-engine* framing:
//!
//! ```text
//! Fetch:    user task, memory refs, branch state
//! Decode:   classify intent, grammar, route, permissions
//! Execute:  scout GPU drafts, tools prepare, memory retrieves
//! Validate: CPU masks, parses, scans, checks
//! Retire:   Blackwell verifies high-value transitions
//! Commit:   deterministic log writes accepted state
//! ```
//!
//! Tier assignment (dump 2449-2451, verbatim): *"The 3090 speculates. The RTX
//! PRO 6000 verifies. The AVX-512 CPU retires instructions of thought."* The
//! architecture is (dump 2453): **speculative AI execution with deterministic
//! commit.** Every stage + content is verbatim — none invented (operator rule:
//! "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The architecture in one line (dump 2453, verbatim).
pub const ARCHITECTURE: &str = "speculative AI execution with deterministic commit";

/// The six execution-pipeline stages (dump 2431-2451).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Fetch.
    Fetch,
    /// Decode.
    Decode,
    /// Execute.
    Execute,
    /// Validate.
    Validate,
    /// Retire.
    Retire,
    /// Commit.
    Commit,
}

impl PipelineStage {
    /// 1-based pipeline order.
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::Fetch => 1,
            Self::Decode => 2,
            Self::Execute => 3,
            Self::Validate => 4,
            Self::Retire => 5,
            Self::Commit => 6,
        }
    }

    /// The verbatim stage content.
    #[must_use]
    pub const fn content(self) -> &'static str {
        match self {
            Self::Fetch => "user task, memory refs, branch state",
            Self::Decode => "classify intent, grammar, route, permissions",
            Self::Execute => "scout GPU drafts, tools prepare, memory retrieves",
            Self::Validate => "CPU masks, parses, scans, checks",
            Self::Retire => "Blackwell verifies high-value transitions",
            Self::Commit => "deterministic log writes accepted state",
        }
    }
}

/// The six stages in pipeline order.
#[must_use]
pub fn pipeline() -> [PipelineStage; 6] {
    [
        PipelineStage::Fetch,
        PipelineStage::Decode,
        PipelineStage::Execute,
        PipelineStage::Validate,
        PipelineStage::Retire,
        PipelineStage::Commit,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_stages_in_order() {
        let p = pipeline();
        assert_eq!(p.len(), 6);
        for (i, s) in p.iter().enumerate() {
            assert_eq!(s.order(), (i + 1) as u8);
        }
    }

    #[test]
    fn stage_content_verbatim() {
        assert_eq!(
            PipelineStage::Fetch.content(),
            "user task, memory refs, branch state"
        );
        assert_eq!(
            PipelineStage::Retire.content(),
            "Blackwell verifies high-value transitions"
        );
        assert_eq!(
            PipelineStage::Commit.content(),
            "deterministic log writes accepted state"
        );
    }

    #[test]
    fn validate_precedes_retire_precedes_commit() {
        // The deterministic-commit discipline: validate (CPU) before retire
        // (oracle verify) before commit (log write).
        assert!(PipelineStage::Validate.order() < PipelineStage::Retire.order());
        assert!(PipelineStage::Retire.order() < PipelineStage::Commit.order());
    }

    #[test]
    fn architecture_is_verbatim() {
        assert_eq!(
            ARCHITECTURE,
            "speculative AI execution with deterministic commit"
        );
    }

    #[test]
    fn stages_distinct() {
        let p = pipeline();
        for i in 0..6 {
            for j in (i + 1)..6 {
                assert_ne!(p[i], p[j]);
                assert_ne!(p[i].content(), p[j].content());
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for s in pipeline() {
            let j = serde_json::to_string(&s).unwrap();
            let back: PipelineStage = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
