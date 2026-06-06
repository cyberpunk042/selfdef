//! `tier_work_policy` — M01151: per-tier work-class admission policy.
//!
//! Encodes the avx-plus-plus dump's **"Blackwell Scheduling" / "3090
//! Scheduling" / "CPU AVX Scheduling"** sections verbatim (dump lines
//! 18043-18116, Goldilocks scheduler section). Each hardware tier has an
//! explicit work-class policy + a one-line doctrine:
//!
//! - **Blackwell (oracle)** — *"Protect it."* Accept: final synthesis / hard
//!   reasoning / high-risk verification / long-context parent calls / batch
//!   verification. Avoid: cheap classification / trivial rewrites / noisy
//!   branch expansion / repeated boilerplate prefill. Doctrine: *"Keep the
//!   Blackwell hot with meaningful work, not busy with junk."*
//! - **RTX 3090 (scout)** — *"Exploit it."* Use for: draft branches / small
//!   models / rerank / embeddings / vision-perception / tool-plan sketches /
//!   failure classification. Doctrine: *"The 3090 should work ahead."*
//! - **CPU AVX-512 (cortex)** — *"The CPU decides."* Hot operations: filter
//!   branches / score candidates / match memory / merge policy / detect
//!   duplicates / compress queues / apply budgets / compute route masks.
//!
//! The tiers map onto the [`crate::Route`] enum (Blackwell / Rtx3090 / Cpu).
//! This module is the WHAT-each-tier-should-run policy; the
//! [`crate::scheduling_law`] recommender is the WHICH-tier-for-this-request
//! decision. Every work class + doctrine is verbatim — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The three compute tiers (oracle / scout / cortex).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareTier {
    /// RTX PRO 6000 Blackwell — oracle.
    Blackwell,
    /// RTX 3090 — scout.
    Rtx3090,
    /// Ryzen 9900X AVX-512 — deterministic cortex.
    Cpu,
}

/// Blackwell ACCEPT work classes (dump 18047-18052).
pub const BLACKWELL_ACCEPT: [&str; 5] = [
    "final synthesis",
    "hard reasoning",
    "high-risk verification",
    "long-context parent calls",
    "batch verification",
];

/// Blackwell AVOID work classes (dump 18054-18058).
pub const BLACKWELL_AVOID: [&str; 4] = [
    "cheap classification",
    "trivial rewrites",
    "noisy branch expansion",
    "repeated boilerplate prefill",
];

/// RTX 3090 USE-FOR work classes (dump 18065-18072).
pub const RTX3090_USE_FOR: [&str; 7] = [
    "draft branches",
    "small models",
    "rerank",
    "embeddings",
    "vision/perception",
    "tool-plan sketches",
    "failure classification",
];

/// CPU AVX hot operations (dump 18092-18100).
pub const CPU_HOT_OPS: [&str; 8] = [
    "filter branches",
    "score candidates",
    "match memory",
    "merge policy",
    "detect duplicates",
    "compress queues",
    "apply budgets",
    "compute route masks",
];

/// Per-tier one-line doctrine (verbatim).
#[must_use]
pub const fn doctrine(tier: HardwareTier) -> &'static str {
    match tier {
        HardwareTier::Blackwell => {
            "Keep the Blackwell hot with meaningful work, not busy with junk."
        }
        HardwareTier::Rtx3090 => "The 3090 should work ahead.",
        HardwareTier::Cpu => "The CPU decides.",
    }
}

/// The work classes this tier should RUN (Blackwell accept / 3090 use-for /
/// CPU hot-ops).
#[must_use]
pub const fn runs(tier: HardwareTier) -> &'static [&'static str] {
    match tier {
        HardwareTier::Blackwell => &BLACKWELL_ACCEPT,
        HardwareTier::Rtx3090 => &RTX3090_USE_FOR,
        HardwareTier::Cpu => &CPU_HOT_OPS,
    }
}

/// The work classes this tier should AVOID. Only Blackwell has an explicit
/// avoid list in the dump (protect the oracle); the others return empty.
#[must_use]
pub const fn avoids(tier: HardwareTier) -> &'static [&'static str] {
    match tier {
        HardwareTier::Blackwell => &BLACKWELL_AVOID,
        HardwareTier::Rtx3090 | HardwareTier::Cpu => &[],
    }
}

/// Whether `work_class` (a verbatim dump phrase) is on this tier's run list.
#[must_use]
pub fn tier_runs(tier: HardwareTier, work_class: &str) -> bool {
    runs(tier).contains(&work_class)
}

/// Whether `work_class` is on this tier's avoid list (Blackwell only).
#[must_use]
pub fn tier_avoids(tier: HardwareTier, work_class: &str) -> bool {
    avoids(tier).contains(&work_class)
}

// ============================================================================
// Coding-domain tier breakdown (dump 864-878, "For coding specifically")
// ============================================================================

/// RTX 3090 coding work (dump 865-869).
pub const CODING_RTX3090: [&str; 4] = [
    "grep/ripgrep summaries",
    "small code model patches",
    "speculative edit proposals",
    "test failure classification",
];

/// CPU coding work (dump 871-876).
pub const CODING_CPU: [&str; 5] = [
    "dependency graph",
    "patch risk scoring",
    "branch scheduling",
    "syntax/grammar constraints",
    "deterministic merge logic",
];

/// Blackwell coding work (dump 878-882).
pub const CODING_BLACKWELL: [&str; 4] = [
    "architectural reasoning",
    "final patch review",
    "hard bug analysis",
    "large-context synthesis",
];

/// The coding-domain work classes for a tier (dump's "For coding specifically"
/// breakdown). A concrete domain instance of the general tier policy.
#[must_use]
pub const fn coding_work(tier: HardwareTier) -> &'static [&'static str] {
    match tier {
        HardwareTier::Blackwell => &CODING_BLACKWELL,
        HardwareTier::Rtx3090 => &CODING_RTX3090,
        HardwareTier::Cpu => &CODING_CPU,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackwell_accepts_high_risk_verification() {
        assert!(tier_runs(HardwareTier::Blackwell, "high-risk verification"));
        assert!(tier_runs(HardwareTier::Blackwell, "final synthesis"));
    }

    #[test]
    fn blackwell_avoids_cheap_classification() {
        assert!(tier_avoids(HardwareTier::Blackwell, "cheap classification"));
        assert!(tier_avoids(
            HardwareTier::Blackwell,
            "repeated boilerplate prefill"
        ));
        // and does not RUN what it avoids
        assert!(!tier_runs(HardwareTier::Blackwell, "cheap classification"));
    }

    #[test]
    fn scout_runs_drafts_and_embeddings() {
        assert!(tier_runs(HardwareTier::Rtx3090, "draft branches"));
        assert!(tier_runs(HardwareTier::Rtx3090, "embeddings"));
        assert!(tier_runs(HardwareTier::Rtx3090, "failure classification"));
    }

    #[test]
    fn cpu_runs_routing_and_filtering() {
        assert!(tier_runs(HardwareTier::Cpu, "compute route masks"));
        assert!(tier_runs(HardwareTier::Cpu, "filter branches"));
        assert!(tier_runs(HardwareTier::Cpu, "apply budgets"));
    }

    #[test]
    fn only_blackwell_has_an_avoid_list() {
        assert!(!avoids(HardwareTier::Blackwell).is_empty());
        assert!(avoids(HardwareTier::Rtx3090).is_empty());
        assert!(avoids(HardwareTier::Cpu).is_empty());
    }

    #[test]
    fn blackwell_run_and_avoid_lists_are_disjoint() {
        for w in BLACKWELL_ACCEPT {
            assert!(!BLACKWELL_AVOID.contains(&w), "{w} on both lists");
        }
    }

    #[test]
    fn list_sizes_match_dump() {
        assert_eq!(BLACKWELL_ACCEPT.len(), 5);
        assert_eq!(BLACKWELL_AVOID.len(), 4);
        assert_eq!(RTX3090_USE_FOR.len(), 7);
        assert_eq!(CPU_HOT_OPS.len(), 8);
    }

    #[test]
    fn doctrines_are_verbatim() {
        assert_eq!(
            doctrine(HardwareTier::Blackwell),
            "Keep the Blackwell hot with meaningful work, not busy with junk."
        );
        assert_eq!(
            doctrine(HardwareTier::Rtx3090),
            "The 3090 should work ahead."
        );
        assert_eq!(doctrine(HardwareTier::Cpu), "The CPU decides.");
    }

    #[test]
    fn coding_breakdown_sizes_match_dump() {
        assert_eq!(coding_work(HardwareTier::Rtx3090).len(), 4);
        assert_eq!(coding_work(HardwareTier::Cpu).len(), 5);
        assert_eq!(coding_work(HardwareTier::Blackwell).len(), 4);
    }

    #[test]
    fn coding_work_is_verbatim_per_tier() {
        // oracle does the hard architectural reasoning; scout does cheap greps;
        // cpu does the deterministic graph/merge logic.
        assert!(coding_work(HardwareTier::Blackwell).contains(&"architectural reasoning"));
        assert!(coding_work(HardwareTier::Rtx3090).contains(&"grep/ripgrep summaries"));
        assert!(coding_work(HardwareTier::Cpu).contains(&"deterministic merge logic"));
    }

    #[test]
    fn coding_work_lists_are_disjoint_across_tiers() {
        for w in CODING_BLACKWELL {
            assert!(
                !CODING_RTX3090.contains(&w) && !CODING_CPU.contains(&w),
                "{w} not unique"
            );
        }
    }

    #[test]
    fn serde_roundtrip_tier() {
        for t in [
            HardwareTier::Blackwell,
            HardwareTier::Rtx3090,
            HardwareTier::Cpu,
        ] {
            let j = serde_json::to_string(&t).unwrap();
            let back: HardwareTier = serde_json::from_str(&j).unwrap();
            assert_eq!(t, back);
        }
    }
}
