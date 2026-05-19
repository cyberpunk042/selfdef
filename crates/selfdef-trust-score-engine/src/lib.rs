//! `selfdef-trust-score-engine` — companion engine to selfdef-trust-score-mirror.
//!
//! Computes trust-score updates from a delta reason, enforces the 0..=1000
//! range, and prevents under/over-flow.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_trust_score_mirror::{DeltaEntry, DeltaReason, TrustBand};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-reason canonical delta magnitudes per MS042 trust-score semantics.
pub fn canonical_delta(reason: DeltaReason) -> i32 {
    match reason {
        DeltaReason::Baseline => 1000,
        DeltaReason::SuccessfulExecution => 1,
        DeltaReason::MismatchMinor => -10,
        DeltaReason::MismatchMajor => -50,
        DeltaReason::MismatchCritical => -200,
        DeltaReason::OperatorAdjustment => 0, // operator supplies the delta separately
        DeltaReason::Decay => -1,
        DeltaReason::QuarantineRelease => 100,
        DeltaReason::Forfeiture => -1000,
    }
}

/// Apply a delta to a starting score and return the new score + band
/// pair, clamped to 0..=1000.
pub fn apply_delta(starting: u16, delta: i32) -> u16 {
    let new = (starting as i32 + delta).clamp(0, 1000);
    new as u16
}

/// Compute the next score + band given a reason. Returns a DeltaEntry
/// shaped record (caller adds trace_id + signature).
pub fn next_entry(
    starting: u16,
    reason: DeltaReason,
    applied_at: &str,
    operator_override: Option<i32>,
    trace_id: &str,
    signature: &str,
) -> DeltaEntry {
    let delta = match (reason, operator_override) {
        (DeltaReason::OperatorAdjustment, Some(d)) => d,
        _ => canonical_delta(reason),
    };
    let score_after = apply_delta(starting, delta);
    DeltaEntry {
        applied_at: applied_at.into(),
        reason,
        delta,
        score_after,
        trace_id: trace_id.into(),
        signature: signature.into(),
    }
}

/// Compute the resulting trust band from a final score.
pub fn band_for_score(score: u16) -> TrustBand {
    TrustBand::for_score(score)
}

/// Errors.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Score overflow / underflow without clamp (defensive; clamp prevents this).
    #[error("score arithmetic failed for starting={starting} delta={delta}")]
    ArithmeticFailed {
        /// Starting score.
        starting: u16,
        /// Delta.
        delta: i32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- canonical_delta ---

    #[test]
    fn baseline_is_1000() {
        assert_eq!(canonical_delta(DeltaReason::Baseline), 1000);
    }
    #[test]
    fn successful_execution_is_plus_1() {
        assert_eq!(canonical_delta(DeltaReason::SuccessfulExecution), 1);
    }
    #[test]
    fn mismatch_minor_is_minus_10() {
        assert_eq!(canonical_delta(DeltaReason::MismatchMinor), -10);
    }
    #[test]
    fn mismatch_major_is_minus_50() {
        assert_eq!(canonical_delta(DeltaReason::MismatchMajor), -50);
    }
    #[test]
    fn mismatch_critical_is_minus_200() {
        assert_eq!(canonical_delta(DeltaReason::MismatchCritical), -200);
    }
    #[test]
    fn decay_is_minus_1() {
        assert_eq!(canonical_delta(DeltaReason::Decay), -1);
    }
    #[test]
    fn quarantine_release_is_plus_100() {
        assert_eq!(canonical_delta(DeltaReason::QuarantineRelease), 100);
    }
    #[test]
    fn forfeiture_is_minus_1000() {
        assert_eq!(canonical_delta(DeltaReason::Forfeiture), -1000);
    }
    #[test]
    fn operator_adjustment_is_zero_default() {
        assert_eq!(canonical_delta(DeltaReason::OperatorAdjustment), 0);
    }

    // --- apply_delta clamping ---

    #[test]
    fn apply_delta_clamps_to_1000_max() {
        assert_eq!(apply_delta(950, 100), 1000);
        assert_eq!(apply_delta(1000, 500), 1000);
    }
    #[test]
    fn apply_delta_clamps_to_0_min() {
        assert_eq!(apply_delta(50, -100), 0);
        assert_eq!(apply_delta(0, -500), 0);
    }
    #[test]
    fn apply_delta_normal_arithmetic() {
        assert_eq!(apply_delta(500, 100), 600);
        assert_eq!(apply_delta(500, -100), 400);
    }

    // --- next_entry ---

    #[test]
    fn next_entry_uses_canonical_delta() {
        let e = next_entry(900, DeltaReason::MismatchMajor, "2026-05-19T03:00:00Z", None, "trace-1", "sig");
        assert_eq!(e.delta, -50);
        assert_eq!(e.score_after, 850);
    }

    #[test]
    fn next_entry_uses_operator_override_for_adjustment() {
        let e = next_entry(500, DeltaReason::OperatorAdjustment, "ts", Some(-200), "trace-1", "sig");
        assert_eq!(e.delta, -200);
        assert_eq!(e.score_after, 300);
    }

    #[test]
    fn next_entry_ignores_override_for_non_adjustment_reason() {
        let e = next_entry(800, DeltaReason::Forfeiture, "ts", Some(-50), "trace-1", "sig");
        // Override ignored; canonical Forfeiture delta = -1000 applies (clamps to 0).
        assert_eq!(e.delta, -1000);
        assert_eq!(e.score_after, 0);
    }

    #[test]
    fn next_entry_baseline_starts_at_1000() {
        let e = next_entry(0, DeltaReason::Baseline, "ts", None, "trace-1", "sig");
        assert_eq!(e.delta, 1000);
        assert_eq!(e.score_after, 1000);
    }

    // --- band_for_score ---

    #[test]
    fn band_thresholds() {
        assert_eq!(band_for_score(1000), TrustBand::Trusted);
        assert_eq!(band_for_score(800), TrustBand::Trusted);
        assert_eq!(band_for_score(799), TrustBand::Watched);
        assert_eq!(band_for_score(500), TrustBand::Watched);
        assert_eq!(band_for_score(499), TrustBand::Suspect);
        assert_eq!(band_for_score(200), TrustBand::Suspect);
        assert_eq!(band_for_score(199), TrustBand::Untrusted);
        assert_eq!(band_for_score(0), TrustBand::Untrusted);
    }

    // --- Sequence simulation ---

    #[test]
    fn sequence_baseline_then_decay_lands_in_trusted() {
        let mut score = next_entry(0, DeltaReason::Baseline, "ts", None, "t", "s").score_after;
        for _ in 0..50 {
            score = next_entry(score, DeltaReason::Decay, "ts", None, "t", "s").score_after;
        }
        // After 50 decays from 1000: 1000-50=950 → Trusted
        assert_eq!(score, 950);
        assert_eq!(band_for_score(score), TrustBand::Trusted);
    }
}
