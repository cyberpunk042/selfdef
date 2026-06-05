//! `objective_signals` — substrate-to-objective bridge (MS048 D-trio close).
//!
//! The scheduler's [`crate::evaluate_objective`] consumes an
//! [`crate::AxisSignals`] tuple of six `[0.0, 1.0]` scores where `1.0`
//! means "ideal". Four of those axes — latency, cost, risk, energy — are
//! *estimated from the request* (the model/router proposes them; the box
//! cannot read them off a sensor). The remaining two —
//! `hardware_pressure` and `human_attention` — are **measurable from the
//! live host substrate** via the PSI + DCGM + IPS-human-gate trio that
//! [`crate::backpressure_driver::BackpressureDriver::poll`] composes into a
//! [`DriverReading`].
//!
//! Before this module there was no function bridging a live
//! `DriverReading` into the objective's two substrate axes: the scoring
//! kernel existed, the substrate poll existed, but nothing connected them.
//! This module closes that seam so the end-to-end loop is:
//!
//! ```text
//!   BackpressureDriver::poll() -> DriverReading
//!     -> merge_substrate_into_signals(model_signals, &reading, cap)
//!       -> evaluate_objective(merged, profile) -> AxisScores
//! ```
//!
//! Doctrinal anchors (verbatim, preserved per "you cannot invent crap"):
//! - Peace Machine + Core Law — *"Models propose / Runtime routes / CPU
//!   enforces"*. The model proposes the four request-estimated axes; this
//!   bridge lets the **runtime** overwrite the two it can measure from the
//!   CPU/GPU/queue substrate the model cannot see.
//! - Honest-offline (backpressure_driver §): an Unavailable/Errored
//!   substrate contributes `0.0` measurements, so a degraded sensor reads as
//!   "no observed pressure" rather than fabricated headroom. Callers that
//!   need to distinguish "measured calm" from "blind" consult
//!   [`DriverReading::substrate_health`]; the score itself never invents a
//!   reading.
//!
//! Standing rule: We do not minimize anything.

use crate::backpressure_driver::DriverReading;
use crate::{AxisScores, AxisSignals, Profile, evaluate_objective};

/// Default human-attention queue cap (dump 18205-18211): a pending-restore
/// queue of this depth or deeper drives the `human_attention` axis to `0.0`
/// (full operator burden). Below it the axis ramps linearly toward `1.0`
/// (no operator decision pending).
pub const DEFAULT_HUMAN_ATTENTION_QUEUE_CAP: u32 = 20;

/// Derive the `hardware_pressure` axis (`1.0` = no surface under pressure,
/// `0.0` = at least one surface fully saturated) from a live
/// [`DriverReading`].
///
/// The score is `1.0 - max(five substrate fractions)`, clamped to
/// `[0.0, 1.0]`. The five fractions are the continuous load measurements
/// the objective cares about: Blackwell VRAM, RTX-3090 utilisation, and the
/// three PSI surfaces (CPU / memory / IO). The human-gate queue is a
/// *separate* axis ([`substrate_human_attention_score`]) and is deliberately
/// excluded here — operator burden is not hardware pressure.
///
/// Honest-offline: an Unavailable/Errored substrate contributes `0.0` to
/// its fraction (per the driver's policy), so it cannot inflate pressure;
/// it also cannot mask pressure on a *healthy* substrate, because `max`
/// takes the worst observed surface.
#[must_use]
pub fn substrate_hardware_pressure_score(reading: &DriverReading) -> f32 {
    let m = &reading.measurements;
    let worst = m
        .blackwell_vram_util
        .max(m.gpu3090_util)
        .max(m.cpu_psi)
        .max(m.mem_psi)
        .max(m.io_psi)
        .clamp(0.0, 1.0);
    1.0 - worst
}

/// Derive the `human_attention` axis (`1.0` = no operator decision pending,
/// `0.0` = queue at or past `max_queue`) from a live [`DriverReading`].
///
/// Linear ramp: an empty IPS pending-restore queue scores `1.0`; a queue at
/// `max_queue` (or deeper) scores `0.0`. A `max_queue` of `0` is treated as
/// "any pending item is full burden" only when the queue is non-empty —
/// an empty queue always scores `1.0`.
#[must_use]
pub fn substrate_human_attention_score(reading: &DriverReading, max_queue: u32) -> f32 {
    let depth = reading.measurements.human_gate_queue_depth;
    if depth == 0 {
        return 1.0;
    }
    if max_queue == 0 || depth >= max_queue {
        return 0.0;
    }
    1.0 - (depth as f32 / max_queue as f32)
}

/// Overwrite the two substrate-measurable axes of a model-proposed
/// [`AxisSignals`] with values derived from a live [`DriverReading`].
///
/// The four request-estimated axes (latency / cost / risk / energy) pass
/// through unchanged — the model is authoritative for them. The two
/// substrate axes (`hardware_pressure` / `human_attention`) are
/// **overwritten** — the box is authoritative for what it can measure, even
/// if the model supplied a guess. The four pass-through axes are clamped to
/// `[0.0, 1.0]` defensively so a malformed model proposal cannot push the
/// compound score out of range.
#[must_use]
pub fn merge_substrate_into_signals(
    model_signals: AxisSignals,
    reading: &DriverReading,
    max_queue: u32,
) -> AxisSignals {
    AxisSignals {
        latency: model_signals.latency.clamp(0.0, 1.0),
        cost: model_signals.cost.clamp(0.0, 1.0),
        risk: model_signals.risk.clamp(0.0, 1.0),
        energy: model_signals.energy.clamp(0.0, 1.0),
        human_attention: substrate_human_attention_score(reading, max_queue),
        hardware_pressure: substrate_hardware_pressure_score(reading),
    }
}

/// End-to-end: merge a live substrate [`DriverReading`] into the
/// model-proposed [`AxisSignals`], then evaluate the 7-axis objective under
/// the active [`Profile`]. Returns the full [`AxisScores`] (six axes +
/// per-profile-weighted compound).
///
/// This is the function the scheduler runtime calls each request after a
/// `BackpressureDriver::poll()`.
#[must_use]
pub fn score_current_substrate(
    reading: &DriverReading,
    model_signals: AxisSignals,
    profile: Profile,
    max_queue: u32,
) -> AxisScores {
    let merged = merge_substrate_into_signals(model_signals, reading, max_queue);
    evaluate_objective(merged, profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceMeasurements;
    use crate::backpressure_driver::SubstrateHealth;
    use selfdef_scheduler_mirror::BackpressureState;

    /// Build a `DriverReading` with the given measurements, a clean
    /// backpressure state, and all-healthy substrate (tests that care about
    /// degraded substrate override the health explicitly).
    fn reading_with(m: ResourceMeasurements) -> DriverReading {
        DriverReading {
            captured_at_unix_micros: 0,
            measurements: m,
            state: BackpressureState::clean(),
            substrate_health: SubstrateHealth::all_healthy(),
        }
    }

    fn neutral_model_signals() -> AxisSignals {
        AxisSignals {
            latency: 0.5,
            cost: 0.5,
            risk: 0.5,
            energy: 0.5,
            // these two are placeholders the merge MUST overwrite:
            human_attention: 0.123,
            hardware_pressure: 0.456,
        }
    }

    // ---- hardware_pressure ------------------------------------------------

    #[test]
    fn pressure_score_all_idle_is_one() {
        let r = reading_with(ResourceMeasurements::clean());
        assert_eq!(substrate_hardware_pressure_score(&r), 1.0);
    }

    #[test]
    fn pressure_score_one_axis_high_drives_down() {
        let r = reading_with(ResourceMeasurements {
            cpu_psi: 0.75,
            ..ResourceMeasurements::clean()
        });
        // 1.0 - 0.75 = 0.25
        assert!((substrate_hardware_pressure_score(&r) - 0.25).abs() < 1e-6);
    }

    #[test]
    fn pressure_score_takes_worst_surface() {
        let r = reading_with(ResourceMeasurements {
            blackwell_vram_util: 0.30,
            gpu3090_util: 0.90, // worst
            cpu_psi: 0.20,
            mem_psi: 0.10,
            io_psi: 0.05,
            human_gate_queue_depth: 0,
        });
        // 1.0 - 0.90 = 0.10
        assert!((substrate_hardware_pressure_score(&r) - 0.10).abs() < 1e-6);
    }

    #[test]
    fn pressure_score_full_saturation_is_zero() {
        let r = reading_with(ResourceMeasurements {
            blackwell_vram_util: 1.0,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_hardware_pressure_score(&r), 0.0);
    }

    #[test]
    fn pressure_score_clamps_overshoot() {
        // A misbehaving sensor reporting >1.0 must not yield a negative score.
        let r = reading_with(ResourceMeasurements {
            mem_psi: 1.5,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_hardware_pressure_score(&r), 0.0);
    }

    #[test]
    fn pressure_score_ignores_human_gate() {
        // A deep human-gate queue must NOT register as hardware pressure.
        let r = reading_with(ResourceMeasurements {
            human_gate_queue_depth: 99,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_hardware_pressure_score(&r), 1.0);
    }

    // ---- human_attention --------------------------------------------------

    #[test]
    fn attention_score_empty_queue_is_one() {
        let r = reading_with(ResourceMeasurements::clean());
        assert_eq!(
            substrate_human_attention_score(&r, DEFAULT_HUMAN_ATTENTION_QUEUE_CAP),
            1.0
        );
    }

    #[test]
    fn attention_score_at_cap_is_zero() {
        let r = reading_with(ResourceMeasurements {
            human_gate_queue_depth: 20,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_human_attention_score(&r, 20), 0.0);
    }

    #[test]
    fn attention_score_above_cap_is_zero() {
        let r = reading_with(ResourceMeasurements {
            human_gate_queue_depth: 50,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_human_attention_score(&r, 20), 0.0);
    }

    #[test]
    fn attention_score_half_cap_is_half() {
        let r = reading_with(ResourceMeasurements {
            human_gate_queue_depth: 10,
            ..ResourceMeasurements::clean()
        });
        assert!((substrate_human_attention_score(&r, 20) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn attention_score_zero_cap_nonempty_is_zero() {
        let r = reading_with(ResourceMeasurements {
            human_gate_queue_depth: 1,
            ..ResourceMeasurements::clean()
        });
        assert_eq!(substrate_human_attention_score(&r, 0), 0.0);
    }

    #[test]
    fn attention_score_zero_cap_empty_is_one() {
        let r = reading_with(ResourceMeasurements::clean());
        assert_eq!(substrate_human_attention_score(&r, 0), 1.0);
    }

    #[test]
    fn default_cap_constant_is_twenty() {
        assert_eq!(DEFAULT_HUMAN_ATTENTION_QUEUE_CAP, 20);
    }

    // ---- merge ------------------------------------------------------------

    #[test]
    fn merge_overwrites_substrate_axes_keeps_model_axes() {
        let r = reading_with(ResourceMeasurements {
            cpu_psi: 0.40,
            human_gate_queue_depth: 5,
            ..ResourceMeasurements::clean()
        });
        let merged = merge_substrate_into_signals(neutral_model_signals(), &r, 20);
        // model axes preserved
        assert_eq!(merged.latency, 0.5);
        assert_eq!(merged.cost, 0.5);
        assert_eq!(merged.risk, 0.5);
        assert_eq!(merged.energy, 0.5);
        // substrate axes overwritten (placeholder 0.456 / 0.123 gone)
        assert!((merged.hardware_pressure - 0.60).abs() < 1e-6); // 1 - 0.40
        assert!((merged.human_attention - 0.75).abs() < 1e-6); // 1 - 5/20
    }

    #[test]
    fn merge_clamps_malformed_model_axes() {
        let r = reading_with(ResourceMeasurements::clean());
        let bad = AxisSignals {
            latency: 2.0,
            cost: -1.0,
            risk: 1.5,
            energy: -0.5,
            human_attention: 0.0,
            hardware_pressure: 0.0,
        };
        let merged = merge_substrate_into_signals(bad, &r, 20);
        assert_eq!(merged.latency, 1.0);
        assert_eq!(merged.cost, 0.0);
        assert_eq!(merged.risk, 1.0);
        assert_eq!(merged.energy, 0.0);
    }

    // ---- end-to-end score -------------------------------------------------

    #[test]
    fn score_returns_compound_in_range() {
        let r = reading_with(ResourceMeasurements {
            cpu_psi: 0.30,
            human_gate_queue_depth: 2,
            ..ResourceMeasurements::clean()
        });
        let scores =
            score_current_substrate(&r, neutral_model_signals(), Profile::Production, 20);
        assert!(scores.compound >= 0.0 && scores.compound <= 1.0);
        // substrate axes are reflected in the returned scores
        assert!((scores.hardware_pressure - 0.70).abs() < 1e-6);
        assert!((scores.human_attention - 0.90).abs() < 1e-6);
    }

    #[test]
    fn score_high_substrate_pressure_pulls_compound_down() {
        let calm = reading_with(ResourceMeasurements::clean());
        let pressed = reading_with(ResourceMeasurements {
            blackwell_vram_util: 0.95,
            cpu_psi: 0.80,
            human_gate_queue_depth: 18,
            ..ResourceMeasurements::clean()
        });
        let calm_c =
            score_current_substrate(&calm, neutral_model_signals(), Profile::Production, 20)
                .compound;
        let pressed_c =
            score_current_substrate(&pressed, neutral_model_signals(), Profile::Production, 20)
                .compound;
        assert!(
            pressed_c < calm_c,
            "pressed compound {pressed_c} should be < calm compound {calm_c}"
        );
    }

    #[test]
    fn score_diverges_across_profiles() {
        // Same substrate, different profile weightings => different compound.
        // The substrate axes must differ from the 0.5 model axes (and from
        // each other) or every weighted average collapses to 0.5 regardless
        // of weights: cpu_psi 0.80 => hardware_pressure 0.20; queue 4 =>
        // human_attention 0.80.
        let r = reading_with(ResourceMeasurements {
            cpu_psi: 0.80,
            human_gate_queue_depth: 4,
            ..ResourceMeasurements::clean()
        });
        let fast =
            score_current_substrate(&r, neutral_model_signals(), Profile::Fast, 20).compound;
        let careful =
            score_current_substrate(&r, neutral_model_signals(), Profile::Careful, 20).compound;
        // Careful weights human_attention + hardware_pressure heavily (0.9/0.9)
        // vs Fast (0.2/0.5), so with pressure present the compounds differ.
        assert!(
            (fast - careful).abs() > 1e-6,
            "profiles should diverge: fast={fast} careful={careful}"
        );
    }
}
