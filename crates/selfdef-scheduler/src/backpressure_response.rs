//! `backpressure_response` — per-surface backpressure response policy (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Backpressure"** response table verbatim
//! (dump lines 18181-18205, Goldilocks scheduler section): *"If a resource is
//! pressured:"*
//!
//! ```text
//! Blackwell VRAM high:    reduce context, evict low-value KV, switch smaller oracle
//! 3090 busy:              reduce branch width, use CPU classifiers
//! CPU pressure high:      defer background indexing/evals
//! RAM pressure high:      hibernate branches, compact memory
//! IO pressure high:       delay cold scans, avoid large snapshots
//! human gate queue high:  batch approvals, lower autonomy
//! ```
//!
//! The [`crate::BackpressureMonitor`] / [`crate::backpressure_driver`] layer
//! *detects* which surfaces are firing (the boolean
//! [`BackpressureState`]); this module says what the scheduler should *do*
//! about each — the verbatim response actions. The two compose:
//! [`active_responses`] maps a live `BackpressureState` to the responses for
//! exactly the surfaces under pressure. No action is invented; each maps to a
//! dump phrase (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use selfdef_scheduler_mirror::BackpressureState;
use serde::{Deserialize, Serialize};

/// The six backpressure surfaces (1:1 with [`BackpressureState`]'s fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackpressureSurface {
    /// Blackwell VRAM high.
    BlackwellVramHigh,
    /// RTX 3090 busy.
    Gpu3090Busy,
    /// CPU PSI pressure high.
    CpuPressure,
    /// Memory PSI pressure high.
    RamPressure,
    /// IO PSI pressure high.
    IoPressure,
    /// Human-gate approval queue high.
    HumanGateQueueHigh,
}

impl BackpressureSurface {
    /// The verbatim response actions for this surface (dump 18182-18204).
    #[must_use]
    pub const fn responses(self) -> &'static [&'static str] {
        match self {
            Self::BlackwellVramHigh => {
                &["reduce context", "evict low-value KV", "switch smaller oracle"]
            }
            Self::Gpu3090Busy => &["reduce branch width", "use CPU classifiers"],
            Self::CpuPressure => &["defer background indexing/evals"],
            Self::RamPressure => &["hibernate branches", "compact memory"],
            Self::IoPressure => &["delay cold scans", "avoid large snapshots"],
            Self::HumanGateQueueHigh => &["batch approvals", "lower autonomy"],
        }
    }

    /// Whether this surface is currently firing in `state`.
    #[must_use]
    pub const fn is_firing(self, state: &BackpressureState) -> bool {
        match self {
            Self::BlackwellVramHigh => state.blackwell_vram_high,
            Self::Gpu3090Busy => state.gpu3090_busy,
            Self::CpuPressure => state.cpu_pressure,
            Self::RamPressure => state.ram_pressure,
            Self::IoPressure => state.io_pressure,
            Self::HumanGateQueueHigh => state.human_gate_queue_high,
        }
    }
}

/// All six surfaces in dump order.
#[must_use]
pub fn all_surfaces() -> [BackpressureSurface; 6] {
    [
        BackpressureSurface::BlackwellVramHigh,
        BackpressureSurface::Gpu3090Busy,
        BackpressureSurface::CpuPressure,
        BackpressureSurface::RamPressure,
        BackpressureSurface::IoPressure,
        BackpressureSurface::HumanGateQueueHigh,
    ]
}

/// The (surface, verbatim responses) pairs for exactly the surfaces firing in
/// `state`, in dump order. Empty when no surface is under pressure.
#[must_use]
pub fn active_responses(
    state: &BackpressureState,
) -> Vec<(BackpressureSurface, &'static [&'static str])> {
    all_surfaces()
        .into_iter()
        .filter(|s| s.is_firing(state))
        .map(|s| (s, s.responses()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_surface_has_at_least_one_verbatim_response() {
        for s in all_surfaces() {
            assert!(!s.responses().is_empty(), "{s:?} has no responses");
        }
    }

    #[test]
    fn blackwell_responses_are_verbatim() {
        assert_eq!(
            BackpressureSurface::BlackwellVramHigh.responses(),
            &["reduce context", "evict low-value KV", "switch smaller oracle"]
        );
    }

    #[test]
    fn human_gate_responses_are_verbatim() {
        assert_eq!(
            BackpressureSurface::HumanGateQueueHigh.responses(),
            &["batch approvals", "lower autonomy"]
        );
    }

    #[test]
    fn active_responses_empty_on_clean_state() {
        assert!(active_responses(&BackpressureState::clean()).is_empty());
    }

    #[test]
    fn active_responses_returns_only_firing_surfaces() {
        let state = BackpressureState {
            blackwell_vram_high: true,
            io_pressure: true,
            ..BackpressureState::clean()
        };
        let active = active_responses(&state);
        let surfaces: Vec<BackpressureSurface> = active.iter().map(|(s, _)| *s).collect();
        assert_eq!(
            surfaces,
            vec![
                BackpressureSurface::BlackwellVramHigh,
                BackpressureSurface::IoPressure
            ]
        );
        // and the responses are the verbatim ones
        assert!(active[0].1.contains(&"evict low-value KV"));
        assert!(active[1].1.contains(&"delay cold scans"));
    }

    #[test]
    fn is_firing_matches_state_fields() {
        let state = BackpressureState {
            cpu_pressure: true,
            ..BackpressureState::clean()
        };
        assert!(BackpressureSurface::CpuPressure.is_firing(&state));
        assert!(!BackpressureSurface::RamPressure.is_firing(&state));
    }

    #[test]
    fn serde_roundtrip_surfaces() {
        for s in all_surfaces() {
            let j = serde_json::to_string(&s).unwrap();
            let back: BackpressureSurface = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }
}
