//! `system_planes` — the seven-plane programming model (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Updated System"** verbatim (dump lines
//! 3966-3994) — the unified programming model the whole local AI OS is built
//! from. Seven planes, each with a role; the **Control Plane** *is* the
//! Goldilocks Scheduler this crate implements (*"deterministic branch graph
//! scheduler"*), so this module is the architectural index that places the
//! scheduler in the full system.
//!
//! ```text
//! Inference Plane:      probabilistic workers
//! Control Plane:        deterministic branch graph scheduler
//! Memory Plane:         typed memories, KV refs, indexes
//! Storage Plane:        replayable checkpoints and artifacts
//! Tool Plane:           side-effect engines behind gates
//! Observability Plane:  metrics and traces feeding policy
//! Programming Plane:    typed durable workflow graphs
//! ```
//!
//! The evolution path (dump 3990): `Prompt chain → Agent loop → Durable graph
//! → Deterministic AI OS`. The closing thesis (3994): *"A programmable,
//! replayable, measurable, permissioned cognition runtime."* Every plane +
//! role is verbatim — none invented (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The closing thesis (dump 3994, verbatim).
pub const THESIS: &str =
    "A programmable, replayable, measurable, permissioned cognition runtime.";

/// The evolution path (dump 3990, verbatim).
pub const EVOLUTION_PATH: [&str; 4] =
    ["Prompt chain", "Agent loop", "Durable graph", "Deterministic AI OS"];

/// The seven system planes (dump 3968-3988).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemPlane {
    /// Inference Plane.
    Inference,
    /// Control Plane (the Goldilocks Scheduler — this crate).
    Control,
    /// Memory Plane.
    Memory,
    /// Storage Plane.
    Storage,
    /// Tool Plane.
    Tool,
    /// Observability Plane.
    Observability,
    /// Programming Plane.
    Programming,
}

impl SystemPlane {
    /// The verbatim plane role.
    #[must_use]
    pub const fn role(self) -> &'static str {
        match self {
            Self::Inference => "probabilistic workers",
            Self::Control => "deterministic branch graph scheduler",
            Self::Memory => "typed memories, KV refs, indexes",
            Self::Storage => "replayable checkpoints and artifacts",
            Self::Tool => "side-effect engines behind gates",
            Self::Observability => "metrics and traces feeding policy",
            Self::Programming => "typed durable workflow graphs",
        }
    }

    /// Whether this is the plane the Goldilocks Scheduler (`selfdef-scheduler`)
    /// implements — the Control Plane.
    #[must_use]
    pub const fn is_scheduler(self) -> bool {
        matches!(self, Self::Control)
    }
}

/// The seven planes in dump order.
#[must_use]
pub fn planes() -> [SystemPlane; 7] {
    [
        SystemPlane::Inference,
        SystemPlane::Control,
        SystemPlane::Memory,
        SystemPlane::Storage,
        SystemPlane::Tool,
        SystemPlane::Observability,
        SystemPlane::Programming,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_planes_with_verbatim_roles() {
        let p = planes();
        assert_eq!(p.len(), 7);
        assert_eq!(SystemPlane::Inference.role(), "probabilistic workers");
        assert_eq!(SystemPlane::Control.role(), "deterministic branch graph scheduler");
        assert_eq!(SystemPlane::Programming.role(), "typed durable workflow graphs");
    }

    #[test]
    fn the_control_plane_is_the_scheduler() {
        // exactly one plane is the scheduler this crate implements
        let sched: Vec<SystemPlane> = planes().into_iter().filter(|p| p.is_scheduler()).collect();
        assert_eq!(sched, vec![SystemPlane::Control]);
    }

    #[test]
    fn evolution_path_verbatim() {
        assert_eq!(
            EVOLUTION_PATH,
            ["Prompt chain", "Agent loop", "Durable graph", "Deterministic AI OS"]
        );
    }

    #[test]
    fn planes_distinct() {
        let p = planes();
        for i in 0..7 {
            for j in (i + 1)..7 {
                assert_ne!(p[i], p[j]);
                assert_ne!(p[i].role(), p[j].role());
            }
        }
    }

    #[test]
    fn thesis_verbatim() {
        assert!(THESIS.contains("permissioned cognition runtime"));
    }

    #[test]
    fn serde_roundtrip() {
        for p in planes() {
            let j = serde_json::to_string(&p).unwrap();
            let back: SystemPlane = serde_json::from_str(&j).unwrap();
            assert_eq!(p, back);
        }
    }
}
