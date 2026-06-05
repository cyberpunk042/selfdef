//! `runtime_shape` — the Deterministic Cortex Runtime catalog (MS048).
//!
//! Encodes the avx-plus-plus dump's **"The Strong Runtime Shape"** verbatim
//! (dump lines 2670-2683): the eight engines of the *"Deterministic Cortex
//! Runtime"*. This is the architectural index of the whole `selfdef-scheduler`
//! crate — every engine the dump names is implemented by one or more of the
//! crate's modules, so this module both documents the architecture and pins,
//! by test, that each engine has an implementation.
//!
//! ```text
//! Deterministic Cortex Runtime
//! 1. Branch Engine
//! 2. Policy Engine
//! 3. Grammar Engine
//! 4. Memory Router
//! 5. Speculation Engine
//! 6. Tool Gate
//! 7. Replay Log
//! 8. KV Cache Controller
//! ```
//!
//! The dump (2683): *"The KV controller is what turns 256 GB RAM + ZFS + two
//! GPUs into an actual memory hierarchy."* Engine names are verbatim; the
//! module mapping is this crate's own implementation record — none invented
//! (operator rule: "you cannot invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The eight engines of the Deterministic Cortex Runtime (dump 2674-2681).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CortexEngine {
    /// 1. Branch Engine.
    BranchEngine,
    /// 2. Policy Engine.
    PolicyEngine,
    /// 3. Grammar Engine.
    GrammarEngine,
    /// 4. Memory Router.
    MemoryRouter,
    /// 5. Speculation Engine.
    SpeculationEngine,
    /// 6. Tool Gate.
    ToolGate,
    /// 7. Replay Log.
    ReplayLog,
    /// 8. KV Cache Controller.
    KvCacheController,
}

impl CortexEngine {
    /// 1-based engine number per the dump list.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::BranchEngine => 1,
            Self::PolicyEngine => 2,
            Self::GrammarEngine => 3,
            Self::MemoryRouter => 4,
            Self::SpeculationEngine => 5,
            Self::ToolGate => 6,
            Self::ReplayLog => 7,
            Self::KvCacheController => 8,
        }
    }

    /// The verbatim engine name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BranchEngine => "Branch Engine",
            Self::PolicyEngine => "Policy Engine",
            Self::GrammarEngine => "Grammar Engine",
            Self::MemoryRouter => "Memory Router",
            Self::SpeculationEngine => "Speculation Engine",
            Self::ToolGate => "Tool Gate",
            Self::ReplayLog => "Replay Log",
            Self::KvCacheController => "KV Cache Controller",
        }
    }

    /// The `selfdef-scheduler` module(s) implementing this engine (this crate's
    /// own implementation record).
    #[must_use]
    pub const fn implemented_by(self) -> &'static [&'static str] {
        match self {
            Self::BranchEngine => &["branch_masks", "branch_lifecycle"],
            Self::PolicyEngine => &["scheduling_law", "tier_work_policy"],
            // grammar is one of the branch-lifecycle Filter masks
            Self::GrammarEngine => &["branch_lifecycle"],
            Self::MemoryRouter => &["memory_scheduling", "memory_admission"],
            Self::SpeculationEngine => &["speculative_parallelism", "speculation_tree"],
            Self::ToolGate => &["tool_scheduling"],
            // the audit chain IS the replay log (emit_audit_entry / decision_audit)
            Self::ReplayLog => &["decision_audit", "decide"],
            Self::KvCacheController => &["kv_context_scheduling", "branch_kv_fusion"],
        }
    }
}

/// The eight engines in dump order.
#[must_use]
pub fn cortex_runtime() -> [CortexEngine; 8] {
    [
        CortexEngine::BranchEngine,
        CortexEngine::PolicyEngine,
        CortexEngine::GrammarEngine,
        CortexEngine::MemoryRouter,
        CortexEngine::SpeculationEngine,
        CortexEngine::ToolGate,
        CortexEngine::ReplayLog,
        CortexEngine::KvCacheController,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eight_engines_in_order() {
        let r = cortex_runtime();
        assert_eq!(r.len(), 8);
        for (i, e) in r.iter().enumerate() {
            assert_eq!(e.number(), (i + 1) as u8);
        }
    }

    #[test]
    fn engine_names_are_verbatim() {
        assert_eq!(CortexEngine::BranchEngine.name(), "Branch Engine");
        assert_eq!(CortexEngine::KvCacheController.name(), "KV Cache Controller");
        assert_eq!(CortexEngine::ReplayLog.name(), "Replay Log");
    }

    #[test]
    fn every_engine_has_at_least_one_implementing_module() {
        for e in cortex_runtime() {
            assert!(
                !e.implemented_by().is_empty(),
                "{e:?} has no implementing module"
            );
        }
    }

    #[test]
    fn key_engine_module_mappings() {
        assert!(CortexEngine::PolicyEngine.implemented_by().contains(&"scheduling_law"));
        assert!(CortexEngine::SpeculationEngine
            .implemented_by()
            .contains(&"speculation_tree"));
        assert!(CortexEngine::KvCacheController
            .implemented_by()
            .contains(&"branch_kv_fusion"));
        assert!(CortexEngine::ReplayLog.implemented_by().contains(&"decision_audit"));
    }

    #[test]
    fn engines_are_distinct() {
        let all = cortex_runtime();
        for i in 0..8 {
            for j in (i + 1)..8 {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn serde_roundtrip() {
        for e in cortex_runtime() {
            let s = serde_json::to_string(&e).unwrap();
            let back: CortexEngine = serde_json::from_str(&s).unwrap();
            assert_eq!(e, back);
        }
    }
}
