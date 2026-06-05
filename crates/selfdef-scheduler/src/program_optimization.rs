//! `program_optimization` — runtime self-optimization metrics + knobs (MS048).
//!
//! Encodes the avx-plus-plus dump's **"Program Optimization"** verbatim (dump
//! lines 3846-3884). The DSPy insight (3848): *"optimize the program against
//! metrics, not vibes."* The runtime measures ten metrics and tunes eight
//! knobs; the sequencing doctrine (3886): *"runtime optimization first,
//! fine-tuning later."*
//!
//! The ten metrics (dump 3852-3862):
//!
//! ```text
//! task success / tool rejection rate / oracle calls per task / latency /
//! user interventions / test pass rate / rollback rate / branch acceptance
//! rate / KV reuse / memory usefulness
//! ```
//!
//! The eight tuning knobs (dump 3866-3884):
//!
//! ```text
//! which scout model to use / speculation depth / retrieval thresholds /
//! prompt templates / grammar strictness / oracle review thresholds /
//! tool approval policies / cache admission
//! ```
//!
//! Every metric + knob is verbatim — none invented (operator rule: "you cannot
//! invent crap").
//!
//! Standing rule: We do not minimize anything.

use serde::{Deserialize, Serialize};

/// The DSPy doctrine (dump 3848, verbatim).
pub const DOCTRINE: &str = "optimize the program against metrics, not vibes.";

/// The sequencing doctrine (dump 3888, verbatim).
pub const SEQUENCING: &str = "runtime optimization first, fine-tuning later";

/// The ten optimization metrics the runtime measures (dump 3852-3862).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationMetric {
    /// task success.
    TaskSuccess,
    /// tool rejection rate.
    ToolRejectionRate,
    /// oracle calls per task.
    OracleCallsPerTask,
    /// latency.
    Latency,
    /// user interventions.
    UserInterventions,
    /// test pass rate.
    TestPassRate,
    /// rollback rate.
    RollbackRate,
    /// branch acceptance rate.
    BranchAcceptanceRate,
    /// KV reuse.
    KvReuse,
    /// memory usefulness.
    MemoryUsefulness,
}

impl OptimizationMetric {
    /// The verbatim metric name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TaskSuccess => "task success",
            Self::ToolRejectionRate => "tool rejection rate",
            Self::OracleCallsPerTask => "oracle calls per task",
            Self::Latency => "latency",
            Self::UserInterventions => "user interventions",
            Self::TestPassRate => "test pass rate",
            Self::RollbackRate => "rollback rate",
            Self::BranchAcceptanceRate => "branch acceptance rate",
            Self::KvReuse => "KV reuse",
            Self::MemoryUsefulness => "memory usefulness",
        }
    }
}

/// The eight tuning knobs the runtime adjusts (dump 3866-3884).
pub const TUNING_KNOBS: [&str; 8] = [
    "which scout model to use",
    "speculation depth",
    "retrieval thresholds",
    "prompt templates",
    "grammar strictness",
    "oracle review thresholds",
    "tool approval policies",
    "cache admission",
];

/// All ten metrics in dump order.
#[must_use]
pub fn metrics() -> [OptimizationMetric; 10] {
    [
        OptimizationMetric::TaskSuccess,
        OptimizationMetric::ToolRejectionRate,
        OptimizationMetric::OracleCallsPerTask,
        OptimizationMetric::Latency,
        OptimizationMetric::UserInterventions,
        OptimizationMetric::TestPassRate,
        OptimizationMetric::RollbackRate,
        OptimizationMetric::BranchAcceptanceRate,
        OptimizationMetric::KvReuse,
        OptimizationMetric::MemoryUsefulness,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_metrics_verbatim() {
        let m = metrics();
        assert_eq!(m.len(), 10);
        assert_eq!(m[0].name(), "task success");
        assert_eq!(m[9].name(), "memory usefulness");
        assert_eq!(OptimizationMetric::OracleCallsPerTask.name(), "oracle calls per task");
    }

    #[test]
    fn eight_tuning_knobs_verbatim() {
        assert_eq!(TUNING_KNOBS.len(), 8);
        assert_eq!(TUNING_KNOBS[0], "which scout model to use");
        assert_eq!(TUNING_KNOBS[7], "cache admission");
        assert!(TUNING_KNOBS.contains(&"oracle review thresholds"));
    }

    #[test]
    fn metrics_distinct() {
        let m = metrics();
        for i in 0..10 {
            for j in (i + 1)..10 {
                assert_ne!(m[i], m[j]);
                assert_ne!(m[i].name(), m[j].name());
            }
        }
    }

    #[test]
    fn doctrines_verbatim() {
        assert_eq!(DOCTRINE, "optimize the program against metrics, not vibes.");
        assert_eq!(SEQUENCING, "runtime optimization first, fine-tuning later");
    }

    #[test]
    fn serde_roundtrip() {
        for m in metrics() {
            let j = serde_json::to_string(&m).unwrap();
            let back: OptimizationMetric = serde_json::from_str(&j).unwrap();
            assert_eq!(m, back);
        }
    }
}
