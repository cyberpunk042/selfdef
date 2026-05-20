//! `selfdef-task-preemption-policy` — when to preempt a running task.
//!
//! `decide(current, incoming, now_ms)` considers:
//!   * `min_priority_gap` — incoming must outrank current by at
//!     least this many steps.
//!   * `min_run_ms` — current task gets a no-preempt window from
//!     its `started_at_ms`.
//!
//! Returns `Preempt` / `Keep { reason }`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Priority (lower = lower priority).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Background.
    Background,
    /// Low.
    Low,
    /// Normal.
    Normal,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl Priority {
    /// Numeric rank.
    pub fn rank(self) -> u8 {
        match self {
            Priority::Background => 0,
            Priority::Low => 1,
            Priority::Normal => 2,
            Priority::High => 3,
            Priority::Critical => 4,
        }
    }
}

/// Running task descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningTask {
    /// Id.
    pub id: String,
    /// Priority.
    pub priority: Priority,
    /// Started ts.
    pub started_at_ms: u64,
}

/// Incoming task descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncomingTask {
    /// Id.
    pub id: String,
    /// Priority.
    pub priority: Priority,
}

/// Preempt verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PreemptVerdict {
    /// Preempt current, run incoming.
    Preempt,
    /// Keep current, queue incoming.
    Keep {
        /// reason.
        reason: String,
    },
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskPreemptionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Min priority gap (incoming.rank - current.rank).
    pub min_priority_gap: u8,
    /// Anti-thrash: current task runs at least this long.
    pub min_run_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PreemptError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad gap.
    #[error("min_priority_gap > 4 is meaningless (only 5 priority levels)")]
    BadGap,
}

impl TaskPreemptionPolicy {
    /// New.
    pub fn new(min_priority_gap: u8, min_run_ms: u64) -> Result<Self, PreemptError> {
        if min_priority_gap > 4 { return Err(PreemptError::BadGap); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            min_priority_gap,
            min_run_ms,
        })
    }

    /// Decide.
    pub fn decide(&self, current: &RunningTask, incoming: &IncomingTask, now_ms: u64) -> PreemptVerdict {
        // Anti-thrash window.
        let run_age = now_ms.saturating_sub(current.started_at_ms);
        if run_age < self.min_run_ms {
            return PreemptVerdict::Keep {
                reason: format!("anti-thrash: current ran {run_age}ms < min {min}ms", min = self.min_run_ms),
            };
        }
        // Priority gap.
        let cur = current.priority.rank();
        let inc = incoming.priority.rank();
        if inc <= cur {
            return PreemptVerdict::Keep {
                reason: format!("incoming priority {:?} does not outrank current {:?}", incoming.priority, current.priority),
            };
        }
        let gap = inc - cur;
        if gap < self.min_priority_gap {
            return PreemptVerdict::Keep {
                reason: format!("gap {gap} < min_gap {gap_min}", gap_min = self.min_priority_gap),
            };
        }
        PreemptVerdict::Preempt
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PreemptError> {
        if self.schema_version != SCHEMA_VERSION { return Err(PreemptError::SchemaMismatch); }
        if self.min_priority_gap > 4 { return Err(PreemptError::BadGap); }
        Ok(())
    }
}

impl Default for TaskPreemptionPolicy {
    fn default() -> Self { Self::new(1, 1000).unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, p: Priority, started: u64) -> RunningTask {
        RunningTask { id: id.into(), priority: p, started_at_ms: started }
    }

    fn inc(id: &str, p: Priority) -> IncomingTask {
        IncomingTask { id: id.into(), priority: p }
    }

    #[test]
    fn preempt_when_higher_priority_after_window() {
        let p = TaskPreemptionPolicy::new(1, 1000).unwrap();
        let c = task("a", Priority::Normal, 0);
        let i = inc("b", Priority::Critical);
        assert_eq!(p.decide(&c, &i, 5000), PreemptVerdict::Preempt);
    }

    #[test]
    fn anti_thrash_holds() {
        let p = TaskPreemptionPolicy::new(1, 1000).unwrap();
        let c = task("a", Priority::Normal, 0);
        let i = inc("b", Priority::Critical);
        match p.decide(&c, &i, 500) {
            PreemptVerdict::Keep { reason } => assert!(reason.contains("anti-thrash")),
            _ => panic!(),
        }
    }

    #[test]
    fn equal_priority_keeps() {
        let p = TaskPreemptionPolicy::new(1, 0).unwrap();
        let c = task("a", Priority::Normal, 0);
        let i = inc("b", Priority::Normal);
        match p.decide(&c, &i, 5000) {
            PreemptVerdict::Keep { .. } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn lower_priority_keeps() {
        let p = TaskPreemptionPolicy::new(1, 0).unwrap();
        let c = task("a", Priority::High, 0);
        let i = inc("b", Priority::Low);
        match p.decide(&c, &i, 5000) {
            PreemptVerdict::Keep { .. } => {}
            _ => panic!(),
        }
    }

    #[test]
    fn small_gap_below_threshold_keeps() {
        let p = TaskPreemptionPolicy::new(2, 0).unwrap();
        let c = task("a", Priority::Normal, 0); // rank 2
        let i = inc("b", Priority::High); // rank 3, gap 1
        match p.decide(&c, &i, 5000) {
            PreemptVerdict::Keep { reason } => assert!(reason.contains("gap")),
            _ => panic!(),
        }
    }

    #[test]
    fn large_gap_at_threshold_preempts() {
        let p = TaskPreemptionPolicy::new(2, 0).unwrap();
        let c = task("a", Priority::Normal, 0); // rank 2
        let i = inc("b", Priority::Critical); // rank 4, gap 2
        assert_eq!(p.decide(&c, &i, 5000), PreemptVerdict::Preempt);
    }

    #[test]
    fn priority_ranks() {
        assert!(Priority::Critical.rank() > Priority::High.rank());
        assert!(Priority::Background.rank() < Priority::Low.rank());
    }

    #[test]
    fn bad_gap_rejected() {
        assert!(matches!(TaskPreemptionPolicy::new(5, 0).unwrap_err(), PreemptError::BadGap));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TaskPreemptionPolicy::new(1, 0).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PreemptError::SchemaMismatch));
    }

    #[test]
    fn preempt_serde_roundtrip() {
        let p = TaskPreemptionPolicy::new(1, 1000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: TaskPreemptionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
