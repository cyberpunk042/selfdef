//! `selfdef-recurring-task-scheduler` — fixed-interval scheduler.
//!
//! Per task id, register a `RecurringTask{interval_ms, first_due_ms,
//! enabled}`. `due_at(now_ms)` returns the ordered list of task
//! ids whose due time is ≤ now. `mark_run(task_id, now_ms)`
//! advances the next-due by `interval_ms` from now (drift-resistant
//! variant: skip past due times if now overshoots a tick). `disable`
//! / `enable` toggle without losing the schedule.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-task record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecurringTask {
    /// Interval.
    pub interval_ms: u64,
    /// Next due timestamp.
    pub next_due_ms: u64,
    /// Enabled?
    pub enabled: bool,
    /// Total runs.
    pub runs: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecurringTaskScheduler {
    /// Schema version.
    pub schema_version: String,
    /// task_id → task.
    pub tasks: BTreeMap<String, RecurringTask>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty task id.
    #[error("task id empty")]
    EmptyTask,
    /// Zero interval.
    #[error("interval must be > 0")]
    ZeroInterval,
    /// Unknown task.
    #[error("unknown task: {0}")]
    UnknownTask(String),
}

impl RecurringTaskScheduler {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tasks: BTreeMap::new(),
        }
    }

    /// Register a task with first due time.
    pub fn register(
        &mut self,
        task_id: &str,
        interval_ms: u64,
        first_due_ms: u64,
    ) -> Result<(), SchedulerError> {
        if task_id.is_empty() {
            return Err(SchedulerError::EmptyTask);
        }
        if interval_ms == 0 {
            return Err(SchedulerError::ZeroInterval);
        }
        self.tasks.insert(
            task_id.into(),
            RecurringTask {
                interval_ms,
                next_due_ms: first_due_ms,
                enabled: true,
                runs: 0,
            },
        );
        Ok(())
    }

    /// Enable / disable.
    pub fn set_enabled(&mut self, task_id: &str, enabled: bool) -> Result<(), SchedulerError> {
        let t = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| SchedulerError::UnknownTask(task_id.into()))?;
        t.enabled = enabled;
        Ok(())
    }

    /// All currently-due tasks (enabled, ordered by next_due then id).
    pub fn due_at(&self, now_ms: u64) -> Vec<String> {
        let mut due: Vec<(&String, &RecurringTask)> = self
            .tasks
            .iter()
            .filter(|(_, t)| t.enabled && now_ms >= t.next_due_ms)
            .collect();
        due.sort_by(|a, b| a.1.next_due_ms.cmp(&b.1.next_due_ms).then(a.0.cmp(b.0)));
        due.into_iter().map(|(k, _)| k.clone()).collect()
    }

    /// Mark task as run. Advance next_due past now in interval steps
    /// — drift-resistant: if many ticks were missed we don't replay,
    /// we land on the first future tick.
    pub fn mark_run(&mut self, task_id: &str, now_ms: u64) -> Result<u64, SchedulerError> {
        let t = self
            .tasks
            .get_mut(task_id)
            .ok_or_else(|| SchedulerError::UnknownTask(task_id.into()))?;
        t.runs = t.runs.saturating_add(1);
        // Advance by interval until strictly > now.
        if t.next_due_ms <= now_ms {
            let elapsed = now_ms - t.next_due_ms;
            let ticks = elapsed / t.interval_ms + 1;
            t.next_due_ms = t
                .next_due_ms
                .saturating_add(ticks.saturating_mul(t.interval_ms));
        } else {
            t.next_due_ms = t.next_due_ms.saturating_add(t.interval_ms);
        }
        Ok(t.next_due_ms)
    }

    /// Get task.
    pub fn get(&self, task_id: &str) -> Option<&RecurringTask> {
        self.tasks.get(task_id)
    }

    /// Remove.
    pub fn remove(&mut self, task_id: &str) -> bool {
        self.tasks.remove(task_id).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SchedulerError::SchemaMismatch);
        }
        for (id, t) in &self.tasks {
            if id.is_empty() {
                return Err(SchedulerError::EmptyTask);
            }
            if t.interval_ms == 0 {
                return Err(SchedulerError::ZeroInterval);
            }
        }
        Ok(())
    }
}

impl Default for RecurringTaskScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_at_lists_currently_due() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 500).unwrap();
        s.register("b", 1000, 1500).unwrap();
        let d = s.due_at(1000);
        assert_eq!(d, vec!["a"]);
    }

    #[test]
    fn mark_run_advances_one_tick_if_on_time() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 1000).unwrap();
        let next = s.mark_run("a", 1000).unwrap();
        assert_eq!(next, 2000);
    }

    #[test]
    fn mark_run_skips_missed_ticks() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 1000).unwrap();
        // 4500ms in — should have run 4 times by now, skip ahead.
        let next = s.mark_run("a", 4500).unwrap();
        assert_eq!(next, 5000);
    }

    #[test]
    fn mark_run_future_due_advances_by_interval() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 5000).unwrap();
        // Called early (rare manual trigger).
        let next = s.mark_run("a", 3000).unwrap();
        assert_eq!(next, 6000);
    }

    #[test]
    fn disable_hides_from_due() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 0).unwrap();
        s.set_enabled("a", false).unwrap();
        assert!(s.due_at(5000).is_empty());
    }

    #[test]
    fn re_enable_resumes() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 0).unwrap();
        s.set_enabled("a", false).unwrap();
        s.set_enabled("a", true).unwrap();
        assert_eq!(s.due_at(5000), vec!["a"]);
    }

    #[test]
    fn due_ordered_by_next_due() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 100).unwrap();
        s.register("b", 1000, 50).unwrap();
        let d = s.due_at(200);
        assert_eq!(d, vec!["b", "a"]);
    }

    #[test]
    fn zero_interval_rejected() {
        let mut s = RecurringTaskScheduler::new();
        assert!(matches!(
            s.register("a", 0, 0).unwrap_err(),
            SchedulerError::ZeroInterval
        ));
    }

    #[test]
    fn empty_task_rejected() {
        let mut s = RecurringTaskScheduler::new();
        assert!(matches!(
            s.register("", 1000, 0).unwrap_err(),
            SchedulerError::EmptyTask
        ));
    }

    #[test]
    fn unknown_task_rejected() {
        let mut s = RecurringTaskScheduler::new();
        assert!(matches!(
            s.mark_run("nope", 0).unwrap_err(),
            SchedulerError::UnknownTask(_)
        ));
    }

    #[test]
    fn run_counter_increments() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 0).unwrap();
        s.mark_run("a", 0).unwrap();
        s.mark_run("a", 1000).unwrap();
        assert_eq!(s.get("a").unwrap().runs, 2);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = RecurringTaskScheduler::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SchedulerError::SchemaMismatch
        ));
    }

    #[test]
    fn scheduler_serde_roundtrip() {
        let mut s = RecurringTaskScheduler::new();
        s.register("a", 1000, 500).unwrap();
        s.mark_run("a", 500).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: RecurringTaskScheduler = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
