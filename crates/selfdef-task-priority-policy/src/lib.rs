//! `selfdef-task-priority-policy` — dispatch-order authority.
//!
//! Priority order (highest first):
//! 1. operator_pinned == true
//! 2. TaskClass: Emergency > Operator > Background > Maintenance
//! 3. earliest deadline_unix (None = +∞)
//! 4. insertion order
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Task class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskClass {
    /// Maintenance (lowest).
    Maintenance,
    /// Background.
    Background,
    /// Operator-initiated.
    Operator,
    /// Emergency (highest).
    Emergency,
}

impl TaskClass {
    /// Numeric priority (higher = wins).
    pub fn priority(self) -> u8 {
        match self {
            TaskClass::Maintenance => 1,
            TaskClass::Background => 2,
            TaskClass::Operator => 3,
            TaskClass::Emergency => 4,
        }
    }
}

/// One task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: TaskClass,
    /// Optional deadline.
    pub deadline_unix: Option<u64>,
    /// Operator pinned to front?
    pub operator_pinned: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskPriorityPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Tasks in insertion order.
    pub tasks: Vec<Task>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PriorityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("task id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate task id: {0}")]
    DuplicateId(String),
}

impl TaskPriorityPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tasks: Vec::new(),
        }
    }

    /// Enqueue a task.
    pub fn enqueue(&mut self, t: Task) -> Result<(), PriorityError> {
        if t.id.is_empty() { return Err(PriorityError::EmptyId); }
        if self.tasks.iter().any(|x| x.id == t.id) {
            return Err(PriorityError::DuplicateId(t.id));
        }
        self.tasks.push(t);
        Ok(())
    }

    /// Compute dispatch order.
    pub fn resolve_order(&self) -> Vec<&Task> {
        let mut indexed: Vec<(usize, &Task)> = self.tasks.iter().enumerate().collect();
        indexed.sort_by(|(ia, a), (ib, b)| {
            // 1. pinned first.
            b.operator_pinned.cmp(&a.operator_pinned)
                // 2. class priority desc.
                .then(b.class.priority().cmp(&a.class.priority()))
                // 3. earliest deadline (None = max u64).
                .then(a.deadline_unix.unwrap_or(u64::MAX).cmp(&b.deadline_unix.unwrap_or(u64::MAX)))
                // 4. insertion order.
                .then(ia.cmp(ib))
        });
        indexed.into_iter().map(|(_, t)| t).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PriorityError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PriorityError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for t in &self.tasks {
            if t.id.is_empty() { return Err(PriorityError::EmptyId); }
            if !seen.insert(t.id.as_str()) {
                return Err(PriorityError::DuplicateId(t.id.clone()));
            }
        }
        Ok(())
    }
}

impl Default for TaskPriorityPolicy {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(id: &str, class: TaskClass, deadline: Option<u64>, pinned: bool) -> Task {
        Task { id: id.into(), class, deadline_unix: deadline, operator_pinned: pinned }
    }

    #[test]
    fn class_priority_correct() {
        assert!(TaskClass::Emergency.priority() > TaskClass::Operator.priority());
        assert!(TaskClass::Operator.priority() > TaskClass::Background.priority());
        assert!(TaskClass::Background.priority() > TaskClass::Maintenance.priority());
    }

    #[test]
    fn class_orders_dispatch() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("maint", TaskClass::Maintenance, None, false)).unwrap();
        p.enqueue(t("emerg", TaskClass::Emergency, None, false)).unwrap();
        p.enqueue(t("op", TaskClass::Operator, None, false)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, vec!["emerg", "op", "maint"]);
    }

    #[test]
    fn pinned_jumps_front() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("emerg", TaskClass::Emergency, None, false)).unwrap();
        p.enqueue(t("pinned-bg", TaskClass::Background, None, true)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order[0], "pinned-bg");
    }

    #[test]
    fn earliest_deadline_wins_ties() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("late", TaskClass::Operator, Some(2000), false)).unwrap();
        p.enqueue(t("early", TaskClass::Operator, Some(1000), false)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, vec!["early", "late"]);
    }

    #[test]
    fn none_deadline_after_some() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("no-deadline", TaskClass::Operator, None, false)).unwrap();
        p.enqueue(t("urgent", TaskClass::Operator, Some(1000), false)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, vec!["urgent", "no-deadline"]);
    }

    #[test]
    fn insertion_tiebreak() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("a", TaskClass::Operator, None, false)).unwrap();
        p.enqueue(t("b", TaskClass::Operator, None, false)).unwrap();
        let order: Vec<&str> = p.resolve_order().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, vec!["a", "b"]);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("a", TaskClass::Operator, None, false)).unwrap();
        assert!(matches!(p.enqueue(t("a", TaskClass::Background, None, false)).unwrap_err(), PriorityError::DuplicateId(_)));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = TaskPriorityPolicy::new();
        assert!(matches!(p.enqueue(t("", TaskClass::Operator, None, false)).unwrap_err(), PriorityError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TaskPriorityPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), PriorityError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&TaskClass::Emergency).unwrap(), "\"emergency\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = TaskPriorityPolicy::new();
        p.enqueue(t("a", TaskClass::Operator, Some(100), false)).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: TaskPriorityPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
