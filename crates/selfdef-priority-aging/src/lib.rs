//! `selfdef-priority-aging` — aging-priority queue.
//!
//! Job{id, base_priority, enqueued_at_ms}. effective_priority(now)
//! = base_priority + (now - enqueued_at_ms) / age_step_ms. The
//! queue's next() returns the job with the highest effective
//! priority (ties broken by lower id). Prevents starvation of
//! low-priority jobs while still preferring high-priority work.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Job {
    /// Stable id.
    pub id: String,
    /// Base priority (higher wins).
    pub base_priority: u32,
    /// Enqueue ts ms.
    pub enqueued_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorityAging {
    /// Schema version.
    pub schema_version: String,
    /// Age step ms — each step adds 1 to effective priority.
    pub age_step_ms: u64,
    /// Pending jobs.
    pub jobs: Vec<Job>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AgingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero step.
    #[error("age_step_ms must be >= 1")]
    ZeroStep,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate job id: {0}")]
    Duplicate(String),
}

impl PriorityAging {
    /// New.
    pub fn new(age_step_ms: u64) -> Result<Self, AgingError> {
        if age_step_ms == 0 {
            return Err(AgingError::ZeroStep);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            age_step_ms,
            jobs: Vec::new(),
        })
    }

    /// Enqueue.
    pub fn enqueue(&mut self, id: &str, base_priority: u32, now_ms: u64) -> Result<(), AgingError> {
        if id.is_empty() {
            return Err(AgingError::EmptyId);
        }
        if self.jobs.iter().any(|j| j.id == id) {
            return Err(AgingError::Duplicate(id.into()));
        }
        self.jobs.push(Job {
            id: id.into(),
            base_priority,
            enqueued_at_ms: now_ms,
        });
        Ok(())
    }

    /// Compute effective priority at now_ms for a job.
    pub fn effective(&self, job: &Job, now_ms: u64) -> u64 {
        let waited = now_ms.saturating_sub(job.enqueued_at_ms);
        let bump = waited / self.age_step_ms;
        job.base_priority as u64 + bump
    }

    /// Pop highest effective priority (ties → lower id).
    pub fn next(&mut self, now_ms: u64) -> Option<Job> {
        let idx = self
            .jobs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                let ea = self.effective(a, now_ms);
                let eb = self.effective(b, now_ms);
                ea.cmp(&eb).then(b.id.cmp(&a.id))
            })
            .map(|(i, _)| i)?;
        Some(self.jobs.remove(idx))
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AgingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AgingError::SchemaMismatch);
        }
        if self.age_step_ms == 0 {
            return Err(AgingError::ZeroStep);
        }
        for j in &self.jobs {
            if j.id.is_empty() {
                return Err(AgingError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_base_wins_immediately() {
        let mut p = PriorityAging::new(1000).unwrap();
        p.enqueue("low", 1, 0).unwrap();
        p.enqueue("high", 10, 0).unwrap();
        assert_eq!(p.next(0).unwrap().id, "high");
    }

    #[test]
    fn aging_overtakes_after_enough_wait() {
        let mut p = PriorityAging::new(1000).unwrap();
        p.enqueue("low", 1, 0).unwrap(); // eff at 20s = 1+20 = 21
        p.enqueue("high", 10, 10000).unwrap(); // eff at 20s = 10+10 = 20
        assert_eq!(p.next(20000).unwrap().id, "low");
    }

    #[test]
    fn tie_broken_by_lower_id() {
        let mut p = PriorityAging::new(1000).unwrap();
        p.enqueue("b", 5, 0).unwrap();
        p.enqueue("a", 5, 0).unwrap();
        assert_eq!(p.next(0).unwrap().id, "a");
    }

    #[test]
    fn duplicate_rejected() {
        let mut p = PriorityAging::new(1000).unwrap();
        p.enqueue("a", 1, 0).unwrap();
        assert!(matches!(
            p.enqueue("a", 2, 0).unwrap_err(),
            AgingError::Duplicate(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = PriorityAging::new(1000).unwrap();
        assert!(matches!(
            p.enqueue("", 1, 0).unwrap_err(),
            AgingError::EmptyId
        ));
    }

    #[test]
    fn zero_step_rejected() {
        assert!(matches!(
            PriorityAging::new(0).unwrap_err(),
            AgingError::ZeroStep
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = PriorityAging::new(1000).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            AgingError::SchemaMismatch
        ));
    }

    #[test]
    fn aging_serde_roundtrip() {
        let mut p = PriorityAging::new(500).unwrap();
        p.enqueue("a", 3, 100).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: PriorityAging = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
