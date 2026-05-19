//! `selfdef-execution-mode-history` — mode-transition log.
//!
//! Bounded chronological log of mode transitions for audit dashboards.
//! record(from, to, at, by, reason) appends + caps; query helpers
//! select by source/target mode.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// ExecutionMode (mirror of selfdef-execution-mode-policy enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionMode {
    /// Plan.
    Plan,
    /// DryRun.
    DryRun,
    /// Shadow.
    Shadow,
    /// Sandbox.
    Sandbox,
    /// Execute.
    Execute,
    /// Replay.
    Replay,
    /// Debug.
    Debug,
}

/// One transition record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transition {
    /// From.
    pub from: ExecutionMode,
    /// To.
    pub to: ExecutionMode,
    /// ISO-8601 UTC.
    pub at: String,
    /// Operator/authority id.
    pub by: String,
    /// Reason (≤ 200 chars).
    pub reason: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionModeHistory {
    /// Schema version.
    pub schema_version: String,
    /// Transitions in chronological order.
    pub transitions: Vec<Transition>,
    /// Max retained.
    pub max_entries: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum HistoryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_entries zero.
    #[error("max_entries is zero")]
    MaxZero,
    /// Empty by.
    #[error("by empty")]
    EmptyBy,
    /// Reason too long.
    #[error("reason length {0} > 200")]
    ReasonTooLong(usize),
}

impl ExecutionModeHistory {
    /// New.
    pub fn new(max_entries: u32) -> Result<Self, HistoryError> {
        if max_entries == 0 { return Err(HistoryError::MaxZero); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            transitions: Vec::new(),
            max_entries,
        })
    }

    /// Append.
    pub fn record(&mut self, from: ExecutionMode, to: ExecutionMode, at: &str, by: &str, reason: &str) -> Result<(), HistoryError> {
        if by.is_empty() { return Err(HistoryError::EmptyBy); }
        let n = reason.chars().count();
        if n > 200 { return Err(HistoryError::ReasonTooLong(n)); }
        self.transitions.push(Transition {
            from, to,
            at: at.into(),
            by: by.into(),
            reason: reason.into(),
        });
        while (self.transitions.len() as u32) > self.max_entries {
            self.transitions.remove(0);
        }
        Ok(())
    }

    /// Filter by source mode.
    pub fn transitions_from(&self, mode: ExecutionMode) -> Vec<&Transition> {
        self.transitions.iter().filter(|t| t.from == mode).collect()
    }

    /// Filter by target mode.
    pub fn transitions_to(&self, mode: ExecutionMode) -> Vec<&Transition> {
        self.transitions.iter().filter(|t| t.to == mode).collect()
    }

    /// Last recorded mode (latest `to`).
    pub fn current_mode(&self) -> Option<ExecutionMode> {
        self.transitions.last().map(|t| t.to)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), HistoryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HistoryError::SchemaMismatch);
        }
        if self.max_entries == 0 { return Err(HistoryError::MaxZero); }
        for t in &self.transitions {
            if t.by.is_empty() { return Err(HistoryError::EmptyBy); }
            let n = t.reason.chars().count();
            if n > 200 { return Err(HistoryError::ReasonTooLong(n)); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecutionMode::*;

    #[test]
    fn max_zero_rejected() {
        assert!(matches!(ExecutionModeHistory::new(0).unwrap_err(), HistoryError::MaxZero));
    }

    #[test]
    fn record_appends() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.record(Plan, DryRun, "t", "ops", "review").unwrap();
        assert_eq!(h.transitions.len(), 1);
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut h = ExecutionModeHistory::new(2).unwrap();
        h.record(Plan, DryRun, "t1", "ops", "").unwrap();
        h.record(DryRun, Shadow, "t2", "ops", "").unwrap();
        h.record(Shadow, Execute, "t3", "ops", "").unwrap();
        assert_eq!(h.transitions.len(), 2);
        assert_eq!(h.transitions[0].from, DryRun);
    }

    #[test]
    fn transitions_to_filter() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.record(Plan, DryRun, "t", "ops", "").unwrap();
        h.record(Plan, Shadow, "t", "ops", "").unwrap();
        h.record(Shadow, Execute, "t", "ops", "").unwrap();
        assert_eq!(h.transitions_to(DryRun).len(), 1);
        assert_eq!(h.transitions_to(Execute).len(), 1);
    }

    #[test]
    fn transitions_from_filter() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.record(Plan, DryRun, "t", "ops", "").unwrap();
        h.record(Plan, Shadow, "t", "ops", "").unwrap();
        assert_eq!(h.transitions_from(Plan).len(), 2);
    }

    #[test]
    fn current_mode_is_last_to() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.record(Plan, DryRun, "t", "ops", "").unwrap();
        h.record(DryRun, Execute, "t", "ops", "").unwrap();
        assert_eq!(h.current_mode(), Some(Execute));
    }

    #[test]
    fn empty_history_no_current() {
        let h = ExecutionModeHistory::new(5).unwrap();
        assert!(h.current_mode().is_none());
    }

    #[test]
    fn empty_by_rejected() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        assert!(matches!(h.record(Plan, DryRun, "t", "", "").unwrap_err(), HistoryError::EmptyBy));
    }

    #[test]
    fn reason_too_long_rejected() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        let r = "x".repeat(201);
        assert!(matches!(h.record(Plan, DryRun, "t", "ops", &r).unwrap_err(), HistoryError::ReasonTooLong(201)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.schema_version = "9.9.9".into();
        assert!(matches!(h.validate().unwrap_err(), HistoryError::SchemaMismatch));
    }

    #[test]
    fn mode_serde_kebab() {
        assert_eq!(serde_json::to_string(&ExecutionMode::DryRun).unwrap(), "\"dry-run\"");
    }

    #[test]
    fn history_serde_roundtrip() {
        let mut h = ExecutionModeHistory::new(5).unwrap();
        h.record(Plan, DryRun, "t", "ops", "").unwrap();
        let j = serde_json::to_string(&h).unwrap();
        let back: ExecutionModeHistory = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
