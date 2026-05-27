//! `selfdef-undo-log` — bounded undo+redo over opaque action ids.
//!
//! record(id) clears the redo stack and pushes id on undo. undo()
//! pops from undo and pushes onto redo (returns id). redo() pops
//! from redo and pushes onto undo. capacity-bounded; oldest undos
//! are front-evicted when capacity exceeded.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UndoLog {
    /// Schema version.
    pub schema_version: String,
    /// Capacity.
    pub capacity: u32,
    /// Undo stack (front=oldest).
    pub undo_stack: VecDeque<String>,
    /// Redo stack (back=most-recent-undone).
    pub redo_stack: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum UndoError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero cap.
    #[error("capacity must be >= 1")]
    ZeroCap,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Nothing to undo.
    #[error("nothing to undo")]
    NothingToUndo,
    /// Nothing to redo.
    #[error("nothing to redo")]
    NothingToRedo,
}

impl UndoLog {
    /// New.
    pub fn new(capacity: u32) -> Result<Self, UndoError> {
        if capacity == 0 {
            return Err(UndoError::ZeroCap);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            capacity,
            undo_stack: VecDeque::new(),
            redo_stack: Vec::new(),
        })
    }

    /// Record a new action; clears redo.
    pub fn record(&mut self, id: &str) -> Result<(), UndoError> {
        if id.is_empty() {
            return Err(UndoError::EmptyId);
        }
        self.redo_stack.clear();
        self.undo_stack.push_back(id.into());
        while self.undo_stack.len() > self.capacity as usize {
            self.undo_stack.pop_front();
        }
        Ok(())
    }

    /// Undo.
    pub fn undo(&mut self) -> Result<String, UndoError> {
        let id = self.undo_stack.pop_back().ok_or(UndoError::NothingToUndo)?;
        self.redo_stack.push(id.clone());
        Ok(id)
    }

    /// Redo.
    pub fn redo(&mut self) -> Result<String, UndoError> {
        let id = self.redo_stack.pop().ok_or(UndoError::NothingToRedo)?;
        self.undo_stack.push_back(id.clone());
        while self.undo_stack.len() > self.capacity as usize {
            self.undo_stack.pop_front();
        }
        Ok(id)
    }

    /// Can undo?
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Can redo?
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), UndoError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(UndoError::SchemaMismatch);
        }
        if self.capacity == 0 {
            return Err(UndoError::ZeroCap);
        }
        for id in self.undo_stack.iter().chain(self.redo_stack.iter()) {
            if id.is_empty() {
                return Err(UndoError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_then_undo() {
        let mut l = UndoLog::new(10).unwrap();
        l.record("a").unwrap();
        l.record("b").unwrap();
        assert_eq!(l.undo().unwrap(), "b");
        assert_eq!(l.undo().unwrap(), "a");
        assert!(matches!(l.undo().unwrap_err(), UndoError::NothingToUndo));
    }

    #[test]
    fn redo_replays() {
        let mut l = UndoLog::new(10).unwrap();
        l.record("a").unwrap();
        l.record("b").unwrap();
        l.undo().unwrap();
        l.undo().unwrap();
        assert_eq!(l.redo().unwrap(), "a");
        assert_eq!(l.redo().unwrap(), "b");
    }

    #[test]
    fn record_clears_redo() {
        let mut l = UndoLog::new(10).unwrap();
        l.record("a").unwrap();
        l.undo().unwrap();
        assert!(l.can_redo());
        l.record("b").unwrap();
        assert!(!l.can_redo());
    }

    #[test]
    fn capacity_evicts_oldest_undo() {
        let mut l = UndoLog::new(2).unwrap();
        l.record("a").unwrap();
        l.record("b").unwrap();
        l.record("c").unwrap();
        // Only b, c retained.
        assert_eq!(l.undo().unwrap(), "c");
        assert_eq!(l.undo().unwrap(), "b");
        assert!(matches!(l.undo().unwrap_err(), UndoError::NothingToUndo));
    }

    #[test]
    fn empty_id_rejected() {
        let mut l = UndoLog::new(2).unwrap();
        assert!(matches!(l.record("").unwrap_err(), UndoError::EmptyId));
    }

    #[test]
    fn zero_cap_rejected() {
        assert!(matches!(UndoLog::new(0).unwrap_err(), UndoError::ZeroCap));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut l = UndoLog::new(2).unwrap();
        l.schema_version = "9.9.9".into();
        assert!(matches!(
            l.validate().unwrap_err(),
            UndoError::SchemaMismatch
        ));
    }

    #[test]
    fn log_serde_roundtrip() {
        let mut l = UndoLog::new(5).unwrap();
        l.record("a").unwrap();
        l.record("b").unwrap();
        l.undo().unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: UndoLog = serde_json::from_str(&j).unwrap();
        assert_eq!(l, back);
    }
}
