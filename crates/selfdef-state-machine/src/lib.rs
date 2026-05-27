//! `selfdef-state-machine` — named-states FSM.
//!
//! Transitions: (from, event) → to. add_transition rejects
//! duplicates. fire(event) consults table; transitions or
//! errors UndefinedTransition. transitions counter; history
//! capped at history_capacity (oldest evicted).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// History entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    /// From state.
    pub from: String,
    /// Event.
    pub event: String,
    /// To state.
    pub to: String,
    /// ts ms.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMachine {
    /// Schema version.
    pub schema_version: String,
    /// Current state.
    pub current: String,
    /// "from||event" → to.
    pub transitions: BTreeMap<String, String>,
    /// History.
    pub history: Vec<HistoryEntry>,
    /// History capacity.
    pub history_capacity: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FsmError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("state empty")]
    EmptyState,
    /// Empty.
    #[error("event empty")]
    EmptyEvent,
    /// Zero capacity.
    #[error("history_capacity must be >= 1")]
    ZeroCapacity,
    /// Duplicate.
    #[error("duplicate transition: ({0}, {1})")]
    DuplicateTransition(String, String),
    /// Undefined.
    #[error("undefined transition: ({0}, {1})")]
    UndefinedTransition(String, String),
}

fn key(from: &str, event: &str) -> String {
    format!("{from}||{event}")
}

impl StateMachine {
    /// New.
    pub fn new(initial: &str, history_capacity: u32) -> Result<Self, FsmError> {
        if initial.is_empty() {
            return Err(FsmError::EmptyState);
        }
        if history_capacity == 0 {
            return Err(FsmError::ZeroCapacity);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            current: initial.into(),
            transitions: BTreeMap::new(),
            history: Vec::new(),
            history_capacity,
        })
    }

    /// Add a transition.
    pub fn add_transition(&mut self, from: &str, event: &str, to: &str) -> Result<(), FsmError> {
        if from.is_empty() || to.is_empty() {
            return Err(FsmError::EmptyState);
        }
        if event.is_empty() {
            return Err(FsmError::EmptyEvent);
        }
        let k = key(from, event);
        if self.transitions.contains_key(&k) {
            return Err(FsmError::DuplicateTransition(from.into(), event.into()));
        }
        self.transitions.insert(k, to.into());
        Ok(())
    }

    /// Fire event.
    pub fn fire(&mut self, event: &str, ts_ms: u64) -> Result<&str, FsmError> {
        if event.is_empty() {
            return Err(FsmError::EmptyEvent);
        }
        let k = key(&self.current, event);
        let to = self
            .transitions
            .get(&k)
            .ok_or_else(|| FsmError::UndefinedTransition(self.current.clone(), event.into()))?
            .clone();
        let from = self.current.clone();
        self.current = to.clone();
        if (self.history.len() as u32) >= self.history_capacity {
            self.history.remove(0);
        }
        self.history.push(HistoryEntry {
            from,
            event: event.into(),
            to,
            ts_ms,
        });
        Ok(&self.current)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FsmError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FsmError::SchemaMismatch);
        }
        if self.current.is_empty() {
            return Err(FsmError::EmptyState);
        }
        if self.history_capacity == 0 {
            return Err(FsmError::ZeroCapacity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic_light() -> StateMachine {
        let mut m = StateMachine::new("red", 5).unwrap();
        m.add_transition("red", "tick", "green").unwrap();
        m.add_transition("green", "tick", "yellow").unwrap();
        m.add_transition("yellow", "tick", "red").unwrap();
        m
    }

    #[test]
    fn fires_through_states() {
        let mut m = traffic_light();
        assert_eq!(m.fire("tick", 100).unwrap(), "green");
        assert_eq!(m.fire("tick", 200).unwrap(), "yellow");
        assert_eq!(m.fire("tick", 300).unwrap(), "red");
    }

    #[test]
    fn undefined_transition_rejected() {
        let mut m = traffic_light();
        assert!(matches!(
            m.fire("bogus", 0).unwrap_err(),
            FsmError::UndefinedTransition(_, _)
        ));
        // State unchanged.
        assert_eq!(m.current, "red");
    }

    #[test]
    fn duplicate_transition_rejected() {
        let mut m = StateMachine::new("a", 5).unwrap();
        m.add_transition("a", "go", "b").unwrap();
        assert!(matches!(
            m.add_transition("a", "go", "c").unwrap_err(),
            FsmError::DuplicateTransition(_, _)
        ));
    }

    #[test]
    fn history_records() {
        let mut m = traffic_light();
        m.fire("tick", 100).unwrap();
        m.fire("tick", 200).unwrap();
        assert_eq!(m.history.len(), 2);
        assert_eq!(m.history[1].from, "green");
        assert_eq!(m.history[1].to, "yellow");
    }

    #[test]
    fn history_capacity_drops_oldest() {
        let mut m = StateMachine::new("a", 2).unwrap();
        m.add_transition("a", "x", "a").unwrap();
        m.fire("x", 1).unwrap();
        m.fire("x", 2).unwrap();
        m.fire("x", 3).unwrap();
        assert_eq!(m.history.len(), 2);
        assert_eq!(m.history[0].ts_ms, 2);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut m = StateMachine::new("a", 5).unwrap();
        assert!(matches!(m.fire("", 0).unwrap_err(), FsmError::EmptyEvent));
        assert!(matches!(
            m.add_transition("", "e", "b").unwrap_err(),
            FsmError::EmptyState
        ));
        assert!(matches!(
            StateMachine::new("", 5).unwrap_err(),
            FsmError::EmptyState
        ));
        assert!(matches!(
            StateMachine::new("a", 0).unwrap_err(),
            FsmError::ZeroCapacity
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = traffic_light();
        m.schema_version = "9.9.9".into();
        assert!(matches!(
            m.validate().unwrap_err(),
            FsmError::SchemaMismatch
        ));
    }

    #[test]
    fn fsm_serde_roundtrip() {
        let mut m = traffic_light();
        m.fire("tick", 100).unwrap();
        let j = serde_json::to_string(&m).unwrap();
        let back: StateMachine = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
