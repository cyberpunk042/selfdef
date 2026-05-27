//! `selfdef-emergency-pause-policy` — soft-hold lever.
//!
//! Operator-toggleable pause flag that:
//! * blocks new task starts (admit_new_task returns Deny);
//! * leaves in-flight tasks free to reach their next safe checkpoint
//!   (admit_checkpoint returns Allow); they then park.
//!
//! Distinct from emergency-stop (which forbids everything but rescue).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Pause state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PauseState {
    /// Running.
    Running,
    /// Paused (no new starts; checkpoint parking allowed).
    Paused,
}

/// Operation classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationClass {
    /// Start a brand-new task.
    NewTask,
    /// In-flight task reaching a safe checkpoint.
    Checkpoint,
    /// Parked task resuming (only with operator release).
    Resume,
    /// Read-only / status query.
    ReadOnly,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PauseDecision {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyPausePolicy {
    /// Schema version.
    pub schema_version: String,
    /// State.
    pub state: PauseState,
    /// Reason text when paused (≤ 200 chars).
    pub reason: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PauseError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty reason when paused.
    #[error("reason empty when paused")]
    EmptyReason,
    /// Reason too long.
    #[error("reason length {0} > 200")]
    ReasonTooLong(usize),
}

impl EmergencyPausePolicy {
    /// New (Running).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            state: PauseState::Running,
            reason: String::new(),
        }
    }

    /// Engage pause with reason.
    pub fn pause(&mut self, reason: &str) -> Result<(), PauseError> {
        if reason.is_empty() {
            return Err(PauseError::EmptyReason);
        }
        let n = reason.chars().count();
        if n > 200 {
            return Err(PauseError::ReasonTooLong(n));
        }
        self.state = PauseState::Paused;
        self.reason = reason.into();
        Ok(())
    }

    /// Resume.
    pub fn resume(&mut self) {
        self.state = PauseState::Running;
        self.reason.clear();
    }

    /// Decide.
    pub fn admit(&self, op: OperationClass) -> PauseDecision {
        match self.state {
            PauseState::Running => PauseDecision::Allow,
            PauseState::Paused => match op {
                OperationClass::NewTask => PauseDecision::Deny,
                OperationClass::Checkpoint => PauseDecision::Allow,
                OperationClass::Resume => PauseDecision::Deny,
                OperationClass::ReadOnly => PauseDecision::Allow,
            },
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PauseError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PauseError::SchemaMismatch);
        }
        if self.state == PauseState::Paused {
            if self.reason.is_empty() {
                return Err(PauseError::EmptyReason);
            }
            let n = self.reason.chars().count();
            if n > 200 {
                return Err(PauseError::ReasonTooLong(n));
            }
        }
        Ok(())
    }
}

impl Default for EmergencyPausePolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_allows_everything() {
        let p = EmergencyPausePolicy::new();
        for op in [
            OperationClass::NewTask,
            OperationClass::Checkpoint,
            OperationClass::Resume,
            OperationClass::ReadOnly,
        ] {
            assert_eq!(p.admit(op), PauseDecision::Allow);
        }
    }

    #[test]
    fn paused_blocks_new_task() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("manual hold").unwrap();
        assert_eq!(p.admit(OperationClass::NewTask), PauseDecision::Deny);
    }

    #[test]
    fn paused_allows_checkpoint() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("manual hold").unwrap();
        assert_eq!(p.admit(OperationClass::Checkpoint), PauseDecision::Allow);
    }

    #[test]
    fn paused_blocks_resume() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("manual hold").unwrap();
        assert_eq!(p.admit(OperationClass::Resume), PauseDecision::Deny);
    }

    #[test]
    fn paused_allows_read_only() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("manual hold").unwrap();
        assert_eq!(p.admit(OperationClass::ReadOnly), PauseDecision::Allow);
    }

    #[test]
    fn resume_clears() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("x").unwrap();
        p.resume();
        assert_eq!(p.state, PauseState::Running);
        assert!(p.reason.is_empty());
    }

    #[test]
    fn empty_reason_rejected() {
        let mut p = EmergencyPausePolicy::new();
        assert!(matches!(p.pause("").unwrap_err(), PauseError::EmptyReason));
    }

    #[test]
    fn long_reason_rejected() {
        let mut p = EmergencyPausePolicy::new();
        let r = "x".repeat(201);
        assert!(matches!(
            p.pause(&r).unwrap_err(),
            PauseError::ReasonTooLong(201)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = EmergencyPausePolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            PauseError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&PauseState::Paused).unwrap(),
            "\"paused\""
        );
    }

    #[test]
    fn op_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&OperationClass::NewTask).unwrap(),
            "\"new-task\""
        );
        assert_eq!(
            serde_json::to_string(&OperationClass::ReadOnly).unwrap(),
            "\"read-only\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = EmergencyPausePolicy::new();
        p.pause("hold").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: EmergencyPausePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
