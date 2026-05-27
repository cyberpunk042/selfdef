//! `selfdef-graceful-shutdown` — multi-stage drain.
//!
//! Stages: Running → StopAccepting → Draining → Terminated.
//! Each stage has a deadline; tick(now) advances past timeouts.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Stage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Running normally.
    Running,
    /// Stop accepting new work.
    StopAccepting,
    /// Drain in-flight.
    Draining,
    /// Terminated.
    Terminated,
}

/// State.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GracefulShutdown {
    /// Schema version marker.
    pub schema_version_marker: u32,
    /// Stage.
    pub stage: Stage,
    /// Time entered current stage.
    pub stage_entered_ms: u64,
    /// Max time in StopAccepting before Draining.
    pub stop_accepting_max_ms: u64,
    /// Max time in Draining before Terminated.
    pub draining_max_ms: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ShutdownError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Invalid transition.
    #[error("invalid transition from {0:?}")]
    InvalidTransition(Stage),
}

impl GracefulShutdown {
    /// New.
    pub fn new(stop_accepting_max_ms: u64, draining_max_ms: u64) -> Self {
        Self {
            schema_version_marker: 1,
            stage: Stage::Running,
            stage_entered_ms: 0,
            stop_accepting_max_ms,
            draining_max_ms,
        }
    }

    /// Begin shutdown (Running → StopAccepting).
    pub fn begin(&mut self, ts_ms: u64) -> Result<(), ShutdownError> {
        if self.stage != Stage::Running {
            return Err(ShutdownError::InvalidTransition(self.stage));
        }
        self.stage = Stage::StopAccepting;
        self.stage_entered_ms = ts_ms;
        Ok(())
    }

    /// Force into Draining (e.g. no inbound work to drain stop-accepting).
    pub fn force_drain(&mut self, ts_ms: u64) -> Result<(), ShutdownError> {
        if !matches!(self.stage, Stage::StopAccepting) {
            return Err(ShutdownError::InvalidTransition(self.stage));
        }
        self.stage = Stage::Draining;
        self.stage_entered_ms = ts_ms;
        Ok(())
    }

    /// Force terminate (from Draining).
    pub fn force_terminate(&mut self, ts_ms: u64) -> Result<(), ShutdownError> {
        if !matches!(self.stage, Stage::Draining | Stage::StopAccepting) {
            return Err(ShutdownError::InvalidTransition(self.stage));
        }
        self.stage = Stage::Terminated;
        self.stage_entered_ms = ts_ms;
        Ok(())
    }

    /// Tick — auto-advance stages on per-stage timeout.
    pub fn tick(&mut self, now_ms: u64) -> Stage {
        let elapsed = now_ms.saturating_sub(self.stage_entered_ms);
        match self.stage {
            Stage::StopAccepting if elapsed >= self.stop_accepting_max_ms => {
                self.stage = Stage::Draining;
                self.stage_entered_ms = now_ms;
            }
            Stage::Draining if elapsed >= self.draining_max_ms => {
                self.stage = Stage::Terminated;
                self.stage_entered_ms = now_ms;
            }
            _ => {}
        }
        self.stage
    }

    /// Accepting new work?
    pub fn accepting_new(&self) -> bool {
        self.stage == Stage::Running
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ShutdownError> {
        if self.schema_version_marker != 1 {
            return Err(ShutdownError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_transitions_to_stop_accepting() {
        let mut s = GracefulShutdown::new(1000, 5000);
        s.begin(0).unwrap();
        assert_eq!(s.stage, Stage::StopAccepting);
    }

    #[test]
    fn double_begin_rejected() {
        let mut s = GracefulShutdown::new(1000, 5000);
        s.begin(0).unwrap();
        assert!(matches!(
            s.begin(1).unwrap_err(),
            ShutdownError::InvalidTransition(_)
        ));
    }

    #[test]
    fn tick_advances_through_stages() {
        let mut s = GracefulShutdown::new(1000, 5000);
        s.begin(0).unwrap();
        // After 1500ms in StopAccepting → Draining.
        assert_eq!(s.tick(1500), Stage::Draining);
        // After 5500ms in Draining → Terminated.
        assert_eq!(s.tick(1500 + 5500), Stage::Terminated);
    }

    #[test]
    fn accepting_new_only_in_running() {
        let mut s = GracefulShutdown::new(1000, 5000);
        assert!(s.accepting_new());
        s.begin(0).unwrap();
        assert!(!s.accepting_new());
    }

    #[test]
    fn force_drain_and_terminate() {
        let mut s = GracefulShutdown::new(1000, 5000);
        s.begin(0).unwrap();
        s.force_drain(100).unwrap();
        s.force_terminate(200).unwrap();
        assert_eq!(s.stage, Stage::Terminated);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = GracefulShutdown::new(1, 1);
        s.schema_version_marker = 99;
        assert!(matches!(
            s.validate().unwrap_err(),
            ShutdownError::SchemaMismatch
        ));
    }

    #[test]
    fn shutdown_serde_roundtrip() {
        let mut s = GracefulShutdown::new(1000, 5000);
        s.begin(0).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: GracefulShutdown = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
