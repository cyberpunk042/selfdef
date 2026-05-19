//! `selfdef-process-spawn-registry` — tracked subprocesses.
//!
//! Each `SpawnedProcess` records (pid, command, args, owner_subject,
//! started_at, exited_at). The registry refuses double-registration of
//! a pid; recording exit clears the live entry.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-process record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpawnedProcess {
    /// OS process id.
    pub pid: i32,
    /// Command (argv[0]).
    pub command: String,
    /// Arguments (argv[1..]).
    pub args: Vec<String>,
    /// Owning subject.
    pub owner_subject: String,
    /// ISO-8601 UTC started.
    pub started_at: String,
    /// ISO-8601 UTC exited; empty while running.
    pub exited_at: String,
    /// Exit code (0 by default while running).
    pub exit_code: i32,
}

/// Registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessSpawnRegistry {
    /// Schema version.
    pub schema_version: String,
    /// Live processes keyed by pid.
    pub live: HashMap<i32, SpawnedProcess>,
    /// Exited processes (history, capped at 1000).
    pub history: Vec<SpawnedProcess>,
}

/// Maximum history length.
pub const MAX_HISTORY: usize = 1000;

/// Errors.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// pid <= 0.
    #[error("pid {0} invalid (must be > 0)")]
    InvalidPid(i32),
    /// Empty command.
    #[error("command empty")]
    EmptyCommand,
    /// Empty owner.
    #[error("owner_subject empty")]
    EmptyOwner,
    /// Empty started_at.
    #[error("started_at missing")]
    MissingStartedAt,
    /// Duplicate pid.
    #[error("duplicate pid: {0}")]
    DuplicatePid(i32),
    /// Unknown pid.
    #[error("unknown pid: {0}")]
    Unknown(i32),
}

impl ProcessSpawnRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            live: HashMap::new(),
            history: Vec::new(),
        }
    }

    /// Register a freshly-spawned process.
    pub fn record_spawn(&mut self, p: SpawnedProcess) -> Result<(), ProcessError> {
        if p.pid <= 0 { return Err(ProcessError::InvalidPid(p.pid)); }
        if p.command.is_empty() { return Err(ProcessError::EmptyCommand); }
        if p.owner_subject.is_empty() { return Err(ProcessError::EmptyOwner); }
        if p.started_at.is_empty() { return Err(ProcessError::MissingStartedAt); }
        if self.live.contains_key(&p.pid) {
            return Err(ProcessError::DuplicatePid(p.pid));
        }
        self.live.insert(p.pid, p);
        Ok(())
    }

    /// Record process exit. Moves entry to history.
    pub fn record_exit(&mut self, pid: i32, exit_code: i32, at: &str) -> Result<(), ProcessError> {
        let mut p = self.live.remove(&pid).ok_or(ProcessError::Unknown(pid))?;
        p.exited_at = at.into();
        p.exit_code = exit_code;
        self.history.push(p);
        while self.history.len() > MAX_HISTORY {
            self.history.remove(0);
        }
        Ok(())
    }

    /// Live count.
    pub fn live_count(&self) -> usize { self.live.len() }

    /// Live processes owned by subject.
    pub fn live_for_subject(&self, subject: &str) -> Vec<&SpawnedProcess> {
        self.live.values().filter(|p| p.owner_subject == subject).collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ProcessError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ProcessError::SchemaMismatch);
        }
        for (pid, p) in &self.live {
            if *pid <= 0 { return Err(ProcessError::InvalidPid(*pid)); }
            if p.pid != *pid { return Err(ProcessError::InvalidPid(p.pid)); }
            if p.command.is_empty() { return Err(ProcessError::EmptyCommand); }
            if p.owner_subject.is_empty() { return Err(ProcessError::EmptyOwner); }
            if p.started_at.is_empty() { return Err(ProcessError::MissingStartedAt); }
        }
        Ok(())
    }
}

impl Default for ProcessSpawnRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: i32, owner: &str) -> SpawnedProcess {
        SpawnedProcess {
            pid,
            command: "cargo".into(),
            args: vec!["test".into()],
            owner_subject: owner.into(),
            started_at: "2026-05-19T03:00:00Z".into(),
            exited_at: String::new(),
            exit_code: 0,
        }
    }

    #[test]
    fn empty_registry_validates() {
        ProcessSpawnRegistry::new().validate().unwrap();
    }

    #[test]
    fn spawn_then_exit() {
        let mut r = ProcessSpawnRegistry::new();
        r.record_spawn(proc(100, "alice")).unwrap();
        assert_eq!(r.live_count(), 1);
        r.record_exit(100, 0, "2026-05-19T03:01:00Z").unwrap();
        assert_eq!(r.live_count(), 0);
        assert_eq!(r.history.len(), 1);
        assert_eq!(r.history[0].exit_code, 0);
    }

    #[test]
    fn duplicate_pid_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        r.record_spawn(proc(100, "alice")).unwrap();
        let err = r.record_spawn(proc(100, "alice")).unwrap_err();
        assert!(matches!(err, ProcessError::DuplicatePid(100)));
    }

    #[test]
    fn unknown_exit_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        let err = r.record_exit(100, 0, "t").unwrap_err();
        assert!(matches!(err, ProcessError::Unknown(100)));
    }

    #[test]
    fn invalid_pid_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        let err = r.record_spawn(proc(0, "alice")).unwrap_err();
        assert!(matches!(err, ProcessError::InvalidPid(0)));
    }

    #[test]
    fn empty_command_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        let mut p = proc(100, "alice");
        p.command = String::new();
        let err = r.record_spawn(p).unwrap_err();
        assert!(matches!(err, ProcessError::EmptyCommand));
    }

    #[test]
    fn empty_owner_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        let err = r.record_spawn(proc(100, "")).unwrap_err();
        assert!(matches!(err, ProcessError::EmptyOwner));
    }

    #[test]
    fn live_for_subject_filters() {
        let mut r = ProcessSpawnRegistry::new();
        r.record_spawn(proc(100, "alice")).unwrap();
        r.record_spawn(proc(101, "bob")).unwrap();
        r.record_spawn(proc(102, "alice")).unwrap();
        assert_eq!(r.live_for_subject("alice").len(), 2);
        assert_eq!(r.live_for_subject("bob").len(), 1);
        assert_eq!(r.live_for_subject("carol").len(), 0);
    }

    #[test]
    fn history_capped() {
        let mut r = ProcessSpawnRegistry::new();
        for pid in 1..=1100 {
            r.record_spawn(proc(pid, "x")).unwrap();
            r.record_exit(pid, 0, "t").unwrap();
        }
        assert_eq!(r.history.len(), MAX_HISTORY);
        // Oldest 100 dropped → first remaining pid is 101.
        assert_eq!(r.history[0].pid, 101);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ProcessSpawnRegistry::new();
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), ProcessError::SchemaMismatch));
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = ProcessSpawnRegistry::new();
        r.record_spawn(proc(100, "alice")).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let back: ProcessSpawnRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
