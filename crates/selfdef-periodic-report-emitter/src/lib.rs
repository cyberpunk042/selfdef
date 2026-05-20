//! `selfdef-periodic-report-emitter` — periodic report cadence.
//!
//! Each report has a `cadence_ms` and a `last_emitted_ms`.
//! `should_emit(report, now)` returns true iff
//! `now - last_emitted_ms >= cadence_ms`. `mark_emitted` snaps
//! `last_emitted_ms = now` (skew-resistant: never plays catch-up,
//! just advances).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-report state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    /// Cadence.
    pub cadence_ms: u64,
    /// Last emit ts.
    pub last_emitted_ms: u64,
    /// Times emitted.
    pub emissions: u64,
    /// Active (false = paused).
    pub active: bool,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeriodicReportEmitter {
    /// Schema version.
    pub schema_version: String,
    /// id → report.
    pub reports: BTreeMap<String, Report>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum EmitterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("report id empty")]
    EmptyId,
    /// Zero cadence.
    #[error("cadence must be > 0")]
    ZeroCadence,
    /// Unknown.
    #[error("unknown report: {0}")]
    UnknownReport(String),
}

impl PeriodicReportEmitter {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            reports: BTreeMap::new(),
        }
    }

    /// Register / update.
    pub fn register(&mut self, id: &str, cadence_ms: u64, last_emitted_ms: u64) -> Result<(), EmitterError> {
        if id.is_empty() { return Err(EmitterError::EmptyId); }
        if cadence_ms == 0 { return Err(EmitterError::ZeroCadence); }
        let entry = self.reports.entry(id.into()).or_insert(Report {
            cadence_ms,
            last_emitted_ms,
            emissions: 0,
            active: true,
        });
        entry.cadence_ms = cadence_ms;
        Ok(())
    }

    /// Should the report emit at `now_ms`?
    pub fn should_emit(&self, id: &str, now_ms: u64) -> bool {
        let Some(r) = self.reports.get(id) else { return false; };
        if !r.active { return false; }
        now_ms.saturating_sub(r.last_emitted_ms) >= r.cadence_ms
    }

    /// Mark emitted.
    pub fn mark_emitted(&mut self, id: &str, now_ms: u64) -> Result<(), EmitterError> {
        let r = self.reports.get_mut(id).ok_or_else(|| EmitterError::UnknownReport(id.into()))?;
        r.last_emitted_ms = now_ms;
        r.emissions = r.emissions.saturating_add(1);
        Ok(())
    }

    /// Pause / resume.
    pub fn set_active(&mut self, id: &str, active: bool) -> Result<(), EmitterError> {
        let r = self.reports.get_mut(id).ok_or_else(|| EmitterError::UnknownReport(id.into()))?;
        r.active = active;
        Ok(())
    }

    /// All ids due at now.
    pub fn due_at(&self, now_ms: u64) -> Vec<String> {
        self.reports.iter()
            .filter(|(_, r)| r.active && now_ms.saturating_sub(r.last_emitted_ms) >= r.cadence_ms)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), EmitterError> {
        if self.schema_version != SCHEMA_VERSION { return Err(EmitterError::SchemaMismatch); }
        for (id, r) in &self.reports {
            if id.is_empty() { return Err(EmitterError::EmptyId); }
            if r.cadence_ms == 0 { return Err(EmitterError::ZeroCadence); }
        }
        Ok(())
    }
}

impl Default for PeriodicReportEmitter {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_emit_when_overdue() {
        let mut e = PeriodicReportEmitter::new();
        e.register("daily", 1000, 0).unwrap();
        assert!(e.should_emit("daily", 1000));
        assert!(!e.should_emit("daily", 500));
    }

    #[test]
    fn mark_emitted_advances() {
        let mut e = PeriodicReportEmitter::new();
        e.register("daily", 1000, 0).unwrap();
        e.mark_emitted("daily", 1500).unwrap();
        assert!(!e.should_emit("daily", 2000));
        assert!(e.should_emit("daily", 2500));
    }

    #[test]
    fn paused_never_due() {
        let mut e = PeriodicReportEmitter::new();
        e.register("r", 1000, 0).unwrap();
        e.set_active("r", false).unwrap();
        assert!(!e.should_emit("r", 1_000_000));
    }

    #[test]
    fn due_at_lists_eligible() {
        let mut e = PeriodicReportEmitter::new();
        e.register("a", 1000, 0).unwrap();
        e.register("b", 5000, 0).unwrap();
        let due = e.due_at(2000);
        assert!(due.contains(&"a".to_string()));
        assert!(!due.contains(&"b".to_string()));
    }

    #[test]
    fn mark_unknown_rejected() {
        let mut e = PeriodicReportEmitter::new();
        assert!(matches!(e.mark_emitted("nope", 0).unwrap_err(), EmitterError::UnknownReport(_)));
    }

    #[test]
    fn zero_cadence_rejected() {
        let mut e = PeriodicReportEmitter::new();
        assert!(matches!(e.register("r", 0, 0).unwrap_err(), EmitterError::ZeroCadence));
    }

    #[test]
    fn empty_id_rejected() {
        let mut e = PeriodicReportEmitter::new();
        assert!(matches!(e.register("", 1, 0).unwrap_err(), EmitterError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = PeriodicReportEmitter::new();
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), EmitterError::SchemaMismatch));
    }

    #[test]
    fn emitter_serde_roundtrip() {
        let mut e = PeriodicReportEmitter::new();
        e.register("r", 1000, 100).unwrap();
        e.mark_emitted("r", 200).unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let back: PeriodicReportEmitter = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
