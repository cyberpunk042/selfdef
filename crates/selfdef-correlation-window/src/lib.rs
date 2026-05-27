//! `selfdef-correlation-window` — sliding-window per-subject event tracker.
//!
//! Tracks epoch-ms timestamps of recent events per subject. `prune(now)`
//! drops entries older than `window_ms`. `count(subject)` returns the
//! live count after pruning.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Tracker state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationWindow {
    /// Schema version.
    pub schema_version: String,
    /// Window length in milliseconds.
    pub window_ms: u64,
    /// Per-subject timestamps (epoch ms).
    pub timestamps: HashMap<String, Vec<u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum WindowError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Window 0.
    #[error("window_ms zero disallowed")]
    ZeroWindow,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
}

impl CorrelationWindow {
    /// New.
    pub fn new(window_ms: u64) -> Result<Self, WindowError> {
        if window_ms == 0 {
            return Err(WindowError::ZeroWindow);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            timestamps: HashMap::new(),
        })
    }

    /// Record an event timestamp for a subject.
    pub fn record(&mut self, subject: &str, now_ms: u64) -> Result<(), WindowError> {
        if subject.is_empty() {
            return Err(WindowError::EmptySubject);
        }
        self.timestamps
            .entry(subject.into())
            .or_default()
            .push(now_ms);
        Ok(())
    }

    /// Prune all entries older than `now_ms - window_ms` for every subject.
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        for ts in self.timestamps.values_mut() {
            ts.retain(|t| *t >= cutoff);
        }
        // Drop empty subjects.
        self.timestamps.retain(|_, ts| !ts.is_empty());
    }

    /// Count of events for subject inside the window when called against `now_ms`.
    /// Side effect: prunes the subject's vec.
    pub fn count(&mut self, subject: &str, now_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let entry = match self.timestamps.get_mut(subject) {
            Some(e) => e,
            None => return 0,
        };
        entry.retain(|t| *t >= cutoff);
        let n = entry.len() as u32;
        if n == 0 {
            self.timestamps.remove(subject);
        }
        n
    }

    /// Subjects with count >= threshold.
    pub fn subjects_above(&mut self, now_ms: u64, threshold: u32) -> Vec<String> {
        self.prune(now_ms);
        self.timestamps
            .iter()
            .filter(|(_, v)| v.len() as u32 >= threshold)
            .map(|(s, _)| s.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), WindowError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(WindowError::SchemaMismatch);
        }
        if self.window_ms == 0 {
            return Err(WindowError::ZeroWindow);
        }
        for s in self.timestamps.keys() {
            if s.is_empty() {
                return Err(WindowError::EmptySubject);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_window_rejected() {
        assert!(matches!(
            CorrelationWindow::new(0).unwrap_err(),
            WindowError::ZeroWindow
        ));
    }

    #[test]
    fn record_and_count() {
        let mut w = CorrelationWindow::new(60_000).unwrap();
        w.record("alice", 1_000).unwrap();
        w.record("alice", 2_000).unwrap();
        w.record("alice", 3_000).unwrap();
        assert_eq!(w.count("alice", 3_000), 3);
    }

    #[test]
    fn entries_outside_window_pruned() {
        let mut w = CorrelationWindow::new(1_000).unwrap();
        w.record("alice", 1_000).unwrap();
        w.record("alice", 2_000).unwrap();
        // At now_ms=3_500 with window 1_000ms, cutoff = 2_500, so only the entry at 2_000 should remain? No:
        // cutoff = 2_500, t >= 2_500 → none of (1_000, 2_000) survive.
        assert_eq!(w.count("alice", 3_500), 0);
    }

    #[test]
    fn boundary_inclusive_at_cutoff() {
        let mut w = CorrelationWindow::new(1_000).unwrap();
        w.record("alice", 1_000).unwrap();
        // At now_ms=2_000, cutoff = 1_000 → 1_000 >= 1_000 survives.
        assert_eq!(w.count("alice", 2_000), 1);
    }

    #[test]
    fn distinct_subjects() {
        let mut w = CorrelationWindow::new(60_000).unwrap();
        w.record("alice", 1_000).unwrap();
        w.record("bob", 1_500).unwrap();
        w.record("alice", 2_000).unwrap();
        assert_eq!(w.count("alice", 2_000), 2);
        assert_eq!(w.count("bob", 2_000), 1);
        assert_eq!(w.count("carol", 2_000), 0);
    }

    #[test]
    fn subjects_above_threshold() {
        let mut w = CorrelationWindow::new(60_000).unwrap();
        for i in 0..5 {
            w.record("alice", 1_000 + i * 100).unwrap();
        }
        for i in 0..2 {
            w.record("bob", 1_000 + i * 100).unwrap();
        }
        let v = w.subjects_above(2_000, 3);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], "alice");
    }

    #[test]
    fn prune_drops_empty_subjects() {
        let mut w = CorrelationWindow::new(1_000).unwrap();
        w.record("alice", 1_000).unwrap();
        w.prune(5_000);
        assert!(!w.timestamps.contains_key("alice"));
    }

    #[test]
    fn empty_subject_rejected() {
        let mut w = CorrelationWindow::new(1_000).unwrap();
        assert!(matches!(
            w.record("", 0).unwrap_err(),
            WindowError::EmptySubject
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut w = CorrelationWindow::new(1_000).unwrap();
        w.schema_version = "9.9.9".into();
        assert!(matches!(
            w.validate().unwrap_err(),
            WindowError::SchemaMismatch
        ));
    }

    #[test]
    fn window_serde_roundtrip() {
        let mut w = CorrelationWindow::new(60_000).unwrap();
        w.record("alice", 1_000).unwrap();
        let j = serde_json::to_string(&w).unwrap();
        let back: CorrelationWindow = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }
}
