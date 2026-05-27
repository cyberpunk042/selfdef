//! `selfdef-action-replay-counter` — per-(subject, action, resource) repeat counter.
//!
//! Sliding-window counter; reports when the same triple repeats N+
//! times within `window_ms`. The anomaly system pulls this signal to
//! emit RepeatedAction hints.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Counter state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionReplayCounter {
    /// Schema version.
    pub schema_version: String,
    /// Window length in ms.
    pub window_ms: u64,
    /// Per-(subject|action|resource) timestamps (epoch ms).
    pub timestamps: HashMap<String, Vec<u64>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CounterError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Zero window.
    #[error("window_ms zero")]
    ZeroWindow,
    /// Empty subject/action/resource.
    #[error("missing key field")]
    MissingKeyField,
}

fn key(subject: &str, action: &str, resource: &str) -> String {
    format!("{subject}|{action}|{resource}")
}

impl ActionReplayCounter {
    /// New with window length.
    pub fn new(window_ms: u64) -> Result<Self, CounterError> {
        if window_ms == 0 {
            return Err(CounterError::ZeroWindow);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            timestamps: HashMap::new(),
        })
    }

    /// Record a request.
    pub fn record(
        &mut self,
        subject: &str,
        action: &str,
        resource: &str,
        now_ms: u64,
    ) -> Result<(), CounterError> {
        if subject.is_empty() || action.is_empty() || resource.is_empty() {
            return Err(CounterError::MissingKeyField);
        }
        let k = key(subject, action, resource);
        let entry = self.timestamps.entry(k).or_default();
        let cutoff = now_ms.saturating_sub(self.window_ms);
        entry.retain(|t| *t >= cutoff);
        entry.push(now_ms);
        Ok(())
    }

    /// Count for (subject, action, resource) in window.
    pub fn count(&mut self, subject: &str, action: &str, resource: &str, now_ms: u64) -> u32 {
        let k = key(subject, action, resource);
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let entry = match self.timestamps.get_mut(&k) {
            Some(e) => e,
            None => return 0,
        };
        entry.retain(|t| *t >= cutoff);
        let n = entry.len() as u32;
        if n == 0 {
            self.timestamps.remove(&k);
        }
        n
    }

    /// True if repeats ≥ threshold.
    pub fn is_repeating(
        &mut self,
        subject: &str,
        action: &str,
        resource: &str,
        now_ms: u64,
        threshold: u32,
    ) -> bool {
        self.count(subject, action, resource, now_ms) >= threshold
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CounterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CounterError::SchemaMismatch);
        }
        if self.window_ms == 0 {
            return Err(CounterError::ZeroWindow);
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
            ActionReplayCounter::new(0).unwrap_err(),
            CounterError::ZeroWindow
        ));
    }

    #[test]
    fn record_and_count() {
        let mut c = ActionReplayCounter::new(60_000).unwrap();
        c.record("alice", "fs.read", "/x", 1000).unwrap();
        c.record("alice", "fs.read", "/x", 2000).unwrap();
        c.record("alice", "fs.read", "/x", 3000).unwrap();
        assert_eq!(c.count("alice", "fs.read", "/x", 3000), 3);
    }

    #[test]
    fn entries_outside_window_pruned() {
        let mut c = ActionReplayCounter::new(1000).unwrap();
        c.record("a", "x", "/r", 1000).unwrap();
        c.record("a", "x", "/r", 2000).unwrap();
        assert_eq!(c.count("a", "x", "/r", 5000), 0);
    }

    #[test]
    fn distinct_keys_separate() {
        let mut c = ActionReplayCounter::new(60_000).unwrap();
        c.record("a", "x", "/r1", 1000).unwrap();
        c.record("a", "x", "/r2", 1000).unwrap();
        assert_eq!(c.count("a", "x", "/r1", 1000), 1);
        assert_eq!(c.count("a", "x", "/r2", 1000), 1);
    }

    #[test]
    fn is_repeating_at_threshold() {
        let mut c = ActionReplayCounter::new(60_000).unwrap();
        for i in 0..5 {
            c.record("a", "x", "/r", 1000 + i * 100).unwrap();
        }
        assert!(c.is_repeating("a", "x", "/r", 5000, 5));
        assert!(!c.is_repeating("a", "x", "/r", 5000, 6));
    }

    #[test]
    fn missing_key_field_rejected() {
        let mut c = ActionReplayCounter::new(1000).unwrap();
        assert!(matches!(
            c.record("", "x", "/r", 0).unwrap_err(),
            CounterError::MissingKeyField
        ));
        assert!(matches!(
            c.record("a", "", "/r", 0).unwrap_err(),
            CounterError::MissingKeyField
        ));
        assert!(matches!(
            c.record("a", "x", "", 0).unwrap_err(),
            CounterError::MissingKeyField
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = ActionReplayCounter::new(1000).unwrap();
        c.schema_version = "9.9.9".into();
        assert!(matches!(
            c.validate().unwrap_err(),
            CounterError::SchemaMismatch
        ));
    }

    #[test]
    fn counter_serde_roundtrip() {
        let mut c = ActionReplayCounter::new(1000).unwrap();
        c.record("a", "x", "/r", 0).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: ActionReplayCounter = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
