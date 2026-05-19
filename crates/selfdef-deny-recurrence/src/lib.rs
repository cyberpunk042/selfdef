//! `selfdef-deny-recurrence` — per-subject deny pattern detector.
//!
//! Maintains a per-(subject, action) bucket. Each call to `record_deny`
//! increments the bucket; `recent_count` returns the count for matching
//! subject+action. A `breach_threshold` constant gates the emission of
//! a RepeatDeny anomaly hint by the consumer crate.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Default threshold above which the tracker recommends anomaly emission.
pub const DEFAULT_BREACH_THRESHOLD: u32 = 5;

/// Per-bucket state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketState {
    /// Subject id.
    pub subject: String,
    /// Action verb.
    pub action: String,
    /// Count of denies recorded.
    pub deny_count: u32,
    /// ISO-8601 UTC of most recent deny.
    pub last_at: String,
}

/// Tracker state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyRecurrenceTracker {
    /// Schema version.
    pub schema_version: String,
    /// Breach threshold.
    pub breach_threshold: u32,
    /// Buckets keyed by "subject|action".
    pub buckets: HashMap<String, BucketState>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TrackerError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty subject.
    #[error("subject empty")]
    EmptySubject,
    /// Empty action.
    #[error("action empty")]
    EmptyAction,
    /// Empty timestamp.
    #[error("timestamp empty")]
    EmptyTimestamp,
    /// Threshold 0 (would always breach).
    #[error("breach_threshold zero disallowed")]
    ZeroThreshold,
}

fn key(subject: &str, action: &str) -> String {
    format!("{subject}|{action}")
}

impl DenyRecurrenceTracker {
    /// New tracker with the default threshold.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            breach_threshold: DEFAULT_BREACH_THRESHOLD,
            buckets: HashMap::new(),
        }
    }

    /// With a custom threshold.
    pub fn with_threshold(threshold: u32) -> Result<Self, TrackerError> {
        if threshold == 0 { return Err(TrackerError::ZeroThreshold); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            breach_threshold: threshold,
            buckets: HashMap::new(),
        })
    }

    /// Record a deny event. Returns the bucket's new count.
    pub fn record_deny(&mut self, subject: &str, action: &str, at: &str) -> Result<u32, TrackerError> {
        if subject.is_empty() { return Err(TrackerError::EmptySubject); }
        if action.is_empty() { return Err(TrackerError::EmptyAction); }
        if at.is_empty() { return Err(TrackerError::EmptyTimestamp); }
        let k = key(subject, action);
        let bucket = self.buckets.entry(k).or_insert_with(|| BucketState {
            subject: subject.into(),
            action: action.into(),
            deny_count: 0,
            last_at: at.into(),
        });
        bucket.deny_count += 1;
        bucket.last_at = at.into();
        Ok(bucket.deny_count)
    }

    /// Lookup count for (subject, action).
    pub fn recent_count(&self, subject: &str, action: &str) -> u32 {
        self.buckets.get(&key(subject, action)).map(|b| b.deny_count).unwrap_or(0)
    }

    /// True if (subject, action) breached the threshold.
    pub fn breached(&self, subject: &str, action: &str) -> bool {
        self.recent_count(subject, action) >= self.breach_threshold
    }

    /// Reset a specific (subject, action) bucket.
    pub fn reset(&mut self, subject: &str, action: &str) -> bool {
        self.buckets.remove(&key(subject, action)).is_some()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TrackerError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TrackerError::SchemaMismatch);
        }
        if self.breach_threshold == 0 {
            return Err(TrackerError::ZeroThreshold);
        }
        for b in self.buckets.values() {
            if b.subject.is_empty() { return Err(TrackerError::EmptySubject); }
            if b.action.is_empty() { return Err(TrackerError::EmptyAction); }
            if b.last_at.is_empty() { return Err(TrackerError::EmptyTimestamp); }
        }
        Ok(())
    }

    /// Buckets currently breached.
    pub fn breached_buckets(&self) -> Vec<&BucketState> {
        self.buckets.values()
            .filter(|b| b.deny_count >= self.breach_threshold)
            .collect()
    }
}

impl Default for DenyRecurrenceTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_validates() {
        DenyRecurrenceTracker::new().validate().unwrap();
    }

    #[test]
    fn record_increments_bucket() {
        let mut t = DenyRecurrenceTracker::new();
        assert_eq!(t.record_deny("op", "fs.write", "t1").unwrap(), 1);
        assert_eq!(t.record_deny("op", "fs.write", "t2").unwrap(), 2);
        assert_eq!(t.recent_count("op", "fs.write"), 2);
    }

    #[test]
    fn distinct_subjects_separate_buckets() {
        let mut t = DenyRecurrenceTracker::new();
        t.record_deny("alice", "fs.write", "t").unwrap();
        t.record_deny("bob", "fs.write", "t").unwrap();
        assert_eq!(t.recent_count("alice", "fs.write"), 1);
        assert_eq!(t.recent_count("bob", "fs.write"), 1);
    }

    #[test]
    fn breach_at_threshold() {
        let mut t = DenyRecurrenceTracker::with_threshold(3).unwrap();
        for _ in 0..2 { t.record_deny("op", "x", "t").unwrap(); }
        assert!(!t.breached("op", "x"));
        t.record_deny("op", "x", "t").unwrap();
        assert!(t.breached("op", "x"));
    }

    #[test]
    fn reset_clears_bucket() {
        let mut t = DenyRecurrenceTracker::new();
        t.record_deny("op", "x", "t").unwrap();
        assert!(t.reset("op", "x"));
        assert_eq!(t.recent_count("op", "x"), 0);
        assert!(!t.reset("op", "x")); // already cleared
    }

    #[test]
    fn breached_buckets_enumerates() {
        let mut t = DenyRecurrenceTracker::with_threshold(2).unwrap();
        for _ in 0..3 { t.record_deny("alice", "x", "t").unwrap(); }
        for _ in 0..1 { t.record_deny("bob", "y", "t").unwrap(); }
        let breached = t.breached_buckets();
        assert_eq!(breached.len(), 1);
        assert_eq!(breached[0].subject, "alice");
    }

    #[test]
    fn empty_subject_rejected() {
        let mut t = DenyRecurrenceTracker::new();
        assert!(matches!(t.record_deny("", "x", "t").unwrap_err(), TrackerError::EmptySubject));
    }

    #[test]
    fn empty_action_rejected() {
        let mut t = DenyRecurrenceTracker::new();
        assert!(matches!(t.record_deny("op", "", "t").unwrap_err(), TrackerError::EmptyAction));
    }

    #[test]
    fn empty_timestamp_rejected() {
        let mut t = DenyRecurrenceTracker::new();
        assert!(matches!(t.record_deny("op", "x", "").unwrap_err(), TrackerError::EmptyTimestamp));
    }

    #[test]
    fn zero_threshold_rejected() {
        assert!(matches!(DenyRecurrenceTracker::with_threshold(0).unwrap_err(), TrackerError::ZeroThreshold));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = DenyRecurrenceTracker::new();
        t.schema_version = "9.9.9".into();
        assert!(matches!(t.validate().unwrap_err(), TrackerError::SchemaMismatch));
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut t = DenyRecurrenceTracker::with_threshold(7).unwrap();
        t.record_deny("op", "x", "t").unwrap();
        t.record_deny("op", "x", "t").unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let back: DenyRecurrenceTracker = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
