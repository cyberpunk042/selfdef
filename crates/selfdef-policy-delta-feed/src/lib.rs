//! `selfdef-policy-delta-feed` — append-only policy-delta event feed.
//!
//! `push(policy_id, kind, version_after, ts)` appends; each event
//! carries a monotonic `seq` assigned by the feed. `since(cursor)`
//! returns `Vec<Event>` whose `seq > cursor` plus the new cursor
//! (= seq of the last returned event, or `cursor` if no new events).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Delta kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeltaKind {
    /// Bundle staged.
    Staged,
    /// Bundle promoted to active.
    Promoted,
    /// Bundle rejected before promotion.
    Rejected,
    /// Bundle reverted.
    Reverted,
    /// Policy sunsetted.
    Sunsetted,
}

/// One event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Monotonic seq.
    pub seq: u64,
    /// Policy id.
    pub policy_id: String,
    /// Delta kind.
    pub kind: DeltaKind,
    /// Version after the delta.
    pub version_after: String,
    /// Ts.
    pub ts_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDeltaFeed {
    /// Schema version.
    pub schema_version: String,
    /// Events in order.
    pub events: Vec<Event>,
    /// Next seq.
    pub next_seq: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FeedError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty policy id.
    #[error("policy id empty")]
    EmptyPolicy,
    /// Empty version.
    #[error("version empty")]
    EmptyVersion,
}

impl PolicyDeltaFeed {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            events: Vec::new(),
            next_seq: 1,
        }
    }

    /// Push.
    pub fn push(&mut self, policy_id: &str, kind: DeltaKind, version_after: &str, ts_ms: u64) -> Result<u64, FeedError> {
        if policy_id.is_empty() { return Err(FeedError::EmptyPolicy); }
        if version_after.is_empty() { return Err(FeedError::EmptyVersion); }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.events.push(Event {
            seq,
            policy_id: policy_id.into(),
            kind,
            version_after: version_after.into(),
            ts_ms,
        });
        Ok(seq)
    }

    /// Read since cursor. Returns (events, new_cursor).
    pub fn since(&self, cursor: u64) -> (Vec<Event>, u64) {
        let events: Vec<Event> = self.events.iter()
            .filter(|e| e.seq > cursor)
            .cloned()
            .collect();
        let new_cursor = events.last().map(|e| e.seq).unwrap_or(cursor);
        (events, new_cursor)
    }

    /// Truncate events older than `retention_ms`.
    pub fn rotate(&mut self, now_ms: u64, retention_ms: u64) {
        let cutoff = now_ms.saturating_sub(retention_ms);
        self.events.retain(|e| e.ts_ms >= cutoff);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FeedError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FeedError::SchemaMismatch); }
        for e in &self.events {
            if e.policy_id.is_empty() { return Err(FeedError::EmptyPolicy); }
            if e.version_after.is_empty() { return Err(FeedError::EmptyVersion); }
        }
        Ok(())
    }
}

impl Default for PolicyDeltaFeed {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_assigns_monotonic_seq() {
        let mut f = PolicyDeltaFeed::new();
        let a = f.push("p1", DeltaKind::Staged, "1.0.0", 0).unwrap();
        let b = f.push("p1", DeltaKind::Promoted, "1.0.0", 1).unwrap();
        assert_eq!(a + 1, b);
    }

    #[test]
    fn since_returns_new_only() {
        let mut f = PolicyDeltaFeed::new();
        f.push("p1", DeltaKind::Staged, "1.0.0", 0).unwrap();
        f.push("p2", DeltaKind::Staged, "2.0.0", 1).unwrap();
        let (events, cursor) = f.since(1);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].policy_id, "p2");
        assert_eq!(cursor, 2);
    }

    #[test]
    fn since_no_new_keeps_cursor() {
        let mut f = PolicyDeltaFeed::new();
        f.push("p1", DeltaKind::Staged, "1.0.0", 0).unwrap();
        let (events, cursor) = f.since(99);
        assert!(events.is_empty());
        assert_eq!(cursor, 99);
    }

    #[test]
    fn rotate_drops_old() {
        let mut f = PolicyDeltaFeed::new();
        f.push("p1", DeltaKind::Staged, "1.0.0", 0).unwrap();
        f.push("p1", DeltaKind::Promoted, "1.0.0", 100_000).unwrap();
        f.rotate(120_000, 50_000);
        assert_eq!(f.events.len(), 1);
        assert_eq!(f.events[0].kind, DeltaKind::Promoted);
    }

    #[test]
    fn empty_fields_rejected() {
        let mut f = PolicyDeltaFeed::new();
        assert!(matches!(f.push("", DeltaKind::Staged, "v", 0).unwrap_err(), FeedError::EmptyPolicy));
        assert!(matches!(f.push("p", DeltaKind::Staged, "", 0).unwrap_err(), FeedError::EmptyVersion));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = PolicyDeltaFeed::new();
        f.schema_version = "9.9.9".into();
        assert!(matches!(f.validate().unwrap_err(), FeedError::SchemaMismatch));
    }

    #[test]
    fn feed_serde_roundtrip() {
        let mut f = PolicyDeltaFeed::new();
        f.push("p1", DeltaKind::Staged, "1.0.0", 0).unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: PolicyDeltaFeed = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
