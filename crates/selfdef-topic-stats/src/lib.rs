//! `selfdef-topic-stats` — per-topic counters + window rate.
//!
//! TopicStat{total, window_count, window_start_ms}. record(
//! topic, n, now) accumulates total + window. rate_per_sec
//! resets window if window_ms elapsed, then returns
//! window_count * 1000 / elapsed.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-topic counters.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicStat {
    /// Total observed (lifetime).
    pub total: u64,
    /// Count in current window.
    pub window_count: u64,
    /// Window start ts ms.
    pub window_start_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopicStats {
    /// Schema version.
    pub schema_version: String,
    /// Window ms.
    pub window_ms: u64,
    /// topic → stat.
    pub stats: BTreeMap<String, TopicStat>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StatError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("topic empty")]
    EmptyTopic,
    /// Zero window.
    #[error("window_ms must be >= 1")]
    ZeroWindow,
}

impl TopicStats {
    /// New.
    pub fn new(window_ms: u64) -> Result<Self, StatError> {
        if window_ms == 0 { return Err(StatError::ZeroWindow); }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            stats: BTreeMap::new(),
        })
    }

    /// Record n events at now.
    pub fn record(&mut self, topic: &str, n: u64, now_ms: u64) -> Result<(), StatError> {
        if topic.is_empty() { return Err(StatError::EmptyTopic); }
        let s = self.stats.entry(topic.into()).or_insert(TopicStat {
            total: 0,
            window_count: 0,
            window_start_ms: now_ms,
        });
        if now_ms.saturating_sub(s.window_start_ms) >= self.window_ms {
            s.window_count = 0;
            s.window_start_ms = now_ms;
        }
        s.total = s.total.saturating_add(n);
        s.window_count = s.window_count.saturating_add(n);
        Ok(())
    }

    /// Rate per second for current window at now_ms.
    pub fn rate_per_sec(&mut self, topic: &str, now_ms: u64) -> u64 {
        let Some(s) = self.stats.get_mut(topic) else { return 0; };
        if now_ms.saturating_sub(s.window_start_ms) >= self.window_ms {
            s.window_count = 0;
            s.window_start_ms = now_ms;
        }
        let elapsed = now_ms.saturating_sub(s.window_start_ms).max(1);
        s.window_count.saturating_mul(1000) / elapsed
    }

    /// Total for topic.
    pub fn total(&self, topic: &str) -> u64 {
        self.stats.get(topic).map(|s| s.total).unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StatError> {
        if self.schema_version != SCHEMA_VERSION { return Err(StatError::SchemaMismatch); }
        if self.window_ms == 0 { return Err(StatError::ZeroWindow); }
        for k in self.stats.keys() {
            if k.is_empty() { return Err(StatError::EmptyTopic); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_total() {
        let mut s = TopicStats::new(1000).unwrap();
        s.record("alerts", 5, 0).unwrap();
        s.record("alerts", 3, 100).unwrap();
        assert_eq!(s.total("alerts"), 8);
    }

    #[test]
    fn rate_per_second() {
        let mut s = TopicStats::new(1000).unwrap();
        s.record("alerts", 100, 0).unwrap();
        // At now=500ms: rate = 100*1000/500 = 200/s.
        assert_eq!(s.rate_per_sec("alerts", 500), 200);
    }

    #[test]
    fn window_resets() {
        let mut s = TopicStats::new(1000).unwrap();
        s.record("a", 100, 0).unwrap();
        // Past window.
        s.record("a", 50, 1500).unwrap();
        // Window was reset on the second record.
        assert_eq!(s.stats["a"].window_count, 50);
        assert_eq!(s.total("a"), 150);
    }

    #[test]
    fn unknown_topic_rate_zero() {
        let mut s = TopicStats::new(1000).unwrap();
        assert_eq!(s.rate_per_sec("nope", 1000), 0);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = TopicStats::new(1000).unwrap();
        assert!(matches!(s.record("", 1, 0).unwrap_err(), StatError::EmptyTopic));
        assert!(matches!(TopicStats::new(0).unwrap_err(), StatError::ZeroWindow));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = TopicStats::new(1000).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), StatError::SchemaMismatch));
    }

    #[test]
    fn stats_serde_roundtrip() {
        let mut s = TopicStats::new(1000).unwrap();
        s.record("a", 5, 0).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: TopicStats = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
