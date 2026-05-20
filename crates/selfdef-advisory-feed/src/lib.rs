//! `selfdef-advisory-feed` — non-blocking operator advisories.
//!
//! `publish(id, severity, summary, ts_ms)` appends. `dismiss(id, ts,
//! actor)` marks dismissed (idempotent). `active()` lists undismissed
//! ordered newest first; `by_severity(min)` filters to severity >= min.
//! `prune(now_ms, max_age_ms)` drops dismissed advisories older
//! than max_age_ms (never drops undismissed).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Severity (ordered).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Info.
    Info,
    /// Notice.
    Notice,
    /// Warn.
    Warn,
    /// Error.
    Error,
    /// Critical.
    Critical,
}

/// One advisory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Advisory {
    /// Id.
    pub id: String,
    /// Severity.
    pub severity: Severity,
    /// Summary.
    pub summary: String,
    /// Published ts.
    pub published_at_ms: u64,
    /// Dismissed?
    pub dismissed: bool,
    /// Dismissed ts.
    pub dismissed_at_ms: Option<u64>,
    /// Who dismissed.
    pub dismissed_by: Option<String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisoryFeed {
    /// Schema version.
    pub schema_version: String,
    /// id → advisory.
    pub advisories: BTreeMap<String, Advisory>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AdvisoryError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("id empty")]
    EmptyId,
    /// Empty summary.
    #[error("summary empty")]
    EmptySummary,
    /// Empty actor.
    #[error("actor empty")]
    EmptyActor,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
    /// Unknown.
    #[error("unknown advisory: {0}")]
    UnknownAdvisory(String),
}

impl AdvisoryFeed {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            advisories: BTreeMap::new(),
        }
    }

    /// Publish.
    pub fn publish(&mut self, id: &str, severity: Severity, summary: &str, ts_ms: u64) -> Result<(), AdvisoryError> {
        if id.is_empty() { return Err(AdvisoryError::EmptyId); }
        if summary.is_empty() { return Err(AdvisoryError::EmptySummary); }
        if self.advisories.contains_key(id) {
            return Err(AdvisoryError::DuplicateId(id.into()));
        }
        self.advisories.insert(id.into(), Advisory {
            id: id.into(),
            severity,
            summary: summary.into(),
            published_at_ms: ts_ms,
            dismissed: false,
            dismissed_at_ms: None,
            dismissed_by: None,
        });
        Ok(())
    }

    /// Dismiss (idempotent — preserves first dismissal metadata).
    pub fn dismiss(&mut self, id: &str, ts_ms: u64, actor: &str) -> Result<bool, AdvisoryError> {
        if actor.is_empty() { return Err(AdvisoryError::EmptyActor); }
        let a = self.advisories.get_mut(id).ok_or_else(|| AdvisoryError::UnknownAdvisory(id.into()))?;
        if a.dismissed { return Ok(false); }
        a.dismissed = true;
        a.dismissed_at_ms = Some(ts_ms);
        a.dismissed_by = Some(actor.into());
        Ok(true)
    }

    /// Active advisories newest first.
    pub fn active(&self) -> Vec<Advisory> {
        let mut v: Vec<Advisory> = self.advisories.values()
            .filter(|a| !a.dismissed)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.published_at_ms.cmp(&a.published_at_ms).then(a.id.cmp(&b.id)));
        v
    }

    /// By minimum severity (active only).
    pub fn by_severity(&self, min: Severity) -> Vec<Advisory> {
        let mut v: Vec<Advisory> = self.advisories.values()
            .filter(|a| !a.dismissed && a.severity >= min)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.published_at_ms.cmp(&a.published_at_ms).then(a.id.cmp(&b.id)));
        v
    }

    /// Drop dismissed older than max_age_ms.
    pub fn prune(&mut self, now_ms: u64, max_age_ms: u64) -> usize {
        let to_drop: Vec<String> = self.advisories.iter()
            .filter(|(_, a)| a.dismissed && now_ms.saturating_sub(a.dismissed_at_ms.unwrap_or(0)) > max_age_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let n = to_drop.len();
        for k in to_drop { self.advisories.remove(&k); }
        n
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AdvisoryError> {
        if self.schema_version != SCHEMA_VERSION { return Err(AdvisoryError::SchemaMismatch); }
        for (id, a) in &self.advisories {
            if id.is_empty() { return Err(AdvisoryError::EmptyId); }
            if a.summary.is_empty() { return Err(AdvisoryError::EmptySummary); }
        }
        Ok(())
    }
}

impl Default for AdvisoryFeed {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_active() {
        let mut f = AdvisoryFeed::new();
        f.publish("a1", Severity::Notice, "Heads up", 100).unwrap();
        f.publish("a2", Severity::Critical, "Outage", 200).unwrap();
        let a = f.active();
        // Newest first.
        assert_eq!(a[0].id, "a2");
        assert_eq!(a[1].id, "a1");
    }

    #[test]
    fn dismiss_hides() {
        let mut f = AdvisoryFeed::new();
        f.publish("a", Severity::Warn, "x", 0).unwrap();
        f.dismiss("a", 100, "alice").unwrap();
        assert!(f.active().is_empty());
    }

    #[test]
    fn dismiss_idempotent() {
        let mut f = AdvisoryFeed::new();
        f.publish("a", Severity::Warn, "x", 0).unwrap();
        assert!(f.dismiss("a", 100, "alice").unwrap());
        // Second dismiss returns false, preserves first metadata.
        assert!(!f.dismiss("a", 200, "bob").unwrap());
        assert_eq!(f.advisories["a"].dismissed_by.as_deref(), Some("alice"));
    }

    #[test]
    fn by_severity_filter() {
        let mut f = AdvisoryFeed::new();
        f.publish("info", Severity::Info, "x", 0).unwrap();
        f.publish("warn", Severity::Warn, "x", 1).unwrap();
        f.publish("crit", Severity::Critical, "x", 2).unwrap();
        let high = f.by_severity(Severity::Warn);
        assert_eq!(high.len(), 2);
        assert!(high.iter().all(|a| a.severity >= Severity::Warn));
    }

    #[test]
    fn prune_keeps_active() {
        let mut f = AdvisoryFeed::new();
        f.publish("active", Severity::Warn, "x", 0).unwrap();
        f.publish("old", Severity::Warn, "x", 0).unwrap();
        f.dismiss("old", 0, "alice").unwrap();
        // After 10_000ms, "old" is well past max_age 1000.
        let n = f.prune(10_000, 1000);
        assert_eq!(n, 1);
        assert!(f.advisories.contains_key("active"));
    }

    #[test]
    fn prune_keeps_recently_dismissed() {
        let mut f = AdvisoryFeed::new();
        f.publish("recent", Severity::Warn, "x", 0).unwrap();
        f.dismiss("recent", 9500, "alice").unwrap();
        // now 10_000, dismissed 9500, max_age 1000 → only 500ms since dismiss; keep.
        f.prune(10_000, 1000);
        assert!(f.advisories.contains_key("recent"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut f = AdvisoryFeed::new();
        f.publish("a", Severity::Info, "x", 0).unwrap();
        assert!(matches!(f.publish("a", Severity::Info, "x", 0).unwrap_err(), AdvisoryError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut f = AdvisoryFeed::new();
        assert!(matches!(f.publish("", Severity::Info, "x", 0).unwrap_err(), AdvisoryError::EmptyId));
        assert!(matches!(f.publish("a", Severity::Info, "", 0).unwrap_err(), AdvisoryError::EmptySummary));
        f.publish("a", Severity::Info, "x", 0).unwrap();
        assert!(matches!(f.dismiss("a", 0, "").unwrap_err(), AdvisoryError::EmptyActor));
    }

    #[test]
    fn dismiss_unknown_rejected() {
        let mut f = AdvisoryFeed::new();
        assert!(matches!(f.dismiss("nope", 0, "a").unwrap_err(), AdvisoryError::UnknownAdvisory(_)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = AdvisoryFeed::new();
        f.schema_version = "9.9.9".into();
        assert!(matches!(f.validate().unwrap_err(), AdvisoryError::SchemaMismatch));
    }

    #[test]
    fn advisory_serde_roundtrip() {
        let mut f = AdvisoryFeed::new();
        f.publish("a", Severity::Critical, "x", 0).unwrap();
        f.dismiss("a", 100, "alice").unwrap();
        let j = serde_json::to_string(&f).unwrap();
        let back: AdvisoryFeed = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
