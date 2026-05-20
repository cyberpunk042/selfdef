//! `selfdef-data-exfil-detector` — outbound payload pattern detector.
//!
//! Registers Patterns by id, each with a name + a needle to look for
//! (substring match) + a `severity`. `scan(payload)` returns the
//! list of matching `Hit { pattern_id, severity, count }`.
//!
//! `observe(payload, total_bytes_limit)` is a streaming-friendly
//! variant: records counts in internal counters and increments a
//! `bytes_scanned` total; useful when wiring through a network
//! egress hook.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Severity.
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

/// One pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pattern {
    /// Stable id.
    pub id: String,
    /// Human name.
    pub name: String,
    /// Substring needle.
    pub needle: String,
    /// Severity.
    pub severity: Severity,
    /// Total hits observed.
    pub total_hits: u64,
}

/// One hit (returned by scan).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hit {
    /// Pattern id.
    pub pattern_id: String,
    /// Severity.
    pub severity: Severity,
    /// Count of occurrences in this scan.
    pub count: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataExfilDetector {
    /// Schema version.
    pub schema_version: String,
    /// id → pattern.
    pub patterns: BTreeMap<String, Pattern>,
    /// Total bytes scanned (across all observe calls).
    pub bytes_scanned: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Empty.
    #[error("name empty")]
    EmptyName,
    /// Empty.
    #[error("needle empty")]
    EmptyNeedle,
    /// Duplicate.
    #[error("duplicate pattern id: {0}")]
    DuplicateId(String),
}

fn count_substring(payload: &str, needle: &str) -> u64 {
    if needle.is_empty() { return 0; }
    let mut count: u64 = 0;
    let mut start = 0usize;
    while let Some(idx) = payload[start..].find(needle) {
        count = count.saturating_add(1);
        start = start.saturating_add(idx).saturating_add(needle.len());
        if start >= payload.len() { break; }
    }
    count
}

impl DataExfilDetector {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            patterns: BTreeMap::new(),
            bytes_scanned: 0,
        }
    }

    /// Register.
    pub fn register(&mut self, id: &str, name: &str, needle: &str, severity: Severity) -> Result<(), DetectorError> {
        if id.is_empty() { return Err(DetectorError::EmptyId); }
        if name.is_empty() { return Err(DetectorError::EmptyName); }
        if needle.is_empty() { return Err(DetectorError::EmptyNeedle); }
        if self.patterns.contains_key(id) {
            return Err(DetectorError::DuplicateId(id.into()));
        }
        self.patterns.insert(id.into(), Pattern {
            id: id.into(),
            name: name.into(),
            needle: needle.into(),
            severity,
            total_hits: 0,
        });
        Ok(())
    }

    /// Pure scan (no state side-effect).
    pub fn scan(&self, payload: &str) -> Vec<Hit> {
        let mut out: Vec<Hit> = Vec::new();
        for p in self.patterns.values() {
            let count = count_substring(payload, &p.needle);
            if count > 0 {
                out.push(Hit { pattern_id: p.id.clone(), severity: p.severity, count });
            }
        }
        // Critical first, then alphabetical id.
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.pattern_id.cmp(&b.pattern_id)));
        out
    }

    /// Observe (scan + record).
    pub fn observe(&mut self, payload: &str) -> Vec<Hit> {
        let hits = self.scan(payload);
        for h in &hits {
            if let Some(p) = self.patterns.get_mut(&h.pattern_id) {
                p.total_hits = p.total_hits.saturating_add(h.count);
            }
        }
        self.bytes_scanned = self.bytes_scanned.saturating_add(payload.len() as u64);
        hits
    }

    /// Highest severity hit at or above min (snapshot).
    pub fn worst_hit(&self, payload: &str, min: Severity) -> Option<Hit> {
        self.scan(payload).into_iter().find(|h| h.severity >= min)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DetectorError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DetectorError::SchemaMismatch); }
        for (id, p) in &self.patterns {
            if id.is_empty() { return Err(DetectorError::EmptyId); }
            if p.name.is_empty() { return Err(DetectorError::EmptyName); }
            if p.needle.is_empty() { return Err(DetectorError::EmptyNeedle); }
        }
        Ok(())
    }
}

impl Default for DataExfilDetector {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_finds_single_hit() {
        let mut d = DataExfilDetector::new();
        d.register("ssn", "SSN prefix", "SSN:", Severity::Critical).unwrap();
        let h = d.scan("Hello SSN: 123-45-6789");
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].count, 1);
        assert_eq!(h[0].severity, Severity::Critical);
    }

    #[test]
    fn scan_counts_multiple_occurrences() {
        let mut d = DataExfilDetector::new();
        d.register("a", "a", "abc", Severity::Info).unwrap();
        let h = d.scan("abcabcabc");
        assert_eq!(h[0].count, 3);
    }

    #[test]
    fn scan_orders_critical_first() {
        let mut d = DataExfilDetector::new();
        d.register("low", "L", "low", Severity::Info).unwrap();
        d.register("hi", "H", "hi", Severity::Critical).unwrap();
        let h = d.scan("hi low");
        assert_eq!(h[0].pattern_id, "hi");
    }

    #[test]
    fn observe_records_counts() {
        let mut d = DataExfilDetector::new();
        d.register("p", "P", "x", Severity::Warn).unwrap();
        d.observe("xx");
        d.observe("xxx");
        assert_eq!(d.patterns["p"].total_hits, 5);
        assert_eq!(d.bytes_scanned, 5);
    }

    #[test]
    fn worst_hit_filters_by_severity() {
        let mut d = DataExfilDetector::new();
        d.register("info", "I", "i", Severity::Info).unwrap();
        d.register("crit", "C", "c", Severity::Critical).unwrap();
        let w = d.worst_hit("i c", Severity::Warn);
        assert_eq!(w.unwrap().pattern_id, "crit");
    }

    #[test]
    fn no_hits_returns_empty() {
        let mut d = DataExfilDetector::new();
        d.register("p", "P", "secret", Severity::Critical).unwrap();
        assert!(d.scan("hello").is_empty());
    }

    #[test]
    fn duplicate_pattern_rejected() {
        let mut d = DataExfilDetector::new();
        d.register("p", "P", "x", Severity::Info).unwrap();
        assert!(matches!(d.register("p", "P", "x", Severity::Info).unwrap_err(), DetectorError::DuplicateId(_)));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut d = DataExfilDetector::new();
        assert!(matches!(d.register("", "n", "x", Severity::Info).unwrap_err(), DetectorError::EmptyId));
        assert!(matches!(d.register("p", "", "x", Severity::Info).unwrap_err(), DetectorError::EmptyName));
        assert!(matches!(d.register("p", "n", "", Severity::Info).unwrap_err(), DetectorError::EmptyNeedle));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = DataExfilDetector::new();
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DetectorError::SchemaMismatch));
    }

    #[test]
    fn detector_serde_roundtrip() {
        let mut d = DataExfilDetector::new();
        d.register("p", "P", "x", Severity::Critical).unwrap();
        d.observe("xx");
        let j = serde_json::to_string(&d).unwrap();
        let back: DataExfilDetector = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
