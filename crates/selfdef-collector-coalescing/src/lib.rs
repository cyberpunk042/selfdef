//! `selfdef-collector-coalescing` — merge repeated raw events.
//!
//! Within `coalesce_ms` of a source's first observation for a given
//! fingerprint, subsequent observations of the same fingerprint are
//! merged: `count` increments, `last_ts_ms` updates. Once the window
//! elapses, the entry is eligible for `drain()`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One merged observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    /// source.
    pub source: String,
    /// fingerprint.
    pub fingerprint: u64,
    /// first ts.
    pub first_ts_ms: u64,
    /// last ts.
    pub last_ts_ms: u64,
    /// count merged.
    pub count: u32,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorCoalescing {
    /// Schema version.
    pub schema_version: String,
    /// Coalesce window (ms).
    pub coalesce_ms: u64,
    /// source → fingerprint → observation.
    pub open: BTreeMap<String, BTreeMap<u64, Observation>>,
}

/// Observe verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObserveVerdict {
    /// New entry opened.
    Started {
        /// count = 1.
        count: u32,
    },
    /// Merged into existing.
    Merged {
        /// count after.
        count: u32,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum CoalesceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty source.
    #[error("source empty")]
    EmptySource,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl CollectorCoalescing {
    /// New.
    pub fn new(coalesce_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            coalesce_ms,
            open: BTreeMap::new(),
        }
    }

    /// Observe.
    pub fn observe(&mut self, source: &str, fingerprint: u64, ts_ms: u64) -> Result<ObserveVerdict, CoalesceError> {
        if source.is_empty() { return Err(CoalesceError::EmptySource); }
        let by_fp = self.open.entry(source.into()).or_default();
        if let Some(o) = by_fp.get_mut(&fingerprint) {
            if ts_ms < o.last_ts_ms {
                return Err(CoalesceError::NonMonotonic { prev: o.last_ts_ms, new: ts_ms });
            }
            if ts_ms.saturating_sub(o.first_ts_ms) <= self.coalesce_ms {
                o.last_ts_ms = ts_ms;
                o.count = o.count.saturating_add(1);
                return Ok(ObserveVerdict::Merged { count: o.count });
            }
            // Window expired — replace with a fresh observation.
            *o = Observation {
                source: source.into(),
                fingerprint,
                first_ts_ms: ts_ms,
                last_ts_ms: ts_ms,
                count: 1,
            };
            return Ok(ObserveVerdict::Started { count: 1 });
        }
        by_fp.insert(fingerprint, Observation {
            source: source.into(),
            fingerprint,
            first_ts_ms: ts_ms,
            last_ts_ms: ts_ms,
            count: 1,
        });
        Ok(ObserveVerdict::Started { count: 1 })
    }

    /// Drain entries whose window has elapsed at `now_ms`.
    pub fn drain(&mut self, now_ms: u64) -> Vec<Observation> {
        let cutoff = self.coalesce_ms;
        let mut out = Vec::new();
        let sources: Vec<String> = self.open.keys().cloned().collect();
        for src in sources {
            if let Some(map) = self.open.get_mut(&src) {
                let expired: Vec<u64> = map.iter()
                    .filter(|(_, o)| now_ms.saturating_sub(o.first_ts_ms) > cutoff)
                    .map(|(fp, _)| *fp)
                    .collect();
                for fp in expired {
                    if let Some(o) = map.remove(&fp) { out.push(o); }
                }
                if map.is_empty() { self.open.remove(&src); }
            }
        }
        out
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CoalesceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CoalesceError::SchemaMismatch); }
        for k in self.open.keys() {
            if k.is_empty() { return Err(CoalesceError::EmptySource); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_starts() {
        let mut c = CollectorCoalescing::new(1000);
        let v = c.observe("s", 0xabc, 100).unwrap();
        assert_eq!(v, ObserveVerdict::Started { count: 1 });
    }

    #[test]
    fn repeats_merge() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        let v = c.observe("s", 0xabc, 200).unwrap();
        assert_eq!(v, ObserveVerdict::Merged { count: 2 });
    }

    #[test]
    fn out_of_window_restarts() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        let v = c.observe("s", 0xabc, 5_000).unwrap();
        assert_eq!(v, ObserveVerdict::Started { count: 1 });
    }

    #[test]
    fn distinct_fingerprints_independent() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        assert_eq!(c.observe("s", 0xdef, 100).unwrap(), ObserveVerdict::Started { count: 1 });
    }

    #[test]
    fn distinct_sources_independent() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s1", 0xabc, 100).unwrap();
        assert_eq!(c.observe("s2", 0xabc, 100).unwrap(), ObserveVerdict::Started { count: 1 });
    }

    #[test]
    fn drain_returns_expired() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        let drained = c.drain(2000);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].count, 1);
    }

    #[test]
    fn drain_leaves_open() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        let drained = c.drain(500);
        assert!(drained.is_empty());
        assert_eq!(c.open["s"].len(), 1);
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 200).unwrap();
        assert!(matches!(c.observe("s", 0xabc, 100).unwrap_err(), CoalesceError::NonMonotonic { .. }));
    }

    #[test]
    fn empty_source_rejected() {
        let mut c = CollectorCoalescing::new(1000);
        assert!(matches!(c.observe("", 0xabc, 0).unwrap_err(), CoalesceError::EmptySource));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut c = CollectorCoalescing::new(1000);
        c.schema_version = "9.9.9".into();
        assert!(matches!(c.validate().unwrap_err(), CoalesceError::SchemaMismatch));
    }

    #[test]
    fn coalesce_serde_roundtrip() {
        let mut c = CollectorCoalescing::new(1000);
        c.observe("s", 0xabc, 100).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let back: CollectorCoalescing = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
