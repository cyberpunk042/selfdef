//! `selfdef-collector-staleness-policy` — per-source freshness budget.
//!
//! `set_budget(source, max_age_ms)` configures a per-source budget.
//! `record(source, ts)` updates the last fresh sample timestamp.
//! `classify(source, now)` returns:
//!   * `Fresh{age_ms}` — age ≤ budget.
//!   * `Stale{age_ms, budget}` — age > budget.
//!   * `Unknown` — no record yet.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One source entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Budget (ms).
    pub max_age_ms: u64,
    /// Last fresh sample ts (ms), if any.
    pub last_ts_ms: Option<u64>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CollectorStalenessPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Per-source entries.
    pub sources: BTreeMap<String, Entry>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StalenessVerdict {
    /// Within budget.
    Fresh {
        /// observed age.
        age_ms: u64,
    },
    /// Over budget.
    Stale {
        /// observed age.
        age_ms: u64,
        /// budget.
        budget_ms: u64,
    },
    /// No samples recorded.
    Unknown,
    /// Source not configured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StalenessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty source.
    #[error("source empty")]
    EmptySource,
    /// Non-monotonic ts.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl CollectorStalenessPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            sources: BTreeMap::new(),
        }
    }

    /// Set budget for a source.
    pub fn set_budget(&mut self, source: &str, max_age_ms: u64) -> Result<(), StalenessError> {
        if source.is_empty() {
            return Err(StalenessError::EmptySource);
        }
        let prev_last = self.sources.get(source).and_then(|e| e.last_ts_ms);
        self.sources.insert(
            source.into(),
            Entry {
                max_age_ms,
                last_ts_ms: prev_last,
            },
        );
        Ok(())
    }

    /// Record a fresh sample.
    pub fn record(&mut self, source: &str, ts_ms: u64) -> Result<(), StalenessError> {
        if source.is_empty() {
            return Err(StalenessError::EmptySource);
        }
        let e = self.sources.entry(source.into()).or_insert(Entry {
            max_age_ms: u64::MAX,
            last_ts_ms: None,
        });
        if let Some(prev) = e.last_ts_ms {
            if ts_ms < prev {
                return Err(StalenessError::NonMonotonic { prev, new: ts_ms });
            }
        }
        e.last_ts_ms = Some(ts_ms);
        Ok(())
    }

    /// Classify.
    pub fn classify(&self, source: &str, now_ms: u64) -> StalenessVerdict {
        let e = match self.sources.get(source) {
            Some(e) => e,
            None => return StalenessVerdict::Unconfigured,
        };
        match e.last_ts_ms {
            None => StalenessVerdict::Unknown,
            Some(t) => {
                let age = now_ms.saturating_sub(t);
                if age <= e.max_age_ms {
                    StalenessVerdict::Fresh { age_ms: age }
                } else {
                    StalenessVerdict::Stale {
                        age_ms: age,
                        budget_ms: e.max_age_ms,
                    }
                }
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StalenessError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(StalenessError::SchemaMismatch);
        }
        for k in self.sources.keys() {
            if k.is_empty() {
                return Err(StalenessError::EmptySource);
            }
        }
        Ok(())
    }
}

impl Default for CollectorStalenessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_source() {
        let p = CollectorStalenessPolicy::new();
        assert_eq!(p.classify("s", 0), StalenessVerdict::Unconfigured);
    }

    #[test]
    fn unknown_when_no_record() {
        let mut p = CollectorStalenessPolicy::new();
        p.set_budget("s", 1000).unwrap();
        assert_eq!(p.classify("s", 100), StalenessVerdict::Unknown);
    }

    #[test]
    fn fresh_within_budget() {
        let mut p = CollectorStalenessPolicy::new();
        p.set_budget("s", 1000).unwrap();
        p.record("s", 100).unwrap();
        assert_eq!(
            p.classify("s", 500),
            StalenessVerdict::Fresh { age_ms: 400 }
        );
    }

    #[test]
    fn stale_past_budget() {
        let mut p = CollectorStalenessPolicy::new();
        p.set_budget("s", 1000).unwrap();
        p.record("s", 100).unwrap();
        let v = p.classify("s", 5000);
        assert_eq!(
            v,
            StalenessVerdict::Stale {
                age_ms: 4900,
                budget_ms: 1000
            }
        );
    }

    #[test]
    fn nonmonotonic_record_rejected() {
        let mut p = CollectorStalenessPolicy::new();
        p.record("s", 200).unwrap();
        assert!(matches!(
            p.record("s", 100).unwrap_err(),
            StalenessError::NonMonotonic { .. }
        ));
    }

    #[test]
    fn empty_source_rejected() {
        let mut p = CollectorStalenessPolicy::new();
        assert!(matches!(
            p.record("", 0).unwrap_err(),
            StalenessError::EmptySource
        ));
    }

    #[test]
    fn set_budget_preserves_record() {
        let mut p = CollectorStalenessPolicy::new();
        p.set_budget("s", 1000).unwrap();
        p.record("s", 100).unwrap();
        p.set_budget("s", 500).unwrap();
        assert_eq!(
            p.classify("s", 300),
            StalenessVerdict::Fresh { age_ms: 200 }
        );
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = CollectorStalenessPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            StalenessError::SchemaMismatch
        ));
    }

    #[test]
    fn staleness_serde_roundtrip() {
        let mut p = CollectorStalenessPolicy::new();
        p.set_budget("s", 1000).unwrap();
        p.record("s", 100).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: CollectorStalenessPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
