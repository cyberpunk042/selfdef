//! `selfdef-prompt-input-dedup` — sliding-window prompt-input dedup.
//!
//! `observe(hash, ts)` records a fresh prompt fingerprint.
//! `check(hash, now)` returns:
//!   * `Fresh` — not seen in the current window.
//!   * `Duplicate { age_ms, original_ts_ms }` — was seen.
//!
//! `rotate(now)` evicts records older than the window.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptInputDedup {
    /// Schema version.
    pub schema_version: String,
    /// Window width (ms).
    pub window_ms: u64,
    /// hash → last_ts.
    pub recent: BTreeMap<u64, u64>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DedupVerdict {
    /// Not seen in window.
    Fresh,
    /// Duplicate.
    Duplicate {
        /// ms since the original observation.
        age_ms: u64,
        /// Original ts (ms).
        original_ts_ms: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum DedupError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Non-monotonic.
    #[error("non-monotonic ts: prev {prev} > new {new}")]
    NonMonotonic {
        /// prev.
        prev: u64,
        /// new.
        new: u64,
    },
}

impl PromptInputDedup {
    /// New.
    pub fn new(window_ms: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            window_ms,
            recent: BTreeMap::new(),
        }
    }

    /// Observe.
    pub fn observe(&mut self, hash: u64, ts_ms: u64) -> Result<(), DedupError> {
        if let Some(&prev) = self.recent.get(&hash) {
            if ts_ms < prev {
                return Err(DedupError::NonMonotonic { prev, new: ts_ms });
            }
        }
        self.recent.insert(hash, ts_ms);
        Ok(())
    }

    /// Check.
    pub fn check(&self, hash: u64, now_ms: u64) -> DedupVerdict {
        match self.recent.get(&hash).copied() {
            None => DedupVerdict::Fresh,
            Some(prev_ts) => {
                if now_ms.saturating_sub(prev_ts) > self.window_ms {
                    DedupVerdict::Fresh
                } else {
                    DedupVerdict::Duplicate {
                        age_ms: now_ms.saturating_sub(prev_ts),
                        original_ts_ms: prev_ts,
                    }
                }
            }
        }
    }

    /// Rotate.
    pub fn rotate(&mut self, now_ms: u64) {
        let w = self.window_ms;
        self.recent.retain(|_, t| now_ms.saturating_sub(*t) <= w);
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), DedupError> {
        if self.schema_version != SCHEMA_VERSION { return Err(DedupError::SchemaMismatch); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_when_unseen() {
        let d = PromptInputDedup::new(60_000);
        assert_eq!(d.check(0xabc, 1000), DedupVerdict::Fresh);
    }

    #[test]
    fn duplicate_within_window() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        let v = d.check(0xabc, 30_000);
        assert_eq!(v, DedupVerdict::Duplicate { age_ms: 29_000, original_ts_ms: 1_000 });
    }

    #[test]
    fn fresh_after_window() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        assert_eq!(d.check(0xabc, 100_000), DedupVerdict::Fresh);
    }

    #[test]
    fn observe_updates_ts() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        d.observe(0xabc, 2_000).unwrap();
        let v = d.check(0xabc, 3_000);
        assert_eq!(v, DedupVerdict::Duplicate { age_ms: 1_000, original_ts_ms: 2_000 });
    }

    #[test]
    fn nonmonotonic_rejected() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        assert!(matches!(d.observe(0xabc, 500).unwrap_err(), DedupError::NonMonotonic { .. }));
    }

    #[test]
    fn rotate_evicts_old() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        d.rotate(120_000);
        assert!(d.recent.is_empty());
    }

    #[test]
    fn distinct_hashes_independent() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        assert_eq!(d.check(0xdef, 2_000), DedupVerdict::Fresh);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut d = PromptInputDedup::new(60_000);
        d.schema_version = "9.9.9".into();
        assert!(matches!(d.validate().unwrap_err(), DedupError::SchemaMismatch));
    }

    #[test]
    fn dedup_serde_roundtrip() {
        let mut d = PromptInputDedup::new(60_000);
        d.observe(0xabc, 1_000).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let back: PromptInputDedup = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }
}
