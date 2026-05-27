//! `selfdef-trace-baggage` — key/value baggage per trace.
//!
//! Per trace_id, a small set of key→value strings travels with the
//! trace context. Bounded by `max_entries` and `max_total_bytes`;
//! over-cap inserts return `OverCount` / `OverSize`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-trace baggage.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baggage {
    /// k → v.
    pub entries: BTreeMap<String, String>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceBaggage {
    /// Schema version.
    pub schema_version: String,
    /// trace_id → baggage.
    pub traces: BTreeMap<String, Baggage>,
    /// Max entries per trace.
    pub max_entries: u32,
    /// Max total bytes per trace (sum of k+v lengths).
    pub max_total_bytes: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BaggageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("trace id empty")]
    EmptyTrace,
    /// Empty.
    #[error("key empty")]
    EmptyKey,
    /// Over count.
    #[error("entry count {count} >= max {max}")]
    OverCount {
        /// count.
        count: u32,
        /// max.
        max: u32,
    },
    /// Over size.
    #[error("total bytes would be {proposed}; max {max}")]
    OverSize {
        /// proposed.
        proposed: u64,
        /// max.
        max: u64,
    },
}

impl TraceBaggage {
    /// New.
    pub fn new(max_entries: u32, max_total_bytes: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            traces: BTreeMap::new(),
            max_entries,
            max_total_bytes,
        }
    }

    fn current_bytes(b: &Baggage) -> u64 {
        b.entries
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// Set k=v (replaces existing).
    pub fn set(&mut self, trace_id: &str, key: &str, value: &str) -> Result<(), BaggageError> {
        if trace_id.is_empty() {
            return Err(BaggageError::EmptyTrace);
        }
        if key.is_empty() {
            return Err(BaggageError::EmptyKey);
        }
        let b = self.traces.entry(trace_id.into()).or_default();
        // Compute size impact of replacing.
        let old_size_of_key = b
            .entries
            .get(key)
            .map(|v| (key.len() + v.len()) as u64)
            .unwrap_or(0);
        let proposed = Self::current_bytes(b)
            .saturating_sub(old_size_of_key)
            .saturating_add((key.len() + value.len()) as u64);
        if proposed > self.max_total_bytes {
            return Err(BaggageError::OverSize {
                proposed,
                max: self.max_total_bytes,
            });
        }
        // Count check (only matters if inserting new key).
        if !b.entries.contains_key(key) && (b.entries.len() as u32) >= self.max_entries {
            return Err(BaggageError::OverCount {
                count: b.entries.len() as u32,
                max: self.max_entries,
            });
        }
        b.entries.insert(key.into(), value.into());
        Ok(())
    }

    /// Get.
    pub fn get(&self, trace_id: &str, key: &str) -> Option<String> {
        self.traces
            .get(trace_id)
            .and_then(|b| b.entries.get(key))
            .cloned()
    }

    /// Remove key.
    pub fn remove(&mut self, trace_id: &str, key: &str) -> bool {
        let Some(b) = self.traces.get_mut(trace_id) else {
            return false;
        };
        let removed = b.entries.remove(key).is_some();
        if b.entries.is_empty() {
            self.traces.remove(trace_id);
        }
        removed
    }

    /// Drop entire trace.
    pub fn drop_trace(&mut self, trace_id: &str) -> bool {
        self.traces.remove(trace_id).is_some()
    }

    /// All keys (sorted).
    pub fn keys_of(&self, trace_id: &str) -> Vec<String> {
        self.traces
            .get(trace_id)
            .map(|b| b.entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Total bytes used.
    pub fn bytes_of(&self, trace_id: &str) -> u64 {
        self.traces
            .get(trace_id)
            .map(Self::current_bytes)
            .unwrap_or(0)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BaggageError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BaggageError::SchemaMismatch);
        }
        for (id, b) in &self.traces {
            if id.is_empty() {
                return Err(BaggageError::EmptyTrace);
            }
            for k in b.entries.keys() {
                if k.is_empty() {
                    return Err(BaggageError::EmptyKey);
                }
            }
        }
        Ok(())
    }
}

impl Default for TraceBaggage {
    fn default() -> Self {
        Self::new(32, 8192)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut b = TraceBaggage::new(10, 1000);
        b.set("t1", "k", "v").unwrap();
        assert_eq!(b.get("t1", "k").as_deref(), Some("v"));
    }

    #[test]
    fn replace_does_not_grow_count() {
        let mut b = TraceBaggage::new(1, 100);
        b.set("t", "k", "v1").unwrap();
        b.set("t", "k", "v2").unwrap();
        assert_eq!(b.get("t", "k").as_deref(), Some("v2"));
    }

    #[test]
    fn over_count_rejected() {
        let mut b = TraceBaggage::new(1, 1000);
        b.set("t", "k1", "v").unwrap();
        assert!(matches!(
            b.set("t", "k2", "v").unwrap_err(),
            BaggageError::OverCount { .. }
        ));
    }

    #[test]
    fn over_size_rejected() {
        let mut b = TraceBaggage::new(10, 5);
        // k+v = 6 bytes, max = 5.
        assert!(matches!(
            b.set("t", "key1", "vv").unwrap_err(),
            BaggageError::OverSize { .. }
        ));
    }

    #[test]
    fn remove_clears() {
        let mut b = TraceBaggage::new(10, 1000);
        b.set("t", "k", "v").unwrap();
        assert!(b.remove("t", "k"));
        assert!(b.get("t", "k").is_none());
        assert!(!b.traces.contains_key("t"));
    }

    #[test]
    fn drop_trace_clears() {
        let mut b = TraceBaggage::new(10, 1000);
        b.set("t", "k1", "v").unwrap();
        b.set("t", "k2", "v").unwrap();
        assert!(b.drop_trace("t"));
        assert!(b.keys_of("t").is_empty());
    }

    #[test]
    fn bytes_of_correct() {
        let mut b = TraceBaggage::new(10, 1000);
        b.set("t", "k", "vv").unwrap();
        assert_eq!(b.bytes_of("t"), 3);
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut b = TraceBaggage::new(10, 1000);
        assert!(matches!(
            b.set("", "k", "v").unwrap_err(),
            BaggageError::EmptyTrace
        ));
        assert!(matches!(
            b.set("t", "", "v").unwrap_err(),
            BaggageError::EmptyKey
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut b = TraceBaggage::new(10, 1000);
        b.schema_version = "9.9.9".into();
        assert!(matches!(
            b.validate().unwrap_err(),
            BaggageError::SchemaMismatch
        ));
    }

    #[test]
    fn baggage_serde_roundtrip() {
        let mut b = TraceBaggage::new(10, 1000);
        b.set("t", "k", "v").unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let back: TraceBaggage = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
