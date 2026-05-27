//! `selfdef-gc-sweeper` — age + size GC over keyed registry.
//!
//! Item{ts_ms, size}. sweep(now):
//! 1. age sweep — remove items older than max_age_ms.
//! 2. size sweep — while total_size > size_cap_bytes, evict
//!    oldest until within cap.
//! Returns removed ids.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Item.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    /// Timestamp ms.
    pub ts_ms: u64,
    /// Size in bytes.
    pub size: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GcSweeper {
    /// Schema version.
    pub schema_version: String,
    /// Max item age ms (0 = disabled).
    pub max_age_ms: u64,
    /// Size cap (0 = disabled).
    pub size_cap_bytes: u64,
    /// id → item.
    pub items: BTreeMap<String, Item>,
    /// Total sweeps.
    pub sweeps: u64,
    /// Total removed.
    pub removed: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GcError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("id empty")]
    EmptyId,
    /// Duplicate.
    #[error("duplicate id: {0}")]
    DuplicateId(String),
}

impl GcSweeper {
    /// New.
    pub fn new(max_age_ms: u64, size_cap_bytes: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_age_ms,
            size_cap_bytes,
            items: BTreeMap::new(),
            sweeps: 0,
            removed: 0,
        }
    }

    /// Insert.
    pub fn insert(&mut self, id: &str, ts_ms: u64, size: u64) -> Result<(), GcError> {
        if id.is_empty() {
            return Err(GcError::EmptyId);
        }
        if self.items.contains_key(id) {
            return Err(GcError::DuplicateId(id.into()));
        }
        self.items.insert(id.into(), Item { ts_ms, size });
        Ok(())
    }

    /// Total size in bytes.
    pub fn total_size(&self) -> u64 {
        self.items.values().map(|i| i.size).sum()
    }

    /// Sweep — returns ids removed in order.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<String> {
        self.sweeps = self.sweeps.saturating_add(1);
        let mut removed_ids: Vec<String> = Vec::new();
        // 1) Age sweep.
        if self.max_age_ms > 0 {
            let cutoff = now_ms.saturating_sub(self.max_age_ms);
            let stale: Vec<String> = self
                .items
                .iter()
                .filter(|(_, i)| i.ts_ms < cutoff)
                .map(|(k, _)| k.clone())
                .collect();
            for k in stale {
                self.items.remove(&k);
                removed_ids.push(k);
            }
        }
        // 2) Size sweep — evict oldest while over cap.
        if self.size_cap_bytes > 0 {
            while self.total_size() > self.size_cap_bytes {
                // Find oldest by ts_ms.
                let oldest = self
                    .items
                    .iter()
                    .min_by_key(|(_, i)| i.ts_ms)
                    .map(|(k, _)| k.clone());
                let Some(k) = oldest else {
                    break;
                };
                self.items.remove(&k);
                removed_ids.push(k);
            }
        }
        self.removed = self.removed.saturating_add(removed_ids.len() as u64);
        removed_ids
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GcError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GcError::SchemaMismatch);
        }
        for k in self.items.keys() {
            if k.is_empty() {
                return Err(GcError::EmptyId);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_sweep_removes_old() {
        let mut g = GcSweeper::new(1000, 0);
        g.insert("a", 0, 10).unwrap();
        g.insert("b", 500, 10).unwrap();
        g.insert("c", 900, 10).unwrap();
        let rm = g.sweep(2000);
        // cutoff = 2000 - 1000 = 1000; a (0), b (500), c (900) all < 1000 → all removed.
        assert_eq!(rm.len(), 3);
    }

    #[test]
    fn age_disabled_no_sweep() {
        let mut g = GcSweeper::new(0, 0);
        g.insert("a", 0, 10).unwrap();
        let rm = g.sweep(99_999_999);
        assert!(rm.is_empty());
    }

    #[test]
    fn size_sweep_evicts_oldest() {
        let mut g = GcSweeper::new(0, 25);
        g.insert("a", 100, 10).unwrap();
        g.insert("b", 200, 10).unwrap();
        g.insert("c", 300, 10).unwrap();
        // Total 30 > 25 → evict oldest (a, ts=100). Total now 20.
        let rm = g.sweep(1000);
        assert_eq!(rm, vec!["a"]);
        assert_eq!(g.total_size(), 20);
    }

    #[test]
    fn combined_age_and_size() {
        let mut g = GcSweeper::new(700, 15);
        g.insert("a", 0, 10).unwrap();
        g.insert("b", 400, 10).unwrap();
        g.insert("c", 600, 10).unwrap();
        // age cutoff at sweep 1000 = 300; a (0<300) removed by age.
        // After: b+c=20 > 15 → evict oldest (b).
        let rm = g.sweep(1000);
        assert_eq!(rm.len(), 2);
        assert!(g.items.contains_key("c"));
    }

    #[test]
    fn duplicate_rejected() {
        let mut g = GcSweeper::new(0, 0);
        g.insert("a", 0, 10).unwrap();
        assert!(matches!(
            g.insert("a", 0, 10).unwrap_err(),
            GcError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut g = GcSweeper::new(0, 0);
        assert!(matches!(g.insert("", 0, 10).unwrap_err(), GcError::EmptyId));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = GcSweeper::new(0, 0);
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), GcError::SchemaMismatch));
    }

    #[test]
    fn sweeper_serde_roundtrip() {
        let mut g = GcSweeper::new(1000, 100);
        g.insert("a", 0, 10).unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: GcSweeper = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
