//! `selfdef-recovery-snapshot-authority` — snapshot retention authority.
//!
//! Snapshots have a class (Hourly/Daily/Weekly) and per-class
//! min_kept. eligible_for_eviction filters out the latest min_kept
//! per class. select_for_recovery returns the most-recent at-or-
//! before target_time.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Snapshot class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotClass {
    /// Hourly snapshot.
    Hourly,
    /// Daily snapshot.
    Daily,
    /// Weekly snapshot.
    Weekly,
}

/// One snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: SnapshotClass,
    /// Unix seconds when taken.
    pub at_unix: u64,
    /// Bytes size (informational).
    pub size_bytes: u64,
}

/// Policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverySnapshotPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Snapshots (chronological order recommended).
    pub snapshots: Vec<Snapshot>,
    /// Min hourly kept.
    pub min_hourly: u32,
    /// Min daily kept.
    pub min_daily: u32,
    /// Min weekly kept.
    pub min_weekly: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("snapshot id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate snapshot id: {0}")]
    DuplicateId(String),
}

impl RecoverySnapshotPolicy {
    /// Canonical: 24 hourly, 14 daily, 8 weekly.
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            snapshots: Vec::new(),
            min_hourly: 24,
            min_daily: 14,
            min_weekly: 8,
        }
    }

    /// Add a snapshot.
    pub fn add(&mut self, s: Snapshot) -> Result<(), SnapshotError> {
        if s.id.is_empty() { return Err(SnapshotError::EmptyId); }
        if self.snapshots.iter().any(|x| x.id == s.id) {
            return Err(SnapshotError::DuplicateId(s.id));
        }
        self.snapshots.push(s);
        Ok(())
    }

    /// Snapshots that may be pruned without violating per-class min_kept.
    pub fn eligible_for_eviction(&self) -> Vec<&Snapshot> {
        for class in [SnapshotClass::Hourly, SnapshotClass::Daily, SnapshotClass::Weekly] {
            let _ = class;
        }
        let mut eligible: Vec<&Snapshot> = Vec::new();
        for class in [SnapshotClass::Hourly, SnapshotClass::Daily, SnapshotClass::Weekly] {
            let min_kept = match class {
                SnapshotClass::Hourly => self.min_hourly,
                SnapshotClass::Daily => self.min_daily,
                SnapshotClass::Weekly => self.min_weekly,
            } as usize;
            let mut of_class: Vec<&Snapshot> = self.snapshots.iter()
                .filter(|s| s.class == class)
                .collect();
            of_class.sort_by_key(|s| std::cmp::Reverse(s.at_unix));
            // Keep first `min_kept`; rest are eligible.
            for s in of_class.into_iter().skip(min_kept) {
                eligible.push(s);
            }
        }
        eligible
    }

    /// Pick the most-recent snapshot at-or-before `target_unix`.
    pub fn select_for_recovery(&self, target_unix: u64) -> Option<&Snapshot> {
        self.snapshots.iter()
            .filter(|s| s.at_unix <= target_unix)
            .max_by_key(|s| s.at_unix)
    }

    /// Total size of all snapshots.
    pub fn total_bytes(&self) -> u64 {
        self.snapshots.iter().map(|s| s.size_bytes).sum()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SnapshotError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SnapshotError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for s in &self.snapshots {
            if s.id.is_empty() { return Err(SnapshotError::EmptyId); }
            if !seen.insert(s.id.as_str()) {
                return Err(SnapshotError::DuplicateId(s.id.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, class: SnapshotClass, at: u64) -> Snapshot {
        Snapshot { id: id.into(), class, at_unix: at, size_bytes: 1024 }
    }

    #[test]
    fn empty_policy_validates() {
        RecoverySnapshotPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn add_and_recover() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        p.add(snap("b", SnapshotClass::Hourly, 200)).unwrap();
        let r = p.select_for_recovery(150).unwrap();
        assert_eq!(r.id, "a");
        let r = p.select_for_recovery(250).unwrap();
        assert_eq!(r.id, "b");
    }

    #[test]
    fn recover_before_oldest_returns_none() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        assert!(p.select_for_recovery(50).is_none());
    }

    #[test]
    fn eligible_respects_min_hourly() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.min_hourly = 2;
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        p.add(snap("b", SnapshotClass::Hourly, 200)).unwrap();
        p.add(snap("c", SnapshotClass::Hourly, 300)).unwrap();
        p.add(snap("d", SnapshotClass::Hourly, 400)).unwrap();
        let e: Vec<&str> = p.eligible_for_eviction().iter().map(|s| s.id.as_str()).collect();
        // 4 hourly, keep 2 newest (d, c). a + b eligible.
        assert!(e.contains(&"a"));
        assert!(e.contains(&"b"));
        assert!(!e.contains(&"c"));
        assert!(!e.contains(&"d"));
    }

    #[test]
    fn min_kept_per_class_independent() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.min_hourly = 1;
        p.min_daily = 1;
        for i in 0..3 {
            p.add(snap(&format!("h{i}"), SnapshotClass::Hourly, 100 + i)).unwrap();
            p.add(snap(&format!("d{i}"), SnapshotClass::Daily, 200 + i)).unwrap();
        }
        // 3 hourly: keep newest, evict 2. Same for daily.
        let e = p.eligible_for_eviction();
        assert_eq!(e.len(), 4);
    }

    #[test]
    fn total_bytes() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        p.add(snap("b", SnapshotClass::Daily, 200)).unwrap();
        assert_eq!(p.total_bytes(), 2048);
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = RecoverySnapshotPolicy::canonical();
        assert!(matches!(
            p.add(snap("", SnapshotClass::Hourly, 100)).unwrap_err(),
            SnapshotError::EmptyId
        ));
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        assert!(matches!(
            p.add(snap("a", SnapshotClass::Daily, 200)).unwrap_err(),
            SnapshotError::DuplicateId(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), SnapshotError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&SnapshotClass::Hourly).unwrap(), "\"hourly\"");
        assert_eq!(serde_json::to_string(&SnapshotClass::Weekly).unwrap(), "\"weekly\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let mut p = RecoverySnapshotPolicy::canonical();
        p.add(snap("a", SnapshotClass::Hourly, 100)).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: RecoverySnapshotPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
