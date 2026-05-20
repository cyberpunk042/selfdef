//! `selfdef-state-checkpoint-store` — periodic state snapshots.
//!
//! Each `Checkpoint { id, ts_ms, label, payload_hash, bytes }` is
//! added via `add(label, bytes, ts_ms)`. `prune(now_ms)` enforces
//! retention rules: keep the most-recent `max_count`, AND drop any
//! older than `max_age_ms` (unless that would leave fewer than
//! `min_keep` checkpoints — operator never loses everything).
//! `latest()` returns the newest; `restore(id)` returns the bytes.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// FNV-1a 64.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    /// Monotonic id.
    pub id: u64,
    /// Timestamp.
    pub ts_ms: u64,
    /// Operator label.
    pub label: String,
    /// FNV-1a-64 of bytes (tamper-evidence).
    pub payload_hash: u64,
    /// Bytes.
    pub bytes: Vec<u8>,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateCheckpointStore {
    /// Schema version.
    pub schema_version: String,
    /// Max checkpoints to keep.
    pub max_count: usize,
    /// Max age before eviction.
    pub max_age_ms: u64,
    /// Floor — never drop below this many.
    pub min_keep: usize,
    /// id → checkpoint.
    pub checkpoints: BTreeMap<u64, Checkpoint>,
    /// Next id.
    pub next_id: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty label.
    #[error("label empty")]
    EmptyLabel,
    /// Unknown id.
    #[error("unknown checkpoint: {0}")]
    UnknownId(u64),
}

impl StateCheckpointStore {
    /// New.
    pub fn new(max_count: usize, max_age_ms: u64, min_keep: usize) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            max_count: max_count.max(min_keep),
            max_age_ms,
            min_keep,
            checkpoints: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Add a checkpoint.
    pub fn add(&mut self, label: &str, bytes: Vec<u8>, ts_ms: u64) -> Result<u64, CheckpointError> {
        if label.is_empty() { return Err(CheckpointError::EmptyLabel); }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let payload_hash = fnv1a_64(&bytes);
        self.checkpoints.insert(id, Checkpoint {
            id,
            ts_ms,
            label: label.into(),
            payload_hash,
            bytes,
        });
        Ok(id)
    }

    /// Latest checkpoint (by ts then id).
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.checkpoints.values()
            .max_by(|a, b| a.ts_ms.cmp(&b.ts_ms).then(a.id.cmp(&b.id)))
    }

    /// Restore.
    pub fn restore(&self, id: u64) -> Result<&Checkpoint, CheckpointError> {
        self.checkpoints.get(&id).ok_or(CheckpointError::UnknownId(id))
    }

    /// Prune by count + age (floor min_keep enforced).
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let total = self.checkpoints.len();
        if total <= self.min_keep { return 0; }
        // Order ids by recency (newest first).
        let mut ids: Vec<u64> = self.checkpoints.keys().copied().collect();
        ids.sort_by(|a, b| {
            let ta = self.checkpoints[a].ts_ms;
            let tb = self.checkpoints[b].ts_ms;
            tb.cmp(&ta).then(b.cmp(a))
        });
        let mut removed = 0;
        let mut to_remove: Vec<u64> = Vec::new();
        for (idx, id) in ids.iter().enumerate() {
            // Keep at least min_keep.
            if total - removed <= self.min_keep { break; }
            let cp = &self.checkpoints[id];
            let too_old = self.max_age_ms > 0 && now_ms.saturating_sub(cp.ts_ms) > self.max_age_ms;
            let over_count = idx >= self.max_count;
            if too_old || over_count {
                to_remove.push(*id);
                removed += 1;
            }
        }
        for id in to_remove {
            self.checkpoints.remove(&id);
        }
        removed
    }

    /// List all (newest first).
    pub fn list(&self) -> Vec<Checkpoint> {
        let mut v: Vec<Checkpoint> = self.checkpoints.values().cloned().collect();
        v.sort_by(|a, b| b.ts_ms.cmp(&a.ts_ms).then(b.id.cmp(&a.id)));
        v
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.schema_version != SCHEMA_VERSION { return Err(CheckpointError::SchemaMismatch); }
        for cp in self.checkpoints.values() {
            if cp.label.is_empty() { return Err(CheckpointError::EmptyLabel); }
        }
        Ok(())
    }
}

impl Default for StateCheckpointStore {
    fn default() -> Self { Self::new(10, 0, 1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_latest() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        s.add("v1", b"hello".to_vec(), 100).unwrap();
        s.add("v2", b"world".to_vec(), 200).unwrap();
        let l = s.latest().unwrap();
        assert_eq!(l.label, "v2");
    }

    #[test]
    fn restore() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        let id = s.add("v1", b"hello".to_vec(), 0).unwrap();
        let cp = s.restore(id).unwrap();
        assert_eq!(cp.bytes, b"hello");
        assert_eq!(cp.payload_hash, super::fnv1a_64(b"hello"));
    }

    #[test]
    fn prune_by_count() {
        let mut s = StateCheckpointStore::new(2, 0, 1);
        for i in 0..5 {
            s.add(&format!("v{i}"), vec![i as u8], i as u64).unwrap();
        }
        let removed = s.prune(100);
        assert_eq!(s.checkpoints.len(), 2);
        assert!(removed > 0);
    }

    #[test]
    fn prune_by_age() {
        let mut s = StateCheckpointStore::new(100, 1000, 1);
        s.add("old", b"a".to_vec(), 0).unwrap();
        s.add("new", b"b".to_vec(), 2_000).unwrap();
        s.prune(2_500);
        // old (2500-0=2500 > 1000) dropped; new kept.
        let list = s.list();
        assert!(list.iter().any(|c| c.label == "new"));
        assert!(!list.iter().any(|c| c.label == "old"));
    }

    #[test]
    fn min_keep_floor() {
        let mut s = StateCheckpointStore::new(0, 1, 2);
        // Even though max_age says drop everything, min_keep=2 holds.
        s.add("a", vec![0], 0).unwrap();
        s.add("b", vec![1], 1).unwrap();
        s.prune(1_000_000);
        assert_eq!(s.checkpoints.len(), 2);
    }

    #[test]
    fn restore_unknown_rejected() {
        let s = StateCheckpointStore::new(10, 0, 1);
        assert!(matches!(s.restore(999).unwrap_err(), CheckpointError::UnknownId(_)));
    }

    #[test]
    fn empty_label_rejected() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        assert!(matches!(s.add("", vec![], 0).unwrap_err(), CheckpointError::EmptyLabel));
    }

    #[test]
    fn list_newest_first() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        s.add("a", vec![0], 100).unwrap();
        s.add("b", vec![1], 200).unwrap();
        let l = s.list();
        assert_eq!(l[0].label, "b");
        assert_eq!(l[1].label, "a");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), CheckpointError::SchemaMismatch));
    }

    #[test]
    fn checkpoint_serde_roundtrip() {
        let mut s = StateCheckpointStore::new(10, 0, 1);
        s.add("v1", b"hello".to_vec(), 100).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: StateCheckpointStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
