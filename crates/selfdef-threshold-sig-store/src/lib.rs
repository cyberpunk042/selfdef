//! `selfdef-threshold-sig-store` — m-of-n signature shards.
//!
//! For each message digest, collects opaque (signer_id, shard)
//! pairs from up to n signers. submit(digest, signer, shard) is
//! idempotent per (digest, signer). met(digest) true iff ≥ m
//! distinct signers have submitted. shards(digest) returns the
//! collected shards in deterministic signer-id order (suitable
//! for assembly by an external threshold-sig combiner).
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
pub struct ThresholdSigStore {
    /// Schema version.
    pub schema_version: String,
    /// Threshold m (signers needed).
    pub m: u32,
    /// Total signer count n.
    pub n: u32,
    /// digest → signer_id → shard.
    pub by_digest: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SigError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Bad threshold.
    #[error("m must be in 1..=n and n >= 1")]
    BadThreshold,
    /// Empty.
    #[error("digest empty")]
    EmptyDigest,
    /// Empty.
    #[error("signer empty")]
    EmptySigner,
    /// Empty.
    #[error("shard empty")]
    EmptyShard,
    /// Conflict.
    #[error("conflicting shard for (digest, signer)")]
    ShardConflict,
}

impl ThresholdSigStore {
    /// New.
    pub fn new(m: u32, n: u32) -> Result<Self, SigError> {
        if n == 0 || m == 0 || m > n {
            return Err(SigError::BadThreshold);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            m,
            n,
            by_digest: BTreeMap::new(),
        })
    }

    /// Submit a shard. Idempotent if same shard; ShardConflict otherwise.
    pub fn submit(&mut self, digest: &str, signer: &str, shard: &[u8]) -> Result<(), SigError> {
        if digest.is_empty() {
            return Err(SigError::EmptyDigest);
        }
        if signer.is_empty() {
            return Err(SigError::EmptySigner);
        }
        if shard.is_empty() {
            return Err(SigError::EmptyShard);
        }
        let by_signer = self.by_digest.entry(digest.into()).or_default();
        if let Some(existing) = by_signer.get(signer) {
            if existing != shard {
                return Err(SigError::ShardConflict);
            }
            return Ok(());
        }
        by_signer.insert(signer.into(), shard.to_vec());
        Ok(())
    }

    /// True iff ≥ m signers have submitted for digest.
    pub fn met(&self, digest: &str) -> bool {
        self.by_digest.get(digest).map_or(0, |s| s.len()) as u32 >= self.m
    }

    /// Collected shards in signer-id order.
    pub fn shards(&self, digest: &str) -> Vec<(String, Vec<u8>)> {
        self.by_digest
            .get(digest)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SigError::SchemaMismatch);
        }
        if self.n == 0 || self.m == 0 || self.m > self.n {
            return Err(SigError::BadThreshold);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn met_when_m_signers() {
        let mut s = ThresholdSigStore::new(3, 5).unwrap();
        s.submit("d1", "s1", b"shard1").unwrap();
        s.submit("d1", "s2", b"shard2").unwrap();
        assert!(!s.met("d1"));
        s.submit("d1", "s3", b"shard3").unwrap();
        assert!(s.met("d1"));
    }

    #[test]
    fn idempotent_same_shard() {
        let mut s = ThresholdSigStore::new(2, 3).unwrap();
        s.submit("d", "s1", b"x").unwrap();
        s.submit("d", "s1", b"x").unwrap();
        let shards = s.shards("d");
        assert_eq!(shards.len(), 1);
    }

    #[test]
    fn shard_conflict_rejected() {
        let mut s = ThresholdSigStore::new(2, 3).unwrap();
        s.submit("d", "s1", b"x").unwrap();
        assert!(matches!(
            s.submit("d", "s1", b"y").unwrap_err(),
            SigError::ShardConflict
        ));
    }

    #[test]
    fn shards_in_signer_order() {
        let mut s = ThresholdSigStore::new(2, 4).unwrap();
        s.submit("d", "b", b"B").unwrap();
        s.submit("d", "a", b"A").unwrap();
        s.submit("d", "c", b"C").unwrap();
        let ids: Vec<_> = s.shards("d").into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn unknown_digest_not_met() {
        let s = ThresholdSigStore::new(2, 3).unwrap();
        assert!(!s.met("nope"));
        assert!(s.shards("nope").is_empty());
    }

    #[test]
    fn bad_threshold_rejected() {
        assert!(matches!(
            ThresholdSigStore::new(0, 5).unwrap_err(),
            SigError::BadThreshold
        ));
        assert!(matches!(
            ThresholdSigStore::new(6, 5).unwrap_err(),
            SigError::BadThreshold
        ));
        assert!(matches!(
            ThresholdSigStore::new(1, 0).unwrap_err(),
            SigError::BadThreshold
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let mut s = ThresholdSigStore::new(1, 1).unwrap();
        assert!(matches!(
            s.submit("", "s", b"x").unwrap_err(),
            SigError::EmptyDigest
        ));
        assert!(matches!(
            s.submit("d", "", b"x").unwrap_err(),
            SigError::EmptySigner
        ));
        assert!(matches!(
            s.submit("d", "s", b"").unwrap_err(),
            SigError::EmptyShard
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = ThresholdSigStore::new(1, 1).unwrap();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            SigError::SchemaMismatch
        ));
    }

    #[test]
    fn store_serde_roundtrip() {
        let mut s = ThresholdSigStore::new(2, 3).unwrap();
        s.submit("d", "a", b"shard").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: ThresholdSigStore = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
