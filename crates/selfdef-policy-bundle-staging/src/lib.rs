//! `selfdef-policy-bundle-staging` — staging area for bundle promotion.
//!
//! `stage(bundle_id, version, content_hash, ts)` parks a candidate.
//! `promote(bundle_id, version)` marks it active (returns the
//! previously-active version, if any). `reject(bundle_id, version)`
//! removes from staging. `list_staged()` returns all staged
//! candidates.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One staged candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    /// version.
    pub version: String,
    /// content hash.
    pub content_hash: String,
    /// staged at.
    pub staged_at_ms: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBundleStaging {
    /// Schema version.
    pub schema_version: String,
    /// bundle_id → version → candidate.
    pub staged: BTreeMap<String, BTreeMap<String, Candidate>>,
    /// bundle_id → active version.
    pub active: BTreeMap<String, String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum StagingError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty bundle id.
    #[error("bundle id empty")]
    EmptyBundleId,
    /// Empty version.
    #[error("version empty")]
    EmptyVersion,
    /// Empty content hash.
    #[error("content_hash empty")]
    EmptyContentHash,
    /// Version not staged.
    #[error("version {0} not staged for bundle {1}")]
    NotStaged(String, String),
}

impl PolicyBundleStaging {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            staged: BTreeMap::new(),
            active: BTreeMap::new(),
        }
    }

    /// Stage.
    pub fn stage(&mut self, bundle_id: &str, version: &str, content_hash: &str, staged_at_ms: u64) -> Result<(), StagingError> {
        if bundle_id.is_empty() { return Err(StagingError::EmptyBundleId); }
        if version.is_empty() { return Err(StagingError::EmptyVersion); }
        if content_hash.is_empty() { return Err(StagingError::EmptyContentHash); }
        self.staged.entry(bundle_id.into()).or_default().insert(version.into(), Candidate {
            version: version.into(),
            content_hash: content_hash.into(),
            staged_at_ms,
        });
        Ok(())
    }

    /// Promote. Returns the previously-active version if any.
    pub fn promote(&mut self, bundle_id: &str, version: &str) -> Result<Option<String>, StagingError> {
        let by_version = self.staged.get(bundle_id)
            .ok_or_else(|| StagingError::NotStaged(version.into(), bundle_id.into()))?;
        if !by_version.contains_key(version) {
            return Err(StagingError::NotStaged(version.into(), bundle_id.into()));
        }
        let prev = self.active.insert(bundle_id.into(), version.into());
        Ok(prev)
    }

    /// Reject.
    pub fn reject(&mut self, bundle_id: &str, version: &str) -> bool {
        if let Some(by_version) = self.staged.get_mut(bundle_id) {
            if by_version.remove(version).is_some() {
                if by_version.is_empty() { self.staged.remove(bundle_id); }
                return true;
            }
        }
        false
    }

    /// List staged candidates for a bundle.
    pub fn list_staged(&self, bundle_id: &str) -> Vec<Candidate> {
        self.staged.get(bundle_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Active version for a bundle.
    pub fn active_version(&self, bundle_id: &str) -> Option<&str> {
        self.active.get(bundle_id).map(|s| s.as_str())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), StagingError> {
        if self.schema_version != SCHEMA_VERSION { return Err(StagingError::SchemaMismatch); }
        for (bid, m) in &self.staged {
            if bid.is_empty() { return Err(StagingError::EmptyBundleId); }
            for (v, c) in m {
                if v.is_empty() { return Err(StagingError::EmptyVersion); }
                if c.content_hash.is_empty() { return Err(StagingError::EmptyContentHash); }
            }
        }
        Ok(())
    }
}

impl Default for PolicyBundleStaging {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_and_list() {
        let mut s = PolicyBundleStaging::new();
        s.stage("b", "1.0.0", "h1", 0).unwrap();
        s.stage("b", "2.0.0", "h2", 0).unwrap();
        assert_eq!(s.list_staged("b").len(), 2);
    }

    #[test]
    fn promote_sets_active_returns_prev() {
        let mut s = PolicyBundleStaging::new();
        s.stage("b", "1.0.0", "h1", 0).unwrap();
        s.stage("b", "2.0.0", "h2", 0).unwrap();
        assert_eq!(s.promote("b", "1.0.0").unwrap(), None);
        assert_eq!(s.promote("b", "2.0.0").unwrap(), Some("1.0.0".into()));
        assert_eq!(s.active_version("b"), Some("2.0.0"));
    }

    #[test]
    fn promote_unstaged_rejected() {
        let mut s = PolicyBundleStaging::new();
        assert!(matches!(s.promote("b", "1.0.0").unwrap_err(), StagingError::NotStaged(_, _)));
    }

    #[test]
    fn reject_removes() {
        let mut s = PolicyBundleStaging::new();
        s.stage("b", "1.0.0", "h1", 0).unwrap();
        assert!(s.reject("b", "1.0.0"));
        assert!(!s.reject("b", "1.0.0"));
    }

    #[test]
    fn empty_fields_rejected() {
        let mut s = PolicyBundleStaging::new();
        assert!(matches!(s.stage("", "v", "h", 0).unwrap_err(), StagingError::EmptyBundleId));
        assert!(matches!(s.stage("b", "", "h", 0).unwrap_err(), StagingError::EmptyVersion));
        assert!(matches!(s.stage("b", "v", "", 0).unwrap_err(), StagingError::EmptyContentHash));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PolicyBundleStaging::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), StagingError::SchemaMismatch));
    }

    #[test]
    fn staging_serde_roundtrip() {
        let mut s = PolicyBundleStaging::new();
        s.stage("b", "1.0.0", "h1", 0).unwrap();
        s.promote("b", "1.0.0").unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let back: PolicyBundleStaging = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
