//! `selfdef-policy-bundle-signature` — operator-signed bundle manifest.
//!
//! The IPS substrate's bring-up requires the operator to sign one
//! manifest that anchors:
//! - `rule_pack_versions` — semver-sorted concat of 8 pack semvers
//! - `doctrine_text_hash` — FNV-1a hash of the 10 doctrines
//! - `collector_summary`  — sorted-comma-join of 7 collector kebab names
//! - `host_fingerprint`   — operator-provided host id
//!
//! The signature is over the canonical-JSON of those 4 fields. The
//! daemon refuses boot if the signature is empty / doesn't match the
//! computed payload digest (caller responsibility — we don't impl ed25519
//! here; we model the schema + non-empty signature gate).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_substrate_fingerprint::SubstrateFingerprint;
use selfdef_rule_pack_version::RulePackManifest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    /// Schema version.
    pub schema_version: String,
    /// Sorted-comma-joined semvers of 8 rule packs.
    pub rule_pack_versions: String,
    /// FNV-1a 64-bit hex of doctrine concat.
    pub doctrine_text_hash: String,
    /// Sorted-comma-joined collector kebab names.
    pub collector_summary: String,
    /// Operator-provided host id.
    pub host_fingerprint: String,
    /// ISO-8601 UTC bundle creation.
    pub created_at: String,
    /// Operator MS003 signature over canonical-JSON of the 4 fields above.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BundleSigError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Signature missing.
    #[error("bundle manifest unsigned")]
    Unsigned,
    /// Empty rule pack versions.
    #[error("rule_pack_versions empty")]
    EmptyRulePackVersions,
    /// Empty doctrine hash.
    #[error("doctrine_text_hash empty")]
    EmptyDoctrineHash,
    /// Empty collector summary.
    #[error("collector_summary empty")]
    EmptyCollectorSummary,
    /// Empty host fingerprint.
    #[error("host_fingerprint empty")]
    EmptyHostFingerprint,
    /// Empty created_at.
    #[error("created_at empty")]
    EmptyCreatedAt,
    /// Bundle drift against a live fingerprint.
    #[error("bundle drift on {field}: bundle={bundle}, live={live}")]
    Drift {
        /// field.
        field: &'static str,
        /// bundle.
        bundle: String,
        /// live.
        live: String,
    },
}

impl BundleManifest {
    /// Build a manifest from a fingerprint + rule pack manifest + operator signature.
    pub fn build(
        fingerprint: &SubstrateFingerprint,
        rule_packs: &RulePackManifest,
        host_fingerprint: &str,
        created_at: &str,
        signature: &str,
    ) -> Self {
        let mut semvers: Vec<String> = rule_packs.packs.iter().map(|p| p.semver.clone()).collect();
        semvers.sort();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rule_pack_versions: semvers.join(","),
            doctrine_text_hash: fingerprint.doctrine_text_hash.clone(),
            collector_summary: fingerprint.collector_summary.clone(),
            host_fingerprint: host_fingerprint.into(),
            created_at: created_at.into(),
            signature: signature.into(),
        }
    }

    /// Validate the manifest is well-formed + signed.
    pub fn validate(&self) -> Result<(), BundleSigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundleSigError::SchemaMismatch);
        }
        if self.signature.is_empty() { return Err(BundleSigError::Unsigned); }
        if self.rule_pack_versions.is_empty() { return Err(BundleSigError::EmptyRulePackVersions); }
        if self.doctrine_text_hash.is_empty() { return Err(BundleSigError::EmptyDoctrineHash); }
        if self.collector_summary.is_empty() { return Err(BundleSigError::EmptyCollectorSummary); }
        if self.host_fingerprint.is_empty() { return Err(BundleSigError::EmptyHostFingerprint); }
        if self.created_at.is_empty() { return Err(BundleSigError::EmptyCreatedAt); }
        Ok(())
    }

    /// Compare manifest against a fresh fingerprint — detect drift.
    pub fn assert_matches_live(&self, live: &SubstrateFingerprint) -> Result<(), BundleSigError> {
        self.validate()?;
        if self.doctrine_text_hash != live.doctrine_text_hash {
            return Err(BundleSigError::Drift {
                field: "doctrine_text_hash",
                bundle: self.doctrine_text_hash.clone(),
                live: live.doctrine_text_hash.clone(),
            });
        }
        if self.collector_summary != live.collector_summary {
            return Err(BundleSigError::Drift {
                field: "collector_summary",
                bundle: self.collector_summary.clone(),
                live: live.collector_summary.clone(),
            });
        }
        if self.host_fingerprint != live.host_fingerprint {
            return Err(BundleSigError::Drift {
                field: "host_fingerprint",
                bundle: self.host_fingerprint.clone(),
                live: live.host_fingerprint.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_rule_pack_version::{RulePack, PackKind};

    fn fp() -> SubstrateFingerprint {
        SubstrateFingerprint::compute(
            &["1.0.0".into()],
            &["d-a".into(), "d-b".into()],
            &["auditd".into(), "ebpf".into()],
            "host-fp",
            "2026-05-19T03:00:00Z",
        )
    }

    fn rp() -> RulePackManifest {
        let kinds = [
            PackKind::Filesystem, PackKind::Network, PackKind::Capability,
            PackKind::Sandbox, PackKind::Communication, PackKind::CollectorBudget,
            PackKind::Quarantine, PackKind::CommitAuthority,
        ];
        RulePackManifest {
            schema_version: "1.0.0".into(),
            packs: kinds.iter().map(|k| RulePack {
                kind: *k,
                semver: "1.0.0".into(),
                signature: "sig".into(),
                loaded_at: "t".into(),
            }).collect(),
        }
    }

    #[test]
    fn ok_bundle_validates() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.validate().unwrap();
    }

    #[test]
    fn unsigned_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.signature = String::new();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::Unsigned));
    }

    #[test]
    fn empty_doctrine_hash_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.doctrine_text_hash = String::new();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::EmptyDoctrineHash));
    }

    #[test]
    fn empty_collector_summary_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.collector_summary = String::new();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::EmptyCollectorSummary));
    }

    #[test]
    fn empty_host_fp_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.host_fingerprint = String::new();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::EmptyHostFingerprint));
    }

    #[test]
    fn empty_created_at_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.created_at = String::new();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::EmptyCreatedAt));
    }

    #[test]
    fn drift_doctrine_hash_caught() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        let mut live = fp();
        live.doctrine_text_hash = "deadbeef".into();
        match m.assert_matches_live(&live).unwrap_err() {
            BundleSigError::Drift { field, .. } => assert_eq!(field, "doctrine_text_hash"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn drift_host_caught() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        let mut live = fp();
        live.host_fingerprint = "other-host".into();
        match m.assert_matches_live(&live).unwrap_err() {
            BundleSigError::Drift { field, .. } => assert_eq!(field, "host_fingerprint"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn assert_matches_live_succeeds() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.assert_matches_live(&fp()).unwrap();
    }

    #[test]
    fn schema_drift_rejected() {
        let mut m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        m.schema_version = "9.9.9".into();
        assert!(matches!(m.validate().unwrap_err(), BundleSigError::SchemaMismatch));
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        let j = serde_json::to_string(&m).unwrap();
        let back: BundleManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn semvers_sorted_in_manifest() {
        let m = BundleManifest::build(&fp(), &rp(), "host-fp", "t", "sig-bundle");
        let parts: Vec<&str> = m.rule_pack_versions.split(',').collect();
        let mut sorted = parts.clone();
        sorted.sort();
        assert_eq!(parts, sorted);
    }
}
