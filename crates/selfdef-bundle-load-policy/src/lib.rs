//! `selfdef-bundle-load-policy` — bundle admission authority.
//!
//! Bundles are admitted when:
//! * schema_version matches.
//! * Vendor source requires signature_present.
//! * Operator source allows unsigned ONLY when source-location == Local.
//! * Untrusted source requires signature AND operator-approval flag.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Bundle source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleSource {
    /// Vendor (engine-shipped).
    Vendor,
    /// Operator (hand-authored).
    Operator,
    /// Untrusted (third-party / community).
    Untrusted,
}

/// Source-location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceLocation {
    /// On-disk local (this machine).
    Local,
    /// Fetched over network.
    Network,
}

/// Bundle metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    /// Stable id.
    pub id: String,
    /// Source.
    pub source: BundleSource,
    /// Source location.
    pub location: SourceLocation,
    /// Signature present?
    pub signature_present: bool,
    /// Schema version this bundle was built against.
    pub schema_version: String,
    /// Operator explicitly approved this bundle?
    pub operator_approved: bool,
}

/// Verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LoadVerdict {
    /// Accepted.
    Loaded,
    /// Schema mismatch.
    SchemaMismatch {
        /// got.
        got: String,
        /// expected.
        expected: String,
    },
    /// Vendor must be signed.
    VendorUnsigned,
    /// Operator network bundle must be signed.
    OperatorNetworkUnsigned,
    /// Untrusted must be both signed + operator-approved.
    UntrustedNotApproved,
    /// Empty id.
    EmptyId,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleLoadPolicy {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum BundleLoadError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl BundleLoadPolicy {
    /// New canonical.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Decide.
    pub fn decide(&self, b: &Bundle) -> LoadVerdict {
        if b.id.is_empty() {
            return LoadVerdict::EmptyId;
        }
        if b.schema_version != SCHEMA_VERSION {
            return LoadVerdict::SchemaMismatch {
                got: b.schema_version.clone(),
                expected: SCHEMA_VERSION.into(),
            };
        }
        match b.source {
            BundleSource::Vendor => {
                if !b.signature_present {
                    return LoadVerdict::VendorUnsigned;
                }
                LoadVerdict::Loaded
            }
            BundleSource::Operator => {
                if !b.signature_present && b.location == SourceLocation::Network {
                    return LoadVerdict::OperatorNetworkUnsigned;
                }
                LoadVerdict::Loaded
            }
            BundleSource::Untrusted => {
                if !b.signature_present || !b.operator_approved {
                    return LoadVerdict::UntrustedNotApproved;
                }
                LoadVerdict::Loaded
            }
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), BundleLoadError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundleLoadError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for BundleLoadPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(
        id: &str,
        src: BundleSource,
        loc: SourceLocation,
        signed: bool,
        approved: bool,
    ) -> Bundle {
        Bundle {
            id: id.into(),
            source: src,
            location: loc,
            signature_present: signed,
            schema_version: SCHEMA_VERSION.into(),
            operator_approved: approved,
        }
    }

    #[test]
    fn empty_id_rejected() {
        let p = BundleLoadPolicy::new();
        let b = bundle("", BundleSource::Vendor, SourceLocation::Local, true, false);
        assert!(matches!(p.decide(&b), LoadVerdict::EmptyId));
    }

    #[test]
    fn vendor_must_be_signed() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Vendor,
            SourceLocation::Local,
            false,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::VendorUnsigned));
    }

    #[test]
    fn vendor_signed_loads() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Vendor,
            SourceLocation::Local,
            true,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::Loaded));
    }

    #[test]
    fn operator_local_unsigned_loads() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Operator,
            SourceLocation::Local,
            false,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::Loaded));
    }

    #[test]
    fn operator_network_unsigned_rejected() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Operator,
            SourceLocation::Network,
            false,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::OperatorNetworkUnsigned));
    }

    #[test]
    fn operator_network_signed_loads() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Operator,
            SourceLocation::Network,
            true,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::Loaded));
    }

    #[test]
    fn untrusted_needs_signature_and_approval() {
        let p = BundleLoadPolicy::new();
        let b = bundle(
            "a",
            BundleSource::Untrusted,
            SourceLocation::Network,
            false,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::UntrustedNotApproved));
        let b = bundle(
            "a",
            BundleSource::Untrusted,
            SourceLocation::Network,
            true,
            false,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::UntrustedNotApproved));
        let b = bundle(
            "a",
            BundleSource::Untrusted,
            SourceLocation::Network,
            true,
            true,
        );
        assert!(matches!(p.decide(&b), LoadVerdict::Loaded));
    }

    #[test]
    fn schema_mismatch_rejected() {
        let p = BundleLoadPolicy::new();
        let mut b = bundle(
            "a",
            BundleSource::Vendor,
            SourceLocation::Local,
            true,
            false,
        );
        b.schema_version = "9.9.9".into();
        assert!(matches!(p.decide(&b), LoadVerdict::SchemaMismatch { .. }));
    }

    #[test]
    fn policy_schema_drift_rejected() {
        let mut p = BundleLoadPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            BundleLoadError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        let v = LoadVerdict::UntrustedNotApproved;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"untrusted-not-approved\"")
        );
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let b = bundle(
            "a",
            BundleSource::Operator,
            SourceLocation::Local,
            false,
            false,
        );
        let j = serde_json::to_string(&b).unwrap();
        let back: Bundle = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }
}
