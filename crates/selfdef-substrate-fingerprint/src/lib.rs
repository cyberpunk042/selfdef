//! `selfdef-substrate-fingerprint` — boot-time tamper-detection snapshot.
//!
//! At boot, the daemon computes:
//! - `rule_pack_summary`  — semver-joined string for 8 rule packs
//! - `doctrine_text_hash` — FNV-1a 64-bit of the 10 verbatim doctrines
//! - `collector_summary`  — kebab-joined string for 7 collectors
//! - `host_fingerprint`   — operator-provided host identifier
//!
//! Comparing the fresh snapshot against a pinned reference detects any
//! drift; `assert_matches` returns the specific field that diverged.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// FNV-1a 64-bit hash of a byte slice.
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Fingerprint snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateFingerprint {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC.
    pub captured_at: String,
    /// Joined semvers for the 8 rule packs (sorted).
    pub rule_pack_summary: String,
    /// FNV-1a 64-bit hex of concatenated doctrine texts.
    pub doctrine_text_hash: String,
    /// Joined kebab names for 7 collectors (sorted).
    pub collector_summary: String,
    /// Operator-provided host id.
    pub host_fingerprint: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FingerprintError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Missing field.
    #[error("field {0} empty")]
    MissingField(&'static str),
    /// Field mismatch against pinned reference.
    #[error("substrate drift on field {field}: snapshot={snapshot}, pinned={pinned}")]
    Drift {
        /// field.
        field: &'static str,
        /// snapshot.
        snapshot: String,
        /// pinned.
        pinned: String,
    },
}

impl SubstrateFingerprint {
    /// Compute a fingerprint from inputs.
    pub fn compute(
        rule_pack_semvers: &[String],
        doctrine_texts: &[String],
        collector_kinds: &[String],
        host_fingerprint: &str,
        captured_at: &str,
    ) -> Self {
        let mut rp = rule_pack_semvers.to_vec();
        rp.sort();
        let rule_pack_summary = rp.join(",");
        let mut concat: Vec<u8> = Vec::new();
        for d in doctrine_texts {
            concat.extend_from_slice(d.as_bytes());
            concat.push(0);
        }
        let hash = fnv1a_64(&concat);
        let doctrine_text_hash = format!("{:016x}", hash);
        let mut ck = collector_kinds.to_vec();
        ck.sort();
        let collector_summary = ck.join(",");
        Self {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: captured_at.into(),
            rule_pack_summary,
            doctrine_text_hash,
            collector_summary,
            host_fingerprint: host_fingerprint.into(),
        }
    }

    /// Validate non-empty.
    pub fn validate(&self) -> Result<(), FingerprintError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FingerprintError::SchemaMismatch);
        }
        if self.captured_at.is_empty() {
            return Err(FingerprintError::MissingField("captured_at"));
        }
        if self.rule_pack_summary.is_empty() {
            return Err(FingerprintError::MissingField("rule_pack_summary"));
        }
        if self.doctrine_text_hash.is_empty() {
            return Err(FingerprintError::MissingField("doctrine_text_hash"));
        }
        if self.collector_summary.is_empty() {
            return Err(FingerprintError::MissingField("collector_summary"));
        }
        if self.host_fingerprint.is_empty() {
            return Err(FingerprintError::MissingField("host_fingerprint"));
        }
        Ok(())
    }

    /// Assert that this snapshot matches a pinned reference (ignoring captured_at).
    pub fn assert_matches(&self, pinned: &SubstrateFingerprint) -> Result<(), FingerprintError> {
        self.validate()?;
        if self.rule_pack_summary != pinned.rule_pack_summary {
            return Err(FingerprintError::Drift {
                field: "rule_pack_summary",
                snapshot: self.rule_pack_summary.clone(),
                pinned: pinned.rule_pack_summary.clone(),
            });
        }
        if self.doctrine_text_hash != pinned.doctrine_text_hash {
            return Err(FingerprintError::Drift {
                field: "doctrine_text_hash",
                snapshot: self.doctrine_text_hash.clone(),
                pinned: pinned.doctrine_text_hash.clone(),
            });
        }
        if self.collector_summary != pinned.collector_summary {
            return Err(FingerprintError::Drift {
                field: "collector_summary",
                snapshot: self.collector_summary.clone(),
                pinned: pinned.collector_summary.clone(),
            });
        }
        if self.host_fingerprint != pinned.host_fingerprint {
            return Err(FingerprintError::Drift {
                field: "host_fingerprint",
                snapshot: self.host_fingerprint.clone(),
                pinned: pinned.host_fingerprint.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SubstrateFingerprint {
        SubstrateFingerprint::compute(
            &[
                "1.0.0".into(),
                "1.1.0".into(),
                "1.2.3".into(),
                "2.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
            ],
            &["doctrine-a".into(), "doctrine-b".into()],
            &["auditd".into(), "tetragon".into(), "ebpf".into()],
            "host-fp-abc",
            "2026-05-19T03:00:00Z",
        )
    }

    #[test]
    fn fnv1a_deterministic() {
        let a = fnv1a_64(b"abc");
        let b = fnv1a_64(b"abc");
        assert_eq!(a, b);
        // Different inputs yield different hashes.
        assert_ne!(fnv1a_64(b"abc"), fnv1a_64(b"abd"));
    }

    #[test]
    fn snapshot_validates() {
        sample().validate().unwrap();
    }

    #[test]
    fn assert_matches_self() {
        sample().assert_matches(&sample()).unwrap();
    }

    #[test]
    fn rule_pack_drift_caught() {
        let a = sample();
        let pinned = SubstrateFingerprint::compute(
            &["9.9.9".into()],
            &["doctrine-a".into(), "doctrine-b".into()],
            &["auditd".into(), "tetragon".into(), "ebpf".into()],
            "host-fp-abc",
            "t",
        );
        match a.assert_matches(&pinned).unwrap_err() {
            FingerprintError::Drift { field, .. } => assert_eq!(field, "rule_pack_summary"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn doctrine_text_drift_caught() {
        let a = sample();
        let mut pinned = sample();
        pinned.doctrine_text_hash = "deadbeef".into();
        match a.assert_matches(&pinned).unwrap_err() {
            FingerprintError::Drift { field, .. } => assert_eq!(field, "doctrine_text_hash"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn collector_drift_caught() {
        let a = sample();
        let pinned = SubstrateFingerprint::compute(
            &[
                "1.0.0".into(),
                "1.1.0".into(),
                "1.2.3".into(),
                "2.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
                "1.0.0".into(),
            ],
            &["doctrine-a".into(), "doctrine-b".into()],
            &["auditd".into()], // missing tetragon and ebpf
            "host-fp-abc",
            "t",
        );
        match a.assert_matches(&pinned).unwrap_err() {
            FingerprintError::Drift { field, .. } => assert_eq!(field, "collector_summary"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn host_fingerprint_drift_caught() {
        let a = sample();
        let mut pinned = sample();
        pinned.host_fingerprint = "different-host".into();
        match a.assert_matches(&pinned).unwrap_err() {
            FingerprintError::Drift { field, .. } => assert_eq!(field, "host_fingerprint"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rule_pack_summary_sorted() {
        let f = sample();
        // Sample passes unsorted-looking input but compute sorts.
        let parts: Vec<&str> = f.rule_pack_summary.split(',').collect();
        let mut sorted = parts.clone();
        sorted.sort();
        assert_eq!(parts, sorted);
    }

    #[test]
    fn collector_summary_sorted() {
        let f = sample();
        let parts: Vec<&str> = f.collector_summary.split(',').collect();
        let mut sorted = parts.clone();
        sorted.sort();
        assert_eq!(parts, sorted);
    }

    #[test]
    fn missing_field_caught() {
        let mut f = sample();
        f.host_fingerprint = String::new();
        assert!(matches!(
            f.validate().unwrap_err(),
            FingerprintError::MissingField("host_fingerprint")
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut f = sample();
        f.schema_version = "9.9.9".into();
        assert!(matches!(
            f.validate().unwrap_err(),
            FingerprintError::SchemaMismatch
        ));
    }

    #[test]
    fn fingerprint_serde_roundtrip() {
        let f = sample();
        let j = serde_json::to_string(&f).unwrap();
        let back: SubstrateFingerprint = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }
}
