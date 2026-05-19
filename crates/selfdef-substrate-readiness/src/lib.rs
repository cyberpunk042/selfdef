//! `selfdef-substrate-readiness` — daemon bring-up readiness probe.
//!
//! 8 readiness checks the daemon runs at boot:
//! 1. mode_policy_loaded
//! 2. rule_pack_loaded
//! 3. doctrine_registry_intact
//! 4. collector_taxonomy_live
//! 5. bus_subscribers_wired
//! 6. audit_chain_healthy
//! 7. trust_floor_present
//! 8. host_fingerprint_pinned
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One of 8 readiness check kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckKind {
    /// Mode policy crate loaded.
    ModePolicyLoaded,
    /// Rule pack loaded.
    RulePackLoaded,
    /// Doctrine registry intact (10 doctrines verified).
    DoctrineRegistryIntact,
    /// Collector taxonomy live (7 collectors).
    CollectorTaxonomyLive,
    /// Bus subscribers wired (9 subscribers).
    BusSubscribersWired,
    /// Audit chain healthy.
    AuditChainHealthy,
    /// Trust floor present.
    TrustFloorPresent,
    /// Host fingerprint pinned.
    HostFingerprintPinned,
}

/// One check result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    /// Kind.
    pub kind: CheckKind,
    /// Passed?
    pub passed: bool,
    /// Detail (empty when passed).
    pub detail: String,
}

/// Readiness report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessReport {
    /// Schema version.
    pub schema_version: String,
    /// ISO-8601 UTC.
    pub captured_at: String,
    /// 8 results.
    pub results: Vec<CheckResult>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ReadinessError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("result count {0} != 8")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing check: {0:?}")]
    Missing(CheckKind),
    /// Empty timestamp.
    #[error("captured_at empty")]
    EmptyTimestamp,
    /// Refused due to failed checks.
    #[error("substrate not ready: {failures:?}")]
    NotReady {
        /// failures.
        failures: Vec<CheckKind>,
    },
}

const REQUIRED: [CheckKind; 8] = [
    CheckKind::ModePolicyLoaded,
    CheckKind::RulePackLoaded,
    CheckKind::DoctrineRegistryIntact,
    CheckKind::CollectorTaxonomyLive,
    CheckKind::BusSubscribersWired,
    CheckKind::AuditChainHealthy,
    CheckKind::TrustFloorPresent,
    CheckKind::HostFingerprintPinned,
];

impl ReadinessReport {
    /// Build a report with all checks marked passed.
    pub fn all_pass(captured_at: &str) -> Self {
        let results = REQUIRED.iter().map(|k| CheckResult {
            kind: *k,
            passed: true,
            detail: String::new(),
        }).collect();
        Self {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: captured_at.into(),
            results,
        }
    }

    /// True if all 8 checks passed.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Failed check kinds.
    pub fn failures(&self) -> Vec<CheckKind> {
        self.results.iter().filter(|r| !r.passed).map(|r| r.kind).collect()
    }

    /// Refuse bring-up if any check failed.
    pub fn assert_ready(&self) -> Result<(), ReadinessError> {
        self.validate()?;
        if !self.all_passed() {
            return Err(ReadinessError::NotReady { failures: self.failures() });
        }
        Ok(())
    }

    /// Validate structure.
    pub fn validate(&self) -> Result<(), ReadinessError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ReadinessError::SchemaMismatch);
        }
        if self.captured_at.is_empty() { return Err(ReadinessError::EmptyTimestamp); }
        if self.results.len() != 8 {
            return Err(ReadinessError::CountInvalid(self.results.len()));
        }
        for k in REQUIRED {
            if !self.results.iter().any(|r| r.kind == k) {
                return Err(ReadinessError::Missing(k));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pass_ready() {
        let r = ReadinessReport::all_pass("2026-05-19T03:00:00Z");
        r.assert_ready().unwrap();
        assert!(r.all_passed());
    }

    #[test]
    fn any_failure_blocks_ready() {
        let mut r = ReadinessReport::all_pass("t");
        r.results[0].passed = false;
        r.results[0].detail = "missing".into();
        let err = r.assert_ready().unwrap_err();
        match err {
            ReadinessError::NotReady { failures } => {
                assert_eq!(failures, vec![CheckKind::ModePolicyLoaded]);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn multiple_failures_all_listed() {
        let mut r = ReadinessReport::all_pass("t");
        r.results[0].passed = false;
        r.results[3].passed = false;
        match r.assert_ready().unwrap_err() {
            ReadinessError::NotReady { failures } => {
                assert_eq!(failures.len(), 2);
                assert!(failures.contains(&CheckKind::ModePolicyLoaded));
                assert!(failures.contains(&CheckKind::CollectorTaxonomyLive));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn missing_check_caught_in_validate() {
        let mut r = ReadinessReport::all_pass("t");
        // Replace AuditChainHealthy with duplicate ModePolicyLoaded.
        for c in r.results.iter_mut() {
            if c.kind == CheckKind::AuditChainHealthy {
                c.kind = CheckKind::ModePolicyLoaded;
            }
        }
        assert!(matches!(r.validate().unwrap_err(), ReadinessError::Missing(CheckKind::AuditChainHealthy)));
    }

    #[test]
    fn empty_timestamp_caught() {
        let mut r = ReadinessReport::all_pass("");
        assert!(matches!(r.validate().unwrap_err(), ReadinessError::EmptyTimestamp));
        // Set a timestamp + try assert_ready.
        r.captured_at = "t".into();
        r.assert_ready().unwrap();
    }

    #[test]
    fn count_invalid_caught() {
        let mut r = ReadinessReport::all_pass("t");
        r.results.pop();
        assert!(matches!(r.validate().unwrap_err(), ReadinessError::CountInvalid(7)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ReadinessReport::all_pass("t");
        r.schema_version = "9.9.9".into();
        assert!(matches!(r.validate().unwrap_err(), ReadinessError::SchemaMismatch));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(serde_json::to_string(&CheckKind::ModePolicyLoaded).unwrap(), "\"mode-policy-loaded\"");
        assert_eq!(serde_json::to_string(&CheckKind::HostFingerprintPinned).unwrap(), "\"host-fingerprint-pinned\"");
    }

    #[test]
    fn report_serde_roundtrip() {
        let r = ReadinessReport::all_pass("2026-05-19T03:00:00Z");
        let j = serde_json::to_string(&r).unwrap();
        let back: ReadinessReport = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
