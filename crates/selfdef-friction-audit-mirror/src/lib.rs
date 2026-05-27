//! `selfdef-friction-audit-mirror` — MS007 typed-mirror crate exposing
//! selfdef friction-audit Verdict state READ-ONLY for:
//!   - sovereign-os M060 cockpit "Friction Audit" panel
//!   - selfdef MS043 R10180 TUI authority-panel row
//!   - selfdef MS027 observability stream (read-only consumer)
//!
//! Implements MS046 catalog rows R10891-R10905 (typed mirror discipline).
//!
//! Per MS007 cross-repo binding doctrine, mirrors expose state read-only;
//! mutations proxy via MS003-signed operator request only. There are NO
//! setter methods on the public API; consumers receive owned `Verdict`
//! values via serde-deserialization from the ring buffer / OCSF jsonl.
//!
//! Cross-references:
//! - SDD-027 friction-audit-system specification
//! - MS046 milestone catalog (backlog/milestones/MS046-*.md)
//! - sister mirror crates: selfdef-capability-mirror, selfdef-quarantine-mirror,
//!   selfdef-grants-mirror, selfdef-audit-mirror, selfdef-cli-mirror
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// to deserialize Verdicts whose schema_version does not match what
/// they were built against. Per MS046 R11024: schema bump is a
/// breaking change requiring sovereign-os mirror version bump.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Which gate the verdict refers to.
///
/// `Pcie` / `Zfs` / `Memory` map verbatim to the three sain-01 §5 gates.
/// `Immutability` / `Signature` are extension gates that fire when the
/// friction-audit script's own integrity (chattr +i + MS003 signature)
/// is violated. `Timeout` fires when the operator-extended 2000ms hard
/// cap is hit (MS046 F05492).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Gate {
    /// PCIe bifurcation symmetry (lspci x8 lane width).
    Pcie,
    /// ZFS pool health (`zpool status -x` == "all pools are healthy").
    Zfs,
    /// System memory geometry (`dmidecode -t memory` DIMM count).
    Memory,
    /// Script binary chattr +i / IMA-appraise integrity.
    Immutability,
    /// MS003 signature on script + systemd unit.
    Signature,
    /// Operator-extended timeout watchdog (2000ms hard cap).
    Timeout,
}

/// Per-gate verdict status.
///
/// `Pass` and `Skipped` are the two clean outcomes (Skipped is operator-
/// extended for hosts without `zpool`/`dmidecode`; not in sain-01
/// baseline). `Fail(code)` carries the script exit code (1=PCIe,
/// 2=ZFS, 3=memory, 4=timeout, etc — see MS046 F05489-F05498).
/// `OverrideActive` indicates the gate failed but an operator-signed
/// override manifest (MS003-signed, MS046 R10869-R10880) is currently
/// honoring the failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum Status {
    /// Gate passed.
    Pass,
    /// Gate skipped (tool not present, deployment-target-conditional).
    Skipped(String),
    /// Gate failed with the given script exit code.
    Fail(u8),
    /// Gate failed but operator-signed override is honoring it.
    OverrideActive {
        /// SHA-256 of the override manifest (hex).
        manifest_sha256: String,
        /// Expiry timestamp (ms epoch).
        expires_at_ms: u64,
    },
}

/// A read-only verdict for one gate at one point in time.
///
/// Carries `signer_kid_policy` (MS003 selfdef-signing key id for the
/// base TracingPolicy / script signature) and optionally
/// `signer_kid_extension` (MS003 signer of an active override manifest)
/// per MS046 R10891-R10893.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verdict {
    /// Schema version (MUST equal `SCHEMA_VERSION`).
    pub schema_version: String,
    /// Which gate this verdict refers to.
    pub gate: Gate,
    /// The verdict status.
    pub status: Status,
    /// Verdict timestamp (ms since epoch).
    pub ts_ms: u64,
    /// Host where the gate ran.
    pub hostname: String,
    /// MS003 signing key id for the base script/policy.
    pub signer_kid_policy: String,
    /// MS003 signing key id for an active override manifest, if any.
    pub signer_kid_extension: Option<String>,
}

/// Errors produced by the mirror surface.
#[derive(Debug, Error)]
pub enum FrictionAuditError {
    /// Schema-version drift (consumer must refuse).
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// Empty signer kid (policy signer cannot be empty).
    #[error("signer_kid_policy is empty (MS003 binding required)")]
    EmptyPolicySigner,
    /// Empty hostname (every verdict must carry device identity).
    #[error("hostname is empty (MS026 OCSF binding requires device.hostname)")]
    EmptyHostname,
    /// Bad timestamp (epoch ms must be ≥ 1)
    #[error("ts_ms must be >= 1 (got 0)")]
    BadTimestamp,
    /// Empty manifest sha256 in OverrideActive status.
    #[error("OverrideActive status requires manifest_sha256")]
    EmptyOverrideManifest,
    /// JSON deserialization error.
    #[error("serde_json: {0}")]
    Serde(String),
}

impl Verdict {
    /// Construct a new Verdict at compile-time-checked schema version.
    ///
    /// Callers must supply the policy signer kid (non-empty per
    /// MS046 R11128/R11129). Use `Verdict::with_override(...)` for
    /// OverrideActive verdicts where the extension signer is required.
    #[must_use]
    pub fn new(
        gate: Gate,
        status: Status,
        ts_ms: u64,
        hostname: impl Into<String>,
        signer_kid_policy: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            gate,
            status,
            ts_ms,
            hostname: hostname.into(),
            signer_kid_policy: signer_kid_policy.into(),
            signer_kid_extension: None,
        }
    }

    /// Attach an override-signer kid (when `status` is `OverrideActive`).
    #[must_use]
    pub fn with_override_signer(mut self, kid: impl Into<String>) -> Self {
        self.signer_kid_extension = Some(kid.into());
        self
    }

    /// Validate per MS046 R10897 + R11128-R11132. Read-only; returns
    /// the first violation found.
    ///
    /// # Errors
    /// Returns `FrictionAuditError` on schema drift, missing signer,
    /// empty hostname, zero timestamp, or empty override manifest.
    pub fn validate(&self) -> Result<(), FrictionAuditError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FrictionAuditError::SchemaMismatch(
                self.schema_version.clone(),
            ));
        }
        if self.signer_kid_policy.is_empty() {
            return Err(FrictionAuditError::EmptyPolicySigner);
        }
        if self.hostname.is_empty() {
            return Err(FrictionAuditError::EmptyHostname);
        }
        if self.ts_ms == 0 {
            return Err(FrictionAuditError::BadTimestamp);
        }
        if let Status::OverrideActive {
            manifest_sha256, ..
        } = &self.status
        {
            if manifest_sha256.is_empty() {
                return Err(FrictionAuditError::EmptyOverrideManifest);
            }
        }
        Ok(())
    }

    /// Convenience: is this verdict a hard FAIL (no override honoring)?
    #[must_use]
    pub fn is_failing(&self) -> bool {
        matches!(self.status, Status::Fail(_))
    }

    /// Convenience: is this verdict honoring an operator override?
    #[must_use]
    pub fn is_override_active(&self) -> bool {
        matches!(self.status, Status::OverrideActive { .. })
    }

    /// Deserialize a Verdict from a JSON byte slice and validate it.
    ///
    /// # Errors
    /// Returns `FrictionAuditError::Serde` on parse failure or any
    /// validation error from `validate()`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, FrictionAuditError> {
        let v: Self =
            serde_json::from_slice(bytes).map_err(|e| FrictionAuditError::Serde(e.to_string()))?;
        v.validate()?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pass() -> Verdict {
        Verdict::new(
            Gate::Pcie,
            Status::Pass,
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    #[test]
    fn pass_verdict_validates() {
        assert!(sample_pass().validate().is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = sample_pass();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            FrictionAuditError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn empty_signer_rejected() {
        let mut v = sample_pass();
        v.signer_kid_policy.clear();
        assert!(matches!(
            v.validate().unwrap_err(),
            FrictionAuditError::EmptyPolicySigner
        ));
    }

    #[test]
    fn empty_hostname_rejected() {
        let mut v = sample_pass();
        v.hostname.clear();
        assert!(matches!(
            v.validate().unwrap_err(),
            FrictionAuditError::EmptyHostname
        ));
    }

    #[test]
    fn zero_timestamp_rejected() {
        let mut v = sample_pass();
        v.ts_ms = 0;
        assert!(matches!(
            v.validate().unwrap_err(),
            FrictionAuditError::BadTimestamp
        ));
    }

    #[test]
    fn fail_verdict_is_failing() {
        let v = Verdict::new(Gate::Pcie, Status::Fail(1), 1, "h", "k");
        assert!(v.is_failing());
        assert!(!v.is_override_active());
    }

    #[test]
    fn override_active_requires_manifest_sha256() {
        let v = Verdict::new(
            Gate::Pcie,
            Status::OverrideActive {
                manifest_sha256: String::new(),
                expires_at_ms: 1,
            },
            1,
            "h",
            "k",
        );
        assert!(matches!(
            v.validate().unwrap_err(),
            FrictionAuditError::EmptyOverrideManifest
        ));
    }

    #[test]
    fn override_active_with_signer_validates() {
        let v = Verdict::new(
            Gate::Zfs,
            Status::OverrideActive {
                manifest_sha256: "abc123".into(),
                expires_at_ms: 1_700_000_999_999,
            },
            1_700_000_500_000,
            "host-B",
            "kid-policy-2",
        )
        .with_override_signer("kid-override-7");
        assert!(v.validate().is_ok());
        assert!(v.is_override_active());
        assert!(!v.is_failing());
        assert_eq!(v.signer_kid_extension.as_deref(), Some("kid-override-7"));
    }

    #[test]
    fn skipped_status_validates() {
        let v = Verdict::new(
            Gate::Zfs,
            Status::Skipped("zpool not installed; deployment.target=generic".into()),
            1_700_000_000_000,
            "container-X",
            "kid-policy-1",
        );
        assert!(v.validate().is_ok());
        assert!(!v.is_failing());
    }

    #[test]
    fn serde_roundtrip_pass() {
        let v = sample_pass();
        let j = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn serde_roundtrip_override() {
        let v = Verdict::new(
            Gate::Pcie,
            Status::OverrideActive {
                manifest_sha256: "deadbeef".into(),
                expires_at_ms: 1_700_100_000_000,
            },
            1_700_000_000_000,
            "h",
            "k1",
        )
        .with_override_signer("k2");
        let j = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn from_json_validates_in_one_call() {
        let v = sample_pass();
        let bytes = serde_json::to_vec(&v).unwrap();
        let parsed = Verdict::from_json(&bytes).expect("parse + validate");
        assert_eq!(parsed, v);
    }

    #[test]
    fn from_json_rejects_schema_drift() {
        let bad = r#"{"schema_version":"9.9.9","gate":"pcie","status":{"status":"pass"},"ts_ms":1,"hostname":"h","signer_kid_policy":"k","signer_kid_extension":null}"#;
        assert!(matches!(
            Verdict::from_json(bad.as_bytes()).unwrap_err(),
            FrictionAuditError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn all_gates_serialize_kebab_case() {
        for (g, want) in &[
            (Gate::Pcie, "pcie"),
            (Gate::Zfs, "zfs"),
            (Gate::Memory, "memory"),
            (Gate::Immutability, "immutability"),
            (Gate::Signature, "signature"),
            (Gate::Timeout, "timeout"),
        ] {
            let j = serde_json::to_string(g).unwrap();
            assert_eq!(
                j,
                format!("\"{want}\""),
                "gate {g:?} did not serialize as {want}"
            );
        }
    }
}
