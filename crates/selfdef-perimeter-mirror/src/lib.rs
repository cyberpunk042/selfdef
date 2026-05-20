//! `selfdef-perimeter-mirror` — MS007 typed-mirror crate exposing selfdef
//! perimeter (Tetragon `sovereign-kernel-fence` TracingPolicy) Verdict
//! state READ-ONLY for:
//!   - sovereign-os M061 cockpit "Perimeter" panel
//!   - selfdef MS043 R10180 TUI authority-panel row
//!   - selfdef MS027 observability stream (read-only consumer)
//!
//! Implements MS047 catalog rows R11128-R11135 (typed mirror discipline).
//!
//! Per MS007 cross-repo binding doctrine, mirrors expose state read-only;
//! mutations proxy via MS003-signed operator request only. There are NO
//! setter methods on the public API; consumers receive owned `Verdict`
//! values via serde-deserialization from the OCSF Detection 2004 jsonl
//! emission / ZFS log bridge.
//!
//! Cross-references:
//! - SDD-028 real-time security perimeter engine specification
//! - MS047 milestone catalog (backlog/milestones/MS047-*.md)
//! - Sister mirror: selfdef-friction-audit-mirror (hardware-frame gate)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse to
/// deserialize Verdicts whose `schema_version` does not match what they
/// were built against. Per MS047 R11134: schema bump is a breaking
/// change requiring sovereign-os mirror version bump.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Outcome of a single `sys_execve` evaluation under the
/// `sovereign-kernel-fence` TracingPolicy.
///
/// `Sigkill` is the in-kernel termination action sain-01 §6 mandates
/// when the attempted binary is not in the allowlist (and no operator
/// extension covers it). `Allowlisted` is emitted on the Audit 1003 /
/// success channel for binaries in the verbatim sain-01 §6 default set.
/// `ExtensionAllowed` is the operator-signed allowlist-extension case
/// where MS003 multi-sig + TTL ≤ 30 days authorized the execve.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "outcome", content = "detail")]
pub enum Outcome {
    /// Tetragon kprobe matched NotIn allowlist; SIGKILL fired in-kernel.
    Sigkill,
    /// Binary was in the verbatim sain-01 §6 default allowlist.
    Allowlisted,
    /// Binary was not in the default allowlist, but an operator-signed
    /// extension manifest (MS047 R11077-R11086, MS003 multi-sig) was
    /// active at the time of the execve and authorized it.
    ExtensionAllowed {
        /// SHA-256 of the extension manifest JSON (hex).
        manifest_sha256: String,
        /// Expiry timestamp (ms epoch). TTL ≤ 30 days per MS047 R11084.
        expires_at_ms: u64,
    },
}

/// A read-only verdict for one `sys_execve` decision.
///
/// Process-identity fields (`attempting_pid`, `parent_pid`, `cgroup`,
/// `container_id`, `process_cmdline`) are populated from the Tetragon
/// event payload. `attempted_binary_path` is the kprobe arg-0 string.
/// `signer_kid_policy` is the MS003 selfdef-signing key id for the
/// TracingPolicy YAML itself; `signer_kid_extension` is set only when
/// `outcome == ExtensionAllowed`.
///
/// Per MS047 R11128-R11132.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verdict {
    /// Schema version (MUST equal `SCHEMA_VERSION`).
    pub schema_version: String,
    /// Outcome of the evaluation.
    pub outcome: Outcome,
    /// Path the attempting process passed to `sys_execve` (kprobe arg 0).
    pub attempted_binary_path: String,
    /// PID of the process that called `sys_execve`.
    pub attempting_pid: u32,
    /// PID of the parent of the attempting process.
    pub parent_pid: u32,
    /// Cgroup path of the attempting process (from Tetragon event).
    pub cgroup: String,
    /// Container id (Podman / runc / containerd) if running in one; empty otherwise.
    pub container_id: String,
    /// Command-line of the attempting process (already-exec'd cmdline, not the new exec).
    pub process_cmdline: String,
    /// Verdict timestamp (ms since epoch).
    pub ts_ms: u64,
    /// Host where the perimeter ran.
    pub hostname: String,
    /// MS003 signing key id for the active TracingPolicy.
    pub signer_kid_policy: String,
    /// MS003 signing key id for an active extension manifest, if any.
    pub signer_kid_extension: Option<String>,
}

/// Errors produced by the mirror surface.
#[derive(Debug, Error)]
pub enum PerimeterError {
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
    /// Empty attempted binary path (every verdict must name the syscall target).
    #[error("attempted_binary_path is empty (kprobe arg 0 absent)")]
    EmptyBinaryPath,
    /// Empty manifest sha256 in ExtensionAllowed outcome.
    #[error("ExtensionAllowed outcome requires manifest_sha256")]
    EmptyExtensionManifest,
    /// ExtensionAllowed outcome missing signer_kid_extension.
    #[error("ExtensionAllowed outcome requires signer_kid_extension")]
    MissingExtensionSigner,
    /// JSON deserialization error.
    #[error("serde_json: {0}")]
    Serde(String),
}

impl Verdict {
    /// Construct a new Verdict at compile-time-checked schema version.
    ///
    /// Callers must supply the policy signer kid (non-empty per MS047
    /// R11128/R11129). Use `with_extension_signer(...)` to attach the
    /// extension-signer kid for `ExtensionAllowed` outcomes.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        outcome: Outcome,
        attempted_binary_path: impl Into<String>,
        attempting_pid: u32,
        parent_pid: u32,
        cgroup: impl Into<String>,
        container_id: impl Into<String>,
        process_cmdline: impl Into<String>,
        ts_ms: u64,
        hostname: impl Into<String>,
        signer_kid_policy: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            outcome,
            attempted_binary_path: attempted_binary_path.into(),
            attempting_pid,
            parent_pid,
            cgroup: cgroup.into(),
            container_id: container_id.into(),
            process_cmdline: process_cmdline.into(),
            ts_ms,
            hostname: hostname.into(),
            signer_kid_policy: signer_kid_policy.into(),
            signer_kid_extension: None,
        }
    }

    /// Attach an extension-signer kid (when `outcome` is `ExtensionAllowed`).
    #[must_use]
    pub fn with_extension_signer(mut self, kid: impl Into<String>) -> Self {
        self.signer_kid_extension = Some(kid.into());
        self
    }

    /// Validate per MS047 R11128-R11132. Read-only; returns the first
    /// violation found.
    ///
    /// # Errors
    /// Returns `PerimeterError` on schema drift, missing signer, empty
    /// hostname, zero timestamp, empty binary path, or extension-outcome
    /// missing manifest / signer.
    pub fn validate(&self) -> Result<(), PerimeterError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PerimeterError::SchemaMismatch(self.schema_version.clone()));
        }
        if self.signer_kid_policy.is_empty() {
            return Err(PerimeterError::EmptyPolicySigner);
        }
        if self.hostname.is_empty() {
            return Err(PerimeterError::EmptyHostname);
        }
        if self.ts_ms == 0 {
            return Err(PerimeterError::BadTimestamp);
        }
        if self.attempted_binary_path.is_empty() {
            return Err(PerimeterError::EmptyBinaryPath);
        }
        if let Outcome::ExtensionAllowed { manifest_sha256, .. } = &self.outcome {
            if manifest_sha256.is_empty() {
                return Err(PerimeterError::EmptyExtensionManifest);
            }
            if self.signer_kid_extension.as_deref().unwrap_or("").is_empty() {
                return Err(PerimeterError::MissingExtensionSigner);
            }
        }
        Ok(())
    }

    /// Convenience: did this verdict result in an in-kernel SIGKILL?
    #[must_use]
    pub fn is_sigkill(&self) -> bool {
        matches!(self.outcome, Outcome::Sigkill)
    }

    /// Convenience: was this verdict honoring an operator-signed extension?
    #[must_use]
    pub fn is_extension_allowed(&self) -> bool {
        matches!(self.outcome, Outcome::ExtensionAllowed { .. })
    }

    /// Convenience: was this verdict a default-allowlist match (sain-01 §6 verbatim)?
    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        matches!(self.outcome, Outcome::Allowlisted)
    }

    /// Deserialize a Verdict from a JSON byte slice and validate it.
    ///
    /// # Errors
    /// Returns `PerimeterError::Serde` on parse failure or any
    /// validation error from `validate()`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PerimeterError> {
        let v: Self = serde_json::from_slice(bytes)
            .map_err(|e| PerimeterError::Serde(e.to_string()))?;
        v.validate()?;
        Ok(v)
    }
}

/// The verbatim sain-01 §6 default allowlist. Consumers use this for
/// display ("policy is default" vs "policy is operator-extended") and
/// for unit-test assertions that the mirror hasn't drifted from spec.
pub const DEFAULT_ALLOWLIST: &[&str] = &[
    "/usr/bin/python3",
    "/usr/bin/nvidia-smi",
    "/usr/local/bin/vllm",
    "/usr/bin/podman",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sigkill() -> Verdict {
        Verdict::new(
            Outcome::Sigkill,
            "/usr/bin/curl",
            4242,
            4200,
            "/system.slice/sshd.service",
            "",
            "sshd: operator@pts/0",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    fn sample_allowlisted() -> Verdict {
        Verdict::new(
            Outcome::Allowlisted,
            "/usr/bin/python3",
            5555,
            5500,
            "/system.slice/selfdefd.service",
            "",
            "selfdefd",
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    fn sample_extension_allowed() -> Verdict {
        Verdict::new(
            Outcome::ExtensionAllowed {
                manifest_sha256: "abc123".into(),
                expires_at_ms: 1_702_000_000_000,
            },
            "/usr/local/bin/custom-tool",
            6666,
            6600,
            "/system.slice/selfdefd.service",
            "",
            "custom-tool --probe",
            1_700_500_000_000,
            "host-A",
            "kid-policy-1",
        )
        .with_extension_signer("kid-ext-7")
    }

    #[test]
    fn sigkill_verdict_validates() {
        assert!(sample_sigkill().validate().is_ok());
    }

    #[test]
    fn allowlisted_verdict_validates() {
        assert!(sample_allowlisted().validate().is_ok());
    }

    #[test]
    fn extension_allowed_validates() {
        assert!(sample_extension_allowed().validate().is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = sample_sigkill();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn empty_signer_rejected() {
        let mut v = sample_sigkill();
        v.signer_kid_policy.clear();
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::EmptyPolicySigner
        ));
    }

    #[test]
    fn empty_hostname_rejected() {
        let mut v = sample_sigkill();
        v.hostname.clear();
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::EmptyHostname
        ));
    }

    #[test]
    fn zero_timestamp_rejected() {
        let mut v = sample_sigkill();
        v.ts_ms = 0;
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::BadTimestamp
        ));
    }

    #[test]
    fn empty_binary_path_rejected() {
        let mut v = sample_sigkill();
        v.attempted_binary_path.clear();
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::EmptyBinaryPath
        ));
    }

    #[test]
    fn extension_requires_manifest_sha256() {
        let v = Verdict::new(
            Outcome::ExtensionAllowed {
                manifest_sha256: String::new(),
                expires_at_ms: 1,
            },
            "/x",
            1,
            1,
            "/",
            "",
            "x",
            1,
            "h",
            "k",
        )
        .with_extension_signer("ext");
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::EmptyExtensionManifest
        ));
    }

    #[test]
    fn extension_requires_signer() {
        let v = Verdict::new(
            Outcome::ExtensionAllowed {
                manifest_sha256: "abc".into(),
                expires_at_ms: 1,
            },
            "/x",
            1,
            1,
            "/",
            "",
            "x",
            1,
            "h",
            "k",
        );
        assert!(matches!(
            v.validate().unwrap_err(),
            PerimeterError::MissingExtensionSigner
        ));
    }

    #[test]
    fn convenience_predicates() {
        let s = sample_sigkill();
        assert!(s.is_sigkill() && !s.is_allowlisted() && !s.is_extension_allowed());

        let a = sample_allowlisted();
        assert!(a.is_allowlisted() && !a.is_sigkill() && !a.is_extension_allowed());

        let e = sample_extension_allowed();
        assert!(e.is_extension_allowed() && !e.is_sigkill() && !e.is_allowlisted());
    }

    #[test]
    fn serde_roundtrip_sigkill() {
        let v = sample_sigkill();
        let j = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn serde_roundtrip_extension() {
        let v = sample_extension_allowed();
        let j = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn from_json_validates_in_one_call() {
        let v = sample_sigkill();
        let bytes = serde_json::to_vec(&v).unwrap();
        let parsed = Verdict::from_json(&bytes).expect("parse + validate");
        assert_eq!(parsed, v);
    }

    #[test]
    fn from_json_rejects_schema_drift() {
        let bad = r#"{"schema_version":"9.9.9","outcome":{"outcome":"sigkill"},"attempted_binary_path":"/x","attempting_pid":1,"parent_pid":1,"cgroup":"/","container_id":"","process_cmdline":"x","ts_ms":1,"hostname":"h","signer_kid_policy":"k","signer_kid_extension":null}"#;
        assert!(matches!(
            Verdict::from_json(bad.as_bytes()).unwrap_err(),
            PerimeterError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn outcome_serializes_kebab_case() {
        let j = serde_json::to_string(&Outcome::Sigkill).unwrap();
        assert_eq!(j, r#"{"outcome":"sigkill"}"#);

        let j = serde_json::to_string(&Outcome::Allowlisted).unwrap();
        assert_eq!(j, r#"{"outcome":"allowlisted"}"#);

        let j = serde_json::to_string(&Outcome::ExtensionAllowed {
            manifest_sha256: "abc".into(),
            expires_at_ms: 1_700_000_000_000,
        })
        .unwrap();
        assert!(j.starts_with(r#"{"outcome":"extension-allowed","detail":"#));
    }

    #[test]
    fn default_allowlist_matches_sain01_section_6_verbatim() {
        assert_eq!(
            DEFAULT_ALLOWLIST,
            &[
                "/usr/bin/python3",
                "/usr/bin/nvidia-smi",
                "/usr/local/bin/vllm",
                "/usr/bin/podman",
            ]
        );
    }
}
