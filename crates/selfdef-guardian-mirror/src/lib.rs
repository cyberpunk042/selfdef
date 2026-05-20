//! `selfdef-guardian-mirror` — MS007 typed-mirror crate exposing
//! selfdef Guardian Daemon (sain-01 §10 `guardian-core`) Verdict state
//! READ-ONLY for:
//!   - sovereign-os M066 cockpit "Guardian" panel (Trinity Genesis
//!     Auditor narrative bound to this IPS-side implementation)
//!   - selfdef MS043 R10180 TUI authority-panel row
//!   - selfdef MS027 observability stream (read-only consumer)
//!
//! Implements MS044 catalog rows R10481-R10485 (typed mirror discipline).
//!
//! Per MS007 cross-repo binding doctrine, mirrors expose state read-only;
//! mutations proxy via MS003-signed operator request only.
//!
//! Cross-references:
//! - SDD-029 guardian-daemon specification
//! - MS044 milestone catalog (backlog/milestones/MS044-*.md)
//! - Sister mirrors: selfdef-friction-audit-mirror (hardware frame),
//!   selfdef-perimeter-mirror (kernel syscall)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse to
/// deserialize Verdicts whose `schema_version` does not match what
/// they were built against. Per MS044 R10485: schema bump is a
/// breaking change requiring sovereign-os mirror version bump.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Which Tetragon-event action triggered Guardian's response.
///
/// `Sigkill` is the in-kernel termination action (e.g. emitted by the
/// `sovereign-kernel-fence` perimeter TracingPolicy). `ProcessRelated`
/// is the broader policy-violation channel — Guardian classifies it
/// per the sain-01 §10 rules and still issues the 3-step response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Tetragon's matchAction was Sigkill.
    Sigkill,
    /// Tetragon emitted a process-related policy event (non-kill).
    ProcessRelated,
    /// Catch-all for action strings that don't map cleanly. Logged
    /// but not actioned (Guardian errs on the side of NOT responding
    /// to unknown events; the operator decides if classification needs
    /// extension).
    Other,
}

/// One step in the verbatim sain-01 §10 3-step Guardian response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseStep {
    /// Step 1 — instant SIGKILL (`podman kill <container_id>` when
    /// container_id present, else `kill -9 <pid>` host-scope).
    Sigkill,
    /// Step 2 — atomic append to ZFS audit log
    /// (`/mnt/vault/context/security_audit.log`, sync=always).
    AuditAppend,
    /// Step 3 — native console alert (ASCII BEL + diagnostic line
    /// to `/dev/console`; PC-speaker bell on hardware that supports it).
    ConsoleAlert,
}

/// Outcome of a single response step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "outcome", content = "detail")]
pub enum StepOutcome {
    /// Step executed cleanly.
    Ok,
    /// Step was deliberately skipped (e.g. ConsoleAlert on a host
    /// without /dev/console writable). String carries reason.
    Skipped(String),
    /// Step failed. String carries the failure detail.
    Failed(String),
}

/// One step + its outcome bundled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepResult {
    /// Which step.
    pub step: ResponseStep,
    /// Outcome of that step.
    pub outcome: StepOutcome,
}

/// A read-only verdict for one Guardian-handled Tetragon event.
///
/// Per MS044 R10481-R10485 typed-mirror discipline. The event id
/// matches the Tetragon-emitted UUID so the OCSF chain can be joined
/// downstream. `target_*` fields identify the SIGKILL target;
/// `response_steps` records what Guardian did about it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verdict {
    /// Schema version (MUST equal `SCHEMA_VERSION`).
    pub schema_version: String,
    /// Tetragon-emitted event id (UUID).
    pub event_id: String,
    /// Originating Tetragon action.
    pub action: Action,
    /// PID of the target process.
    pub target_pid: u32,
    /// Cgroup path of the target process.
    pub target_cgroup: String,
    /// Container id (Podman/runc/containerd) if running in one; empty otherwise.
    pub target_container_id: String,
    /// Path of the binary the target was trying to / did execute.
    pub target_binary_path: String,
    /// Ordered list of response steps Guardian took (Step1 → Step2 → Step3).
    pub response_steps: Vec<StepResult>,
    /// Verdict timestamp (ms since epoch).
    pub ts_ms: u64,
    /// Host where Guardian ran.
    pub hostname: String,
    /// MS003 signing key id for the active Guardian policy.
    pub signer_kid_policy: String,
}

/// Errors produced by the mirror surface.
#[derive(Debug, Error)]
pub enum GuardianError {
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
    /// Empty event id (every verdict joins a Tetragon-event id).
    #[error("event_id is empty (Tetragon UUID join required)")]
    EmptyEventId,
    /// Empty response steps (Guardian must record what it did).
    #[error("response_steps is empty (Guardian must record at least one step)")]
    EmptyResponseSteps,
    /// JSON deserialization error.
    #[error("serde_json: {0}")]
    Serde(String),
}

impl Verdict {
    /// Construct a new Verdict at compile-time-checked schema version.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        event_id: impl Into<String>,
        action: Action,
        target_pid: u32,
        target_cgroup: impl Into<String>,
        target_container_id: impl Into<String>,
        target_binary_path: impl Into<String>,
        response_steps: Vec<StepResult>,
        ts_ms: u64,
        hostname: impl Into<String>,
        signer_kid_policy: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: event_id.into(),
            action,
            target_pid,
            target_cgroup: target_cgroup.into(),
            target_container_id: target_container_id.into(),
            target_binary_path: target_binary_path.into(),
            response_steps,
            ts_ms,
            hostname: hostname.into(),
            signer_kid_policy: signer_kid_policy.into(),
        }
    }

    /// Validate per MS044 R10481-R10485. Read-only; returns the first
    /// violation found.
    ///
    /// # Errors
    /// Returns `GuardianError` on schema drift, empty event_id, missing
    /// signer, empty hostname, zero timestamp, or empty response_steps.
    pub fn validate(&self) -> Result<(), GuardianError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(GuardianError::SchemaMismatch(self.schema_version.clone()));
        }
        if self.event_id.is_empty() {
            return Err(GuardianError::EmptyEventId);
        }
        if self.signer_kid_policy.is_empty() {
            return Err(GuardianError::EmptyPolicySigner);
        }
        if self.hostname.is_empty() {
            return Err(GuardianError::EmptyHostname);
        }
        if self.ts_ms == 0 {
            return Err(GuardianError::BadTimestamp);
        }
        if self.response_steps.is_empty() {
            return Err(GuardianError::EmptyResponseSteps);
        }
        Ok(())
    }

    /// Convenience: did the SIGKILL step succeed?
    #[must_use]
    pub fn sigkill_ok(&self) -> bool {
        self.response_steps
            .iter()
            .any(|s| s.step == ResponseStep::Sigkill && matches!(s.outcome, StepOutcome::Ok))
    }

    /// Convenience: did the audit append step succeed?
    #[must_use]
    pub fn audit_append_ok(&self) -> bool {
        self.response_steps
            .iter()
            .any(|s| s.step == ResponseStep::AuditAppend && matches!(s.outcome, StepOutcome::Ok))
    }

    /// Convenience: are ALL three response steps OK (no failures)?
    #[must_use]
    pub fn all_steps_ok(&self) -> bool {
        let mut have_sigkill = false;
        let mut have_audit = false;
        let mut have_console = false;
        for s in &self.response_steps {
            if !matches!(s.outcome, StepOutcome::Ok | StepOutcome::Skipped(_)) {
                return false;
            }
            match s.step {
                ResponseStep::Sigkill => have_sigkill = true,
                ResponseStep::AuditAppend => have_audit = true,
                ResponseStep::ConsoleAlert => have_console = true,
            }
        }
        have_sigkill && have_audit && have_console
    }

    /// Deserialize a Verdict from a JSON byte slice and validate it.
    ///
    /// # Errors
    /// Returns `GuardianError::Serde` on parse failure or any
    /// validation error from `validate()`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, GuardianError> {
        let v: Self = serde_json::from_slice(bytes)
            .map_err(|e| GuardianError::Serde(e.to_string()))?;
        v.validate()?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn three_step_ok() -> Vec<StepResult> {
        vec![
            StepResult { step: ResponseStep::Sigkill, outcome: StepOutcome::Ok },
            StepResult { step: ResponseStep::AuditAppend, outcome: StepOutcome::Ok },
            StepResult { step: ResponseStep::ConsoleAlert, outcome: StepOutcome::Ok },
        ]
    }

    fn sample() -> Verdict {
        Verdict::new(
            "evt-abc-123",
            Action::Sigkill,
            4242,
            "/system.slice/sshd.service",
            "",
            "/usr/bin/curl",
            three_step_ok(),
            1_700_000_000_000,
            "host-A",
            "kid-policy-1",
        )
    }

    #[test]
    fn valid_verdict_passes_validation() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = sample();
        v.schema_version = "9.9.9".into();
        assert!(matches!(v.validate().unwrap_err(), GuardianError::SchemaMismatch(_)));
    }

    #[test]
    fn empty_event_id_rejected() {
        let mut v = sample();
        v.event_id.clear();
        assert!(matches!(v.validate().unwrap_err(), GuardianError::EmptyEventId));
    }

    #[test]
    fn empty_signer_rejected() {
        let mut v = sample();
        v.signer_kid_policy.clear();
        assert!(matches!(v.validate().unwrap_err(), GuardianError::EmptyPolicySigner));
    }

    #[test]
    fn empty_hostname_rejected() {
        let mut v = sample();
        v.hostname.clear();
        assert!(matches!(v.validate().unwrap_err(), GuardianError::EmptyHostname));
    }

    #[test]
    fn zero_timestamp_rejected() {
        let mut v = sample();
        v.ts_ms = 0;
        assert!(matches!(v.validate().unwrap_err(), GuardianError::BadTimestamp));
    }

    #[test]
    fn empty_response_steps_rejected() {
        let mut v = sample();
        v.response_steps.clear();
        assert!(matches!(v.validate().unwrap_err(), GuardianError::EmptyResponseSteps));
    }

    #[test]
    fn sigkill_ok_convenience() {
        let v = sample();
        assert!(v.sigkill_ok());
        assert!(v.audit_append_ok());
        assert!(v.all_steps_ok());
    }

    #[test]
    fn all_steps_ok_false_on_step_failure() {
        let mut v = sample();
        v.response_steps[0].outcome = StepOutcome::Failed("podman daemon down".into());
        assert!(!v.all_steps_ok());
    }

    #[test]
    fn all_steps_ok_true_when_step_skipped() {
        let mut v = sample();
        v.response_steps[2].outcome = StepOutcome::Skipped("/dev/console not writable".into());
        // Skipped is still "OK" — operator-extended graceful path.
        assert!(v.all_steps_ok());
    }

    #[test]
    fn all_steps_ok_false_when_step_missing() {
        let mut v = sample();
        v.response_steps.truncate(2); // drop ConsoleAlert
        assert!(!v.all_steps_ok());
    }

    #[test]
    fn serde_roundtrip() {
        let v = sample();
        let j = serde_json::to_string(&v).expect("serialize");
        let back: Verdict = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(v, back);
    }

    #[test]
    fn from_json_validates_in_one_call() {
        let v = sample();
        let bytes = serde_json::to_vec(&v).unwrap();
        let parsed = Verdict::from_json(&bytes).expect("parse + validate");
        assert_eq!(parsed, v);
    }

    #[test]
    fn from_json_rejects_schema_drift() {
        let bad = r#"{"schema_version":"9.9.9","event_id":"e","action":"sigkill","target_pid":1,"target_cgroup":"/","target_container_id":"","target_binary_path":"/x","response_steps":[{"step":"sigkill","outcome":{"outcome":"ok"}}],"ts_ms":1,"hostname":"h","signer_kid_policy":"k"}"#;
        assert!(matches!(
            Verdict::from_json(bad.as_bytes()).unwrap_err(),
            GuardianError::SchemaMismatch(_)
        ));
    }

    #[test]
    fn action_serializes_kebab_case() {
        for (a, want) in &[
            (Action::Sigkill, "sigkill"),
            (Action::ProcessRelated, "process-related"),
            (Action::Other, "other"),
        ] {
            let j = serde_json::to_string(a).unwrap();
            assert_eq!(j, format!("\"{want}\""), "{a:?} serialized as {j}");
        }
    }

    #[test]
    fn response_step_serializes_kebab_case() {
        for (s, want) in &[
            (ResponseStep::Sigkill, "sigkill"),
            (ResponseStep::AuditAppend, "audit-append"),
            (ResponseStep::ConsoleAlert, "console-alert"),
        ] {
            let j = serde_json::to_string(s).unwrap();
            assert_eq!(j, format!("\"{want}\""));
        }
    }
}
