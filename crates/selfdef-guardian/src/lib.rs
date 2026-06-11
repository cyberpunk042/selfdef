//! `selfdef-guardian` — SDD-029 Deliverable 2: Guardian Daemon runtime
//! (sain-01 §10 `guardian-core` IPS-side implementation).
//!
//! Provides:
//! - [`TetragonEvent`] — typed JSON shape Tetragon emits on its UNIX
//!   socket (`/var/run/tetragon/tetragon.events`)
//! - [`classify`] — violation classifier (action == "SIGKILL" OR
//!   process-related per sain-01 §10 547-552)
//! - [`Responder`] — 3-step response orchestrator (SIGKILL → audit
//!   append → console alert)
//! - [`emit_ocsf_detection_2004`] — OCSF event emitter (atomic append,
//!   audit-chain linked)
//! - [`audit_chain_check`] — SHA-256 chain integrity verifier
//! - [`CircuitBreaker`] — back-pressure + same-target-flood guard
//!   (MS044 R10399-R10410)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use selfdef_guardian_mirror::{
    Action, GuardianError as MirrorError, ResponseStep, SCHEMA_VERSION, StepOutcome, StepResult,
    Verdict,
};

/// Default Tetragon UNIX-socket path.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/tetragon/tetragon.events";

/// Default ZFS audit log path (`tank/vault/context/security_audit.log`
/// mounted at `/mnt/vault/context/security_audit.log` per sain-01 §10
/// dump 531-533 + Trinity Genesis Auditor dump 981).
pub const DEFAULT_AUDIT_LOG_PATH: &str = "/mnt/vault/context/security_audit.log";

/// Default OCSF JSONL log (parallel to audit log for OCSF schema
/// consumers — Loki / OpenSearch sinks).
pub const DEFAULT_OCSF_PATH: &str = "/var/log/selfdef/guardian.ocsf.jsonl";

/// Default ring buffer directory (selfdef-cli + cockpit panel consumer).
pub const DEFAULT_RING_DIR: &str = "/var/cache/selfdef/guardian/ring";

/// Default console device for the BEL + diagnostic alert.
pub const DEFAULT_CONSOLE_PATH: &str = "/dev/console";

/// OCSF schema version for Detection 2004 events.
pub const OCSF_SCHEMA_VERSION: &str = "1.1.0";

/// Maximum SIGKILL-flood rate before the circuit breaker opens
/// (per-target). Per MS044 R10403.
pub const FLOOD_THRESHOLD_PER_TARGET: u32 = 5;

/// Time window (ms) for SIGKILL-flood detection. Per MS044 R10404.
pub const FLOOD_WINDOW_MS: u64 = 60_000;

/// Tetragon event shape — the subset Guardian needs from the UNIX
/// socket JSON stream. Tetragon emits richer schemas; this is the
/// minimal shape sain-01 §10 547-552 references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TetragonEvent {
    /// Event UUID (Tetragon-generated).
    #[serde(default)]
    pub event_id: String,
    /// Action string as Tetragon emits it ("SIGKILL", "Sigkill",
    /// "ProcessExec", "ProcessKprobe", etc.).
    #[serde(default)]
    pub action: String,
    /// PID of the target process (Tetragon's `process.pid`).
    #[serde(default)]
    pub pid: u32,
    /// Cgroup path.
    #[serde(default)]
    pub cgroup: String,
    /// Container id (Podman/runc/containerd).
    #[serde(default)]
    pub container_id: String,
    /// Path the target was trying to / did execute.
    #[serde(default)]
    pub binary_path: String,
    /// Event ts (ms epoch).
    #[serde(default)]
    pub ts_ms: u64,
}

/// Errors produced by the runtime crate.
#[derive(Debug, Error)]
pub enum GuardianError {
    /// Schema-version drift.
    #[error("schema version mismatch: expected {SCHEMA_VERSION}, got {0}")]
    SchemaMismatch(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(String),
    /// JSON parse / serialize error.
    #[error("serde_json: {0}")]
    Serde(String),
    /// Tetragon event classifier rejected the event (unknown / malformed).
    #[error("classifier: {0}")]
    Classifier(String),
    /// External command failure (podman kill / kill -9).
    #[error("command: {0}")]
    Command(String),
    /// OCSF audit chain integrity broken.
    #[error("audit chain break at line {line}: {detail}")]
    AuditChainBreak {
        /// Line number in the audit jsonl file.
        line: usize,
        /// What was wrong.
        detail: String,
    },
    /// Circuit breaker is open — Guardian is back-pressuring.
    #[error("circuit breaker open: {0}")]
    CircuitBreakerOpen(String),
}

/// Classify a Tetragon event into a Guardian [`Action`]. Maps the
/// raw action string per sain-01 §10 dump 547-552.
///
/// Sain-01 §10 spec: `if event["action"] == "SIGKILL" or "Process"
/// in event.get("type", "")` triggers the response. We implement that
/// rule literally.
#[must_use]
pub fn classify(event: &TetragonEvent) -> Action {
    let a = event.action.to_ascii_lowercase();
    if a == "sigkill" {
        Action::Sigkill
    } else if a.contains("process") {
        Action::ProcessRelated
    } else {
        Action::Other
    }
}

/// Whether an event should trigger Guardian's 3-step response.
#[must_use]
pub fn should_respond(action: Action) -> bool {
    matches!(action, Action::Sigkill | Action::ProcessRelated)
}

/// Trait for the external-effect surfaces Guardian uses, so unit tests
/// can stub them out (no real `podman kill`, no real writes to
/// `/dev/console`).
pub trait Effector {
    /// Send SIGKILL — `podman kill <container_id>` if container_id is
    /// non-empty, else `kill -9 <pid>` for host-scope.
    ///
    /// # Errors
    /// Returns an error if the underlying command spawn fails.
    fn sigkill(&self, target_pid: u32, container_id: &str) -> Result<(), String>;

    /// Atomic append a line to the audit log. Implementations MUST
    /// open with `O_APPEND` and `fsync` to disk before returning.
    ///
    /// # Errors
    /// Returns an error on I/O failure.
    fn append_audit_log(&self, audit_log: &Path, line: &str) -> Result<(), String>;

    /// Write a BEL + diagnostic line to the console.
    ///
    /// # Errors
    /// Returns an error if the device is not writable. Operators on
    /// hosts without `/dev/console` accessible expect this to fail
    /// gracefully (the Responder records it as `Skipped`, not `Failed`).
    fn console_alert(&self, console: &Path, message: &str) -> Result<(), String>;
}

/// Default Effector — real podman / kill / fs / console.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEffector;

impl Effector for RealEffector {
    fn sigkill(&self, target_pid: u32, container_id: &str) -> Result<(), String> {
        if !container_id.is_empty() {
            // Argument-injection guard (F-2026-123): `container_id` comes from a
            // Tetragon event (attacker-influenceable). `podman kill --all` / `-a`
            // kills EVERY container on the host, so a value like "--all" must
            // never be flag-parsed. A real container id/name never starts with
            // '-'; refuse it fail-closed, and pass `--` so any value is treated
            // as positional regardless.
            if container_id.starts_with('-') {
                return Err(format!(
                    "refusing container_id with leading '-' (possible argv injection, e.g. `podman kill --all`): {container_id:?}"
                ));
            }
            let st = Command::new("podman")
                .args(["kill", "--", container_id])
                .status()
                .map_err(|e| format!("spawn podman kill: {e}"))?;
            if !st.success() {
                return Err(format!("podman kill exit={st}"));
            }
            return Ok(());
        }
        if target_pid == 0 {
            return Err("target_pid=0 with empty container_id; nothing to kill".into());
        }
        if target_pid == 1 {
            // Backstop (the orchestrator already refuses pid <= 1 on the host
            // path): SIGKILL-ing init halts the host — never do it.
            return Err("refusing to SIGKILL pid 1 (init); would halt the host".into());
        }
        // Self-preservation (F-2026-122, guardian analog of F-2026-120): never
        // SIGKILL the guardian's OWN process. `target_pid` comes from a Tetragon
        // event (attacker-influenceable), so a crafted/misattributed event
        // naming the guardian's pid would otherwise make the supervisor kill
        // itself — tearing down the supervisor-tier containment + audit chain.
        if target_pid == std::process::id() {
            return Err("refusing to SIGKILL the guardian's own pid (self-preservation)".into());
        }
        let st = Command::new("kill")
            .args(["-9", &target_pid.to_string()])
            .status()
            .map_err(|e| format!("spawn kill -9: {e}"))?;
        if !st.success() {
            return Err(format!("kill -9 exit={st}"));
        }
        Ok(())
    }

    fn append_audit_log(&self, audit_log: &Path, line: &str) -> Result<(), String> {
        if let Some(parent) = audit_log.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_log)
            .map_err(|e| format!("open {}: {e}", audit_log.display()))?;
        writeln!(f, "{line}").map_err(|e| format!("write: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;
        Ok(())
    }

    fn console_alert(&self, console: &Path, message: &str) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(console)
            .map_err(|e| format!("open {}: {e}", console.display()))?;
        // Terminal-escape-injection guard (F-2026-124): `message` embeds
        // attacker-influenceable event fields (binary_path, cgroup, event_id),
        // and this writes to /dev/console — raw ANSI/control sequences there
        // could clear the screen, spoof the guardian's alert, or hide it. Strip
        // every control character from the message (the only intended control is
        // the `\x07` BEL prefix this function adds itself) before writing.
        let safe: String = message.chars().filter(|c| !c.is_control()).collect();
        writeln!(f, "\x07{safe}").map_err(|e| format!("write: {e}"))?;
        Ok(())
    }
}

/// 3-step response orchestrator. Executes Step1 → Step2 → Step3 in
/// order. Continues through step failures (records them) so the audit
/// trail always reflects every step the responder attempted.
pub struct Responder<E: Effector> {
    /// External-effect surface (real or test-stub).
    pub effector: E,
    /// Audit log destination.
    pub audit_log: PathBuf,
    /// Console device destination.
    pub console: PathBuf,
    /// Host identity for OCSF + audit log.
    pub hostname: String,
    /// MS003 policy signer kid.
    pub signer_kid_policy: String,
}

impl<E: Effector> Responder<E> {
    /// Construct a responder.
    #[must_use]
    pub fn new(
        effector: E,
        audit_log: PathBuf,
        console: PathBuf,
        hostname: impl Into<String>,
        signer_kid_policy: impl Into<String>,
    ) -> Self {
        Self {
            effector,
            audit_log,
            console,
            hostname: hostname.into(),
            signer_kid_policy: signer_kid_policy.into(),
        }
    }

    /// Execute the 3-step response. Returns a Verdict whose
    /// `response_steps` records each step's outcome.
    ///
    /// # Errors
    /// Returns `GuardianError::Serde` on audit-line serialization
    /// failure (rare; would mean the Verdict shape itself doesn't
    /// serialize).
    pub fn respond(&self, event: &TetragonEvent) -> Result<Verdict, GuardianError> {
        let action = classify(event);
        let mut steps = Vec::with_capacity(3);

        // Step 1 — SIGKILL. Never let the host path signal pid 0 or pid 1: `kill
        // 0` hits the responder's whole process group and SIGKILL-ing pid 1
        // (init) halts the machine, so a crafted or buggy Tetragon event must
        // not turn the guardian into a host-down switch. The container path is
        // unaffected — it kills a container, not a host pid.
        //
        // Self-preservation (F-2026-122): also refuse the guardian's OWN pid —
        // `event.pid` is attacker-influenceable, and SIGKILL-ing the guardian
        // tears down supervisor-tier containment + the audit chain. (Orchestrator
        // guard here + a backstop in RealEffector::sigkill, mirroring pid 1.)
        let self_pid = std::process::id();
        let sk_outcome = if event.container_id.is_empty()
            && (event.pid <= 1 || event.pid == self_pid)
        {
            StepOutcome::Skipped(format!(
                "refusing host SIGKILL of pid {} (init/invalid/self); would halt the host or the guardian",
                event.pid
            ))
        } else {
            match self.effector.sigkill(event.pid, &event.container_id) {
                Ok(()) => StepOutcome::Ok,
                Err(e) => StepOutcome::Failed(e),
            }
        };
        steps.push(StepResult {
            step: ResponseStep::Sigkill,
            outcome: sk_outcome,
        });

        // Step 2 — audit-log append (synthesized from event + step 1).
        let audit_line = serde_json::to_string(&serde_json::json!({
            "ts_ms": event.ts_ms,
            "hostname": self.hostname,
            "event_id": event.event_id,
            "action": event.action,
            "target_pid": event.pid,
            "target_container_id": event.container_id,
            "target_binary_path": event.binary_path,
            "target_cgroup": event.cgroup,
            "signer_kid_policy": self.signer_kid_policy,
        }))
        .map_err(|e| GuardianError::Serde(e.to_string()))?;
        let aa_outcome = match self.effector.append_audit_log(&self.audit_log, &audit_line) {
            Ok(()) => StepOutcome::Ok,
            Err(e) => StepOutcome::Failed(e),
        };
        steps.push(StepResult {
            step: ResponseStep::AuditAppend,
            outcome: aa_outcome,
        });

        // Step 3 — console alert.
        let message = format!(
            "[Guardian] SIGKILL pid={} cgroup={} binary={} event={}",
            event.pid, event.cgroup, event.binary_path, event.event_id
        );
        let ca_outcome = match self.effector.console_alert(&self.console, &message) {
            Ok(()) => StepOutcome::Ok,
            // Console-write failures are operator-extended Skipped on
            // hosts without /dev/console writable (e.g. unprivileged
            // containers); the audit trail still captures the attempt.
            Err(e) => {
                if e.contains("Permission denied") || e.contains("No such file") {
                    StepOutcome::Skipped(e)
                } else {
                    StepOutcome::Failed(e)
                }
            }
        };
        steps.push(StepResult {
            step: ResponseStep::ConsoleAlert,
            outcome: ca_outcome,
        });

        Ok(Verdict::new(
            event.event_id.clone(),
            action,
            event.pid,
            event.cgroup.clone(),
            event.container_id.clone(),
            event.binary_path.clone(),
            steps,
            if event.ts_ms == 0 {
                now_ms()
            } else {
                event.ts_ms
            },
            self.hostname.clone(),
            self.signer_kid_policy.clone(),
        ))
    }
}

/// Emit a single OCSF Detection 2004 event to the OCSF JSONL log.
///
/// Atomic append (O_APPEND opened per call); `prev_event_sha256` chained
/// from the last line of the existing file. Per MS044 R10441-R10470.
///
/// # Errors
/// Returns `GuardianError::Io` on file I/O failure,
/// `GuardianError::Serde` on serialization failure.
pub fn emit_ocsf_detection_2004(ocsf_jsonl: &Path, verdict: &Verdict) -> Result<(), GuardianError> {
    if let Some(parent) = ocsf_jsonl.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| GuardianError::Io(e.to_string()))?;
        }
    }
    let prev_sha = last_line_sha256(ocsf_jsonl)?;
    let all_ok = verdict.all_steps_ok();
    let (activity_id, severity_id, status_id) = if all_ok {
        (1u32, 4u32, 1u32)
    } else {
        (3u32, 5u32, 2u32)
    };
    let event = serde_json::json!({
        "metadata": {
            "version": OCSF_SCHEMA_VERSION,
            "product": { "name": "selfdef-guardian", "vendor_name": "selfdef" },
            "log_name": "guardian",
        },
        "category_uid": 2u32,
        "class_uid": 2004u32,
        "class_name": "Detection Finding",
        "type_uid": 2004u32 * 100 + activity_id,
        "activity_id": activity_id,
        "severity_id": severity_id,
        "status_id": status_id,
        "time": verdict.ts_ms,
        "device": { "hostname": verdict.hostname },
        "process": {
            "pid": verdict.target_pid,
            "file": { "path": verdict.target_binary_path },
            "container": { "id": verdict.target_container_id },
            "cgroup": verdict.target_cgroup,
        },
        "guardian_event_id": verdict.event_id,
        "guardian_action": verdict.action,
        "guardian_steps": verdict.response_steps,
        "policy_signer_kid": verdict.signer_kid_policy,
        "schema_version": verdict.schema_version,
        "prev_event_sha256": prev_sha,
    });
    let line = serde_json::to_string(&event).map_err(|e| GuardianError::Serde(e.to_string()))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ocsf_jsonl)
        .map_err(|e| GuardianError::Io(e.to_string()))?;
    writeln!(f, "{line}").map_err(|e| GuardianError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| GuardianError::Io(e.to_string()))?;
    Ok(())
}

fn last_line_sha256(path: &Path) -> Result<Option<String>, GuardianError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| GuardianError::Io(e.to_string()))?;
    let last = text.lines().filter(|l| !l.trim().is_empty()).next_back();
    match last {
        None => Ok(None),
        Some(line) => {
            let mut h = Sha256::new();
            h.update(line.as_bytes());
            Ok(Some(format!("{:x}", h.finalize())))
        }
    }
}

/// Verify the OCSF audit chain integrity. Per MS044 R10470.
///
/// # Errors
/// Returns `GuardianError::AuditChainBreak` on chain break, malformed
/// JSON, or missing prev_event_sha256 on non-first event.
pub fn audit_chain_check(ocsf_jsonl: &Path) -> Result<usize, GuardianError> {
    if !ocsf_jsonl.exists() {
        return Ok(0);
    }
    let text = fs::read_to_string(ocsf_jsonl).map_err(|e| GuardianError::Io(e.to_string()))?;
    let mut last_sha: Option<String> = None;
    let mut events = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).map_err(|e| GuardianError::AuditChainBreak {
                line: idx + 1,
                detail: format!("malformed JSON: {e}"),
            })?;
        let claimed_prev = parsed
            .get("prev_event_sha256")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        match (&last_sha, claimed_prev.as_deref()) {
            (Some(want), Some(got)) if got != want => {
                return Err(GuardianError::AuditChainBreak {
                    line: idx + 1,
                    detail: format!("prev_event_sha256={got}, expected {want}"),
                });
            }
            (Some(_), None) => {
                return Err(GuardianError::AuditChainBreak {
                    line: idx + 1,
                    detail: "prev_event_sha256 missing from non-first event".into(),
                });
            }
            (None, Some(got)) => {
                // First event of the file. `emit_ocsf_detection_2004` always
                // writes a null prev for the opening event (last_line_sha256
                // returns None on an empty file), so a first line that claims a
                // predecessor means the genuine opening events were deleted —
                // prefix/head truncation. A pure forward walk would accept it;
                // flag it as a chain break.
                return Err(GuardianError::AuditChainBreak {
                    line: idx + 1,
                    detail: format!(
                        "first event claims predecessor prev_event_sha256={got} (head truncated)"
                    ),
                });
            }
            _ => {}
        }
        let mut h = Sha256::new();
        h.update(line.as_bytes());
        last_sha = Some(format!("{:x}", h.finalize()));
        events += 1;
    }
    Ok(events)
}

/// Same-target flood guard — circuit breaker. Per MS044 R10399-R10410.
///
/// Tracks per-target SIGKILL counts in a sliding window. When a target
/// (identified by pid or container_id) exceeds [`FLOOD_THRESHOLD_PER_TARGET`]
/// SIGKILLs in [`FLOOD_WINDOW_MS`], the breaker opens for that target —
/// further responds() short-circuit with [`GuardianError::CircuitBreakerOpen`].
///
/// Breaker auto-resets after the window slides past.
#[derive(Debug, Default)]
pub struct CircuitBreaker {
    history: HashMap<String, Vec<u64>>,
}

impl CircuitBreaker {
    /// Construct an empty breaker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a SIGKILL attempt at `now_ms` against `target_key`. The
    /// target_key is `<container_id>` if non-empty else `pid:<pid>`.
    /// Returns Ok(()) if the attempt is allowed, Err(CircuitBreakerOpen)
    /// if flood-threshold exceeded.
    ///
    /// # Errors
    /// Returns `GuardianError::CircuitBreakerOpen` when the per-target
    /// count in the current window exceeds [`FLOOD_THRESHOLD_PER_TARGET`].
    pub fn record(&mut self, target_key: &str, now_ms: u64) -> Result<(), GuardianError> {
        let v = self.history.entry(target_key.to_string()).or_default();
        // Slide the window: drop entries older than now - FLOOD_WINDOW_MS.
        let cutoff = now_ms.saturating_sub(FLOOD_WINDOW_MS);
        v.retain(|&t| t > cutoff);
        if v.len() as u32 >= FLOOD_THRESHOLD_PER_TARGET {
            return Err(GuardianError::CircuitBreakerOpen(format!(
                "target {target_key:?} exceeded {FLOOD_THRESHOLD_PER_TARGET} SIGKILLs in {FLOOD_WINDOW_MS}ms"
            )));
        }
        v.push(now_ms);
        Ok(())
    }

    /// Compute the per-target key Guardian uses (container_id preferred).
    #[must_use]
    pub fn target_key(container_id: &str, pid: u32) -> String {
        if container_id.is_empty() {
            format!("pid:{pid}")
        } else {
            container_id.to_string()
        }
    }
}

/// Current wall-clock as epoch ms.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Read the Guardian ring buffer directory into Verdicts (newest-first).
/// Returns empty vec on missing dir.
///
/// # Errors
/// Returns `GuardianError::Io` on read failure of an existing dir.
pub fn read_ring_buffer(ring: &Path) -> Result<Vec<Verdict>, GuardianError> {
    if !ring.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Verdict> = Vec::new();
    for dirent in fs::read_dir(ring).map_err(|e| GuardianError::Io(e.to_string()))? {
        let dirent = dirent.map_err(|e| GuardianError::Io(e.to_string()))?;
        let path = dirent.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(v) = serde_json::from_slice::<Verdict>(&bytes) {
            if v.validate().is_ok() {
                out.push(v);
            }
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.ts_ms));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use tempfile::TempDir;

    /// Test stub for Effector — records every call, can be configured
    /// to return errors for specific steps.
    #[derive(Default)]
    struct StubEffector {
        sigkills: Rc<RefCell<Vec<(u32, String)>>>,
        audit_writes: Rc<RefCell<Vec<String>>>,
        console_writes: Rc<RefCell<Vec<String>>>,
        fail_sigkill: bool,
        skip_console: bool,
    }

    impl Effector for StubEffector {
        fn sigkill(&self, pid: u32, cid: &str) -> Result<(), String> {
            self.sigkills.borrow_mut().push((pid, cid.to_string()));
            if self.fail_sigkill {
                return Err("stub failure".into());
            }
            Ok(())
        }
        fn append_audit_log(&self, _audit: &Path, line: &str) -> Result<(), String> {
            self.audit_writes.borrow_mut().push(line.to_string());
            Ok(())
        }
        fn console_alert(&self, _console: &Path, m: &str) -> Result<(), String> {
            if self.skip_console {
                return Err("No such file or directory (os error 2)".into());
            }
            self.console_writes.borrow_mut().push(m.to_string());
            Ok(())
        }
    }

    fn sample_event() -> TetragonEvent {
        TetragonEvent {
            event_id: "evt-1".into(),
            action: "SIGKILL".into(),
            pid: 4242,
            cgroup: "/system.slice/sshd.service".into(),
            container_id: String::new(),
            binary_path: "/usr/bin/curl".into(),
            ts_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn classify_sigkill() {
        let mut e = sample_event();
        e.action = "SIGKILL".into();
        assert_eq!(classify(&e), Action::Sigkill);
        e.action = "Sigkill".into();
        assert_eq!(classify(&e), Action::Sigkill);
        e.action = "sigkill".into();
        assert_eq!(classify(&e), Action::Sigkill);
    }

    #[test]
    fn classify_process_related() {
        let mut e = sample_event();
        e.action = "ProcessExec".into();
        assert_eq!(classify(&e), Action::ProcessRelated);
        e.action = "ProcessKprobe".into();
        assert_eq!(classify(&e), Action::ProcessRelated);
    }

    #[test]
    fn classify_other() {
        let mut e = sample_event();
        e.action = "NetworkConnect".into();
        assert_eq!(classify(&e), Action::Other);
    }

    #[test]
    fn should_respond_sigkill_and_process_related() {
        assert!(should_respond(Action::Sigkill));
        assert!(should_respond(Action::ProcessRelated));
        assert!(!should_respond(Action::Other));
    }

    fn make_responder<E: Effector>(eff: E, dir: &TempDir) -> Responder<E> {
        Responder::new(
            eff,
            dir.path().join("audit.log"),
            dir.path().join("console"),
            "host-A",
            "kid-policy-1",
        )
    }

    #[test]
    fn respond_writes_three_steps_on_clean_path() {
        let dir = TempDir::new().unwrap();
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        let v = r.respond(&sample_event()).unwrap();
        assert_eq!(v.response_steps.len(), 3);
        assert!(v.all_steps_ok());
        assert!(v.sigkill_ok());
        assert!(v.audit_append_ok());
    }

    #[test]
    fn respond_refuses_host_sigkill_of_pid_1() {
        // A Tetragon event targeting pid 1 with no container scope must never
        // reach `kill -9 1` — SIGKILL-ing init halts the host. The sibling
        // responder (SigtermProcess) and apparmor backend both guard pid 1.
        let dir = TempDir::new().unwrap();
        let sigkills = Rc::new(RefCell::new(Vec::new()));
        let eff = StubEffector {
            sigkills: sigkills.clone(),
            ..StubEffector::default()
        };
        let r = make_responder(eff, &dir);
        let mut ev = sample_event();
        ev.pid = 1;
        ev.container_id = String::new();
        ev.action = "ProcessExec".into();
        let v = r.respond(&ev).unwrap();
        // The effector was never asked to kill pid 1.
        assert!(
            sigkills.borrow().is_empty(),
            "must not invoke kill on host pid 1"
        );
        // Recorded as a safety Skipped, not Ok; audit/console still run.
        assert!(matches!(
            v.response_steps[0].outcome,
            StepOutcome::Skipped(_)
        ));
        assert!(!v.sigkill_ok());
        assert!(v.audit_append_ok());

        // The container path is unaffected — it kills a container, not host pid 1.
        let sigkills2 = Rc::new(RefCell::new(Vec::new()));
        let eff2 = StubEffector {
            sigkills: sigkills2.clone(),
            ..StubEffector::default()
        };
        let r2 = make_responder(eff2, &dir);
        let mut ev2 = sample_event();
        ev2.pid = 1;
        ev2.container_id = "abc123".into();
        let _ = r2.respond(&ev2).unwrap();
        assert_eq!(
            sigkills2.borrow().len(),
            1,
            "container-scoped kill still proceeds"
        );
    }

    #[test]
    fn respond_refuses_host_sigkill_of_guardians_own_pid() {
        // F-2026-122 self-preservation: a Tetragon event naming the guardian's
        // OWN pid (host-scoped) must never reach `kill -9 <self>` — that would
        // tear down the supervisor. event.pid is attacker-influenceable.
        let dir = TempDir::new().unwrap();
        let sigkills = Rc::new(RefCell::new(Vec::new()));
        let eff = StubEffector {
            sigkills: sigkills.clone(),
            ..StubEffector::default()
        };
        let r = make_responder(eff, &dir);
        let mut ev = sample_event();
        ev.pid = std::process::id();
        ev.container_id = String::new();
        ev.action = "ProcessExec".into();
        let v = r.respond(&ev).unwrap();
        assert!(
            sigkills.borrow().is_empty(),
            "must not invoke kill on the guardian's own pid"
        );
        assert!(matches!(v.response_steps[0].outcome, StepOutcome::Skipped(_)));
        assert!(!v.sigkill_ok());
        // Audit + console still run (the threat is recorded, just not self-killed).
        assert!(v.audit_append_ok());
    }

    #[test]
    fn respond_records_sigkill_failure_continues_to_step_2_and_3() {
        let dir = TempDir::new().unwrap();
        let eff = StubEffector {
            fail_sigkill: true,
            ..StubEffector::default()
        };
        let r = make_responder(eff, &dir);
        let v = r.respond(&sample_event()).unwrap();
        assert_eq!(v.response_steps.len(), 3);
        assert!(!v.sigkill_ok());
        assert!(v.audit_append_ok()); // step 2 still ran
        assert!(matches!(
            v.response_steps[0].outcome,
            StepOutcome::Failed(_)
        ));
    }

    #[test]
    fn respond_treats_no_console_as_skipped_not_failed() {
        let dir = TempDir::new().unwrap();
        let eff = StubEffector {
            skip_console: true,
            ..StubEffector::default()
        };
        let r = make_responder(eff, &dir);
        let v = r.respond(&sample_event()).unwrap();
        assert!(matches!(
            v.response_steps[2].outcome,
            StepOutcome::Skipped(_)
        ));
        // all_steps_ok treats Skipped as still OK (operator-extended).
        assert!(v.all_steps_ok());
    }

    #[test]
    fn respond_validates_resulting_verdict() {
        let dir = TempDir::new().unwrap();
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        let v = r.respond(&sample_event()).unwrap();
        assert!(v.validate().is_ok());
    }

    #[test]
    fn respond_substitutes_now_ms_when_event_ts_zero() {
        let dir = TempDir::new().unwrap();
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        let mut e = sample_event();
        e.ts_ms = 0;
        let v = r.respond(&e).unwrap();
        assert!(v.ts_ms > 0);
    }

    #[test]
    fn real_effector_append_audit_log_writes_and_fsyncs() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("a.log");
        let eff = RealEffector;
        eff.append_audit_log(&log, "line1").unwrap();
        eff.append_audit_log(&log, "line2").unwrap();
        let text = fs::read_to_string(&log).unwrap();
        assert_eq!(text, "line1\nline2\n");
    }

    #[test]
    fn real_effector_audit_log_creates_parent() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("nested/deeply/a.log");
        RealEffector.append_audit_log(&log, "x").unwrap();
        assert!(log.exists());
    }

    #[test]
    fn real_effector_console_alert_strips_terminal_escapes() {
        // F-2026-124: attacker-influenced event fields flow into the console
        // message; ANSI/control sequences must be stripped before reaching
        // /dev/console (here a tempfile), leaving only the intended BEL prefix.
        let dir = TempDir::new().unwrap();
        let console = dir.path().join("console");
        std::fs::File::create(&console).unwrap(); // console_alert opens, doesn't create
        RealEffector
            .console_alert(&console, "[Guardian] binary=\x1b[2J\x1b[Hspoofed\x07\r evt=1")
            .unwrap();
        let written = fs::read_to_string(&console).unwrap();
        // Only the leading BEL this function adds + a trailing newline are control
        // chars; the injected ESC / BEL / CR from the message are gone.
        assert!(written.starts_with('\x07'), "BEL prefix kept: {written:?}");
        assert!(!written.contains('\x1b'), "ESC must be stripped: {written:?}");
        assert!(!written.contains('\r'), "CR must be stripped: {written:?}");
        assert_eq!(
            written.matches('\x07').count(),
            1,
            "only the prefix BEL, not the injected one: {written:?}"
        );
        assert!(written.contains("spoofed"), "printable text preserved");
    }

    #[test]
    fn real_effector_refuses_flag_like_container_id() {
        // F-2026-123: a Tetragon event with container_id="--all" must NOT become
        // `podman kill --all` (mass container kill). The guard returns Err BEFORE
        // spawning podman, so this is safe to assert without a container runtime.
        for bad in ["--all", "-a", "--filter=x"] {
            let err = RealEffector
                .sigkill(0, bad)
                .expect_err("flag-like container_id must be refused");
            assert!(err.contains("argv injection"), "err for {bad:?}: {err}");
        }
    }

    #[test]
    fn emit_ocsf_chains_prev_sha256() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        let v = r.respond(&sample_event()).unwrap();
        emit_ocsf_detection_2004(&path, &v).unwrap();
        emit_ocsf_detection_2004(&path, &v).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let l2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let prev = l2["prev_event_sha256"].as_str().expect("chained");
        let mut h = Sha256::new();
        h.update(lines[0].as_bytes());
        assert_eq!(prev, format!("{:x}", h.finalize()));
    }

    #[test]
    fn emit_ocsf_severity_keyed_on_all_steps_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let eff_fail = StubEffector {
            fail_sigkill: true,
            ..StubEffector::default()
        };
        let r = make_responder(eff_fail, &dir);
        let v = r.respond(&sample_event()).unwrap();
        emit_ocsf_detection_2004(&path, &v).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        // Step1 failed → severity_id=5 (critical), status_id=2.
        assert_eq!(parsed["severity_id"].as_u64(), Some(5));
        assert_eq!(parsed["status_id"].as_u64(), Some(2));
    }

    #[test]
    fn audit_chain_check_clean_pass() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        for i in 0..3u32 {
            let mut e = sample_event();
            e.event_id = format!("evt-{i}");
            e.ts_ms += u64::from(i);
            let v = r.respond(&e).unwrap();
            emit_ocsf_detection_2004(&path, &v).unwrap();
        }
        let n = audit_chain_check(&path).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn audit_chain_check_detects_break() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let l1 = r#"{"class_uid":2004}"#;
        let l2 = r#"{"class_uid":2004,"prev_event_sha256":"bogus"}"#;
        fs::write(&path, format!("{l1}\n{l2}\n")).unwrap();
        let err = audit_chain_check(&path).unwrap_err();
        assert!(matches!(
            err,
            GuardianError::AuditChainBreak { line: 2, .. }
        ));
    }

    #[test]
    fn audit_chain_check_detects_head_truncation() {
        // A legitimate chain's first event carries a null prev. If the genuine
        // opening events are deleted, the new first line still claims a real
        // predecessor hash referencing a now-absent line. A forward-only walk
        // would accept it; the chain check must flag a first event that claims
        // a predecessor as a break (prefix-deletion tamper).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.jsonl");
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        for i in 0..3u32 {
            let mut e = sample_event();
            e.event_id = format!("evt-{i}");
            e.ts_ms += u64::from(i);
            let v = r.respond(&e).unwrap();
            emit_ocsf_detection_2004(&path, &v).unwrap();
        }
        assert_eq!(audit_chain_check(&path).unwrap(), 3);
        // Drop the genuine first event; the orphaned tail now opens with a line
        // that claims a predecessor.
        let text = fs::read_to_string(&path).unwrap();
        let tail: String = text.lines().skip(1).collect::<Vec<_>>().join("\n");
        fs::write(&path, format!("{tail}\n")).unwrap();
        let err = audit_chain_check(&path).unwrap_err();
        assert!(
            matches!(err, GuardianError::AuditChainBreak { line: 1, .. }),
            "head-truncated chain must break at line 1, got {err:?}"
        );
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let mut cb = CircuitBreaker::new();
        for i in 0..FLOOD_THRESHOLD_PER_TARGET {
            cb.record("container-1", 1_000 + u64::from(i)).unwrap();
        }
        // Next record should error.
        let err = cb.record("container-1", 1_010).unwrap_err();
        assert!(matches!(err, GuardianError::CircuitBreakerOpen(_)));
    }

    #[test]
    fn circuit_breaker_resets_after_window() {
        let mut cb = CircuitBreaker::new();
        for i in 0..FLOOD_THRESHOLD_PER_TARGET {
            cb.record("container-1", 1_000 + u64::from(i)).unwrap();
        }
        // Slide past the window.
        let later = 1_000 + FLOOD_WINDOW_MS + 1;
        assert!(cb.record("container-1", later).is_ok());
    }

    #[test]
    fn circuit_breaker_per_target_independent() {
        let mut cb = CircuitBreaker::new();
        for i in 0..FLOOD_THRESHOLD_PER_TARGET {
            cb.record("container-1", 1_000 + u64::from(i)).unwrap();
        }
        // container-2 is fresh.
        assert!(cb.record("container-2", 1_010).is_ok());
    }

    #[test]
    fn target_key_prefers_container_id() {
        assert_eq!(CircuitBreaker::target_key("abc", 42), "abc");
        assert_eq!(CircuitBreaker::target_key("", 42), "pid:42");
    }

    #[test]
    fn read_ring_buffer_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let v = read_ring_buffer(&dir.path().join("nope")).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn read_ring_buffer_newest_first() {
        let dir = TempDir::new().unwrap();
        let ring = dir.path().join("ring");
        fs::create_dir_all(&ring).unwrap();
        let eff = StubEffector::default();
        let r = make_responder(eff, &dir);
        for (name, ts) in [("a", 100_u64), ("b", 300), ("c", 200)] {
            let mut e = sample_event();
            e.event_id = name.into();
            e.ts_ms = ts;
            let v = r.respond(&e).unwrap();
            fs::write(
                ring.join(format!("{name}.json")),
                serde_json::to_vec(&v).unwrap(),
            )
            .unwrap();
        }
        let out = read_ring_buffer(&ring).unwrap();
        let ts: Vec<u64> = out.iter().map(|v| v.ts_ms).collect();
        assert_eq!(ts, vec![300, 200, 100]);
    }
}
