//! Built-in [`Action`] implementations.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_notifier::{Notifier, NotifierError};
use thiserror::Error;
use tokio::process::Command;
use tracing::debug;

// Bound the size of best-effort log captures so a bundle can't blow up the
// disk on a noisy host.
const DMESG_TAIL_LINES: usize = 2_000;
const JOURNAL_TAIL_LINES: usize = 2_000;

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("notify failed: {0}")]
    Notify(#[from] NotifierError),
    #[error("exec failed: {0}")]
    Exec(String),
}

/// Outcome of a single action attempt.
#[derive(Debug)]
pub struct ActionOutcome {
    pub status: Status,
    pub notes: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Success,
    DryRun,
    /// Action wasn't applicable to this event (e.g. no pid available).
    Skipped,
}

impl ActionOutcome {
    pub fn ok(notes: impl Into<String>) -> Self {
        Self {
            status: Status::Success,
            notes: notes.into(),
        }
    }
    pub fn dry_run(notes: impl Into<String>) -> Self {
        Self {
            status: Status::DryRun,
            notes: notes.into(),
        }
    }
    pub fn skipped(notes: impl Into<String>) -> Self {
        Self {
            status: Status::Skipped,
            notes: notes.into(),
        }
    }
}

#[async_trait]
pub trait Action: Send + Sync {
    fn name(&self) -> &'static str;
    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError>;
}

fn pid_from_event(event: &Event) -> Option<i32> {
    event
        .actor
        .as_ref()
        .and_then(|a| a.process.as_ref())
        .map(|p| p.pid)
        .or_else(|| event.process.as_ref().map(|p| p.pid))
        .filter(|p| *p > 0)
}

// ================================================================ NotifyAction

pub struct NotifyAction {
    notifier: Arc<dyn Notifier>,
}

impl NotifyAction {
    pub fn new(notifier: Arc<dyn Notifier>) -> Self {
        Self { notifier }
    }
}

#[async_trait]
impl Action for NotifyAction {
    fn name(&self) -> &'static str {
        "notify"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        if dry_run {
            let summary = event.message.as_deref().unwrap_or("(no message)");
            return Ok(ActionOutcome::dry_run(format!("would notify: {summary}")));
        }
        self.notifier.notify(event).await?;
        Ok(ActionOutcome::ok("notified"))
    }
}

// ============================================================= SnapshotProcAction

pub struct SnapshotProcAction {
    /// Directory under which per-event subdirs are created.
    snapshot_dir: PathBuf,
}

impl SnapshotProcAction {
    pub fn new(snapshot_dir: PathBuf) -> Self {
        Self { snapshot_dir }
    }
}

#[async_trait]
impl Action for SnapshotProcAction {
    fn name(&self) -> &'static str {
        "snapshot_proc"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped("no actor pid available"));
        };

        let dir = self.snapshot_dir.join(event.id.to_string());

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would snapshot pid {pid} to {}",
                dir.display()
            )));
        }

        tokio::fs::create_dir_all(&dir).await?;

        // Best-effort reads — some files may be unreadable depending on PID
        // ownership. We don't propagate per-file errors.
        let proc_root = format!("/proc/{pid}");
        for source in ["cmdline", "environ", "status", "maps", "stat", "io"] {
            let src = format!("{proc_root}/{source}");
            if let Ok(content) = tokio::fs::read(&src).await {
                let _ = tokio::fs::write(dir.join(source), content).await;
            }
        }
        // exe symlink — record its target as text.
        if let Ok(target) = tokio::fs::read_link(format!("{proc_root}/exe")).await {
            let _ =
                tokio::fs::write(dir.join("exe_link"), target.to_string_lossy().as_bytes()).await;
        }
        // cwd symlink — same treatment.
        if let Ok(target) = tokio::fs::read_link(format!("{proc_root}/cwd")).await {
            let _ =
                tokio::fs::write(dir.join("cwd_link"), target.to_string_lossy().as_bytes()).await;
        }

        Ok(ActionOutcome::ok(format!(
            "snapshotted pid {pid} → {}",
            dir.display()
        )))
    }
}

// ============================================================= KillPidAction

pub struct KillPidAction;

impl KillPidAction {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KillPidAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for KillPidAction {
    fn name(&self) -> &'static str {
        "kill_pid"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped("no actor pid available"));
        };

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!("would SIGTERM pid {pid}")));
        }

        let output = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output()
            .await?;
        if output.status.success() {
            Ok(ActionOutcome::ok(format!("SIGTERM sent to pid {pid}")))
        } else {
            Err(ActionError::Exec(format!(
                "kill exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

// ============================================================= LockdownEgressAction

pub struct LockdownEgressAction {
    script: PathBuf,
}

impl LockdownEgressAction {
    pub fn new(script: PathBuf) -> Self {
        Self { script }
    }
}

#[async_trait]
impl Action for LockdownEgressAction {
    fn name(&self) -> &'static str {
        "lockdown_egress"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would invoke {} activate",
                self.script.display()
            )));
        }
        debug!(event_id = %event.id, script = %self.script.display(), "activating egress lockdown");
        let output = Command::new(&self.script).arg("activate").output().await?;
        if output.status.success() {
            Ok(ActionOutcome::ok("egress locked down"))
        } else {
            Err(ActionError::Exec(format!(
                "lockdown script exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

// ============================================================= RevokeSessionAction

pub struct RevokeSessionAction {
    script: PathBuf,
}

impl RevokeSessionAction {
    pub fn new(script: PathBuf) -> Self {
        Self { script }
    }
}

#[async_trait]
impl Action for RevokeSessionAction {
    fn name(&self) -> &'static str {
        "revoke_session"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let user = event
            .actor
            .as_ref()
            .and_then(|a| a.user.as_ref())
            .and_then(|u| u.name.clone());
        let Some(user) = user else {
            return Ok(ActionOutcome::skipped("no actor user name"));
        };

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would invoke {} {user}",
                self.script.display()
            )));
        }

        let output = Command::new(&self.script).arg(&user).output().await?;
        if output.status.success() {
            Ok(ActionOutcome::ok(format!("revoked sessions for {user}")))
        } else {
            Err(ActionError::Exec(format!(
                "revoke script exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

// ============================================================= ForensicsBundleAction

/// Collects a forensic snapshot of the host into
/// `forensics_dir/<event-uuid>/`. Best-effort: per-file errors are swallowed
/// and recorded in `manifest.txt`. Designed to run on **any** Critical
/// finding (not just one with a pid) — system state has standalone value.
///
/// Files in the bundle:
/// - `event.json` — the triggering event
/// - `uname`, `os-release`, `proc-version`, `proc-cmdline`, `uptime`
/// - `mounts`, `modules`, `passwd`, `group`
/// - `net-tcp`, `net-udp`, `ss-tnap`
/// - `dmesg` (last `DMESG_TAIL_LINES`), `journalctl` (last
///   `JOURNAL_TAIL_LINES`)
/// - `proc/<pid>/{cmdline,environ,status,maps,stat,io,exe_link,cwd_link,fd}`
///   when the event carries an actor pid
/// - `manifest.txt` — list of artifacts captured plus any per-file errors
pub struct ForensicsBundleAction {
    forensics_dir: PathBuf,
}

impl ForensicsBundleAction {
    pub fn new(forensics_dir: PathBuf) -> Self {
        Self { forensics_dir }
    }
}

#[async_trait]
impl Action for ForensicsBundleAction {
    fn name(&self) -> &'static str {
        "forensics_bundle"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let dir = self.forensics_dir.join(event.id.to_string());

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would write forensics bundle to {}",
                dir.display()
            )));
        }

        tokio::fs::create_dir_all(&dir).await?;
        let mut manifest: Vec<String> = Vec::new();

        // Triggering event — always available, always recorded.
        match serde_json::to_vec_pretty(event) {
            Ok(bytes) => {
                if let Err(e) = tokio::fs::write(dir.join("event.json"), &bytes).await {
                    manifest.push(format!("event.json ERR {e}"));
                } else {
                    manifest.push(format!("event.json {} bytes", bytes.len()));
                }
            }
            Err(e) => manifest.push(format!("event.json SERIALIZE-ERR {e}")),
        }

        // /proc and /etc snapshots — best effort, missing files are normal on
        // minimal containers and aren't an error.
        let static_sources: &[(&str, &str)] = &[
            ("os-release", "/etc/os-release"),
            ("proc-version", "/proc/version"),
            ("proc-cmdline", "/proc/cmdline"),
            ("uptime", "/proc/uptime"),
            ("mounts", "/proc/mounts"),
            ("modules", "/proc/modules"),
            ("passwd", "/etc/passwd"),
            ("group", "/etc/group"),
            ("net-tcp", "/proc/net/tcp"),
            ("net-udp", "/proc/net/udp"),
        ];
        for (dest, src) in static_sources {
            match tokio::fs::read(src).await {
                Ok(content) => {
                    let _ = tokio::fs::write(dir.join(dest), &content).await;
                    manifest.push(format!("{dest} {} bytes", content.len()));
                }
                Err(e) => manifest.push(format!("{dest} SKIP ({e})")),
            }
        }

        // External tools — invoked best-effort. Output captured even on
        // nonzero exit codes (useful for forensics: a failing command is
        // also a data point).
        for (dest, prog, args) in [
            ("uname", "uname", vec!["-a"]),
            ("ss-tnap", "ss", vec!["-tnap"]),
        ] {
            match Command::new(prog).args(&args).output().await {
                Ok(output) => {
                    let _ = tokio::fs::write(dir.join(dest), &output.stdout).await;
                    manifest.push(format!(
                        "{dest} {} bytes (exit {:?})",
                        output.stdout.len(),
                        output.status.code()
                    ));
                }
                Err(e) => manifest.push(format!("{dest} SKIP ({e})")),
            }
        }

        // dmesg — kernel ring buffer tail.
        match Command::new("dmesg").arg("--ctime").output().await {
            Ok(output) => {
                let tail = tail_lines(&output.stdout, DMESG_TAIL_LINES);
                let _ = tokio::fs::write(dir.join("dmesg"), &tail).await;
                manifest.push(format!("dmesg {} bytes", tail.len()));
            }
            Err(e) => manifest.push(format!("dmesg SKIP ({e})")),
        }

        // journalctl — recent system journal.
        match Command::new("journalctl")
            .args(["-n", &JOURNAL_TAIL_LINES.to_string(), "--no-pager"])
            .output()
            .await
        {
            Ok(output) => {
                let _ = tokio::fs::write(dir.join("journalctl"), &output.stdout).await;
                manifest.push(format!("journalctl {} bytes", output.stdout.len()));
            }
            Err(e) => manifest.push(format!("journalctl SKIP ({e})")),
        }

        // Per-pid snapshot if an actor pid is attached.
        if let Some(pid) = pid_from_event(event) {
            let proc_dir = dir.join("proc");
            let _ = tokio::fs::create_dir_all(&proc_dir).await;
            let proc_root = format!("/proc/{pid}");
            for source in ["cmdline", "environ", "status", "maps", "stat", "io"] {
                let src = format!("{proc_root}/{source}");
                match tokio::fs::read(&src).await {
                    Ok(content) => {
                        let _ = tokio::fs::write(proc_dir.join(source), &content).await;
                        manifest.push(format!("proc/{source} {} bytes", content.len()));
                    }
                    Err(e) => manifest.push(format!("proc/{source} SKIP ({e})")),
                }
            }
            if let Ok(target) = tokio::fs::read_link(format!("{proc_root}/exe")).await {
                let s = target.to_string_lossy().into_owned();
                let _ = tokio::fs::write(proc_dir.join("exe_link"), s.as_bytes()).await;
                manifest.push(format!("proc/exe_link {} bytes", s.len()));
            }
            if let Ok(target) = tokio::fs::read_link(format!("{proc_root}/cwd")).await {
                let s = target.to_string_lossy().into_owned();
                let _ = tokio::fs::write(proc_dir.join("cwd_link"), s.as_bytes()).await;
                manifest.push(format!("proc/cwd_link {} bytes", s.len()));
            }
            // fd table listing (names only — descriptors themselves point at
            // sensitive sockets/files and are noisy).
            if let Ok(mut rd) = tokio::fs::read_dir(format!("{proc_root}/fd")).await {
                let mut fd_lines = String::new();
                let mut entries = 0usize;
                while let Ok(Some(entry)) = rd.next_entry().await {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let link = tokio::fs::read_link(entry.path())
                        .await
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|e| format!("<unreadable: {e}>"));
                    fd_lines.push_str(&format!("{name} -> {link}\n"));
                    entries += 1;
                }
                let _ = tokio::fs::write(proc_dir.join("fd"), fd_lines.as_bytes()).await;
                manifest.push(format!("proc/fd ({entries} entries)"));
            }
        } else {
            manifest.push("proc/* SKIP (no actor pid)".to_string());
        }

        let manifest_text = manifest.join("\n") + "\n";
        let _ = tokio::fs::write(dir.join("manifest.txt"), manifest_text.as_bytes()).await;

        Ok(ActionOutcome::ok(format!(
            "forensics bundle written → {}",
            dir.display()
        )))
    }
}

/// Return the last `n` lines of `bytes` (or all of it if it has fewer
/// lines). Lines are delimited by `\n`; the delimiter is preserved. Falls
/// back to returning the input unchanged if it isn't valid UTF-8 — kernel
/// log output is overwhelmingly UTF-8 in practice and the fallback keeps
/// the bundle honest if it isn't.
fn tail_lines(bytes: &[u8], n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let Ok(s) = std::str::from_utf8(bytes) else {
        return bytes.to_vec();
    };
    let lines: Vec<&str> = s.split_inclusive('\n').collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].concat().into_bytes()
}

// ============================================================= VelociraptorEscalateAction

/// Escalates a finding to a [Velociraptor](https://docs.velociraptor.app/)
/// deployment by invoking the configured binary. Arguments support
/// placeholder substitution: `{event_id}` and `{host_tag}` in any argument
/// are replaced with the event's values before invocation.
///
/// The action is intentionally a thin shell-out: the operator owns the
/// actual workflow (client-side artifact collection, server-side hunt
/// creation, etc.), expressed via the configured argv. selfdef just decides
/// *when* to run it.
pub struct VelociraptorEscalateAction {
    binary: PathBuf,
    args: Vec<String>,
}

impl VelociraptorEscalateAction {
    pub fn new(binary: PathBuf, args: Vec<String>) -> Self {
        Self { binary, args }
    }

    fn render_args(&self, event: &Event) -> Vec<String> {
        let event_id = event.id.to_string();
        let host = event.host_tag.as_str();
        self.args
            .iter()
            .map(|a| {
                a.replace("{event_id}", &event_id)
                    .replace("{host_tag}", host)
            })
            .collect()
    }
}

#[async_trait]
impl Action for VelociraptorEscalateAction {
    fn name(&self) -> &'static str {
        "velociraptor_escalate"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let rendered = self.render_args(event);

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would invoke {} {}",
                self.binary.display(),
                rendered.join(" ")
            )));
        }
        debug!(
            event_id = %event.id,
            binary = %self.binary.display(),
            argc = rendered.len(),
            "escalating to Velociraptor"
        );
        let output = Command::new(&self.binary).args(&rendered).output().await?;
        if output.status.success() {
            Ok(ActionOutcome::ok(format!(
                "velociraptor escalation dispatched ({} args)",
                rendered.len()
            )))
        } else {
            Err(ActionError::Exec(format!(
                "velociraptor exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

// ============================================================= BlockIpAction
//
// SDD-065 MS2 — wires the BlockSetBackend trait into the Action
// runner. Extracts the source IP from event.src_endpoint and
// submits a BlockIpRequest under the configured authority tier.

use selfdef_blockset_backend::{AuthorityTier as BsTier, BlockIpRequest, BlockSetBackend};
use std::time::Duration;

/// Block the source IP of the event via the configured backend.
pub struct BlockIpAction {
    backend: Arc<dyn BlockSetBackend>,
    /// Authority tier under which this action operates. Determines
    /// the maximum permissible duration; see SDD-065 §4.
    authority: BsTier,
    /// Block duration. Must be ≤ authority.max_duration().
    duration: Duration,
    /// Static reason prefix (the event id is appended for traceability).
    reason_prefix: String,
}

impl BlockIpAction {
    pub fn new(
        backend: Arc<dyn BlockSetBackend>,
        authority: BsTier,
        duration: Duration,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            reason_prefix: reason_prefix.into(),
        }
    }
}

fn source_ip_from_event(event: &Event) -> Option<std::net::IpAddr> {
    event.src_endpoint.as_ref().and_then(|ep| ep.ip)
}

#[async_trait]
impl Action for BlockIpAction {
    fn name(&self) -> &'static str {
        "block_ip"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(addr) = source_ip_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no src_endpoint.ip in event — block_ip skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!("{addr}:{}:{:?}", event.id, self.authority);

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would block {addr} for {}s under {:?} ({})",
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = BlockIpRequest {
            addr,
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            idempotency_key,
        };

        match self.backend.block_ip(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "blocked {addr} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!("block_ip backend: {e}"))),
        }
    }
}

// ====================================================== QuarantineProcessAction
//
// SDD-066 MS2 — wires the ProcessQuarantineBackend trait into
// the Action runner. Extracts pid from event.actor (existing
// pid_from_event helper); submits a FreezeRequest under the
// configured authority tier + scope.

use selfdef_process_quarantine_backend::{
    AuthorityTier as PqTier, FreezeRequest, FreezeScope, ProcessQuarantineBackend,
};

pub struct QuarantineProcessAction {
    backend: Arc<dyn ProcessQuarantineBackend>,
    authority: PqTier,
    duration: std::time::Duration,
    scope: FreezeScope,
    reason_prefix: String,
}

impl QuarantineProcessAction {
    pub fn new(
        backend: Arc<dyn ProcessQuarantineBackend>,
        authority: PqTier,
        duration: std::time::Duration,
        scope: FreezeScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for QuarantineProcessAction {
    fn name(&self) -> &'static str {
        "quarantine_process"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor pid available — quarantine_process skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!("{pid}:{}:{:?}:{:?}", event.id, self.authority, self.scope);

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would freeze pid {pid} ({:?}) for {}s under {:?} ({})",
                self.scope,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = FreezeRequest {
            pid,
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            idempotency_key,
        };

        match self.backend.freeze_process(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "frozen pid {pid} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "quarantine_process backend: {e}"
            ))),
        }
    }
}

// ======================================================== SessionRevocationAction
//
// SDD-067 MS2 — wires the SessionRevocationBackend trait into
// the Action runner. Third primitive in the IPS trio
// (BlockIpAction at perimeter + QuarantineProcessAction at
// process + SessionRevocationAction at session/identity boundary).
//
// Distinct from the prior `RevokeSessionAction` (script-based stub
// that shells out to an operator-provided revoke script);
// SessionRevocationAction uses the structured
// SessionRevocationBackend trait per SDD-067 with the InMemoryBackend
// + future LoginctlBackend (MS1b) implementations.
//
// Extracts user from event.actor.user.name (existing selfdef-core
// Actor field); submits RevokeRequest under configured tier+scope.

use selfdef_session_revocation_backend::{
    AuthorityTier as SrTier, RevocationScope, RevokeRequest, SessionRevocationBackend,
};

pub struct SessionRevocationAction {
    backend: Arc<dyn SessionRevocationBackend>,
    authority: SrTier,
    duration: std::time::Duration,
    scope: RevocationScope,
    reason_prefix: String,
}

impl SessionRevocationAction {
    pub fn new(
        backend: Arc<dyn SessionRevocationBackend>,
        authority: SrTier,
        duration: std::time::Duration,
        scope: RevocationScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

fn sdd067_user_from_event(event: &Event) -> Option<String> {
    event
        .actor
        .as_ref()
        .and_then(|a| a.user.as_ref())
        .and_then(|u| u.name.clone())
        .filter(|n| !n.is_empty())
}

#[async_trait]
impl Action for SessionRevocationAction {
    fn name(&self) -> &'static str {
        "session_revocation"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(user) = sdd067_user_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.user.name in event — session_revocation skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!("{user}:{}:{:?}:{:?}", event.id, self.authority, self.scope);

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would revoke sessions for {user} ({:?}) for {}s under {:?} ({})",
                self.scope,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = RevokeRequest {
            user: user.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            idempotency_key,
        };

        match self.backend.revoke_sessions(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "revoked sessions for {user} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!("revoke_sessions backend: {e}"))),
        }
    }
}

// ==================================================== ApiTokenRevocationAction
//
// SDD-068 MS2 — wires the ApiTokenRevocationBackend trait into
// the Action runner. Fourth primitive in the IPS quartet
// (BlockIpAction at perimeter + QuarantineProcessAction at
// process + SessionRevocationAction at session +
// ApiTokenRevocationAction at API-token/identity layer).
//
// Extracts principal from event.actor.user.name (same field as
// SDD-067 SessionRevocationAction); submits TokenRevokeRequest
// under configured tier + token-class mask.

use selfdef_api_token_revocation_backend::{
    ApiTokenRevocationBackend, AuthorityTier as AtrTier, TokenClassMask, TokenRevokeRequest,
};

pub struct ApiTokenRevocationAction {
    backend: Arc<dyn ApiTokenRevocationBackend>,
    authority: AtrTier,
    duration: std::time::Duration,
    token_classes: TokenClassMask,
    reason_prefix: String,
}

impl ApiTokenRevocationAction {
    pub fn new(
        backend: Arc<dyn ApiTokenRevocationBackend>,
        authority: AtrTier,
        duration: std::time::Duration,
        token_classes: TokenClassMask,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            token_classes,
            reason_prefix: reason_prefix.into(),
        }
    }
}

fn sdd068_principal_from_event(event: &Event) -> Option<String> {
    event
        .actor
        .as_ref()
        .and_then(|a| a.user.as_ref())
        .and_then(|u| u.name.clone())
        .filter(|n| !n.is_empty())
}

#[async_trait]
impl Action for ApiTokenRevocationAction {
    fn name(&self) -> &'static str {
        "api_token_revocation"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(principal) = sdd068_principal_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.user.name in event — api_token_revocation skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{principal}:{}:{:?}:{:?}",
            event.id, self.authority, self.token_classes
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would revoke tokens for {principal} ({:?}) for {}s under {:?} ({})",
                self.token_classes,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = TokenRevokeRequest {
            principal: principal.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            token_classes: self.token_classes.clone(),
            idempotency_key,
        };

        match self.backend.revoke_tokens(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "revoked tokens for {principal} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "api_token_revocation backend: {e}"
            ))),
        }
    }
}

// =================================================== MfaGrantRevocationAction
//
// SDD-069 MS2 — wires the MfaGrantRevocationBackend trait into
// the Action runner. Fifth primitive in the IPS pentet.

use selfdef_mfa_grant_revocation_backend::{
    AuthorityTier as MgrTier, MfaGrantRevocationBackend, MfaGrantRevokeRequest, MfaGrantScope,
};

pub struct MfaGrantRevocationAction {
    backend: Arc<dyn MfaGrantRevocationBackend>,
    authority: MgrTier,
    duration: std::time::Duration,
    grant_scope: MfaGrantScope,
    reason_prefix: String,
}

impl MfaGrantRevocationAction {
    pub fn new(
        backend: Arc<dyn MfaGrantRevocationBackend>,
        authority: MgrTier,
        duration: std::time::Duration,
        grant_scope: MfaGrantScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            grant_scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

fn sdd069_principal_from_event(event: &Event) -> Option<String> {
    event
        .actor
        .as_ref()
        .and_then(|a| a.user.as_ref())
        .and_then(|u| u.name.clone())
        .filter(|n| !n.is_empty())
}

#[async_trait]
impl Action for MfaGrantRevocationAction {
    fn name(&self) -> &'static str {
        "mfa_grant_revocation"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(principal) = sdd069_principal_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.user.name in event — mfa_grant_revocation skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{principal}:{}:{:?}:{:?}",
            event.id, self.authority, self.grant_scope
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would revoke MFA grants for {principal} ({:?}) for {}s under {:?} ({})",
                self.grant_scope,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = MfaGrantRevokeRequest {
            principal: principal.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            grant_scope: self.grant_scope.clone(),
            idempotency_key,
        };

        match self.backend.revoke_mfa_grants(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "revoked MFA grants for {principal} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "mfa_grant_revocation backend: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_core::category::ClassUid;
    use selfdef_core::prelude::*;

    fn finding_with_pid(pid: i32) -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Critical,
            "host",
            "test",
            0,
        )
        .with_actor(Actor {
            process: Some(Process {
                pid,
                ..Process::default()
            }),
            ..Actor::default()
        })
    }

    fn finding_without_pid() -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Critical,
            "host",
            "test",
            0,
        )
    }

    #[tokio::test]
    async fn snapshot_proc_dry_run_with_pid() {
        let action = SnapshotProcAction::new(PathBuf::from("/tmp/sd-snap"));
        let outcome = action.execute(&finding_with_pid(1234), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("1234"));
    }

    #[tokio::test]
    async fn snapshot_proc_skips_without_pid() {
        let action = SnapshotProcAction::new(PathBuf::from("/tmp/sd-snap"));
        let outcome = action.execute(&finding_without_pid(), true).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
    }

    #[tokio::test]
    async fn kill_pid_dry_run() {
        let action = KillPidAction::new();
        let outcome = action
            .execute(&finding_with_pid(99999), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
    }

    #[tokio::test]
    async fn lockdown_dry_run_doesnt_execute() {
        let action = LockdownEgressAction::new(PathBuf::from("/nonexistent/script"));
        let outcome = action.execute(&finding_without_pid(), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
    }

    #[tokio::test]
    async fn forensics_dry_run_announces_target_dir() {
        let action = ForensicsBundleAction::new(PathBuf::from("/tmp/sd-forensics"));
        let outcome = action.execute(&finding_without_pid(), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("/tmp/sd-forensics"));
    }

    #[tokio::test]
    async fn forensics_real_run_writes_event_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let action = ForensicsBundleAction::new(dir.path().to_path_buf());
        let event = finding_without_pid();
        let outcome = action.execute(&event, false).await.unwrap();
        assert_eq!(outcome.status, Status::Success);
        let bundle = dir.path().join(event.id.to_string());
        assert!(bundle.join("event.json").exists());
        assert!(bundle.join("manifest.txt").exists());
        let manifest = std::fs::read_to_string(bundle.join("manifest.txt")).unwrap();
        assert!(manifest.contains("event.json"));
        // pid-less event: manifest records the skip, not a fake proc dir.
        assert!(manifest.contains("proc/* SKIP"));
        assert!(!bundle.join("proc").exists());
    }

    #[tokio::test]
    async fn velociraptor_dry_run_renders_placeholders() {
        let action = VelociraptorEscalateAction::new(
            PathBuf::from("/usr/local/bin/velociraptor"),
            vec![
                "client".into(),
                "collect".into(),
                "--artifact=Generic.Forensic.SQLiteHunter".into(),
                "--label={host_tag}".into(),
                "--tag={event_id}".into(),
            ],
        );
        let event = finding_with_pid(42);
        let outcome = action.execute(&event, true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        // The rendered command line should contain the substituted values.
        assert!(outcome.notes.contains(&event.id.to_string()));
        assert!(outcome.notes.contains("--label=host"));
        // Placeholders themselves must be gone.
        assert!(!outcome.notes.contains("{event_id}"));
        assert!(!outcome.notes.contains("{host_tag}"));
    }

    #[test]
    fn tail_lines_returns_last_n() {
        let input = b"a\nb\nc\nd\ne\n";
        assert_eq!(tail_lines(input, 0), b"");
        assert_eq!(tail_lines(input, 2), b"d\ne\n");
        assert_eq!(tail_lines(input, 10), input);
    }

    #[test]
    fn tail_lines_handles_no_trailing_newline() {
        let input = b"a\nb\nc";
        // Only two `\n` markers, so requesting 2 lines returns from after
        // the first one onward.
        assert_eq!(tail_lines(input, 2), b"b\nc");
    }

    // ------------------------------ BlockIpAction (SDD-065 MS2)

    use selfdef_blockset_backend::InMemoryBackend;
    use std::net::{IpAddr, Ipv4Addr};

    fn finding_with_src_ip(ip: IpAddr) -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Critical,
            "host",
            "test",
            0,
        )
        .with_src_endpoint(selfdef_core::observable::Endpoint::ip_port(ip, 22))
    }

    #[tokio::test]
    async fn block_ip_dry_run_renders_address_and_duration() {
        let backend = Arc::new(InMemoryBackend::new());
        let action = BlockIpAction::new(
            backend.clone(),
            BsTier::Responder,
            Duration::from_secs(600),
            "test-responder",
        );
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let outcome = action
            .execute(&finding_with_src_ip(ip), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("203.0.113.7"));
        assert!(outcome.notes.contains("600s"));
        // Backend untouched.
        assert_eq!(backend.active_v4_count().await, 0);
    }

    #[tokio::test]
    async fn block_ip_applies_real_block_when_not_dry_run() {
        let backend = Arc::new(InMemoryBackend::new());
        let action = BlockIpAction::new(
            backend.clone(),
            BsTier::Operator,
            Duration::from_secs(60 * 60),
            "operator-cli",
        );
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        let outcome = action
            .execute(&finding_with_src_ip(ip), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("203.0.113.8"));
        assert_eq!(backend.active_v4_count().await, 1);
    }

    #[tokio::test]
    async fn block_ip_skipped_when_no_src_endpoint() {
        let backend = Arc::new(InMemoryBackend::new());
        let action = BlockIpAction::new(
            backend.clone(),
            BsTier::Responder,
            Duration::from_secs(60),
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_v4_count().await, 0);
    }

    #[tokio::test]
    async fn block_ip_propagates_authority_insufficient_as_exec_error() {
        let backend = Arc::new(InMemoryBackend::new());
        // Autonomous max = 5m; request 1h ⇒ AuthorityInsufficient.
        let action = BlockIpAction::new(
            backend.clone(),
            BsTier::Autonomous,
            Duration::from_secs(60 * 60),
            "auto",
        );
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let err = action
            .execute(&finding_with_src_ip(ip), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[test]
    fn action_name_is_stable_string() {
        let backend = Arc::new(InMemoryBackend::new());
        let action = BlockIpAction::new(backend, BsTier::Responder, Duration::from_secs(60), "x");
        assert_eq!(action.name(), "block_ip");
    }

    // ----------------------------- QuarantineProcessAction (SDD-066 MS2)

    use selfdef_process_quarantine_backend::{
        AuthorityTier as PqTier, FreezeScope, InMemoryBackend as PqInMemoryBackend,
    };

    #[tokio::test]
    async fn quarantine_process_dry_run_renders_pid_and_duration() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend.clone(),
            PqTier::Responder,
            Duration::from_secs(600),
            FreezeScope::Process,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4242), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4242"));
        assert!(outcome.notes.contains("600s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn quarantine_process_applies_real_freeze_when_not_dry_run() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend.clone(),
            PqTier::Operator,
            Duration::from_secs(60 * 60),
            FreezeScope::Process,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(4243), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("4243"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn quarantine_process_skipped_when_no_pid() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend.clone(),
            PqTier::Responder,
            Duration::from_secs(60),
            FreezeScope::Process,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn quarantine_process_propagates_authority_insufficient() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend.clone(),
            PqTier::Autonomous,
            Duration::from_secs(60 * 60),
            FreezeScope::Process,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(4244), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn quarantine_process_tree_scope_routes_through_backend() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend.clone(),
            PqTier::Operator,
            Duration::from_secs(60),
            FreezeScope::Tree,
            "tree-test",
        );
        let outcome = action
            .execute(&finding_with_pid(4245), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn quarantine_action_name_is_stable_string() {
        let backend = Arc::new(PqInMemoryBackend::new());
        let action = QuarantineProcessAction::new(
            backend,
            PqTier::Responder,
            Duration::from_secs(60),
            FreezeScope::Process,
            "x",
        );
        assert_eq!(action.name(), "quarantine_process");
    }

    // ------------------------------ SessionRevocationAction (SDD-067 MS2)

    use selfdef_session_revocation_backend::{
        AuthorityTier as SrTier, InMemoryBackend as SrInMemoryBackend, RevocationScope,
    };

    fn finding_with_user(name: &str) -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Critical,
            "host",
            "test",
            0,
        )
        .with_actor(Actor {
            user: Some(selfdef_core::observable::User {
                name: Some(name.into()),
                ..selfdef_core::observable::User::default()
            }),
            ..Actor::default()
        })
    }

    #[tokio::test]
    async fn session_revocation_dry_run_renders_user_and_duration() {
        let backend = Arc::new(SrInMemoryBackend::new());
        let action = SessionRevocationAction::new(
            backend.clone(),
            SrTier::Responder,
            Duration::from_secs(900),
            RevocationScope::Local,
            "test-responder",
        );
        let outcome = action
            .execute(&finding_with_user("alice"), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("alice"));
        assert!(outcome.notes.contains("900s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn session_revocation_applies_real_revoke_when_not_dry_run() {
        let backend = Arc::new(SrInMemoryBackend::new());
        let action = SessionRevocationAction::new(
            backend.clone(),
            SrTier::Operator,
            Duration::from_secs(60 * 60),
            RevocationScope::Local,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_user("bob"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("bob"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn session_revocation_skipped_when_no_user() {
        let backend = Arc::new(SrInMemoryBackend::new());
        let action = SessionRevocationAction::new(
            backend.clone(),
            SrTier::Responder,
            Duration::from_secs(60),
            RevocationScope::Local,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn session_revocation_propagates_authority_insufficient() {
        let backend = Arc::new(SrInMemoryBackend::new());
        let action = SessionRevocationAction::new(
            backend.clone(),
            SrTier::Autonomous,
            Duration::from_secs(60 * 60),
            RevocationScope::Local,
            "auto",
        );
        let err = action
            .execute(&finding_with_user("carol"), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[test]
    fn session_revocation_action_name_is_stable_string() {
        let backend = Arc::new(SrInMemoryBackend::new());
        let action = SessionRevocationAction::new(
            backend,
            SrTier::Responder,
            Duration::from_secs(60),
            RevocationScope::Local,
            "x",
        );
        assert_eq!(action.name(), "session_revocation");
    }

    // -------------------------- ApiTokenRevocationAction (SDD-068 MS2)

    use selfdef_api_token_revocation_backend::{
        AuthorityTier as AtrTier, InMemoryBackend as AtrInMemoryBackend, TokenClass, TokenClassMask,
    };

    #[tokio::test]
    async fn api_token_revocation_dry_run_renders_principal_and_duration() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend.clone(),
            AtrTier::Responder,
            Duration::from_secs(1800),
            TokenClassMask::All,
            "test-responder",
        );
        let outcome = action
            .execute(&finding_with_user("alice"), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("alice"));
        assert!(outcome.notes.contains("1800s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn api_token_revocation_applies_real_revoke_when_not_dry_run() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend.clone(),
            AtrTier::Operator,
            Duration::from_secs(60 * 60),
            TokenClassMask::All,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_user("bob"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("bob"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn api_token_revocation_skipped_when_no_principal() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend.clone(),
            AtrTier::Responder,
            Duration::from_secs(60),
            TokenClassMask::All,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn api_token_revocation_propagates_authority_insufficient() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend.clone(),
            AtrTier::Autonomous,
            Duration::from_secs(60 * 60),
            TokenClassMask::All,
            "auto",
        );
        let err = action
            .execute(&finding_with_user("carol"), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn api_token_revocation_scoped_classes_routed() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend.clone(),
            AtrTier::Operator,
            Duration::from_secs(60),
            TokenClassMask::Specific(vec![TokenClass::Api, TokenClass::Cockpit]),
            "scoped",
        );
        let outcome = action
            .execute(&finding_with_user("dan"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn api_token_revocation_action_name_is_stable_string() {
        let backend = Arc::new(AtrInMemoryBackend::new());
        let action = ApiTokenRevocationAction::new(
            backend,
            AtrTier::Responder,
            Duration::from_secs(60),
            TokenClassMask::All,
            "x",
        );
        assert_eq!(action.name(), "api_token_revocation");
    }

    // ------------------------ MfaGrantRevocationAction (SDD-069 MS2)

    use selfdef_mfa_grant_revocation_backend::{
        AuthorityTier as MgrTier, InMemoryBackend as MgrInMemoryBackend, MfaGrantScope,
        MfaGrantSurface,
    };

    #[tokio::test]
    async fn mfa_grant_revocation_dry_run_renders_principal_and_duration() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend.clone(),
            MgrTier::Responder,
            Duration::from_secs(900),
            MfaGrantScope::All,
            "test-responder",
        );
        let outcome = action
            .execute(&finding_with_user("alice"), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("alice"));
        assert!(outcome.notes.contains("900s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn mfa_grant_revocation_applies_real_revoke_when_not_dry_run() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend.clone(),
            MgrTier::Operator,
            Duration::from_secs(60 * 60),
            MfaGrantScope::All,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_user("bob"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("bob"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn mfa_grant_revocation_skipped_when_no_principal() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend.clone(),
            MgrTier::Responder,
            Duration::from_secs(60),
            MfaGrantScope::All,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn mfa_grant_revocation_propagates_authority_insufficient() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend.clone(),
            MgrTier::Autonomous,
            Duration::from_secs(60 * 60),
            MfaGrantScope::All,
            "auto",
        );
        let err = action
            .execute(&finding_with_user("carol"), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn mfa_grant_revocation_scoped_surfaces_routed() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend.clone(),
            MgrTier::Operator,
            Duration::from_secs(60),
            MfaGrantScope::Specific(vec![MfaGrantSurface::Pam, MfaGrantSurface::Api]),
            "scoped",
        );
        let outcome = action
            .execute(&finding_with_user("dan"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn mfa_grant_revocation_action_name_is_stable_string() {
        let backend = Arc::new(MgrInMemoryBackend::new());
        let action = MfaGrantRevocationAction::new(
            backend,
            MgrTier::Responder,
            Duration::from_secs(60),
            MfaGrantScope::All,
            "x",
        );
        assert_eq!(action.name(), "mfa_grant_revocation");
    }
}
