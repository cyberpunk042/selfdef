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
        // `> 0` is load-bearing safety, not just extraction: `kill 0` signals the
        // responder's WHOLE process group and `kill -1` signals EVERY process, so
        // a crafted or buggy event must never reach a signalling action with a
        // `0` or negative pid. PID 1 (init) IS still returned here — individual
        // actions own the policy for it (most refuse it; apparmor propagates a
        // "sacrosanct" pid), so that decision lives in the per-action guard, not
        // in this shared extractor.
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

        // Never signal init. `pid_from_event` already blocks 0 and negatives (the
        // process-group and `kill -1` mass-kill targets); pid 1 still reaches
        // here, but SIGTERM-ing init is never a legitimate response (only ever an
        // attempt to disrupt the host), and the sibling containment actions
        // refuse pid 1 too — kill_pid, the most destructive of them, must as well.
        if pid == 1 {
            return Ok(ActionOutcome::skipped("refusing to signal pid 1 (init)"));
        }

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!("would SIGTERM pid {pid}")));
        }

        let output = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .kill_on_drop(true)
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
        let output = Command::new(&self.script)
            .arg("activate")
            .kill_on_drop(true)
            .output()
            .await?;
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

        let output = Command::new(&self.script)
            .arg(&user)
            .kill_on_drop(true)
            .output()
            .await?;
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
            match Command::new(prog)
                .args(&args)
                .kill_on_drop(true)
                .output()
                .await
            {
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
        match Command::new("dmesg")
            .arg("--ctime")
            .kill_on_drop(true)
            .output()
            .await
        {
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
            .kill_on_drop(true)
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
        let output = Command::new(&self.binary)
            .args(&rendered)
            .kill_on_drop(true)
            .output()
            .await?;
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

// ======================================================= NetnsIsolationAction
//
// SDD-070 MS2 — wires the NetnsIsolationBackend trait into the
// Action runner. Sixth primitive in the IPS hexet; pairs with
// SDD-066 process-freeze at the kernel-containment axis.

use selfdef_netns_isolation_backend::{
    AuthorityTier as NetnsTier, IsolatePidRequest, IsolationScope as NetnsScope,
    NetnsIsolationBackend,
};

pub struct NetnsIsolationAction {
    backend: Arc<dyn NetnsIsolationBackend>,
    authority: NetnsTier,
    duration: std::time::Duration,
    scope: NetnsScope,
    reason_prefix: String,
}

impl NetnsIsolationAction {
    pub fn new(
        backend: Arc<dyn NetnsIsolationBackend>,
        authority: NetnsTier,
        duration: std::time::Duration,
        scope: NetnsScope,
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
impl Action for NetnsIsolationAction {
    fn name(&self) -> &'static str {
        "netns_isolation"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid in event — netns_isolation skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!("{pid}:{}:{:?}:{:?}", event.id, self.authority, self.scope);

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would isolate pid {pid} ({:?}) for {}s under {:?} ({})",
                self.scope,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = IsolatePidRequest {
            pid,
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            idempotency_key,
        };

        match self.backend.isolate_pid(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "isolated pid {pid} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!("netns_isolation backend: {e}"))),
        }
    }
}

// =================================================== MountBindingUnbindAction
//
// SDD-071 MS2 — wires the MountBindingUnbindBackend trait into the
// Action runner. Seventh primitive in the IPS septet; pairs with
// SDD-066 process-freeze + SDD-070 netns-isolation at the
// kernel-containment family.

use selfdef_mount_binding_unbind_backend::{
    AuthorityTier as MbTier, MountBindingUnbindBackend, UnbindMountRequest, UnbindScope as MbScope,
};

pub struct MountBindingUnbindAction {
    backend: Arc<dyn MountBindingUnbindBackend>,
    authority: MbTier,
    duration: std::time::Duration,
    scope: MbScope,
    lazy: bool,
    reason_prefix: String,
}

impl MountBindingUnbindAction {
    pub fn new(
        backend: Arc<dyn MountBindingUnbindBackend>,
        authority: MbTier,
        duration: std::time::Duration,
        scope: MbScope,
        lazy: bool,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            scope,
            lazy,
            reason_prefix: reason_prefix.into(),
        }
    }
}

fn sdd071_mount_point_from_event(event: &Event) -> Option<String> {
    event
        .file
        .as_ref()
        .and_then(|f| f.path.clone())
        .filter(|p| !p.is_empty())
}

#[async_trait]
impl Action for MountBindingUnbindAction {
    fn name(&self) -> &'static str {
        "mount_binding_unbind"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(mount_point) = sdd071_mount_point_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no file.path in event — mount_binding_unbind skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{mount_point}:{}:{:?}:{:?}",
            event.id, self.authority, self.scope
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would unbind {mount_point} ({:?}, lazy={}) for {}s under {:?} ({})",
                self.scope,
                self.lazy,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = UnbindMountRequest {
            mount_point: mount_point.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope.clone(),
            lazy: self.lazy,
            idempotency_key,
        };

        match self.backend.unbind_mount(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "unbound {mount_point} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "mount_binding_unbind backend: {e}"
            ))),
        }
    }
}

// ====================================================== ProcessTreeFreezeAction
//
// SDD-072 MS2 — wires the ProcessTreeFreezeBackend trait into the
// Action runner. Eighth primitive in the IPS octet; pairs with
// SDD-066 single-pid freeze + SDD-070 netns-isolation at the
// kernel-containment family.

use selfdef_process_tree_freeze_backend::{
    AuthorityTier as PtfTier, FreezeTreeRequest, ProcessTreeFreezeBackend, TreeScope,
};

pub struct ProcessTreeFreezeAction {
    backend: Arc<dyn ProcessTreeFreezeBackend>,
    authority: PtfTier,
    duration: std::time::Duration,
    scope: TreeScope,
    include_self: bool,
    reason_prefix: String,
}

impl ProcessTreeFreezeAction {
    pub fn new(
        backend: Arc<dyn ProcessTreeFreezeBackend>,
        authority: PtfTier,
        duration: std::time::Duration,
        scope: TreeScope,
        include_self: bool,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            scope,
            include_self,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for ProcessTreeFreezeAction {
    fn name(&self) -> &'static str {
        "process_tree_freeze"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(root_pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid in event — process_tree_freeze skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{root_pid}:{}:{:?}:{:?}",
            event.id, self.authority, self.scope
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would freeze tree root={root_pid} ({:?}, include_self={}) for {}s under {:?} ({})",
                self.scope,
                self.include_self,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = FreezeTreeRequest {
            root_pid,
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            include_self: self.include_self,
            idempotency_key,
        };

        match self.backend.freeze_tree(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "froze tree root={root_pid} ({reason}); frozen_pid_count={}; handle={:?}",
                receipt.frozen_pid_count, receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "process_tree_freeze backend: {e}"
            ))),
        }
    }
}

// ===================================================== SocketFdRevocationAction
//
// SDD-073 MS2 — wires the SocketFdRevocationBackend trait into the
// Action runner. Ninth primitive in the IPS nonet; pairs with
// SDD-065 perimeter-block + SDD-070 netns-isolation at the
// network-containment family.

use selfdef_socket_fd_revocation_backend::{
    AuthorityTier as SfrTier, RevokeFdRequest, SocketFdRevocationBackend,
    SocketProtocol as SfrProtocol,
};

pub struct SocketFdRevocationAction {
    backend: Arc<dyn SocketFdRevocationBackend>,
    authority: SfrTier,
    duration: std::time::Duration,
    protocol: SfrProtocol,
    /// When None, the action sends no inode hint; when Some, the
    /// production adapter (MS5a) will verify /proc/<pid>/fdinfo/<fd>
    /// still references the same inode before closing.
    expected_inode: Option<u64>,
    reason_prefix: String,
}

impl SocketFdRevocationAction {
    pub fn new(
        backend: Arc<dyn SocketFdRevocationBackend>,
        authority: SfrTier,
        duration: std::time::Duration,
        protocol: SfrProtocol,
        expected_inode: Option<u64>,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            protocol,
            expected_inode,
            reason_prefix: reason_prefix.into(),
        }
    }
}

/// Extracts (pid, fd) from event payload. The fd is read from a
/// custom event field; for MS2 we look at event.metadata.profiles
/// for a "socket_fd:<n>" marker, falling back to None. Production
/// integrations will populate event.metadata with structured fd
/// info; this stub keeps MS2 deterministic for tests.
fn sdd073_pid_fd_from_event(event: &Event) -> Option<(i32, i32)> {
    let pid = pid_from_event(event)?;
    let fd = event
        .metadata
        .profiles
        .iter()
        .find_map(|p| p.strip_prefix("socket_fd:")?.parse::<i32>().ok())?;
    Some((pid, fd))
}

#[async_trait]
impl Action for SocketFdRevocationAction {
    fn name(&self) -> &'static str {
        "socket_fd_revocation"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some((pid, fd)) = sdd073_pid_fd_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid + metadata.profiles[socket_fd:N] in event — socket_fd_revocation skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{pid}:{fd}:{}:{:?}:{:?}",
            event.id, self.authority, self.protocol
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would revoke fd {fd} on pid {pid} ({:?}) for {}s under {:?} ({})",
                self.protocol,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = RevokeFdRequest {
            pid,
            fd,
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            protocol: self.protocol,
            expected_inode: self.expected_inode,
            idempotency_key,
        };

        match self.backend.revoke_fd(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "revoked fd {fd} on pid {pid} ({reason}); handle={:?}",
                receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "socket_fd_revocation backend: {e}"
            ))),
        }
    }
}

// ======================================================== ProcessEnvScrubAction
//
// SDD-074 MS2 — wires the ProcessEnvScrubBackend trait into the
// Action runner. Tenth primitive in the IPS dectet; pairs with
// SDD-068 token-revocation at the credential-axis family
// (SDD-068 revokes server-side, SDD-074 scrubs client-side cache).

use selfdef_process_env_scrub_backend::{
    AuthorityTier as PesTier, ProcessEnvScrubBackend, ScrubEnvRequest, ScrubSignal as PesSignal,
};

pub struct ProcessEnvScrubAction {
    backend: Arc<dyn ProcessEnvScrubBackend>,
    authority: PesTier,
    duration: std::time::Duration,
    /// Static variable-name list — typically configured per-rule
    /// (e.g. "AWS_SECRET_ACCESS_KEY,DB_PASSWORD"). Production
    /// rules will populate this from event metadata too.
    vars: Vec<String>,
    signal: PesSignal,
    reason_prefix: String,
}

impl ProcessEnvScrubAction {
    pub fn new(
        backend: Arc<dyn ProcessEnvScrubBackend>,
        authority: PesTier,
        duration: std::time::Duration,
        vars: Vec<String>,
        signal: PesSignal,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            vars,
            signal,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for ProcessEnvScrubAction {
    fn name(&self) -> &'static str {
        "process_env_scrub"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid in event — process_env_scrub skipped",
            ));
        };
        if self.vars.is_empty() {
            return Ok(ActionOutcome::skipped(
                "no vars configured on action — process_env_scrub skipped",
            ));
        }

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{pid}:{}:{}:{:?}:{:?}",
            event.id,
            self.vars.join(","),
            self.authority,
            self.signal
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would scrub vars {:?} on pid {pid} (signal={:?}) for {}s under {:?} ({})",
                self.vars,
                self.signal,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = ScrubEnvRequest {
            pid,
            vars: self.vars.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            signal: self.signal,
            idempotency_key,
        };

        match self.backend.scrub_env(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "scrubbed {} vars on pid {pid} ({reason}); handle={:?}",
                receipt.vars_scrubbed, receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!("process_env_scrub backend: {e}"))),
        }
    }
}

// ===================================================== CapabilityDropAction
//
// SDD-075 MS2 — wires the CapabilityDropBackend trait into the
// Action runner. Eleventh primitive in the IPS undectet; pairs
// with SDD-066 single-pid freeze + SDD-070 netns-isolation at
// the kernel-containment family (least-privilege graduation:
// drop one capability instead of freezing/isolating the whole
// process).

use selfdef_capability_drop_backend::{
    AuthorityTier as CdrTier, CapScope, CapabilityDropBackend, DropCapsRequest, canonicalize_cap,
};

pub struct CapabilityDropAction {
    backend: Arc<dyn CapabilityDropBackend>,
    authority: CdrTier,
    duration: std::time::Duration,
    /// Static cap-name list — typically configured per-rule
    /// (e.g. "CAP_NET_ADMIN,CAP_SYS_PTRACE"). Production rules
    /// will populate this from event metadata too.
    caps: Vec<String>,
    scope: CapScope,
    reason_prefix: String,
}

impl CapabilityDropAction {
    pub fn new(
        backend: Arc<dyn CapabilityDropBackend>,
        authority: CdrTier,
        duration: std::time::Duration,
        caps: Vec<String>,
        scope: CapScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            caps,
            scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for CapabilityDropAction {
    fn name(&self) -> &'static str {
        "capability_drop"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid in event — capability_drop skipped",
            ));
        };
        if self.caps.is_empty() {
            return Ok(ActionOutcome::skipped(
                "no caps configured on action — capability_drop skipped",
            ));
        }
        // Pre-validate cap names client-side so a typo in the action
        // config surfaces at execute time instead of round-tripping
        // through the backend's validator.
        for c in &self.caps {
            if canonicalize_cap(c).is_none() {
                return Err(ActionError::Exec(format!(
                    "capability_drop: unknown cap name {c:?} in action config"
                )));
            }
        }

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{pid}:{}:{}:{:?}:{:?}",
            event.id,
            self.caps.join(","),
            self.authority,
            self.scope
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would drop caps {:?} on pid {pid} ({:?}) for {}s under {:?} ({})",
                self.caps,
                self.scope,
                self.duration.as_secs(),
                self.authority,
                reason
            )));
        }

        let req = DropCapsRequest {
            pid,
            caps: self.caps.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            idempotency_key,
        };

        match self.backend.drop_caps(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "dropped {} caps on pid {pid} ({reason}); handle={:?}",
                receipt.caps_dropped, receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!("capability_drop backend: {e}"))),
        }
    }
}

// ================================================ KernelKeyringEvictionAction
//
// SDD-076 MS2 — wires the KernelKeyringEvictionBackend trait into
// the Action runner. Twelfth primitive in the IPS duodectet;
// pairs with SDD-068 token-revoke + SDD-069 MFA-grant + SDD-074
// env-scrub + SDD-075 capability-drop at the credential-axis
// family (distinct surface — kernel keyctl-managed cache).

use selfdef_kernel_keyring_eviction_backend::{
    AuthorityTier as KkeTier, EvictKeyRequest, EvictionScope, KernelKeyringEvictionBackend,
};

pub struct KernelKeyringEvictionAction {
    backend: Arc<dyn KernelKeyringEvictionBackend>,
    authority: KkeTier,
    duration: std::time::Duration,
    /// Static key-spec list — typically configured per-rule
    /// (e.g. "user:krb5cc/uid=1000" or "0xdeadbeef").
    key_specs: Vec<String>,
    scope: EvictionScope,
    reason_prefix: String,
}

impl KernelKeyringEvictionAction {
    pub fn new(
        backend: Arc<dyn KernelKeyringEvictionBackend>,
        authority: KkeTier,
        duration: std::time::Duration,
        key_specs: Vec<String>,
        scope: EvictionScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            key_specs,
            scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for KernelKeyringEvictionAction {
    fn name(&self) -> &'static str {
        "kernel_keyring_eviction"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        if self.key_specs.is_empty() {
            return Ok(ActionOutcome::skipped(
                "no key_specs configured on action — kernel_keyring_eviction skipped",
            ));
        }

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        // Each key_spec triggers a separate evict call (the action
        // can target multiple keys per event). Aggregate results
        // into the outcome message.
        let mut handles: Vec<String> = Vec::with_capacity(self.key_specs.len());
        let mut total_evicted: usize = 0;
        let mut total_not_found: usize = 0;
        for spec in &self.key_specs {
            let idempotency_key =
                format!("{}:{:?}:{spec}:{:?}", event.id, self.authority, self.scope);
            if dry_run {
                handles.push(format!(
                    "would evict {spec} ({:?}) for {}s under {:?}",
                    self.scope,
                    self.duration.as_secs(),
                    self.authority
                ));
                continue;
            }
            let req = EvictKeyRequest {
                key_spec: spec.clone(),
                reason: reason.clone(),
                duration: self.duration,
                authority: self.authority,
                scope: self.scope,
                idempotency_key,
            };
            match self.backend.evict_key(req).await {
                Ok(receipt) => {
                    total_evicted += receipt.keys_evicted;
                    if receipt.keys_evicted == 0 {
                        total_not_found += 1;
                    }
                    handles.push(format!("{:?}", receipt.handle));
                }
                Err(e) => {
                    return Err(ActionError::Exec(format!(
                        "kernel_keyring_eviction backend on spec {spec:?}: {e}"
                    )));
                }
            }
        }

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would evict {} key(s) ({}); {}",
                self.key_specs.len(),
                self.key_specs.join(", "),
                reason
            )));
        }
        Ok(ActionOutcome::ok(format!(
            "evicted {total_evicted} kernel keys across {} spec(s); {total_not_found} NotFound; \
             handles={handles:?}; reason={reason}",
            self.key_specs.len()
        )))
    }
}

// =================================================== ApparmorProfilePivotAction
//
// SDD-077 MS2 — wires the ApparmorProfilePivotBackend trait into
// the Action runner. Thirteenth primitive in the IPS tridectet;
// pairs with SDD-075 capability-drop at the privilege/policy
// family — caps strip kernel-side capabilities; profile pivot
// narrows the AppArmor MAC profile that further gates path /
// network / cap usage within the remaining capability set.

use selfdef_apparmor_profile_pivot_backend::{
    ApparmorProfilePivotBackend, AuthorityTier as AppTier, PivotProfileRequest, PivotScope,
};

pub struct ApparmorProfilePivotAction {
    backend: Arc<dyn ApparmorProfilePivotBackend>,
    authority: AppTier,
    duration: std::time::Duration,
    /// AppArmor profile (or hat) to pivot the target pid into.
    /// Typically `selfdef-observe-only` / `selfdef-quarantine-strict`
    /// from action config — admin-loaded out-of-band.
    target_profile: String,
    scope: PivotScope,
    reason_prefix: String,
}

impl ApparmorProfilePivotAction {
    pub fn new(
        backend: Arc<dyn ApparmorProfilePivotBackend>,
        authority: AppTier,
        duration: std::time::Duration,
        target_profile: impl Into<String>,
        scope: PivotScope,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            target_profile: target_profile.into(),
            scope,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for ApparmorProfilePivotAction {
    fn name(&self) -> &'static str {
        "apparmor_profile_pivot"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        let Some(pid) = pid_from_event(event) else {
            return Ok(ActionOutcome::skipped(
                "no actor.process.pid in event — apparmor_profile_pivot skipped",
            ));
        };

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{pid}:{}:{}:{:?}:{:?}",
            event.id, self.target_profile, self.authority, self.scope
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would pivot pid {pid} into AppArmor profile {:?} ({:?}) for {}s under {:?} ({reason})",
                self.target_profile,
                self.scope,
                self.duration.as_secs(),
                self.authority
            )));
        }

        let req = PivotProfileRequest {
            pid,
            target_profile: self.target_profile.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            scope: self.scope,
            idempotency_key,
        };

        match self.backend.pivot_profile(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "pivoted pid {pid} into AppArmor profile {:?} (was {:?}); handle={:?}; {reason}",
                self.target_profile, receipt.original_profile, receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "apparmor_profile_pivot backend: {e}"
            ))),
        }
    }
}

// ==================================================== BpfMapElementClearAction
//
// SDD-078 MS2 — wires the BpfMapElementClearBackend trait into
// the Action runner. Fourteenth primitive in the IPS quattuordectet;
// pairs with SDD-076 kernel-keyring-eviction at the kernel-state-
// eviction family — keyctl evicts credential cache; bpf-map-element
// clear evicts BPF policy/counter state.

use selfdef_bpf_map_element_clear_backend::{
    AuthorityTier as BmcTier, BpfMapElementClearBackend, ClearRequest, ClearScope,
    parse_key_hex as bmc_parse_key_hex, parse_map_spec as bmc_parse_map_spec,
};

pub struct BpfMapElementClearAction {
    backend: Arc<dyn BpfMapElementClearBackend>,
    authority: BmcTier,
    duration: std::time::Duration,
    /// Map spec — `/sys/fs/bpf/<n>` or `id:<u32>` or `name:<x>`.
    map_spec: String,
    scope: ClearScope,
    /// Hex-bytes key. Required when `scope==Element`; must be None
    /// when `scope==All`. Validated client-side before backend call.
    key_hex: Option<String>,
    reason_prefix: String,
}

impl BpfMapElementClearAction {
    pub fn new(
        backend: Arc<dyn BpfMapElementClearBackend>,
        authority: BmcTier,
        duration: std::time::Duration,
        map_spec: impl Into<String>,
        scope: ClearScope,
        key_hex: Option<String>,
        reason_prefix: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            authority,
            duration,
            map_spec: map_spec.into(),
            scope,
            key_hex,
            reason_prefix: reason_prefix.into(),
        }
    }
}

#[async_trait]
impl Action for BpfMapElementClearAction {
    fn name(&self) -> &'static str {
        "bpf_map_element_clear"
    }

    async fn execute(&self, event: &Event, dry_run: bool) -> Result<ActionOutcome, ActionError> {
        // Pre-validate map_spec + key_hex client-side so config
        // errors surface at execute time, not after a backend round-trip.
        if bmc_parse_map_spec(&self.map_spec).is_none() {
            return Err(ActionError::Exec(format!(
                "bpf_map_element_clear: unparseable map spec {:?} in action config",
                self.map_spec
            )));
        }
        match self.scope {
            ClearScope::Element => {
                let Some(key) = self.key_hex.as_ref() else {
                    return Err(ActionError::Exec(
                        "bpf_map_element_clear: element-scope requires key_hex in action config"
                            .to_string(),
                    ));
                };
                if bmc_parse_key_hex(key).is_none() {
                    return Err(ActionError::Exec(format!(
                        "bpf_map_element_clear: invalid key_hex {key:?} in action config"
                    )));
                }
            }
            ClearScope::All => {
                if self.key_hex.is_some() {
                    return Err(ActionError::Exec(
                        "bpf_map_element_clear: all-scope forbids key_hex in action config"
                            .to_string(),
                    ));
                }
            }
        }

        let reason = format!("{}: event {}", self.reason_prefix, event.id);
        let idempotency_key = format!(
            "{}:{}:{:?}:{:?}:{:?}",
            event.id, self.map_spec, self.scope, self.key_hex, self.authority
        );

        if dry_run {
            return Ok(ActionOutcome::dry_run(format!(
                "would clear BPF map {:?} ({:?}) key={:?} for {}s under {:?} ({reason})",
                self.map_spec,
                self.scope,
                self.key_hex,
                self.duration.as_secs(),
                self.authority
            )));
        }

        let req = ClearRequest {
            map_spec: self.map_spec.clone(),
            scope: self.scope,
            key_hex: self.key_hex.clone(),
            reason: reason.clone(),
            duration: self.duration,
            authority: self.authority,
            idempotency_key,
        };

        match self.backend.clear(req).await {
            Ok(receipt) => Ok(ActionOutcome::ok(format!(
                "cleared {} BPF map element(s) in {:?} ({:?}); handle={:?}; {reason}",
                receipt.elements_cleared, self.map_spec, self.scope, receipt.handle
            ))),
            Err(e) => Err(ActionError::Exec(format!(
                "bpf_map_element_clear backend: {e}"
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
    async fn kill_pid_refuses_init_and_invalid_pids() {
        // A crafted/buggy event naming init (pid 1), pid 0 (process-group signal),
        // or a negative pid (kill -1 mass-kill) must NEVER reach `kill` —
        // pid_from_event refuses them, so kill_pid skips before doing anything.
        // Run with dry_run = false to prove nothing is signalled.
        let action = KillPidAction::new();
        for pid in [1, 0, -1] {
            let outcome = action.execute(&finding_with_pid(pid), false).await.unwrap();
            assert_eq!(outcome.status, Status::Skipped, "pid {pid} must be refused");
        }
        // A real userspace pid (> 1) is accepted (verified via dry-run so no
        // actual signal is sent in the test).
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

    // ----------------------------- NetnsIsolationAction (SDD-070 MS2)

    use selfdef_netns_isolation_backend::{
        AuthorityTier as NetnsTier, InMemoryBackend as NetnsInMemoryBackend, IsolationScope,
    };

    #[tokio::test]
    async fn netns_isolation_dry_run_renders_pid_scope_and_duration() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend.clone(),
            NetnsTier::Responder,
            Duration::from_secs(900),
            IsolationScope::NetOnly,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("900s"));
        assert!(outcome.notes.contains("NetOnly"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn netns_isolation_applies_real_isolate_when_not_dry_run() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend.clone(),
            NetnsTier::Operator,
            Duration::from_secs(60 * 60),
            IsolationScope::NetOnly,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn netns_isolation_skipped_when_no_pid() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend.clone(),
            NetnsTier::Responder,
            Duration::from_secs(60),
            IsolationScope::NetOnly,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn netns_isolation_propagates_authority_insufficient() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend.clone(),
            NetnsTier::Autonomous,
            Duration::from_secs(60 * 60),
            IsolationScope::NetOnly,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn netns_isolation_scoped_net_pid_ipc() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend.clone(),
            NetnsTier::Operator,
            Duration::from_secs(60),
            IsolationScope::NetPidIpc,
            "scoped",
        );
        let outcome = action
            .execute(&finding_with_pid(9090), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn netns_isolation_action_name_is_stable_string() {
        let backend = Arc::new(NetnsInMemoryBackend::new());
        let action = NetnsIsolationAction::new(
            backend,
            NetnsTier::Responder,
            Duration::from_secs(60),
            IsolationScope::NetOnly,
            "x",
        );
        assert_eq!(action.name(), "netns_isolation");
    }

    // ----------------------------- MountBindingUnbindAction (SDD-071 MS2)

    use selfdef_core::observable::File;
    use selfdef_mount_binding_unbind_backend::{
        AuthorityTier as MbTier, InMemoryBackend as MbInMemoryBackend, UnbindScope,
    };

    fn finding_with_path(path: &str) -> Event {
        Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Critical,
            "host",
            "test",
            0,
        )
        .with_file(File {
            path: Some(path.into()),
            ..File::default()
        })
    }

    #[tokio::test]
    async fn mount_binding_unbind_dry_run_renders_mount_point_and_duration() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend.clone(),
            MbTier::Responder,
            Duration::from_secs(900),
            UnbindScope::Bind,
            true,
            "test-responder",
        );
        let outcome = action
            .execute(&finding_with_path("/mnt/leak"), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("/mnt/leak"));
        assert!(outcome.notes.contains("900s"));
        assert!(outcome.notes.contains("Bind"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn mount_binding_unbind_applies_real_unbind_when_not_dry_run() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend.clone(),
            MbTier::Operator,
            Duration::from_secs(60 * 30),
            UnbindScope::Bind,
            true,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_path("/mnt/escape"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("/mnt/escape"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn mount_binding_unbind_skipped_when_no_path() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend.clone(),
            MbTier::Responder,
            Duration::from_secs(60),
            UnbindScope::Bind,
            true,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn mount_binding_unbind_propagates_authority_insufficient() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend.clone(),
            MbTier::Autonomous,
            Duration::from_secs(60 * 30),
            UnbindScope::Bind,
            true,
            "auto",
        );
        let err = action
            .execute(&finding_with_path("/mnt/leak"), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn mount_binding_unbind_scoped_overlay() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend.clone(),
            MbTier::Operator,
            Duration::from_secs(60),
            UnbindScope::Overlay,
            true,
            "scoped",
        );
        let outcome = action
            .execute(&finding_with_path("/mnt/overlay"), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn mount_binding_unbind_action_name_is_stable_string() {
        let backend = Arc::new(MbInMemoryBackend::new());
        let action = MountBindingUnbindAction::new(
            backend,
            MbTier::Responder,
            Duration::from_secs(60),
            UnbindScope::Bind,
            true,
            "x",
        );
        assert_eq!(action.name(), "mount_binding_unbind");
    }

    // ---------------------------- ProcessTreeFreezeAction (SDD-072 MS2)

    use selfdef_process_tree_freeze_backend::{
        AuthorityTier as PtfTier, InMemoryBackend as PtfInMemoryBackend, TreeScope,
    };

    #[tokio::test]
    async fn process_tree_freeze_dry_run_renders_root_pid_and_scope() {
        let backend = Arc::new(PtfInMemoryBackend::new());
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Responder,
            Duration::from_secs(900),
            TreeScope::Descendants,
            true,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("900s"));
        assert!(outcome.notes.contains("Descendants"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn process_tree_freeze_applies_real_freeze_when_not_dry_run() {
        let backend = Arc::new(PtfInMemoryBackend::with_simulated_tree_size(5));
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Operator,
            Duration::from_secs(60 * 60),
            TreeScope::Descendants,
            true,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        assert!(outcome.notes.contains("frozen_pid_count=5"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn process_tree_freeze_skipped_when_no_pid() {
        let backend = Arc::new(PtfInMemoryBackend::new());
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Responder,
            Duration::from_secs(60),
            TreeScope::Descendants,
            true,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn process_tree_freeze_propagates_authority_insufficient() {
        let backend = Arc::new(PtfInMemoryBackend::new());
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Autonomous,
            Duration::from_secs(60 * 60),
            TreeScope::Descendants,
            true,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn process_tree_freeze_pid_one_refused() {
        let backend = Arc::new(PtfInMemoryBackend::new());
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Operator,
            Duration::from_secs(60),
            TreeScope::Descendants,
            true,
            "test",
        );
        let err = action
            .execute(&finding_with_pid(1), false)
            .await
            .expect_err("pid 1 (init) must be refused");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn process_tree_freeze_scoped_strict_descendants() {
        let backend = Arc::new(PtfInMemoryBackend::with_simulated_tree_size(20));
        let action = ProcessTreeFreezeAction::new(
            backend.clone(),
            PtfTier::Operator,
            Duration::from_secs(60),
            TreeScope::StrictDescendants,
            true,
            "fork-bomb",
        );
        let outcome = action
            .execute(&finding_with_pid(9090), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("frozen_pid_count=20"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[test]
    fn process_tree_freeze_action_name_is_stable_string() {
        let backend = Arc::new(PtfInMemoryBackend::new());
        let action = ProcessTreeFreezeAction::new(
            backend,
            PtfTier::Responder,
            Duration::from_secs(60),
            TreeScope::Descendants,
            true,
            "x",
        );
        assert_eq!(action.name(), "process_tree_freeze");
    }

    // -------------------------- SocketFdRevocationAction (SDD-073 MS2)

    use selfdef_socket_fd_revocation_backend::{
        AuthorityTier as SfrTier, InMemoryBackend as SfrInMemoryBackend, SocketProtocol,
    };

    fn finding_with_pid_and_fd(pid: i32, fd: i32) -> Event {
        let mut event = finding_with_pid(pid);
        event.metadata.profiles.push(format!("socket_fd:{fd}"));
        event
    }

    #[tokio::test]
    async fn socket_fd_revocation_dry_run_renders_pid_fd_and_protocol() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Responder,
            Duration::from_secs(900),
            SocketProtocol::Tcp,
            None,
            "test-responder",
        );
        let outcome = action
            .execute(&finding_with_pid_and_fd(4321, 17), true)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("fd 17"));
        assert!(outcome.notes.contains("Tcp"));
        assert!(outcome.notes.contains("900s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn socket_fd_revocation_applies_real_revoke_when_not_dry_run() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Operator,
            Duration::from_secs(30 * 60),
            SocketProtocol::Tcp,
            None,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid_and_fd(7777, 42), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        assert!(outcome.notes.contains("fd 42"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn socket_fd_revocation_skipped_when_no_pid() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Responder,
            Duration::from_secs(60),
            SocketProtocol::Tcp,
            None,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn socket_fd_revocation_skipped_when_no_fd_marker() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Responder,
            Duration::from_secs(60),
            SocketProtocol::Tcp,
            None,
            "test",
        );
        // finding_with_pid alone — no socket_fd:N profile marker.
        let outcome = action
            .execute(&finding_with_pid(1234), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn socket_fd_revocation_propagates_authority_insufficient() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Autonomous,
            Duration::from_secs(30 * 60),
            SocketProtocol::Tcp,
            None,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid_and_fd(8888, 9), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn socket_fd_revocation_inode_race_yields_stale_handle() {
        // Backend's current inode is 999; action passes expected=100
        // → Stale handle, NOT counted as active.
        let backend = Arc::new(SfrInMemoryBackend::with_simulated_current_inode(999));
        let action = SocketFdRevocationAction::new(
            backend.clone(),
            SfrTier::Operator,
            Duration::from_secs(60),
            SocketProtocol::Tcp,
            Some(100),
            "race-check",
        );
        let outcome = action
            .execute(&finding_with_pid_and_fd(9090, 5), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("Stale"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[test]
    fn socket_fd_revocation_action_name_is_stable_string() {
        let backend = Arc::new(SfrInMemoryBackend::new());
        let action = SocketFdRevocationAction::new(
            backend,
            SfrTier::Responder,
            Duration::from_secs(60),
            SocketProtocol::Tcp,
            None,
            "x",
        );
        assert_eq!(action.name(), "socket_fd_revocation");
    }

    // ----------------------------- ProcessEnvScrubAction (SDD-074 MS2)

    use selfdef_process_env_scrub_backend::{
        AuthorityTier as PesTier, InMemoryBackend as PesInMemoryBackend, ScrubSignal,
    };

    #[tokio::test]
    async fn process_env_scrub_dry_run_renders_vars_and_signal() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Responder,
            Duration::from_secs(900),
            vec!["AWS_SECRET_ACCESS_KEY".into(), "DB_PASSWORD".into()],
            ScrubSignal::Sigusr2,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(outcome.notes.contains("Sigusr2"));
        assert!(outcome.notes.contains("900s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn process_env_scrub_applies_real_scrub_when_not_dry_run() {
        let backend = Arc::new(PesInMemoryBackend::with_simulated_vars_matched(2));
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Operator,
            Duration::from_secs(60 * 60),
            vec!["A".into(), "B".into(), "C".into()],
            ScrubSignal::Sigusr2,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        // 2 of 3 requested vars actually matched.
        assert!(outcome.notes.contains("scrubbed 2 vars"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn process_env_scrub_skipped_when_no_pid() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Responder,
            Duration::from_secs(60),
            vec!["X".into()],
            ScrubSignal::None,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn process_env_scrub_skipped_when_no_vars_configured() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Operator,
            Duration::from_secs(60),
            vec![], // empty
            ScrubSignal::None,
            "test",
        );
        let outcome = action
            .execute(&finding_with_pid(1234), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn process_env_scrub_propagates_authority_insufficient() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Autonomous,
            Duration::from_secs(60 * 60),
            vec!["X".into()],
            ScrubSignal::Sigusr2,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn process_env_scrub_pid_one_refused() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Operator,
            Duration::from_secs(60),
            vec!["X".into()],
            ScrubSignal::None,
            "test",
        );
        let err = action
            .execute(&finding_with_pid(1), false)
            .await
            .expect_err("pid 1 (init) must be refused");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn process_env_scrub_no_match_yields_no_match_handle() {
        let backend = Arc::new(PesInMemoryBackend::with_simulated_vars_matched(0));
        let action = ProcessEnvScrubAction::new(
            backend.clone(),
            PesTier::Operator,
            Duration::from_secs(60),
            vec!["X".into()],
            ScrubSignal::None,
            "no-match",
        );
        let outcome = action
            .execute(&finding_with_pid(9090), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("NoMatch"));
        assert!(outcome.notes.contains("scrubbed 0 vars"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[test]
    fn process_env_scrub_action_name_is_stable_string() {
        let backend = Arc::new(PesInMemoryBackend::new());
        let action = ProcessEnvScrubAction::new(
            backend,
            PesTier::Responder,
            Duration::from_secs(60),
            vec!["X".into()],
            ScrubSignal::Sigusr2,
            "x",
        );
        assert_eq!(action.name(), "process_env_scrub");
    }

    // ---------------------------------- CapabilityDropAction (SDD-075 MS2)

    use selfdef_capability_drop_backend::{
        AuthorityTier as CdrTier, CapScope, InMemoryBackend as CdrInMemoryBackend,
    };

    #[tokio::test]
    async fn capability_drop_dry_run_renders_caps_pid_and_scope() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Responder,
            Duration::from_secs(900),
            vec!["CAP_NET_ADMIN".into(), "CAP_SYS_PTRACE".into()],
            CapScope::AllSets,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("CAP_NET_ADMIN"));
        assert!(outcome.notes.contains("AllSets"));
        assert!(outcome.notes.contains("900s"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn capability_drop_applies_real_drop_when_not_dry_run() {
        let backend = Arc::new(CdrInMemoryBackend::with_simulated_caps_held(2));
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Operator,
            Duration::from_secs(60 * 60),
            vec![
                "CAP_NET_ADMIN".into(),
                "CAP_SYS_PTRACE".into(),
                "CAP_BPF".into(),
            ],
            CapScope::AllSets,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        // simulated 2 of 3 held → "dropped 2 caps"
        assert!(outcome.notes.contains("dropped 2 caps"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn capability_drop_skipped_when_no_pid() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Responder,
            Duration::from_secs(60),
            vec!["CAP_NET_ADMIN".into()],
            CapScope::AllSets,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn capability_drop_skipped_when_no_caps_configured() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Operator,
            Duration::from_secs(60),
            vec![], // empty
            CapScope::AllSets,
            "test",
        );
        let outcome = action
            .execute(&finding_with_pid(1234), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn capability_drop_rejects_typo_in_action_config() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Operator,
            Duration::from_secs(60),
            vec!["CAP_NET_ADMIN".into(), "CAP_FROBNICATE".into()],
            CapScope::AllSets,
            "typo-test",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("unknown cap in action config must error pre-roundtrip");
        let ActionError::Exec(msg) = &err else {
            panic!("expected Exec error, got {err:?}");
        };
        assert!(msg.contains("CAP_FROBNICATE"), "got: {msg}");
    }

    #[tokio::test]
    async fn capability_drop_propagates_authority_insufficient() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Autonomous,
            Duration::from_secs(60 * 60),
            vec!["CAP_NET_ADMIN".into()],
            CapScope::AllSets,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn capability_drop_pid_one_refused() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Operator,
            Duration::from_secs(60),
            vec!["CAP_NET_ADMIN".into()],
            CapScope::AllSets,
            "test",
        );
        let err = action
            .execute(&finding_with_pid(1), false)
            .await
            .expect_err("pid 1 (init) must be refused");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn capability_drop_redundant_yields_redundant_handle() {
        let backend = Arc::new(CdrInMemoryBackend::with_simulated_caps_held(0));
        let action = CapabilityDropAction::new(
            backend.clone(),
            CdrTier::Operator,
            Duration::from_secs(60),
            vec!["CAP_NET_ADMIN".into()],
            CapScope::AllSets,
            "stale-awareness",
        );
        let outcome = action
            .execute(&finding_with_pid(9090), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("Redundant"));
        assert!(outcome.notes.contains("dropped 0 caps"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[test]
    fn capability_drop_action_name_is_stable_string() {
        let backend = Arc::new(CdrInMemoryBackend::new());
        let action = CapabilityDropAction::new(
            backend,
            CdrTier::Responder,
            Duration::from_secs(60),
            vec!["CAP_NET_ADMIN".into()],
            CapScope::AllSets,
            "x",
        );
        assert_eq!(action.name(), "capability_drop");
    }

    // ---------------------------- KernelKeyringEvictionAction (SDD-076 MS2)

    use selfdef_kernel_keyring_eviction_backend::{
        AuthorityTier as KkeTier, EvictionScope, InMemoryBackend as KkeInMemoryBackend,
    };

    #[tokio::test]
    async fn kernel_keyring_eviction_dry_run_renders_specs_and_scope() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Responder,
            Duration::from_secs(900),
            vec![
                "user:krb5cc/uid=1000".into(),
                "logon:dm-crypt:luks-xyz".into(),
            ],
            EvictionScope::Invalidate,
            "test-responder",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("2 key(s)"));
        assert!(outcome.notes.contains("user:krb5cc"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn kernel_keyring_eviction_evicts_each_spec() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Operator,
            Duration::from_secs(60 * 30),
            vec!["user:s1".into(), "user:s2".into(), "0xdeadbeef".into()],
            EvictionScope::Invalidate,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("evicted 3 kernel keys"));
        assert_eq!(backend.active_count().await, 3);
    }

    #[tokio::test]
    async fn kernel_keyring_eviction_not_found_aggregates() {
        let backend = Arc::new(KkeInMemoryBackend::with_simulated_keys_evicted(0));
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Operator,
            Duration::from_secs(60),
            vec!["user:gone-1".into(), "user:gone-2".into()],
            EvictionScope::Invalidate,
            "stale-awareness",
        );
        let outcome = action
            .execute(&finding_with_pid(9090), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("evicted 0 kernel keys"));
        assert!(outcome.notes.contains("2 NotFound"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn kernel_keyring_eviction_skipped_when_no_specs() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Operator,
            Duration::from_secs(60),
            vec![],
            EvictionScope::Invalidate,
            "test",
        );
        let outcome = action
            .execute(&finding_with_pid(1234), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn kernel_keyring_eviction_unparseable_spec_propagates_error() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Operator,
            Duration::from_secs(60),
            vec!["unknown_type:foo".into()],
            EvictionScope::Invalidate,
            "typo",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("unparseable spec must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn kernel_keyring_eviction_propagates_authority_insufficient() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend.clone(),
            KkeTier::Autonomous,
            Duration::from_secs(60 * 60),
            vec!["user:test".into()],
            EvictionScope::Invalidate,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[test]
    fn kernel_keyring_eviction_action_name_is_stable_string() {
        let backend = Arc::new(KkeInMemoryBackend::new());
        let action = KernelKeyringEvictionAction::new(
            backend,
            KkeTier::Responder,
            Duration::from_secs(60),
            vec!["user:test".into()],
            EvictionScope::Invalidate,
            "x",
        );
        assert_eq!(action.name(), "kernel_keyring_eviction");
    }

    // ---------------------------- ApparmorProfilePivotAction (SDD-077 MS2)

    use selfdef_apparmor_profile_pivot_backend::{
        AuthorityTier as AppTier, InMemoryBackend as AppInMemoryBackend, PivotScope,
    };

    #[tokio::test]
    async fn apparmor_profile_pivot_dry_run_renders_profile_and_scope() {
        let backend = Arc::new(AppInMemoryBackend::with_original_profile("firefox"));
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Operator,
            Duration::from_secs(900),
            "selfdef-quarantine-strict",
            PivotScope::Profile,
            "test-operator",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("4321"));
        assert!(outcome.notes.contains("selfdef-quarantine-strict"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_pivots_the_pid() {
        let backend = Arc::new(AppInMemoryBackend::with_original_profile("nginx"));
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Operator,
            Duration::from_secs(60 * 30),
            "selfdef-quarantine-strict",
            PivotScope::Profile,
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("7777"));
        assert!(outcome.notes.contains("nginx"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_skipped_without_pid() {
        let backend = Arc::new(AppInMemoryBackend::new());
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Operator,
            Duration::from_secs(60),
            "selfdef-quarantine-strict",
            PivotScope::Profile,
            "test",
        );
        let outcome = action.execute(&finding_without_pid(), false).await.unwrap();
        assert_eq!(outcome.status, Status::Skipped);
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_no_target_when_forced() {
        let backend =
            Arc::new(AppInMemoryBackend::with_original_profile("firefox").force_no_target());
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Autonomous,
            Duration::from_secs(60),
            "selfdef-observe-only",
            PivotScope::Profile,
            "test",
        );
        let outcome = action
            .execute(&finding_with_pid(1234), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(matches!(outcome.status, Status::Success));
        assert!(outcome.notes.contains("NoTarget"));
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_invalid_profile_propagates_error() {
        let backend = Arc::new(AppInMemoryBackend::new());
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Operator,
            Duration::from_secs(60),
            "name with space",
            PivotScope::Profile,
            "typo",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("invalid profile name must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_propagates_authority_insufficient() {
        let backend = Arc::new(AppInMemoryBackend::new());
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Autonomous,
            Duration::from_secs(60 * 60),
            "selfdef-observe-only",
            PivotScope::Profile,
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn apparmor_profile_pivot_sacrosanct_pid_propagates() {
        let backend = Arc::new(AppInMemoryBackend::new());
        let action = ApparmorProfilePivotAction::new(
            backend.clone(),
            AppTier::Operator,
            Duration::from_secs(60),
            "selfdef-quarantine-strict",
            PivotScope::Profile,
            "x",
        );
        let err = action
            .execute(&finding_with_pid(1), false)
            .await
            .expect_err("pid 1 must propagate as error");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[test]
    fn apparmor_profile_pivot_action_name_is_stable_string() {
        let backend = Arc::new(AppInMemoryBackend::new());
        let action = ApparmorProfilePivotAction::new(
            backend,
            AppTier::Responder,
            Duration::from_secs(60),
            "selfdef-quarantine-strict",
            PivotScope::Profile,
            "x",
        );
        assert_eq!(action.name(), "apparmor_profile_pivot");
    }

    // ----------------------------- BpfMapElementClearAction (SDD-078 MS2)

    use selfdef_bpf_map_element_clear_backend::{
        AuthorityTier as BmcTier, ClearScope as BmcScope, InMemoryBackend as BmcInMemoryBackend,
    };

    #[tokio::test]
    async fn bpf_map_element_clear_dry_run_renders_spec_and_scope() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(900),
            "/sys/fs/bpf/ip_allow_list",
            BmcScope::Element,
            Some("0a000001".to_string()),
            "test-operator",
        );
        let outcome = action.execute(&finding_with_pid(4321), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
        assert!(outcome.notes.contains("ip_allow_list"));
        assert!(outcome.notes.contains("0a000001"));
        assert_eq!(backend.active_count().await, 0);
    }

    #[tokio::test]
    async fn bpf_map_element_clear_element_scope_executes() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(60 * 30),
            "/sys/fs/bpf/ip_allow_list",
            BmcScope::Element,
            Some("0a000001".to_string()),
            "operator-cli",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("cleared 1 BPF map element"));
        assert_eq!(backend.active_count().await, 1);
    }

    #[tokio::test]
    async fn bpf_map_element_clear_all_scope_under_operator() {
        let backend = Arc::new(BmcInMemoryBackend::with_simulated_elements_cleared(17));
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(60 * 30),
            "name:poisoned",
            BmcScope::All,
            None,
            "wipe-all",
        );
        let outcome = action
            .execute(&finding_with_pid(7777), false)
            .await
            .unwrap();
        assert_eq!(outcome.status, Status::Success);
        assert!(outcome.notes.contains("cleared 17 BPF map element"));
    }

    #[tokio::test]
    async fn bpf_map_element_clear_unparseable_spec_propagates() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(60),
            "no-prefix",
            BmcScope::Element,
            Some("00".to_string()),
            "typo",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("unparseable spec must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn bpf_map_element_clear_invalid_key_hex_propagates() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(60),
            "/sys/fs/bpf/x",
            BmcScope::Element,
            Some("zz".to_string()),
            "typo",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("invalid key hex must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn bpf_map_element_clear_element_scope_without_key_propagates() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Operator,
            Duration::from_secs(60),
            "/sys/fs/bpf/x",
            BmcScope::Element,
            None,
            "missing key",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("element scope without key must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn bpf_map_element_clear_all_scope_low_tier_propagates() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Responder,
            Duration::from_secs(60),
            "/sys/fs/bpf/x",
            BmcScope::All,
            None,
            "low-tier wipe",
        );
        let err = action
            .execute(&finding_with_pid(1234), false)
            .await
            .expect_err("all-scope under Responder must propagate via backend");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[tokio::test]
    async fn bpf_map_element_clear_propagates_authority_insufficient() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend.clone(),
            BmcTier::Autonomous,
            Duration::from_secs(60 * 60),
            "/sys/fs/bpf/x",
            BmcScope::Element,
            Some("00".to_string()),
            "auto",
        );
        let err = action
            .execute(&finding_with_pid(8888), false)
            .await
            .expect_err("over-tier must propagate");
        assert!(matches!(err, ActionError::Exec(_)));
    }

    #[test]
    fn bpf_map_element_clear_action_name_is_stable_string() {
        let backend = Arc::new(BmcInMemoryBackend::new());
        let action = BpfMapElementClearAction::new(
            backend,
            BmcTier::Responder,
            Duration::from_secs(60),
            "/sys/fs/bpf/x",
            BmcScope::Element,
            Some("00".to_string()),
            "x",
        );
        assert_eq!(action.name(), "bpf_map_element_clear");
    }
}
