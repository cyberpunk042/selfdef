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
}
