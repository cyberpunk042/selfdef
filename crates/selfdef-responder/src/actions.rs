//! Built-in [`Action`] implementations.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use selfdef_core::Event;
use selfdef_notifier::{Notifier, NotifierError};
use thiserror::Error;
use tokio::process::Command;
use tracing::debug;

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
        Self { status: Status::Success, notes: notes.into() }
    }
    pub fn dry_run(notes: impl Into<String>) -> Self {
        Self { status: Status::DryRun, notes: notes.into() }
    }
    pub fn skipped(notes: impl Into<String>) -> Self {
        Self { status: Status::Skipped, notes: notes.into() }
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
    fn name(&self) -> &'static str { "notify" }

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
    fn name(&self) -> &'static str { "snapshot_proc" }

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
            let _ = tokio::fs::write(
                dir.join("exe_link"),
                target.to_string_lossy().as_bytes(),
            )
            .await;
        }
        // cwd symlink — same treatment.
        if let Ok(target) = tokio::fs::read_link(format!("{proc_root}/cwd")).await {
            let _ = tokio::fs::write(
                dir.join("cwd_link"),
                target.to_string_lossy().as_bytes(),
            )
            .await;
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
    pub fn new() -> Self { Self }
}

impl Default for KillPidAction {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Action for KillPidAction {
    fn name(&self) -> &'static str { "kill_pid" }

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
    fn name(&self) -> &'static str { "lockdown_egress" }

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
    fn name(&self) -> &'static str { "revoke_session" }

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
            process: Some(Process { pid, ..Process::default() }),
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
        let outcome = action.execute(&finding_with_pid(99999), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
    }

    #[tokio::test]
    async fn lockdown_dry_run_doesnt_execute() {
        let action = LockdownEgressAction::new(PathBuf::from("/nonexistent/script"));
        let outcome = action.execute(&finding_without_pid(), true).await.unwrap();
        assert_eq!(outcome.status, Status::DryRun);
    }
}
