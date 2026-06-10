//! systemd-journald → bus collector.
//!
//! Two input modes:
//! - **subprocess** (default for production): spawns
//!   `journalctl --output=json --follow --no-pager` and reads its stdout.
//! - **file** (for tests / replay): tails a JSON-lines file written by an
//!   external pipeline (e.g. `journalctl ... | tee /var/log/journal.jsonl`).
//!
//! Journal entries are emitted as generic OCSF events; classification is
//! done downstream by Sigma rules. Common identifiers (`sshd`, `sudo`) get
//! mapped to a more specific class for ergonomic rule writing.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// First delay before respawning a `journalctl` follower that exited, and the
/// ceiling the delay backs off to. `journalctl --follow` exits when journald
/// restarts or its process is killed; respawning (instead of giving up) keeps
/// the collector alive across those transient outages, and the exponential cap
/// stops a permanently-failing follower from respawn-storming.
const MIN_RESPAWN_BACKOFF: Duration = Duration::from_millis(100);
const MAX_RESPAWN_BACKOFF: Duration = Duration::from_secs(30);

/// Double the respawn backoff, capped at [`MAX_RESPAWN_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_RESPAWN_BACKOFF)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    Start,
    End,
}

impl ReadFrom {
    pub fn parse(s: &str) -> Self {
        match s {
            "start" => Self::Start,
            _ => Self::End,
        }
    }
}

#[derive(Debug, Clone)]
pub enum InputMode {
    /// Spawn `journalctl --output=json --follow --no-pager [-u UNIT...]`
    Journalctl { binary: PathBuf, units: Vec<String> },
    /// Tail a JSON-lines file (for tests / external pipelines).
    File { path: PathBuf, read_from: ReadFrom },
}

#[derive(Debug, Error)]
pub enum JournaldError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journalctl exited with status {0}")]
    JournalctlExit(i32),
}

pub struct JournaldCollector {
    mode: InputMode,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
}

impl JournaldCollector {
    pub fn new(mode: InputMode, publisher: Publisher, host_tag: String) -> Self {
        Self {
            mode,
            publisher,
            host_tag,
            sequence: AtomicU64::new(0),
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), JournaldError> {
        match &self.mode {
            InputMode::File { path, read_from } => self.run_file(path, *read_from, shutdown).await,
            InputMode::Journalctl { binary, units } => {
                self.run_journalctl(binary, units, shutdown).await
            }
        }
    }

    async fn run_file(
        &self,
        path: &PathBuf,
        read_from: ReadFrom,
        shutdown: CancellationToken,
    ) -> Result<(), JournaldError> {
        info!(path = %path.display(), "journald collector (file mode) starting");
        for _ in 0..10 {
            if path.exists() {
                break;
            }
            if shutdown.is_cancelled() {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        let mut file = tokio::fs::File::open(path).await?;
        if read_from == ReadFrom::End {
            file.seek(std::io::SeekFrom::End(0)).await?;
        }
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        // Buffers a partial line so a write racing the reader can't split+drop.
        let mut pending = String::new();
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            buf.clear();
            let n = tokio::select! {
                r = reader.read_line(&mut buf) => r?,
                () = shutdown.cancelled() => return Ok(()),
            };
            if n == 0 {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            pending.push_str(&buf);
            for line in selfdef_collector_util::drain_complete_lines(&mut pending) {
                self.process_line(&line);
            }
        }
    }

    async fn run_journalctl(
        &self,
        binary: &PathBuf,
        units: &[String],
        shutdown: CancellationToken,
    ) -> Result<(), JournaldError> {
        info!(binary = %binary.display(), ?units, "journald collector (subprocess mode) starting");

        // Respawn loop. `journalctl --follow` exits when journald restarts or
        // its process dies; previously that returned Ok(()) and the spawned task
        // simply ended — the daemon does NOT watch collector tasks while it runs
        // (it only joins them at shutdown), so the collector silently went dead
        // and the IPS ran blind to journald (auth/ssh/sudo) until a daemon
        // restart. Respawn the follower with an exponential backoff so a
        // transient outage doesn't permanently disable the collector; the only
        // clean exits are a shutdown signal (Ok) or a failure to even spawn the
        // process (Err — a permanent fault worth surfacing loudly).
        let mut backoff = MIN_RESPAWN_BACKOFF;
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let mut cmd = Command::new(binary);
            cmd.arg("--output=json")
                .arg("--follow")
                .arg("--no-pager")
                .stdout(Stdio::piped());
            for u in units {
                cmd.arg("-u").arg(u);
            }
            // A spawn failure (e.g. the journalctl binary is missing) is a
            // permanent configuration fault — surface it rather than
            // respawn-storming on something that can never succeed.
            let mut child = cmd.spawn()?;
            let stdout = child.stdout.take().expect("stdout was piped");
            let mut reader = BufReader::new(stdout).lines();

            // Stream this follower until it closes its stdout or we're shut down.
            let mut delivered = false;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        let _ = child.kill().await;
                        return Ok(());
                    }
                    next = reader.next_line() => match next {
                        Ok(Some(line)) => {
                            self.process_line(&line);
                            delivered = true;
                        }
                        Ok(None) => break, // journalctl closed stdout (it exited)
                        Err(e) => {
                            // A read error usually means the pipe broke because
                            // journalctl died — treat it like a close and respawn.
                            warn!(error = %e, "journald: error reading journalctl stdout");
                            break;
                        }
                    }
                }
            }

            // The follower exited. Reap it, then back off before respawning. A
            // follower that actually delivered events ran healthily, so reset the
            // backoff — a flapping journald still recovers quickly after a good run.
            let _ = child.kill().await;
            if delivered {
                backoff = MIN_RESPAWN_BACKOFF;
            }
            warn!(
                backoff_ms = backoff.as_millis() as u64,
                "journalctl follower exited; respawning after backoff"
            );
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = tokio::time::sleep(backoff) => {}
            }
            backoff = next_backoff(backoff);
        }
    }

    fn process_line(&self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, line, "ignored unparseable journald line");
                return;
            }
        };
        let event = self.build_event(value);
        self.publisher.publish_lossy(event);
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn build_event(&self, raw: serde_json::Value) -> Event {
        let seq = self.next_sequence();
        let ident = raw
            .get("SYSLOG_IDENTIFIER")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let priority = raw
            .get("PRIORITY")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(6);
        let message = raw
            .get("MESSAGE")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Classify by syslog identifier where useful, otherwise generic.
        let (class_uid, activity_id) = match ident {
            "sshd" => (ClassUid::SSH_ACTIVITY, 1),
            "sudo" => (ClassUid::AUTHENTICATION, 1),
            "systemd-logind" => (ClassUid::AUTHORIZE_SESSION, 1),
            _ => (ClassUid::new(0), 0),
        };

        let severity_id = match priority {
            0..=2 => SeverityId::Critical,
            3 => SeverityId::High,
            4 => SeverityId::Medium,
            5 => SeverityId::Low,
            _ => SeverityId::Informational,
        };

        // Optional actor.user from _UID.
        let actor = raw
            .get("_UID")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u32>().ok())
            .map(|uid| Actor {
                user: Some(User {
                    uid: Some(uid),
                    ..User::default()
                }),
                ..Actor::default()
            });

        let mut ev = Event::new(
            class_uid,
            activity_id,
            severity_id,
            &self.host_tag,
            "journald",
            seq,
        )
        .with_raw(raw);
        if !message.is_empty() {
            ev = ev.with_message(message);
        }
        if let Some(a) = actor {
            ev = ev.with_actor(a);
        }
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(ReadFrom::parse("start"), ReadFrom::Start);
        assert_eq!(ReadFrom::parse("end"), ReadFrom::End);
        assert_eq!(ReadFrom::parse(""), ReadFrom::End);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let b0 = MIN_RESPAWN_BACKOFF;
        assert_eq!(next_backoff(b0), b0 * 2);
        // repeated doubling saturates at the ceiling and stays there.
        let mut b = b0;
        for _ in 0..20 {
            b = next_backoff(b);
        }
        assert_eq!(b, MAX_RESPAWN_BACKOFF);
        assert_eq!(next_backoff(MAX_RESPAWN_BACKOFF), MAX_RESPAWN_BACKOFF);
    }

    #[tokio::test]
    async fn journalctl_follower_respawns_after_exit() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // A fake `journalctl` that ignores its args, emits ONE journal line, and
        // exits — modelling a `journalctl --follow` that quits when journald
        // restarts. A single spawn publishes exactly one event; seeing several
        // proves the collector respawned the follower instead of going dead.
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-journalctl");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            writeln!(f, "#!/bin/sh").unwrap();
            writeln!(
                f,
                "printf '%s\\n' '{{\"MESSAGE\":\"hello\",\"PRIORITY\":\"6\"}}'"
            )
            .unwrap();
            writeln!(f, "exit 0").unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let bus = selfdef_bus::Bus::new(64);
        let mut sub = bus.subscribe();
        let collector = JournaldCollector::new(
            InputMode::Journalctl {
                binary: script.clone(),
                units: vec![],
            },
            bus.publisher(),
            "test-host".into(),
        );
        let token = CancellationToken::new();
        let run_token = token.clone();
        let handle = tokio::spawn(async move { collector.run(run_token).await });

        // With the 100ms respawn backoff we should see several events within a
        // couple of seconds; require at least two (one per follower spawn).
        let mut count = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while count < 2 && tokio::time::Instant::now() < deadline {
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(1), sub.recv()).await {
                count += 1;
            }
        }
        token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            count >= 2,
            "expected >= 2 events from respawned followers, got {count}"
        );
    }
}
