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
#![warn(clippy::pedantic)]
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
    Journalctl {
        binary: PathBuf,
        units: Vec<String>,
    },
    /// Tail a JSON-lines file (for tests / external pipelines).
    File {
        path: PathBuf,
        read_from: ReadFrom,
    },
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
            self.process_line(buf.trim_end());
        }
    }

    async fn run_journalctl(
        &self,
        binary: &PathBuf,
        units: &[String],
        shutdown: CancellationToken,
    ) -> Result<(), JournaldError> {
        info!(binary = %binary.display(), ?units, "journald collector (subprocess mode) starting");
        let mut cmd = Command::new(binary);
        cmd.arg("--output=json")
            .arg("--follow")
            .arg("--no-pager")
            .stdout(Stdio::piped());
        for u in units {
            cmd.arg("-u").arg(u);
        }
        let mut child = cmd.spawn()?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = BufReader::new(stdout).lines();

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    let _ = child.kill().await;
                    return Ok(());
                }
                next = reader.next_line() => match next? {
                    Some(line) => self.process_line(&line),
                    None => {
                        warn!("journalctl stdout closed");
                        return Ok(());
                    }
                }
            }
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
}
