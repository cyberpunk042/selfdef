//! Event emission to a JSONL file the daemon can tail.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct EventSink {
    path: PathBuf,
    host_tag: String,
}

impl EventSink {
    pub fn open() -> anyhow::Result<Self> {
        let path = event_log_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let host_tag = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "unknown".into());
        Ok(Self { path, host_tag })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn emit(&self, event: Event) -> anyhow::Result<()> {
        let line = serde_json::to_string(&event)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // POSIX guarantees atomic short appends under PIPE_BUF (4096B) when
        // the fd is in O_APPEND mode. One Event line is well under that.
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Session opening — emitted before the real ssh is exec'd.
    pub fn session_start(
        &self,
        target: &str,
        host: &str,
        port: Option<u16>,
        user: Option<&str>,
        first_seen: bool,
    ) -> anyhow::Result<()> {
        let severity = if first_seen {
            SeverityId::Low
        } else {
            SeverityId::Informational
        };
        let mut event = Event::new(
            ClassUid::SSH_ACTIVITY,
            1, // Open
            severity,
            &self.host_tag,
            "selfdef.ssh-wrap",
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        )
        .with_message(format!(
            "ssh session opening: {target}{}",
            if first_seen {
                " (first connection — host key learned)"
            } else {
                ""
            }
        ));
        let dst = Endpoint {
            hostname: Some(host.to_string()),
            port,
            ..Endpoint::default()
        };
        event = event.with_dst_endpoint(dst);
        if let Some(u) = user {
            event = event.with_actor(Actor {
                user: Some(User {
                    name: Some(u.to_string()),
                    ..User::default()
                }),
                ..Actor::default()
            });
        }
        if first_seen {
            event = event.with_raw(serde_json::json!({
                "first_seen": true,
                "target": target,
            }));
        }
        self.emit(event)
    }

    /// Session closing — emitted after the real ssh exits.
    pub fn session_end(
        &self,
        target: &str,
        duration_secs: f64,
        exit_code: Option<i32>,
    ) -> anyhow::Result<()> {
        let severity = match exit_code {
            Some(0) => SeverityId::Informational,
            Some(_) | None => SeverityId::Low,
        };
        let mut event = Event::new(
            ClassUid::SSH_ACTIVITY,
            2, // Close
            severity,
            &self.host_tag,
            "selfdef.ssh-wrap",
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        )
        .with_message(format!(
            "ssh session ended: {target} ({duration_secs:.1}s, exit {exit_code:?})"
        ))
        .with_raw(serde_json::json!({
            "target": target,
            "duration_secs": duration_secs,
            "exit_code": exit_code,
        }));
        if let Some(c) = exit_code {
            event = event.with_status(if c == 0 {
                StatusId::Success
            } else {
                StatusId::Failure
            });
        }
        self.emit(event)
    }

    /// Policy violation — emitted when we strip a user flag conflicting
    /// with the resolved policy.
    pub fn policy_strip(&self, target: &str, stripped: &[String]) -> anyhow::Result<()> {
        if stripped.is_empty() {
            return Ok(());
        }
        let event = Event::new(
            ClassUid::DETECTION_FINDING,
            1,
            SeverityId::Low,
            &self.host_tag,
            "selfdef.ssh-wrap",
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        )
        .with_message(format!(
            "stripped {} arg(s) from ssh invocation per policy: {}",
            stripped.len(),
            stripped.join(", ")
        ))
        .with_raw(serde_json::json!({
            "target": target,
            "stripped": stripped,
        }));
        self.emit(event)
    }
}

fn event_log_path() -> anyhow::Result<PathBuf> {
    if let Some(p) = std::env::var_os("SELFDEF_SSH_EVENT_LOG") {
        return Ok(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .ok_or_else(|| anyhow::anyhow!("can't determine data dir"))?;
    Ok(base.join("selfdef").join("ssh-wrap.jsonl"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_session_event() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        // SAFETY: single-threaded test, no concurrent env mutators.
        unsafe {
            std::env::set_var("SELFDEF_SSH_EVENT_LOG", &path);
        }
        let sink = EventSink::open().unwrap();
        sink.session_start("user@host", "host", Some(22), Some("user"), false)
            .unwrap();
        sink.session_end("user@host", 1.5, Some(0)).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line must be a valid Event.
        for line in lines {
            let _: selfdef_core::Event = serde_json::from_str(line).unwrap();
        }
    }
}
