//! Tetragon JSON → bus collector.
//!
//! Tails a file containing Tetragon's JSON output (typically produced by
//! `tetra getevents -o json > /var/log/tetragon/events.json`, or via the
//! Tetragon export-stdout config).
//!
//! M6 recognizes the two event kinds most useful for selfdef rules:
//! - `process_exec` → `PROCESS_ACTIVITY` / Launch
//! - `process_kprobe` → typically `FILE_SYSTEM_ACTIVITY` / Open when the
//!   underlying function is `security_file_open` (Tetragon's standard
//!   sensitive-file watcher pattern).
//!
//! All other event kinds are emitted as generic events with the raw payload
//! preserved — Sigma rules can match against `raw.*` if interested.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

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

#[derive(Debug, Error)]
pub enum TetragonError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct TetragonCollector {
    input_path: PathBuf,
    read_from: ReadFrom,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
}

impl TetragonCollector {
    pub fn new(
        input_path: PathBuf,
        read_from: ReadFrom,
        publisher: Publisher,
        host_tag: String,
    ) -> Self {
        Self {
            input_path,
            read_from,
            publisher,
            host_tag,
            sequence: AtomicU64::new(0),
        }
    }

    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), TetragonError> {
        info!(path = %self.input_path.display(), "tetragon collector starting");
        wait_for_file(&self.input_path, &shutdown).await;

        let mut file = tokio::fs::File::open(&self.input_path).await?;
        if self.read_from == ReadFrom::End {
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

    fn process_line(&self, line: &str) {
        if let Some(event) = self.translate_line(line) {
            self.publisher.publish_lossy(event);
        }
    }

    /// SDD-005 Test-6: translate a single Tetragon JSON line into a
    /// `selfdef_core::Event` without touching the bus. Returns
    /// `None` for empty input or unparseable JSON (those are
    /// soft-skipped with a debug log; callers can distinguish from
    /// the structured-status flow by the `None`). External
    /// translation tests use this surface to exercise the
    /// collector in isolation.
    pub fn translate_line(&self, line: &str) -> Option<Event> {
        if line.is_empty() {
            return None;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                debug!(error = %e, "ignored unparseable tetragon line");
                return None;
            }
        };
        Some(if let Some(exec) = v.get("process_exec") {
            self.build_process_exec(exec, &v)
        } else if let Some(kp) = v.get("process_kprobe") {
            self.build_process_kprobe(kp, &v)
        } else if let Some(exit) = v.get("process_exit") {
            self.build_process_exit(exit, &v)
        } else {
            self.build_generic(&v)
        })
    }

    fn next_seq(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn build_process_exec(&self, exec: &serde_json::Value, full: &serde_json::Value) -> Event {
        let proc = exec
            .get("process")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let parent = exec.get("parent");
        let pid = proc.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let binary = proc.get("binary").and_then(|v| v.as_str()).unwrap_or("");
        let arguments = proc.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
        let uid = proc.get("uid").and_then(|v| v.as_u64()).map(|n| n as u32);
        let parent_pid = parent
            .and_then(|p| p.get("pid"))
            .and_then(|v| v.as_i64())
            .map(|n| n as i32);

        let process = Process {
            pid,
            parent_pid,
            name: Some(binary.rsplit('/').next().unwrap_or(binary).to_string()),
            path: if binary.is_empty() {
                None
            } else {
                Some(binary.to_string())
            },
            cmdline: if arguments.is_empty() {
                Some(binary.to_string())
            } else {
                Some(format!("{binary} {arguments}"))
            },
            user: uid.map(|u| User {
                uid: Some(u),
                ..User::default()
            }),
            ..Process::default()
        };

        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            1, // Launch
            SeverityId::Informational,
            &self.host_tag,
            "tetragon",
            self.next_seq(),
        )
        .with_process(process)
        .with_message(format!("exec: {binary} {arguments}"))
        .with_raw(full.clone())
    }

    fn build_process_kprobe(&self, kp: &serde_json::Value, full: &serde_json::Value) -> Event {
        let function = kp
            .get("function_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let proc = kp.get("process");
        let pid = proc
            .and_then(|p| p.get("pid"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let binary = proc
            .and_then(|p| p.get("binary"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Extract file path from args (typical kprobe shape for security_file_open).
        let file_path = kp.get("args").and_then(|a| a.as_array()).and_then(|arr| {
            arr.iter().find_map(|item| {
                item.get("file_arg")
                    .and_then(|f| f.get("path"))
                    .and_then(|p| p.as_str())
                    .map(str::to_owned)
            })
        });

        // Choose class by function name.
        let (class, activity) = if function.contains("file_open") || function.contains("inode") {
            (ClassUid::FILE_SYSTEM_ACTIVITY, 14) // Open
        } else if function.contains("socket") || function.contains("connect") {
            (ClassUid::NETWORK_ACTIVITY, 1)
        } else {
            (ClassUid::KERNEL_ACTIVITY, 0)
        };

        let mut ev = Event::new(
            class,
            activity,
            SeverityId::Informational,
            &self.host_tag,
            "tetragon",
            self.next_seq(),
        )
        .with_message(format!("kprobe: {function}"))
        .with_raw(tetragon_raw(kp, full));

        if let Some(p) = file_path {
            ev = ev.with_file(File::at_path(p));
        }
        if pid != 0 {
            ev = ev.with_process(Process {
                pid,
                path: if binary.is_empty() {
                    None
                } else {
                    Some(binary.to_string())
                },
                ..Process::default()
            });
        }
        ev
    }

    fn build_process_exit(&self, _exit: &serde_json::Value, full: &serde_json::Value) -> Event {
        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            2, // Terminate
            SeverityId::Informational,
            &self.host_tag,
            "tetragon",
            self.next_seq(),
        )
        .with_raw(full.clone())
    }

    fn build_generic(&self, full: &serde_json::Value) -> Event {
        Event::new(
            ClassUid::new(0),
            0,
            SeverityId::Informational,
            &self.host_tag,
            "tetragon",
            self.next_seq(),
        )
        .with_raw(full.clone())
    }
}

/// Build the `Event.raw` JSON for a process_kprobe event so sigma rules
/// can match on the Tetragon-specific fields (policy name, action,
/// function name, namespace) without re-walking the upstream JSON
/// shape. The original Tetragon payload is preserved under the same
/// keys it had on the wire; the structured fields go under a stable
/// `tetragon.*` subobject. Closes F-2026-001 / SDD-001 D-1.
fn tetragon_raw(kp: &serde_json::Value, full: &serde_json::Value) -> serde_json::Value {
    let mut raw = full.clone();
    let policy_name = kp.get("policy_name").and_then(|v| v.as_str()).unwrap_or("");
    let policy_namespace = kp
        .get("policy_namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let action = kp.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let function_name = kp
        .get("function_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let subobj = serde_json::json!({
        "policy_name": policy_name,
        "policy_namespace": policy_namespace,
        "action": action,
        "function_name": function_name,
    });
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("tetragon".into(), subobj);
    }
    raw
}

async fn wait_for_file(path: &Path, shutdown: &CancellationToken) {
    for _ in 0..10 {
        if path.exists() {
            return;
        }
        if shutdown.is_cancelled() {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_bus::Bus;

    #[tokio::test(flavor = "current_thread")]
    async fn process_exec_becomes_event() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();
        let coll = TetragonCollector::new(
            std::path::PathBuf::from("/dev/null"),
            ReadFrom::End,
            pub_,
            "h".into(),
        );
        let line = r#"{"process_exec":{"process":{"pid":1234,"binary":"/usr/bin/ls","arguments":"-la","uid":1000}}}"#;
        coll.process_line(line);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
            .await
            .expect("recv timed out")
            .expect("recv error");
        assert_eq!(event.class_uid, ClassUid::PROCESS_ACTIVITY);
        assert_eq!(event.activity_id, 1);
        let proc = event.process.expect("process attached");
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.name.as_deref(), Some("ls"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kprobe_security_file_open_becomes_filesystem_event() {
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();
        let coll = TetragonCollector::new(
            std::path::PathBuf::from("/dev/null"),
            ReadFrom::End,
            pub_,
            "h".into(),
        );
        let line = r#"{"process_kprobe":{"function_name":"security_file_open","process":{"pid":1,"binary":"/usr/bin/cat"},"args":[{"file_arg":{"path":"/etc/shadow"}}]}}"#;
        coll.process_line(line);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.class_uid, ClassUid::FILE_SYSTEM_ACTIVITY);
        let f = event.file.expect("file attached");
        assert_eq!(f.path.as_deref(), Some("/etc/shadow"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn process_kprobe_attaches_structured_tetragon_subobject() {
        // SDD-001 D-1: every process_kprobe event must carry a
        // stable `raw.tetragon.{policy_name,policy_namespace,
        // action,function_name}` so sigma rules can promote
        // agent-guard policy events to Findings without
        // re-walking the upstream JSON shape.
        let bus = Bus::new(16);
        let pub_ = bus.publisher();
        let mut sub = bus.subscribe();
        let coll = TetragonCollector::new(
            std::path::PathBuf::from("/dev/null"),
            ReadFrom::End,
            pub_,
            "test-host".into(),
        );
        let line = r#"{"process_kprobe":{"function_name":"security_file_open","policy_name":"selfdef-agent-etc-write-guard","policy_namespace":"","action":"Sigkill","process":{"pid":4242,"binary":"/usr/bin/sed"},"args":[{"file_arg":{"path":"/etc/shadow"}}]}}"#;
        coll.process_line(line);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), sub.recv())
            .await
            .unwrap()
            .unwrap();
        let raw = event.raw.expect("raw payload preserved");
        let tetragon = raw
            .get("tetragon")
            .expect("raw.tetragon subobject attached");
        assert_eq!(
            tetragon.get("policy_name").and_then(|v| v.as_str()),
            Some("selfdef-agent-etc-write-guard"),
        );
        assert_eq!(
            tetragon.get("action").and_then(|v| v.as_str()),
            Some("Sigkill"),
        );
        assert_eq!(
            tetragon.get("function_name").and_then(|v| v.as_str()),
            Some("security_file_open"),
        );
        // The original Tetragon payload is preserved alongside.
        assert!(raw.get("process_kprobe").is_some());
    }
}
