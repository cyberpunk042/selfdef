//! auditd → bus collector.
//!
//! Tails the audit log (or audisp input file), parses lines into typed
//! events, publishes them on the [`Publisher`]. M3 handles the most common
//! single-line user-auth records; richer parsing (multi-line SYSCALL+EXECVE,
//! anomaly types) lands in a later milestone.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

mod parser;

pub use parser::{parse_avc_decision, AuditRecord};

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_core::activity::{AuthenticationActivity, ProcessActivity};
use selfdef_core::attack::{Tactic, TechniqueRef};
use selfdef_core::category::ClassUid;
use selfdef_core::prelude::*;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Error)]
pub enum AuditdError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Where in the file to start reading.
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

pub struct AuditdCollector {
    input_path: PathBuf,
    read_from: ReadFrom,
    publisher: Publisher,
    host_tag: String,
    sequence: AtomicU64,
}

impl AuditdCollector {
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

    /// Run until `shutdown` is cancelled.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), AuditdError> {
        info!(path = %self.input_path.display(), "auditd collector starting");

        // Wait briefly for the file to appear if it's missing at startup.
        for _ in 0..10 {
            if self.input_path.exists() {
                break;
            }
            if shutdown.is_cancelled() {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        let mut file = tokio::fs::File::open(&self.input_path).await?;

        // Seek if requested.
        match self.read_from {
            ReadFrom::Start => {} // already at position 0
            ReadFrom::End => {
                file.seek(std::io::SeekFrom::End(0)).await?;
            }
        }

        let mut reader = BufReader::new(file);
        let mut buf = String::new();

        loop {
            if shutdown.is_cancelled() {
                debug!("auditd collector shutdown requested");
                return Ok(());
            }

            buf.clear();
            let n = tokio::select! {
                r = reader.read_line(&mut buf) => r?,
                () = shutdown.cancelled() => return Ok(()),
            };

            if n == 0 {
                // EOF — wait for more data.
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }

            let line = buf.trim_end();
            if line.is_empty() {
                continue;
            }

            match parser::parse_line(line) {
                Some(record) => {
                    let event = self.build_event(&record, line);
                    self.publisher.publish_lossy(event);
                }
                None => {
                    debug!(line, "ignored unparseable audit line");
                }
            }
        }
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn build_event(&self, record: &AuditRecord, raw_line: &str) -> Event {
        let seq = self.next_sequence();
        match record.kind.as_str() {
            "USER_AUTH" | "USER_LOGIN" | "USER_ACCT" => self.build_auth_event(record, seq),
            "AVC" => self.build_avc_event(record, raw_line, seq),
            _ => self.build_other_event(record, seq),
        }
    }

    fn build_auth_event(&self, record: &AuditRecord, seq: u64) -> Event {
        let success = record.get("res") == Some("success");
        let severity = if success {
            SeverityId::Informational
        } else {
            SeverityId::Medium
        };
        let status = if success {
            StatusId::Success
        } else {
            StatusId::Failure
        };

        let actor = record.get("acct").map(|name| Actor {
            user: Some(User {
                name: Some(name.to_string()),
                ..User::default()
            }),
            ..Actor::default()
        });

        let src_endpoint = record
            .get("addr")
            .or_else(|| record.get("hostname"))
            .and_then(|a| a.parse::<std::net::IpAddr>().ok())
            .map(|ip| Endpoint {
                ip: Some(ip),
                ..Endpoint::default()
            });

        let message = format!(
            "{}: {} for {} ({})",
            record.kind,
            record.get("res").unwrap_or("unknown"),
            record.get("acct").unwrap_or("?"),
            record.get("op").unwrap_or("auth"),
        );

        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);

        let mut event = Event::new(
            ClassUid::AUTHENTICATION,
            AuthenticationActivity::Logon as u32,
            severity,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(status)
        .with_message(message)
        .with_raw(raw);

        if let Some(a) = actor {
            event = event.with_actor(a);
        }
        if let Some(ep) = src_endpoint {
            event = event.with_src_endpoint(ep);
        }
        if !success {
            event = event.with_attack(TechniqueRef::brute_force());
        }
        event
    }

    /// AVC = SELinux / SMACK access-vector-cache decision. Two outcomes:
    /// `denied` (the usual operator-actionable case — high signal) and
    /// `granted` (rare; only logged when explicitly configured). Maps to
    /// ClassUid::PROCESS_ACTIVITY with `ProcessActivity::Open` because
    /// AVC fires at the security_*_open / security_*_access LSM hook
    /// point. Severity High for denied, Informational for granted.
    fn build_avc_event(&self, record: &AuditRecord, raw_line: &str, seq: u64) -> Event {
        let decision = parser::parse_avc_decision(raw_line).unwrap_or("unknown");
        let denied = decision == "denied";
        let severity = if denied { SeverityId::High } else { SeverityId::Informational };
        let status = if denied { StatusId::Failure } else { StatusId::Success };

        let comm = record.get("comm").unwrap_or("?");
        let target_name = record.get("name").unwrap_or("?");
        let tclass = record.get("tclass").unwrap_or("?");
        let scontext = record.get("scontext").unwrap_or("?");
        let tcontext = record.get("tcontext").unwrap_or("?");
        let permissive = record.get("permissive").unwrap_or("0");

        let message = format!(
            "AVC {decision}: comm={comm} target={target_name} tclass={tclass} \
             scontext={scontext} tcontext={tcontext} permissive={permissive}"
        );

        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);

        let mut event = Event::new(
            ClassUid::PROCESS_ACTIVITY,
            ProcessActivity::Open as u32,
            severity,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(status)
        .with_message(message)
        .with_raw(raw);

        if denied {
            // T1083 covers File and Directory Discovery — the most common
            // discovery vector flagged by AVC denials (denied read on
            // /etc/shadow, /proc/kcore, etc.). When tclass != file the
            // technique is approximate but still in the Discovery tactic.
            event = event.with_attack(TechniqueRef::new(
                "T1083",
                "File and Directory Discovery",
                Tactic::Discovery,
            ));
        }
        event
    }

    fn build_other_event(&self, record: &AuditRecord, seq: u64) -> Event {
        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);
        Event::new(
            ClassUid::new(0),
            0,
            SeverityId::Informational,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_message(format!("auditd record: {}", record.kind))
        .with_raw(raw)
    }
}

pub fn host_tag_from_env_or_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_from_parses_strings() {
        assert_eq!(ReadFrom::parse("start"), ReadFrom::Start);
        assert_eq!(ReadFrom::parse("end"), ReadFrom::End);
        assert_eq!(ReadFrom::parse("garbage"), ReadFrom::End); // default
    }
}
