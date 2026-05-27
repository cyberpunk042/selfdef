//! auditd → bus collector.
//!
//! Tails the audit log (or audisp input file), parses lines into typed
//! events, publishes them on the [`Publisher`]. M3 handles the most common
//! single-line user-auth records; richer parsing (multi-line SYSCALL+EXECVE,
//! anomaly types) lands in a later milestone.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

mod parser;

pub use parser::{AuditRecord, parse_avc_decision, parse_execve_argv};

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

        // SDD-059 C-5 — pending SYSCALL waiting for a matching EXECVE
        // companion. The auditd subsystem emits SYSCALL + EXECVE
        // for each exec call as TWO lines correlated by msg=audit(
        // <ts>:<serial>); SYSCALL comes first. We buffer the SYSCALL
        // briefly so we can emit ONE combined event with the argv
        // extracted instead of two generic events.
        let mut pending_syscall: Option<(AuditRecord, String)> = None;

        loop {
            if shutdown.is_cancelled() {
                debug!("auditd collector shutdown requested");
                // Flush any pending SYSCALL before exit.
                if let Some((rec, line)) = pending_syscall.take() {
                    let evt = self.build_event(&rec, &line);
                    self.publisher.publish_lossy(evt);
                }
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
                    match record.kind.as_str() {
                        "SYSCALL" => {
                            // Flush any previously-pending SYSCALL
                            // (its EXECVE never arrived) as a lone
                            // generic event.
                            if let Some((prev_rec, prev_line)) = pending_syscall.take() {
                                let evt = self.build_event(&prev_rec, &prev_line);
                                self.publisher.publish_lossy(evt);
                            }
                            pending_syscall = Some((record, line.to_string()));
                        }
                        "EXECVE" => {
                            if let Some((syscall_rec, syscall_line)) = pending_syscall.take() {
                                if syscall_rec.serial == record.serial {
                                    // Pair! Emit one combined event.
                                    let evt =
                                        self.build_syscall_execve_event(&syscall_rec, &record);
                                    self.publisher.publish_lossy(evt);
                                } else {
                                    // Serial mismatch — flush the
                                    // pending SYSCALL then emit this
                                    // EXECVE as generic.
                                    let evt = self.build_event(&syscall_rec, &syscall_line);
                                    self.publisher.publish_lossy(evt);
                                    let evt2 = self.build_event(&record, line);
                                    self.publisher.publish_lossy(evt2);
                                }
                            } else {
                                // EXECVE without preceding SYSCALL
                                // (unusual but possible if we tail
                                // mid-stream) — emit as generic.
                                let evt = self.build_event(&record, line);
                                self.publisher.publish_lossy(evt);
                            }
                        }
                        _ => {
                            // Any other kind: flush pending then
                            // handle this record normally.
                            if let Some((prev_rec, prev_line)) = pending_syscall.take() {
                                let evt = self.build_event(&prev_rec, &prev_line);
                                self.publisher.publish_lossy(evt);
                            }
                            let event = self.build_event(&record, line);
                            self.publisher.publish_lossy(event);
                        }
                    }
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
            "SECCOMP" => self.build_seccomp_event(record, seq),
            "ANOM_ABEND" => self.build_anom_abend_event(record, seq),
            "ANOM_PROMISCUOUS" => self.build_anom_promiscuous_event(record, seq),
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

    /// SYSCALL + EXECVE pair — emitted by the kernel as TWO lines
    /// per exec() call. SDD-059 C-5 closure: instead of emitting two
    /// generic events, we pair them and emit ONE PROCESS_ACTIVITY ::
    /// Launch event with the full argv vector + executable path +
    /// exit code (0=success, non-zero=execve failed). Severity Medium
    /// (every exec is signal; severity escalation belongs in the
    /// correlator). Attack tag: T1059 Command and Scripting Interpreter
    /// (Tactic::Execution) — every exec IS the technique foundation;
    /// the correlator narrows to a specific T1059.<sub> at decision
    /// time based on the argv contents.
    fn build_syscall_execve_event(&self, syscall: &AuditRecord, execve: &AuditRecord) -> Event {
        let seq = self.next_sequence();
        let argv = parser::parse_execve_argv(execve);
        let argc = execve
            .get("argc")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(argv.len());

        let pid = syscall.get("pid").unwrap_or("?");
        let ppid = syscall.get("ppid").unwrap_or("?");
        let uid = syscall.get("uid").unwrap_or("?");
        let auid = syscall.get("auid").unwrap_or("?");
        let comm = syscall.get("comm").unwrap_or("?");
        let exe = syscall.get("exe").unwrap_or("?");
        let exit_code = syscall.get("exit").unwrap_or("?");

        let argv_display = if argv.is_empty() {
            "(no argv)".to_string()
        } else {
            argv.iter()
                .map(|a| format!("{a:?}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let message = format!(
            "EXECVE: pid={pid} ppid={ppid} auid={auid} uid={uid} comm={comm} exe={exe} \
             argc={argc} argv=[{argv_display}] exit={exit_code}"
        );

        // Combined raw payload: SYSCALL fields + execve_argv array +
        // execve_raw (the original EXECVE record's fields).
        let mut raw = serde_json::Map::new();
        if let serde_json::Value::Object(m) =
            serde_json::to_value(&syscall.fields).unwrap_or(serde_json::Value::Null)
        {
            raw.extend(m);
        }
        raw.insert(
            "execve_argv".to_string(),
            serde_json::Value::Array(
                argv.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
        raw.insert(
            "execve_raw".to_string(),
            serde_json::to_value(&execve.fields).unwrap_or(serde_json::Value::Null),
        );

        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            ProcessActivity::Launch as u32,
            SeverityId::Medium,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(if exit_code == "0" {
            StatusId::Success
        } else if exit_code == "?" {
            StatusId::Unknown
        } else {
            // Non-zero (including hex-encoded "0xfffffffe" failures on
            // some kernels) → exec did not succeed.
            StatusId::Failure
        })
        .with_message(message)
        .with_raw(serde_json::Value::Object(raw))
        .with_attack(TechniqueRef::new(
            "T1059",
            "Command and Scripting Interpreter",
            Tactic::Execution,
        ))
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
        let severity = if denied {
            SeverityId::High
        } else {
            SeverityId::Informational
        };
        let status = if denied {
            StatusId::Failure
        } else {
            StatusId::Success
        };

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

    /// SECCOMP = a seccomp filter trip. The kernel emits one of these
    /// every time a process tries a syscall its filter doesn't allow.
    /// Very high signal — a tripped seccomp filter is either a benign
    /// portability bug OR an attempted defense-evasion / sandbox-escape.
    /// Maps to ClassUid::PROCESS_ACTIVITY + ProcessActivity::Other with
    /// severity High. Attack tag: T1562 (Impair Defenses), Tactic::
    /// DefenseEvasion — seccomp evasion is the relevant threat model.
    fn build_seccomp_event(&self, record: &AuditRecord, seq: u64) -> Event {
        let comm = record.get("comm").unwrap_or("?");
        let exe = record.get("exe").unwrap_or("?");
        let pid = record.get("pid").unwrap_or("?");
        let syscall = record.get("syscall").unwrap_or("?");
        let arch = record.get("arch").unwrap_or("?");
        let sig = record.get("sig").unwrap_or("?");
        let code = record.get("code").unwrap_or("?");

        let message = format!(
            "SECCOMP trip: pid={pid} comm={comm} exe={exe} syscall={syscall} \
             arch={arch} sig={sig} filter_code={code}"
        );

        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);

        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            ProcessActivity::Other as u32,
            SeverityId::High,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(StatusId::Failure)
        .with_message(message)
        .with_raw(raw)
        .with_attack(TechniqueRef::new(
            "T1562",
            "Impair Defenses",
            Tactic::DefenseEvasion,
        ))
    }

    /// ANOM_ABEND = abnormal program termination via signal (SIGSEGV,
    /// SIGABRT, SIGILL, SIGBUS, SIGFPE). Could be benign (crash, OOM),
    /// could be exploit-attempt fallout (corrupted SUID binary,
    /// successful-then-killed shellcode). Severity Medium so the
    /// correlator can decide whether to escalate based on context
    /// (e.g. ABEND on a SUID exec).
    fn build_anom_abend_event(&self, record: &AuditRecord, seq: u64) -> Event {
        let comm = record.get("comm").unwrap_or("?");
        let exe = record.get("exe").unwrap_or("?");
        let pid = record.get("pid").unwrap_or("?");
        let sig = record.get("sig").unwrap_or("?");

        let message = format!("ANOM_ABEND: pid={pid} comm={comm} exe={exe} sig={sig}");
        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);

        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            ProcessActivity::Terminate as u32,
            SeverityId::Medium,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(StatusId::Failure)
        .with_message(message)
        .with_raw(raw)
    }

    /// ANOM_PROMISCUOUS = network interface entered promiscuous mode
    /// (typical of `tcpdump`, `wireshark`, or unauthorized sniffer).
    /// Maps to ClassUid::PROCESS_ACTIVITY (no NETWORK_ACTIVITY mode-
    /// change variant exists) with severity High. Attack tag:
    /// T1040 (Network Sniffing, Tactic::Discovery).
    fn build_anom_promiscuous_event(&self, record: &AuditRecord, seq: u64) -> Event {
        let dev = record.get("dev").unwrap_or("?");
        let prom = record.get("prom").unwrap_or("?");
        let old_prom = record.get("old_prom").unwrap_or("?");
        let auid = record.get("auid").unwrap_or("?");

        let message =
            format!("ANOM_PROMISCUOUS: dev={dev} old_prom={old_prom} prom={prom} auid={auid}");
        let raw = serde_json::to_value(&record.fields).unwrap_or(serde_json::Value::Null);

        Event::new(
            ClassUid::PROCESS_ACTIVITY,
            ProcessActivity::Other as u32,
            SeverityId::High,
            &self.host_tag,
            "auditd",
            seq,
        )
        .with_status(StatusId::Failure)
        .with_message(message)
        .with_raw(raw)
        .with_attack(TechniqueRef::new(
            "T1040",
            "Network Sniffing",
            Tactic::Discovery,
        ))
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
