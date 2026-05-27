//! `selfdef-guardian` daemon executable — Stage-1 production wrapper.
//!
//! Watches the Tetragon UNIX socket at `/var/run/tetragon/tetragon.events`
//! (or operator-overridden path). When the socket appears, connects + reads
//! newline-delimited JSON events. For each event that classifies as a
//! response-eligible action (Sigkill / ProcessRelated), invokes the
//! 3-step Responder pattern (SIGKILL via podman/kill -9 → atomic audit
//! log append → /dev/console BEL alert) per sain-01 §10 dump 527-552.
//!
//! Verdicts are appended to the ring buffer for downstream consumers
//! (selfdefctl guardian show, cockpit panel binding, dashboard JS).
//!
//! Honored env vars:
//! - `SELFDEF_GUARDIAN_SOCKET_PATH` (default /var/run/tetragon/tetragon.events)
//! - `SELFDEF_GUARDIAN_RING_DIR` (default /var/cache/selfdef/guardian/ring)
//! - `SELFDEF_GUARDIAN_AUDIT_LOG` (default /mnt/vault/context/security_audit.log)
//! - `SELFDEF_GUARDIAN_CONSOLE` (default /dev/console)
//! - `SELFDEF_GUARDIAN_OCSF_PATH` (default /var/log/selfdef/guardian.ocsf.jsonl)
//! - `SELFDEF_GUARDIAN_HOSTNAME` (default: gethostname)
//! - `SELFDEF_GUARDIAN_SIGNER_KID` (default kid-bootstrap)
//! - `SELFDEF_GUARDIAN_SOCKET_POLL_SECS` (default 5) — how often to
//!   probe for the socket when it's missing
//!
//! Stage-1 behavior: if the socket is missing, the daemon polls + waits.
//! It does NOT crash — operators want Guardian to come up before Tetragon
//! and stay up across Tetragon restarts. When the socket appears, it
//! connects + streams. Disconnect → polling resumes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use selfdef_guardian::{
    CircuitBreaker, RealEffector, Responder, TetragonEvent, classify, emit_ocsf_detection_2004,
    now_ms, should_respond,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    eprintln!("[selfdef-guardian {VERSION}] starting");

    let socket_path = std::env::var("SELFDEF_GUARDIAN_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_guardian::DEFAULT_SOCKET_PATH));
    let ring_dir = std::env::var("SELFDEF_GUARDIAN_RING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_guardian::DEFAULT_RING_DIR));
    let audit_log = std::env::var("SELFDEF_GUARDIAN_AUDIT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_guardian::DEFAULT_AUDIT_LOG_PATH));
    let console = std::env::var("SELFDEF_GUARDIAN_CONSOLE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_guardian::DEFAULT_CONSOLE_PATH));
    let ocsf = std::env::var("SELFDEF_GUARDIAN_OCSF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_guardian::DEFAULT_OCSF_PATH));
    let hostname = std::env::var("SELFDEF_GUARDIAN_HOSTNAME").unwrap_or_else(|_| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    });
    let signer_kid = std::env::var("SELFDEF_GUARDIAN_SIGNER_KID")
        .unwrap_or_else(|_| "kid-bootstrap".to_string());
    let poll_secs: u64 = std::env::var("SELFDEF_GUARDIAN_SOCKET_POLL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    if let Err(e) = std::fs::create_dir_all(&ring_dir) {
        eprintln!(
            "[selfdef-guardian] ERROR: cannot create ring dir {}: {e}",
            ring_dir.display()
        );
        return ExitCode::from(1);
    }

    eprintln!(
        "[selfdef-guardian] socket={} ring={} audit={} console={} host={hostname}",
        socket_path.display(),
        ring_dir.display(),
        audit_log.display(),
        console.display(),
    );

    let responder = Responder::new(RealEffector, audit_log, console, &hostname, &signer_kid);
    let mut breaker = CircuitBreaker::new();

    // Outer loop: wait for socket → connect → process → on disconnect, retry.
    loop {
        if !socket_path.exists() {
            eprintln!(
                "[selfdef-guardian] socket {} not present; sleeping {poll_secs}s",
                socket_path.display()
            );
            std::thread::sleep(Duration::from_secs(poll_secs));
            continue;
        }

        let stream = match UnixStream::connect(&socket_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[selfdef-guardian] connect {} failed: {e}; retrying in {poll_secs}s",
                    socket_path.display()
                );
                std::thread::sleep(Duration::from_secs(poll_secs));
                continue;
            }
        };
        eprintln!("[selfdef-guardian] connected to {}", socket_path.display());

        let reader = BufReader::new(stream);
        let mut events_seen: u64 = 0;
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[selfdef-guardian] read err: {e}; reconnecting");
                    break;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            events_seen += 1;

            // Parse Tetragon event (best-effort — malformed lines are
            // logged + skipped, not fatal).
            let event: TetragonEvent = match serde_json::from_str(trimmed) {
                Ok(e) => e,
                Err(parse_err) => {
                    eprintln!(
                        "[selfdef-guardian] WARN: malformed tetragon event #{events_seen}: {parse_err}"
                    );
                    continue;
                }
            };

            // Classify + decide whether to respond.
            let action = classify(&event);
            if !should_respond(action) {
                continue; // informational / non-violation event
            }

            // Circuit breaker — protect against same-target flood
            // (R10399-R10410). Stage-1 keys on container_id|pid.
            let key = CircuitBreaker::target_key(&event.container_id, event.pid);
            if let Err(e) = breaker.record(&key, now_ms()) {
                eprintln!("[selfdef-guardian] WARN: circuit breaker open: {e}");
                continue;
            }

            // 3-step response.
            match responder.respond(&event) {
                Ok(verdict) => {
                    let ring_path = ring_dir.join(format!("evt-{}.json", verdict.ts_ms));
                    if let Err(e) = write_ring_entry(&ring_path, &verdict) {
                        eprintln!("[selfdef-guardian] WARN: ring write: {e}");
                    }
                    if let Err(e) = evict_old_ring_entries(&ring_dir, 256) {
                        eprintln!("[selfdef-guardian] WARN: ring evict: {e}");
                    }
                    if let Err(e) = emit_ocsf_detection_2004(&ocsf, &verdict) {
                        eprintln!("[selfdef-guardian] WARN: OCSF emit: {e}");
                    }
                    if events_seen % 100 == 0 {
                        eprintln!(
                            "[selfdef-guardian] events_seen={events_seen} last_verdict={} all_ok={}",
                            verdict.event_id,
                            verdict.all_steps_ok()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("[selfdef-guardian] ERROR: respond failed: {e}");
                }
            }
        }

        eprintln!(
            "[selfdef-guardian] socket EOF after {events_seen} events; reconnecting in {poll_secs}s"
        );
        std::thread::sleep(Duration::from_secs(poll_secs));
    }
}

fn write_ring_entry(path: &Path, verdict: &selfdef_guardian::Verdict) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(verdict).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(path, bytes)
}

fn evict_old_ring_entries(ring: &Path, cap: usize) -> std::io::Result<()> {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for d in std::fs::read_dir(ring)? {
        let d = d?;
        let p = d.path();
        if p.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let m = d.metadata()?;
        entries.push((m.modified().unwrap_or(std::time::UNIX_EPOCH), p));
    }
    if entries.len() <= cap {
        return Ok(());
    }
    entries.sort_by_key(|(t, _)| std::cmp::Reverse(*t));
    for (_, p) in entries.into_iter().skip(cap) {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}
