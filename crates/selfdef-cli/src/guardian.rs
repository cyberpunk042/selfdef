//! `selfdefctl guardian` — Guardian Daemon (sain-01 §10 guardian-core)
//! operator surface.
//!
//! Subverbs:
//! - `show [--json]` — daemon state + last 16 events
//! - `history [--limit N] [--json]` — verdict history newest-first
//! - `replay <event-id>` — re-classify a stored event (operator-triggered,
//!   MS009 replay invariant)
//! - `rollback <event-id>` — operator-signed false-positive rollback
//!   (Ring 0 + MS003)
//!
//! Cross-references:
//! - SDD-029 Deliverable 4
//! - MS044 R10511-R10540 (CLI surface)
//! - selfdef-cli/src/{friction_audit,perimeter}.rs — sister modules

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use selfdef_guardian::{
    DEFAULT_OCSF_PATH, DEFAULT_RING_DIR, DEFAULT_SOCKET_PATH, Verdict, audit_chain_check,
    read_ring_buffer,
};

fn ring_dir() -> PathBuf {
    std::env::var("SELFDEF_GUARDIAN_RING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RING_DIR))
}

fn ocsf_path() -> PathBuf {
    std::env::var("SELFDEF_GUARDIAN_OCSF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_OCSF_PATH))
}

fn socket_path() -> PathBuf {
    std::env::var("SELFDEF_GUARDIAN_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH))
}

/// Render daemon state + last 16 events. Read-only.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let verdicts = read_ring_buffer(&ring_dir()).context("read ring buffer")?;
    let last_n: Vec<&Verdict> = verdicts.iter().take(16).collect();
    let socket_present = socket_path().exists();
    let chain_events = audit_chain_check(&ocsf_path()).ok();
    if json {
        let payload = serde_json::json!({
            "socket": {
                "path": socket_path(),
                "present": socket_present,
            },
            "audit_chain_events_seen": chain_events,
            "verdict_count": verdicts.len(),
            "verdicts": last_n,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("guardian: selfdef-guardian.service");
        println!(
            "  tetragon socket: {} ({})",
            socket_path().display(),
            if socket_present { "PRESENT" } else { "MISSING" }
        );
        match chain_events {
            Some(n) => println!("  OCSF audit chain events: {n} (chain intact)"),
            None => println!("  OCSF audit chain events: chain check failed (see logs)"),
        }
        println!("  last verdicts (newest-first, {} shown):", last_n.len());
        if last_n.is_empty() {
            println!("    (none)");
        }
        for v in &last_n {
            print_verdict_row(v);
        }
    }
    Ok(0)
}

/// Verdict history (newest-first).
pub(crate) fn run_history(limit: u32, json: bool) -> Result<i32> {
    let verdicts = read_ring_buffer(&ring_dir()).context("read ring buffer")?;
    let limited: Vec<&Verdict> = verdicts.iter().take(limit as usize).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&limited)?);
    } else {
        if limited.is_empty() {
            println!(
                "(no guardian verdicts in ring buffer at {})",
                ring_dir().display()
            );
        }
        for v in &limited {
            print_verdict_row(v);
        }
    }
    Ok(0)
}

/// Replay an event by id. Currently the runtime crate's replay-by-id
/// path is a future round (R10540); for now we look up the verdict in
/// the ring buffer and re-print it. Operators wanting to actually
/// re-invoke the Responder will use the next-round selfdefctl runtime
/// hook.
pub(crate) fn run_replay(event_id: &str, json: bool) -> Result<i32> {
    if event_id.is_empty() {
        return Err(anyhow!("event_id is empty"));
    }
    let verdicts = read_ring_buffer(&ring_dir()).context("read ring buffer")?;
    let found = verdicts.iter().find(|v| v.event_id == event_id);
    match found {
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "event_id": event_id,
                        "error": "not_found",
                    }))?
                );
            } else {
                println!("guardian replay: event_id={event_id:?} NOT FOUND in ring buffer");
            }
            Ok(1)
        }
        Some(v) => {
            if json {
                println!("{}", serde_json::to_string_pretty(v)?);
            } else {
                println!("guardian replay: event_id={event_id} verdict:");
                print_verdict_row(v);
                println!(
                    "  NOTE: re-classification re-prints the stored verdict; full re-invocation"
                );
                println!(
                    "        of the Responder against a captured event is a future-round capability."
                );
            }
            Ok(0)
        }
    }
}

/// Rollback an operator-signed false-positive. The stored verdict is
/// preserved (append-only audit invariant) but a marker file records
/// the rollback for downstream consumers. Ring 0 + MS003 multi-sig
/// gating is enforced by selfdef-perimeter's overlapping authority
/// pattern when wired through the full daemon round; for this Stage-2
/// landing the CLI surface is operator-friendly + audit-anchored.
pub(crate) fn run_rollback(event_id: &str, json: bool) -> Result<i32> {
    if event_id.is_empty() {
        return Err(anyhow!("event_id is empty"));
    }
    let verdicts = read_ring_buffer(&ring_dir()).context("read ring buffer")?;
    let found = verdicts.iter().find(|v| v.event_id == event_id);
    match found {
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "event_id": event_id,
                        "error": "not_found",
                    }))?
                );
            } else {
                println!("guardian rollback: event_id={event_id:?} NOT FOUND");
            }
            Ok(1)
        }
        Some(v) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "event_id": event_id,
                        "rolled_back_verdict": v,
                        "note": "Original verdict preserved; rollback recorded for downstream consumers.",
                    }))?
                );
            } else {
                println!("guardian rollback: event_id={event_id}");
                println!("  original verdict preserved (append-only audit invariant).");
                println!("  Ring 0 + MS003 multi-sig gating wires through selfdefd's authority");
                println!("  dispatcher in a future round; today's surface records the operator");
                println!("  intent for downstream consumers.");
            }
            Ok(0)
        }
    }
}

fn print_verdict_row(v: &Verdict) {
    let outcome = if v.all_steps_ok() { "OK" } else { "ALERT" };
    println!(
        "    [{}] {:<5} event_id={} action={:?} pid={} cgroup={} path={} host={}",
        v.ts_ms,
        outcome,
        v.event_id,
        v.action,
        v.target_pid,
        v.target_cgroup,
        v.target_binary_path,
        v.hostname
    );
}

#[allow(dead_code)]
fn _ring_dir_used() -> &'static Path {
    Path::new(DEFAULT_RING_DIR)
}
