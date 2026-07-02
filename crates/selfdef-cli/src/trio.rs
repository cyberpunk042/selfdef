//! `selfdefctl trio` — consolidated four-watchdog-set operator view.
//!
//! Renders friction-audit + perimeter + guardian + scheduler state in
//! one read-only snapshot. The CLI analog of the dashboard's main
//! page; useful when no GUI/browser is available (operator-on-tty
//! scenario).
//!
//! MS043 R10081 ("Do not minimize the work in selfdef") + F05081 (TUI
//! main dashboard 4-panel layout — this is the 4-panel CLI projection
//! of the four-watchdog set MS046/MS047/MS044/MS048 in production today).
//!
//! Read-only. Composes the existing per-watchdog runtime crates'
//! `read_ring_buffer` + state functions; no new authority surface.
//!
//! Note: the command name `trio` is preserved from the original
//! three-watchdog scope (commit 83c9749). Renaming the command would
//! break operator muscle-memory + scripts; the rendered banner +
//! drill-down pointers were updated to read "four-watchdog set"
//! when MS048 (Goldilocks Scheduler) was added (commit d12d226).

use std::path::Path;

use anyhow::{Context, Result};

use selfdef_friction_audit::{DEFAULT_RING_DIR as FA_RING, read_ring_buffer as fa_read};
use selfdef_friction_audit_mirror::Status;
use selfdef_guardian::{
    DEFAULT_OCSF_PATH as GUARD_OCSF, DEFAULT_RING_DIR as GUARD_RING,
    DEFAULT_SOCKET_PATH as GUARD_SOCK, audit_chain_check as guard_chain,
    read_ring_buffer as guard_read,
};
use selfdef_perimeter::{
    DEFAULT_EXTENSION_DIR, DEFAULT_OCSF_PATH as PERIM_OCSF, DEFAULT_POLICY_PATH,
    DEFAULT_RING_DIR as PERIM_RING, DEFAULT_TRUST_ROOTS_DIR, ExtensionStore, Outcome,
    audit_chain_check as perim_chain, now_ms, read_ring_buffer as perim_read,
};
use selfdef_scheduler::{
    DEFAULT_AUDIT_LOG_PATH as SCHED_AUDIT, DEFAULT_RING_DIR as SCHED_RING,
    audit_chain_check as sched_chain, read_ring_buffer as sched_read,
};

pub(crate) fn run(json: bool, watch_secs: u32, quiet: bool) -> Result<i32> {
    // 5 modes:
    //  - --quiet      → single-line aggregate summary (overrides --json)
    //  - no flags     → one-shot human render
    //  - --json       → one-shot JSON
    //  - --watch N    → human clear-and-redraw every N seconds
    //  - --json --watch N → JSONL stream, one JSON per cycle (for
    //    monitoring pipelines: cron + jq, collectd, Loki ingest, etc).
    //    No clear-and-redraw — operators piping into a log shipper
    //    want each cycle as a distinct line, not overwritten.
    if quiet {
        // --quiet wins over --json + --watch — quiet is for PS1 prompts
        // + status bars, which are one-shot single-line by definition.
        return render_quiet();
    }
    if watch_secs == 0 {
        // One-shot: pretty JSON for readability OR human render.
        return render_once_with(json, /*compact=*/ false);
    }
    if json {
        // JSONL stream mode — one COMPACT JSON line per cycle, no banner.
        // Compact form is essential for log shippers + jq line-mode +
        // collectd file-tail; pretty would emit multi-line JSON that
        // breaks per-line tooling.
        loop {
            let _ = render_once_with(true, /*compact=*/ true)?;
            std::thread::sleep(std::time::Duration::from_secs(u64::from(watch_secs)));
        }
    }
    // Human watch mode: clear + redraw every watch_secs seconds.
    // ANSI escape: ESC[2J clears screen, ESC[H homes cursor.
    loop {
        // Clear + home.
        print!("\x1b[2J\x1b[H");
        // Inline timestamp banner for at-a-glance freshness.
        let now = chrono_now_iso();
        println!("[watch · refresh every {watch_secs}s · {now}] — Ctrl-C to exit");
        let _ = render_once_with(false, /*compact=*/ false)?;
        // Sleep — Ctrl-C breaks the sleep + process exits with 130, which
        // is the standard convention. No explicit signal handler needed
        // for an interactive CLI.
        std::thread::sleep(std::time::Duration::from_secs(u64::from(watch_secs)));
    }
}

fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Avoid pulling chrono just for this; render ms-since-epoch + a
    // human "Hms" derivation from secs % day.
    let day_secs = secs % 86_400;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    format!("{secs}s epoch · {h:02}:{m:02}:{s:02} UTC")
}

/// Single-line aggregate summary suitable for PS1 prompts + status
/// bars. Format: `selfdef: fa=OK perim=ALERT guard=OK sched=OK`.
/// Exit code 0 when all 4 aggregates are 'ok'; 1 otherwise (so
/// `selfdefctl trio --quiet && command` works as a gate).
fn render_quiet() -> Result<i32> {
    let agg = compute_aggregates()?;
    let fa = agg.friction_audit.to_uppercase();
    let perim = agg.perimeter.to_uppercase();
    let guard = agg.guardian.to_uppercase();
    let sched = agg.scheduler.to_uppercase();
    println!("selfdef: fa={fa} perim={perim} guard={guard} sched={sched}");
    // Exit 0 iff every aggregate is 'ok'. Any other state ('alert',
    // 'fail', 'override', 'extended', 'degraded', 'backpressure',
    // 'unknown') maps to exit 1 — operator gates can rely on this.
    let all_ok = agg.friction_audit == "ok"
        && agg.perimeter == "ok"
        && agg.guardian == "ok"
        && agg.scheduler == "ok";
    Ok(if all_ok { 0 } else { 1 })
}

/// Aggregate states for all four watchdogs, as the lowercased strings
/// the existing human/JSON renderers emit.
struct Aggregates {
    friction_audit: String,
    perimeter: String,
    guardian: String,
    scheduler: String,
}

fn compute_aggregates() -> Result<Aggregates> {
    let now = now_ms();

    let fa_verdicts = fa_read(Path::new(FA_RING)).context("friction-audit ring read")?;
    let fa_failing = fa_verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::Fail(_)))
        .count();
    let fa_overrides = fa_verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::OverrideActive { .. }))
        .count();
    let friction_audit = if !fa_verdicts.is_empty() && fa_failing > 0 {
        "fail"
    } else if fa_overrides > 0 {
        "override"
    } else if fa_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    }
    .to_string();

    let perim_verdicts = perim_read(Path::new(PERIM_RING)).context("perimeter ring read")?;
    let (perim_store, _) = ExtensionStore::load_dir(
        Path::new(DEFAULT_EXTENSION_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now,
    )
    .context("perimeter extension store load")?;
    let perim_extensions = perim_store.active(now).len();
    let perim_sigkills = perim_verdicts
        .iter()
        .filter(|v| matches!(v.outcome, Outcome::Sigkill))
        .count();
    let perimeter = if perim_sigkills > 0 {
        "alert"
    } else if perim_extensions > 0 {
        "extended"
    } else if perim_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    }
    .to_string();

    let guard_verdicts = guard_read(Path::new(GUARD_RING)).context("guardian ring read")?;
    let guard_failed = guard_verdicts.iter().filter(|v| !v.all_steps_ok()).count();
    let guard_socket_present = Path::new(GUARD_SOCK).exists();
    let guardian = if guard_failed > 0 {
        "alert"
    } else if !guard_socket_present {
        "degraded"
    } else if guard_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    }
    .to_string();

    let sched_decisions = sched_read(Path::new(SCHED_RING)).context("scheduler ring read")?;
    let sched_backpressured = sched_decisions
        .iter()
        .filter(|d| d.backpressure.any_pressure())
        .count();
    let scheduler = if sched_decisions.is_empty() {
        "unknown"
    } else if sched_backpressured > 0 {
        "backpressure"
    } else {
        "ok"
    }
    .to_string();

    Ok(Aggregates {
        friction_audit,
        perimeter,
        guardian,
        scheduler,
    })
}

fn render_once_with(json: bool, compact: bool) -> Result<i32> {
    let now = now_ms();

    // friction-audit snapshot
    let fa_verdicts = fa_read(Path::new(FA_RING)).context("friction-audit ring read")?;
    let fa_failing = fa_verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::Fail(_)))
        .count();
    let fa_overrides = fa_verdicts
        .iter()
        .filter(|v| matches!(v.status, Status::OverrideActive { .. }))
        .count();
    let fa_aggregate = if !fa_verdicts.is_empty() && fa_failing > 0 {
        "fail"
    } else if fa_overrides > 0 {
        "override"
    } else if fa_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    };

    // perimeter snapshot
    let perim_verdicts = perim_read(Path::new(PERIM_RING)).context("perimeter ring read")?;
    let (perim_store, _) = ExtensionStore::load_dir(
        Path::new(DEFAULT_EXTENSION_DIR),
        Path::new(DEFAULT_TRUST_ROOTS_DIR),
        now,
    )
    .context("perimeter extension store load")?;
    let perim_extensions = perim_store.active(now).len();
    let perim_sigkills = perim_verdicts
        .iter()
        .filter(|v| matches!(v.outcome, Outcome::Sigkill))
        .count();
    let perim_policy_present = Path::new(DEFAULT_POLICY_PATH).exists();
    let perim_chain_events = perim_chain(Path::new(PERIM_OCSF)).ok();
    let perim_aggregate = if perim_sigkills > 0 {
        "alert"
    } else if perim_extensions > 0 {
        "extended"
    } else if perim_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    };

    // guardian snapshot
    let guard_verdicts = guard_read(Path::new(GUARD_RING)).context("guardian ring read")?;
    let guard_failed = guard_verdicts.iter().filter(|v| !v.all_steps_ok()).count();
    let guard_socket_present = Path::new(GUARD_SOCK).exists();
    let guard_chain_events = guard_chain(Path::new(GUARD_OCSF)).ok();
    let guard_aggregate = if guard_failed > 0 {
        "alert"
    } else if !guard_socket_present {
        "degraded"
    } else if guard_verdicts.is_empty() {
        "unknown"
    } else {
        "ok"
    };

    // scheduler snapshot (MS048)
    let sched_decisions = sched_read(Path::new(SCHED_RING)).context("scheduler ring read")?;
    let sched_backpressured = sched_decisions
        .iter()
        .filter(|d| d.backpressure.any_pressure())
        .count();
    let sched_chain_events = sched_chain(Path::new(SCHED_AUDIT)).ok();
    let sched_aggregate = if sched_decisions.is_empty() {
        "unknown"
    } else if sched_backpressured > 0 {
        "backpressure"
    } else {
        "ok"
    };

    if json {
        let payload = serde_json::json!({
            "now_ms": now,
            "friction_audit": {
                "aggregate": fa_aggregate,
                "verdict_count": fa_verdicts.len(),
                "failing_gates": fa_failing,
                "active_overrides": fa_overrides,
            },
            "perimeter": {
                "aggregate": perim_aggregate,
                "verdict_count": perim_verdicts.len(),
                "sigkill_count": perim_sigkills,
                "active_extensions": perim_extensions,
                "policy_present": perim_policy_present,
                "audit_chain_events": perim_chain_events,
            },
            "guardian": {
                "aggregate": guard_aggregate,
                "verdict_count": guard_verdicts.len(),
                "failed_responses": guard_failed,
                "tetragon_socket_present": guard_socket_present,
                "audit_chain_events": guard_chain_events,
            },
            "scheduler": {
                "aggregate": sched_aggregate,
                "decision_count": sched_decisions.len(),
                "backpressured_decisions": sched_backpressured,
                "audit_chain_events": sched_chain_events,
            },
        });
        let serialized = if compact {
            serde_json::to_string(&payload)?
        } else {
            serde_json::to_string_pretty(&payload)?
        };
        println!("{serialized}");
        return Ok(0);
    }

    println!("selfdef four-watchdog set (read-only snapshot)");
    println!("{}", "═".repeat(72));
    println!(
        "  [{aggregate:<12}] friction-audit (hardware frame, SDD-027 / MS046)",
        aggregate = fa_aggregate.to_uppercase()
    );
    println!(
        "             verdicts={count} · failing-gates={fail} · overrides={ovr}",
        count = fa_verdicts.len(),
        fail = fa_failing,
        ovr = fa_overrides
    );
    println!();
    println!(
        "  [{aggregate:<12}] perimeter      (kernel syscall, SDD-028 / MS047)",
        aggregate = perim_aggregate.to_uppercase()
    );
    println!(
        "             verdicts={count} · sigkills={sk} · extensions={ext} · policy={p} · chain={c}",
        count = perim_verdicts.len(),
        sk = perim_sigkills,
        ext = perim_extensions,
        p = if perim_policy_present {
            "PRESENT"
        } else {
            "MISSING"
        },
        c = perim_chain_events
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    println!();
    println!(
        "  [{aggregate:<12}] guardian       (supervisor tier, SDD-029 / MS044)",
        aggregate = guard_aggregate.to_uppercase()
    );
    println!(
        "             verdicts={count} · failed={failed} · tetragon-socket={s} · chain={c}",
        count = guard_verdicts.len(),
        failed = guard_failed,
        s = if guard_socket_present {
            "PRESENT"
        } else {
            "MISSING"
        },
        c = guard_chain_events
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    println!();
    println!(
        "  [{aggregate:<12}] scheduler      (routing layer, SDD-031 / MS048)",
        aggregate = sched_aggregate.to_uppercase()
    );
    println!(
        "             decisions={count} · backpressured={bp} · chain={c}",
        count = sched_decisions.len(),
        bp = sched_backpressured,
        c = sched_chain_events
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".to_string()),
    );
    println!("{}", "═".repeat(72));
    println!(
        "  Drill down: `selfdefctl friction-audit show` / `perimeter show` / `guardian show` / `scheduler show`"
    );
    println!(
        "  Dashboard:  <api transport>/dashboard (bundled PWA served by selfdefd's [api] socket) · minimal web: https://localhost:7575 (selfdef-web fallback)"
    );
    println!("  Runbooks:   ~/devops-solutions-information-hub/wiki/runbooks/");
    Ok(0)
}

/// Unified tail of the four watchdog OCSF jsonl logs.
/// Polls each file every `interval_ms` ms; emits new lines as they
/// appear, tagged with the source watchdog. Honors env-var overrides
/// for sandboxed test runs (SELFDEF_FRICTION_AUDIT_OCSF_PATH /
/// SELFDEF_PERIMETER_OCSF_PATH / SELFDEF_GUARDIAN_OCSF_PATH /
/// SELFDEF_SCHEDULER_OCSF_PATH). Ctrl-C exits.
pub(crate) fn run_tail(interval_ms: u64, json: bool) -> Result<i32> {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader};

    let sources: [(&'static str, std::path::PathBuf); 4] = [
        (
            "friction-audit",
            std::env::var("SELFDEF_FRICTION_AUDIT_OCSF_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    std::path::PathBuf::from(selfdef_friction_audit::DEFAULT_OCSF_PATH)
                }),
        ),
        (
            "perimeter",
            std::env::var("SELFDEF_PERIMETER_OCSF_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from(PERIM_OCSF)),
        ),
        (
            "guardian",
            std::env::var("SELFDEF_GUARDIAN_OCSF_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from(GUARD_OCSF)),
        ),
        (
            "scheduler",
            std::env::var("SELFDEF_SCHEDULER_OCSF_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from(SCHED_AUDIT)),
        ),
    ];

    // Per-source byte offset. Start at end-of-file (live tail; old
    // events are accessible via `<watchdog> history`).
    let mut offsets: BTreeMap<String, u64> = BTreeMap::new();
    for (tag, path) in &sources {
        let off = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        offsets.insert((*tag).to_string(), off);
    }

    eprintln!(
        "selfdef trio-tail: watching {} sources, polling every {interval_ms}ms — Ctrl-C to exit",
        sources.len()
    );
    if !json {
        eprintln!("  {:>14}  ts_ms          severity  class  detail", "source");
        eprintln!("  {}", "─".repeat(78));
    }

    loop {
        for (tag, path) in &sources {
            if !path.exists() {
                continue;
            }
            let cur_off = offsets.get(*tag).copied().unwrap_or(0);
            let len = match std::fs::metadata(path) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if len == cur_off {
                continue;
            }
            if len < cur_off {
                // File rotated/truncated — reset to start.
                offsets.insert((*tag).to_string(), 0);
                continue;
            }
            // Read from cur_off to end.
            let f = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            use std::io::{Seek, SeekFrom};
            let mut f = f;
            if f.seek(SeekFrom::Start(cur_off)).is_err() {
                continue;
            }
            let mut new_off = cur_off;
            for line in BufReader::new(&mut f).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                new_off += (line.len() as u64) + 1; // +1 for \n
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if json {
                    // Prefix the source tag for the consumer.
                    let parsed: serde_json::Value = serde_json::from_str(trimmed)
                        .unwrap_or(serde_json::json!({"raw": trimmed}));
                    let tagged = serde_json::json!({"source": tag, "event": parsed});
                    println!(
                        "{}",
                        serde_json::to_string(&tagged).unwrap_or_else(|_| String::new())
                    );
                } else {
                    let parsed: serde_json::Value =
                        serde_json::from_str(trimmed).unwrap_or(serde_json::json!({}));
                    let ts = parsed
                        .get("ts_ms")
                        .or_else(|| parsed.get("time"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let sev = parsed
                        .get("severity_id")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let class = parsed
                        .get("class_uid")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let detail = render_detail(tag, &parsed);
                    println!("  {tag:>14}  {ts:<14}  sev={sev}     {class}   {detail}");
                }
            }
            offsets.insert((*tag).to_string(), new_off);
        }
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
}

fn render_detail(tag: &str, ev: &serde_json::Value) -> String {
    match tag {
        "friction-audit" => {
            let gate = ev.get("gate").and_then(|v| v.as_str()).unwrap_or("?");
            let status = ev.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            format!("gate={gate} status={status}")
        }
        "perimeter" => {
            let outcome = ev
                .pointer("/outcome/outcome")
                .and_then(|v| v.as_str())
                .unwrap_or(
                    ev.pointer("/outcome")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                );
            let path = ev
                .pointer("/process/file/path")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("outcome={outcome} path={path}")
        }
        "guardian" => {
            let evt = ev
                .get("guardian_event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let act = ev
                .pointer("/guardian_action")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            format!("event={evt} action={act}")
        }
        "scheduler" => {
            let req = ev.get("request_id").and_then(|v| v.as_str()).unwrap_or("?");
            let prof = ev
                .pointer("/profile")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let route = ev.pointer("/route").and_then(|v| v.as_str()).unwrap_or("?");
            format!("req={req} profile={prof} route={route}")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    // Integration test of run() requires env-var-mutating path overrides
    // (unsafe on Rust 2024 multi-threaded test runner). The aggregate
    // rules tested here mirror the API-level logic which is already
    // covered by 5 tests in crates/selfdef-api/src/{friction_audit,
    // perimeter,guardian}.rs. CLI-surface coverage is provided by the
    // L1 dashboard-sections gate + the L1 CLI-surface subverb-count
    // gate (which will detect when `trio` was added — the subverb count
    // ticks; the gate will fail unless its expected count is bumped
    // for the parent command). The trio subverb is at the top-level
    // command tree, not under another command, so it doesn't bump any
    // existing subverb-count check.
}
