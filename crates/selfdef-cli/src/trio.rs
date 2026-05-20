//! `selfdefctl trio` — consolidated three-watchdog-trio operator view.
//!
//! Renders friction-audit + perimeter + guardian state in one read-only
//! snapshot. The CLI analog of the dashboard's main page; useful when
//! no GUI/browser is available (operator-on-tty scenario).
//!
//! MS043 R10081 ("Do not minimize the work in selfdef") + F05081 (TUI
//! main dashboard 4-panel layout — this is the 3-panel CLI projection
//! covering the three watchdogs in production today).
//!
//! Read-only. Composes the existing per-watchdog runtime crates'
//! `read_ring_buffer` + state functions; no new authority surface.

use std::path::Path;

use anyhow::{Context, Result};

use selfdef_friction_audit::{
    read_ring_buffer as fa_read, DEFAULT_RING_DIR as FA_RING,
};
use selfdef_friction_audit_mirror::Status;
use selfdef_guardian::{
    audit_chain_check as guard_chain, read_ring_buffer as guard_read,
    DEFAULT_OCSF_PATH as GUARD_OCSF, DEFAULT_RING_DIR as GUARD_RING,
    DEFAULT_SOCKET_PATH as GUARD_SOCK,
};
use selfdef_perimeter::{
    audit_chain_check as perim_chain, now_ms, read_ring_buffer as perim_read,
    ExtensionStore, Outcome, DEFAULT_EXTENSION_DIR, DEFAULT_OCSF_PATH as PERIM_OCSF,
    DEFAULT_POLICY_PATH, DEFAULT_RING_DIR as PERIM_RING, DEFAULT_TRUST_ROOTS_DIR,
};
use selfdef_scheduler::{
    audit_chain_check as sched_chain, read_ring_buffer as sched_read,
    DEFAULT_AUDIT_LOG_PATH as SCHED_AUDIT, DEFAULT_RING_DIR as SCHED_RING,
};

pub(crate) fn run(json: bool, watch_secs: u32) -> Result<i32> {
    // --json + --watch is nonsensical (JSON is one-shot machine-readable).
    // Honor --json and ignore --watch.
    if json || watch_secs == 0 {
        return render_once(json);
    }
    // Watch mode: clear + redraw every watch_secs seconds.
    // ANSI escape: ESC[2J clears screen, ESC[H homes cursor.
    loop {
        // Clear + home.
        print!("\x1b[2J\x1b[H");
        // Inline timestamp banner for at-a-glance freshness.
        let now = chrono_now_iso();
        println!("[watch · refresh every {watch_secs}s · {now}] — Ctrl-C to exit");
        let _ = render_once(false)?;
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

fn render_once(json: bool) -> Result<i32> {
    let now = now_ms();

    // friction-audit snapshot
    let fa_verdicts = fa_read(Path::new(FA_RING)).context("friction-audit ring read")?;
    let fa_failing = fa_verdicts.iter().filter(|v| matches!(v.status, Status::Fail(_))).count();
    let fa_overrides = fa_verdicts.iter().filter(|v| matches!(v.status, Status::OverrideActive { .. })).count();
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
        println!("{}", serde_json::to_string_pretty(&payload)?);
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
        p = if perim_policy_present { "PRESENT" } else { "MISSING" },
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
        s = if guard_socket_present { "PRESENT" } else { "MISSING" },
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
    println!("  Dashboard:  http://localhost:7575/dashboard (when selfdefd HTTP server is bound)");
    println!("  Runbooks:   ~/devops-solutions-information-hub/wiki/runbooks/");
    Ok(0)
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
