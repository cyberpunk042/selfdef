//! `selfdefctl notify {ack,forget,list,resend}` — SDD-008 D-4.
//!
//! Operator-facing CLI verbs for the persistent escalation engine.
//! Talks directly to the `[notifier].escalations_path` SQLite file;
//! WAL mode handles concurrent reads with a running daemon.
//!
//! - `ack <event_id>` → set `acked_at`, short-circuit further rungs.
//! - `forget <event_id>` → DELETE the row entirely (audit trail
//!   reflects "operator suppressed"; not the same as ack).
//! - `list [--limit N] [--json]` → print pending escalations.
//! - `resend <event_id>` → pull the next wake-task action forward to
//!   "right now" by setting `deadline_at = now` on an unacked row.
//!   The wake task then fires the current rung's channels (or closes
//!   if already at max rung). Does NOT reset rung state or bypass
//!   profile limits — only collapses the wait.

use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use selfdef_config::Config;
use selfdef_notifier_engine::EscalationEngine;
use selfdef_notifier_orchestrator::{EventId, SeverityId};
use uuid::Uuid;

/// `selfdefctl notify ack <event_id>`.
pub(crate) fn ack(cfg: &Config, event_id_raw: &str) -> Result<()> {
    let path = require_path(cfg)?;
    let event_id = parse_event_id(event_id_raw)?;
    let engine =
        EscalationEngine::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let now = unix_now();
    let rt = tokio_rt()?;
    let acked = rt.block_on(engine.record_ack(event_id, now))?;
    if acked {
        println!("ok: acked event {event_id_raw} at unix={now}");
    } else {
        println!("noop: event {event_id_raw} unknown or already acked (no row changed)");
    }
    Ok(())
}

/// `selfdefctl notify resend <event_id>`.
///
/// Sets the row's `deadline_at` to "now" so the daemon's wake task
/// fires the current rung's channels at its next poll iteration
/// (typically within `IDLE_POLL_INTERVAL_SECS`). The rung state
/// machine is preserved: if the row is already at the active
/// profile's max rung, the wake task closes it (the natural max-
/// rung action); otherwise it re-fires + advances. Resend does NOT
/// reset the rung counter and does NOT touch acked rows.
pub(crate) fn resend(cfg: &Config, event_id_raw: &str) -> Result<()> {
    let path = require_path(cfg)?;
    let event_id = parse_event_id(event_id_raw)?;
    let engine =
        EscalationEngine::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let now = unix_now();
    let rt = tokio_rt()?;
    let rescheduled = rt.block_on(engine.reschedule_now(event_id, now))?;
    if rescheduled {
        println!(
            "ok: rescheduled event {event_id_raw} to fire at unix={now} \
             (wake task will pick it up on its next poll)"
        );
    } else {
        println!("noop: event {event_id_raw} unknown or already acked (no row changed)");
    }
    Ok(())
}

/// `selfdefctl notify forget <event_id>`.
pub(crate) fn forget(cfg: &Config, event_id_raw: &str) -> Result<()> {
    let path = require_path(cfg)?;
    let event_id = parse_event_id(event_id_raw)?;
    let engine =
        EscalationEngine::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let rt = tokio_rt()?;
    let removed = rt.block_on(engine.close_event(event_id))?;
    if removed {
        println!("ok: forgot event {event_id_raw} (row deleted)");
    } else {
        println!("noop: event {event_id_raw} not in the escalation queue");
    }
    Ok(())
}

/// `selfdefctl notify list [--limit N] [--json]`.
///
/// Prints the pending escalation queue. We pull "due-up-to-i64::MAX"
/// to get every unacked row regardless of how far in the future its
/// next rung is — operators want the full pending picture, not just
/// already-due rows.
pub(crate) fn list(cfg: &Config, limit: usize, json: bool) -> Result<()> {
    let path = require_path(cfg)?;
    let engine =
        EscalationEngine::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let rt = tokio_rt()?;
    let rows = rt.block_on(engine.take_due(i64::MAX, limit))?;
    if rows.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("(empty: no pending escalations)");
        }
        return Ok(());
    }
    if json {
        for r in rows {
            // Render one JSON object per row (NDJSON). Keep keys
            // stable so scripts can parse without surprises.
            println!(
                "{{\"event_id\":\"{}\",\"payload_id\":\"{}\",\"title\":{},\"severity\":\"{}\",\"rung_index\":{},\"deadline_at\":{}}}",
                r.event_id,
                r.payload_id,
                serde_json_string(&r.title),
                r.severity.name(),
                r.rung_index,
                r.deadline_at,
            );
        }
    } else {
        println!(
            "{:<38} {:<5} {:<6} {:<13} TITLE",
            "EVENT ID", "RUNG", "SEV", "DEADLINE_AT"
        );
        for r in rows {
            println!(
                "{:<38} {:<5} {:<6} {:<13} {} {}",
                r.event_id.0,
                r.rung_index,
                severity_short(r.severity),
                r.deadline_at,
                severity_emoji(r.severity),
                r.title,
            );
        }
    }
    Ok(())
}

fn require_path(cfg: &Config) -> Result<std::path::PathBuf> {
    cfg.notifier.escalations_path.clone().context(
        "[notifier].escalations_path is not set in selfdef.toml; \
             SDD-008 escalation engine is not configured",
    )
}

fn parse_event_id(raw: &str) -> Result<EventId> {
    let uuid =
        Uuid::parse_str(raw).with_context(|| format!("event_id must be a UUID; got {raw:?}"))?;
    Ok(EventId(uuid))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a single-threaded tokio runtime to drive the engine's
/// async API from this sync CLI. CLI is short-lived; one runtime
/// per invocation is fine.
fn tokio_rt() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for notify subcommand")
}

/// Manual JSON-string escaping for the `--json` output. We avoid
/// pulling in serde_json just for one string field — keeps the
/// dep graph clean.
fn serde_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Short severity label for the table column.
fn severity_short(s: SeverityId) -> &'static str {
    match s {
        SeverityId::Unknown => "UNK",
        SeverityId::Informational => "INFO",
        SeverityId::Low => "LOW",
        SeverityId::Medium => "MED",
        SeverityId::High => "HIGH",
        SeverityId::Critical => "CRIT",
        SeverityId::Fatal => "FATAL",
        SeverityId::Other => "OTHER",
    }
}

/// Severity emoji prefix matching the conventions of the Slack /
/// Discord integration crates. Operators get a consistent visual
/// across `notify list` output and the messages themselves.
fn severity_emoji(s: SeverityId) -> &'static str {
    match s {
        SeverityId::Unknown | SeverityId::Informational => "ℹ️",
        SeverityId::Low => "🔹",
        SeverityId::Medium => "⚠️",
        SeverityId::High => "🚨",
        SeverityId::Critical | SeverityId::Fatal => "🔥",
        SeverityId::Other => "❓",
    }
}

// `bail!` is used by no current call site but kept imported in case
// future error paths grow.
#[allow(dead_code)]
fn _force_bail_imported_for_future_use() -> Result<()> {
    bail!("placeholder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_notifier_orchestrator::{Payload, PayloadId};

    fn fresh_engine() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escalations.sqlite");
        // Touch the file by opening once.
        let _e = EscalationEngine::open(&path).unwrap();
        (dir, path)
    }

    fn enqueue_test_row(path: &std::path::PathBuf, title: &str) -> EventId {
        let rt = tokio_rt().unwrap();
        let engine = EscalationEngine::open(path).unwrap();
        let event_id = EventId(Uuid::now_v7());
        let payload = Payload {
            id: PayloadId::new(),
            event_id: Some(event_id),
            title: title.into(),
            body: format!("body for {title}"),
            severity: SeverityId::High,
            ack_link: None,
            event_kind: None,
            ack_token: None,
        };
        rt.block_on(engine.enqueue(&payload, 100, 0)).unwrap();
        event_id
    }

    fn cfg_with_path(path: std::path::PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.notifier.escalations_path = Some(path);
        cfg
    }

    #[test]
    fn require_path_errors_when_unset() {
        let cfg = Config::default();
        let err = require_path(&cfg).expect_err("must error when path unset");
        assert!(
            err.to_string().contains("escalations_path is not set"),
            "{err}"
        );
    }

    #[test]
    fn parse_event_id_rejects_non_uuid() {
        let err = parse_event_id("not-a-uuid").expect_err("must reject");
        assert!(err.to_string().contains("must be a UUID"), "{err}");
    }

    #[test]
    fn ack_returns_ok_for_existing_row() {
        let (_dir, path) = fresh_engine();
        let eid = enqueue_test_row(&path, "alert-1");
        let cfg = cfg_with_path(path);
        // First ack: changes a row.
        ack(&cfg, &eid.0.to_string()).expect("ack ok");
        // Second ack: no-op (already acked).
        ack(&cfg, &eid.0.to_string()).expect("re-ack also ok");
    }

    #[test]
    fn ack_returns_ok_for_unknown_event() {
        let (_dir, path) = fresh_engine();
        let cfg = cfg_with_path(path);
        let fake = Uuid::now_v7().to_string();
        // Unknown id is a no-op, not a failure.
        ack(&cfg, &fake).expect("unknown event ack is noop, not error");
    }

    #[test]
    fn resend_changes_row_for_existing_unacked() {
        let (_dir, path) = fresh_engine();
        let eid = enqueue_test_row(&path, "to-be-resent");
        let cfg = cfg_with_path(path.clone());
        // Resend on an unacked row: must not error.
        resend(&cfg, &eid.0.to_string()).expect("resend ok");
        // After resend, the row's deadline_at should be <= now: a
        // subsequent take_due(now, _) call must claim it.
        let rt = tokio_rt().unwrap();
        let engine = EscalationEngine::open(&path).unwrap();
        let due = rt.block_on(engine.take_due(unix_now(), 10)).unwrap();
        assert_eq!(
            due.len(),
            1,
            "row should be due immediately after resend; got {due:?}"
        );
        assert_eq!(due[0].event_id, eid);
    }

    #[test]
    fn resend_is_noop_for_unknown_event() {
        let (_dir, path) = fresh_engine();
        let cfg = cfg_with_path(path);
        let fake = Uuid::now_v7().to_string();
        // Unknown id is a no-op, not a failure.
        resend(&cfg, &fake).expect("unknown event resend is noop, not error");
    }

    #[test]
    fn resend_is_noop_for_acked_event() {
        let (_dir, path) = fresh_engine();
        let eid = enqueue_test_row(&path, "already-acked");
        let cfg = cfg_with_path(path.clone());
        // Ack first, then attempt to resend — the WHERE acked_at IS NULL
        // guard must reject.
        ack(&cfg, &eid.0.to_string()).expect("ack ok");
        resend(&cfg, &eid.0.to_string()).expect("resend on acked is noop, not error");
        // No row should be due (it was acked).
        let rt = tokio_rt().unwrap();
        let engine = EscalationEngine::open(&path).unwrap();
        let due = rt.block_on(engine.take_due(unix_now(), 10)).unwrap();
        assert_eq!(due.len(), 0, "acked row must not become due");
    }

    #[test]
    fn forget_removes_row() {
        let (_dir, path) = fresh_engine();
        let eid = enqueue_test_row(&path, "to-be-forgotten");
        let cfg = cfg_with_path(path.clone());
        forget(&cfg, &eid.0.to_string()).expect("forget ok");
        // Engine has no row left.
        let rt = tokio_rt().unwrap();
        let engine = EscalationEngine::open(&path).unwrap();
        assert_eq!(rt.block_on(engine.row_count()).unwrap(), 0);
    }

    #[test]
    fn list_on_empty_engine() {
        let (_dir, path) = fresh_engine();
        let cfg = cfg_with_path(path);
        // Empty list call must not error; output goes to stdout
        // and is not captured here, but the function must return
        // Ok cleanly.
        list(&cfg, 10, false).expect("empty list ok");
        list(&cfg, 10, true).expect("empty list json ok");
    }

    #[test]
    fn list_after_enqueue() {
        let (_dir, path) = fresh_engine();
        enqueue_test_row(&path, "row-a");
        enqueue_test_row(&path, "row-b");
        let cfg = cfg_with_path(path);
        list(&cfg, 50, false).expect("list ok");
        list(&cfg, 50, true).expect("list json ok");
    }

    #[test]
    fn serde_json_string_escapes_quotes_and_control_chars() {
        assert_eq!(serde_json_string("hello"), "\"hello\"");
        assert_eq!(
            serde_json_string("with \"quotes\""),
            "\"with \\\"quotes\\\"\""
        );
        assert_eq!(serde_json_string("line\nbreak"), "\"line\\nbreak\"");
        assert_eq!(serde_json_string("tab\there"), "\"tab\\there\"");
        assert_eq!(serde_json_string("bell\x07"), "\"bell\\u0007\"");
    }

    #[test]
    fn severity_short_covers_all_variants() {
        // Every variant maps to a non-empty short label.
        for s in [
            SeverityId::Unknown,
            SeverityId::Informational,
            SeverityId::Low,
            SeverityId::Medium,
            SeverityId::High,
            SeverityId::Critical,
            SeverityId::Fatal,
            SeverityId::Other,
        ] {
            assert!(
                !severity_short(s).is_empty(),
                "short label missing for {s:?}"
            );
            assert!(!severity_emoji(s).is_empty(), "emoji missing for {s:?}");
        }
    }
}
