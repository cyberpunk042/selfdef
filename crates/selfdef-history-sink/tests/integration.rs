//! Integration tests for `selfdef-history-sink`. Validates the
//! sovereign-os global-history (R448) JSONL contract end-to-end.

use selfdef_history_sink::{HistoryEvent, emit, emit_default, resolve_log_path, validate};
use std::fs;
use tempfile::TempDir;

#[test]
fn emit_writes_one_jsonl_line_per_call() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("modules.jsonl");

    let e1 = HistoryEvent::now("agent-guard", "installed", "ok");
    let e2 = HistoryEvent::now("polarproxy", "feature-toggled", "ok").with_actor("selfdefctl");
    emit(&e1, &path).unwrap();
    emit(&e2, &path).unwrap();

    let body = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed["source"], "modules");
    assert_eq!(parsed["module"], "agent-guard");
    assert_eq!(parsed["status"], "ok");
}

#[test]
fn emit_appends_does_not_truncate() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("modules.jsonl");
    fs::write(&path, "PRE-EXISTING-LINE\n").unwrap();

    let e = HistoryEvent::now("a", "b", "ok");
    emit(&e, &path).unwrap();

    let body = fs::read_to_string(&path).unwrap();
    assert!(
        body.starts_with("PRE-EXISTING-LINE\n"),
        "first line should be preserved; got: {body:?}"
    );
    assert!(body.lines().count() >= 2);
}

#[test]
fn emit_creates_parent_directory() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("nested/sub/dir/modules.jsonl");
    let e = HistoryEvent::now("m", "ev", "ok");
    emit(&e, &path).unwrap();
    assert!(path.exists());
}

#[test]
fn emit_rejects_invalid_event_before_writing() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("modules.jsonl");
    let mut e = HistoryEvent::now("m", "ev", "ok");
    e.status = "definitely-bogus".into();
    assert!(emit(&e, &path).is_err());
    assert!(!path.exists(), "invalid event must not create the file");
}

#[test]
fn detail_round_trips_via_serde() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("modules.jsonl");
    let e =
        HistoryEvent::now("agent-guard", "policy-applied", "ok").with_detail(serde_json::json!({
            "policy": "default",
            "rules": 42,
        }));
    emit(&e, &path).unwrap();
    let body = fs::read_to_string(&path).unwrap();
    let v: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(v["detail"]["policy"], "default");
    assert_eq!(v["detail"]["rules"], 42);
}

#[test]
fn validate_helper_is_pub() {
    let e = HistoryEvent::now("m", "ev", "ok");
    validate(&e).unwrap();
}

#[test]
fn emit_default_uses_resolved_path() {
    // We cannot safely write to /var/log in the test sandbox, so
    // validate that resolve_log_path() returns an absolute path
    // matching the contract. Live writes through emit_default() are
    // covered by emit() above (emit_default just forwards).
    let p = resolve_log_path();
    assert!(p.is_absolute());
    // Smoke: emit_default with a known-invalid event should not write
    let mut bad = HistoryEvent::now("m", "ev", "ok");
    bad.status = "bogus".into();
    assert!(emit_default(&bad).is_err());
}
