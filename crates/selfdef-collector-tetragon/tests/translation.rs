//! SDD-005 Test-6 / closes F-2026-036: tetragon collector
//! isolation tests. Pre-SDD-005, every translation went through
//! the daemon pipeline tests; a regression in the collector's
//! translation logic would have been caught only via the
//! pipeline's end-to-end shape. These tests exercise
//! `TetragonCollector::translate_line` in isolation, giving us
//! fast feedback per branch.
//!
//! See `docs/dev/test-contract.md` for the Category 1
//! (translation) contract this file satisfies.

use selfdef_bus::Bus;
use selfdef_collector_tetragon::{ReadFrom, TetragonCollector};
use selfdef_core::category::ClassUid;

fn new_collector() -> TetragonCollector {
    // The collector's tail file path doesn't matter for
    // translation-only tests; we never call `run()`.
    let bus = Bus::new(16);
    TetragonCollector::new(
        std::path::PathBuf::from("/dev/null"),
        ReadFrom::End,
        bus.publisher(),
        "host-test".into(),
    )
}

#[test]
fn process_exec_translates_to_process_activity_launch() {
    let c = new_collector();
    let line = r#"{"process_exec":{"process":{"pid":4242,"binary":"/usr/bin/ls","arguments":"-la /tmp","uid":1000},"parent":{"pid":1}}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::PROCESS_ACTIVITY);
    assert_eq!(ev.activity_id, 1, "exec is Launch (activity_id=1)");
    let p = ev.process.expect("process attached");
    assert_eq!(p.pid, 4242);
    assert_eq!(p.parent_pid, Some(1));
    assert_eq!(p.path.as_deref(), Some("/usr/bin/ls"));
    assert_eq!(p.cmdline.as_deref(), Some("/usr/bin/ls -la /tmp"));
    assert_eq!(p.user.as_ref().and_then(|u| u.uid), Some(1000));
}

#[test]
fn process_kprobe_file_open_translates_to_file_system_activity() {
    let c = new_collector();
    let line = r#"{"process_kprobe":{"function_name":"security_file_open","process":{"pid":1,"binary":"/usr/bin/cat"},"args":[{"file_arg":{"path":"/etc/shadow"}}]}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::FILE_SYSTEM_ACTIVITY);
    let f = ev.file.expect("file attached");
    assert_eq!(f.path.as_deref(), Some("/etc/shadow"));
}

#[test]
fn process_kprobe_socket_branches_to_network_activity() {
    let c = new_collector();
    let line = r#"{"process_kprobe":{"function_name":"__sys_connect","process":{"pid":2,"binary":"/usr/bin/curl"},"args":[]}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::NETWORK_ACTIVITY);
    assert_eq!(ev.activity_id, 1);
}

#[test]
fn process_kprobe_unknown_function_falls_back_to_kernel_activity() {
    let c = new_collector();
    let line = r#"{"process_kprobe":{"function_name":"some_unknown_kfunc","process":{"pid":3,"binary":"/usr/bin/bash"},"args":[]}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::KERNEL_ACTIVITY);
}

#[test]
fn process_kprobe_carries_structured_tetragon_subobject() {
    // SDD-001 D-1 / SDD-005 Test-6: every process_kprobe event
    // must carry a stable `raw.tetragon.{policy_name,
    // policy_namespace, action, function_name}` so sigma rules
    // promote agent-guard policy events to Findings without
    // re-walking the upstream JSON.
    let c = new_collector();
    let line = r#"{"process_kprobe":{"function_name":"security_file_open","policy_name":"selfdef-agent-etc-write-guard","policy_namespace":"default","action":"Sigkill","process":{"pid":42,"binary":"/usr/bin/sed"},"args":[{"file_arg":{"path":"/etc/shadow"}}]}}"#;
    let ev = c.translate_line(line).expect("translates");
    let raw = ev.raw.expect("raw payload preserved");
    let tetragon = raw.get("tetragon").expect("raw.tetragon subobject");
    assert_eq!(
        tetragon.get("policy_name").and_then(|v| v.as_str()),
        Some("selfdef-agent-etc-write-guard"),
    );
    assert_eq!(
        tetragon.get("policy_namespace").and_then(|v| v.as_str()),
        Some("default"),
    );
    assert_eq!(
        tetragon.get("action").and_then(|v| v.as_str()),
        Some("Sigkill"),
    );
    assert_eq!(
        tetragon.get("function_name").and_then(|v| v.as_str()),
        Some("security_file_open"),
    );
    // The original Tetragon payload must be preserved alongside
    // so consumers that already walk it keep working.
    assert!(raw.get("process_kprobe").is_some());
}

#[test]
fn process_exit_translates_to_process_terminate() {
    let c = new_collector();
    let line = r#"{"process_exit":{"process":{"pid":99,"binary":"/usr/bin/false"}}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::PROCESS_ACTIVITY);
    assert_eq!(ev.activity_id, 2, "exit is Terminate (activity_id=2)");
}

#[test]
fn unknown_top_level_event_falls_back_to_generic() {
    let c = new_collector();
    // Tetragon emits new top-level event types in future
    // versions; the collector must not drop them — it builds a
    // generic Event with the raw payload so downstream sigma
    // rules can still match.
    let line = r#"{"future_event":{"foo":"bar"}}"#;
    let ev = c.translate_line(line).expect("translates");
    assert_eq!(ev.class_uid, ClassUid::new(0));
    let raw = ev.raw.expect("raw preserved");
    assert!(raw.get("future_event").is_some());
}

// --- tolerance branch (Category 1 contract requires it) ---

#[test]
fn empty_line_is_soft_skipped() {
    let c = new_collector();
    assert!(c.translate_line("").is_none());
}

#[test]
fn malformed_json_is_soft_skipped_not_panicked() {
    // Tetragon export-stderr can interleave non-JSON tracing
    // lines if misconfigured. The collector must log + drop the
    // line, never panic.
    let c = new_collector();
    assert!(c.translate_line("not json").is_none());
    assert!(c.translate_line("{ unbalanced").is_none());
}

#[test]
fn process_kprobe_missing_fields_produces_event_without_panicking() {
    // A kprobe line missing `process`/`args` shouldn't crash —
    // upstream Tetragon shipped malformed shapes during early
    // M5 dev; collector resilience is a documented promise.
    let c = new_collector();
    let line = r#"{"process_kprobe":{"function_name":"security_file_open"}}"#;
    let ev = c.translate_line(line).expect("translates");
    // pid defaulted to 0 → no Process attached.
    assert!(
        ev.process.is_none(),
        "missing pid means no Process: {:?}",
        ev.process
    );
    // No file_arg → no File attached.
    assert!(ev.file.is_none());
}
