//! Integration tests for `selfdefctl init`. Covers each
//! subcommand's happy path + the --force semantics that
//! protect operators from accidentally clobbering an existing
//! `/etc/selfdef/selfdef.toml`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn run_init(args: &[&str]) -> std::process::Output {
    Command::new(binary())
        .args(["init"].iter().chain(args.iter()))
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn init_config_writes_starter_file_at_0644() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("selfdef.toml");
    let out = run_init(&["config", "--output", target.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(target.exists(), "config file must exist");
    let body = std::fs::read_to_string(&target).unwrap();
    assert!(body.contains("[daemon]"), "starter must have [daemon]");
    assert!(body.contains("[security]"), "starter must have [security]");
    assert!(
        body.contains("require_signed_rules    = false"),
        "every opt-in must default OFF",
    );
    // F-2027-009: commented [notifier.ntfy] stanza inline so
    // operators see the shape without grepping the example file.
    assert!(
        body.contains("# [notifier.ntfy]") && body.contains("# server") && body.contains("# topic"),
        "starter must embed a commented [notifier.ntfy] example",
    );
    let md = std::fs::metadata(&target).unwrap();
    assert_eq!(md.permissions().mode() & 0o777, 0o644);
}

#[test]
fn init_config_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("selfdef.toml");
    std::fs::write(&target, "# pre-existing\n").unwrap();
    let out = run_init(&["config", "--output", target.to_str().unwrap()]);
    assert!(!out.status.success(), "should refuse to clobber");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}",);
    // Pre-existing content must be untouched.
    let body = std::fs::read_to_string(&target).unwrap();
    assert_eq!(body, "# pre-existing\n");
}

#[test]
fn init_config_force_overwrites_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("selfdef.toml");
    std::fs::write(&target, "# pre-existing\n").unwrap();
    let out = run_init(&["config", "--output", target.to_str().unwrap(), "--force"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let body = std::fs::read_to_string(&target).unwrap();
    assert!(body.contains("[daemon]"), "should be the starter content");
    assert!(
        !body.contains("# pre-existing"),
        "pre-existing content should be gone",
    );
}

#[test]
fn init_modules_writes_starter_with_every_module_commented_out() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("modules.toml");
    let out = run_init(&["modules", "--output", target.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&target).unwrap();
    // Every shipped module should be mentioned (commented).
    for slug in [
        "tetragon",
        "agent-guard",
        "integrity-sentinel",
        "bridge-l2",
        "suricata",
        "polarproxy",
        "vpn-bridge",
        "observability",
        "detect-host",
    ] {
        assert!(
            body.contains(slug),
            "starter must mention {slug}; body:\n{body}",
        );
    }
    // Crucially: NO module should be actually enabled out of the box.
    // Every [modules.<slug>] header line must be commented.
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[modules.") {
            panic!("uncommented module activation in starter: {trimmed}\nbody:\n{body}",);
        }
    }
}

#[test]
fn init_modules_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("modules.toml");
    std::fs::write(&target, "[modules.tetragon]\n").unwrap();
    let out = run_init(&["modules", "--output", target.to_str().unwrap()]);
    assert!(!out.status.success());
    let body = std::fs::read_to_string(&target).unwrap();
    assert_eq!(body, "[modules.tetragon]\n");
}

#[test]
fn init_checklist_prints_to_stdout_without_filesystem_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let before: std::collections::BTreeSet<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let out = Command::new(binary())
        .args(["init", "checklist"])
        .current_dir(tmp.path())
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("first-run checklist"), "stdout: {stdout}",);
    assert!(
        stdout.contains("selfdefctl init config"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("selfdefctl doctor"), "stdout: {stdout}");
    assert!(stdout.contains("rotate-token"), "stdout: {stdout}");
    // Filesystem in CWD must be unchanged.
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(before, after, "checklist must not touch the filesystem");
}

#[test]
fn init_config_creates_parent_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("nested/dir/selfdef.toml");
    assert!(!target.parent().unwrap().exists(), "precondition");
    let out = run_init(&["config", "--output", target.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(target.exists());
}
