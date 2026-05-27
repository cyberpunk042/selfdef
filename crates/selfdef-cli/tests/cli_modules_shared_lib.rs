//! SDD-006 integration tests for the shared module-script lib.
//!
//! Asserts: (1) selfdefctl exports `SELFDEF_MODULE_LIB` for every
//! script it spawns; (2) sourcing the shared lib with a satisfiable
//! version requirement works end-to-end; (3) requesting a higher
//! version than the lib provides aborts with exit 99 and a clear
//! stderr message.

use std::path::{Path, PathBuf};
use std::process::Command;

// F-2027-049 / -051: helpers live in common/mod.rs.
mod common;
use common::{workspace_root, write_executable};

fn shared_lib_path() -> PathBuf {
    workspace_root().join("packaging/lib/module-lib.sh")
}

fn run_apply(host_cfg: &Path, catalog: &Path, daemon_cfg: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_selfdefctl"))
        .args([
            "--config",
            daemon_cfg.to_str().unwrap(),
            "modules",
            "apply",
            "--host-config",
            host_cfg.to_str().unwrap(),
            "--dir",
            catalog.to_str().unwrap(),
            "--ignore-daemon-requires",
            "--dry-run",
        ])
        .output()
        .expect("spawn selfdefctl")
}

fn stage_lib_consuming_module(catalog: &Path, slug: &str, lib_body: &str) {
    let modroot = catalog.join(slug);
    std::fs::create_dir_all(modroot.join("install")).unwrap();
    std::fs::write(modroot.join("install/lib.sh"), lib_body).unwrap();
    let apply_body = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
MODULE="{slug}"
DRY_RUN="${{SELFDEF_DRY_RUN:-0}}"
# shellcheck source=lib.sh
source "${{BASH_SOURCE[0]%/*}}/lib.sh"

log "hello from {slug}"
emit_status "ok" "shared-lib smoke test"
"#
    );
    write_executable(&modroot.join("install/apply.sh"), &apply_body);
    let manifest = format!(
        r#"
name = "{slug}"
version = "0.0.0"
summary = "shared-lib smoke"
category = "test"

[install]
kind = "script"
apply = "install/apply.sh"
"#
    );
    std::fs::write(modroot.join("module.toml"), manifest).unwrap();
}

#[test]
fn dispatcher_exports_module_lib_env_var() {
    // Stage a tiny module whose apply.sh logs the value of
    // $SELFDEF_MODULE_LIB into the JSON status message. We then
    // run it via selfdefctl and assert the env var reached the
    // script.
    let scratch = tempfile::tempdir().unwrap();
    let catalog = scratch.path().join("catalog");
    let modroot = catalog.join("envprobe");
    std::fs::create_dir_all(modroot.join("install")).unwrap();
    let apply_body = r#"#!/usr/bin/env bash
set -euo pipefail
MODULE="envprobe"
emit_status() {
    local s="$1" m="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' "$MODULE" "$s" "${m//\"/\\\"}"
}
emit_status "ok" "lib=${SELFDEF_MODULE_LIB:-UNSET}"
"#;
    write_executable(&modroot.join("install/apply.sh"), apply_body);
    let manifest = r#"
name = "envprobe"
version = "0.0.0"
summary = "envprobe"
category = "test"

[install]
kind = "script"
apply = "install/apply.sh"
"#;
    std::fs::write(modroot.join("module.toml"), manifest).unwrap();

    let host_cfg = scratch.path().join("modules.toml");
    std::fs::write(&host_cfg, "[modules.envprobe]\n").unwrap();
    let daemon_cfg = scratch.path().join("selfdef.toml");
    std::fs::write(&daemon_cfg, "").unwrap();

    let out = run_apply(&host_cfg, &catalog, &daemon_cfg);
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("lib=UNSET"),
        "SELFDEF_MODULE_LIB should be set; stdout: {stdout}",
    );
    // The dispatcher should resolve to either the workspace path
    // or the installed path. In this test harness it's the
    // workspace path.
    assert!(
        stdout.contains("module-lib.sh"),
        "expected SELFDEF_MODULE_LIB to point at module-lib.sh; stdout: {stdout}",
    );
}

#[test]
fn module_sourcing_shared_lib_at_v1_succeeds() {
    // A module whose lib.sh requires v1 (the current library
    // version) sources successfully and the apply emits ok.
    let scratch = tempfile::tempdir().unwrap();
    let catalog = scratch.path().join("catalog");
    let lib_body = format!(
        r#"# Smoke-test lib.
SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
# shellcheck disable=SC1090,SC2034
source "{}"
"#,
        shared_lib_path().display(),
    );
    stage_lib_consuming_module(&catalog, "smoke", &lib_body);

    let host_cfg = scratch.path().join("modules.toml");
    std::fs::write(&host_cfg, "[modules.smoke]\n").unwrap();
    let daemon_cfg = scratch.path().join("selfdef.toml");
    std::fs::write(&daemon_cfg, "").unwrap();

    let out = run_apply(&host_cfg, &catalog, &daemon_cfg);
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok: shared-lib smoke test")
            && stdout.contains("1 ok, 0 skipped, 0 failed"),
        "stdout: {stdout}",
    );
}

#[test]
fn module_requesting_newer_lib_version_is_refused() {
    // A module declaring SELFDEF_MODULE_LIB_VERSION_REQUIRED=99
    // sources against the v1 lib. The lib must abort with exit 99
    // and a stderr message naming the version mismatch.
    let scratch = tempfile::tempdir().unwrap();
    let catalog = scratch.path().join("catalog");
    let lib_body = format!(
        r#"# Version-mismatch smoke-test lib.
SELFDEF_MODULE_LIB_VERSION_REQUIRED=99
# shellcheck disable=SC1090,SC2034
source "{}"
"#,
        shared_lib_path().display(),
    );
    stage_lib_consuming_module(&catalog, "needsv99", &lib_body);

    let host_cfg = scratch.path().join("modules.toml");
    std::fs::write(&host_cfg, "[modules.needsv99]\n").unwrap();
    let daemon_cfg = scratch.path().join("selfdef.toml");
    std::fs::write(&daemon_cfg, "").unwrap();

    let out = run_apply(&host_cfg, &catalog, &daemon_cfg);
    // selfdefctl returns non-zero when a module's apply exits
    // non-zero (the lib aborts with 99; the dispatcher surfaces
    // that as a failed outcome).
    assert!(
        !out.status.success(),
        "expected non-zero exit; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // The "have" version is whatever the shared lib currently declares —
    // read it so this stays correct across SELFDEF_MODULE_LIB_VERSION bumps
    // (was hardcoded "have 2"; the lib is now v4 — the stale literal was the
    // pre-existing test-job failure this fixes).
    let lib_src = std::fs::read_to_string(shared_lib_path()).unwrap();
    let have_ver = lib_src
        .lines()
        .find_map(|l| l.strip_prefix("SELFDEF_MODULE_LIB_VERSION="))
        .expect("shared lib declares SELFDEF_MODULE_LIB_VERSION")
        .trim();
    assert!(
        combined.contains("shared module-lib version mismatch")
            && combined.contains("require >=99")
            && combined.contains(&format!("have {have_ver}")),
        "expected version-mismatch diagnostic; got:\n{combined}",
    );
}
