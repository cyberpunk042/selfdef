//! SD-R79 (SDD-025 Y-1) — apply-time observability for `any_of`
//! OR-predicate resolution. When a module passes via an OR-branch
//! (vs the root-only path), the apply path emits an operator-visible
//! `# SD-R79: module X resolved via [[requires_hardware.any_of]]`
//! stderr block citing which branch index matched.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Stage a module whose [requires_hardware] declares ONLY an
/// any_of array, where the FIRST branch is trivially-empty so the
/// gate always passes via any_of[0] on any host (including CI runners
/// without AVX-512).
fn stage_anyof_module(dir: &std::path::Path) {
    let slug = "anyof-pass-module";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "anyof-pass-module"
version     = "0.1.0"
summary     = "SD-R79 demo — passes via any_of[0]"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"

[requires_hardware]
# Two OR-branches. The first is trivially-empty (always passes);
# the second demands an impossible flag (would fail). The gate
# must match branch 0 + emit "any_of[0] matched" on stderr.

[[requires_hardware.any_of]]
# Empty branch — always passes.

[[requires_hardware.any_of]]
host_features_required = "absolutely-no-such-flag"

[install]
kind = "script"
"#,
    )
    .unwrap();
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\nprintf '{\"module\":\"anyof-pass-module\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

/// Stage a module with NO any_of (root-only requirements that pass
/// trivially). Used to verify SD-R79 stays SILENT when no module
/// resolves via any_of.
fn stage_root_only_module(dir: &std::path::Path) {
    let slug = "root-only-module";
    let sub = dir.join(slug);
    std::fs::create_dir_all(sub.join("install")).unwrap();
    std::fs::write(
        sub.join("module.toml"),
        r#"
name        = "root-only-module"
version     = "0.1.0"
summary     = "SD-R79 silence pin — gate via root-only predicates"
category    = "detection"
depends_on  = []
provides    = []
consumes    = []
phase       = "main"

[requires_hardware]
memory_gib_min = 1
[install]
kind = "script"
"#,
    )
    .unwrap();
    for s in ["apply.sh", "check.sh", "uninstall.sh"] {
        let p = sub.join("install").join(s);
        std::fs::write(
            &p,
            "#!/usr/bin/env bash\nprintf '{\"module\":\"root-only-module\",\"status\":\"ok\",\"message\":\"\"}\\n'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&p, perms).unwrap();
        }
    }
}

fn write_host_config(dir: &std::path::Path, slug: &str) -> PathBuf {
    let host_config = dir.join("modules.toml");
    std::fs::write(&host_config, format!("[modules.{slug}]\n")).unwrap();
    host_config
}

#[test]
fn sdr79_apply_emits_stderr_line_when_anyof_branch_matches() {
    let dir = tempfile::tempdir().unwrap();
    stage_anyof_module(dir.path());
    let host_config = write_host_config(dir.path(), "anyof-pass-module");

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "apply",
            "--dir",
            dir.path().to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SD-R79"),
        "expected SD-R79 banner on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("any_of[0] matched"),
        "expected branch 0 match marker, got: {stderr}"
    );
    assert!(
        stderr.contains("anyof-pass-module"),
        "expected module name in SD-R79 block, got: {stderr}"
    );
}

#[test]
fn sdr79_apply_silent_when_no_module_resolves_via_anyof() {
    let dir = tempfile::tempdir().unwrap();
    stage_root_only_module(dir.path());
    let host_config = write_host_config(dir.path(), "root-only-module");

    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "modules",
            "apply",
            "--dir",
            dir.path().to_str().unwrap(),
            "--host-config",
            host_config.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("SD-R79"),
        "expected NO SD-R79 banner for root-only gate, got: {stderr}"
    );
}
