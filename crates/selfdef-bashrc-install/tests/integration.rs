//! Integration tests for the SD-R-BASHRC-1 installer. Exercises the
//! bash script end-to-end via `std::process::Command` against a
//! temp-dir bashrc fixture.

use selfdef_bashrc_install::{
    BLOCK_BEGIN_SENTINEL, BLOCK_END_SENTINEL, COMPLETION_TOP_VERBS, INSTALLER_REL_PATH,
    SHIPPED_ALIASES,
};
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points to .../crates/selfdef-bashrc-install
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn installer_path() -> PathBuf {
    repo_root().join(INSTALLER_REL_PATH)
}

fn run_installer(verb: &str, bashrc_path: &std::path::Path) -> std::process::Output {
    Command::new(installer_path())
        .arg(verb)
        .env("SELFDEF_BASHRC_PATH", bashrc_path)
        .env_remove("SOVEREIGN_OS_DRY_RUN")
        .env_remove("SELFDEF_BASHRC_DRY_RUN")
        .output()
        .expect("failed to invoke installer script")
}

#[test]
fn installer_script_exists_and_is_executable() {
    let p = installer_path();
    assert!(p.is_file(), "installer missing at {p:?}");
    let meta = std::fs::metadata(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "installer not executable: mode={mode:o}");
    }
    let _ = meta;
}

#[test]
fn status_on_empty_bashrc_reports_not_installed() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    std::fs::write(&bashrc, "# existing content\n").unwrap();
    let out = run_installer("status", &bashrc);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "status failed: {out:?}");
    assert!(
        stdout.contains("not installed"),
        "expected 'not installed'; got {stdout}"
    );
}

#[test]
fn install_then_status_reports_installed() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    std::fs::write(&bashrc, "# existing content\n").unwrap();
    let out = run_installer("install", &bashrc);
    assert!(out.status.success(), "install failed: {out:?}");
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(body.contains(BLOCK_BEGIN_SENTINEL));
    assert!(body.contains(BLOCK_END_SENTINEL));
    let st = run_installer("status", &bashrc);
    let st_out = String::from_utf8_lossy(&st.stdout);
    assert!(st_out.contains("installed at"));
}

#[test]
fn install_preserves_pre_existing_content() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let pre = "# OPERATOR-EDIT-PRE\nexport FOO=bar\n";
    std::fs::write(&bashrc, pre).unwrap();
    run_installer("install", &bashrc);
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(
        body.contains("# OPERATOR-EDIT-PRE"),
        "operator-anti-destruction: pre-existing content lost"
    );
    assert!(body.contains("export FOO=bar"));
}

#[test]
fn double_install_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    std::fs::write(&bashrc, "").unwrap();
    run_installer("install", &bashrc);
    run_installer("install", &bashrc);
    let body = std::fs::read_to_string(&bashrc).unwrap();
    let begin_count = body.matches(BLOCK_BEGIN_SENTINEL).count();
    let end_count = body.matches(BLOCK_END_SENTINEL).count();
    assert_eq!(
        begin_count, 1,
        "block appears {begin_count} times after 2× install"
    );
    assert_eq!(end_count, 1);
}

#[test]
fn uninstall_removes_block_keeps_other_content() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let pre = "# OPERATOR-EDIT-PRE\nalias x='y'\n";
    std::fs::write(&bashrc, pre).unwrap();
    run_installer("install", &bashrc);
    run_installer("uninstall", &bashrc);
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(!body.contains(BLOCK_BEGIN_SENTINEL));
    assert!(!body.contains(BLOCK_END_SENTINEL));
    assert!(body.contains("# OPERATOR-EDIT-PRE"));
    assert!(body.contains("alias x='y'"));
    let backup = bashrc.with_extension("bashrc.selfdef-bashrc-bak");
    // Backup is at <path>.selfdef-bashrc-bak (suffix appended to
    // full path including extension).
    let backup_alt = bashrc.with_file_name(".bashrc.selfdef-bashrc-bak");
    assert!(
        backup.exists() || backup_alt.exists(),
        "no backup file found; checked {backup:?} and {backup_alt:?}"
    );
}

#[test]
fn dump_emits_block_with_sentinels() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let out = run_installer("dump", &bashrc);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains(BLOCK_BEGIN_SENTINEL));
    assert!(stdout.contains(BLOCK_END_SENTINEL));
}

#[test]
fn dump_includes_all_documented_aliases() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let out = run_installer("dump", &bashrc);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for alias in SHIPPED_ALIASES {
        assert!(
            stdout.contains(&format!("alias {alias}=")),
            "missing alias {alias} in dump output"
        );
    }
}

#[test]
fn dump_completion_covers_all_top_verbs() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let out = run_installer("dump", &bashrc);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in COMPLETION_TOP_VERBS {
        assert!(
            stdout.contains(verb),
            "tab-completion missing top-level verb {verb}"
        );
    }
}

#[test]
fn dump_includes_sdhelp_menu_function() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let out = run_installer("dump", &bashrc);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sdhelp-menu()"));
    assert!(stdout.contains("operator quick reference"));
}

#[test]
fn unknown_verb_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    let out = Command::new(installer_path())
        .arg("bogus-verb")
        .env("SELFDEF_BASHRC_PATH", &bashrc)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn dry_run_env_short_circuits_install() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    std::fs::write(&bashrc, "# untouched\n").unwrap();
    let out = Command::new(installer_path())
        .arg("install")
        .env("SELFDEF_BASHRC_PATH", &bashrc)
        .env("SELFDEF_BASHRC_DRY_RUN", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DRY-RUN"));
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(!body.contains(BLOCK_BEGIN_SENTINEL));
}

#[test]
fn sovereign_os_dry_run_env_also_honored() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    std::fs::write(&bashrc, "# untouched\n").unwrap();
    let out = Command::new(installer_path())
        .arg("install")
        .env("SELFDEF_BASHRC_PATH", &bashrc)
        .env("SOVEREIGN_OS_DRY_RUN", "1")
        .env_remove("SELFDEF_BASHRC_DRY_RUN")
        .output()
        .unwrap();
    assert!(out.status.success());
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(
        !body.contains(BLOCK_BEGIN_SENTINEL),
        "cross-repo SOVEREIGN_OS_DRY_RUN should short-circuit"
    );
}

#[test]
fn install_creates_bashrc_if_missing() {
    let tmp = TempDir::new().unwrap();
    let bashrc = tmp.path().join(".bashrc");
    // Do NOT pre-create; installer must touch it.
    let out = run_installer("install", &bashrc);
    assert!(out.status.success(), "install with missing bashrc: {out:?}");
    assert!(bashrc.exists());
    let body = std::fs::read_to_string(&bashrc).unwrap();
    assert!(body.contains(BLOCK_BEGIN_SENTINEL));
}
