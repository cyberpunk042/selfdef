//! Shared helpers for the CLI integration test suites.
//!
//! Most module tests need the same primitives: locate the workspace
//! root, locate a module's source dir, write an executable file
//! into a tempdir, capture the last stdout line of an exit'd
//! process. Before this module those helpers were duplicated across
//! every `module_*.rs` file (≈9 copies). Closes the duplication
//! half of F-2026-060; per-test migration to use this module
//! follows in incremental PRs.
//!
//! Per Rust's `tests/` convention, this file is included by each
//! integration test that wants it via `mod common;` at the top of
//! the test file. Cargo silently allows the unused-imports warning
//! when an individual test file uses only a subset of the helpers,
//! so the module is annotated `#[allow(dead_code)]`.

#![allow(dead_code)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn module_dir(slug: &str) -> PathBuf {
    workspace_root().join("modules").join(slug)
}

/// Write a file, creating any missing parent directories. Test
/// fixtures use this to drop config files into a tempdir.
pub fn write_file(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

/// Same as [`write_file`] but `chmod 0755` after the write so the
/// resulting path can be exec'd directly. Used by the per-module
/// tests that stub a binary on `PATH`.
pub fn write_executable(path: &Path, body: &str) {
    write_file(path, body);
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Return the last non-empty stdout line of an exited process.
/// Module install scripts emit their structured-status JSON as the
/// final line; tests assert against it.
pub fn last_stdout_line(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Build a `PATH` value that prefixes `extra` onto the inherited
/// `PATH`. Tests that need to shim a system binary (`tetragon`,
/// `systemctl`, `nft`, …) write the stubs into a tempdir and pass
/// that dir through this helper.
pub fn prepended_path(extra: &Path) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut out = std::ffi::OsString::from(extra);
    out.push(":");
    out.push(&existing);
    out
}
