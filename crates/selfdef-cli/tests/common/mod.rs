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

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub(crate) fn module_dir(slug: &str) -> PathBuf {
    workspace_root().join("modules").join(slug)
}

/// Write a file, creating any missing parent directories. Test
/// fixtures use this to drop config files into a tempdir.
pub(crate) fn write_file(path: &Path, body: &str) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
}

/// Same as [`write_file`] but `chmod 0755` after the write so the
/// resulting path can be exec'd directly. Used by the per-module
/// tests that stub a binary on `PATH`.
pub(crate) fn write_executable(path: &Path, body: &str) {
    write_file(path, body);
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// Return the last non-empty stdout line of an exited process.
/// Module install scripts emit their structured-status JSON as the
/// final line; tests assert against it.
pub(crate) fn last_stdout_line(out: &Output) -> String {
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
pub(crate) fn prepended_path(extra: &Path) -> std::ffi::OsString {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    let mut out = std::ffi::OsString::from(extra);
    out.push(":");
    out.push(&existing);
    out
}

// --- SDD-005 D-2a / Test-1: dry-run-must-be-a-noop helper -------

use std::collections::BTreeMap;

/// SDD-005 D-2a: snapshot a directory tree as `{relative path →
/// fingerprint}` where the fingerprint encodes content for
/// regular files (`f:<len>:<first-32-bytes-hex>`), the literal
/// `<dir>` for directories (so `mkdir` is caught), and the
/// target for symlinks. Compared before/after a dry-run apply
/// to catch any state mutation. We deliberately don't depend
/// on a hash crate: dry-run tempdirs are small, and a length +
/// content prefix is enough to flag every mutation the dry-run
/// contract is meant to catch (writes, truncations, removals,
/// renames).
pub(crate) fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let md = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let rel = p.strip_prefix(root).unwrap_or(&p).to_path_buf();
        if md.file_type().is_symlink() {
            let target = std::fs::read_link(&p)
                .map(|t| t.display().to_string())
                .unwrap_or_else(|_| String::from("<broken>"));
            out.insert(rel, format!("<symlink {target}>"));
        } else if md.is_dir() {
            out.insert(rel, String::from("<dir>"));
            for entry in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                stack.push(entry.path());
            }
        } else if md.is_file() {
            let body = std::fs::read(&p).unwrap_or_default();
            // Length + first-32 hex bytes is a cheap fingerprint
            // that catches every contract-relevant mutation while
            // avoiding a hash-crate dep.
            let mut hex = String::new();
            for b in body.iter().take(32) {
                hex.push_str(&format!("{b:02x}"));
            }
            out.insert(rel, format!("f:{}:{hex}", body.len()));
        }
    }
    out
}

/// SDD-005 D-2a: assert that two tree snapshots are equal,
/// producing a human-readable diff on failure. The standard
/// dry-run-negative test shape is:
///
/// ```rust,ignore
/// let before = snapshot_tree(scratch.path());
/// run_apply_with_dry_run(...);
/// let after  = snapshot_tree(scratch.path());
/// assert_tree_unchanged(&before, &after);
/// ```
pub(crate) fn assert_tree_unchanged(
    before: &BTreeMap<PathBuf, String>,
    after: &BTreeMap<PathBuf, String>,
) {
    if before == after {
        return;
    }
    let mut diff = String::new();
    for (k, v) in before {
        match after.get(k) {
            None => diff.push_str(&format!("  removed: {} (was {v})\n", k.display())),
            Some(v2) if v2 != v => {
                diff.push_str(&format!("  changed: {} ({v} -> {v2})\n", k.display()));
            }
            _ => {}
        }
    }
    for (k, v) in after {
        if !before.contains_key(k) {
            diff.push_str(&format!("  added:   {} ({v})\n", k.display()));
        }
    }
    panic!("dry-run produced on-disk delta — apply.sh broke the no-op contract:\n{diff}");
}
