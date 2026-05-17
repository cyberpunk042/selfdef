//! SD-R97 (E8.M6) — REPL token-saving aliases + wasted-path tracker.
//! Operator-named (§1b): "save/need less tokens, save wasted paths
//! / useless tracks".

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn bootstrap_source() -> String {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "bootstrap"])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn sdr97_bootstrap_defines_all_token_saving_aliases() {
    let src = bootstrap_source();
    // Each compact alias has a `def X(` line in the script.
    for alias in [
        "def h(", "def p(", "def m(", "def mi(", "def md(", "def mio(", "def mip(", "def lo(",
        "def la(", "def ld(", "def ls(", "def mt(", "def mtt(", "def rh(",
    ] {
        assert!(
            src.contains(alias),
            "missing alias definition `{alias}` in bootstrap"
        );
    }
}

#[test]
fn sdr97_bootstrap_defines_track_decorator() {
    let src = bootstrap_source();
    assert!(src.contains("def track("), "missing @track decorator");
    // Tracker must invoke the existing _record_history helper.
    assert!(
        src.contains("_record_history"),
        "@track must call _record_history"
    );
    // Empty-result detection is part of the spec.
    assert!(
        src.contains("empty-result"),
        "@track must classify empty-result"
    );
}

#[test]
fn sdr97_bootstrap_is_valid_python_with_aliases() {
    // Compile the entire bootstrap source as Python to catch any
    // syntax error introduced by the SD-R97 additions.
    let src = bootstrap_source();
    let out = Command::new("python3")
        .arg("-c")
        .arg(format!("{src}\nimport sys; names = sorted(n for n in dir() if not n.startswith('_')); print('|'.join(names))"))
        .output()
        .expect("spawn python3");
    assert!(
        out.status.success(),
        "python3 exec failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let names = String::from_utf8_lossy(&out.stdout);
    // Every alias lands in the namespace.
    for alias in [
        "h", "p", "m", "mi", "md", "mio", "mip", "lo", "la", "ld", "ls", "mt", "mtt", "rh", "track",
    ] {
        assert!(
            names.contains(alias),
            "Python namespace missing alias `{alias}`: {names}"
        );
    }
}

#[test]
fn sdr97_track_decorator_classifies_outcomes_in_isolation() {
    // Run bootstrap + an in-Python test exercising @track's
    // classification logic without needing a real selfdefctl binary.
    // Use a tempfile so Python indentation isn't mangled by Rust's
    // format! string concatenation.
    let src = bootstrap_source();
    let probe_body = r#"
@track('test-none')
def _t1():
    return None

@track('test-empty-list')
def _t2():
    return []

@track('test-ok')
def _t3():
    return {'data': 1}

@track('test-raise')
def _t4():
    raise ValueError('synthetic')

import sys
try:
    r1 = _t1()
    assert r1 is None
    r2 = _t2()
    assert r2 == []
    r3 = _t3()
    assert r3 == {'data': 1}
    try:
        _t4()
        print('SHOULD_HAVE_RAISED', file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        assert str(e) == 'synthetic'
    print('PASS')
except Exception as e:
    print(f'FAIL: {type(e).__name__}: {e}', file=sys.stderr)
    sys.exit(1)
"#;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe_body}")).unwrap();
    let out = Command::new("python3")
        .arg(&script)
        .output()
        .expect("spawn python3");
    assert!(
        out.status.success(),
        "@track unit test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PASS"),
        "expected PASS marker; got {stdout}"
    );
}

#[test]
fn sdr97_alias_h_delegates_to_hardware_full_name() {
    // Inspecting source — the compact `h()` must call `hardware()`
    // (not `_ctl(...)` directly) so the alias inherits the full
    // function's _record_history side-effect.
    let src = bootstrap_source();
    // Find the body of `def h():` — operator-readable contract.
    let h_idx = src.find("def h():").expect("def h() should exist");
    let after = &src[h_idx..];
    // The 3 lines after `def h():` should reference hardware().
    let head = after.lines().take(4).collect::<Vec<_>>().join("\n");
    assert!(
        head.contains("hardware()"),
        "def h(): body must call hardware() — keeps audit trail intact; got: {head}"
    );
}

#[test]
fn sdr97_aliases_advertised_in_repl_banner() {
    let src = bootstrap_source();
    // Banner must list at least one alias example so operators see
    // the compact set without re-reading the source.
    assert!(
        src.contains("SD-R97 token-saving aliases"),
        "banner must announce the SD-R97 aliases"
    );
    assert!(
        src.contains("@track"),
        "banner must mention the @track decorator"
    );
}
