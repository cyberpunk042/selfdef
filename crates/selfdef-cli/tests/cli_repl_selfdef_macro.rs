//! SD-R98 (E8.M4) — integrated-intelligence module registry
//! (`@selfdef_macro` decorator + list_macros / macro_info / run_macro).
//! Operator-named (§1b verbatim): "Integrated-intelligence modules —
//! operator-pull CoT routines registered with @selfdef_macro".

use std::path::PathBuf;
use std::process::Command;

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

fn run_probe(probe: &str) -> (bool, String, String) {
    let src = bootstrap_source();
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe}")).unwrap();
    let out = Command::new("python3")
        .arg(&script)
        .output()
        .expect("spawn python3");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn sdr98_bootstrap_defines_selfdef_macro_registry_surface() {
    let src = bootstrap_source();
    for needle in [
        "_SELFDEF_MACROS",
        "def selfdef_macro(",
        "def list_macros(",
        "def macro_info(",
        "def run_macro(",
    ] {
        assert!(
            src.contains(needle),
            "missing `{needle}` in bootstrap source"
        );
    }
}

#[test]
fn sdr98_banner_advertises_selfdef_macro() {
    let src = bootstrap_source();
    assert!(
        src.contains("SD-R98 integrated-intelligence registry"),
        "banner must announce the SD-R98 registry"
    );
    assert!(
        src.contains("@selfdef_macro"),
        "banner must mention the @selfdef_macro decorator"
    );
    assert!(
        src.contains("list_macros()"),
        "banner must show list_macros() surface"
    );
    assert!(
        src.contains("run_macro(name"),
        "banner must show run_macro(name, ...) surface"
    );
}

#[test]
fn sdr98_registry_registers_and_runs() {
    let probe = r#"
@selfdef_macro(description="probe macro", tags=["probe"])
def _r1(x, y=10):
    """First line of docstring."""
    return x + y

# Registration places it in _SELFDEF_MACROS.
assert "_r1" in _SELFDEF_MACROS, _SELFDEF_MACROS
# list_macros enumerates it.
names = [m["name"] for m in list_macros()]
assert "_r1" in names, names
# macro_info returns the metadata.
mi = macro_info("_r1")
assert mi["name"] == "_r1"
assert mi["description"] == "probe macro"
assert mi["tags"] == ["probe"]
assert mi["track_outcome"] is True
# run_macro invokes the wrapped callable end-to-end.
assert run_macro("_r1", 5) == 15
assert run_macro("_r1", 5, y=2) == 7
print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe(probe);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"), "expected PASS; got {stdout}");
}

#[test]
fn sdr98_description_defaults_to_docstring_first_line() {
    let probe = r#"
@selfdef_macro(tags=["docstring-test"])
def _docfn():
    """auto-described from docstring.

    Subsequent lines are ignored.
    """
    return 1

mi = macro_info("_docfn")
assert mi is not None
assert mi["description"] == "auto-described from docstring.", mi
print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe(probe);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"));
}

#[test]
fn sdr98_list_macros_filters_by_tag() {
    let probe = r#"
@selfdef_macro(tags=["alpha"])
def _ma(): return "a"

@selfdef_macro(tags=["beta"])
def _mb(): return "b"

@selfdef_macro(tags=["alpha", "shared"])
def _mc(): return "c"

alpha_names = sorted(m["name"] for m in list_macros(tag="alpha"))
beta_names  = sorted(m["name"] for m in list_macros(tag="beta"))
shared_names = sorted(m["name"] for m in list_macros(tag="shared"))
all_names = sorted(m["name"] for m in list_macros())

assert alpha_names == ["_ma", "_mc"], alpha_names
assert beta_names == ["_mb"], beta_names
assert shared_names == ["_mc"], shared_names
# all_names contains at least our 3 (plus any other registered macros).
for n in ("_ma", "_mb", "_mc"):
    assert n in all_names, (n, all_names)
print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe(probe);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"));
}

#[test]
fn sdr98_unknown_macro_returns_none_or_raises() {
    let probe = r#"
assert macro_info("absolutely-does-not-exist") is None
try:
    run_macro("absolutely-does-not-exist")
    print("SHOULD_HAVE_RAISED")
    raise SystemExit(1)
except KeyError as e:
    assert "unknown selfdef_macro" in str(e), str(e)
    assert "absolutely-does-not-exist" in str(e), str(e)
print("PASS")
"#;
    let (ok, stdout, stderr) = run_probe(probe);
    assert!(ok, "probe failed: stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("PASS"));
}

#[test]
fn sdr98_track_outcome_records_history_when_enabled() {
    // When track_outcome=True (the default), invoking a registered
    // macro must append an SD-R95 history row tagged tier2-macro.
    let dir = tempfile::tempdir().unwrap();
    let hist_path = dir.path().join("hist.jsonl");
    let src = bootstrap_source();
    let probe = "\n\
         @selfdef_macro(description=\"emits history\", tags=[\"audit\"])\n\
         def _audited():\n    return {\"data\": 1}\n\
         \n\
         run_macro(\"_audited\")\n\
         print(\"PASS\")\n";
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe}")).unwrap();
    // _HISTORY_PATH is captured at bootstrap-import time, so the env
    // var must be set on the python3 subprocess BEFORE the source runs.
    let out = Command::new("python3")
        .arg(&script)
        .env("SELFDEF_REPL_HISTORY", &hist_path)
        .output()
        .expect("spawn python3");
    assert!(
        out.status.success(),
        "probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let history =
        std::fs::read_to_string(&hist_path).expect("history file should have been written");
    assert!(
        history.contains("tier2-macro"),
        "expected tier2-macro row in history; got: {history}"
    );
    assert!(
        history.contains("_audited"),
        "expected _audited macro name in history; got: {history}"
    );
}

#[test]
fn sdr98_track_outcome_disabled_skips_history() {
    let dir = tempfile::tempdir().unwrap();
    let hist_path = dir.path().join("hist2.jsonl");
    let src = bootstrap_source();
    let probe = "\n\
         @selfdef_macro(description=\"not audited\", track_outcome=False)\n\
         def _unaudited():\n    return 42\n\
         \n\
         assert run_macro(\"_unaudited\") == 42\n\
         print(\"PASS\")\n";
    let script = dir.path().join("probe.py");
    std::fs::write(&script, format!("{src}\n{probe}")).unwrap();
    let out = Command::new("python3")
        .arg(&script)
        .env("SELFDEF_REPL_HISTORY", &hist_path)
        .output()
        .expect("spawn python3");
    assert!(out.status.success());
    // History file shouldn't have a row for _unaudited.
    if hist_path.exists() {
        let history = std::fs::read_to_string(&hist_path).unwrap();
        assert!(
            !history.contains("_unaudited"),
            "track_outcome=False must skip history; got: {history}"
        );
    }
}

#[test]
fn sdr98_tier2_examples_include_registered_health_rollup() {
    // The Tier 2 example list (operator-pull catalog) must include
    // a SD-R98 example showcasing @selfdef_macro.
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "tier2-examples", "--json"])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8_lossy(&out.stdout);
    assert!(
        body.contains("registered_health_rollup"),
        "tier2-examples must include the SD-R98 @selfdef_macro example; got: {body}"
    );
    assert!(
        body.contains("@selfdef_macro"),
        "example source must use @selfdef_macro decorator"
    );
}
