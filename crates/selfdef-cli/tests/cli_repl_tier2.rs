//! SD-R90 (SDD-026 Z-12 follow-up) — `selfdefctl repl tier2-examples`.
//! Ready-to-paste example Tier 2 macros built on top of the SD-R85
//! Tier 1 callable surface. Verifies the inventory shape + that each
//! example body is syntactically valid Python.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn run(args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["--config", "/dev/null"];
    full.extend_from_slice(args);
    let out = Command::new(binary())
        .args(&full)
        .output()
        .expect("spawn selfdefctl");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn sdr90_tier2_examples_json_lists_named_examples() {
    let (rc, stdout, _) = run(&["repl", "tier2-examples", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R90");
    assert_eq!(v["sdd_vector"], "SDD-026 Z-12 follow-up");
    let names: Vec<&str> = v["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    // The cycle-8 SEED ships at least these four examples.
    for needle in [
        "hw_summary",
        "modules_ready_only",
        "apply_install_plan",
        "health_to_attention",
    ] {
        assert!(names.contains(&needle), "missing {needle} in {names:?}");
    }
}

#[test]
fn sdr90_tier2_example_filter_by_name() {
    let (rc, stdout, _) = run(&["repl", "tier2-examples", "--name", "hw_summary", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let arr = v["examples"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "hw_summary");
}

#[test]
fn sdr90_tier2_example_unknown_name_rc2() {
    let (rc, _stdout, stderr) = run(&[
        "repl",
        "tier2-examples",
        "--name",
        "definitely-not-a-real-example",
    ]);
    assert_eq!(rc, 2);
    assert!(stderr.contains("unknown tier2 example"), "{stderr}");
}

#[test]
fn sdr90_tier2_example_human_render_marks_each() {
    let (rc, stdout, _) = run(&["repl", "tier2-examples"]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("SD-R90 selfdef Tier 2 example macros"));
    for needle in [
        "hw_summary",
        "modules_ready_only",
        "apply_install_plan",
        "health_to_attention",
    ] {
        assert!(stdout.contains(needle), "{stdout}");
    }
}

#[test]
fn sdr90_every_tier2_example_is_valid_python() {
    // Concatenate the bootstrap + every example body + reference each
    // defined name. If any example body has a syntax error, `python3
    // -c` will exit non-zero.
    let (_, bootstrap, _) = run(&["repl", "bootstrap"]);
    let (_, examples_json, _) = run(&["repl", "tier2-examples", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&examples_json).expect("json");

    let mut combined = bootstrap.clone();
    let mut names: Vec<String> = Vec::new();
    for e in v["examples"].as_array().unwrap() {
        let src = e["source"].as_str().unwrap();
        let name = e["name"].as_str().unwrap().to_string();
        combined.push('\n');
        combined.push_str(src);
        combined.push('\n');
        names.push(name);
    }
    // Build the "for n in names: assert n in dir()" guard.
    combined.push_str("\nimport sys\n");
    for n in &names {
        combined.push_str(&format!(
            "assert '{n}' in dir(), 'tier2 example {n} did not land in namespace'\n"
        ));
    }
    combined.push_str("print('OK')\n");

    let py_out = Command::new("python3")
        .arg("-c")
        .arg(&combined)
        .output()
        .expect("spawn python3");
    assert!(
        py_out.status.success(),
        "python3 -c failed:\n  stderr: {}",
        String::from_utf8_lossy(&py_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&py_out.stdout).contains("OK"),
        "expected OK marker"
    );
}
