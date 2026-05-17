//! SD-R85 (SDD-026 Z-12 foundation) — `selfdefctl repl` surface.
//! Tier 1 Python REPL bootstrap + tier manifest.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

#[test]
fn sdr85_repl_tiers_json_lists_three_tiers() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "tiers"])
        .output()
        .expect("spawn selfdefctl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["round"], "SD-R85");
    let tiers = v["tiers"].as_array().expect("tiers array");
    assert_eq!(tiers.len(), 3);
    let names: Vec<&str> = tiers.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "Programming",
            "Proto-Programming",
            "Proto-Proto-Programming"
        ]
    );
}

#[test]
fn sdr85_repl_tiers_human_renders_all_tiers() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "tiers", "--human"])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Tier 0 — Programming"), "{stdout}");
    assert!(stdout.contains("Tier 1 — Proto-Programming"), "{stdout}");
    assert!(
        stdout.contains("Tier 2 — Proto-Proto-Programming"),
        "{stdout}"
    );
}

#[test]
fn sdr85_repl_bootstrap_emits_executable_python() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "bootstrap"])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The script must define every Tier 1 callable.
    for needle in [
        "import json",
        "import subprocess",
        "def hardware()",
        "def posture()",
        "def modules(",
        "def modules_info(",
        "def modules_diff(",
        "def models(",
        "def lora_list(",
        "def mcp_tools()",
    ] {
        assert!(
            stdout.contains(needle),
            "missing `{needle}` in bootstrap: {stdout}"
        );
    }
}

#[test]
fn sdr85_repl_bootstrap_is_valid_python() {
    // Execute the bootstrap script via `python3 -c` to verify it's
    // syntactically valid + every callable lands in the namespace.
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "bootstrap"])
        .output()
        .expect("spawn selfdefctl");
    assert!(out.status.success());
    let bootstrap = String::from_utf8(out.stdout).unwrap();

    let py_out = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "{bootstrap}\nimport sys; names = sorted(n for n in dir() if not n.startswith('_')); \
             print('|'.join(names))"
        ))
        .output()
        .expect("spawn python3");
    assert!(
        py_out.status.success(),
        "python3 exec failed — stderr: {}",
        String::from_utf8_lossy(&py_out.stderr)
    );
    let names = String::from_utf8_lossy(&py_out.stdout);
    // Every shipped Tier 1 callable must land in the namespace.
    for needle in [
        "hardware",
        "posture",
        "modules",
        "modules_info",
        "modules_diff",
        "models",
        "lora_list",
        "mcp_tools",
    ] {
        assert!(
            names.contains(needle),
            "Python namespace missing `{needle}`: {names}"
        );
    }
}

#[test]
fn sdr85_repl_help_documents_subcommands() {
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args(["repl", "--help"])
        .output()
        .expect("spawn selfdefctl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("bootstrap"), "{stdout}");
    assert!(stdout.contains("tiers"), "{stdout}");
}
