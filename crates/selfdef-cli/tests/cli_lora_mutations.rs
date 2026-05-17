//! SD-R89 (SDD-025 Y-2 extension) — atomic LoRA state mutation verbs
//! (attach / detach / set-status). Builds on the SD-R81 list-only
//! foundation; turns the state file into a managed resource.

use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn run(state: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["--config", "/dev/null", "models", "lora"];
    full.extend_from_slice(args);
    full.push("--state");
    full.push(state.to_str().unwrap());
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
fn sdr89_attach_creates_state_file_and_adds_entry() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    let (rc, stdout, _) = run(
        &state,
        &["attach", "alpha-adapter", "base/model-1", "--json"],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R89");
    assert_eq!(v["outcome"], "attached");
    assert_eq!(v["adapter_id"], "alpha-adapter");
    assert_eq!(v["base_model"], "base/model-1");
    assert_eq!(v["status"], "active");
    assert_eq!(v["adapter_count"], 1);
    assert!(state.exists());
    // attached_at is ISO-8601 UTC; just verify shape.
    let attached: &str = v["attached_at"].as_str().unwrap();
    assert!(attached.ends_with("Z"));
    assert_eq!(attached.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
}

#[test]
fn sdr89_attach_idempotent_upserts_existing_entry() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    run(&state, &["attach", "id-1", "base/v1"]);
    let (rc, stdout, _) = run(
        &state,
        &[
            "attach", "id-1", "base/v2", "--status", "disabled", "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "upserted");
    assert_eq!(v["adapter_count"], 1); // still only one row
    assert_eq!(v["base_model"], "base/v2");
    assert_eq!(v["status"], "disabled");
}

#[test]
fn sdr89_detach_removes_entry_and_returns_zero() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    run(&state, &["attach", "alpha", "base/m"]);
    run(&state, &["attach", "beta", "base/m"]);
    let (rc, stdout, _) = run(&state, &["detach", "alpha", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "removed");
    assert_eq!(v["adapter_count"], 1);

    // list should show only beta now.
    let (rc, stdout, _) = run(&state, &["list", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let ids: Vec<&str> = v["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["adapter_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["beta"]);
}

#[test]
fn sdr89_detach_not_found_returns_rc1() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    run(&state, &["attach", "alpha", "base/m"]);
    let (rc, stdout, _) = run(&state, &["detach", "never-attached", "--json"]);
    assert_eq!(rc, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "not-found");
}

#[test]
fn sdr89_set_status_updates_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    run(&state, &["attach", "alpha", "base/m"]);
    let (rc, stdout, _) = run(&state, &["set-status", "alpha", "disabled", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "updated");
    assert_eq!(v["prior_status"], "active");
    assert_eq!(v["new_status"], "disabled");

    let (rc, stdout, _) = run(&state, &["list", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["adapters"][0]["status"], "disabled");
}

#[test]
fn sdr89_set_status_rejects_unknown_value() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    run(&state, &["attach", "alpha", "base/m"]);
    let (rc, _stdout, stderr) = run(&state, &["set-status", "alpha", "bogus"]);
    assert_eq!(rc, 2);
    assert!(stderr.contains("active"), "{stderr}");
}

#[test]
fn sdr89_set_status_not_found_returns_rc1() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    let (rc, stdout, _) = run(&state, &["set-status", "ghost", "disabled", "--json"]);
    assert_eq!(rc, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["outcome"], "not-found");
}

#[test]
fn sdr89_attach_detach_round_trip_state_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("loras.json");
    for id in ["a", "b", "c", "d"] {
        run(&state, &["attach", id, "base/m"]);
    }
    for id in ["b", "d"] {
        run(&state, &["detach", id]);
    }
    let (rc, stdout, _) = run(&state, &["list", "--json"]);
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let ids: Vec<&str> = v["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["adapter_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["a", "c"]);
}
