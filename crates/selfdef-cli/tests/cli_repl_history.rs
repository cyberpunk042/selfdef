//! SD-R95 (SDD-026 Z-12 audit) — `selfdefctl repl history`.
//! Reads back the JSONL audit trail the REPL bootstrap writes when
//! SELFDEF_REPL_HISTORY is set. Cycle-9 opening round.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

fn run_env(env: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("--config").arg("/dev/null").args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn sdr95_history_empty_when_path_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let (rc, stdout, _) = run_env(
        &[],
        &[
            "repl",
            "history",
            "--path",
            path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["round"], "SD-R95");
    assert_eq!(v["exists"], false);
    assert_eq!(v["total_rows"], 0);
    assert!(v["rows"].as_array().unwrap().is_empty());
}

#[test]
fn sdr95_history_reads_existing_jsonl_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, r#"{{"round":"SD-R95","started_at":"2026-05-17T15:00:00Z","duration_ms":42,"argv":["hardware","--json"],"rc":0}}"#).unwrap();
    writeln!(f, r#"{{"round":"SD-R95","started_at":"2026-05-17T15:01:00Z","duration_ms":17,"argv":["modules","list","--json"],"rc":0}}"#).unwrap();
    writeln!(f, r#"{{"round":"SD-R95","started_at":"2026-05-17T15:02:00Z","duration_ms":99,"argv":["modules","info","nope"],"rc":2}}"#).unwrap();
    drop(f);
    let (rc, stdout, _) = run_env(
        &[],
        &[
            "repl",
            "history",
            "--path",
            path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["exists"], true);
    assert_eq!(v["total_rows"], 3);
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["rc"], 0);
    assert_eq!(rows[2]["rc"], 2);
}

#[test]
fn sdr95_history_tails_to_limit_when_above() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    for i in 0..10 {
        writeln!(
            f,
            r#"{{"round":"SD-R95","started_at":"2026-05-17T15:{i:02}:00Z","duration_ms":10,"argv":["row","{i}"],"rc":0}}"#
        )
        .unwrap();
    }
    drop(f);
    let (rc, stdout, _) = run_env(
        &[],
        &[
            "repl",
            "history",
            "--path",
            path.to_str().unwrap(),
            "--limit",
            "3",
            "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["total_rows"], 10);
    assert_eq!(v["returned_rows"], 3);
    let rows = v["rows"].as_array().unwrap();
    // Last 3 rows; argv[1] should be "7", "8", "9" (zero-indexed last three).
    assert_eq!(rows[0]["argv"][1], "7");
    assert_eq!(rows[2]["argv"][1], "9");
}

#[test]
fn sdr95_history_all_overrides_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    for i in 0..6 {
        writeln!(
            f,
            r#"{{"round":"SD-R95","started_at":"x","duration_ms":1,"argv":["row","{i}"],"rc":0}}"#
        )
        .unwrap();
    }
    drop(f);
    let (rc, stdout, _) = run_env(
        &[],
        &[
            "repl",
            "history",
            "--path",
            path.to_str().unwrap(),
            "--limit",
            "2",
            "--all",
            "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(v["returned_rows"], 6);
}

#[test]
fn sdr95_history_human_render_shows_path_and_argv() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, r#"{{"round":"SD-R95","started_at":"2026-05-17T15:00:00Z","duration_ms":42,"argv":["hardware","--json"],"rc":0}}"#).unwrap();
    drop(f);
    let (rc, stdout, _) = run_env(&[], &["repl", "history", "--path", path.to_str().unwrap()]);
    assert_eq!(rc, 0);
    assert!(stdout.contains("SD-R95 selfdefctl repl history"));
    assert!(stdout.contains(path.to_str().unwrap()), "{stdout}");
    assert!(stdout.contains("hardware --json"), "{stdout}");
    assert!(stdout.contains("[OK  ]"), "{stdout}");
}

#[test]
fn sdr95_history_skips_malformed_lines_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.jsonl");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "not json at all").unwrap();
    writeln!(
        f,
        r#"{{"round":"SD-R95","argv":["ok"],"rc":0,"started_at":"x","duration_ms":1}}"#
    )
    .unwrap();
    writeln!(f).unwrap();
    writeln!(f, "garbage").unwrap();
    drop(f);
    let (rc, stdout, _) = run_env(
        &[],
        &[
            "repl",
            "history",
            "--path",
            path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(rc, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    // Only the valid row should land.
    assert_eq!(v["total_rows"], 1);
    assert_eq!(v["rows"][0]["argv"][0], "ok");
}

#[test]
fn sdr95_history_help_documents_flags() {
    let (_, stdout, _) = run_env(&[], &["repl", "history", "--help"]);
    assert!(stdout.contains("--path"), "{stdout}");
    assert!(stdout.contains("--limit"), "{stdout}");
    assert!(stdout.contains("--all"), "{stdout}");
}
