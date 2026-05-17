//! Integration tests for `selfdefctl models fetch` (SD-R57).
//!
//! Closes SDD-019 T-3 fetch-side. The fetcher hits HTTP, streams
//! the artifact through sha256, atomic-renames on match, refuses
//! on mismatch. Tests spin a tiny tokio TCP listener that serves
//! a fixed payload over HTTP/1.1.

use std::io::Write;
use std::process::Command;

mod common;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

/// Spawn a one-shot HTTP/1.1 server on 127.0.0.1:0 that responds
/// to the next GET with `payload`. Returns (port, JoinHandle).
fn spawn_http_server(payload: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        use std::io::Read;
        let (mut stream, _) = listener.accept().unwrap();
        // Drain headers
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(&payload).unwrap();
    });
    (port, handle)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(bytes);
    h.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sdr57_fetch_verifies_and_writes_on_matching_sha256() {
    let payload = b"the canonical bitnet test artifact contents".to_vec();
    let expected_sha = sha256_hex(&payload);
    let (port, handle) = spawn_http_server(payload.clone());

    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry");
    let model_dir = registry.join("test-model");
    std::fs::create_dir_all(&model_dir).unwrap();
    std::fs::write(
        model_dir.join("model.toml"),
        format!(
            "[model]\nname = \"test-model\"\nweight_format = \"ternary\"\n\
             artifact_url = \"http://127.0.0.1:{port}/model.gguf\"\n\
             artifact_sha256 = \"{expected_sha}\"\nsize_bytes = {}\n",
            payload.len()
        ),
    )
    .unwrap();

    let dest = root.path().join("artifact.gguf");
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "models",
            "fetch",
            "test-model",
            "--dir",
            registry.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fetch should succeed: stderr={stderr}"
    );
    assert!(dest.exists(), "artifact should land at --to");
    let body = std::fs::read(&dest).unwrap();
    assert_eq!(
        body, payload,
        "artifact content should match served payload"
    );
    assert!(
        stderr.contains("SD-R57: ✓ verified"),
        "verification banner missing: {stderr}"
    );
    handle.join().unwrap();
}

#[test]
fn sdr57_fetch_refuses_on_sha256_mismatch_and_cleans_up_tempfile() {
    let payload = b"actual content the server sends".to_vec();
    // Manifest declares a DIFFERENT expected sha — should refuse.
    let bogus_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
    let (port, handle) = spawn_http_server(payload.clone());

    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry");
    let model_dir = registry.join("tampered");
    std::fs::create_dir_all(&model_dir).unwrap();
    std::fs::write(
        model_dir.join("model.toml"),
        format!(
            "[model]\nname = \"tampered\"\nweight_format = \"fp16\"\n\
             artifact_url = \"http://127.0.0.1:{port}/file\"\n\
             artifact_sha256 = \"{bogus_sha}\"\n"
        ),
    )
    .unwrap();

    let dest = root.path().join("downloaded.bin");
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "models",
            "fetch",
            "tampered",
            "--dir",
            registry.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "should refuse on mismatch: stderr={stderr}"
    );
    assert!(
        stderr.contains("digest MISMATCH"),
        "mismatch banner missing: {stderr}"
    );
    // Destination should NOT exist (no atomic rename on mismatch).
    assert!(!dest.exists(), "should not have committed mismatched file");
    // Tempfile (.partial) should also be cleaned up.
    let tmp = root.path().join("downloaded.bin.partial");
    assert!(!tmp.exists(), "tempfile should be cleaned up");
    handle.join().unwrap();
}

#[test]
fn sdr57_fetch_refuses_manifest_without_artifact_sha256() {
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry");
    let model_dir = registry.join("unpinned");
    std::fs::create_dir_all(&model_dir).unwrap();
    // Manifest has url but no sha256 — fetcher refuses up-front.
    std::fs::write(
        model_dir.join("model.toml"),
        "[model]\nname = \"unpinned\"\nartifact_url = \"http://127.0.0.1:1/x\"\n",
    )
    .unwrap();

    let dest = root.path().join("out.bin");
    let out = Command::new(binary())
        .arg("--config")
        .arg("/dev/null")
        .args([
            "models",
            "fetch",
            "unpinned",
            "--dir",
            registry.to_str().unwrap(),
            "--to",
            dest.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "should refuse: stderr={stderr}");
    assert!(
        stderr.contains("no artifact_sha256") || stderr.contains("refusing to fetch unverifiable"),
        "should cite missing sha256: {stderr}"
    );
    assert!(!dest.exists(), "no file should be written");
}
