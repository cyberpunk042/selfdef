//! F-2027-006 integration tests for `selfdefctl keys verify-dir`.
//!
//! Covers:
//! - all-signed directory → exit 0, summary line "N ok, 0 fail".
//! - mixed signed/unsigned → exit non-zero, summary "ok/fail"
//!   reflects the actual counts.
//! - empty (no yml/yaml) directory → exit 0 trivially.
//! - non-existent directory → exit non-zero with a clear error.
//! - non-yaml files ignored (e.g. README.md doesn't get verified).
//!
//! Tests generate a real ed25519 keypair via the `minisign`
//! dev-dep, write the public key + signed targets to a tempdir,
//! and shell out to the real selfdefctl binary. No external
//! `minisign` CLI required at test time.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

struct Keypair {
    pub_path: PathBuf,
    sk: minisign::SecretKey,
}

fn fresh_keypair(dir: &Path) -> Keypair {
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let pub_path = dir.join("policy.pub");
    std::fs::write(&pub_path, kp.pk.to_box().unwrap().to_string()).unwrap();
    Keypair {
        pub_path,
        sk: kp.sk,
    }
}

fn sign_file(sk: &minisign::SecretKey, target: &Path) {
    let body = std::fs::read(target).unwrap();
    let sig = minisign::sign(None, sk, &body[..], None, None).unwrap();
    let mut sig_path = target.as_os_str().to_owned();
    sig_path.push(".minisig");
    std::fs::write(PathBuf::from(sig_path), sig.to_string()).unwrap();
}

fn write_yaml(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

fn run_verify_dir(dir: &Path, pubkey: &Path) -> Output {
    Command::new(binary())
        .args([
            "keys",
            "verify-dir",
            dir.to_str().unwrap(),
            "--public-key",
            pubkey.to_str().unwrap(),
        ])
        .output()
        .expect("spawn selfdefctl")
}

#[test]
fn verify_dir_all_signed_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = fresh_keypair(tmp.path());
    let policy_dir = tmp.path().join("policies");
    std::fs::create_dir(&policy_dir).unwrap();
    let a = write_yaml(&policy_dir, "a.yml", "title: one\n");
    let b = write_yaml(&policy_dir, "b.yaml", "title: two\n");
    sign_file(&kp.sk, &a);
    sign_file(&kp.sk, &b);

    let out = run_verify_dir(&policy_dir, &kp.pub_path);
    assert!(
        out.status.success(),
        "all-signed dir must exit 0; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok:   ") && stdout.contains("a.yml"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("ok:   ") && stdout.contains("b.yaml"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("summary: 2 file(s), 2 ok, 0 fail"),
        "expected clean summary; stdout: {stdout}",
    );
}

#[test]
fn verify_dir_mixed_signed_unsigned_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = fresh_keypair(tmp.path());
    let policy_dir = tmp.path().join("policies");
    std::fs::create_dir(&policy_dir).unwrap();
    let good = write_yaml(&policy_dir, "good.yml", "title: ok\n");
    let bad = write_yaml(&policy_dir, "bad.yml", "title: nope\n");
    sign_file(&kp.sk, &good);
    let _ = bad;

    let out = run_verify_dir(&policy_dir, &kp.pub_path);
    assert!(!out.status.success(), "mixed dir must exit non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok:   ") && stdout.contains("good.yml"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("fail: ") && stdout.contains("bad.yml"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("summary: 2 file(s), 1 ok, 1 fail"),
        "expected mixed-count summary; stdout: {stdout}",
    );
}

#[test]
fn verify_dir_empty_dir_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = fresh_keypair(tmp.path());
    let policy_dir = tmp.path().join("policies");
    std::fs::create_dir(&policy_dir).unwrap();

    let out = run_verify_dir(&policy_dir, &kp.pub_path);
    assert!(
        out.status.success(),
        "empty dir verifies trivially; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("summary: 0 file(s), 0 ok, 0 fail"),
        "expected empty summary; stdout: {stdout}",
    );
}

#[test]
fn verify_dir_nonexistent_dir_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = fresh_keypair(tmp.path());
    let missing = tmp.path().join("does-not-exist");

    let out = run_verify_dir(&missing, &kp.pub_path);
    assert!(!out.status.success(), "missing dir must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a directory"),
        "expected clear error; stderr: {stderr}",
    );
}

#[test]
fn verify_dir_ignores_non_yaml_files() {
    let tmp = tempfile::tempdir().unwrap();
    let kp = fresh_keypair(tmp.path());
    let policy_dir = tmp.path().join("policies");
    std::fs::create_dir(&policy_dir).unwrap();
    // Real, signed YAML — must verify.
    let yaml = write_yaml(&policy_dir, "a.yml", "title: hi\n");
    sign_file(&kp.sk, &yaml);
    // Decoy: README without a matching .minisig — must NOT fail
    // the verification (verify-dir is non-recursive and only
    // considers `*.yml`/`*.yaml`).
    std::fs::write(policy_dir.join("README.md"), "not a policy\n").unwrap();
    std::fs::write(policy_dir.join("notes.txt"), "also not a policy\n").unwrap();

    let out = run_verify_dir(&policy_dir, &kp.pub_path);
    assert!(
        out.status.success(),
        "non-yaml files must not affect verification; stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("summary: 1 file(s), 1 ok, 0 fail"),
        "stdout: {stdout}",
    );
    assert!(
        !stdout.contains("README.md"),
        "README must not be probed; stdout: {stdout}"
    );
}
