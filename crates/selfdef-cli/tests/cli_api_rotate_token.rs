//! SDD-004 F-2026-023 follow-up integration tests for
//! `selfdefctl api rotate-token`. Asserts the rotation writes
//! a fresh, base64-url-safe, mode-0600 token to the requested
//! file. The SIGUSR2 path is exercised by the daemon-side
//! `TokenReloader` unit tests; this file covers the CLI
//! contract.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_selfdefctl"))
}

#[test]
fn rotate_token_writes_url_safe_token_at_0600() {
    let tmp = tempfile::tempdir().unwrap();
    let token_path = tmp.path().join("api.token");
    // Daemon config: minimal but valid.
    let cfg = tmp.path().join("selfdef.toml");
    std::fs::write(
        &cfg,
        format!("[api]\ntoken_file = \"{}\"\n", token_path.display(),),
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "api",
            "rotate-token",
            "--print",
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "rotate-token failed; stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );

    // File exists, mode 0600.
    let md = std::fs::metadata(&token_path).expect("token file");
    assert_eq!(
        md.permissions().mode() & 0o777,
        0o600,
        "expected mode 0600, got {:o}",
        md.permissions().mode() & 0o777,
    );

    // Token is base64-url-safe, non-empty.
    let token = std::fs::read_to_string(&token_path).unwrap();
    let token = token.trim_end_matches('\n');
    assert!(!token.is_empty());
    for c in token.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "non-url-safe char {c:?} in token (length {})",
            token.len(),
        );
    }

    // F-2027-064: assert the `--print` *contract* (token format)
    // rather than substring-matching the literal token value. The
    // tokens are tempfile-scoped and never used against a real
    // daemon, so echoing them to CI logs is very low risk — but
    // the format-only assertion is strictly stronger (it catches
    // base64-vs-base64url drift, length-default regressions, and
    // stray whitespace the value-match would silently accept).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("wrote "), "stdout shape mismatch");

    // Find the printed token line: stdout shape is
    //   wrote <path> (<n> bytes)
    //   <token>
    // We hunt for a line that is non-empty, url-safe-base64,
    // and (when `--bytes` is left at its default) of the
    // expected length.
    let printed = stdout
        .lines()
        .find(|line| {
            !line.is_empty()
                && line
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .expect("--print should write a url-safe-base64 line to stdout");
    assert_eq!(
        printed.len(),
        token.len(),
        "printed line length must match the file's token length",
    );
    // Cross-check the printed line equals the file content
    // without including either value in the failure message.
    assert!(
        printed == token,
        "printed token does not match the rotated file's content",
    );
}

#[test]
fn rotate_token_with_explicit_path_overrides_config() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg_token = tmp.path().join("api.token");
    let override_token = tmp.path().join("ctl.token");
    let cfg = tmp.path().join("selfdef.toml");
    std::fs::write(
        &cfg,
        format!("[api]\ntoken_file = \"{}\"\n", cfg_token.display(),),
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "api",
            "rotate-token",
            "--token-file",
            override_token.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The override path got the new token; the config path
    // stayed untouched (didn't exist).
    assert!(override_token.exists(), "override path must be written");
    assert!(!cfg_token.exists(), "config path must NOT be touched");
}

#[test]
fn rotate_token_rejects_bytes_out_of_range() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("selfdef.toml");
    std::fs::write(
        &cfg,
        format!(
            "[api]\ntoken_file = \"{}\"\n",
            tmp.path().join("t").display()
        ),
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "api",
            "rotate-token",
            "--bytes",
            "0",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "should reject --bytes=0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--bytes must be in 1..=256"),
        "stderr: {stderr}",
    );
}

#[test]
fn rotate_token_two_invocations_produce_different_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let token_path = tmp.path().join("api.token");
    let cfg = tmp.path().join("selfdef.toml");
    std::fs::write(
        &cfg,
        format!("[api]\ntoken_file = \"{}\"\n", token_path.display(),),
    )
    .unwrap();

    let run = || -> String {
        let out = Command::new(binary())
            .args(["--config", cfg.to_str().unwrap(), "api", "rotate-token"])
            .output()
            .expect("spawn");
        assert!(out.status.success());
        std::fs::read_to_string(&token_path).unwrap()
    };
    let t1 = run();
    let t2 = run();
    assert_ne!(t1, t2, "two rotations must produce different tokens");
}
