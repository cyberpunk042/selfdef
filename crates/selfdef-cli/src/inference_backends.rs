//! `selfdefctl inference-backends` — CLI parity with
//! `GET /v1/inference-backends`. MS011 Z-2 + LM Studio surface.
//!
//! Tries the typed HTTP endpoint first; no client-side fallback
//! (the probe lives daemon-side per SDD-026 Z-2 — re-implementing
//! it client-side would diverge).
//!
//! Exit code:
//! - 0 always (Z-2 is informational; an operator-deliberate non-
//!   install is not an error)
//!
//! Source: MS011 Z-2 + GET /v1/inference-backends
//! (`crates/selfdef-api/src/inference_backends.rs`).

use std::process::Command;

use anyhow::{Context, Result, anyhow};

fn fetch_endpoint() -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                "http://localhost/v1/inference-backends",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/inference-backends")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "-H",
                &format!("Authorization: Bearer {token}"),
                &format!("{url}/v1/inference-backends"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/inference-backends")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/inference-backends — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

/// 4 canonical backends — must stay byte-identical to the daemon-side
/// `BACKENDS` table in `crates/selfdef-api/src/inference_backends.rs`
/// (default binary + env-var override name). Mirroring the table here
/// is intentional per the "no client-side fallback" rule for the live
/// probe — but the shell-out for `--version` is a direct local action,
/// not a probe, so it stands alone.
const BACKENDS: &[(&str, &str, &str)] = &[
    (
        "llama.cpp",
        "llama-server",
        "SELFDEF_INFERENCE_LLAMA_CPP_BIN",
    ),
    ("vllm", "vllm", "SELFDEF_INFERENCE_VLLM_BIN"),
    (
        "bitnet.cpp",
        "bitnet-cli",
        "SELFDEF_INFERENCE_BITNET_CPP_BIN",
    ),
    ("unsloth", "unsloth-cli", "SELFDEF_INFERENCE_UNSLOTH_BIN"),
];

pub(crate) fn run_version(backend: &str) -> Result<i32> {
    let (_, default_bin, env_var) = match BACKENDS.iter().find(|b| b.0 == backend) {
        Some(row) => *row,
        None => {
            let names: Vec<&str> = BACKENDS.iter().map(|b| b.0).collect();
            return Err(anyhow!(
                "unknown backend {:?} — expected one of: {}",
                backend,
                names.join(", ")
            ));
        }
    };
    let binary = std::env::var(env_var).unwrap_or_else(|_| default_bin.to_string());
    let which = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {binary}"))
        .output()
        .context("invoking `command -v` to locate the backend binary")?;
    if !which.status.success() || which.stdout.is_empty() {
        eprintln!(
            "{backend} not installed — `{binary}` not found on PATH (override via {env_var}=<path>)"
        );
        return Ok(1);
    }
    let out = Command::new(&binary)
        .arg("--version")
        .output()
        .with_context(|| format!("invoking `{binary} --version`"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    if out.status.success() { Ok(0) } else { Ok(2) }
}

pub(crate) fn run(json: bool) -> Result<i32> {
    let body = fetch_endpoint()?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/inference-backends"))?;
    let worst = parsed
        .get("worst")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let backends = parsed
        .get("backends")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    println!("{:<14} {:<10} {:<20} BINARY", "BACKEND", "STATE", "VERSION");
    println!("{}", "─".repeat(70));
    for b in &backends {
        let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let state = b.get("state").and_then(|v| v.as_str()).unwrap_or("?");
        let version = b.get("version").and_then(|v| v.as_str()).unwrap_or("—");
        let binary = b.get("binary").and_then(|v| v.as_str()).unwrap_or("?");
        println!(
            "{:<14} {:<10} {:<20} {}",
            name,
            state.to_uppercase(),
            if version.len() > 20 {
                &version[..20]
            } else {
                version
            },
            binary
        );
    }
    println!("{}", "─".repeat(70));
    println!("WORST: {}", worst.to_uppercase());
    Ok(0)
}
