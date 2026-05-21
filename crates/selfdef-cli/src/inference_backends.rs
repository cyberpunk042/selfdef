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

use anyhow::{anyhow, Context, Result};

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
        "could not fetch /v1/inference-backends — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable",
        socket
    ))
}

pub(crate) fn run(json: bool) -> Result<i32> {
    let body = fetch_endpoint()?;
    if json {
        println!("{}", body);
        return Ok(0);
    }
    let parsed: serde_json::Value = serde_json::from_str(&body).ok().ok_or_else(|| {
        anyhow!("daemon returned non-JSON body for /v1/inference-backends")
    })?;
    let worst = parsed.get("worst").and_then(|v| v.as_str()).unwrap_or("unknown");
    let backends = parsed
        .get("backends")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    println!(
        "{:<14} {:<10} {:<20} {}",
        "BACKEND", "STATE", "VERSION", "BINARY"
    );
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
            if version.len() > 20 { &version[..20] } else { version },
            binary
        );
    }
    println!("{}", "─".repeat(70));
    println!("WORST: {}", worst.to_uppercase());
    Ok(0)
}
