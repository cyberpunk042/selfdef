//! `selfdefctl health` — CLI parity with the dashboard `Composite health`
//! panel + `GET /v1/health` server-side aggregate.
//!
//! Single-command answer to "is the box OK?". Mirrors `selfdefctl
//! alerts` in shape: tries the typed HTTP endpoint first, no
//! client-side fallback (the composite aggregate is server-built;
//! re-implementing it client-side would defeat the point).
//!
//! Exit codes:
//! - 0 = composite worst is `ok` or `unknown` (don't break operator
//!       gates on a freshly-booted daemon)
//! - 1 = composite worst is `warn` or `critical`
//!
//! Source: MS011 Z-6 + GET /v1/health (`crates/selfdef-api/src/health.rs`).

use std::process::Command;

use anyhow::{Context, Result, anyhow};

/// Try the typed `/v1/health` endpoint. Returns `(worst, rows)` on
/// success, `None` on any failure — caller maps to an error.
fn try_fetch() -> Option<(String, Vec<(String, String, String)>)> {
    let body = fetch_health().ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
    let worst = parsed.get("worst")?.as_str()?.to_string();
    let arr = parsed.get("components")?.as_array()?;
    let mut rows = Vec::with_capacity(arr.len());
    for row_val in arr {
        let name = row_val.get("name")?.as_str()?.to_string();
        let state = row_val.get("state")?.as_str()?.to_string();
        let detail = row_val.get("detail")?.as_str()?.to_string();
        rows.push((name, state, detail));
    }
    Some((worst, rows))
}

/// Same UNIX-socket + TCP fallback shape as the alerts CLI.
fn fetch_health() -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                "http://localhost/v1/health",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/health")?;
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
                &format!("{url}/v1/health"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/health")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/health — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable",
        socket
    ))
}

pub(crate) fn run(json: bool, quiet: bool) -> Result<i32> {
    let (worst, rows) = try_fetch().ok_or_else(|| {
        anyhow!(
            "could not fetch or parse /v1/health from the daemon — see SELFDEF_SOCKET / SELFDEF_API_URL"
        )
    })?;

    if quiet {
        // PS1-friendly single-line output: `selfdef-health: WORST`.
        println!("selfdef-health: {}", worst);
    } else if json {
        let obj = serde_json::json!({
            "worst": worst,
            "components": rows.iter().map(|(n, s, d)| serde_json::json!({
                "name": n,
                "state": s,
                "detail": d,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&obj)?);
    } else {
        println!("{:<12} {:<10}   {}", "COMPONENT", "STATE", "DETAIL");
        println!("{}", "─".repeat(80));
        for (name, state, detail) in &rows {
            println!("{:<12} {:<10}   {}", name, state.to_uppercase(), detail);
        }
        println!("{}", "─".repeat(80));
        println!("WORST: {}", worst.to_uppercase());
    }

    // Mirrors selfdefctl alerts: unknown does NOT break gates (host
    // may be freshly booted with some series not yet exported).
    Ok(match worst.as_str() {
        "ok" | "unknown" => 0,
        _ => 1,
    })
}
