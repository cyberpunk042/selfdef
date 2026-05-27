//! `selfdefctl audit-chains` — CLI parity with GET /v1/audit-chains.
//!
//! One-command answer to "are the 3 chained-audit OCSF logs intact?"
//! Mirrors the dashboard "Audit chains" panel + the composite probe
//! the daemon's autohealth scheduler runs.
//!
//! Exit codes:
//! - 0 = every chain verified (worst = "ok")
//! - 1 = at least one chain broken (worst = "critical") OR the
//!       daemon's /v1/audit-chains endpoint is unreachable (no
//!       fallback — chain verification requires reading the daemon-
//!       owned OCSF files, which the CLI process may not have access
//!       to under the operator's daemon-as-its-own-user posture)
//!
//! Source: GET /v1/audit-chains (crates/selfdef-api/src/audit_chains.rs).

use std::process::Command;

use anyhow::{Context, Result, anyhow};

fn fetch_audit_chains() -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                "http://localhost/v1/audit-chains",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/audit-chains")?;
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
                &format!("{url}/v1/audit-chains"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/audit-chains")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/audit-chains — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable",
        socket
    ))
}

pub(crate) fn run(json: bool, quiet: bool) -> Result<i32> {
    let body = fetch_audit_chains()?;
    let parsed: serde_json::Value =
        serde_json::from_str(&body).context("parsing /v1/audit-chains JSON response")?;
    let worst = parsed
        .get("worst")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("malformed /v1/audit-chains: missing `worst`"))?;
    let chains = parsed
        .get("chains")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("malformed /v1/audit-chains: missing `chains`"))?;

    if quiet {
        println!("selfdef-audit-chains: {}", worst);
    } else if json {
        println!("{}", body);
    } else {
        println!(
            "{:<12} {:<8} {:>14}   {}",
            "WATCHDOG", "STATE", "EVENTS", "DETAIL"
        );
        println!("{}", "─".repeat(100));
        for c in chains {
            let watchdog = c.get("watchdog").and_then(|v| v.as_str()).unwrap_or("?");
            let ok = c.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let state = if ok { "OK" } else { "BROKEN" };
            let events = c
                .get("events_verified")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let detail = if ok {
                c.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string()
            } else {
                let err = c.get("error").and_then(|v| v.as_str()).unwrap_or("");
                let path = c.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                format!("{err}  ({path})")
            };
            println!("{:<12} {:<8} {:>14}   {}", watchdog, state, events, detail);
        }
        println!("{}", "─".repeat(100));
        println!("WORST: {}", worst.to_uppercase());
    }

    Ok(match worst {
        "ok" => 0,
        _ => 1,
    })
}
