//! `selfdefctl dashboards` — operator-pull view of the 5 named
//! dashboard view presets via `GET /v1/dashboards`. Mirrors the
//! pattern of `selfdefctl inference-backends` / `selfdefctl
//! dashboard-prefs`.
//!
//! Exit codes:
//!   0 = ok
//!   1 = daemon not reachable / fetch failed

use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DashboardEntry {
    name: String,
    label: String,
    description: String,
    active_tab: String,
    refresh_rate: String,
    visible_panel_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DashboardsBody {
    count: usize,
    note: String,
    dashboards: Vec<DashboardEntry>,
}

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
                "http://localhost/v1/dashboards",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/dashboards")?;
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
                &format!("{url}/v1/dashboards"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/dashboards")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/dashboards — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

pub(crate) fn run(json: bool) -> Result<i32> {
    let body = match fetch_endpoint() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    if json {
        println!("{body}");
        return Ok(0);
    }
    let parsed: DashboardsBody =
        serde_json::from_str(&body).context("daemon returned non-JSON body for /v1/dashboards")?;
    println!("{} operator-named dashboard view presets:", parsed.count);
    println!();
    println!(
        "{:<14} {:<14} {:<10} {:<8} DESCRIPTION",
        "NAME", "TAB", "REFRESH", "PANELS"
    );
    println!("{}", "─".repeat(110));
    for d in &parsed.dashboards {
        let desc_truncated = if d.description.len() > 60 {
            format!("{}…", &d.description[..60])
        } else {
            d.description.clone()
        };
        println!(
            "{:<14} {:<14} {:<10} {:<8} {}",
            d.name, d.active_tab, d.refresh_rate, d.visible_panel_count, desc_truncated,
        );
    }
    println!("{}", "─".repeat(110));
    println!();
    println!("Note: {}", parsed.note);
    println!();
    println!("Operator deep-link any of these via:");
    println!("  /dashboard/#preset=<name>");
    println!("Or apply server-side via:");
    println!("  selfdefctl dashboard-prefs set active_preset <name>");
    Ok(0)
}
