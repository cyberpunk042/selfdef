//! `selfdefctl dashboard-prefs` — operator-pull view of the daemon-
//! side dashboard preferences surface (SDD-060). `show` prints the
//! current persisted prefs; `set` PUTs a new value for one field.
//!
//! Wire format: GET/PUT /v1/dashboard-prefs (axum route declared
//! in `crates/selfdef-api/src/lib.rs`). On a host without a running
//! daemon the operator can still hand-edit
//! `/etc/selfdef/dashboard-prefs.toml` — this CLI just provides the
//! scriptable + atomic path.
//!
//! Exit codes:
//!   0 ok
//!   1 daemon not reachable / fetch failed
//!   2 invalid arg (unknown field / unknown enum value)
//!   3 server rejected the PUT (400/409)

use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

const VALID_RATES: &[&str] = &["fast", "normal", "slow", "paused"];
const VALID_PRESETS: &[&str] = &[
    "audit-trail",
    "compact",
    "cpu-bound",
    "default",
    "gpu-monitor",
    "health-only",
    "incident-response",
    "inference",
    "inference-throughput",
    "mcp-debug",
    "mcp-tools",
    "models-lab",
    "module-status",
    "network-ops",
    "paused-snapshot",
    "performance",
    "repl-session",
    "security",
    "storage-ops",
    "watchdog-deep",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DashboardPrefs {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    hidden_panels: Vec<String>,
    #[serde(default)]
    refresh_rate: String,
    #[serde(default)]
    active_preset: String,
    #[serde(default)]
    updated_at_ms: u64,
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
                "http://localhost/v1/dashboard-prefs",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /v1/dashboard-prefs")?;
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
                &format!("{url}/v1/dashboard-prefs"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /v1/dashboard-prefs")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /v1/dashboard-prefs — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable",
        socket
    ))
}

fn put_endpoint(body: &str) -> Result<(i32, String)> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--unix-socket",
                &socket,
                "-X",
                "PUT",
                "-H",
                "content-type: application/json",
                "-d",
                body,
                "-w",
                "\n%{http_code}",
                "http://localhost/v1/dashboard-prefs",
            ])
            .output()
            .context("invoking curl PUT against the UNIX socket")?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body_part, code_part) = text.rsplit_once('\n').unwrap_or((&text, "0"));
        let code: i32 = code_part.trim().parse().unwrap_or(0);
        return Ok((code, body_part.to_string()));
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Command::new("curl")
            .args([
                "-s",
                "-X",
                "PUT",
                "-H",
                &format!("Authorization: Bearer {token}"),
                "-H",
                "content-type: application/json",
                "-d",
                body,
                "-w",
                "\n%{http_code}",
                &format!("{url}/v1/dashboard-prefs"),
            ])
            .output()
            .context("invoking curl PUT against TCP API URL")?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body_part, code_part) = text.rsplit_once('\n').unwrap_or((&text, "0"));
        let code: i32 = code_part.trim().parse().unwrap_or(0);
        return Ok((code, body_part.to_string()));
    }
    Err(anyhow!("daemon not reachable for PUT /v1/dashboard-prefs"))
}

pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = match fetch_endpoint() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    if json {
        println!("{}", body);
        return Ok(0);
    }
    let prefs: DashboardPrefs = serde_json::from_str(&body)
        .context("daemon returned non-JSON body for /v1/dashboard-prefs")?;
    println!("dashboard-prefs (schema {})", prefs.schema_version);
    println!("  active_preset = {}", prefs.active_preset);
    println!("  refresh_rate  = {}", prefs.refresh_rate);
    if prefs.hidden_panels.is_empty() {
        println!("  hidden_panels = (none — all visible)");
    } else {
        println!("  hidden_panels = {} panel(s):", prefs.hidden_panels.len());
        for p in &prefs.hidden_panels {
            println!("    - {p}");
        }
    }
    println!("  updated_at_ms = {}", prefs.updated_at_ms);
    Ok(0)
}

pub(crate) fn run_set(field: &str, value: &str) -> Result<i32> {
    // Validate field name + enum constraints client-side before the
    // round-trip. Saves the operator from a 400 they could have
    // foreseen.
    match field {
        "refresh_rate" => {
            if !VALID_RATES.contains(&value) {
                eprintln!(
                    "invalid refresh_rate {value:?}; expected one of: {}",
                    VALID_RATES.join(", ")
                );
                return Ok(2);
            }
        }
        "active_preset" => {
            if !VALID_PRESETS.contains(&value) {
                eprintln!(
                    "invalid active_preset {value:?}; expected one of: {}",
                    VALID_PRESETS.join(", ")
                );
                return Ok(2);
            }
        }
        "hidden_panels" => {
            // value is comma-separated section IDs; no enum validation
            // (SDD-060 D-6: hidden_panels is unconstrained Vec<String>).
        }
        _ => {
            eprintln!(
                "unknown field {field:?}; expected one of: refresh_rate | active_preset | hidden_panels"
            );
            return Ok(2);
        }
    }
    // Fetch current state, mutate the named field, PUT.
    let current_body = match fetch_endpoint() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    let mut prefs: DashboardPrefs = serde_json::from_str(&current_body)
        .context("daemon returned non-JSON body for /v1/dashboard-prefs")?;
    if prefs.schema_version.is_empty() {
        // Daemon's blank-valid default — fill in the version so the
        // PUT doesn't trip 409.
        prefs.schema_version = "1.0.0".to_string();
    }
    if prefs.refresh_rate.is_empty() {
        prefs.refresh_rate = "normal".to_string();
    }
    if prefs.active_preset.is_empty() {
        prefs.active_preset = "default".to_string();
    }
    match field {
        "refresh_rate" => prefs.refresh_rate = value.to_string(),
        "active_preset" => prefs.active_preset = value.to_string(),
        "hidden_panels" => {
            prefs.hidden_panels = if value.is_empty() {
                Vec::new()
            } else {
                value.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        _ => unreachable!(),
    }
    let put_body = serde_json::to_string(&prefs).context("serialize prefs for PUT")?;
    let (code, response_body) = put_endpoint(&put_body)?;
    if (200..300).contains(&code) {
        println!("ok ({code}); new prefs:");
        println!("{response_body}");
        Ok(0)
    } else {
        eprintln!("daemon rejected PUT: HTTP {code}");
        eprintln!("{response_body}");
        Ok(3)
    }
}
