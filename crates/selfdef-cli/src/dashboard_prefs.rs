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

use anyhow::{Context, Result, anyhow};
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
    "ips-dectet-incident",
    "ips-dectet-overview",
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
    /// MS043 UX batch 21 — mirror of the daemon-side custom_presets
    /// field added in batch 19; the CLI now reads + mutates it via
    /// `selfdefctl dashboard-prefs add-custom-preset` / `delete-custom-preset`.
    #[serde(default)]
    custom_presets: Vec<CustomPreset>,
    #[serde(default)]
    updated_at_ms: u64,
}

/// MS043 UX batch 21 — CLI-side mirror of the daemon CustomPreset shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct CustomPreset {
    pub name: String,
    pub label: String,
    #[serde(default)]
    pub hidden_panels: Vec<String>,
    pub refresh_rate: String,
    pub active_tab: String,
}

const VALID_TABS: &[&str] = &[
    "all", "models", "modules", "profiles", "hardware", "network", "logs", "mcp", "repl",
];

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
        "could not fetch /v1/dashboard-prefs — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
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
        println!("{body}");
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

// ───────────────── MS043 UX batch 21 — custom-preset CLI ─────────────────

/// Client-side validators mirroring `selfdef-api::dashboard_prefs::validate_custom_preset`.
/// Catches operator mistakes before the round-trip; the daemon does
/// the authoritative validation server-side too (defense-in-depth).
fn validate_custom_preset_cli(cp: &CustomPreset) -> Result<(), String> {
    let n = cp.name.as_str();
    if !(3..=32).contains(&n.len()) {
        return Err(format!(
            "custom preset name {n:?} length must be 3..=32 chars"
        ));
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!("custom preset name {n:?} must match ^[a-z0-9-]+$"));
    }
    if n.starts_with('-') || n.ends_with('-') {
        return Err(format!(
            "custom preset name {n:?} must not start or end with '-'"
        ));
    }
    if VALID_PRESETS.contains(&n) {
        return Err(format!(
            "custom preset name {n:?} collides with a builtin; choose a different name"
        ));
    }
    if cp.label.is_empty() || cp.label.len() > 64 {
        return Err(format!(
            "custom preset {n:?} label must be 1..=64 chars (got {})",
            cp.label.len()
        ));
    }
    if !VALID_RATES.contains(&cp.refresh_rate.as_str()) {
        return Err(format!(
            "custom preset {n:?} has invalid refresh_rate {:?}; expected one of {:?}",
            cp.refresh_rate, VALID_RATES
        ));
    }
    if !VALID_TABS.contains(&cp.active_tab.as_str()) {
        return Err(format!(
            "custom preset {n:?} has invalid active_tab {:?}; expected one of {:?}",
            cp.active_tab, VALID_TABS
        ));
    }
    Ok(())
}

fn parse_hidden_panels_csv(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    }
}

fn fetch_current_prefs() -> Result<DashboardPrefs> {
    let body = fetch_endpoint()?;
    let mut prefs: DashboardPrefs = serde_json::from_str(&body)
        .context("daemon returned non-JSON body for /v1/dashboard-prefs")?;
    if prefs.schema_version.is_empty() {
        prefs.schema_version = "1.0.0".to_string();
    }
    if prefs.refresh_rate.is_empty() {
        prefs.refresh_rate = "normal".to_string();
    }
    if prefs.active_preset.is_empty() {
        prefs.active_preset = "default".to_string();
    }
    Ok(prefs)
}

fn put_prefs(prefs: &DashboardPrefs) -> Result<(i32, String)> {
    let body = serde_json::to_string(prefs).context("serialize prefs for PUT")?;
    put_endpoint(&body)
}

/// `selfdefctl dashboard-prefs add-custom-preset` — define + persist
/// a new operator-named preset. The daemon validates server-side
/// too; this CLI pre-validates to save the operator from a 400 they
/// could have foreseen.
pub(crate) fn run_add_custom_preset(
    name: &str,
    label: &str,
    hidden_panels: &str,
    refresh_rate: &str,
    active_tab: &str,
) -> Result<i32> {
    let cp = CustomPreset {
        name: name.to_string(),
        label: label.to_string(),
        hidden_panels: parse_hidden_panels_csv(hidden_panels),
        refresh_rate: refresh_rate.to_string(),
        active_tab: active_tab.to_string(),
    };
    if let Err(e) = validate_custom_preset_cli(&cp) {
        eprintln!("{e}");
        return Ok(2);
    }
    let mut prefs = match fetch_current_prefs() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    // Operator can't add a preset that already exists; suggest delete + re-add.
    if prefs.custom_presets.iter().any(|p| p.name == cp.name) {
        eprintln!(
            "custom preset {name:?} already exists; use `selfdefctl dashboard-prefs \
             delete-custom-preset {name}` first, then re-add"
        );
        return Ok(2);
    }
    prefs.custom_presets.push(cp.clone());
    let (code, response_body) = put_prefs(&prefs)?;
    if (200..300).contains(&code) {
        println!("added custom preset {:?} ({})", cp.name, cp.label);
        println!("total custom presets: {}", prefs.custom_presets.len());
        Ok(0)
    } else {
        eprintln!("daemon rejected PUT: HTTP {code}");
        eprintln!("{response_body}");
        Ok(3)
    }
}

/// `selfdefctl dashboard-prefs delete-custom-preset <name>` — remove
/// a custom preset from `dashboard-prefs.toml`.
///
/// If the operator's `active_preset` is the one being deleted, the
/// daemon's PUT validator would reject (orphan active_preset), so
/// this command falls back to `default` for `active_preset` if it
/// matches the deletion target.
pub(crate) fn run_delete_custom_preset(name: &str) -> Result<i32> {
    let mut prefs = match fetch_current_prefs() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    let before = prefs.custom_presets.len();
    prefs.custom_presets.retain(|p| p.name != name);
    if prefs.custom_presets.len() == before {
        eprintln!("no custom preset named {name:?} (nothing deleted)");
        return Ok(2);
    }
    if prefs.active_preset == name {
        eprintln!(
            "note: active_preset was {name:?} which is being deleted; falling back to \"default\""
        );
        prefs.active_preset = "default".to_string();
    }
    let (code, response_body) = put_prefs(&prefs)?;
    if (200..300).contains(&code) {
        println!("deleted custom preset {name:?}");
        println!("remaining custom presets: {}", prefs.custom_presets.len());
        Ok(0)
    } else {
        eprintln!("daemon rejected PUT: HTTP {code}");
        eprintln!("{response_body}");
        Ok(3)
    }
}

/// `selfdefctl dashboard-prefs list-custom-presets [--json]` —
/// human or JSON listing of operator-defined custom presets. (The
/// builtin presets are discoverable via `selfdefctl dashboards`.)
pub(crate) fn run_list_custom_presets(json: bool) -> Result<i32> {
    let prefs = match fetch_current_prefs() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return Ok(1);
        }
    };
    if json {
        let body = serde_json::to_string_pretty(&prefs.custom_presets)
            .context("serialize custom_presets")?;
        println!("{body}");
        return Ok(0);
    }
    if prefs.custom_presets.is_empty() {
        println!("no operator-defined custom presets");
        println!(
            "(add one with: selfdefctl dashboard-prefs add-custom-preset <name> <label> \
             <hidden-csv> <refresh_rate> <active_tab>)"
        );
        return Ok(0);
    }
    println!(
        "{} operator-defined custom preset(s):",
        prefs.custom_presets.len()
    );
    for cp in &prefs.custom_presets {
        println!("  {} — {}", cp.name, cp.label);
        println!(
            "    refresh_rate={} active_tab={} hidden_panels={}",
            cp.refresh_rate,
            cp.active_tab,
            if cp.hidden_panels.is_empty() {
                "(none)".to_string()
            } else {
                cp.hidden_panels.join(",")
            }
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_cp() -> CustomPreset {
        CustomPreset {
            name: "my-view".into(),
            label: "My view".into(),
            hidden_panels: vec!["raid-section".into()],
            refresh_rate: "normal".into(),
            active_tab: "logs".into(),
        }
    }

    #[test]
    fn valid_cp_passes() {
        assert!(validate_custom_preset_cli(&valid_cp()).is_ok());
    }

    #[test]
    fn name_too_short_rejected() {
        let mut cp = valid_cp();
        cp.name = "ab".into();
        assert!(validate_custom_preset_cli(&cp).is_err());
    }

    #[test]
    fn name_uppercase_rejected() {
        let mut cp = valid_cp();
        cp.name = "My-View".into();
        assert!(validate_custom_preset_cli(&cp).is_err());
    }

    #[test]
    fn name_collides_with_builtin_rejected() {
        for builtin in ["default", "security", "ips-dectet-incident"] {
            let mut cp = valid_cp();
            cp.name = builtin.into();
            let err = validate_custom_preset_cli(&cp).unwrap_err();
            assert!(err.contains("collides with a builtin"));
        }
    }

    #[test]
    fn invalid_refresh_rate_rejected() {
        let mut cp = valid_cp();
        cp.refresh_rate = "blinky".into();
        assert!(validate_custom_preset_cli(&cp).is_err());
    }

    #[test]
    fn invalid_tab_rejected() {
        let mut cp = valid_cp();
        cp.active_tab = "not-a-tab".into();
        assert!(validate_custom_preset_cli(&cp).is_err());
    }

    #[test]
    fn parse_hidden_panels_csv_empty_string_yields_empty_vec() {
        assert!(parse_hidden_panels_csv("").is_empty());
    }

    #[test]
    fn parse_hidden_panels_csv_with_spaces_trims() {
        let got = parse_hidden_panels_csv("a, b , c");
        assert_eq!(got, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_hidden_panels_csv_drops_blanks() {
        let got = parse_hidden_panels_csv("a,,b,");
        assert_eq!(got, vec!["a", "b"]);
    }
}
