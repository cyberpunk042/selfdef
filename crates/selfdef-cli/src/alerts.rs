//! `selfdefctl alerts` — CLI parity with the dashboard "Alerts overview"
//! 6th panel.
//!
//! Reads the daemon's `/metrics` endpoint (Prometheus text exposition
//! format), parses out the 9 alert-relevant series, applies the same
//! threshold predicates as `modules/observability/assets/alerts/
//! selfdef.yml.template`, and renders a per-alert row to the operator
//! showing `NAME · MS · series · threshold · current value · STATE`.
//!
//! Exit codes:
//! - 0 = every alert OK (or only `unknown` for series the daemon isn't
//!       exporting yet)
//! - 1 = at least one alert in `warn` or `critical` state
//!
//! This lets operators gate other commands behind the alert state:
//!     selfdefctl alerts --quiet && deploy.sh
//!
//! Source: MS027 alert rules + dashboard `app.js::refreshAlerts` (the
//! same 9 series + same predicates, but rendered for the terminal).

use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

/// One alert row — matches the dashboard panel's row shape so any
/// future cross-surface drift gets caught by L1-cli-surface +
/// L1-dashboard-sections both consuming the same alert table.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AlertRow {
    pub(crate) name: &'static str,
    pub(crate) ms: &'static str,
    pub(crate) series: &'static str,
    pub(crate) threshold: &'static str,
    /// Current value from `/metrics`. `None` when the series isn't
    /// in the exposition (daemon down, metric not exported yet).
    pub(crate) value: Option<f64>,
    /// `"ok"` / `"warn"` / `"critical"` / `"unknown"`.
    pub(crate) state: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum Threshold {
    /// Critical when value > 0.
    CriticalGreaterThanZero,
    /// Warning when value > 0.
    WarnGreaterThanZero,
    /// Critical when value == 0.
    CriticalEqualsZero,
    /// Warning when value == 0.
    WarnEqualsZero,
    /// Critical when value == -1 (sentinel for "chain broken").
    CriticalEqualsMinusOne,
}

impl Threshold {
    fn classify(&self, v: f64) -> &'static str {
        match self {
            Threshold::CriticalGreaterThanZero => {
                if v > 0.0 {
                    "critical"
                } else {
                    "ok"
                }
            }
            Threshold::WarnGreaterThanZero => {
                if v > 0.0 {
                    "warn"
                } else {
                    "ok"
                }
            }
            Threshold::CriticalEqualsZero => {
                if v == 0.0 {
                    "critical"
                } else {
                    "ok"
                }
            }
            Threshold::WarnEqualsZero => {
                if v == 0.0 {
                    "warn"
                } else {
                    "ok"
                }
            }
            Threshold::CriticalEqualsMinusOne => {
                if v == -1.0 {
                    "critical"
                } else {
                    "ok"
                }
            }
        }
    }
}

const ALERTS: &[(&str, &str, &str, &str, Threshold)] = &[
    (
        "FrictionAuditFailing",
        "MS046",
        "selfdef_friction_audit_failing_total",
        "> 0",
        Threshold::CriticalGreaterThanZero,
    ),
    (
        "PerimeterSigkill",
        "MS047",
        "selfdef_perimeter_sigkills_total",
        "rate > 0 / 5m",
        Threshold::WarnGreaterThanZero,
    ),
    (
        "PerimeterPolicyMissing",
        "MS047",
        "selfdef_perimeter_policy_present",
        "== 0 for 2m",
        Threshold::CriticalEqualsZero,
    ),
    (
        "PerimeterChainBroken",
        "MS047",
        "selfdef_perimeter_audit_chain_events",
        "== -1",
        Threshold::CriticalEqualsMinusOne,
    ),
    (
        "GuardianFailedResponse",
        "MS044",
        "selfdef_guardian_failed_responses_total",
        "> 0",
        Threshold::CriticalGreaterThanZero,
    ),
    (
        "GuardianTetragonSocketMissing",
        "MS044",
        "selfdef_guardian_tetragon_socket_present",
        "== 0 for 2m",
        Threshold::WarnEqualsZero,
    ),
    (
        "GuardianChainBroken",
        "MS044",
        "selfdef_guardian_audit_chain_events",
        "== -1",
        Threshold::CriticalEqualsMinusOne,
    ),
    (
        "SchedulerSustainedBackpressure",
        "MS048",
        "selfdef_scheduler_backpressured_decisions_total",
        "rate > 0 / 10m",
        Threshold::WarnGreaterThanZero,
    ),
    (
        "SchedulerChainBroken",
        "MS048",
        "selfdef_scheduler_audit_chain_events",
        "== -1",
        Threshold::CriticalEqualsMinusOne,
    ),
];

/// Parse Prometheus text exposition into a `(series_name → value)`
/// map. Comments (`# ...`) are skipped; samples with `{labels}` blocks
/// have those stripped before parsing (matches the JS parser shape).
pub(crate) fn parse_prom_exposition(text: &str) -> std::collections::HashMap<String, f64> {
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip any {labels} block: `foo{a="b"} 1.0` → `foo 1.0`.
        let no_labels = if let (Some(lb), Some(rb)) = (trimmed.find('{'), trimmed.find('}')) {
            if lb < rb {
                let mut s = String::with_capacity(trimmed.len() - (rb - lb + 1));
                s.push_str(&trimmed[..lb]);
                s.push_str(&trimmed[rb + 1..]);
                s
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };
        let mut parts = no_labels.split_whitespace();
        let name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        let val_str = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        if let Ok(v) = val_str.parse::<f64>() {
            out.insert(name.to_string(), v);
        }
    }
    out
}

/// Worst state across all rows, with `critical > warn > unknown > ok`
/// ordering.
fn worst_state(rows: &[AlertRow]) -> &'static str {
    let mut worst = "ok";
    for r in rows {
        match (worst, r.state) {
            (_, "critical") => return "critical",
            ("ok", "warn") => worst = "warn",
            ("ok", "unknown") => worst = "unknown",
            ("unknown", "warn") => worst = "warn",
            _ => {}
        }
    }
    worst
}

/// Build the 9 rows from a parsed exposition map.
pub(crate) fn classify(series: &std::collections::HashMap<String, f64>) -> Vec<AlertRow> {
    ALERTS
        .iter()
        .map(|(name, ms, series_name, threshold, predicate)| {
            let value = series.get(*series_name).copied();
            let state = match value {
                Some(v) => predicate.classify(v),
                None => "unknown",
            };
            AlertRow {
                name,
                ms,
                series: series_name,
                threshold,
                value,
                state,
            }
        })
        .collect()
}

/// Fetch any endpoint from the local daemon. Tries the UNIX socket first
/// (no auth needed), falls back to TCP with bearer token if configured.
fn fetch_endpoint(path: &str) -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    let socket_path = std::path::Path::new(&socket);
    if socket_path.exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                &format!("http://localhost{path}"),
            ])
            .output()
            .with_context(|| format!("invoking curl against the UNIX socket for {path}"))?;
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
                &format!("{url}{path}"),
            ])
            .output()
            .with_context(|| format!("invoking curl against the TCP API URL for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch {} — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable",
        path,
        socket
    ))
}

/// Parse a `/v1/alerts` JSON response body into `(worst, rows)`.
/// Extracted from `try_fetch_v1_alerts` so the conversion can be
/// unit-tested without a live daemon. Returns `None` on any shape
/// mismatch — caller falls through to the `/metrics` fallback.
fn parse_v1_alerts_response(body: &str) -> Option<(&'static str, Vec<AlertRow>)> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let worst_str = parsed.get("worst")?.as_str()?;
    let worst: &'static str = match worst_str {
        "ok" => "ok",
        "warn" => "warn",
        "critical" => "critical",
        "unknown" => "unknown",
        _ => return None,
    };
    let alerts_arr = parsed.get("alerts")?.as_array()?;
    let mut rows = Vec::with_capacity(alerts_arr.len());
    for row_val in alerts_arr {
        let name_str = row_val.get("name")?.as_str()?;
        // Resolve back to the static ALERTS metadata by name match,
        // so AlertRow's static-str fields stay consistent with the
        // /metrics-fallback path's rows.
        let (name, ms, series, threshold, _) =
            ALERTS.iter().find(|(n, ..)| *n == name_str).copied()?;
        let value = row_val.get("value").and_then(|v| v.as_f64());
        let state_str = row_val.get("state")?.as_str()?;
        let state: &'static str = match state_str {
            "ok" => "ok",
            "warn" => "warn",
            "critical" => "critical",
            "unknown" => "unknown",
            _ => return None,
        };
        rows.push(AlertRow {
            name,
            ms,
            series,
            threshold,
            value,
            state,
        });
    }
    Some((worst, rows))
}

/// Try the typed `/v1/alerts` endpoint — returns `(worst, rows)` if
/// the daemon serves it, `None` otherwise (older daemon, 404 HTML,
/// network failure). Caller falls back to client-side classification.
fn try_fetch_v1_alerts() -> Option<(&'static str, Vec<AlertRow>)> {
    let body = fetch_endpoint("/v1/alerts").ok()?;
    parse_v1_alerts_response(&body)
}

/// Fetch `/metrics` from the local daemon — kept as the fallback when
/// `/v1/alerts` is unavailable. Tries the UNIX socket first (no auth
/// needed), falls back to TCP with bearer token if configured.
fn fetch_metrics() -> Result<String> {
    // First try the curl wrapper against the UNIX socket — the daemon
    // ships at `/run/selfdef.sock` by default. Operators may override
    // via `SELFDEF_SOCKET` env (matches the dashboard's local-only
    // dev-loop).
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    let socket_path = std::path::Path::new(&socket);
    if socket_path.exists() {
        let out = Command::new("curl")
            .args(["-s", "--unix-socket", &socket, "http://localhost/metrics"])
            .output()
            .context("invoking curl against the UNIX socket")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    // Fall back to TCP. Operator must set SELFDEF_API_URL +
    // SELFDEF_API_TOKEN (matches selfdefctl + dashboard convention).
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Command::new("curl")
            .args([
                "-s",
                "-H",
                &format!("Authorization: Bearer {token}"),
                &format!("{url}/metrics"),
            ])
            .output()
            .context("invoking curl against the TCP API URL")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /metrics — neither {} nor SELFDEF_API_URL+SELFDEF_API_TOKEN were reachable",
        socket
    ))
}

/// Entry-point. Returns the process exit code.
///
/// Prefers the typed `GET /v1/alerts` endpoint (server-side classifier,
/// single source of truth shared with the PWA dashboard). Falls back
/// to `/metrics` + client-side classification when `/v1/alerts` is
/// unreachable (older daemon / 404 / network failure) so older
/// deployments keep working.
pub(crate) fn run(json: bool, quiet: bool) -> Result<i32> {
    let (worst, rows) = match try_fetch_v1_alerts() {
        Some((w, r)) => (w, r),
        None => {
            let metrics_text = fetch_metrics()?;
            let series = parse_prom_exposition(&metrics_text);
            let rows = classify(&series);
            let worst = worst_state(&rows);
            (worst, rows)
        }
    };

    if quiet {
        // PS1-friendly single-line output: `selfdef-alerts: WORST` —
        // exit non-zero iff worst != "ok" so operators can do
        // `selfdefctl alerts --quiet && deploy.sh`.
        println!("selfdef-alerts: {}", worst);
    } else if json {
        let json_out = serde_json::json!({
            "worst": worst,
            "alerts": rows,
        });
        println!("{}", serde_json::to_string(&json_out)?);
    } else {
        println!(
            "{:<32} {:<5} {:<48} {:<18} {:>10}   {}",
            "ALERT", "MS", "SERIES", "THRESHOLD", "CURRENT", "STATE"
        );
        println!("{}", "─".repeat(132));
        for r in &rows {
            let val = match r.value {
                Some(v) => format!("{v}"),
                None => "—".to_string(),
            };
            println!(
                "{:<32} {:<5} {:<48} {:<18} {:>10}   {}",
                r.name,
                r.ms,
                r.series,
                r.threshold,
                val,
                r.state.to_uppercase()
            );
        }
        println!("{}", "─".repeat(132));
        println!("WORST: {}", worst.to_uppercase());
    }

    Ok(match worst {
        "ok" => 0,
        // Treat unknown as 0 so a freshly-booted daemon that hasn't
        // exported every series yet doesn't break operator gates.
        "unknown" => 0,
        _ => 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_exposition() {
        let text = "# HELP foo whatever\n# TYPE foo counter\nfoo 42\nbar{label=\"x\"} 3.14\n";
        let m = parse_prom_exposition(text);
        assert_eq!(m.get("foo"), Some(&42.0));
        assert_eq!(m.get("bar"), Some(&3.14));
    }

    #[test]
    fn classify_all_ok_when_series_clean() {
        let mut series = std::collections::HashMap::new();
        series.insert("selfdef_friction_audit_failing_total".to_string(), 0.0);
        series.insert("selfdef_perimeter_sigkills_total".to_string(), 0.0);
        series.insert("selfdef_perimeter_policy_present".to_string(), 1.0);
        series.insert("selfdef_perimeter_audit_chain_events".to_string(), 7.0);
        series.insert("selfdef_guardian_failed_responses_total".to_string(), 0.0);
        series.insert("selfdef_guardian_tetragon_socket_present".to_string(), 1.0);
        series.insert("selfdef_guardian_audit_chain_events".to_string(), 5.0);
        series.insert(
            "selfdef_scheduler_backpressured_decisions_total".to_string(),
            0.0,
        );
        series.insert("selfdef_scheduler_audit_chain_events".to_string(), 12.0);
        let rows = classify(&series);
        assert_eq!(rows.len(), 9);
        for r in &rows {
            assert_eq!(r.state, "ok", "{} expected ok", r.name);
        }
        assert_eq!(worst_state(&rows), "ok");
    }

    #[test]
    fn classify_critical_on_chain_broken() {
        let mut series = std::collections::HashMap::new();
        series.insert("selfdef_perimeter_audit_chain_events".to_string(), -1.0);
        let rows = classify(&series);
        let row = rows
            .iter()
            .find(|r| r.name == "PerimeterChainBroken")
            .expect("PerimeterChainBroken row");
        assert_eq!(row.state, "critical");
        assert_eq!(worst_state(&rows), "critical");
    }

    #[test]
    fn classify_unknown_when_series_missing() {
        let series = std::collections::HashMap::new();
        let rows = classify(&series);
        for r in &rows {
            assert_eq!(r.state, "unknown");
        }
        // worst is "unknown" but the run() entrypoint maps that to 0
        // (don't break operator gates on a freshly-booted daemon).
        assert_eq!(worst_state(&rows), "unknown");
    }

    #[test]
    fn classify_warn_on_sigkill_count() {
        let mut series = std::collections::HashMap::new();
        series.insert("selfdef_perimeter_sigkills_total".to_string(), 42.0);
        let rows = classify(&series);
        let row = rows
            .iter()
            .find(|r| r.name == "PerimeterSigkill")
            .expect("PerimeterSigkill row");
        assert_eq!(row.state, "warn");
    }

    #[test]
    fn parse_v1_alerts_response_round_trips_canonical_shape() {
        // The exact JSON shape the daemon's GET /v1/alerts handler
        // serves (crates/selfdef-api/src/alerts.rs::list).
        let body = r#"{
          "worst": "critical",
          "alerts": [
            {"name":"FrictionAuditFailing","ms":"MS046","series":"selfdef_friction_audit_failing_total","threshold":"> 0","value":0.0,"state":"ok"},
            {"name":"PerimeterSigkill","ms":"MS047","series":"selfdef_perimeter_sigkills_total","threshold":"rate > 0 / 5m","value":42.0,"state":"warn"},
            {"name":"PerimeterPolicyMissing","ms":"MS047","series":"selfdef_perimeter_policy_present","threshold":"== 0 for 2m","value":1.0,"state":"ok"},
            {"name":"PerimeterChainBroken","ms":"MS047","series":"selfdef_perimeter_audit_chain_events","threshold":"== -1","value":-1.0,"state":"critical"},
            {"name":"GuardianFailedResponse","ms":"MS044","series":"selfdef_guardian_failed_responses_total","threshold":"> 0","value":0.0,"state":"ok"},
            {"name":"GuardianTetragonSocketMissing","ms":"MS044","series":"selfdef_guardian_tetragon_socket_present","threshold":"== 0 for 2m","value":1.0,"state":"ok"},
            {"name":"GuardianChainBroken","ms":"MS044","series":"selfdef_guardian_audit_chain_events","threshold":"== -1","value":5.0,"state":"ok"},
            {"name":"SchedulerSustainedBackpressure","ms":"MS048","series":"selfdef_scheduler_backpressured_decisions_total","threshold":"rate > 0 / 10m","value":0.0,"state":"ok"},
            {"name":"SchedulerChainBroken","ms":"MS048","series":"selfdef_scheduler_audit_chain_events","threshold":"== -1","value":12.0,"state":"ok"}
          ]
        }"#;
        let (worst, rows) = parse_v1_alerts_response(body).expect("expected Some");
        assert_eq!(worst, "critical");
        assert_eq!(rows.len(), 9);
        // PerimeterChainBroken row
        let chain = rows
            .iter()
            .find(|r| r.name == "PerimeterChainBroken")
            .expect("PerimeterChainBroken row");
        assert_eq!(chain.state, "critical");
        assert_eq!(chain.value, Some(-1.0));
        // The static-str rehydration: ms/series/threshold must come
        // from the local ALERTS table, not be borrowed from the body
        // (so the lifetime is 'static).
        assert_eq!(chain.ms, "MS047");
        assert_eq!(chain.series, "selfdef_perimeter_audit_chain_events");
    }

    #[test]
    fn parse_v1_alerts_response_returns_none_on_malformed_body() {
        assert!(parse_v1_alerts_response("not json").is_none());
        assert!(parse_v1_alerts_response("{}").is_none());
        assert!(parse_v1_alerts_response(r#"{"worst":"ok"}"#).is_none());
        // Unknown state string → reject (don't silently coerce).
        let bad_state = r#"{"worst":"ok","alerts":[{"name":"FrictionAuditFailing","ms":"MS046","series":"selfdef_friction_audit_failing_total","threshold":"> 0","value":0.0,"state":"unicorn"}]}"#;
        assert!(parse_v1_alerts_response(bad_state).is_none());
        // Unknown alert name → reject (catches drift between server
        // and CLI's static ALERTS table).
        let bad_name = r#"{"worst":"ok","alerts":[{"name":"NewAlertName","ms":"MS046","series":"x","threshold":"> 0","value":0.0,"state":"ok"}]}"#;
        assert!(parse_v1_alerts_response(bad_name).is_none());
    }

    #[test]
    fn parse_v1_alerts_response_handles_null_value() {
        // Server emits value=null when the series isn't exported yet.
        let body = r#"{
          "worst": "unknown",
          "alerts": [
            {"name":"FrictionAuditFailing","ms":"MS046","series":"selfdef_friction_audit_failing_total","threshold":"> 0","value":null,"state":"unknown"}
          ]
        }"#;
        let (worst, rows) = parse_v1_alerts_response(body).expect("expected Some");
        assert_eq!(worst, "unknown");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, None);
        assert_eq!(rows[0].state, "unknown");
    }
}
