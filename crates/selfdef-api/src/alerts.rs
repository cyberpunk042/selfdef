//! `GET /v1/alerts` — typed JSON view of the 9 four-watchdog alert
//! classifications shipped in `modules/observability/assets/alerts/
//! selfdef.yml.template`.
//!
//! Reads the daemon's own watchdog metrics (via
//! `crate::watchdog_metrics::render()`), classifies each alert series
//! once on the server side, and returns the structured result so both
//! the PWA dashboard and `selfdefctl alerts` can consume a single
//! authoritative shape instead of re-parsing text/exposition twice on
//! the client side.
//!
//! Source: MS027 alert rules + dashboard `app.js::refreshAlerts` +
//! `selfdef-cli/src/alerts.rs` (same 9 series, same predicates,
//! moved server-side).

use axum::Json;
use serde::Serialize;
use std::collections::HashMap;

/// One alert row in the JSON response.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AlertRow {
    pub name: &'static str,
    pub ms: &'static str,
    pub series: &'static str,
    pub threshold: &'static str,
    pub value: Option<f64>,
    /// `"ok"` / `"warn"` / `"critical"` / `"unknown"`.
    pub state: &'static str,
}

/// Top-level response: aggregate worst-state plus per-row detail.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AlertsResponse {
    pub worst: &'static str,
    pub alerts: Vec<AlertRow>,
}

#[derive(Debug, Clone, Copy)]
enum Threshold {
    CriticalGreaterThanZero,
    WarnGreaterThanZero,
    CriticalEqualsZero,
    WarnEqualsZero,
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

/// Parse Prometheus text exposition into `(series → value)` map.
/// Mirrors the CLI's parser — kept independent so the two surfaces
/// can drift-test against each other (e.g. by running both and
/// asserting identical results).
fn parse_prom_exposition(text: &str) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
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
        let Some(name) = parts.next() else { continue };
        let Some(val_str) = parts.next() else {
            continue;
        };
        if let Ok(v) = val_str.parse::<f64>() {
            out.insert(name.to_string(), v);
        }
    }
    out
}

fn classify(series: &HashMap<String, f64>) -> Vec<AlertRow> {
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

/// `GET /v1/alerts` handler.
pub(crate) async fn list() -> Json<AlertsResponse> {
    let metrics_text = crate::watchdog_metrics::render();
    let series = parse_prom_exposition(&metrics_text);
    let rows = classify(&series);
    let worst = worst_state(&rows);
    Json(AlertsResponse {
        worst,
        alerts: rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_handles_labels_and_comments() {
        let text = "# HELP foo\n# TYPE foo gauge\nfoo 42\nbar{k=\"v\"} 1.5\n\nbaz 0\n";
        let m = parse_prom_exposition(text);
        assert_eq!(m.get("foo"), Some(&42.0));
        assert_eq!(m.get("bar"), Some(&1.5));
        assert_eq!(m.get("baz"), Some(&0.0));
    }

    #[test]
    fn classify_returns_nine_rows_in_canonical_order() {
        let series = HashMap::new();
        let rows = classify(&series);
        assert_eq!(rows.len(), 9);
        let names: Vec<&str> = rows.iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            vec![
                "FrictionAuditFailing",
                "PerimeterSigkill",
                "PerimeterPolicyMissing",
                "PerimeterChainBroken",
                "GuardianFailedResponse",
                "GuardianTetragonSocketMissing",
                "GuardianChainBroken",
                "SchedulerSustainedBackpressure",
                "SchedulerChainBroken",
            ]
        );
    }

    #[test]
    fn classify_critical_on_chain_broken_sentinel() {
        let mut series = HashMap::new();
        series.insert("selfdef_guardian_audit_chain_events".to_string(), -1.0);
        let rows = classify(&series);
        let row = rows
            .iter()
            .find(|r| r.name == "GuardianChainBroken")
            .expect("GuardianChainBroken row");
        assert_eq!(row.state, "critical");
        assert_eq!(worst_state(&rows), "critical");
    }

    #[test]
    fn worst_state_critical_dominates_warn_and_unknown() {
        let mut series = HashMap::new();
        series.insert("selfdef_perimeter_sigkills_total".to_string(), 42.0); // warn
        series.insert(
            "selfdef_scheduler_audit_chain_events".to_string(),
            -1.0,
        ); // critical
        let rows = classify(&series);
        assert_eq!(worst_state(&rows), "critical");
    }
}
