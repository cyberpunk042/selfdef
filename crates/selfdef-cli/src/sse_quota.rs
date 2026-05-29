//! `selfdefctl sse-quota` — live MS022 SSE subscriber-quota state.
//!
//! Reads the 6 `selfdef_sse_subscribers_*` gauges from the daemon's
//! `/metrics` endpoint (shipped at selfdef commit 77b4499) and
//! renders an operator-readable saturation table + per-token
//! breakdown. Operator-side mirror of what sovereign-os surfaces
//! through the cockpit (proxy daemon + alerts + Grafana). Lets
//! operators inspect quota state without standing up the sovereign-os
//! proxy.
//!
//! Transport: UNIX socket `$SELFDEF_SOCKET` (default
//! `/run/selfdef.sock`) preferred; TCP fallback via
//! `$SELFDEF_API_URL` + `$SELFDEF_API_TOKEN` matching `m060-metrics`.
//!
//! Exit codes mirror the sovereign-os `ms022-doctor` severity ladder:
//!
//! - 0  OK    saturation ≤ 0.85 AND no token saturated
//! - 1  WARN  saturation > 0.85 OR ≥1 token at cap
//! - 2  FAIL  saturation ≥ 1.0 OR /metrics unreachable
//!
//! Read-only — never mutates anything.

use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

/// Thresholds match the sovereign-os alert rules + the ms022-doctor
/// classifier (`config/prometheus/alerts/ms022-sse-quota.rules.yml`
/// in the partner repo).
const APPROACHING_THRESHOLD: f64 = 0.85;
const SATURATED_THRESHOLD: f64 = 1.0;

/// Operator-side snapshot of the SSE quota state.
#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct SseQuotaSnapshot {
    pub(crate) global_active: Option<u64>,
    pub(crate) global_cap: Option<u64>,
    pub(crate) global_saturation: Option<f64>,
    pub(crate) per_token_cap: Option<u64>,
    pub(crate) per_token_saturated: Option<u64>,
    /// Per-token live counts; (token_fp_hex, subscribers). Sorted
    /// descending by subscriber count for operator readability.
    pub(crate) per_token: Vec<(String, u64)>,
    /// Derived classification — ok/approaching/saturated.
    pub(crate) state: &'static str,
}

fn fetch_metrics() -> Result<String> {
    let socket =
        std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string());
    if std::path::Path::new(&socket).exists() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                "http://localhost/metrics",
            ])
            .output()
            .context("invoking curl against the UNIX socket for /metrics")?;
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
                &format!("{url}/metrics"),
            ])
            .output()
            .context("invoking curl against the TCP API URL for /metrics")?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not fetch /metrics — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

/// Parse the SSE quota gauges out of a Prometheus exposition body.
/// Lines unrelated to MS022 are skipped silently.
pub(crate) fn parse_sse_quota_metrics(body: &str) -> SseQuotaSnapshot {
    let mut snap = SseQuotaSnapshot::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split metric name (with optional labels) from value.
        let (head, value_str) = match line.rsplit_once(' ') {
            Some(pair) => pair,
            None => continue,
        };
        let value_str = value_str.trim();

        if let Some(rest) = head.strip_prefix("selfdef_sse_subscribers_") {
            // The bare metric name (no labels) ends at `{` or end-of-string.
            let bare = rest.split('{').next().unwrap_or(rest);
            match bare {
                "global_active" => {
                    snap.global_active = value_str.parse::<u64>().ok();
                }
                "global_cap" => {
                    snap.global_cap = value_str.parse::<u64>().ok();
                }
                "global_saturation" => {
                    snap.global_saturation = value_str.parse::<f64>().ok();
                }
                "per_token_cap" => {
                    snap.per_token_cap = value_str.parse::<u64>().ok();
                }
                "per_token_saturated" => {
                    snap.per_token_saturated = value_str.parse::<u64>().ok();
                }
                "per_token" => {
                    if let (Some(fp), Ok(count)) =
                        (extract_token_fp(head), value_str.parse::<u64>())
                    {
                        snap.per_token.push((fp, count));
                    }
                }
                _ => {}
            }
        }
    }
    // Sort per-token descending by count, ties broken by fp for
    // determinism so successive invocations produce stable output.
    snap.per_token
        .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    snap.state = classify_state(&snap);
    snap
}

/// Extract the `token_fp` label value from a line head like
/// `selfdef_sse_subscribers_per_token{token_fp="aabbccdd"}`.
fn extract_token_fp(head: &str) -> Option<String> {
    let labels = head.split_once('{')?.1;
    let inner = labels.split_once('}').map_or(labels, |(a, _)| a);
    for part in inner.split(',') {
        let (k, v) = part.split_once('=')?;
        if k.trim() == "token_fp" {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Same classifier as the sovereign-os ms022-sse-quota-api proxy +
/// the doctor verb (locked thresholds 0.85 / 1.0).
fn classify_state(snap: &SseQuotaSnapshot) -> &'static str {
    let Some(sat) = snap.global_saturation else {
        return "unreachable";
    };
    if sat >= SATURATED_THRESHOLD {
        return "saturated";
    }
    let per_token_sat = snap.per_token_saturated.unwrap_or(0);
    if sat > APPROACHING_THRESHOLD || per_token_sat > 0 {
        return "approaching";
    }
    "ok"
}

fn render_table(snap: &SseQuotaSnapshot, rollup_only: bool) {
    println!("MS022 SSE subscriber quota");
    println!("==========================");
    println!("state            : {}", snap.state);
    println!(
        "global active    : {}",
        snap.global_active.map_or("—".into(), |n| n.to_string())
    );
    println!(
        "global cap       : {}",
        snap.global_cap.map_or("—".into(), |n| n.to_string())
    );
    println!(
        "global saturation: {:>7.4} ({})",
        snap.global_saturation.unwrap_or(0.0),
        snap.global_saturation
            .map(|s| format!("{:.1}%", s * 100.0))
            .unwrap_or_else(|| "—".into()),
    );
    println!(
        "per-token cap    : {}",
        snap.per_token_cap.map_or("—".into(), |n| n.to_string())
    );
    println!(
        "tokens saturated : {}",
        snap.per_token_saturated
            .map_or("—".into(), |n| n.to_string()),
    );

    if !rollup_only && !snap.per_token.is_empty() {
        println!();
        println!("per-token subscribers (descending):");
        println!("  {:<10} {:>10}", "token_fp", "count");
        println!("  {:-<10} {:->10}", "", "");
        for (fp, count) in &snap.per_token {
            println!("  {fp:<10} {count:>10}");
        }
    }
}

fn exit_code(snap: &SseQuotaSnapshot) -> i32 {
    match snap.state {
        "ok" => 0,
        "approaching" => 1,
        "saturated" | "unreachable" => 2,
        _ => 1,
    }
}

pub(crate) fn run(json: bool, rollup_only: bool) -> Result<i32> {
    let body = match fetch_metrics() {
        Ok(b) => b,
        Err(e) => {
            // Unreachable — render an honest envelope so monitoring
            // integrations get the same shape regardless of state.
            let snap = SseQuotaSnapshot {
                state: "unreachable",
                ..Default::default()
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "state": snap.state,
                        "error": e.to_string(),
                        "snapshot": snap,
                    }))?
                );
            } else {
                println!("MS022 SSE subscriber quota");
                println!("==========================");
                println!("state            : unreachable");
                println!("error            : {e}");
            }
            return Ok(exit_code(&snap));
        }
    };
    let snap = parse_sse_quota_metrics(&body);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "state": snap.state,
                "global_active": snap.global_active,
                "global_cap": snap.global_cap,
                "global_saturation": snap.global_saturation,
                "per_token_cap": snap.per_token_cap,
                "per_token_saturated": snap.per_token_saturated,
                "per_token": snap.per_token,
                "thresholds": {
                    "approaching": APPROACHING_THRESHOLD,
                    "saturated": SATURATED_THRESHOLD,
                },
            }))?
        );
    } else {
        render_table(&snap, rollup_only);
    }
    Ok(exit_code(&snap))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> String {
        let mut body = String::new();
        body.push_str("# HELP selfdef_sse_subscribers_global_active foo\n");
        body.push_str("# TYPE selfdef_sse_subscribers_global_active gauge\n");
        body.push_str("selfdef_sse_subscribers_global_active 25\n");
        body.push_str("selfdef_sse_subscribers_global_cap 100\n");
        body.push_str("selfdef_sse_subscribers_global_saturation 0.250000\n");
        body.push_str("selfdef_sse_subscribers_per_token_cap 8\n");
        body.push_str("selfdef_sse_subscribers_per_token_saturated 1\n");
        body.push_str("selfdef_sse_subscribers_per_token{token_fp=\"aaaa1111\"} 4\n");
        body.push_str("selfdef_sse_subscribers_per_token{token_fp=\"bbbb2222\"} 8\n");
        body.push_str("selfdef_sse_subscribers_per_token{token_fp=\"cccc3333\"} 1\n");
        body
    }

    #[test]
    fn parse_extracts_all_six_gauges() {
        let snap = parse_sse_quota_metrics(&sample_body());
        assert_eq!(snap.global_active, Some(25));
        assert_eq!(snap.global_cap, Some(100));
        assert!((snap.global_saturation.unwrap() - 0.25).abs() < 1e-6);
        assert_eq!(snap.per_token_cap, Some(8));
        assert_eq!(snap.per_token_saturated, Some(1));
        assert_eq!(snap.per_token.len(), 3);
    }

    #[test]
    fn parse_sorts_per_token_descending_by_count() {
        let snap = parse_sse_quota_metrics(&sample_body());
        assert_eq!(snap.per_token[0].0, "bbbb2222");
        assert_eq!(snap.per_token[0].1, 8);
        assert_eq!(snap.per_token[1].1, 4);
        assert_eq!(snap.per_token[2].1, 1);
    }

    #[test]
    fn classify_ok_below_approaching_threshold() {
        let snap = SseQuotaSnapshot {
            global_saturation: Some(0.5),
            per_token_saturated: Some(0),
            ..Default::default()
        };
        assert_eq!(classify_state(&snap), "ok");
    }

    #[test]
    fn classify_approaching_above_threshold() {
        let snap = SseQuotaSnapshot {
            global_saturation: Some(0.9),
            per_token_saturated: Some(0),
            ..Default::default()
        };
        assert_eq!(classify_state(&snap), "approaching");
    }

    #[test]
    fn classify_approaching_when_any_token_saturated() {
        let snap = SseQuotaSnapshot {
            global_saturation: Some(0.2),
            per_token_saturated: Some(1),
            ..Default::default()
        };
        assert_eq!(classify_state(&snap), "approaching");
    }

    #[test]
    fn classify_saturated_at_full_cap() {
        let snap = SseQuotaSnapshot {
            global_saturation: Some(1.0),
            per_token_saturated: Some(5),
            ..Default::default()
        };
        assert_eq!(classify_state(&snap), "saturated");
    }

    #[test]
    fn classify_unreachable_when_saturation_absent() {
        let snap = SseQuotaSnapshot {
            global_saturation: None,
            ..Default::default()
        };
        assert_eq!(classify_state(&snap), "unreachable");
    }

    #[test]
    fn exit_code_maps_states_to_severity_ladder() {
        for (state, expected) in [
            ("ok", 0),
            ("approaching", 1),
            ("saturated", 2),
            ("unreachable", 2),
        ] {
            let snap = SseQuotaSnapshot {
                state,
                ..Default::default()
            };
            assert_eq!(exit_code(&snap), expected, "state {state:?}");
        }
    }

    #[test]
    fn thresholds_match_partner_repo_alerts() {
        // The sovereign-os alerts (ms022-sse-quota.rules.yml) and the
        // ms022-doctor classifier both lock at 0.85 / 1.0. Drift here
        // = silent operator misdirection. The partner repo's
        // test_ms022_sse_quota_alerts_contract.py asserts the same
        // constants on its side.
        assert!((APPROACHING_THRESHOLD - 0.85).abs() < 1e-9);
        assert!((SATURATED_THRESHOLD - 1.0).abs() < 1e-9);
    }

    #[test]
    fn extract_token_fp_handles_canonical_label_shape() {
        assert_eq!(
            extract_token_fp("selfdef_sse_subscribers_per_token{token_fp=\"abc12345\"}"),
            Some("abc12345".to_string()),
        );
        assert_eq!(extract_token_fp("selfdef_sse_subscribers_per_token"), None,);
    }

    #[test]
    fn parse_skips_comments_blank_lines_and_unrelated_metrics() {
        let body = "# this is a comment\n\n\
                    irrelevant_metric 99\n\
                    selfdef_sse_subscribers_global_active 5\n";
        let snap = parse_sse_quota_metrics(body);
        assert_eq!(snap.global_active, Some(5));
        assert!(snap.global_cap.is_none());
    }
}
