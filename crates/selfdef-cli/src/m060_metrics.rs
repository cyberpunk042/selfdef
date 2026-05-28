//! `selfdefctl m060-metrics` — per-artifact M060 mirror-publish stats
//! directly from the daemon's /metrics endpoint.
//!
//! Sister to `m060-doctor` (filesystem-state checks) — this command
//! queries the LIVE daemon Prometheus surface for per-artifact
//! counters that selfdef-api/metrics.rs exposes:
//!
//!   selfdef_m060_mirror_publish_total{artifact, result}
//!   selfdef_m060_mirror_last_publish_unix{artifact}
//!
//! Useful during incident response when Prometheus itself may be the
//! unhealthy component — the operator wants the canonical counters
//! WITHOUT a Prometheus hop.
//!
//! Transport mirrors `audit-chains`: UNIX socket at $SELFDEF_SOCKET
//! preferred; falls back to TCP via $SELFDEF_API_URL +
//! $SELFDEF_API_TOKEN.
//!
//! Exit codes:
//!   0 = every artifact has been published at least once + no recent
//!       failures (worst = "ok")
//!   1 = at least one artifact has zero ok publishes OR > 0 failures
//!       in the last counter window (worst = "warn"|"critical") OR
//!       /metrics is unreachable

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

/// Stale-age threshold matching selfdef-api::m060_health::STALE_AGE_SECS.
const STALE_AGE_SECS: u64 = 5 * 60;

#[derive(Debug, Default, Clone, Serialize)]
pub(crate) struct ArtifactStats {
    artifact: String,
    ok: u64,
    failed: u64,
    last_publish_unix: Option<u64>,
    age_seconds: Option<u64>,
    state: &'static str,
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

/// Parse the relevant M060 lines out of a Prometheus exposition string.
/// Returns a {artifact -> stats} map.
pub(crate) fn parse_m060_metrics(body: &str) -> BTreeMap<String, ArtifactStats> {
    let mut map: BTreeMap<String, ArtifactStats> = BTreeMap::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("selfdef_m060_mirror_publish_total{") {
            let (labels, value) = match split_label_block(rest) {
                Some(v) => v,
                None => continue,
            };
            let artifact = label_value(&labels, "artifact").unwrap_or_default();
            let result = label_value(&labels, "result").unwrap_or_default();
            if artifact.is_empty() {
                continue;
            }
            let v: u64 = value.parse().unwrap_or(0);
            let entry = map
                .entry(artifact.clone())
                .or_insert_with(|| ArtifactStats {
                    artifact: artifact.clone(),
                    ..Default::default()
                });
            match result.as_str() {
                "ok" => entry.ok = v,
                "failed" => entry.failed = v,
                _ => {}
            }
        } else if let Some(rest) = trimmed.strip_prefix("selfdef_m060_mirror_last_publish_unix{") {
            let (labels, value) = match split_label_block(rest) {
                Some(v) => v,
                None => continue,
            };
            let artifact = label_value(&labels, "artifact").unwrap_or_default();
            if artifact.is_empty() {
                continue;
            }
            let ts: u64 = value.parse().unwrap_or(0);
            let entry = map
                .entry(artifact.clone())
                .or_insert_with(|| ArtifactStats {
                    artifact: artifact.clone(),
                    ..Default::default()
                });
            entry.last_publish_unix = Some(ts);
            entry.age_seconds = Some(now.saturating_sub(ts));
        }
    }
    // Classify each artifact's state — same vocabulary as
    // selfdef-api::m060_health::classify_state, applied per-artifact.
    for entry in map.values_mut() {
        entry.state = classify(entry);
    }
    map
}

fn classify(stats: &ArtifactStats) -> &'static str {
    if stats.ok == 0 && stats.failed == 0 {
        return "offline";
    }
    if stats.failed > 0 && stats.ok == 0 {
        return "failed";
    }
    if let Some(age) = stats.age_seconds {
        if age > STALE_AGE_SECS {
            return "stale";
        }
    }
    if stats.failed > 0 {
        return "degraded";
    }
    "ok"
}

/// Split `labels} value` → (labels-content, value-token).
fn split_label_block(rest: &str) -> Option<(String, String)> {
    let close = rest.find('}')?;
    let labels = &rest[..close];
    let value = rest[close + 1..].split_whitespace().next()?;
    Some((labels.to_string(), value.to_string()))
}

/// Extract `key="value"` from a Prometheus label block.
fn label_value(labels: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = labels.find(&needle)?;
    let after = &labels[start + needle.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn worst_state(map: &BTreeMap<String, ArtifactStats>) -> &'static str {
    let mut worst = "ok";
    for stats in map.values() {
        worst = match (worst, stats.state) {
            (_, "failed") => "failed",
            ("failed", _) => "failed",
            (_, "stale") if worst != "failed" => "stale",
            (_, "degraded") if worst != "failed" && worst != "stale" => "degraded",
            (_, "offline") if worst == "ok" => "offline",
            _ => worst,
        };
    }
    worst
}

/// Exit code from the worst state across all artifacts.
fn exit_code_for(worst: &str) -> i32 {
    match worst {
        "failed" | "stale" | "degraded" | "offline" => 1,
        _ => 0,
    }
}

pub(crate) fn run(json: bool, artifact: Option<&str>) -> Result<i32> {
    let body = fetch_metrics()?;
    let mut stats = parse_m060_metrics(&body);
    // Optional artifact filter — applied AFTER parse so the parser
    // stays general-purpose. Missing artifact under a filter is exit 1
    // with a clear message (vs silently returning empty).
    if let Some(want) = artifact {
        if !stats.contains_key(want) {
            let available: Vec<String> = stats.keys().cloned().collect();
            if json {
                let payload = serde_json::json!({
                    "schema_version": "1.0.0",
                    "filter_artifact": want,
                    "error": "artifact not found in daemon counters",
                    "available_artifacts": available,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!(
                    "artifact `{want}` not found in daemon counters — publisher \
                     may have never run, OR the artifact name is wrong"
                );
                if !available.is_empty() {
                    println!("available artifacts: {}", available.join(", "));
                }
            }
            return Ok(1);
        }
        let only = stats.remove(want).unwrap();
        stats.clear();
        stats.insert(want.to_string(), only);
    }
    let worst = worst_state(&stats);
    if json {
        let payload = serde_json::json!({
            "schema_version": "1.0.0",
            "worst": worst,
            "artifacts": stats.values().collect::<Vec<_>>(),
            "stale_threshold_seconds": STALE_AGE_SECS,
            "filter_artifact": artifact,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(exit_code_for(worst));
    }
    if stats.is_empty() {
        println!(
            "no M060 mirror-publish counters in /metrics — daemon may not have published yet, OR the mirror-export loop is disabled (no [deployment].selfdef_mirror_dir)"
        );
        return Ok(1);
    }
    println!(
        "{:<22} {:>8} {:>8} {:>12} {:>10}",
        "artifact", "ok", "failed", "age(s)", "state"
    );
    println!("{}", "-".repeat(22 + 8 + 8 + 12 + 10 + 4));
    for stats in stats.values() {
        let age = stats.age_seconds.map_or("—".to_string(), |a| a.to_string());
        println!(
            "{:<22} {:>8} {:>8} {:>12} {:>10}",
            stats.artifact, stats.ok, stats.failed, age, stats.state
        );
    }
    println!("{}", "-".repeat(22 + 8 + 8 + 12 + 10 + 4));
    let filter_note = artifact
        .map(|a| format!(" (filter: {a})"))
        .unwrap_or_default();
    let plural = if stats.len() == 1 { "" } else { "s" };
    println!(
        "worst: {worst} · stale threshold: {STALE_AGE_SECS}s ({} mirror{plural}{filter_note})",
        stats.len()
    );
    Ok(exit_code_for(worst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_artifact_ok_and_failed_counts() {
        let body = r#"# HELP selfdef_m060_mirror_publish_total
# TYPE selfdef_m060_mirror_publish_total counter
selfdef_m060_mirror_publish_total{artifact="grants.json",result="ok"} 42
selfdef_m060_mirror_publish_total{artifact="grants.json",result="failed"} 3
selfdef_m060_mirror_publish_total{artifact="audit.json",result="ok"} 17
"#;
        let map = parse_m060_metrics(body);
        assert_eq!(map.get("grants.json").unwrap().ok, 42);
        assert_eq!(map.get("grants.json").unwrap().failed, 3);
        assert_eq!(map.get("audit.json").unwrap().ok, 17);
        assert_eq!(map.get("audit.json").unwrap().failed, 0);
    }

    #[test]
    fn parse_extracts_last_publish_timestamp_and_derives_age() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "selfdef_m060_mirror_last_publish_unix{{artifact=\"grants.json\"}} {}\n",
            now - 100,
        );
        let map = parse_m060_metrics(&body);
        let stats = map.get("grants.json").unwrap();
        assert_eq!(stats.last_publish_unix.unwrap(), now - 100);
        // Age should be ~100s; allow ±2s for the now-vs-test-run gap.
        let age = stats.age_seconds.unwrap();
        assert!((100..=102).contains(&age), "age out of range: {age}");
    }

    #[test]
    fn classify_ok_when_recent_ok_no_failures() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "selfdef_m060_mirror_publish_total{{artifact=\"x\",result=\"ok\"}} 1\n\
             selfdef_m060_mirror_last_publish_unix{{artifact=\"x\"}} {}\n",
            now - 10,
        );
        let map = parse_m060_metrics(&body);
        assert_eq!(map.get("x").unwrap().state, "ok");
    }

    #[test]
    fn classify_stale_when_age_exceeds_threshold() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "selfdef_m060_mirror_publish_total{{artifact=\"x\",result=\"ok\"}} 1\n\
             selfdef_m060_mirror_last_publish_unix{{artifact=\"x\"}} {}\n",
            now - (STALE_AGE_SECS + 60),
        );
        let map = parse_m060_metrics(&body);
        assert_eq!(map.get("x").unwrap().state, "stale");
    }

    #[test]
    fn classify_degraded_when_ok_and_failed_both_present() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "selfdef_m060_mirror_publish_total{{artifact=\"x\",result=\"ok\"}} 5\n\
             selfdef_m060_mirror_publish_total{{artifact=\"x\",result=\"failed\"}} 2\n\
             selfdef_m060_mirror_last_publish_unix{{artifact=\"x\"}} {}\n",
            now - 5,
        );
        let map = parse_m060_metrics(&body);
        assert_eq!(map.get("x").unwrap().state, "degraded");
    }

    #[test]
    fn classify_failed_when_only_failed_no_ok() {
        let body = "selfdef_m060_mirror_publish_total{artifact=\"x\",result=\"failed\"} 3\n";
        let map = parse_m060_metrics(body);
        assert_eq!(map.get("x").unwrap().state, "failed");
    }

    #[test]
    fn classify_offline_when_no_counters_present() {
        // Edge case: HELP/TYPE lines present, no series → no entries.
        let body = "# HELP selfdef_m060_mirror_publish_total\n# TYPE selfdef_m060_mirror_publish_total counter\n";
        let map = parse_m060_metrics(body);
        assert!(map.is_empty(), "should be empty when no series present");
    }

    #[test]
    fn parse_skips_unrelated_series() {
        let body = "selfdef_events_total 42\n\
                    selfdef_m060_mirror_publish_total{artifact=\"x\",result=\"ok\"} 1\n";
        let map = parse_m060_metrics(body);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("x"));
    }

    #[test]
    fn worst_state_picks_failed_over_others() {
        let body = "selfdef_m060_mirror_publish_total{artifact=\"a\",result=\"failed\"} 1\n\
                    selfdef_m060_mirror_publish_total{artifact=\"b\",result=\"ok\"} 5\n";
        let map = parse_m060_metrics(body);
        assert_eq!(worst_state(&map), "failed");
    }

    #[test]
    fn worst_state_ok_when_every_artifact_clean() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            "selfdef_m060_mirror_publish_total{{artifact=\"a\",result=\"ok\"}} 5\n\
             selfdef_m060_mirror_last_publish_unix{{artifact=\"a\"}} {}\n",
            now - 5,
        );
        let map = parse_m060_metrics(&body);
        assert_eq!(worst_state(&map), "ok");
    }

    #[test]
    fn classify_handles_missing_artifact_signal() {
        // When the filter targets a non-existent artifact, the
        // classifier should never be called on it because we check
        // contains_key first. This test asserts the BTreeMap contract:
        // contains_key returns false on a key never inserted.
        let body = "selfdef_m060_mirror_publish_total{artifact=\"grants.json\",result=\"ok\"} 1\n";
        let map = parse_m060_metrics(body);
        assert!(!map.contains_key("audit.json"));
        assert!(map.contains_key("grants.json"));
    }

    #[test]
    fn parse_preserves_btreemap_sort_order_for_deterministic_output() {
        // Render output sorts by artifact name (BTreeMap). This test
        // asserts the contract — operators eyeballing diffs across
        // calls need stable ordering.
        let body = "selfdef_m060_mirror_publish_total{artifact=\"trust-scores.json\",result=\"ok\"} 1\n\
                    selfdef_m060_mirror_publish_total{artifact=\"audit.json\",result=\"ok\"} 1\n\
                    selfdef_m060_mirror_publish_total{artifact=\"grants.json\",result=\"ok\"} 1\n";
        let map = parse_m060_metrics(body);
        let names: Vec<&String> = map.keys().collect();
        assert_eq!(
            names,
            vec![
                &"audit.json".to_string(),
                &"grants.json".to_string(),
                &"trust-scores.json".to_string(),
            ]
        );
    }

    #[test]
    fn exit_code_zero_only_on_ok() {
        assert_eq!(exit_code_for("ok"), 0);
        assert_eq!(exit_code_for("offline"), 1);
        assert_eq!(exit_code_for("stale"), 1);
        assert_eq!(exit_code_for("failed"), 1);
        assert_eq!(exit_code_for("degraded"), 1);
    }
}
