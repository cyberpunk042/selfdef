//! `GET /v1/m060/health` — chain health observability for the M060
//! cross-repo mirror-export loop.
//!
//! The selfdef daemon's `mirror_export_loop` publishes 10 typed-mirror
//! artifacts into `[deployment].selfdef_mirror_dir` (default
//! `/run/sovereign-os/selfdef-mirror/`) on a 30s cadence. Operators
//! and sovereign-os health-aggregators need a single endpoint to query
//! "is the chain alive, when was each artifact last refreshed, do the
//! payloads parse?" without shell-poking the filesystem.
//!
//! Per-artifact health probe:
//! - `present`: file exists on disk
//! - `bytes`: file size in bytes (0 when absent)
//! - `last_publish_at`: mtime as RFC-3339 UTC (None when absent)
//! - `age_seconds`: seconds since mtime (None when absent)
//! - `parses_as_json`: whether the body is valid JSON (a tampered or
//!   half-written artifact fails this check; consumers can refuse it)
//!
//! Overall chain state derives from the 10 per-artifact probes:
//! - `online` = every expected artifact is present + parses
//! - `degraded` = some artifacts present, some absent (partial
//!   resident-store population — honest state during the operator-
//!   issued-domain onboarding flow)
//! - `offline` = zero artifacts present (daemon not running, or
//!   `selfdef_mirror_dir` not configured)
//! - `stale` = newest artifact's age > 5 minutes (~10 ticks of the
//!   30s mirror-export loop — indicates the loop is stuck or the
//!   daemon is paused)
//!
//! No mutation endpoints — this is pure observability.

use std::path::PathBuf;
use std::time::SystemTime;

use axum::Json;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const STALE_AGE_SECS: u64 = 5 * 60;

/// The 10 canonical M060 mirror artifacts in publish order. Wire-stable
/// per the daemon's `mirror_export_loop`.
const ARTIFACT_NAMES: &[&str] = &[
    "active-profile.json",
    "grants.json",
    "capability-tokens.json",
    "sandboxes.json",
    "quarantine.json",
    "trust-scores.json",
    "audit.json",
    "rules.json",
    "tui.json",
    "cli.json",
];

fn mirror_dir() -> PathBuf {
    std::env::var("SOVEREIGN_OS_SELFDEF_MIRROR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/sovereign-os/selfdef-mirror"))
}

#[derive(Debug, Serialize)]
pub(crate) struct ArtifactHealth {
    pub artifact: String,
    pub present: bool,
    pub bytes: u64,
    pub last_publish_at: Option<String>,
    pub age_seconds: Option<u64>,
    pub parses_as_json: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChainHealth {
    pub schema_version: &'static str,
    pub mirror_dir: String,
    pub state: &'static str,
    pub artifacts_present: usize,
    pub artifacts_expected: usize,
    pub newest_age_seconds: Option<u64>,
    pub artifacts: Vec<ArtifactHealth>,
}

/// `GET /v1/m060/health` handler.
pub(crate) async fn health() -> Json<ChainHealth> {
    let dir = mirror_dir();
    let now = SystemTime::now();
    let mut artifacts = Vec::with_capacity(ARTIFACT_NAMES.len());
    let mut present_count = 0usize;
    let mut parse_failures = 0usize;
    let mut newest_age: Option<u64> = None;
    for name in ARTIFACT_NAMES {
        let path = dir.join(name);
        let probe = probe_artifact(name, &path, now);
        if probe.present {
            present_count += 1;
        }
        if probe.present && !probe.parses_as_json {
            parse_failures += 1;
        }
        if let Some(age) = probe.age_seconds {
            newest_age = Some(newest_age.map_or(age, |existing| existing.min(age)));
        }
        artifacts.push(probe);
    }
    let state = classify_state(present_count, parse_failures, newest_age);
    Json(ChainHealth {
        schema_version: "1.0.0",
        mirror_dir: dir.display().to_string(),
        state,
        artifacts_present: present_count,
        artifacts_expected: ARTIFACT_NAMES.len(),
        newest_age_seconds: newest_age,
        artifacts,
    })
}

fn classify_state(present: usize, parse_failures: usize, newest_age: Option<u64>) -> &'static str {
    if present == 0 {
        return "offline";
    }
    if parse_failures > 0 {
        return "degraded";
    }
    if let Some(age) = newest_age {
        if age > STALE_AGE_SECS {
            return "stale";
        }
    }
    if present < ARTIFACT_NAMES.len() {
        return "degraded";
    }
    "online"
}

fn probe_artifact(name: &str, path: &std::path::Path, now: SystemTime) -> ArtifactHealth {
    let Ok(meta) = std::fs::metadata(path) else {
        return ArtifactHealth {
            artifact: name.to_string(),
            present: false,
            bytes: 0,
            last_publish_at: None,
            age_seconds: None,
            parses_as_json: false,
        };
    };
    let bytes = meta.len();
    let last_publish_at = meta.modified().ok().and_then(|m| {
        let odt: OffsetDateTime = m.into();
        odt.format(&Rfc3339).ok()
    });
    let age_seconds = meta
        .modified()
        .ok()
        .and_then(|m| now.duration_since(m).ok())
        .map(|d| d.as_secs());
    // Only attempt to parse if the file is reasonably small (8 MiB
    // cap — any M060 artifact larger than that is a bug). Avoids
    // unbounded memory use on a tampered artifact.
    let parses_as_json = if bytes > 8 * 1024 * 1024 {
        false
    } else {
        std::fs::read(path)
            .ok()
            .and_then(|bs| serde_json::from_slice::<serde_json::Value>(&bs).ok())
            .is_some()
    };
    ArtifactHealth {
        artifact: name.to_string(),
        present: true,
        bytes,
        last_publish_at,
        age_seconds,
        parses_as_json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_artifact(dir: &std::path::Path, name: &str, body: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn classify_state_offline_when_zero_present() {
        assert_eq!(classify_state(0, 0, None), "offline");
    }

    #[test]
    fn classify_state_degraded_when_partial() {
        assert_eq!(classify_state(5, 0, Some(10)), "degraded");
    }

    #[test]
    fn classify_state_degraded_when_parse_failures() {
        assert_eq!(classify_state(10, 1, Some(10)), "degraded");
    }

    #[test]
    fn classify_state_stale_when_age_exceeds_threshold() {
        assert_eq!(classify_state(10, 0, Some(STALE_AGE_SECS + 1)), "stale");
    }

    #[test]
    fn classify_state_online_when_all_present_fresh_parseable() {
        assert_eq!(classify_state(10, 0, Some(10)), "online");
    }

    #[test]
    fn probe_artifact_absent_path() {
        let tmp = tempfile::tempdir().unwrap();
        let probe = probe_artifact(
            "missing.json",
            &tmp.path().join("missing.json"),
            SystemTime::now(),
        );
        assert!(!probe.present);
        assert_eq!(probe.bytes, 0);
        assert!(probe.last_publish_at.is_none());
        assert!(probe.age_seconds.is_none());
        assert!(!probe.parses_as_json);
    }

    #[test]
    fn probe_artifact_present_and_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        write_artifact(tmp.path(), "ok.json", br#"{"k":1}"#);
        let probe = probe_artifact("ok.json", &path, SystemTime::now());
        assert!(probe.present);
        assert_eq!(probe.bytes, 7);
        assert!(probe.last_publish_at.is_some());
        assert!(probe.age_seconds.is_some());
        assert!(probe.parses_as_json);
    }

    #[test]
    fn probe_artifact_present_but_invalid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        write_artifact(tmp.path(), "bad.json", b"not json at all");
        let probe = probe_artifact("bad.json", &path, SystemTime::now());
        assert!(probe.present);
        assert!(!probe.parses_as_json);
    }

    #[test]
    fn artifact_names_set_is_exactly_ten_canonical() {
        let names: std::collections::HashSet<&&str> = ARTIFACT_NAMES.iter().collect();
        assert_eq!(names.len(), 10, "duplicate artifact in ARTIFACT_NAMES");
        // The 8 D-NN-tied + 2 MS007 cross-cutting (tui + cli).
        for required in [
            "active-profile.json",
            "grants.json",
            "capability-tokens.json",
            "sandboxes.json",
            "quarantine.json",
            "trust-scores.json",
            "audit.json",
            "rules.json",
            "tui.json",
            "cli.json",
        ] {
            assert!(names.contains(&required), "missing {required}");
        }
    }
}
