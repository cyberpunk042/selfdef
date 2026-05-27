//! `GET /v1/gpu` — MS011 Z-5 GPU watt deviance state surface.
//!
//! Per-GPU current power draw vs operator-defined `expected_power_
//! limit_watts`. SDD-026 Z-5 calls out: operator authors a per-GPU
//! expected limit in `/etc/selfdef/gpu-policy.toml` and the daemon
//! warns when current draw drifts from it (either spiking above or
//! sitting unexpectedly low, which can indicate driver fall-back or
//! a card going offline).
//!
//! Probe path:
//! 1. `nvidia-smi --query-gpu=index,power.draw,power.limit
//!    --format=csv,noheader,nounits` for the current snapshot
//!    (selfdef-hardware already ships the parser).
//! 2. Read `/etc/selfdef/gpu-policy.toml` (path overridable via
//!    `SELFDEF_GPU_POLICY` env). Missing file → policy is empty;
//!    every GPU classified as `unknown` (no expected limit) rather
//!    than `green` (we don't know if it's drifting).
//! 3. Per-GPU classification:
//!    - `green`  — |draw - expected_limit| ≤ tolerance_watts (default 25 W)
//!    - `yellow` — drift exceeds tolerance but within 2x tolerance
//!    - `red`    — drift exceeds 2x tolerance, OR draw exceeds the
//!      card's own power.limit (nvidia-smi reported)
//!    - `unknown` — operator hasn't set expected_power_limit_watts
//!      for this GPU, OR nvidia-smi reported N/A
//!
//! Source: MS011 catalog row M00275 (Hardware tab) + SDD-026 Z-5.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
struct GpuPolicy {
    /// Per-GPU-index expected power-limit. Operator authors this
    /// from per-card baseline measurements.
    #[serde(default)]
    expected_power_limit_watts: HashMap<String, u32>,
    /// Tolerance band around expected limit. Default 25 W matches
    /// the typical idle-vs-utility drift for a workstation card.
    #[serde(default)]
    tolerance_watts: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GpuRow {
    pub index: usize,
    pub current_watts: Option<u32>,
    pub power_limit_watts: Option<u32>,
    /// From `/etc/selfdef/gpu-policy.toml`.
    pub expected_limit_watts: Option<u32>,
    pub tolerance_watts: u32,
    pub state: &'static str,
    /// Human-readable summary of the classification.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct GpuResponse {
    pub worst: &'static str,
    pub policy_path: String,
    pub policy_present: bool,
    pub gpus: Vec<GpuRow>,
}

fn worst_state(rows: &[GpuRow]) -> &'static str {
    let mut worst = "green";
    for r in rows {
        match (worst, r.state) {
            (_, "red") => return "red",
            ("green", "yellow") => worst = "yellow",
            ("green", "unknown") => worst = "unknown",
            ("unknown", "yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

const DEFAULT_TOLERANCE_WATTS: u32 = 25;

fn classify(
    draw: Option<u32>,
    nvidia_limit: Option<u32>,
    expected: Option<u32>,
    tolerance: u32,
) -> (&'static str, String) {
    let Some(d) = draw else {
        return ("unknown", "nvidia-smi reported N/A for power.draw".into());
    };
    // Hard cap: draw exceeds the card's own reported limit → red.
    if let Some(l) = nvidia_limit {
        if d > l {
            return (
                "red",
                format!("draw {d} W > nvidia-smi power.limit {l} W (hardware over-cap)"),
            );
        }
    }
    let Some(e) = expected else {
        return (
            "unknown",
            format!("no expected_power_limit_watts in operator policy (current draw {d} W)"),
        );
    };
    let drift = d.abs_diff(e);
    if drift <= tolerance {
        (
            "green",
            format!("draw {d} W within ±{tolerance} W of expected {e} W"),
        )
    } else if drift <= tolerance.saturating_mul(2) {
        (
            "yellow",
            format!("draw {d} W drifts {drift} W from expected {e} W (tolerance ±{tolerance} W)"),
        )
    } else {
        (
            "red",
            format!(
                "draw {d} W drifts {drift} W from expected {e} W (>2x tolerance ±{tolerance} W)"
            ),
        )
    }
}

fn policy_path() -> PathBuf {
    std::env::var("SELFDEF_GPU_POLICY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/selfdef/gpu-policy.toml"))
}

fn load_policy(path: &std::path::Path) -> (GpuPolicy, bool) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (GpuPolicy::default(), false);
    };
    match toml::from_str::<GpuPolicy>(&text) {
        Ok(p) => (p, true),
        Err(_) => (GpuPolicy::default(), true), // malformed but present
    }
}

fn run_nvidia_smi() -> String {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,power.draw,power.limit",
            "--format=csv,noheader,nounits",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => String::new(),
    }
}

pub(crate) fn probe() -> GpuResponse {
    let policy_path = policy_path();
    let (policy, policy_present) = load_policy(&policy_path);
    let tolerance = policy.tolerance_watts.unwrap_or(DEFAULT_TOLERANCE_WATTS);
    let body = run_nvidia_smi();
    let snapshots = selfdef_hardware::parse_nvidia_smi_power_csv(&body);
    let mut gpus: Vec<GpuRow> = Vec::with_capacity(snapshots.len());
    for (index, draw, nvidia_limit) in snapshots {
        let key = index.to_string();
        let expected = policy.expected_power_limit_watts.get(&key).copied();
        let (state, detail) = classify(draw, nvidia_limit, expected, tolerance);
        gpus.push(GpuRow {
            index,
            current_watts: draw,
            power_limit_watts: nvidia_limit,
            expected_limit_watts: expected,
            tolerance_watts: tolerance,
            state,
            detail,
        });
    }
    let worst = worst_state(&gpus);
    GpuResponse {
        worst,
        policy_path: policy_path.display().to_string(),
        policy_present,
        gpus,
    }
}

/// `GET /v1/gpu` handler.
pub(crate) async fn show() -> Json<GpuResponse> {
    Json(probe())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_green_within_tolerance() {
        let (state, _) = classify(Some(300), Some(350), Some(290), 25);
        assert_eq!(state, "green");
    }

    #[test]
    fn classify_yellow_outside_tolerance_within_double() {
        // tolerance 25, drift 40 → between 1x and 2x tolerance
        let (state, _) = classify(Some(335), Some(350), Some(295), 25);
        assert_eq!(state, "yellow");
    }

    #[test]
    fn classify_red_more_than_double_tolerance() {
        // tolerance 25, drift 100
        let (state, _) = classify(Some(395), Some(450), Some(295), 25);
        assert_eq!(state, "red");
    }

    #[test]
    fn classify_red_when_draw_exceeds_nvidia_limit() {
        // draw exceeds hardware-reported limit (driver/firmware bug?)
        let (state, _) = classify(Some(360), Some(350), Some(300), 25);
        assert_eq!(state, "red");
    }

    #[test]
    fn classify_unknown_when_no_expected_in_policy() {
        let (state, _) = classify(Some(300), Some(350), None, 25);
        assert_eq!(state, "unknown");
    }

    #[test]
    fn classify_unknown_when_draw_is_na() {
        let (state, _) = classify(None, Some(350), Some(300), 25);
        assert_eq!(state, "unknown");
    }

    #[test]
    fn worst_state_red_dominates() {
        let rows = vec![
            GpuRow {
                index: 0,
                current_watts: Some(300),
                power_limit_watts: Some(350),
                expected_limit_watts: Some(300),
                tolerance_watts: 25,
                state: "green",
                detail: "ok".into(),
            },
            GpuRow {
                index: 1,
                current_watts: Some(400),
                power_limit_watts: Some(350),
                expected_limit_watts: Some(300),
                tolerance_watts: 25,
                state: "red",
                detail: "over".into(),
            },
        ];
        assert_eq!(worst_state(&rows), "red");
    }

    #[test]
    fn load_policy_returns_empty_when_path_missing() {
        let tmp = std::env::temp_dir().join("nonexistent-gpu-policy-xyz.toml");
        let _ = std::fs::remove_file(&tmp);
        let (p, present) = load_policy(&tmp);
        assert!(!present);
        assert!(p.expected_power_limit_watts.is_empty());
    }

    #[test]
    fn load_policy_parses_operator_authored_toml() {
        let tmp = std::env::temp_dir().join(format!(
            "selfdef-gpu-policy-test-{}.toml",
            std::process::id()
        ));
        let body = "tolerance_watts = 40\n\
                    [expected_power_limit_watts]\n\
                    \"0\" = 290\n\
                    \"1\" = 295\n";
        std::fs::write(&tmp, body).unwrap();
        let (p, present) = load_policy(&tmp);
        assert!(present);
        assert_eq!(p.tolerance_watts, Some(40));
        assert_eq!(p.expected_power_limit_watts.get("0").copied(), Some(290));
        assert_eq!(p.expected_power_limit_watts.get("1").copied(), Some(295));
        let _ = std::fs::remove_file(&tmp);
    }
}
