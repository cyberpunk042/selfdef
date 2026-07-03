//! `GET /v1/health` — MS011 Z-6 composite autohealth surface.
//!
//! Aggregates every operator-visible state surface into a single
//! response so operators can answer "is the box healthy?" with one
//! HTTP call. Used by the daemon's autohealth scheduler (when it
//! lands) + by external monitoring that doesn't want to scrape every
//! /v1/* endpoint separately.
//!
//! Composition (each component contributes one row + its `worst`
//! state to the aggregate):
//!
//! - `alerts`   — `/v1/alerts` worst across the 15-alert ALERTS catalog
//! - `network`  — `/v1/network` worst across the 5 components
//! - `storage`  — `/v1/storage` worst across filesystem mounts
//! - `raid`     — `/v1/raid` worst across MD arrays (or "ok" if no MD)
//! - `gpu`      — `/v1/gpu` worst across GPUs (or "unknown" if no policy / no nvidia-smi)
//! - `cpu`      — `/v1/cpu` mode classification (informational; never
//!   degrades the aggregate — `custom` is operator choice)
//!
//! The composite `worst` follows the standard ordering:
//! `red/critical > yellow/warn > unknown > green/ok`.
//!
//! Source: MS011 catalog rows + SDD-026 Z-6 (autohealth composite).

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HealthComponent {
    pub name: &'static str,
    /// `"ok" | "warn" | "critical" | "unknown"` — normalized so the
    /// aggregate can compose across surfaces that use different
    /// vocabularies (alerts uses critical/warn/ok; network uses
    /// red/yellow/green; cpu uses mode names).
    pub state: &'static str,
    /// One-line operator-readable detail (e.g. `"3 of 15 alerts in
    /// WARN state"`, `"all 5 components green"`, `"current mode
    /// peak-inference"`).
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HealthResponse {
    pub worst: &'static str,
    pub components: Vec<HealthComponent>,
}

/// Normalize each surface's own state vocabulary into the composite
/// 4-state ladder. Returns `"unknown"` for anything that doesn't
/// match the documented vocabularies.
fn normalize(state: &str) -> &'static str {
    match state {
        "ok" | "green" => "ok",
        "warn" | "yellow" => "warn",
        "critical" | "red" => "critical",
        "unknown" => "unknown",
        _ => "unknown",
    }
}

fn worst_state(components: &[HealthComponent]) -> &'static str {
    let mut worst = "ok";
    for c in components {
        match (worst, c.state) {
            (_, "critical") => return "critical",
            ("ok", "warn") => worst = "warn",
            ("ok", "unknown") => worst = "unknown",
            ("unknown", "warn") => worst = "warn",
            _ => {}
        }
    }
    worst
}

pub(crate) async fn show() -> Json<HealthResponse> {
    // Each component reuses the existing probe function from its
    // module. Sequential probes keep the implementation simple; if
    // latency becomes a concern, we can parallelize with tokio::join!
    // (the probes are independent — none depends on the result of
    // another).
    let alerts_resp = crate::alerts::list().await;
    let network_resp = crate::network::show().await;
    let storage_resp = crate::storage::show().await;
    let raid_resp = crate::raid::show().await;
    let gpu_resp = crate::gpu::show().await;
    let cpu_resp = crate::cpu::show().await;

    let alerts = &alerts_resp.0;
    let network = &network_resp.0;
    let storage = &storage_resp.0;
    let raid = &raid_resp.0;
    let gpu = &gpu_resp.0;
    let cpu = &cpu_resp.0;

    // Alerts detail: count by state. Total comes from the live
    // catalog length so future YAML/catalog growth auto-cascades
    // through the operator-facing detail string.
    let alert_total = alerts.alerts.len();
    let mut alert_critical = 0usize;
    let mut alert_warn = 0usize;
    let mut alert_unknown = 0usize;
    for a in &alerts.alerts {
        match a.state {
            "critical" => alert_critical += 1,
            "warn" => alert_warn += 1,
            "unknown" => alert_unknown += 1,
            _ => {}
        }
    }
    let alerts_detail = if alert_critical > 0 {
        format!(
            "{alert_critical} CRITICAL, {alert_warn} WARN ({} of {alert_total} alerts elevated)",
            alert_critical + alert_warn
        )
    } else if alert_warn > 0 {
        format!("{alert_warn} WARN of {alert_total} alerts")
    } else if alert_unknown > 0 {
        format!("{alert_unknown} UNKNOWN of {alert_total} alerts (some series not yet exported)")
    } else {
        format!("all {alert_total} alerts green")
    };

    let components = vec![
        HealthComponent {
            name: "alerts",
            state: normalize(alerts.worst),
            detail: alerts_detail,
        },
        HealthComponent {
            name: "network",
            state: normalize(network.worst),
            detail: format!("{} components", network.components.len()),
        },
        HealthComponent {
            name: "storage",
            state: normalize(storage.worst),
            detail: format!(
                "{} mount(s), {} log dir(s)",
                storage.mounts.len(),
                storage.log_dirs.len()
            ),
        },
        HealthComponent {
            name: "raid",
            state: if raid.mdstat_present {
                normalize(raid.worst)
            } else {
                // No /proc/mdstat → no software RAID on this host →
                // vacuously OK (don't drag the aggregate down).
                "ok"
            },
            detail: if raid.mdstat_present {
                format!("{} MD array(s)", raid.arrays.len())
            } else {
                "no /proc/mdstat (host has no software RAID)".to_string()
            },
        },
        HealthComponent {
            name: "gpu",
            state: normalize(gpu.worst),
            detail: if gpu.gpus.is_empty() {
                "no GPUs detected".to_string()
            } else if !gpu.policy_present {
                format!("{} GPU(s), no operator policy", gpu.gpus.len())
            } else {
                format!("{} GPU(s), policy active", gpu.gpus.len())
            },
        },
        HealthComponent {
            name: "cpu",
            // CPU mode is operator choice, not health — never degrade
            // the aggregate from this surface. Always reports "ok".
            state: "ok",
            detail: format!("mode = {}", cpu.mode),
        },
    ];
    let worst = worst_state(&components);
    Json(HealthResponse { worst, components })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_maps_all_known_vocabularies() {
        assert_eq!(normalize("ok"), "ok");
        assert_eq!(normalize("green"), "ok");
        assert_eq!(normalize("warn"), "warn");
        assert_eq!(normalize("yellow"), "warn");
        assert_eq!(normalize("critical"), "critical");
        assert_eq!(normalize("red"), "critical");
        assert_eq!(normalize("unknown"), "unknown");
        assert_eq!(normalize("something-weird"), "unknown");
    }

    #[test]
    fn worst_state_critical_dominates() {
        let comps = vec![
            HealthComponent {
                name: "a",
                state: "ok",
                detail: "".into(),
            },
            HealthComponent {
                name: "b",
                state: "critical",
                detail: "".into(),
            },
            HealthComponent {
                name: "c",
                state: "warn",
                detail: "".into(),
            },
        ];
        assert_eq!(worst_state(&comps), "critical");
    }

    #[test]
    fn worst_state_warn_above_unknown_and_ok() {
        let comps = vec![
            HealthComponent {
                name: "a",
                state: "ok",
                detail: "".into(),
            },
            HealthComponent {
                name: "b",
                state: "unknown",
                detail: "".into(),
            },
            HealthComponent {
                name: "c",
                state: "warn",
                detail: "".into(),
            },
        ];
        assert_eq!(worst_state(&comps), "warn");
    }

    #[test]
    fn worst_state_all_ok_is_ok() {
        let comps = vec![
            HealthComponent {
                name: "a",
                state: "ok",
                detail: "".into(),
            },
            HealthComponent {
                name: "b",
                state: "ok",
                detail: "".into(),
            },
        ];
        assert_eq!(worst_state(&comps), "ok");
    }
}
