//! `GET /v1/dashboards` — operator-pull discovery surface for the
//! 22 operator-named dashboard view presets shipped under MS043 UX
//! batch 12 (PWA-side preset selector) + batch 13/14 (daemon-side
//! persistence + sync) + batch 17 (5→20 expansion fulfilling the
//! operator's verbatim "20 dashboards" target) + batch 18 (+2 IPS-
//! dectet presets bridging the SDD-065..074 enforcement work into
//! the preset menu).
//!
//! Verbatim operator direction (2026-05-19, sacrosanct):
//!
//! > "there is over 20 dashboards and a main one and everything can
//! >  be turned on and off and there are also a tons of modes and
//! >  profiles."
//!
//! The dashboard is one PWA today; the 22 operator-named view presets
//! act as distinct dashboards within that PWA. This route makes the
//! preset catalog discoverable so:
//!   - CLI: `selfdefctl dashboards` lists them
//!   - MCP: an external `claude-code` client lists them as tools
//!   - Future: distinct URL paths (`/dashboard-secops/`,
//!     `/dashboard-perf/`, etc.) consume the same catalog
//!
//! Source of truth: this file. The dashboard PWA's `PRESETS` table
//! in `dashboard/app.js` must stay byte-identical to the names +
//! refresh_rate + tab values here; L1-api-endpoints + L2 catalog
//! parity checks (future) enforce that.

use axum::Json;
use serde::Serialize;

/// One operator-named dashboard view preset. Holds builtin
/// `&'static str` data zero-copy via the internal `BuiltinEntry`;
/// the response shape uses owned `String` so operator-defined
/// custom presets (loaded from dashboard-prefs.toml at request
/// time) can be mixed in.
#[derive(Debug, Serialize)]
pub(crate) struct DashboardEntry {
    /// Machine-readable name (matches the active_preset enum in
    /// /v1/dashboard-prefs).
    pub name: String,
    /// One-line operator-readable label.
    pub label: String,
    /// Longer description of what the preset shows.
    pub description: String,
    /// The active tab the preset switches to (one of the 8 SDD-056
    /// tabs + "all" pseudo-tab).
    pub active_tab: String,
    /// The refresh rate the preset selects.
    pub refresh_rate: String,
    /// Approximate number of panels visible (16 minus hidden). For
    /// discovery-tier reporting only; the actual visible set is in
    /// the dashboard's PRESETS table.
    pub visible_panel_count: u8,
    /// **MS043 UX batch 20** — provenance marker so operator UI can
    /// render builtin and custom presets differently (lock icon,
    /// editability gate, etc.). One of `"builtin"` or `"custom"`.
    pub origin: &'static str,
}

/// Internal compile-time representation of a builtin preset. Stays
/// `&'static str` to keep the const table zero-alloc.
#[derive(Debug)]
struct BuiltinEntry {
    name: &'static str,
    label: &'static str,
    description: &'static str,
    active_tab: &'static str,
    refresh_rate: &'static str,
    visible_panel_count: u8,
}

/// Response envelope for `GET /v1/dashboards`.
#[derive(Debug, Serialize)]
pub(crate) struct DashboardsBody {
    /// Total number of preset entries shipped (builtins + customs).
    pub count: usize,
    /// Number of builtin presets — stable; today 22.
    pub builtin_count: usize,
    /// Number of operator-defined custom presets — variable per
    /// operator's `dashboard-prefs.toml`.
    pub custom_count: usize,
    /// Operator-readable note about the multi-dashboard architecture.
    pub note: &'static str,
    /// Sorted by name (builtins + customs interleaved alphabetically).
    pub dashboards: Vec<DashboardEntry>,
}

const DASHBOARDS: &[BuiltinEntry] = &[
    BuiltinEntry {
        name: "audit-trail",
        label: "Audit trail",
        description: "Audit chains + alerts + logs tab focus; slow refresh — operator-pull forensic posture.",
        active_tab: "logs",
        refresh_rate: "slow",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "compact",
        label: "Compact",
        description: "Always-visible strip only (composite health + 4 watchdogs + alerts). Smallest footprint; slow refresh.",
        active_tab: "all",
        refresh_rate: "slow",
        visible_panel_count: 6,
    },
    BuiltinEntry {
        name: "cpu-bound",
        label: "CPU bound",
        description: "CPU + hardware + composite health. For operators investigating compute saturation; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "default",
        label: "Default",
        description: "All 16 panels visible, no specific tab focus, normal refresh. The catch-all view.",
        active_tab: "all",
        refresh_rate: "normal",
        visible_panel_count: 16,
    },
    BuiltinEntry {
        name: "gpu-monitor",
        label: "GPU monitor",
        description: "GPU + CPU + flex-profile + composite health. For inference / compute workloads; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 4,
    },
    BuiltinEntry {
        name: "health-only",
        label: "Health only",
        description: "Composite-health panel alone. Smallest footprint; slow refresh — first-glance heartbeat.",
        active_tab: "all",
        refresh_rate: "slow",
        visible_panel_count: 1,
    },
    BuiltinEntry {
        name: "incident-response",
        label: "Incident response",
        description: "4 watchdogs + alerts + audit chains + logs tab focus; fast refresh — for active-incident triage.",
        active_tab: "logs",
        refresh_rate: "fast",
        visible_panel_count: 7,
    },
    BuiltinEntry {
        name: "inference",
        label: "Inference",
        description: "Composite health + inference backends + GPU + flex profile. Models tab focus; normal refresh.",
        active_tab: "models",
        refresh_rate: "normal",
        visible_panel_count: 4,
    },
    BuiltinEntry {
        name: "inference-throughput",
        label: "Inference throughput",
        description: "Inference backends + GPU + flex-profile + composite health + CPU; fast refresh — tuning hot path.",
        active_tab: "models",
        refresh_rate: "fast",
        visible_panel_count: 5,
    },
    BuiltinEntry {
        name: "ips-dectet-incident",
        label: "IPS dectet — incident drill-down",
        description: "All 10 IPS-dectet enforcement primitives (SDD-065 blockset / 066 quarantine / 067 revocations / 068 token-revocations / 069 mfa-grant-revocations / 070 netns-isolations / 071 mount-bindings / 072 process-tree-freezes / 073 socket-fd-revocations / 074 env-scrubs) + composite health + alerts. Logs tab focus; fast refresh — for live incident response when one or more IPS primitives is actively engaged.",
        active_tab: "logs",
        refresh_rate: "fast",
        visible_panel_count: 12,
    },
    BuiltinEntry {
        name: "ips-dectet-overview",
        label: "IPS dectet — enforcement overview",
        description: "Compact view of the IPS-dectet enforcement layer — 10 primitives' active/pending counts in rollup form + composite health. Profiles tab focus (or 'all' for full strip); normal refresh — operator-pull defensive-posture review without incident-mode urgency.",
        active_tab: "profiles",
        refresh_rate: "normal",
        visible_panel_count: 11,
    },
    BuiltinEntry {
        name: "mcp-debug",
        label: "MCP debug",
        description: "MCP tab focus + alerts + logs; normal refresh — diagnosing external client problems.",
        active_tab: "mcp",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "mcp-tools",
        label: "MCP tools",
        description: "MCP + modules + alerts; normal refresh — managing tool-side rollout.",
        active_tab: "mcp",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "models-lab",
        label: "Models lab",
        description: "Models tab focus + inference backends + GPU; normal refresh — model evaluation / swap workflow.",
        active_tab: "models",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "module-status",
        label: "Module status",
        description: "Modules + profiles tabs focus + composite health; slow refresh — reviewing apply/check drift.",
        active_tab: "modules",
        refresh_rate: "slow",
        visible_panel_count: 2,
    },
    BuiltinEntry {
        name: "network-ops",
        label: "Network ops",
        description: "Network + storage + RAID + composite health; network tab focus; normal refresh.",
        active_tab: "network",
        refresh_rate: "normal",
        visible_panel_count: 4,
    },
    BuiltinEntry {
        name: "paused-snapshot",
        label: "Paused snapshot",
        description: "All panels visible BUT refresh paused. Operator-driven one-shot inspection without polling load.",
        active_tab: "all",
        refresh_rate: "paused",
        visible_panel_count: 16,
    },
    BuiltinEntry {
        name: "performance",
        label: "Performance",
        description: "Hardware + network + storage + RAID + GPU + CPU + composite health. Hardware tab focus; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 7,
    },
    BuiltinEntry {
        name: "repl-session",
        label: "REPL session",
        description: "REPL tab focus + composite health + alerts; normal refresh — for interactive operator sessions.",
        active_tab: "repl",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "security",
        label: "Security",
        description: "Composite health + 4 watchdogs + alerts + audit chains. Logs tab focus; normal refresh.",
        active_tab: "logs",
        refresh_rate: "normal",
        visible_panel_count: 7,
    },
    BuiltinEntry {
        name: "storage-ops",
        label: "Storage ops",
        description: "Storage + RAID + composite health; normal refresh — disk / RAID maintenance posture.",
        active_tab: "all",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    BuiltinEntry {
        name: "watchdog-deep",
        label: "Watchdog deep",
        description: "All four watchdogs (friction-audit + perimeter + guardian + scheduler) + composite health; fast refresh.",
        active_tab: "all",
        refresh_rate: "fast",
        visible_panel_count: 5,
    },
];

pub(crate) async fn show() -> Json<DashboardsBody> {
    Json(build_body(
        crate::dashboard_prefs::read_custom_presets_for_discovery(),
    ))
}

/// **MS043 UX batch 20** — pure helper that builds the discovery body
/// from a given custom-preset list. Tests pass a controlled vec;
/// `show()` reads from disk.
pub(crate) fn build_body(customs: Vec<crate::dashboard_prefs::CustomPreset>) -> DashboardsBody {
    let mut dashboards: Vec<DashboardEntry> = DASHBOARDS
        .iter()
        .map(|d| DashboardEntry {
            name: d.name.to_string(),
            label: d.label.to_string(),
            description: d.description.to_string(),
            active_tab: d.active_tab.to_string(),
            refresh_rate: d.refresh_rate.to_string(),
            visible_panel_count: d.visible_panel_count,
            origin: "builtin",
        })
        .collect();
    let builtin_count = dashboards.len();
    let custom_count = customs.len();
    for cp in customs {
        let visible_panel_count = TOTAL_PANELS.saturating_sub(cp.hidden_panels.len() as u8);
        let description = format!(
            "Operator-defined custom preset. Hides {} panel(s). [origin=custom]",
            cp.hidden_panels.len()
        );
        dashboards.push(DashboardEntry {
            name: cp.name,
            label: cp.label,
            description,
            active_tab: cp.active_tab,
            refresh_rate: cp.refresh_rate,
            visible_panel_count,
            origin: "custom",
        });
    }
    // Sort merged list by name so operator UI sees a stable alphabetical
    // order regardless of how many customs the operator has defined.
    dashboards.sort_by(|a, b| a.name.cmp(&b.name));

    DashboardsBody {
        count: dashboards.len(),
        builtin_count,
        custom_count,
        note: "22 builtin operator-named view presets within the single PWA (5 original + 15 batch-17 expansion + 2 batch-18 IPS-dectet) plus operator-defined custom presets from dashboard-prefs.toml (MS043 batch 20). Operator-pull deep-link: /dashboard/#preset=<name>. Customs carry origin=\"custom\" so operator UI can render them differently; builtins carry origin=\"builtin\".",
        dashboards,
    }
}

/// Total panel count in the dashboard PWA. Used to compute
/// `visible_panel_count = TOTAL_PANELS - hidden_panels.len()` for
/// custom presets surfaced via `GET /v1/dashboards`.
const TOTAL_PANELS: u8 = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboards_table_has_22_entries() {
        assert_eq!(DASHBOARDS.len(), 22);
    }

    #[test]
    fn dashboards_table_names_match_pwa_presets() {
        // These names MUST stay byte-identical to the keys of the
        // PRESETS table in `dashboard/app.js`. The dashboard's PUT
        // /v1/dashboard-prefs validator rejects any other value.
        let names: Vec<&str> = DASHBOARDS.iter().map(|d| d.name).collect();
        let expected = vec![
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
        assert_eq!(names, expected);
    }

    #[test]
    fn dashboards_refresh_rates_are_valid_enum() {
        // Refresh rates must be one of the 4 documented in SDD-060.
        let valid = ["fast", "normal", "slow", "paused"];
        for d in DASHBOARDS {
            assert!(
                valid.contains(&d.refresh_rate),
                "{} has invalid refresh_rate {}",
                d.name,
                d.refresh_rate
            );
        }
    }

    #[test]
    fn dashboards_tabs_are_one_of_eight_plus_all() {
        // Tabs must match SDD-056 § 8-tab specification + "all" pseudo.
        let valid = [
            "all", "models", "modules", "profiles", "hardware", "network", "logs", "mcp", "repl",
        ];
        for d in DASHBOARDS {
            assert!(
                valid.contains(&d.active_tab),
                "{} has invalid active_tab {}",
                d.name,
                d.active_tab
            );
        }
    }

    #[test]
    fn dashboards_panel_counts_are_plausible() {
        for d in DASHBOARDS {
            assert!(
                d.visible_panel_count <= 16,
                "{} claims more than 16 visible panels",
                d.name
            );
            assert!(
                d.visible_panel_count > 0,
                "{} claims zero visible panels",
                d.name
            );
        }
    }

    #[test]
    fn default_preset_shows_all_panels() {
        let default = DASHBOARDS.iter().find(|d| d.name == "default").unwrap();
        assert_eq!(default.visible_panel_count, 16);
        assert_eq!(default.refresh_rate, "normal");
    }

    // ─────────────── MS043 UX batch 20 — custom-preset merge tests ───────────────

    use crate::dashboard_prefs::{CustomPreset, read_custom_presets_at};

    #[test]
    fn build_body_returns_22_builtins_with_origin_marker_when_no_customs() {
        let body = build_body(vec![]);
        assert_eq!(body.count, 22);
        assert_eq!(body.builtin_count, 22);
        assert_eq!(body.custom_count, 0);
        for d in &body.dashboards {
            assert_eq!(d.origin, "builtin", "preset {} should be builtin", d.name);
        }
    }

    #[test]
    fn build_body_merges_customs_alphabetically() {
        let customs = vec![
            CustomPreset {
                name: "my-view".into(),
                label: "My custom view".into(),
                hidden_panels: vec!["raid-section".into(), "storage-section".into()],
                refresh_rate: "fast".into(),
                active_tab: "logs".into(),
            },
            CustomPreset {
                name: "ops-view".into(),
                label: "Ops view".into(),
                hidden_panels: vec!["mcp-section".into()],
                refresh_rate: "slow".into(),
                active_tab: "modules".into(),
            },
        ];
        let body = build_body(customs);
        assert_eq!(body.builtin_count, 22);
        assert_eq!(body.custom_count, 2);
        assert_eq!(body.count, 24);

        // Customs interleaved alphabetically with builtins.
        let my_view = body
            .dashboards
            .iter()
            .find(|d| d.name == "my-view")
            .unwrap();
        assert_eq!(my_view.origin, "custom");
        assert_eq!(my_view.label, "My custom view");
        assert_eq!(my_view.refresh_rate, "fast");
        assert_eq!(my_view.active_tab, "logs");
        // visible_panel_count = 16 - 2 hidden
        assert_eq!(my_view.visible_panel_count, 14);

        let ops_view = body
            .dashboards
            .iter()
            .find(|d| d.name == "ops-view")
            .unwrap();
        assert_eq!(ops_view.origin, "custom");
        assert_eq!(ops_view.visible_panel_count, 15);

        // Sort order: module-status < my-view < network-ops < ops-view
        let names: Vec<&str> = body.dashboards.iter().map(|d| d.name.as_str()).collect();
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(pos("module-status") < pos("my-view"));
        assert!(pos("my-view") < pos("network-ops"));
        assert!(pos("network-ops") < pos("ops-view"));
    }

    #[test]
    fn read_custom_presets_at_returns_empty_for_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nope.toml");
        let customs = read_custom_presets_at(&path);
        assert!(customs.is_empty());
    }

    #[test]
    fn read_custom_presets_at_loads_two_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("prefs.toml");
        std::fs::write(
            &path,
            r#"
schema_version = "1.0.0"
hidden_panels = []
refresh_rate = "normal"
active_preset = "default"
updated_at_ms = 0

[[custom_presets]]
name = "alpha"
label = "Alpha"
hidden_panels = ["mcp-section"]
refresh_rate = "fast"
active_tab = "logs"

[[custom_presets]]
name = "beta"
label = "Beta"
hidden_panels = []
refresh_rate = "slow"
active_tab = "all"
"#,
        )
        .unwrap();
        let customs = read_custom_presets_at(&path);
        assert_eq!(customs.len(), 2);
        assert_eq!(customs[0].name, "alpha");
        assert_eq!(customs[0].active_tab, "logs");
        assert_eq!(customs[1].name, "beta");
        assert_eq!(customs[1].refresh_rate, "slow");
    }
}
