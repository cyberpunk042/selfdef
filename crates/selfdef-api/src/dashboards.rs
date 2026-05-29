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

/// One operator-named dashboard view preset.
#[derive(Debug, Serialize)]
pub(crate) struct DashboardEntry {
    /// Machine-readable name (matches the active_preset enum in
    /// /v1/dashboard-prefs).
    pub name: &'static str,
    /// One-line operator-readable label.
    pub label: &'static str,
    /// Longer description of what the preset shows.
    pub description: &'static str,
    /// The active tab the preset switches to (one of the 8 SDD-056
    /// tabs + "all" pseudo-tab).
    pub active_tab: &'static str,
    /// The refresh rate the preset selects.
    pub refresh_rate: &'static str,
    /// Approximate number of panels visible (16 minus hidden). For
    /// discovery-tier reporting only; the actual visible set is in
    /// the dashboard's PRESETS table.
    pub visible_panel_count: u8,
}

/// Response envelope for `GET /v1/dashboards`.
#[derive(Debug, Serialize)]
pub(crate) struct DashboardsBody {
    /// Total number of preset entries shipped.
    pub count: usize,
    /// Operator-readable note about the multi-dashboard architecture.
    pub note: &'static str,
    /// Sorted by name.
    pub dashboards: Vec<DashboardEntry>,
}

const DASHBOARDS: &[DashboardEntry] = &[
    DashboardEntry {
        name: "audit-trail",
        label: "Audit trail",
        description: "Audit chains + alerts + logs tab focus; slow refresh — operator-pull forensic posture.",
        active_tab: "logs",
        refresh_rate: "slow",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "compact",
        label: "Compact",
        description: "Always-visible strip only (composite health + 4 watchdogs + alerts). Smallest footprint; slow refresh.",
        active_tab: "all",
        refresh_rate: "slow",
        visible_panel_count: 6,
    },
    DashboardEntry {
        name: "cpu-bound",
        label: "CPU bound",
        description: "CPU + hardware + composite health. For operators investigating compute saturation; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "default",
        label: "Default",
        description: "All 16 panels visible, no specific tab focus, normal refresh. The catch-all view.",
        active_tab: "all",
        refresh_rate: "normal",
        visible_panel_count: 16,
    },
    DashboardEntry {
        name: "gpu-monitor",
        label: "GPU monitor",
        description: "GPU + CPU + flex-profile + composite health. For inference / compute workloads; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 4,
    },
    DashboardEntry {
        name: "health-only",
        label: "Health only",
        description: "Composite-health panel alone. Smallest footprint; slow refresh — first-glance heartbeat.",
        active_tab: "all",
        refresh_rate: "slow",
        visible_panel_count: 1,
    },
    DashboardEntry {
        name: "incident-response",
        label: "Incident response",
        description: "4 watchdogs + alerts + audit chains + logs tab focus; fast refresh — for active-incident triage.",
        active_tab: "logs",
        refresh_rate: "fast",
        visible_panel_count: 7,
    },
    DashboardEntry {
        name: "inference",
        label: "Inference",
        description: "Composite health + inference backends + GPU + flex profile. Models tab focus; normal refresh.",
        active_tab: "models",
        refresh_rate: "normal",
        visible_panel_count: 4,
    },
    DashboardEntry {
        name: "inference-throughput",
        label: "Inference throughput",
        description: "Inference backends + GPU + flex-profile + composite health + CPU; fast refresh — tuning hot path.",
        active_tab: "models",
        refresh_rate: "fast",
        visible_panel_count: 5,
    },
    DashboardEntry {
        name: "ips-dectet-incident",
        label: "IPS dectet — incident drill-down",
        description: "All 10 IPS-dectet enforcement primitives (SDD-065 blockset / 066 quarantine / 067 revocations / 068 token-revocations / 069 mfa-grant-revocations / 070 netns-isolations / 071 mount-bindings / 072 process-tree-freezes / 073 socket-fd-revocations / 074 env-scrubs) + composite health + alerts. Logs tab focus; fast refresh — for live incident response when one or more IPS primitives is actively engaged.",
        active_tab: "logs",
        refresh_rate: "fast",
        visible_panel_count: 12,
    },
    DashboardEntry {
        name: "ips-dectet-overview",
        label: "IPS dectet — enforcement overview",
        description: "Compact view of the IPS-dectet enforcement layer — 10 primitives' active/pending counts in rollup form + composite health. Profiles tab focus (or 'all' for full strip); normal refresh — operator-pull defensive-posture review without incident-mode urgency.",
        active_tab: "profiles",
        refresh_rate: "normal",
        visible_panel_count: 11,
    },
    DashboardEntry {
        name: "mcp-debug",
        label: "MCP debug",
        description: "MCP tab focus + alerts + logs; normal refresh — diagnosing external client problems.",
        active_tab: "mcp",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "mcp-tools",
        label: "MCP tools",
        description: "MCP + modules + alerts; normal refresh — managing tool-side rollout.",
        active_tab: "mcp",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "models-lab",
        label: "Models lab",
        description: "Models tab focus + inference backends + GPU; normal refresh — model evaluation / swap workflow.",
        active_tab: "models",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "module-status",
        label: "Module status",
        description: "Modules + profiles tabs focus + composite health; slow refresh — reviewing apply/check drift.",
        active_tab: "modules",
        refresh_rate: "slow",
        visible_panel_count: 2,
    },
    DashboardEntry {
        name: "network-ops",
        label: "Network ops",
        description: "Network + storage + RAID + composite health; network tab focus; normal refresh.",
        active_tab: "network",
        refresh_rate: "normal",
        visible_panel_count: 4,
    },
    DashboardEntry {
        name: "paused-snapshot",
        label: "Paused snapshot",
        description: "All panels visible BUT refresh paused. Operator-driven one-shot inspection without polling load.",
        active_tab: "all",
        refresh_rate: "paused",
        visible_panel_count: 16,
    },
    DashboardEntry {
        name: "performance",
        label: "Performance",
        description: "Hardware + network + storage + RAID + GPU + CPU + composite health. Hardware tab focus; fast refresh.",
        active_tab: "hardware",
        refresh_rate: "fast",
        visible_panel_count: 7,
    },
    DashboardEntry {
        name: "repl-session",
        label: "REPL session",
        description: "REPL tab focus + composite health + alerts; normal refresh — for interactive operator sessions.",
        active_tab: "repl",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "security",
        label: "Security",
        description: "Composite health + 4 watchdogs + alerts + audit chains. Logs tab focus; normal refresh.",
        active_tab: "logs",
        refresh_rate: "normal",
        visible_panel_count: 7,
    },
    DashboardEntry {
        name: "storage-ops",
        label: "Storage ops",
        description: "Storage + RAID + composite health; normal refresh — disk / RAID maintenance posture.",
        active_tab: "all",
        refresh_rate: "normal",
        visible_panel_count: 3,
    },
    DashboardEntry {
        name: "watchdog-deep",
        label: "Watchdog deep",
        description: "All four watchdogs (friction-audit + perimeter + guardian + scheduler) + composite health; fast refresh.",
        active_tab: "all",
        refresh_rate: "fast",
        visible_panel_count: 5,
    },
];

pub(crate) async fn show() -> Json<DashboardsBody> {
    let dashboards: Vec<DashboardEntry> = DASHBOARDS
        .iter()
        .map(|d| DashboardEntry {
            name: d.name,
            label: d.label,
            description: d.description,
            active_tab: d.active_tab,
            refresh_rate: d.refresh_rate,
            visible_panel_count: d.visible_panel_count,
        })
        .collect();
    Json(DashboardsBody {
        count: dashboards.len(),
        note: "22 operator-named view presets within the single PWA (5 original + 15 batch-17 expansion + 2 batch-18 IPS-dectet presets bridging SDD-065..074 enforcement work). Operator-pull deep-link: /dashboard/#preset=<name>. Distinct URL paths per dashboard is the Stage-2 arc; the 22 presets fulfill the operator's verbatim 'over 20 dashboards' target via the visibility+refresh+preset triad.",
        dashboards,
    })
}

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
}
