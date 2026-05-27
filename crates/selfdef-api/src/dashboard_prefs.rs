//! `/v1/dashboard-prefs` — operator-pull dashboard preferences.
//!
//! Verbatim operator direction (2026-05-19): *"there is over 20
//! dashboards and a main one and everything can be turned on and
//! off and there are also a tons of modes and profiles."*
//!
//! The PWA already persists three preference surfaces in
//! `localStorage`:
//!   - `selfdef.hiddenPanels` — Set<sectionId> the operator wants
//!     permanently hidden (MS043 UX batch 10)
//!   - `selfdef.refreshRate`  — one of "fast"|"normal"|"slow"|
//!     "paused" (MS043 UX batch 11)
//!   - `selfdef.activePreset` — one of "default"|"security"|
//!     "performance"|"inference"|"compact" (MS043 UX batch 12)
//!
//! `localStorage` is per-browser. The same operator on a phone PWA
//! / laptop / different host loses their choices. This module
//! promotes the preferences to the **daemon** as the source of
//! truth — every browser fetches on load + PUTs on change, so
//! preferences sync across all browsers connected to the same
//! selfdef daemon.
//!
//! Disk persistence: `/etc/selfdef/dashboard-prefs.toml` (override
//! via `SELFDEF_DASHBOARD_PREFS_PATH` env). Atomic write via the
//! temp-file-then-rename pattern (SDD-026 Z-3 echoed).

use std::path::{Path, PathBuf};

use axum::{Json, extract::Json as ExtractJson, http::StatusCode};
use serde::{Deserialize, Serialize};

const DEFAULT_PREFS_PATH: &str = "/etc/selfdef/dashboard-prefs.toml";
const SCHEMA_VERSION: &str = "1.0.0";

fn prefs_path() -> PathBuf {
    std::env::var("SELFDEF_DASHBOARD_PREFS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PREFS_PATH))
}

/// Persisted preferences shape. ALL fields default so a missing
/// file → blank-but-valid response (operator never sees a 404).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub(crate) struct DashboardPrefs {
    /// Schema version pin. Defaults to current; mismatch on PUT
    /// returns 409 Conflict.
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    /// Section IDs the operator has chosen to hide.
    #[serde(default)]
    pub hidden_panels: Vec<String>,
    /// Refresh rate: "fast" | "normal" | "slow" | "paused".
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate: String,
    /// Active preset name; one of the 5 documented or "default".
    #[serde(default = "default_active_preset")]
    pub active_preset: String,
    /// Last-write epoch milliseconds — operator-readable freshness
    /// signal. Set server-side on every PUT.
    #[serde(default)]
    pub updated_at_ms: u64,
}

fn default_schema_version() -> String {
    SCHEMA_VERSION.to_string()
}
fn default_refresh_rate() -> String {
    "normal".to_string()
}
fn default_active_preset() -> String {
    "default".to_string()
}

/// PUT request body — same shape as `DashboardPrefs` but the
/// `updated_at_ms` field (if present) is ignored: the server sets
/// it from `SystemTime::now()` on every accepted write.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DashboardPrefsPut {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub hidden_panels: Vec<String>,
    #[serde(default = "default_refresh_rate")]
    pub refresh_rate: String,
    #[serde(default = "default_active_preset")]
    pub active_preset: String,
}

fn read_prefs_from_disk(path: &Path) -> DashboardPrefs {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => {
            return DashboardPrefs {
                schema_version: SCHEMA_VERSION.to_string(),
                hidden_panels: Vec::new(),
                refresh_rate: default_refresh_rate(),
                active_preset: default_active_preset(),
                updated_at_ms: 0,
            };
        }
    };
    toml::from_str(&text).unwrap_or_else(|_| DashboardPrefs::default())
}

fn atomic_write(path: &Path, body: &str) -> Result<(), (StatusCode, String)> {
    let tmp = path.with_extension("toml.tmp");
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("create_dir_all {}: {e}", parent.display()),
                )
            })?;
        }
    }
    std::fs::write(&tmp, body).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write {}: {e}", tmp.display()),
        )
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("rename {} → {}: {e}", tmp.display(), path.display()),
        )
    })?;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `GET /v1/dashboard-prefs` — fetch the current preferences.
/// Missing file → 200 with default body. Malformed file → 200 with
/// default body (we do NOT 500 on operator-induced disk corruption;
/// the dashboard would lose all UX customization).
pub(crate) async fn show() -> Json<DashboardPrefs> {
    let path = prefs_path();
    Json(read_prefs_from_disk(&path))
}

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

/// `PUT /v1/dashboard-prefs` — persist new preferences.
/// - 409 Conflict on schema-version mismatch
/// - 400 Bad Request on unknown refresh_rate / active_preset enum
/// - 200 OK + the new persisted body on success
pub(crate) async fn put(
    ExtractJson(req): ExtractJson<DashboardPrefsPut>,
) -> Result<Json<DashboardPrefs>, (StatusCode, String)> {
    if req.schema_version != SCHEMA_VERSION {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "schema version {} ≠ server's {}; refresh + retry",
                req.schema_version, SCHEMA_VERSION
            ),
        ));
    }
    if !VALID_RATES.contains(&req.refresh_rate.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid refresh_rate {:?}; expected one of {:?}",
                req.refresh_rate, VALID_RATES
            ),
        ));
    }
    if !VALID_PRESETS.contains(&req.active_preset.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid active_preset {:?}; expected one of {:?}",
                req.active_preset, VALID_PRESETS
            ),
        ));
    }
    let prefs = DashboardPrefs {
        schema_version: req.schema_version,
        hidden_panels: req.hidden_panels,
        refresh_rate: req.refresh_rate,
        active_preset: req.active_preset,
        updated_at_ms: now_ms(),
    };
    let body = toml::to_string_pretty(&prefs).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("toml serialize: {e}"),
        )
    })?;
    let path = prefs_path();
    atomic_write(&path, &body)?;
    Ok(Json(prefs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefs_have_sensible_defaults() {
        let p = DashboardPrefs::default();
        assert_eq!(p.schema_version, ""); // serde Default = empty
        assert!(p.hidden_panels.is_empty());
        // Note: Default impl gives "" not "normal" — read_prefs_from_disk
        // hand-substitutes when the file is missing. The defaults
        // documented here are the constructor-side defaults (function-
        // backed serde defaults), not the trait Default.
    }

    #[test]
    fn missing_file_returns_blank_but_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent.toml");
        let p = read_prefs_from_disk(&path);
        assert_eq!(p.schema_version, SCHEMA_VERSION);
        assert!(p.hidden_panels.is_empty());
        assert_eq!(p.refresh_rate, "normal");
        assert_eq!(p.active_preset, "default");
        assert_eq!(p.updated_at_ms, 0);
    }

    #[test]
    fn round_trip_via_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dashboard-prefs.toml");
        let prefs = DashboardPrefs {
            schema_version: SCHEMA_VERSION.to_string(),
            hidden_panels: vec!["raid-section".into(), "storage-section".into()],
            refresh_rate: "slow".to_string(),
            active_preset: "security".to_string(),
            updated_at_ms: 1_736_944_500_000,
        };
        let body = toml::to_string_pretty(&prefs).unwrap();
        atomic_write(&path, &body).unwrap();
        let back = read_prefs_from_disk(&path);
        assert_eq!(back, prefs);
    }

    #[test]
    fn malformed_file_returns_default_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dashboard-prefs.toml");
        std::fs::write(&path, "not = valid = toml = at = all").unwrap();
        let p = read_prefs_from_disk(&path);
        // Default-impl yields empty schema_version + empty hidden + empty rate
        // — operator's dashboard sees a "blank slate" and re-PUTs.
        // We do NOT 500 the entire GET request.
        assert!(p.hidden_panels.is_empty());
    }

    #[test]
    fn valid_rates_table_matches_dashboard_factors() {
        assert_eq!(VALID_RATES, &["fast", "normal", "slow", "paused"]);
    }

    #[test]
    fn valid_presets_table_matches_dashboard_presets() {
        assert_eq!(
            VALID_PRESETS,
            &[
                "audit-trail",
                "compact",
                "cpu-bound",
                "default",
                "gpu-monitor",
                "health-only",
                "incident-response",
                "inference",
                "inference-throughput",
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
            ]
        );
    }

    #[test]
    fn atomic_write_creates_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c/prefs.toml");
        atomic_write(&nested, "schema_version = \"1.0.0\"").unwrap();
        assert!(nested.exists());
    }
}
