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
    /// Active preset name. Either a builtin (one of the 22 documented
    /// in `VALID_PRESETS`) or a custom-preset name appearing in
    /// `custom_presets[].name`.
    #[serde(default = "default_active_preset")]
    pub active_preset: String,
    /// **MS043 UX batch 19** — operator-defined custom presets,
    /// addressing the verbatim "endless configurations and options
    /// and personalization's" standing direction. Each entry is a
    /// fully-formed preset the operator named themselves; appears
    /// alongside the 22 builtins in `GET /v1/dashboards` and is
    /// selectable as `active_preset`. Validated for name-format,
    /// non-collision with builtins, and refresh_rate / active_tab
    /// enum membership.
    #[serde(default)]
    pub custom_presets: Vec<CustomPreset>,
    /// Last-write epoch milliseconds — operator-readable freshness
    /// signal. Set server-side on every PUT.
    #[serde(default)]
    pub updated_at_ms: u64,
}

/// **MS043 UX batch 19** — operator-defined custom preset row. Mirror
/// of the daemon-side `DashboardEntry` builtin shape, but
/// operator-mutable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct CustomPreset {
    /// Machine-readable name. Must match `^[a-z0-9-]{3,32}$` and
    /// must not collide with any builtin in `VALID_PRESETS`.
    pub name: String,
    /// Operator-readable label (1..64 chars).
    pub label: String,
    /// Section IDs to hide for this preset.
    #[serde(default)]
    pub hidden_panels: Vec<String>,
    /// Refresh rate: one of `VALID_RATES`.
    pub refresh_rate: String,
    /// Active tab: one of the 8 SDD-056 tabs + "all".
    pub active_tab: String,
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
    /// MS043 UX batch 19 — operator-defined custom presets sent
    /// alongside the rest of the prefs in a single PUT. The
    /// server validates each + persists atomically with the rest.
    #[serde(default)]
    pub custom_presets: Vec<CustomPreset>,
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
                custom_presets: Vec::new(),
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

/// **MS043 UX batch 20** — sibling-module helper for `dashboards::show()`
/// to merge operator-defined custom presets into the `GET /v1/dashboards`
/// discovery response. Returns a flat `Vec<CustomPreset>` from the
/// operator's on-disk prefs, or an empty vec if the file is
/// missing/malformed (operator UI never sees an error here — degrades
/// gracefully to builtin-only).
pub(crate) fn read_custom_presets_for_discovery() -> Vec<CustomPreset> {
    read_custom_presets_at(&prefs_path())
}

/// Test-and-prod helper: reads custom presets from a specific
/// path. Used by `dashboards::show()` via `prefs_path()` in prod,
/// and directly by unit tests that need to control the file.
pub(crate) fn read_custom_presets_at(path: &Path) -> Vec<CustomPreset> {
    read_prefs_from_disk(path).custom_presets
}

const VALID_RATES: &[&str] = &["fast", "normal", "slow", "paused"];
/// SDD-056 § 8-tab specification + "all" pseudo-tab. Mirrors the
/// `dashboards_tabs_are_one_of_eight_plus_all` test in dashboards.rs.
const VALID_TABS: &[&str] = &[
    "all", "models", "modules", "profiles", "hardware", "network", "logs", "mcp", "repl",
];
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

/// MS043 UX batch 19 — validate a single CustomPreset row.
fn validate_custom_preset(cp: &CustomPreset) -> Result<(), String> {
    // Name format: ^[a-z0-9-]{3,32}$
    let n = cp.name.as_str();
    if !(3..=32).contains(&n.len()) {
        return Err(format!(
            "custom preset name {n:?} length must be 3..=32 chars"
        ));
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!("custom preset name {n:?} must match ^[a-z0-9-]+$"));
    }
    if n.starts_with('-') || n.ends_with('-') {
        return Err(format!(
            "custom preset name {n:?} must not start or end with '-'"
        ));
    }
    // Collision check: operator can't shadow a builtin.
    if VALID_PRESETS.contains(&n) {
        return Err(format!(
            "custom preset name {n:?} collides with a builtin; choose a different name"
        ));
    }
    // Label sanity.
    if cp.label.is_empty() || cp.label.len() > 64 {
        return Err(format!(
            "custom preset {n:?} label must be 1..=64 chars (got {})",
            cp.label.len()
        ));
    }
    // Refresh rate + tab enum membership.
    if !VALID_RATES.contains(&cp.refresh_rate.as_str()) {
        return Err(format!(
            "custom preset {n:?} has invalid refresh_rate {:?}; expected one of {:?}",
            cp.refresh_rate, VALID_RATES
        ));
    }
    if !VALID_TABS.contains(&cp.active_tab.as_str()) {
        return Err(format!(
            "custom preset {n:?} has invalid active_tab {:?}; expected one of {:?}",
            cp.active_tab, VALID_TABS
        ));
    }
    Ok(())
}

/// `PUT /v1/dashboard-prefs` — persist new preferences.
/// - 409 Conflict on schema-version mismatch
/// - 400 Bad Request on unknown refresh_rate / active_preset enum,
///   or on any invalid custom_preset (name format, collision with
///   builtin, duplicate name within request, bad refresh_rate / tab)
/// - 200 OK + the new persisted body on success
pub(crate) async fn put(
    _cap: crate::control::RequireControl,
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
    // MS043 batch 19 — validate each custom preset individually.
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for cp in &req.custom_presets {
        if !seen_names.insert(cp.name.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("duplicate custom preset name {:?} within request", cp.name),
            ));
        }
        validate_custom_preset(cp).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }
    // active_preset can be a builtin OR a custom preset name from
    // THIS request (so operator can create-and-select atomically).
    let is_builtin = VALID_PRESETS.contains(&req.active_preset.as_str());
    let is_custom = req
        .custom_presets
        .iter()
        .any(|cp| cp.name == req.active_preset);
    if !is_builtin && !is_custom {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "invalid active_preset {:?}; expected one of the 22 builtins or a name from \
                 the request's custom_presets",
                req.active_preset
            ),
        ));
    }
    let prefs = DashboardPrefs {
        schema_version: req.schema_version,
        hidden_panels: req.hidden_panels,
        refresh_rate: req.refresh_rate,
        active_preset: req.active_preset,
        custom_presets: req.custom_presets,
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
            custom_presets: Vec::new(),
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

    // ─────────────── MS043 UX batch 19 — custom-preset tests ───────────────

    fn valid_custom_preset() -> CustomPreset {
        CustomPreset {
            name: "my-secops-view".into(),
            label: "My SecOps view".into(),
            hidden_panels: vec!["raid-section".into()],
            refresh_rate: "normal".into(),
            active_tab: "logs".into(),
        }
    }

    #[test]
    fn valid_custom_preset_passes() {
        assert!(validate_custom_preset(&valid_custom_preset()).is_ok());
    }

    #[test]
    fn custom_preset_name_too_short_rejected() {
        let mut cp = valid_custom_preset();
        cp.name = "ab".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("3..=32"));
    }

    #[test]
    fn custom_preset_name_too_long_rejected() {
        let mut cp = valid_custom_preset();
        cp.name = "a".repeat(33);
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("3..=32"));
    }

    #[test]
    fn custom_preset_name_uppercase_rejected() {
        let mut cp = valid_custom_preset();
        cp.name = "My-View".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("[a-z0-9-]"));
    }

    #[test]
    fn custom_preset_name_leading_dash_rejected() {
        let mut cp = valid_custom_preset();
        cp.name = "-leading".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("start or end with '-'"));
    }

    #[test]
    fn custom_preset_name_trailing_dash_rejected() {
        let mut cp = valid_custom_preset();
        cp.name = "trailing-".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("start or end with '-'"));
    }

    #[test]
    fn custom_preset_collision_with_builtin_rejected() {
        for builtin in [
            "default",
            "security",
            "ips-dectet-incident",
            "watchdog-deep",
        ] {
            let mut cp = valid_custom_preset();
            cp.name = builtin.to_string();
            let err = validate_custom_preset(&cp).unwrap_err();
            assert!(
                err.contains("collides with a builtin"),
                "expected collision error for {builtin:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn custom_preset_empty_label_rejected() {
        let mut cp = valid_custom_preset();
        cp.label = "".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("label must be"));
    }

    #[test]
    fn custom_preset_label_too_long_rejected() {
        let mut cp = valid_custom_preset();
        cp.label = "x".repeat(65);
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("label must be"));
    }

    #[test]
    fn custom_preset_invalid_refresh_rate_rejected() {
        let mut cp = valid_custom_preset();
        cp.refresh_rate = "blinky".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("invalid refresh_rate"));
    }

    #[test]
    fn custom_preset_invalid_tab_rejected() {
        let mut cp = valid_custom_preset();
        cp.active_tab = "not-a-tab".into();
        let err = validate_custom_preset(&cp).unwrap_err();
        assert!(err.contains("invalid active_tab"));
    }

    #[test]
    fn custom_preset_round_trips_via_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("prefs.toml");
        let cp = valid_custom_preset();
        let prefs = DashboardPrefs {
            schema_version: SCHEMA_VERSION.to_string(),
            hidden_panels: vec![],
            refresh_rate: "normal".into(),
            active_preset: "my-secops-view".into(),
            custom_presets: vec![cp.clone()],
            updated_at_ms: 123,
        };
        let body = toml::to_string_pretty(&prefs).unwrap();
        std::fs::write(&path, &body).unwrap();
        let loaded = read_prefs_from_disk(&path);
        assert_eq!(loaded.custom_presets.len(), 1);
        assert_eq!(loaded.custom_presets[0], cp);
        assert_eq!(loaded.active_preset, "my-secops-view");
    }

    #[test]
    fn missing_custom_presets_field_defaults_to_empty() {
        // Backwards-compat: existing dashboard-prefs.toml files
        // without [[custom_presets]] tables must keep working.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("prefs.toml");
        std::fs::write(
            &path,
            r#"
schema_version = "1.0.0"
hidden_panels = []
refresh_rate = "fast"
active_preset = "security"
updated_at_ms = 0
"#,
        )
        .unwrap();
        let loaded = read_prefs_from_disk(&path);
        assert!(loaded.custom_presets.is_empty());
        assert_eq!(loaded.refresh_rate, "fast");
        assert_eq!(loaded.active_preset, "security");
    }
}
