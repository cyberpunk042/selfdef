//! HTTP handler for the operator-facing modules surface
//! (MS006 / SDD-009 Q-G: module-list as a dashboardable HTTP endpoint).
//!
//! Mounts at `GET /v1/modules` and returns a JSON array of every
//! module manifest the host ships at `/usr/share/selfdef/modules/<name>/module.toml`
//! (override via `SELFDEF_MODULES_DIR` env var for local dev).
//!
//! Schema is the minimal projection the dashboard / operator UIs need.
//! Heavier surfaces (requirements, install spec, daemon_requires) stay
//! in selfdef-cli — they're CLI-mediated operator workflows that
//! dashboards shouldn't dictate.
//!
//! Read-only. There's no `apply` HTTP route — module activation goes
//! through `selfdefctl modules apply` (Ring 0 + operator-confirmed
//! flow). The HTTP surface is for the dashboard to render module
//! state, not for the dashboard to mutate it.

use std::path::{Path, PathBuf};

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// Default modules directory shipped by the Debian package.
pub(crate) const DEFAULT_MODULES_DIR: &str = "/usr/share/selfdef/modules";

/// Default operator-chosen modules-config file
/// (presence-of-`[modules.<name>]`-section means active).
pub(crate) const DEFAULT_MODULES_TOML: &str = "/etc/selfdef/modules.toml";

/// Minimal projection of a module's manifest. Fields beyond these
/// stay in selfdef-cli — dashboards display these; CLI handles
/// the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ModuleSummary {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub consumes: Vec<String>,
    /// True iff the operator activated this module in modules.toml
    /// (presence of `[modules.<name>]` section).
    #[serde(default)]
    pub active: bool,
}

/// Response body for `GET /v1/modules`.
#[derive(Debug, Serialize)]
pub(crate) struct ModulesBody {
    /// Modules dir actually read (resolved via env override or default).
    pub modules_dir: PathBuf,
    /// Sorted by name.
    pub modules: Vec<ModuleSummary>,
}

fn modules_dir() -> PathBuf {
    std::env::var("SELFDEF_MODULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_MODULES_DIR))
}

fn modules_toml() -> PathBuf {
    std::env::var("SELFDEF_MODULES_TOML")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_MODULES_TOML))
}

/// Parse the operator-chosen modules.toml and return the set of
/// active module names (presence of `[modules.<name>]` section).
/// Missing file → empty set (graceful: operator hasn't run
/// `selfdefctl init modules` yet). Malformed file → empty set
/// (logged elsewhere; dashboard shouldn't break).
pub(crate) fn active_modules(modules_toml_path: &Path) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    let mut out = BTreeSet::new();
    let text = match std::fs::read_to_string(modules_toml_path) {
        Ok(t) => t,
        Err(_) => return out,
    };
    // Parse as generic toml::Value; only the [modules.<name>] subtables matter.
    let parsed: toml::Value = match toml::from_str(&text) {
        Ok(v) => v,
        Err(_) => return out,
    };
    if let Some(modules_tbl) = parsed.get("modules").and_then(|v| v.as_table()) {
        for name in modules_tbl.keys() {
            out.insert(name.clone());
        }
    }
    out
}

/// Read every module.toml at `<dir>/<name>/module.toml`. Sorted by
/// name. Missing dir → empty list (graceful). Malformed manifests
/// logged-and-skipped (not fatal).
///
/// Pure read-only filesystem walk; safe to call from any test runner
/// without env-var setup. The HTTP handler resolves the path via
/// env override + calls this.
pub(crate) fn list_in_dir(dir: &Path) -> std::io::Result<Vec<ModuleSummary>> {
    let mut modules: Vec<ModuleSummary> = Vec::new();
    if !dir.is_dir() {
        return Ok(modules);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let manifest = entry.path().join("module.toml");
        if !manifest.is_file() {
            continue;
        }
        let bytes = match std::fs::read_to_string(&manifest) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Malformed manifests get logged-and-skipped, not fatal.
        if let Ok(m) = toml::from_str::<ModuleSummary>(&bytes) {
            modules.push(m);
        }
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(modules)
}

/// `GET /v1/modules` — list every module manifest the host ships,
/// each tagged with its active state (presence of `[modules.<name>]`
/// in /etc/selfdef/modules.toml).
pub(crate) async fn list() -> Result<Json<ModulesBody>, ApiError> {
    let dir = modules_dir();
    let mut modules = list_in_dir(&dir)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", dir.display())))?;
    let active = active_modules(&modules_toml());
    for m in &mut modules {
        m.active = active.contains(&m.name);
    }
    Ok(Json(ModulesBody { modules_dir: dir, modules }))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("internal: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({"error": msg}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_manifest(dir: &std::path::Path, name: &str, body: &str) {
        let module_dir = dir.join(name);
        fs::create_dir_all(&module_dir).unwrap();
        fs::write(module_dir.join("module.toml"), body).unwrap();
    }

    #[test]
    fn list_in_dir_returns_empty_when_dir_missing() {
        // Path that doesn't exist — should not error; should return [].
        let result = list_in_dir(std::path::Path::new("/tmp/nope-selfdef-api-does-not-exist"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn list_in_dir_parses_manifests_sorted_by_name() {
        let dir = TempDir::new().unwrap();
        write_manifest(
            dir.path(),
            "zeta",
            r#"name = "zeta"
version = "0.1.0"
summary = "z module"
category = "detection"
"#,
        );
        write_manifest(
            dir.path(),
            "alpha",
            r#"name = "alpha"
version = "0.2.0"
summary = "a module"
category = "hardening"
depends_on = ["zeta"]
provides = ["alpha-thing"]
"#,
        );
        let modules = list_in_dir(dir.path()).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "alpha");
        assert_eq!(modules[0].version, "0.2.0");
        assert_eq!(modules[0].depends_on, vec!["zeta".to_string()]);
        assert_eq!(modules[0].provides, vec!["alpha-thing".to_string()]);
        assert_eq!(modules[1].name, "zeta");
    }

    #[test]
    fn list_in_dir_skips_malformed_manifests() {
        let dir = TempDir::new().unwrap();
        write_manifest(dir.path(), "good", r#"name = "good""#);
        write_manifest(dir.path(), "bad", "{not toml");
        let modules = list_in_dir(dir.path()).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "good");
    }

    #[test]
    fn active_modules_returns_empty_when_modules_toml_missing() {
        let active = active_modules(std::path::Path::new(
            "/tmp/nope-selfdef-modules-toml-does-not-exist",
        ));
        assert!(active.is_empty());
    }

    #[test]
    fn active_modules_extracts_modules_subtable_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("modules.toml");
        fs::write(
            &path,
            r#"
[modules.tetragon]
config = "/etc/selfdef/modules/tetragon.toml"

[modules.observability]

[modules."agent-guard"]
config = "/etc/selfdef/modules/agent-guard.toml"
"#,
        )
        .unwrap();
        let active = active_modules(&path);
        assert_eq!(active.len(), 3);
        assert!(active.contains("tetragon"));
        assert!(active.contains("observability"));
        assert!(active.contains("agent-guard"));
    }

    #[test]
    fn active_modules_returns_empty_when_no_modules_subtable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("modules.toml");
        // Valid TOML but no [modules.*] sections.
        fs::write(&path, "# operator hasn't activated anything yet\n").unwrap();
        let active = active_modules(&path);
        assert!(active.is_empty());
    }

    #[test]
    fn active_modules_returns_empty_when_malformed_toml() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("modules.toml");
        fs::write(&path, "{not valid toml").unwrap();
        let active = active_modules(&path);
        // Malformed file → empty set (graceful; dashboard shouldn't break).
        assert!(active.is_empty());
    }

    #[test]
    fn list_in_dir_skips_dirs_without_module_toml() {
        let dir = TempDir::new().unwrap();
        // Sibling dir with no module.toml — must be skipped silently.
        fs::create_dir_all(dir.path().join("not-a-module")).unwrap();
        write_manifest(dir.path(), "real", r#"name = "real""#);
        let modules = list_in_dir(dir.path()).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "real");
    }
}
