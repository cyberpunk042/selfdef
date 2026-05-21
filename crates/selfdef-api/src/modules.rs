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
use axum::extract::Path as AxumPath;
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

/// `GET /v1/modules/:name` — single-module drill-down. Operator
/// dashboards link to this from the modules-list panel.
///
/// Validates the name to prevent directory traversal — only
/// `[a-z0-9-]+` accepted (matches the kebab-case convention shipped
/// modules already use).
pub(crate) async fn show(
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ModuleSummary>, ApiError> {
    // Validate name — only kebab-case + lowercase to defeat directory
    // traversal + symlink shenanigans. Operator modules are uniformly
    // [a-z0-9-]+ per docs/dev/modules.md naming convention.
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::NotFound(format!(
            "invalid module name: {name:?} (must be kebab-case [a-z0-9-]+)"
        )));
    }
    let dir = modules_dir();
    let manifest = dir.join(&name).join("module.toml");
    if !manifest.is_file() {
        return Err(ApiError::NotFound(format!("module {name:?} not found")));
    }
    let bytes = std::fs::read_to_string(&manifest)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", manifest.display())))?;
    let mut module: ModuleSummary = toml::from_str(&bytes)
        .map_err(|e| ApiError::Internal(format!("parse {}: {e}", manifest.display())))?;
    // Tag with active state from /etc/selfdef/modules.toml.
    let active = active_modules(&modules_toml());
    module.active = active.contains(&module.name);
    Ok(Json(module))
}

/// Response shape for `GET /v1/modules/:name/check`.
///
/// Surfaces the module's own `install/check.sh` script result.
/// Operators get a structured view of per-module health without
/// needing shell access to the host.
#[derive(Debug, Serialize)]
pub(crate) struct ModuleCheckBody {
    pub module: String,
    /// Path of the check script that ran.
    pub script: PathBuf,
    /// Exit code: 0 = healthy; non-zero = failing per module-author
    /// contract.
    pub exit_code: i32,
    /// Whether the script reported success (exit == 0).
    pub ok: bool,
    /// First 64 KiB of stdout (operator-readable diagnostic).
    pub stdout: String,
    /// First 64 KiB of stderr (operator-readable diagnostic).
    pub stderr: String,
}

/// Validate a module name — only kebab-case + lowercase to defeat
/// directory traversal + symlink shenanigans. Pulled out of `show`
/// so `check` can share the predicate.
fn valid_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `GET /v1/modules/:name/check` — MS006/MS016/MS017/MS018/MS022..MS031
/// per-module health surface. Invokes `<modules_dir>/<name>/install/
/// check.sh` and returns the structured result. Read-token gated
/// (same as other /v1/ routes); never executes anything that mutates
/// host state (check.sh by module-author contract is read-only;
/// documented in docs/dev/modules.md).
pub(crate) async fn check(
    AxumPath(name): AxumPath<String>,
) -> Result<Json<ModuleCheckBody>, ApiError> {
    if !valid_module_name(&name) {
        return Err(ApiError::NotFound(format!(
            "invalid module name: {name:?} (must be kebab-case [a-z0-9-]+)"
        )));
    }
    let dir = modules_dir();
    let module_dir = dir.join(&name);
    let manifest = module_dir.join("module.toml");
    if !manifest.is_file() {
        return Err(ApiError::NotFound(format!("module {name:?} not found")));
    }
    let script = module_dir.join("install").join("check.sh");
    if !script.is_file() {
        return Err(ApiError::NotFound(format!(
            "module {name:?} has no install/check.sh"
        )));
    }
    let output = std::process::Command::new("bash")
        .arg(&script)
        .output()
        .map_err(|e| ApiError::Internal(format!("invoking {}: {e}", script.display())))?;
    let exit_code = output.status.code().unwrap_or(-1);
    let truncate = |bytes: &[u8]| -> String {
        let s = String::from_utf8_lossy(bytes);
        if s.len() > 64 * 1024 {
            format!("{}\n…[truncated, {} bytes total]", &s[..64 * 1024], s.len())
        } else {
            s.into_owned()
        }
    };
    Ok(Json(ModuleCheckBody {
        module: name,
        script,
        exit_code,
        ok: output.status.success(),
        stdout: truncate(&output.stdout),
        stderr: truncate(&output.stderr),
    }))
}

/// Response shape for `GET /v1/modules/diff`.
///
/// Partitions the shipped catalog × operator-activated host config
/// into three buckets per SD-R83 / MS011 Z-13:
///
/// - **installed** — slug in catalog AND active in modules.toml
/// - **available** — slug in catalog only (operator could activate
///   via `selfdefctl modules apply --only <slug>`)
/// - **orphaned**  — slug in modules.toml only (operator has a stale
///   entry — either restore the manifest or prune)
#[derive(Debug, Serialize)]
pub(crate) struct ModulesDiffBody {
    pub modules_dir: PathBuf,
    pub modules_toml: PathBuf,
    pub installed: Vec<String>,
    pub available: Vec<String>,
    pub orphaned: Vec<String>,
    pub counts: ModulesDiffCounts,
}

#[derive(Debug, Serialize)]
pub(crate) struct ModulesDiffCounts {
    pub installed: usize,
    pub available: usize,
    pub orphaned: usize,
}

/// Pure set-difference helper extracted from `diff()` so it can be
/// unit-tested without touching `OnceLock` env / FS state. Mirrors
/// SD-R83 semantics: installed = catalog ∩ active; available =
/// catalog \ active; orphaned = active \ catalog. Each output is
/// sorted (BTreeSet input ordering).
pub(crate) fn partition_modules(
    catalog: &std::collections::BTreeSet<String>,
    active: &std::collections::BTreeSet<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let installed: Vec<String> = catalog.intersection(active).cloned().collect();
    let available: Vec<String> = catalog.difference(active).cloned().collect();
    let orphaned: Vec<String> = active.difference(catalog).cloned().collect();
    (installed, available, orphaned)
}

/// `GET /v1/modules/diff` — MS011 Z-13 / SD-R83 modules-diff surface.
/// Pure set operations over the existing `list_in_dir` + `active_modules`
/// helpers; no manifest re-parsing.
pub(crate) async fn diff() -> Result<Json<ModulesDiffBody>, ApiError> {
    let dir = modules_dir();
    let toml_path = modules_toml();
    let modules = list_in_dir(&dir)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", dir.display())))?;
    let active = active_modules(&toml_path);
    let catalog: std::collections::BTreeSet<String> =
        modules.into_iter().map(|m| m.name).collect();
    let (installed, available, orphaned) = partition_modules(&catalog, &active);
    let counts = ModulesDiffCounts {
        installed: installed.len(),
        available: available.len(),
        orphaned: orphaned.len(),
    };
    Ok(Json(ModulesDiffBody {
        modules_dir: dir,
        modules_toml: toml_path,
        installed,
        available,
        orphaned,
        counts,
    }))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("internal: {0}")]
    Internal(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg) = match self {
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),
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

    #[test]
    fn partition_modules_three_way_split() {
        use std::collections::BTreeSet;
        let catalog: BTreeSet<String> = ["module-a", "module-b", "module-c"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let active: BTreeSet<String> = ["module-b", "stale-slug"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (installed, available, orphaned) = partition_modules(&catalog, &active);
        assert_eq!(installed, vec!["module-b"]);
        assert_eq!(available, vec!["module-a", "module-c"]);
        assert_eq!(orphaned, vec!["stale-slug"]);
    }

    #[test]
    fn partition_modules_empty_active_set() {
        use std::collections::BTreeSet;
        let catalog: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let active: BTreeSet<String> = BTreeSet::new();
        let (installed, available, orphaned) = partition_modules(&catalog, &active);
        assert!(installed.is_empty());
        assert_eq!(available, vec!["a", "b"]);
        assert!(orphaned.is_empty());
    }

    #[test]
    fn partition_modules_all_orphaned_no_catalog() {
        use std::collections::BTreeSet;
        let catalog: BTreeSet<String> = BTreeSet::new();
        let active: BTreeSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
        let (installed, available, orphaned) = partition_modules(&catalog, &active);
        assert!(installed.is_empty());
        assert!(available.is_empty());
        assert_eq!(orphaned, vec!["x", "y"]);
    }
}
