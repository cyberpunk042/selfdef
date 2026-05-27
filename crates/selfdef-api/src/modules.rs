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
    /// MS011 Z-8 / SDD-026 — install-path manifest distinguishing
    /// container-level vs system-level scope. Optional in the
    /// shipped module.toml (back-compat for the 14 modules that
    /// pre-date the schema extension); defaults to empty + scope
    /// `system` when absent.
    #[serde(default)]
    pub install_paths: ModuleInstallPaths,
    /// SDD-057 step 5 — `[requires_hardware]` table from module.toml.
    /// Parsed via the shared `selfdef-hardware-requirements` crate
    /// so the install-options handler can evaluate hardware-gate
    /// readiness for each AVAILABLE module. Skipped from serialization
    /// because HardwareRequirements doesn't derive Serialize (only
    /// Deserialize — operators write predicates in module.toml; we
    /// don't echo them back) + the field is parser-only on this side.
    #[serde(default, skip_serializing)]
    pub requires_hardware: selfdef_hardware_requirements::HardwareRequirements,
}

/// MS011 Z-8 install-path classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ModuleInstallPaths {
    /// `"system"` (default sovereignty; writes /etc / /usr / /var)
    /// or `"container"` (isolated; writes within the module's
    /// container scope only).
    #[serde(default = "default_install_scope")]
    pub scope: String,
    /// Absolute paths the module writes to on apply. Empty when the
    /// module hasn't declared its surfaces yet (back-compat default).
    #[serde(default)]
    pub paths: Vec<String>,
}

impl Default for ModuleInstallPaths {
    fn default() -> Self {
        Self {
            scope: default_install_scope(),
            paths: Vec::new(),
        }
    }
}

fn default_install_scope() -> String {
    "system".to_string()
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
    Ok(Json(ModulesBody {
        modules_dir: dir,
        modules,
    }))
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
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
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

/// Response shape for `GET /v1/modules/install-options`.
///
/// MS011 Z-13 / SD-R86 — surface UNINSTALLED-but-AVAILABLE catalog
/// modules with operator-actionable recommendations. Mirrors the
/// CLI's `selfdefctl modules install-options` but performs the
/// deps-only classification (the full hardware-gate enrichment from
/// the CLI is deferred until HardwareRequirements moves to a shared
/// crate per a follow-up arc).
#[derive(Debug, Serialize)]
pub(crate) struct ModulesInstallOptionsBody {
    pub modules_dir: PathBuf,
    pub modules_toml: PathBuf,
    pub options: Vec<InstallOption>,
    pub counts: InstallOptionsCounts,
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallOption {
    pub slug: String,
    pub version: String,
    pub summary: String,
    pub category: String,
    /// One of: `ready` | `blocked-by-missing-deps` |
    /// `blocked-by-hardware` | `needs-review`. SDD-057 step 5
    /// shipped the hardware-gate enrichment via the shared
    /// `selfdef-hardware-requirements` crate.
    pub recommendation: &'static str,
    /// SDD-057 step 5 — when `recommendation == "blocked-by-hardware"`,
    /// this lists the unmet predicates from the gate evaluation.
    /// Empty for other recommendations.
    #[serde(default)]
    pub unmet_hardware_predicates: Vec<String>,
    pub missing_deps: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallOptionsCounts {
    pub total: usize,
    pub ready: usize,
    pub blocked_by_missing_deps: usize,
    /// SDD-057 step 5 — gate fails against probed capabilities.
    #[serde(default)]
    pub blocked_by_hardware: usize,
    /// SDD-057 step 5 — hardware probe unavailable (e.g. nvidia-smi
    /// missing on a host that declares GPU predicates); operator
    /// review needed before classifying.
    #[serde(default)]
    pub needs_review: usize,
}

/// `GET /v1/modules/install-options` — MS011 Z-13 / SD-R86 +
/// SDD-057 step 5. Classifies AVAILABLE modules (catalog \ active)
/// by dep-readiness AND hardware-gate readiness via the shared
/// `selfdef-hardware-requirements` crate.
pub(crate) async fn install_options() -> Result<Json<ModulesInstallOptionsBody>, ApiError> {
    let dir = modules_dir();
    let toml_path = modules_toml();
    let modules = list_in_dir(&dir)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", dir.display())))?;
    let active = active_modules(&toml_path);

    // SDD-057 step 5 — try to derive HardwareCapabilities from the
    // cached snapshot. When probe fails (e.g. CI runner, no
    // nvidia-smi, no /sys/devices/system/cpu), gate evaluation
    // falls back to "needs-review" for any module declaring a
    // hardware predicate.
    let caps: Option<selfdef_hardware::HardwareCapabilities> = crate::hardware::cached_snapshot()
        .ok()
        .map(selfdef_hardware::derive_capabilities);

    let mut options: Vec<InstallOption> = Vec::new();
    let mut ready = 0usize;
    let mut blocked_deps = 0usize;
    let mut blocked_hw = 0usize;
    let mut needs_review = 0usize;

    for m in &modules {
        if active.contains(&m.name) {
            continue; // installed — skip
        }
        // 1. Dep-readiness.
        let missing_deps: Vec<String> = m
            .depends_on
            .iter()
            .filter(|d| !active.contains(*d))
            .cloned()
            .collect();
        if !missing_deps.is_empty() {
            blocked_deps += 1;
            options.push(InstallOption {
                slug: m.name.clone(),
                version: m.version.clone(),
                summary: m.summary.clone(),
                category: m.category.clone(),
                recommendation: "blocked-by-missing-deps",
                missing_deps,
                unmet_hardware_predicates: Vec::new(),
            });
            continue;
        }
        // 2. Hardware gate (SDD-057 step 5).
        let req = &m.requires_hardware;
        let req_is_disabled = req.is_empty();
        let (recommendation, unmet_hw): (&'static str, Vec<String>) = if req_is_disabled {
            ("ready", Vec::new())
        } else {
            match &caps {
                Some(c) => match req.evaluate(c) {
                    Ok(()) => ("ready", Vec::new()),
                    Err(unmet) => ("blocked-by-hardware", unmet),
                },
                None => ("needs-review", Vec::new()),
            }
        };
        match recommendation {
            "ready" => ready += 1,
            "blocked-by-hardware" => blocked_hw += 1,
            "needs-review" => needs_review += 1,
            _ => {}
        }
        options.push(InstallOption {
            slug: m.name.clone(),
            version: m.version.clone(),
            summary: m.summary.clone(),
            category: m.category.clone(),
            recommendation,
            missing_deps: Vec::new(),
            unmet_hardware_predicates: unmet_hw,
        });
    }

    let counts = InstallOptionsCounts {
        total: options.len(),
        ready,
        blocked_by_missing_deps: blocked_deps,
        blocked_by_hardware: blocked_hw,
        needs_review,
    };
    Ok(Json(ModulesInstallOptionsBody {
        modules_dir: dir,
        modules_toml: toml_path,
        options,
        counts,
    }))
}

/// Response shape for `GET /v1/modules/install-plan`.
///
/// MS011 Z-13 / SD-R87 — topologically-ordered install plan over
/// the READY (no-missing-deps) modules. Each step's commands
/// run in order; later steps depend on earlier steps. Operators
/// can paste each command directly or wrap with `selfdefctl modules
/// apply --only <slug>` per step.
#[derive(Debug, Serialize)]
pub(crate) struct ModulesInstallPlanBody {
    pub modules_dir: PathBuf,
    pub modules_toml: PathBuf,
    /// Topologically-ordered slugs (oldest dependency first).
    /// Empty when no READY modules exist.
    pub plan: Vec<String>,
    /// Modules skipped because they're not in the READY set —
    /// either already installed, or blocked-by-missing-deps.
    pub skipped: Vec<SkippedReason>,
    /// True iff a dependency cycle was detected (rare; would mean
    /// the catalog is malformed). When true, `plan` is empty +
    /// `cycle_member_slugs` lists the offending modules.
    pub cycle_detected: bool,
    pub cycle_member_slugs: Vec<String>,
    /// MS011 Z-8 / SDD-026 — path-conflict detection across the
    /// planned modules. When two or more modules in the plan declare
    /// the same path in their `[install_paths].paths` list, the
    /// conflict is surfaced here so the operator can resolve it
    /// (different scope, different config, or operator-chosen
    /// override) BEFORE running the plan. Empty when no conflicts.
    pub path_conflicts: Vec<PathConflict>,
}

/// One on-disk path that two or more planned modules both intend to
/// write under their `[install_paths].paths` declaration. The
/// operator-resolution UX is dashboard-side; this struct carries
/// the data.
#[derive(Debug, Serialize)]
pub(crate) struct PathConflict {
    /// Absolute path that both modules touch.
    pub path: String,
    /// Module slugs that all declare this path (sorted, ≥2 entries).
    pub modules: Vec<String>,
    /// Distinct scope values across the conflicting modules. When all
    /// are `"system"` (the common case), the conflict is unambiguous
    /// — both modules really do write to the same host location.
    /// When scopes differ (`"system"` + `"container"`), the conflict
    /// is informational (separate scopes can coexist).
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SkippedReason {
    pub slug: String,
    /// `"installed"` | `"blocked-by-missing-deps"`.
    pub reason: &'static str,
    pub missing_deps: Vec<String>,
}

/// `GET /v1/modules/install-plan` — MS011 Z-13 / SD-R87.
/// Topological sort (Kahn's algorithm) over the READY set.
pub(crate) async fn install_plan() -> Result<Json<ModulesInstallPlanBody>, ApiError> {
    let dir = modules_dir();
    let toml_path = modules_toml();
    let modules = list_in_dir(&dir)
        .map_err(|e| ApiError::Internal(format!("read {}: {e}", dir.display())))?;
    let active = active_modules(&toml_path);

    // Pass 1: classify each manifest into READY / installed /
    // blocked-by-missing-deps + collect dep edges for Kahn's.
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    let mut ready: BTreeSet<String> = BTreeSet::new();
    let mut skipped: Vec<SkippedReason> = Vec::new();
    // dep edges: dep_slug → set of dependents
    let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // indegree: slug → count of unresolved deps that are in READY
    let mut indegree: BTreeMap<String, usize> = BTreeMap::new();

    for m in &modules {
        let slug = m.name.clone();
        if active.contains(&slug) {
            skipped.push(SkippedReason {
                slug,
                reason: "installed",
                missing_deps: Vec::new(),
            });
            continue;
        }
        let missing: Vec<String> = m
            .depends_on
            .iter()
            .filter(|d| !active.contains(*d))
            .filter(|d| {
                // dep is missing if NOT active AND not in any catalog manifest
                // (catalog manifests are the modules vec) — if it IS in the
                // catalog but not active, it's a candidate for the plan, not
                // a "missing" dep.
                !modules.iter().any(|c| c.name == **d)
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            skipped.push(SkippedReason {
                slug,
                reason: "blocked-by-missing-deps",
                missing_deps: missing,
            });
            continue;
        }
        ready.insert(slug);
    }

    // Pass 2: build the dep graph over READY-only modules.
    for m in &modules {
        if !ready.contains(&m.name) {
            continue;
        }
        let mut deg = 0usize;
        for d in &m.depends_on {
            // dep is either active (skip; already there) or also
            // in READY (need to wait for it)
            if ready.contains(d) {
                dependents
                    .entry(d.clone())
                    .or_default()
                    .insert(m.name.clone());
                deg += 1;
            }
            // Active deps don't count toward indegree
        }
        indegree.insert(m.name.clone(), deg);
    }

    // Pass 3: Kahn's algorithm.
    let mut queue: VecDeque<String> = indegree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(k, _)| k.clone())
        .collect();
    // Sort initial frontier for determinism (BTreeMap iteration is
    // ordered already; this just guards against future refactors).
    let mut frontier: Vec<String> = queue.drain(..).collect();
    frontier.sort();
    for s in frontier {
        queue.push_back(s);
    }
    let mut plan: Vec<String> = Vec::new();
    while let Some(slug) = queue.pop_front() {
        plan.push(slug.clone());
        // Discover newly-zero-indegree dependents.
        if let Some(deps) = dependents.get(&slug) {
            let mut next: Vec<String> = Vec::new();
            for d in deps {
                if let Some(deg) = indegree.get_mut(d) {
                    if *deg > 0 {
                        *deg -= 1;
                        if *deg == 0 {
                            next.push(d.clone());
                        }
                    }
                }
            }
            next.sort();
            for s in next {
                queue.push_back(s);
            }
        }
    }

    // Cycle detection: anything still in indegree > 0 is cyclic.
    let cycle_members: Vec<String> = indegree
        .iter()
        .filter(|&(_, &d)| d > 0)
        .map(|(k, _)| k.clone())
        .collect();
    let cycle_detected = !cycle_members.is_empty();

    let plan_final = if cycle_detected { Vec::new() } else { plan };

    // MS011 Z-8: path-conflict detection across the planned modules.
    // Walks every module's [install_paths].paths and groups them
    // by path string; ≥2 distinct slugs on the same path = conflict.
    let path_conflicts = compute_path_conflicts(&modules, &plan_final);

    Ok(Json(ModulesInstallPlanBody {
        modules_dir: dir,
        modules_toml: toml_path,
        plan: plan_final,
        skipped,
        cycle_detected,
        cycle_member_slugs: cycle_members,
        path_conflicts,
    }))
}

/// MS011 Z-8 — group `install_paths.paths` across the planned slugs.
/// Returns ≥2-slug groups sorted by path then by membership.
pub(crate) fn compute_path_conflicts(
    modules: &[ModuleSummary],
    plan_slugs: &[String],
) -> Vec<PathConflict> {
    use std::collections::BTreeMap;
    let plan_set: std::collections::BTreeSet<&String> = plan_slugs.iter().collect();
    let mut by_path: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for m in modules {
        if !plan_set.contains(&m.name) {
            continue;
        }
        for p in &m.install_paths.paths {
            by_path
                .entry(p.clone())
                .or_default()
                .insert(m.name.clone(), m.install_paths.scope.clone());
        }
    }
    let mut out: Vec<PathConflict> = Vec::new();
    for (path, slug_to_scope) in by_path {
        if slug_to_scope.len() < 2 {
            continue;
        }
        let modules: Vec<String> = slug_to_scope.keys().cloned().collect();
        let mut scopes: Vec<String> = slug_to_scope.values().cloned().collect();
        scopes.sort();
        scopes.dedup();
        out.push(PathConflict {
            path,
            modules,
            scopes,
        });
    }
    out
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
    let catalog: std::collections::BTreeSet<String> = modules.into_iter().map(|m| m.name).collect();
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

    #[test]
    fn install_paths_default_back_compat() {
        // MS011 Z-8 — module.toml WITHOUT [install_paths] block
        // (every shipped manifest pre-extension) parses cleanly +
        // gets default scope="system" + empty paths.
        let body = r#"
name = "test-module"
version = "0.1.0"
summary = "no install_paths block declared"
category = "test"
"#;
        let m: ModuleSummary = toml::from_str(body).unwrap();
        assert_eq!(m.name, "test-module");
        assert_eq!(m.install_paths.scope, "system");
        assert!(m.install_paths.paths.is_empty());
    }

    #[test]
    fn install_paths_container_scope_round_trips() {
        // MS011 Z-8 — module.toml WITH [install_paths] block parses
        // the scope + paths fields.
        let body = r#"
name = "test-module"

[install_paths]
scope = "container"
paths = ["/opt/foo", "/var/lib/foo"]
"#;
        let m: ModuleSummary = toml::from_str(body).unwrap();
        assert_eq!(m.install_paths.scope, "container");
        assert_eq!(m.install_paths.paths, vec!["/opt/foo", "/var/lib/foo"]);
    }

    #[test]
    fn path_conflict_detection_two_modules_same_path() {
        // MS011 Z-8 — when two planned modules declare the same path,
        // compute_path_conflicts returns a single conflict naming
        // both slugs sorted alphabetically.
        let make = |name: &str, paths: Vec<&str>| ModuleSummary {
            name: name.to_string(),
            version: String::new(),
            summary: String::new(),
            category: String::new(),
            depends_on: Vec::new(),
            conflicts: Vec::new(),
            provides: Vec::new(),
            consumes: Vec::new(),
            active: false,
            install_paths: ModuleInstallPaths {
                scope: "system".to_string(),
                paths: paths.into_iter().map(String::from).collect(),
            },
            requires_hardware: Default::default(),
        };
        let modules = vec![
            make(
                "agent-guard",
                vec![
                    "/etc/tetragon/tetragon.tp.d",
                    "/etc/selfdef/modules/agent-guard.toml",
                ],
            ),
            make(
                "tetragon",
                vec!["/etc/tetragon/tetragon.tp.d", "/etc/tetragon/tetragon.yaml"],
            ),
            make("unrelated", vec!["/var/lib/selfdef/wasm-aot"]),
        ];
        let plan = vec![
            "agent-guard".to_string(),
            "tetragon".to_string(),
            "unrelated".to_string(),
        ];
        let conflicts = compute_path_conflicts(&modules, &plan);
        assert_eq!(conflicts.len(), 1, "exactly one shared path");
        assert_eq!(conflicts[0].path, "/etc/tetragon/tetragon.tp.d");
        assert_eq!(conflicts[0].modules, vec!["agent-guard", "tetragon"]);
        assert_eq!(conflicts[0].scopes, vec!["system"]);
    }

    #[test]
    fn path_conflict_detection_skips_modules_not_in_plan() {
        // MS011 Z-8 — conflicts are only computed across the active
        // plan set. A module that declares a shared path but isn't
        // in the plan must NOT trigger a conflict.
        let make = |name: &str, paths: Vec<&str>| ModuleSummary {
            name: name.to_string(),
            version: String::new(),
            summary: String::new(),
            category: String::new(),
            depends_on: Vec::new(),
            conflicts: Vec::new(),
            provides: Vec::new(),
            consumes: Vec::new(),
            active: false,
            install_paths: ModuleInstallPaths {
                scope: "system".to_string(),
                paths: paths.into_iter().map(String::from).collect(),
            },
            requires_hardware: Default::default(),
        };
        let modules = vec![
            make("a", vec!["/shared/path"]),
            make("b", vec!["/shared/path"]),
            make("c", vec!["/c/path"]),
        ];
        let plan = vec!["a".to_string(), "c".to_string()]; // b not in plan
        let conflicts = compute_path_conflicts(&modules, &plan);
        assert!(
            conflicts.is_empty(),
            "b's /shared/path declaration must not conflict when b isn't planned"
        );
    }

    #[test]
    fn path_conflict_detection_distinct_scopes_surfaced() {
        // MS011 Z-8 — when two modules share a path but with
        // different scopes, scopes list contains both (informational
        // conflict: separate scopes can coexist).
        let make = |name: &str, scope: &str, paths: Vec<&str>| ModuleSummary {
            name: name.to_string(),
            version: String::new(),
            summary: String::new(),
            category: String::new(),
            depends_on: Vec::new(),
            conflicts: Vec::new(),
            provides: Vec::new(),
            consumes: Vec::new(),
            active: false,
            install_paths: ModuleInstallPaths {
                scope: scope.to_string(),
                paths: paths.into_iter().map(String::from).collect(),
            },
            requires_hardware: Default::default(),
        };
        let modules = vec![
            make("host-mod", "system", vec!["/etc/foo"]),
            make("container-mod", "container", vec!["/etc/foo"]),
        ];
        let plan = vec!["container-mod".to_string(), "host-mod".to_string()];
        let conflicts = compute_path_conflicts(&modules, &plan);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].scopes, vec!["container", "system"]);
    }
}
