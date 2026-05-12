//! `selfdefctl modules` — module-catalog inspector + apply / check runner.
//!
//! Two surfaces:
//!
//! 1. **Catalog**: `list`, `info` (read-only — what's available on disk).
//! 2. **Lifecycle**: `apply`, `check`, `status` — drive each active
//!    module's `apply.sh` / `check.sh` and aggregate their structured-
//!    status JSON output.
//!
//! Active modules are declared in a host config at
//! `/etc/selfdef/modules.toml` (or `--host-config <path>`). Per-module
//! config files default to `/etc/selfdef/modules/<slug>.toml` and are
//! passed to scripts via the existing `SELFDEF_<SLUG>_CONFIG` env
//! convention. Multi-instance syntax (`[modules."vpn-bridge#tunnel"]`)
//! is reserved for a follow-up PR; this file accepts only flat
//! one-instance-per-module configs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::Deserialize;

const SYSTEM_MODULES_DIR: &str = "/usr/share/selfdef/modules";
const DEFAULT_HOST_CONFIG: &str = "/etc/selfdef/modules.toml";
const DEFAULT_PER_MODULE_DIR: &str = "/etc/selfdef/modules";

#[derive(Debug, Deserialize)]
pub(crate) struct ModuleManifest {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) summary: String,
    #[serde(default)]
    pub(crate) category: String,
    #[serde(default)]
    pub(crate) depends_on: Vec<String>,
    #[serde(default)]
    pub(crate) conflicts: Vec<String>,
    #[serde(default)]
    pub(crate) provides: Vec<String>,
    #[serde(default)]
    pub(crate) consumes: Vec<String>,
    #[serde(default)]
    pub(crate) requires: Vec<Requirement>,
    #[serde(default)]
    pub(crate) install: Option<InstallSpec>,
    #[serde(default)]
    pub(crate) profiles: Option<ProfileSpec>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Requirement {
    pub(crate) kind: String,
    pub(crate) value: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InstallSpec {
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) package: Option<String>,
    #[serde(default)]
    pub(crate) apply: Option<String>,
    #[serde(default)]
    pub(crate) check: Option<String>,
    #[serde(default)]
    pub(crate) uninstall: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileSpec {
    #[serde(default)]
    pub(crate) default: Option<String>,
    #[serde(default)]
    pub(crate) available: Vec<String>,
}

/// Resolve the modules directory, honouring `--dir` if given, then a
/// system path, then the workspace fallback for dev runs.
pub(crate) fn resolve_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    let system = PathBuf::from(SYSTEM_MODULES_DIR);
    if system.exists() {
        return system;
    }
    // Workspace fallback for `cargo run`: crates/selfdef-cli/ -> ../../modules
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../modules")
}

/// Load every `module.toml` directly under `dir`. Returns (slug, manifest)
/// pairs in stable directory order.
pub(crate) fn load_all(dir: &Path) -> Result<Vec<(String, ModuleManifest)>> {
    if !dir.exists() {
        anyhow::bail!("modules directory does not exist: {}", dir.display());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    let mut out = Vec::new();
    for entry in entries {
        let slug = entry.file_name().to_string_lossy().into_owned();
        let manifest_path = entry.path().join("module.toml");
        if !manifest_path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        let manifest: ModuleManifest = toml::from_str(&content)
            .with_context(|| format!("parsing {}", manifest_path.display()))?;
        if manifest.name != slug {
            anyhow::bail!(
                "manifest name `{}` does not match directory `{}` ({})",
                manifest.name,
                slug,
                manifest_path.display(),
            );
        }
        out.push((slug, manifest));
    }
    Ok(out)
}

pub(crate) fn cmd_list(dir: &Path) -> Result<()> {
    let mods = load_all(dir)?;
    if mods.is_empty() {
        println!("(no modules in {})", dir.display());
        return Ok(());
    }
    println!(
        "{:<20}  {:<10}  {:<14}  summary",
        "name", "version", "category"
    );
    for (_, m) in &mods {
        println!(
            "{:<20}  {:<10}  {:<14}  {}",
            m.name, m.version, m.category, m.summary
        );
    }
    Ok(())
}

pub(crate) fn cmd_info(dir: &Path, slug: &str) -> Result<()> {
    let mods = load_all(dir)?;
    let m = mods
        .iter()
        .find(|(s, _)| s == slug)
        .map(|(_, m)| m)
        .with_context(|| format!("no module named `{slug}` in {}", dir.display()))?;

    println!("name:     {}", m.name);
    println!("version:  {}", m.version);
    println!("category: {}", m.category);
    println!("summary:  {}", m.summary);
    if !m.depends_on.is_empty() {
        println!("depends:  {}", m.depends_on.join(", "));
    }
    if !m.conflicts.is_empty() {
        println!("conflicts:{}", m.conflicts.join(", "));
    }
    if !m.provides.is_empty() {
        println!("provides: {}", m.provides.join(", "));
    }
    if !m.consumes.is_empty() {
        println!("consumes: {}", m.consumes.join(", "));
    }
    if !m.requires.is_empty() {
        println!("requires:");
        for r in &m.requires {
            println!("  - {} = {}", r.kind, r.value);
        }
    }
    if let Some(i) = &m.install {
        print!("install:  kind={}", i.kind);
        if let Some(p) = &i.package {
            print!(" package={p}");
        }
        if let Some(a) = &i.apply {
            print!(" apply={a}");
        }
        println!();
    }
    if let Some(p) = &m.profiles {
        let def = p.default.as_deref().unwrap_or("-");
        println!("profiles: default={def} ({})", p.available.join(", "));
    }
    Ok(())
}

// ---------------------------------------------------------------- host config
//
// /etc/selfdef/modules.toml — declares which modules are active on
// this host and (optionally) overrides per-module config paths.
//
//   [modules.detect-host]
//   [modules.vpn-bridge]
//   config = "/etc/selfdef/modules/vpn-bridge.toml"   # optional
//
// A module slug appears here with at most one block. Multi-instance
// support (e.g. "vpn-bridge#tunnel") is reserved; the parser refuses
// keys containing '#' for now, with a clear error.

#[derive(Debug, Default, Deserialize)]
pub(crate) struct HostConfig {
    #[serde(default)]
    pub(crate) modules: BTreeMap<String, HostModuleEntry>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub(crate) struct HostModuleEntry {
    #[serde(default)]
    pub(crate) config: Option<PathBuf>,
}

/// Where to look for the host config. Honour explicit > $SELFDEF_HOST_MODULES_CONFIG
/// > default system path.
pub(crate) fn resolve_host_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Some(env) = std::env::var_os("SELFDEF_HOST_MODULES_CONFIG") {
        return PathBuf::from(env);
    }
    PathBuf::from(DEFAULT_HOST_CONFIG)
}

pub(crate) fn load_host_config(path: &Path) -> Result<HostConfig> {
    if !path.exists() {
        // A missing host config is *not* an error — it means no modules
        // are active on this host. Apply/check are then no-ops.
        return Ok(HostConfig::default());
    }
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: HostConfig =
        toml::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    for slug in cfg.modules.keys() {
        if slug.contains('#') {
            anyhow::bail!(
                "instance-suffix module keys (`{slug}`) are reserved for a future PR — \
                 use the flat slug for now"
            );
        }
        if slug.is_empty() || !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            anyhow::bail!("invalid module slug in {}: `{slug}`", path.display());
        }
    }
    Ok(cfg)
}

/// An active module after resolving against the catalog: ready to run.
#[derive(Debug)]
pub(crate) struct ActiveModule {
    pub(crate) slug: String,
    pub(crate) module_root: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) manifest: ModuleManifest,
}

/// Resolve the host's active modules against a catalog. Returns the
/// list in **dependency-applied order** (depends_on first). Errors on
/// missing deps, conflicts, or cycles.
pub(crate) fn resolve_active(
    host: &HostConfig,
    catalog_dir: &Path,
    catalog: Vec<(String, ModuleManifest)>,
) -> Result<Vec<ActiveModule>> {
    let mut by_slug: HashMap<String, ModuleManifest> = catalog.into_iter().collect();

    // 1. Make sure every active slug exists in the catalog.
    for slug in host.modules.keys() {
        if !by_slug.contains_key(slug) {
            anyhow::bail!(
                "active module `{slug}` not found in catalog {}",
                catalog_dir.display()
            );
        }
    }

    // 2. Refuse `conflicts` collisions among the active set.
    let active_set: BTreeSet<&str> = host.modules.keys().map(String::as_str).collect();
    for slug in &active_set {
        let m = &by_slug[*slug];
        for c in &m.conflicts {
            if active_set.contains(c.as_str()) {
                anyhow::bail!("module `{slug}` conflicts with active module `{c}`");
            }
        }
    }

    // 3. Refuse missing depends_on. Deps must themselves be active.
    for slug in &active_set {
        let m = &by_slug[*slug];
        for d in &m.depends_on {
            if !active_set.contains(d.as_str()) {
                anyhow::bail!("module `{slug}` depends on `{d}` which is not active");
            }
        }
    }

    // 4. Kahn-style topological sort across active modules by depends_on.
    let mut indeg: HashMap<&str, usize> = active_set.iter().map(|s| (*s, 0)).collect();
    for slug in &active_set {
        let m = &by_slug[*slug];
        for d in &m.depends_on {
            // edge: d -> slug (apply d before slug)
            if active_set.contains(d.as_str()) {
                *indeg.get_mut(*slug).unwrap() += 1;
            }
        }
    }
    // Sort descending so that `Vec::pop` (which pops from the back)
    // yields modules in alphabetical order — deterministic apply
    // sequence for the operator.
    let mut ready: Vec<&str> = indeg
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(s, _)| *s)
        .collect();
    ready.sort_unstable_by(|a, b| b.cmp(a));
    let mut order: Vec<String> = Vec::with_capacity(active_set.len());
    while let Some(next) = ready.pop() {
        order.push(next.to_string());
        // Decrement indegree of every module that has `next` in depends_on.
        let mut newly_ready: Vec<&str> = Vec::new();
        for slug in &active_set {
            let m = &by_slug[*slug];
            if m.depends_on.iter().any(|d| d == next) {
                let e = indeg.get_mut(*slug).unwrap();
                *e -= 1;
                if *e == 0 {
                    newly_ready.push(*slug);
                }
            }
        }
        // Insert keeping `ready` sorted descending so the smallest
        // alphabetically still pops first on the next iteration.
        for s in newly_ready {
            ready.push(s);
        }
        ready.sort_unstable_by(|a, b| b.cmp(a));
    }
    if order.len() != active_set.len() {
        let leftover: Vec<String> = active_set
            .iter()
            .filter(|s| !order.contains(&s.to_string()))
            .map(|s| (*s).to_string())
            .collect();
        anyhow::bail!(
            "dependency cycle among active modules: {}",
            leftover.join(", ")
        );
    }

    // 5. Materialise.
    let mut out = Vec::with_capacity(order.len());
    for slug in order {
        let entry = host.modules.get(&slug).cloned().unwrap_or_default();
        let manifest = by_slug.remove(&slug).expect("present in catalog");
        let module_root = catalog_dir.join(&slug);
        let config_path = entry
            .config
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PER_MODULE_DIR).join(format!("{slug}.toml")));
        out.push(ActiveModule {
            slug,
            module_root,
            config_path,
            manifest,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------- runner
//
// Each module's apply.sh / check.sh / uninstall.sh ends with a single
// JSON line on stdout: {"module":"<slug>","status":"<state>","message":"..."}.
// The runner spawns the script with the right env vars, captures
// stdout, and pulls the last JSON object as the authoritative result.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutcomeStatus {
    Ok,
    Skipped,
    Failed,
}

impl OutcomeStatus {
    fn from_str(s: &str) -> Self {
        match s {
            "ok" => Self::Ok,
            "skipped" => Self::Skipped,
            _ => Self::Failed,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub(crate) slug: String,
    pub(crate) status: OutcomeStatus,
    pub(crate) message: String,
    pub(crate) raw_stderr: String,
}

#[derive(Debug, Deserialize)]
struct StatusLine {
    #[serde(default)]
    module: String,
    status: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Action {
    Apply,
    Check,
    // `Uninstall` is plumbed but not yet exposed as a subcommand —
    // destructive op needs operator-confirmation UX, deferred to its
    // own PR. Keeping the variant so the runner stays complete.
    #[allow(dead_code)]
    Uninstall,
}

impl Action {
    fn script_relpath<'a>(&self, install: &'a InstallSpec) -> Option<&'a str> {
        match self {
            Self::Apply => install.apply.as_deref(),
            Self::Check => install.check.as_deref(),
            Self::Uninstall => install.uninstall.as_deref(),
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Check => "check",
            Self::Uninstall => "uninstall",
        }
    }
}

/// Convention: per-module config path is exposed to the script via
/// `SELFDEF_<UPPER_SLUG>_CONFIG`. Hyphens become underscores so the
/// var name is a valid identifier.
fn env_var_for_config(slug: &str) -> String {
    let upper: String = slug
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    format!("SELFDEF_{upper}_CONFIG")
}

pub(crate) fn run_one(active: &ActiveModule, action: Action, dry_run: bool) -> Result<Outcome> {
    let install = active
        .manifest
        .install
        .as_ref()
        .with_context(|| format!("module `{}` has no [install] section", active.slug))?;
    let rel = action.script_relpath(install).with_context(|| {
        format!(
            "module `{}` does not declare an `{}` script",
            active.slug,
            action.name()
        )
    })?;
    let script = active.module_root.join(rel);
    if !script.exists() {
        anyhow::bail!(
            "module `{}` script missing: {}",
            active.slug,
            script.display()
        );
    }

    let mut cmd = Command::new("bash");
    cmd.arg(&script)
        .env(env_var_for_config(&active.slug), &active.config_path)
        .env("SELFDEF_DRY_RUN", if dry_run { "1" } else { "0" })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let out = cmd
        .output()
        .with_context(|| format!("spawning {}", script.display()))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    let parsed = parse_status_line(&stdout);
    let (status, message) = match parsed {
        Some(s) => {
            // Defence-in-depth: a script for module `foo` claiming to
            // be `bar` is a bug we want surfaced, not silently trusted.
            if !s.module.is_empty() && s.module != active.slug {
                anyhow::bail!(
                    "module `{}` script emitted status for `{}` — refusing",
                    active.slug,
                    s.module
                );
            }
            (OutcomeStatus::from_str(&s.status), s.message)
        }
        None if out.status.success() => (
            OutcomeStatus::Ok,
            "(no structured status emitted)".to_string(),
        ),
        None => (
            OutcomeStatus::Failed,
            format!("exit={:?}, no structured status", out.status.code()),
        ),
    };

    // Reconcile: if the script exited non-zero, surface failure even
    // if it printed an "ok" status — defence in depth.
    let status = if !out.status.success() && status != OutcomeStatus::Failed {
        OutcomeStatus::Failed
    } else {
        status
    };

    Ok(Outcome {
        slug: active.slug.clone(),
        status,
        message,
        raw_stderr: stderr,
    })
}

fn parse_status_line(stdout: &str) -> Option<StatusLine> {
    // Walk from the end — modules may emit multiple status lines if
    // they fail and re-emit; the last one wins.
    stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<StatusLine>(line.trim()).ok())
}

// ---------------------------------------------------------------- CLI bodies

#[derive(Debug, Default, Clone)]
pub(crate) struct LifecycleOpts {
    pub(crate) host_config: Option<PathBuf>,
    pub(crate) dir: Option<PathBuf>,
    pub(crate) only: Vec<String>,
    pub(crate) except: Vec<String>,
    pub(crate) dry_run: bool,
}

fn filter_active(
    active: Vec<ActiveModule>,
    only: &[String],
    except: &[String],
) -> Vec<ActiveModule> {
    let only: HashSet<&str> = only.iter().map(String::as_str).collect();
    let except: HashSet<&str> = except.iter().map(String::as_str).collect();
    active
        .into_iter()
        .filter(|a| {
            if !only.is_empty() && !only.contains(a.slug.as_str()) {
                return false;
            }
            if except.contains(a.slug.as_str()) {
                return false;
            }
            true
        })
        .collect()
}

/// Shared resolution path for apply / check / status.
fn prepare(opts: &LifecycleOpts) -> Result<(PathBuf, Vec<ActiveModule>)> {
    let catalog_dir = resolve_dir(opts.dir.as_deref());
    let catalog = load_all(&catalog_dir)?;
    let host_path = resolve_host_config_path(opts.host_config.as_deref());
    let host = load_host_config(&host_path)?;
    let active = resolve_active(&host, &catalog_dir, catalog)?;
    let active = filter_active(active, &opts.only, &opts.except);
    Ok((host_path, active))
}

pub(crate) fn cmd_apply(opts: &LifecycleOpts) -> Result<i32> {
    run_lifecycle(opts, Action::Apply)
}

pub(crate) fn cmd_check(opts: &LifecycleOpts) -> Result<i32> {
    // `check` never mutates — force dry_run off (it's a no-op for
    // check scripts but keeps the env consistent).
    let mut o = opts.clone();
    o.dry_run = false;
    run_lifecycle(&o, Action::Check)
}

pub(crate) fn cmd_status(opts: &LifecycleOpts) -> Result<i32> {
    // Status is a pretty-printed check; same machinery, different header.
    let mut o = opts.clone();
    o.dry_run = false;
    run_lifecycle(&o, Action::Check)
}

fn run_lifecycle(opts: &LifecycleOpts, action: Action) -> Result<i32> {
    let (host_path, active) = prepare(opts)?;
    println!(
        "{} {} module(s) (host config: {})",
        match action {
            Action::Apply => "Applying",
            Action::Check => "Checking",
            Action::Uninstall => "Uninstalling",
        },
        active.len(),
        host_path.display(),
    );
    if active.is_empty() {
        return Ok(0);
    }

    let mut outcomes = Vec::with_capacity(active.len());
    for a in &active {
        let label = format!("{} [{}]", a.slug, action.name());
        print!("  {label} ... ");
        let outcome = run_one(a, action, opts.dry_run)?;
        println!("{}: {}", outcome.status.as_str(), outcome.message);
        outcomes.push(outcome);
    }

    let failed: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| o.status == OutcomeStatus::Failed)
        .collect();
    println!();
    println!(
        "Summary: {} ok, {} skipped, {} failed",
        outcomes
            .iter()
            .filter(|o| o.status == OutcomeStatus::Ok)
            .count(),
        outcomes
            .iter()
            .filter(|o| o.status == OutcomeStatus::Skipped)
            .count(),
        failed.len(),
    );
    if !failed.is_empty() {
        for f in &failed {
            eprintln!();
            eprintln!("--- {} stderr ---", f.slug);
            eprint!("{}", f.raw_stderr);
        }
        return Ok(1);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn loads_detect_host_from_workspace() {
        let dir = resolve_dir(None);
        // In a workspace dev run this points at <repo>/modules.
        // CI rebuilds .deb without modules/, so allow absence.
        if !dir.exists() {
            eprintln!("skipping: modules dir not present at {}", dir.display());
            return;
        }
        let mods = load_all(&dir).expect("load");
        assert!(
            mods.iter().any(|(s, _)| s == "detect-host"),
            "detect-host module missing from {}",
            dir.display()
        );
    }

    // -- host config parsing -----------------------------------------

    #[test]
    fn host_config_missing_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = load_host_config(&dir.path().join("none.toml")).unwrap();
        assert!(cfg.modules.is_empty());
    }

    #[test]
    fn host_config_rejects_instance_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("modules.toml");
        std::fs::write(&p, "[modules.\"vpn-bridge#tunnel\"]\n").unwrap();
        let err = load_host_config(&p).unwrap_err().to_string();
        assert!(err.contains("instance-suffix"), "got: {err}");
    }

    #[test]
    fn host_config_rejects_bad_slug_chars() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("modules.toml");
        std::fs::write(&p, "[modules.\"weird name\"]\n").unwrap();
        let err = load_host_config(&p).unwrap_err().to_string();
        assert!(err.contains("invalid module slug"), "got: {err}");
    }

    // -- helpers for resolver / runner tests -------------------------

    fn make_manifest(name: &str, deps: &[&str], conflicts: &[&str]) -> ModuleManifest {
        ModuleManifest {
            name: name.to_string(),
            version: "0.0.0".into(),
            summary: "test".into(),
            category: "test".into(),
            depends_on: deps.iter().map(|s| (*s).to_string()).collect(),
            conflicts: conflicts.iter().map(|s| (*s).to_string()).collect(),
            provides: Vec::new(),
            consumes: Vec::new(),
            requires: Vec::new(),
            install: None,
            profiles: None,
        }
    }

    fn host_with(slugs: &[&str]) -> HostConfig {
        let mut cfg = HostConfig::default();
        for s in slugs {
            cfg.modules
                .insert((*s).to_string(), HostModuleEntry::default());
        }
        cfg
    }

    // -- resolver ---------------------------------------------------

    #[test]
    fn resolver_topo_orders_depends_on() {
        // c depends on b, b depends on a → apply a, b, c.
        let catalog = vec![
            ("a".into(), make_manifest("a", &[], &[])),
            ("b".into(), make_manifest("b", &["a"], &[])),
            ("c".into(), make_manifest("c", &["b"], &[])),
        ];
        let host = host_with(&["a", "b", "c"]);
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let order: Vec<_> = active.iter().map(|a| a.slug.as_str()).collect();
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn resolver_orders_independent_modules_alphabetically() {
        // No deps anywhere — order is stable / alphabetical.
        let catalog = vec![
            ("zeta".into(), make_manifest("zeta", &[], &[])),
            ("alpha".into(), make_manifest("alpha", &[], &[])),
            ("mu".into(), make_manifest("mu", &[], &[])),
        ];
        let host = host_with(&["zeta", "alpha", "mu"]);
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let order: Vec<_> = active.iter().map(|a| a.slug.as_str()).collect();
        assert_eq!(order, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn resolver_rejects_missing_dep() {
        let catalog = vec![("b".into(), make_manifest("b", &["a"], &[]))];
        let host = host_with(&["b"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("depends on `a`"), "got: {err}");
    }

    #[test]
    fn resolver_rejects_conflict() {
        let catalog = vec![
            ("x".into(), make_manifest("x", &[], &["y"])),
            ("y".into(), make_manifest("y", &[], &[])),
        ];
        let host = host_with(&["x", "y"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("conflicts with"), "got: {err}");
    }

    #[test]
    fn resolver_rejects_cycle() {
        let catalog = vec![
            ("a".into(), make_manifest("a", &["b"], &[])),
            ("b".into(), make_manifest("b", &["a"], &[])),
        ];
        let host = host_with(&["a", "b"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("dependency cycle"), "got: {err}");
    }

    #[test]
    fn resolver_rejects_unknown_active_module() {
        let catalog = vec![("a".into(), make_manifest("a", &[], &[]))];
        let host = host_with(&["a", "ghost"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("active module `ghost`"), "got: {err}");
    }

    // -- runner ------------------------------------------------------

    fn write_stub_module(catalog: &Path, slug: &str, apply_body: &str) -> ActiveModule {
        let mdir = catalog.join(slug);
        std::fs::create_dir_all(mdir.join("install")).unwrap();
        let apply_path = mdir.join("install/apply.sh");
        std::fs::write(&apply_path, apply_body).unwrap();
        let mut perms = std::fs::metadata(&apply_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&apply_path, perms).unwrap();

        let manifest_body = format!(
            "name = \"{slug}\"\nversion = \"0.0.0\"\nsummary = \"t\"\n\n[install]\nkind = \"script\"\napply = \"install/apply.sh\"\n"
        );
        std::fs::write(mdir.join("module.toml"), manifest_body).unwrap();

        let manifest: ModuleManifest =
            toml::from_str(&std::fs::read_to_string(mdir.join("module.toml")).unwrap()).unwrap();
        ActiveModule {
            slug: slug.to_string(),
            module_root: mdir.clone(),
            config_path: mdir.join("config.toml"),
            manifest,
        }
    }

    #[test]
    fn runner_captures_ok_status() {
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\necho '{\"module\":\"sample\",\"status\":\"ok\",\"message\":\"applied 2 changes\"}'\n";
        let active = write_stub_module(catalog.path(), "sample", body);
        let outcome = run_one(&active, Action::Apply, /*dry_run*/ false).unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Ok);
        assert_eq!(outcome.message, "applied 2 changes");
    }

    #[test]
    fn runner_surfaces_failure_when_script_exits_nonzero_even_if_status_ok() {
        // Defence-in-depth: a script that prints "ok" but exits non-zero
        // is treated as failed.
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\necho '{\"module\":\"sneaky\",\"status\":\"ok\",\"message\":\"lying\"}'\nexit 1\n";
        let active = write_stub_module(catalog.path(), "sneaky", body);
        let outcome = run_one(&active, Action::Apply, false).unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
    }

    #[test]
    fn runner_rejects_status_emitted_for_wrong_module() {
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\necho '{\"module\":\"other\",\"status\":\"ok\",\"message\":\"\"}'\n";
        let active = write_stub_module(catalog.path(), "thismodule", body);
        let err = run_one(&active, Action::Apply, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing"), "got: {err}");
    }

    #[test]
    fn runner_propagates_dry_run_env() {
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\nif [[ \"$SELFDEF_DRY_RUN\" == \"1\" ]]; then echo '{\"module\":\"envcheck\",\"status\":\"skipped\",\"message\":\"dry-run\"}'; else echo '{\"module\":\"envcheck\",\"status\":\"ok\",\"message\":\"live\"}'; fi\n";
        let active = write_stub_module(catalog.path(), "envcheck", body);
        let dry = run_one(&active, Action::Apply, true).unwrap();
        assert_eq!(dry.status, OutcomeStatus::Skipped);
        assert_eq!(dry.message, "dry-run");
        let live = run_one(&active, Action::Apply, false).unwrap();
        assert_eq!(live.status, OutcomeStatus::Ok);
        assert_eq!(live.message, "live");
    }

    #[test]
    fn runner_exposes_config_path_via_env() {
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\necho \"{\\\"module\\\":\\\"cfgcheck\\\",\\\"status\\\":\\\"ok\\\",\\\"message\\\":\\\"$SELFDEF_CFGCHECK_CONFIG\\\"}\"\n";
        let active = write_stub_module(catalog.path(), "cfgcheck", body);
        let outcome = run_one(&active, Action::Apply, false).unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Ok);
        assert_eq!(outcome.message, active.config_path.display().to_string());
    }

    #[test]
    fn runner_synthesises_failure_when_no_status_line() {
        let catalog = tempfile::tempdir().unwrap();
        let body = "#!/usr/bin/env bash\necho hi >&2\nexit 7\n";
        let active = write_stub_module(catalog.path(), "noisy", body);
        let outcome = run_one(&active, Action::Apply, false).unwrap();
        assert_eq!(outcome.status, OutcomeStatus::Failed);
        assert!(
            outcome.message.contains("exit=Some(7)"),
            "got: {}",
            outcome.message
        );
    }
}
