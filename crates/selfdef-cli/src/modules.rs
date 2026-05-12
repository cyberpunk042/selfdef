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
//! config files default to `/etc/selfdef/modules/<slug>.toml` (or
//! `<slug>.<instance>.toml` for multi-instance modules) and are
//! passed to scripts via the existing `SELFDEF_<SLUG>_CONFIG` env
//! convention.
//!
//! Multi-instance: a module's manifest opts in with
//! `instanced = true`. A host can then declare it multiple times
//! under different `[modules."<slug>#<instance>"]` keys. Manifest
//! `depends_on` / `conflicts` are slug-level — any active instance of
//! the depended-on slug satisfies the dependency.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::Deserialize;

const SYSTEM_MODULES_DIR: &str = "/usr/share/selfdef/modules";
const DEFAULT_HOST_CONFIG: &str = "/etc/selfdef/modules.toml";
const DEFAULT_PER_MODULE_DIR: &str = "/etc/selfdef/modules";

/// Apply-order bucket. Modules in `pre` run before any `main` module;
/// `post` runs after all `main` modules. Within a bucket the existing
/// `depends_on` topo sort applies. Default is `main` so existing
/// manifests carry over unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Phase {
    Pre,
    Main,
    Post,
}

impl Default for Phase {
    fn default() -> Self {
        Self::Main
    }
}

impl Phase {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::Main => "main",
            Self::Post => "post",
        }
    }
}

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
    /// If true, multiple host-config entries may activate this module
    /// under different `slug#instance` keys. Default false: only one
    /// `[modules.<slug>]` block per host.
    #[serde(default)]
    pub(crate) instanced: bool,
    /// Apply-order bucket: `pre` runs before `main`, `post` runs
    /// after. Default `main` so existing manifests carry over.
    #[serde(default)]
    pub(crate) phase: Phase,
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
    if m.instanced {
        println!("instanced: true (multiple host entries allowed via slug#instance)");
    }
    // Only mention `phase` when it diverges from the default; saying
    // "phase: main" for every module would just be noise.
    if m.phase != Phase::default() {
        println!("phase:    {}", m.phase.as_str());
    }
    Ok(())
}

// ---------------------------------------------------------------- host config
//
// /etc/selfdef/modules.toml — declares which modules are active on
// this host and (optionally) overrides per-module config paths.
//
//   # Single-instance (the normal case):
//   [modules.detect-host]
//   [modules.bridge-l2]
//
//   # Multi-instance (manifest must declare `instanced = true`):
//   [modules."vpn-bridge#overlay"]
//   config = "/etc/selfdef/modules/vpn-bridge.overlay.toml"
//   [modules."vpn-bridge#publish"]
//   config = "/etc/selfdef/modules/vpn-bridge.publish.toml"

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
    // Validate each key parses into (slug, instance?) cleanly. Whether
    // a given module accepts instance suffixes at all is the resolver's
    // concern (it needs the manifest); here we only check syntax.
    for key in cfg.modules.keys() {
        parse_host_key(key)
            .with_context(|| format!("invalid module key in {}: `{key}`", path.display()))?;
    }
    Ok(cfg)
}

/// Split a host-config key into (slug, optional instance).
///
/// Grammar:
///   key      ::= slug ("#" instance)?
///   slug     ::= [a-zA-Z0-9][a-zA-Z0-9-]*
///   instance ::= [a-zA-Z0-9][a-zA-Z0-9-]*
///
/// Single-instance: "vpn-bridge"           → ("vpn-bridge", None)
/// Multi-instance:  "vpn-bridge#tunnel"    → ("vpn-bridge", Some("tunnel"))
pub(crate) fn parse_host_key(key: &str) -> Result<(String, Option<String>)> {
    fn valid_part(s: &str) -> bool {
        !s.is_empty()
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
    }
    if let Some((slug, instance)) = key.split_once('#') {
        if !valid_part(slug) {
            anyhow::bail!("slug part `{slug}` has invalid characters");
        }
        if !valid_part(instance) {
            anyhow::bail!("instance part `{instance}` has invalid characters");
        }
        if key.matches('#').count() > 1 {
            anyhow::bail!("more than one `#` in key");
        }
        Ok((slug.to_string(), Some(instance.to_string())))
    } else {
        if !valid_part(key) {
            anyhow::bail!("invalid characters");
        }
        Ok((key.to_string(), None))
    }
}

/// An active module after resolving against the catalog: ready to run.
#[derive(Debug)]
pub(crate) struct ActiveModule {
    pub(crate) slug: String,
    /// `None` for single-instance modules, `Some("tunnel")` for the
    /// `[modules."vpn-bridge#tunnel"]` host entry.
    pub(crate) instance: Option<String>,
    pub(crate) module_root: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) manifest: ModuleManifest,
}

impl ActiveModule {
    /// Display name for logs / output. `slug` for single-instance,
    /// `slug#instance` for multi-instance.
    pub(crate) fn display_name(&self) -> String {
        match &self.instance {
            Some(i) => format!("{}#{i}", self.slug),
            None => self.slug.clone(),
        }
    }
}

/// Resolve the host's active modules against a catalog. Returns the
/// list in **dependency-applied order** at the slug level; instances
/// of the same slug are expanded alphabetically by instance name.
/// Errors on: missing deps, conflicts, dependency cycles, unknown
/// slugs, illegal use of multi-instance suffixes against modules not
/// marked `instanced`, or mixed single/multi blocks for one slug.
pub(crate) fn resolve_active(
    host: &HostConfig,
    catalog_dir: &Path,
    catalog: Vec<(String, ModuleManifest)>,
) -> Result<Vec<ActiveModule>> {
    let mut by_slug: HashMap<String, ModuleManifest> = catalog.into_iter().collect();

    // 1. Parse every host key into (slug, instance?). Group by slug.
    //    `BTreeMap` + alphabetical Vec keeps everything deterministic.
    let mut grouped: BTreeMap<String, Vec<(Option<String>, HostModuleEntry)>> = BTreeMap::new();
    for (key, entry) in &host.modules {
        let (slug, instance) =
            parse_host_key(key).with_context(|| format!("parsing host key `{key}`"))?;
        grouped
            .entry(slug)
            .or_default()
            .push((instance, entry.clone()));
    }
    for v in grouped.values_mut() {
        v.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // 2. Each active slug must exist in the catalog.
    for slug in grouped.keys() {
        if !by_slug.contains_key(slug) {
            anyhow::bail!(
                "active module `{slug}` not found in catalog {}",
                catalog_dir.display()
            );
        }
    }

    // 3. Enforce instancing rules. A slug is either single-instance
    //    (exactly one entry with `instance == None`) or multi-instance
    //    (every entry has an instance, and the manifest opted in via
    //    `instanced = true`). Mixing is an error in either direction.
    for (slug, entries) in &grouped {
        let manifest = &by_slug[slug];
        let any_instanced = entries.iter().any(|(i, _)| i.is_some());
        let any_flat = entries.iter().any(|(i, _)| i.is_none());

        if any_instanced && any_flat {
            anyhow::bail!(
                "module `{slug}` is configured with both flat and `#instance` keys — pick one"
            );
        }
        if any_instanced && !manifest.instanced {
            anyhow::bail!(
                "module `{slug}` is not declared `instanced = true` in its manifest — \
                 `#instance` keys are not allowed"
            );
        }
        if any_flat && entries.len() > 1 {
            // Should be impossible (BTreeMap dedupes identical keys),
            // but guard against any future structural change.
            anyhow::bail!("module `{slug}` has duplicate single-instance entries");
        }
        if any_instanced {
            // Refuse duplicate instance names.
            let mut seen = std::collections::HashSet::new();
            for (i, _) in entries {
                let name = i.as_deref().unwrap();
                if !seen.insert(name) {
                    anyhow::bail!("module `{slug}` has duplicate instance `{name}`");
                }
            }
        }
    }

    // 4. Conflicts: any active instance of A whose manifest lists B as
    //    a conflict refuses any active instance of B.
    for slug in grouped.keys() {
        let m = &by_slug[slug];
        for c in &m.conflicts {
            if grouped.contains_key(c) {
                anyhow::bail!("module `{slug}` conflicts with active module `{c}`");
            }
        }
    }

    // 5. Missing deps: each declared dep slug must have ≥1 active
    //    instance. Manifest deps are slug-level, not instance-level.
    //    Cross-phase deps are forbidden in the backward direction: a
    //    `pre` module cannot depend on a `main`/`post` module, etc.
    for slug in grouped.keys() {
        let m = &by_slug[slug];
        for d in &m.depends_on {
            let dep_m = match by_slug.get(d) {
                Some(x) => x,
                None => anyhow::bail!("module `{slug}` depends on `{d}` which is not in catalog"),
            };
            if !grouped.contains_key(d) {
                anyhow::bail!("module `{slug}` depends on `{d}` which is not active");
            }
            if dep_m.phase > m.phase {
                anyhow::bail!(
                    "module `{slug}` (phase {}) depends on `{d}` (phase {}) — \
                     a dependency cannot run in a later phase",
                    m.phase.as_str(),
                    dep_m.phase.as_str(),
                );
            }
        }
    }

    // 6. Topo sort at the slug level, bucketed by phase. Pre → Main →
    //    Post. Within each phase, deps within that phase determine
    //    order; ties break alphabetically. Cross-phase deps are
    //    already validated above (must go backward only).
    let mut slug_order: Vec<String> = Vec::new();
    for phase in [Phase::Pre, Phase::Main, Phase::Post] {
        let phase_slugs: BTreeSet<&str> = grouped
            .keys()
            .filter(|s| by_slug[*s].phase == phase)
            .map(String::as_str)
            .collect();
        if phase_slugs.is_empty() {
            continue;
        }
        let mut indeg: HashMap<&str, usize> = phase_slugs.iter().map(|s| (*s, 0)).collect();
        for slug in &phase_slugs {
            let m = &by_slug[*slug];
            for d in &m.depends_on {
                // Only count edges within the same phase — cross-phase
                // deps go backward and are already implicitly ordered.
                if phase_slugs.contains(d.as_str()) {
                    *indeg.get_mut(*slug).unwrap() += 1;
                }
            }
        }
        let mut ready: Vec<&str> = indeg
            .iter()
            .filter(|(_, n)| **n == 0)
            .map(|(s, _)| *s)
            .collect();
        ready.sort_unstable_by(|a, b| b.cmp(a)); // pop yields alphabetical
        let mut phase_order: Vec<String> = Vec::with_capacity(phase_slugs.len());
        while let Some(next) = ready.pop() {
            phase_order.push(next.to_string());
            let mut newly_ready: Vec<&str> = Vec::new();
            for slug in &phase_slugs {
                let m = &by_slug[*slug];
                if m.depends_on.iter().any(|d| d == next) {
                    let e = indeg.get_mut(*slug).unwrap();
                    *e -= 1;
                    if *e == 0 {
                        newly_ready.push(*slug);
                    }
                }
            }
            for s in newly_ready {
                ready.push(s);
            }
            ready.sort_unstable_by(|a, b| b.cmp(a));
        }
        if phase_order.len() != phase_slugs.len() {
            let leftover: Vec<String> = phase_slugs
                .iter()
                .filter(|s| !phase_order.contains(&(*s).to_string()))
                .map(|s| (*s).to_string())
                .collect();
            anyhow::bail!(
                "dependency cycle in phase {} among: {}",
                phase.as_str(),
                leftover.join(", ")
            );
        }
        slug_order.extend(phase_order);
    }

    // 7. Materialise: walk slug_order, expand each slug's instance
    //    list alphabetically. The manifest is identical across
    //    instances of the same slug, so we clone it per ActiveModule.
    let mut out = Vec::new();
    for slug in slug_order {
        let entries = grouped.remove(&slug).expect("present in grouped");
        let manifest_template = by_slug.remove(&slug).expect("present in catalog");
        let module_root = catalog_dir.join(&slug);
        for (instance, entry) in entries {
            let config_path = entry
                .config
                .clone()
                .unwrap_or_else(|| default_config_path(&slug, instance.as_deref()));
            out.push(ActiveModule {
                slug: slug.clone(),
                instance,
                module_root: module_root.clone(),
                config_path,
                manifest: clone_manifest(&manifest_template),
            });
        }
    }
    Ok(out)
}

fn default_config_path(slug: &str, instance: Option<&str>) -> PathBuf {
    let fname = match instance {
        Some(i) => format!("{slug}.{i}.toml"),
        None => format!("{slug}.toml"),
    };
    PathBuf::from(DEFAULT_PER_MODULE_DIR).join(fname)
}

/// `ModuleManifest` isn't `Clone` because the upstream `Deserialize`
/// derivation didn't need it. For the multi-instance fanout we need
/// one owned manifest per `ActiveModule`; do a field-by-field copy
/// rather than touching the public derive.
fn clone_manifest(m: &ModuleManifest) -> ModuleManifest {
    ModuleManifest {
        name: m.name.clone(),
        version: m.version.clone(),
        summary: m.summary.clone(),
        category: m.category.clone(),
        depends_on: m.depends_on.clone(),
        conflicts: m.conflicts.clone(),
        provides: m.provides.clone(),
        consumes: m.consumes.clone(),
        requires: m
            .requires
            .iter()
            .map(|r| Requirement {
                kind: r.kind.clone(),
                value: r.value.clone(),
            })
            .collect(),
        install: m.install.as_ref().map(|i| InstallSpec {
            kind: i.kind.clone(),
            package: i.package.clone(),
            apply: i.apply.clone(),
            check: i.check.clone(),
            uninstall: i.uninstall.clone(),
        }),
        profiles: m.profiles.as_ref().map(|p| ProfileSpec {
            default: p.default.clone(),
            available: p.available.clone(),
        }),
        instanced: m.instanced,
        phase: m.phase,
    }
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
    pub(crate) instance: Option<String>,
    pub(crate) status: OutcomeStatus,
    pub(crate) message: String,
    pub(crate) raw_stderr: String,
}

impl Outcome {
    pub(crate) fn display_name(&self) -> String {
        match &self.instance {
            Some(i) => format!("{}#{i}", self.slug),
            None => self.slug.clone(),
        }
    }
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
        instance: active.instance.clone(),
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
    // `--only vpn-bridge` matches every active instance of vpn-bridge;
    // `--only vpn-bridge#tunnel` matches only that one. Same for
    // `--except`. So we check both forms.
    let matches = |a: &ActiveModule, set: &HashSet<&str>| -> bool {
        set.contains(a.slug.as_str()) || set.contains(a.display_name().as_str())
    };
    let only: HashSet<&str> = only.iter().map(String::as_str).collect();
    let except: HashSet<&str> = except.iter().map(String::as_str).collect();
    active
        .into_iter()
        .filter(|a| {
            if !only.is_empty() && !matches(a, &only) {
                return false;
            }
            if matches(a, &except) {
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
    run_lifecycle(opts, Action::Apply, LifecyclePolicy::default())
}

pub(crate) fn cmd_check(opts: &LifecycleOpts) -> Result<i32> {
    // `check` never mutates — force dry_run off (it's a no-op for
    // check scripts but keeps the env consistent).
    let mut o = opts.clone();
    o.dry_run = false;
    run_lifecycle(&o, Action::Check, LifecyclePolicy::default())
}

pub(crate) fn cmd_status(opts: &LifecycleOpts) -> Result<i32> {
    // Status is a pretty-printed check; same machinery, different header.
    let mut o = opts.clone();
    o.dry_run = false;
    run_lifecycle(&o, Action::Check, LifecyclePolicy::default())
}

pub(crate) fn cmd_uninstall(opts: &LifecycleOpts) -> Result<i32> {
    // Tear-down order is the inverse of apply order: any module that
    // depended on `X` must come down before `X` does. Modules that
    // never declared an uninstall script (or are package-installed) are
    // surfaced as `skipped` so an op-wide uninstall is still useful
    // even when some manifests didn't bother with rollback.
    run_lifecycle(
        opts,
        Action::Uninstall,
        LifecyclePolicy {
            reverse_order: true,
            tolerate_missing_script: true,
        },
    )
}

/// Knobs that distinguish `apply` / `check` from `uninstall` without
/// duplicating the runner body.
#[derive(Debug, Default, Clone, Copy)]
struct LifecyclePolicy {
    /// Walk modules in reverse dependency-applied order. Used for
    /// `uninstall` so dependents come down before the things they
    /// depended on.
    reverse_order: bool,
    /// When the manifest doesn't declare a script for the chosen
    /// action, treat it as `skipped` rather than a hard error.
    tolerate_missing_script: bool,
}

fn module_has_script(active: &ActiveModule, action: Action) -> bool {
    active
        .manifest
        .install
        .as_ref()
        .and_then(|i| action.script_relpath(i))
        .is_some()
}

fn run_lifecycle(opts: &LifecycleOpts, action: Action, policy: LifecyclePolicy) -> Result<i32> {
    let (host_path, mut active) = prepare(opts)?;
    if policy.reverse_order {
        active.reverse();
    }
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
        let label = format!("{} [{}]", a.display_name(), action.name());
        print!("  {label} ... ");
        let outcome = if policy.tolerate_missing_script && !module_has_script(a, action) {
            Outcome {
                slug: a.slug.clone(),
                instance: a.instance.clone(),
                status: OutcomeStatus::Skipped,
                message: format!("no {} script declared", action.name()),
                raw_stderr: String::new(),
            }
        } else {
            run_one(a, action, opts.dry_run)?
        };
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
            eprintln!("--- {} stderr ---", f.display_name());
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
    fn host_config_accepts_instance_suffix_syntax() {
        // Parse-time: `slug#instance` keys are syntactically valid.
        // Whether the slug's manifest allows them is checked at
        // resolve-time, not here.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("modules.toml");
        std::fs::write(&p, "[modules.\"vpn-bridge#tunnel\"]\n").unwrap();
        let cfg = load_host_config(&p).unwrap();
        assert!(cfg.modules.contains_key("vpn-bridge#tunnel"));
    }

    #[test]
    fn host_config_rejects_bad_slug_chars() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("modules.toml");
        std::fs::write(&p, "[modules.\"weird name\"]\n").unwrap();
        let err = load_host_config(&p).unwrap_err().to_string();
        // Wrapped through parse_host_key's "invalid characters" error.
        assert!(
            err.contains("invalid module key") || err.contains("invalid characters"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_host_key_round_trips() {
        let (s, i) = parse_host_key("vpn-bridge").unwrap();
        assert_eq!(s, "vpn-bridge");
        assert_eq!(i, None);
        let (s, i) = parse_host_key("vpn-bridge#tunnel").unwrap();
        assert_eq!(s, "vpn-bridge");
        assert_eq!(i.as_deref(), Some("tunnel"));
    }

    #[test]
    fn parse_host_key_rejects_double_hash() {
        let err = parse_host_key("a#b#c").unwrap_err().to_string();
        assert!(
            err.contains("invalid characters") || err.contains("more than one"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_host_key_rejects_empty_instance() {
        let err = parse_host_key("vpn-bridge#").unwrap_err().to_string();
        assert!(err.contains("instance part"), "got: {err}");
    }

    // -- helpers for resolver / runner tests -------------------------

    fn make_manifest(name: &str, deps: &[&str], conflicts: &[&str]) -> ModuleManifest {
        make_manifest_full(name, deps, conflicts, /*instanced*/ false, Phase::Main)
    }

    fn make_manifest_full(
        name: &str,
        deps: &[&str],
        conflicts: &[&str],
        instanced: bool,
        phase: Phase,
    ) -> ModuleManifest {
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
            instanced,
            phase,
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

    // -- phase ------------------------------------------------------

    #[test]
    fn phase_default_is_main() {
        // A manifest without `phase = "..."` parses as Phase::Main.
        let toml_body = "name = \"x\"\nversion = \"1\"\nsummary = \"y\"\n";
        let m: ModuleManifest = toml::from_str(toml_body).unwrap();
        assert_eq!(m.phase, Phase::Main);
    }

    #[test]
    fn phase_parses_pre_main_post() {
        for s in ["pre", "main", "post"] {
            let body = format!("name = \"x\"\nversion = \"1\"\nsummary = \"y\"\nphase = \"{s}\"\n");
            let m: ModuleManifest = toml::from_str(&body).unwrap();
            assert_eq!(m.phase.as_str(), s);
        }
    }

    #[test]
    fn phase_rejects_unknown_value() {
        let body = "name = \"x\"\nversion = \"1\"\nsummary = \"y\"\nphase = \"midway\"\n";
        let err = toml::from_str::<ModuleManifest>(body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("phase"), "got: {err}");
    }

    #[test]
    fn resolver_pre_runs_before_main_runs_before_post() {
        let catalog = vec![
            (
                "alpha".into(),
                make_manifest_full("alpha", &[], &[], false, Phase::Main),
            ),
            (
                "guard".into(),
                make_manifest_full("guard", &[], &[], false, Phase::Pre),
            ),
            (
                "audit".into(),
                make_manifest_full("audit", &[], &[], false, Phase::Post),
            ),
            (
                "beta".into(),
                make_manifest_full("beta", &[], &[], false, Phase::Main),
            ),
        ];
        let host = host_with(&["alpha", "audit", "beta", "guard"]);
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let order: Vec<_> = active.iter().map(|a| a.slug.as_str()).collect();
        // pre (guard) → main (alpha, beta alphabetical) → post (audit).
        assert_eq!(order, vec!["guard", "alpha", "beta", "audit"]);
    }

    #[test]
    fn resolver_rejects_dep_pointing_to_later_phase() {
        // A `pre` module depending on a `main` module would force the
        // `main` module to run first — violating the phase order.
        let catalog = vec![
            (
                "guard".into(),
                make_manifest_full("guard", &["alpha"], &[], false, Phase::Pre),
            ),
            (
                "alpha".into(),
                make_manifest_full("alpha", &[], &[], false, Phase::Main),
            ),
        ];
        let host = host_with(&["guard", "alpha"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("phase pre") && err.contains("phase main"),
            "got: {err}"
        );
    }

    #[test]
    fn resolver_allows_dep_pointing_to_earlier_phase() {
        // `main` → `pre` is fine: pre runs first anyway.
        let catalog = vec![
            (
                "alpha".into(),
                make_manifest_full("alpha", &["guard"], &[], false, Phase::Main),
            ),
            (
                "guard".into(),
                make_manifest_full("guard", &[], &[], false, Phase::Pre),
            ),
        ];
        let host = host_with(&["alpha", "guard"]);
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let order: Vec<_> = active.iter().map(|a| a.slug.as_str()).collect();
        assert_eq!(order, vec!["guard", "alpha"]);
    }

    #[test]
    fn resolver_cycle_within_phase_is_caught() {
        let catalog = vec![
            (
                "a".into(),
                make_manifest_full("a", &["b"], &[], false, Phase::Pre),
            ),
            (
                "b".into(),
                make_manifest_full("b", &["a"], &[], false, Phase::Pre),
            ),
        ];
        let host = host_with(&["a", "b"]);
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cycle in phase pre"), "got: {err}");
    }

    // -- multi-instance --------------------------------------------

    fn host_from_toml(body: &str) -> HostConfig {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.toml");
        std::fs::write(&p, body).unwrap();
        load_host_config(&p).unwrap()
    }

    #[test]
    fn resolver_supports_multi_instance_for_instanced_modules() {
        let catalog = vec![(
            "vpn-bridge".into(),
            make_manifest_full("vpn-bridge", &[], &[], /*instanced*/ true, Phase::Main),
        )];
        let host =
            host_from_toml("[modules.\"vpn-bridge#tunnel\"]\n[modules.\"vpn-bridge#publish\"]\n");
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let names: Vec<_> = active.iter().map(ActiveModule::display_name).collect();
        // Alphabetical within the slug.
        assert_eq!(names, vec!["vpn-bridge#publish", "vpn-bridge#tunnel"]);
        // Default config paths include the instance suffix.
        assert!(
            active[0]
                .config_path
                .display()
                .to_string()
                .ends_with("vpn-bridge.publish.toml")
        );
        assert!(
            active[1]
                .config_path
                .display()
                .to_string()
                .ends_with("vpn-bridge.tunnel.toml")
        );
    }

    #[test]
    fn resolver_rejects_instance_for_non_instanced_module() {
        let catalog = vec![(
            "detect-host".into(),
            make_manifest_full(
                "detect-host",
                &[],
                &[],
                /*instanced*/ false,
                Phase::Main,
            ),
        )];
        let host = host_from_toml("[modules.\"detect-host#a\"]\n");
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not declared `instanced = true`"),
            "got: {err}"
        );
    }

    #[test]
    fn resolver_rejects_mixed_flat_and_instance_keys_for_same_slug() {
        let catalog = vec![(
            "vpn-bridge".into(),
            make_manifest_full("vpn-bridge", &[], &[], true, Phase::Main),
        )];
        let host = host_from_toml("[modules.\"vpn-bridge\"]\n[modules.\"vpn-bridge#tunnel\"]\n");
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(err.contains("both flat and `#instance` keys"), "got: {err}");
    }

    #[test]
    fn resolver_depends_on_is_slug_level_and_satisfied_by_any_instance() {
        // bridge-l2 (single) → suricata (multi-instance with two instances).
        let catalog = vec![
            (
                "bridge-l2".into(),
                make_manifest_full("bridge-l2", &[], &[], false, Phase::Main),
            ),
            (
                "suricata".into(),
                make_manifest_full("suricata", &["bridge-l2"], &[], true, Phase::Main),
            ),
        ];
        let host = host_from_toml(
            "[modules.\"bridge-l2\"]\n\
             [modules.\"suricata#wan\"]\n\
             [modules.\"suricata#lan\"]\n",
        );
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let names: Vec<_> = active.iter().map(ActiveModule::display_name).collect();
        // bridge-l2 first (depends_on), then suricata's two instances
        // alphabetically.
        assert_eq!(names, vec!["bridge-l2", "suricata#lan", "suricata#wan"]);
    }

    #[test]
    fn resolver_per_instance_config_override_wins() {
        let catalog = vec![(
            "vpn-bridge".into(),
            make_manifest_full("vpn-bridge", &[], &[], true, Phase::Main),
        )];
        let host =
            host_from_toml("[modules.\"vpn-bridge#tunnel\"]\nconfig = \"/custom/path.toml\"\n");
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].config_path, PathBuf::from("/custom/path.toml"));
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
            instance: None,
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

    // -- uninstall --------------------------------------------------

    #[test]
    fn module_has_script_reflects_manifest() {
        // Manifest declares `apply` but not `uninstall` → only apply
        // is considered present.
        let catalog = tempfile::tempdir().unwrap();
        let body =
            "#!/usr/bin/env bash\necho '{\"module\":\"only-apply\",\"status\":\"ok\",\"message\":\"\"}'\n";
        let active = write_stub_module(catalog.path(), "only-apply", body);
        assert!(module_has_script(&active, Action::Apply));
        assert!(!module_has_script(&active, Action::Uninstall));
    }

    #[test]
    fn uninstall_runs_in_reverse_apply_order() {
        // alpha → beta dep chain: apply order is alpha, beta;
        // uninstall must walk beta first so dependents come down
        // before what they depended on.
        let catalog = vec![
            ("alpha".into(), make_manifest("alpha", &[], &[])),
            ("beta".into(), make_manifest("beta", &["alpha"], &[])),
        ];
        let host = host_with(&["alpha", "beta"]);
        let mut active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        let apply_order: Vec<_> = active.iter().map(|a| a.slug.clone()).collect();
        assert_eq!(apply_order, vec!["alpha", "beta"]);
        active.reverse();
        let uninstall_order: Vec<_> = active.iter().map(|a| a.slug.clone()).collect();
        assert_eq!(uninstall_order, vec!["beta", "alpha"]);
    }

    #[test]
    fn uninstall_reverses_phase_order() {
        // Apply walks pre → main → post; uninstall must walk
        // post → main → pre.
        let catalog = vec![
            (
                "guard".into(),
                make_manifest_full("guard", &[], &[], false, Phase::Pre),
            ),
            (
                "alpha".into(),
                make_manifest_full("alpha", &[], &[], false, Phase::Main),
            ),
            (
                "audit".into(),
                make_manifest_full("audit", &[], &[], false, Phase::Post),
            ),
        ];
        let host = host_with(&["guard", "alpha", "audit"]);
        let mut active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        active.reverse();
        let order: Vec<_> = active.iter().map(|a| a.slug.clone()).collect();
        assert_eq!(order, vec!["audit", "alpha", "guard"]);
    }
}
