//! `selfdefctl modules` — read-only module-catalog inspector.
//!
//! Loads `module.toml` manifests from the modules directory and prints
//! their summary or full contents. Apply / enable / disable land in a
//! later milestone; this file is the surface the operator will already
//! be familiar with when those arrive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

const SYSTEM_MODULES_DIR: &str = "/usr/share/selfdef/modules";

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

// `check` and `uninstall` are part of the manifest contract; they're
// read by the future `modules apply` / `modules status` paths, not by
// the read-only commands in this PR.
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
