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
// F-2027-017: import the canonical paths from `crate::paths`
// instead of redefining `/etc/selfdef/...` locally. The two
// constants below are kept as aliases for crate-internal call
// sites (low-friction rename) but point at the same string.
const DEFAULT_HOST_CONFIG: &str = crate::paths::MODULES_HOST_CONFIG;
const DEFAULT_PER_MODULE_DIR: &str = crate::paths::MODULES_PER_MODULE_DIR;

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
    /// SD-R14: hardware requirements gate. Module is SKIPPED at
    /// apply-time when any declared requirement isn't met. Empty
    /// (default) means the module is always applied.
    ///
    /// Operator-stable; consumed by `cmd_apply` via
    /// [`hardware_requirements_met`].
    #[serde(default)]
    pub(crate) requires_hardware: HardwareRequirements,
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
    /// Daemon-side config expectations (SDD-002). Each entry is a
    /// dotted key path under `/etc/selfdef/selfdef.toml` plus the
    /// expected scalar or array value. Values may reference
    /// same-module config keys via `${key}` substitution. The
    /// validator runs before any apply.sh fires and refuses to
    /// proceed on mismatch unless `--ignore-daemon-requires` is
    /// passed.
    #[serde(default)]
    pub(crate) daemon_requires: BTreeMap<String, DaemonRequirement>,
}

/// Expected value for one daemon-config knob. Backed by an untagged
/// enum so a manifest can write either a scalar
/// (`"collectors.tetragon.enabled" = true`) or an array
/// (`"collectors.eventstream.paths" = ["/path/a", "/path/b"]`) and
/// the validator interprets array-typed entries as set-inclusion
/// (the daemon's actual array must contain every element here).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum DaemonRequirement {
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<String>),
}

impl DaemonRequirement {
    /// Render this requirement as the right-hand-side of a TOML
    /// assignment for the snippet shown to operators.
    fn render_value(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => n.to_string(),
            Self::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            Self::Array(v) => {
                let mut out = String::from("[");
                for (i, item) in v.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push('"');
                    out.push_str(&item.replace('"', "\\\""));
                    out.push('"');
                }
                out.push(']');
                out
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Requirement {
    pub(crate) kind: String,
    pub(crate) value: String,
}

/// SD-R14: hardware-aware module gating.
///
/// A module's `[requires_hardware]` table declares minimum host
/// hardware. The apply path skips modules that don't meet the bar
/// with a clear log line; operators can override with
/// `--ignore-hardware` (future round) or by editing the module manifest.
#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct HardwareRequirements {
    /// When set, requires `cpu.avx512_vnni = true` in the host's
    /// HardwareCapabilities. Match for ternary-inference fast path
    /// modules (master spec § 16).
    #[serde(default)]
    pub(crate) avx512_vnni: bool,

    /// When set, requires `cpu.avx512_bf16 = true`. Match for
    /// BitNet acceleration modules.
    #[serde(default)]
    pub(crate) avx512_bf16: bool,

    /// Minimum memory in GiB.
    #[serde(default)]
    pub(crate) memory_gib_min: u64,

    /// Minimum count of NVIDIA GPUs. 0 disables the gate.
    #[serde(default)]
    pub(crate) gpu_count_min: u32,

    /// SD-R26: minimum VRAM (GiB) on AT LEAST ONE GPU. Lets a module
    /// declare "I need to fit a model that takes 80 GiB" — passes
    /// when any GPU in HardwareCapabilities.gpu.devices reports
    /// vram_bytes ≥ this. 0 disables the gate.
    ///
    /// Pairs naturally with `gpu_count_min`: combined "needs 2 GPUs
    /// AND at least one with 80 GiB VRAM" lands inference modules
    /// on the SAIN-01 dual-GPU rig (RTX PRO 6000 → 98 GiB).
    #[serde(default)]
    pub(crate) gpu_vram_gib_min: u64,

    /// SD-R26: minimum total power headroom (watts) across ALL GPUs.
    /// Headroom for one GPU = power_limit - power_draw; we sum
    /// across the fleet. Gate disabled when 0. When set, requires
    /// every GPU to expose both `power_limit_watts` AND
    /// `power_draw_watts` (else the predicate fails — modules
    /// asking for headroom assurance must have telemetry).
    ///
    /// Use case: a sustained-load inference module declares
    /// `gpu_power_headroom_watts_min = 200` and only applies on
    /// hosts where adding ~200W won't blow the cap.
    #[serde(default)]
    pub(crate) gpu_power_headroom_watts_min: u32,

    /// SD-R32: required wasm-AOT target features (comma-separated,
    /// `+feature` syntax; sovereign-os pulse/wasm-aot.sh-compatible).
    /// Empty disables the gate. Module passes when EVERY listed
    /// feature appears in
    /// HardwareCapabilities.wasm_aot.target_features.
    ///
    /// Examples (operator surface):
    ///   wasm_aot_features_required = "+avx512f"
    ///   wasm_aot_features_required = "+avx512vnni,+avx512bf16"
    ///
    /// Use case: an AOT-compiled inference module declares
    /// "I need VNNI for INT8 matmul AND BF16 for the activation
    /// reduction stage" — passes on the SAIN-01 9900X, fails on
    /// 9700X (no BF16) before any compile happens.
    #[serde(default)]
    pub(crate) wasm_aot_features_required: String,

    /// Required Sain01Match verdict, when set:
    /// `"FullMatch"` / `"PartialMatch"` / `"NoMatch"` (the last
    /// would be weird — operator should rarely use it).
    #[serde(default)]
    pub(crate) sain01_verdict_min: String,
}

impl HardwareRequirements {
    /// Returns Ok iff every set requirement passes; Err with a list
    /// of unmet predicates otherwise.
    pub(crate) fn evaluate(
        &self,
        caps: &selfdef_hardware::HardwareCapabilities,
    ) -> Result<(), Vec<String>> {
        let mut unmet = Vec::new();
        if self.avx512_vnni && !caps.cpu.avx512vnni {
            unmet.push("avx512_vnni required (host lacks AVX-512 VNNI)".into());
        }
        if self.avx512_bf16 && !caps.cpu.avx512bf16 {
            unmet.push("avx512_bf16 required (host lacks AVX-512 BF16)".into());
        }
        if self.memory_gib_min > 0 {
            let host_gib = caps.memory.total_bytes / (1024 * 1024 * 1024);
            if host_gib < self.memory_gib_min {
                unmet.push(format!(
                    "memory_gib_min = {} (host has {} GiB)",
                    self.memory_gib_min, host_gib,
                ));
            }
        }
        if self.gpu_count_min > 0 && caps.gpu.device_count < self.gpu_count_min {
            unmet.push(format!(
                "gpu_count_min = {} (host has {} GPU(s))",
                self.gpu_count_min, caps.gpu.device_count,
            ));
        }
        if self.gpu_vram_gib_min > 0 {
            // Pass when ANY GPU meets the bar. Uses the SD-R25
            // per-device caps surface; falls back to a fail if the
            // per-device list is empty (probe didn't enrich).
            let want_bytes = self.gpu_vram_gib_min.saturating_mul(1024 * 1024 * 1024);
            let any_big_enough = caps
                .gpu
                .devices
                .iter()
                .any(|d| d.vram_bytes.is_some_and(|b| b >= want_bytes));
            if !any_big_enough {
                let best_gib = caps
                    .gpu
                    .devices
                    .iter()
                    .filter_map(|d| d.vram_bytes)
                    .max()
                    .map(|b| b / (1024 * 1024 * 1024))
                    .unwrap_or(0);
                unmet.push(format!(
                    "gpu_vram_gib_min = {} (host best is {} GiB)",
                    self.gpu_vram_gib_min, best_gib,
                ));
            }
        }
        if self.gpu_power_headroom_watts_min > 0 {
            let mut total_headroom: u32 = 0;
            let mut telemetry_complete = !caps.gpu.devices.is_empty();
            for d in &caps.gpu.devices {
                match (d.power_limit_watts, d.power_draw_watts) {
                    (Some(limit), Some(draw)) => {
                        total_headroom = total_headroom.saturating_add(limit.saturating_sub(draw));
                    }
                    _ => {
                        telemetry_complete = false;
                    }
                }
            }
            if !telemetry_complete {
                unmet.push(format!(
                    "gpu_power_headroom_watts_min = {} (host GPU(s) lack power telemetry — install nvidia-smi + NVML)",
                    self.gpu_power_headroom_watts_min
                ));
            } else if total_headroom < self.gpu_power_headroom_watts_min {
                unmet.push(format!(
                    "gpu_power_headroom_watts_min = {} (host headroom is {} W)",
                    self.gpu_power_headroom_watts_min, total_headroom
                ));
            }
        }
        if !self.wasm_aot_features_required.is_empty() {
            // Build the actual host feature set from the SD-R30
            // wasm_aot.target_features string. Both sides use the
            // `+feature` convention (LLVM/wasmtime). Empty side =
            // host hasn't enabled AOT → every required feature is
            // missing.
            let actual: std::collections::HashSet<&str> = caps
                .wasm_aot
                .target_features
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let missing: Vec<&str> = self
                .wasm_aot_features_required
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter(|f| !actual.contains(f))
                .collect();
            if !missing.is_empty() {
                unmet.push(format!(
                    "wasm_aot_features_required = {:?} (host missing: {})",
                    self.wasm_aot_features_required,
                    missing.join(",")
                ));
            }
        }
        if !self.sain01_verdict_min.is_empty() {
            let actual = match caps.sain01_match.overall {
                selfdef_hardware::Sain01Verdict::FullMatch => "FullMatch",
                selfdef_hardware::Sain01Verdict::PartialMatch => "PartialMatch",
                selfdef_hardware::Sain01Verdict::NoMatch => "NoMatch",
            };
            let rank = |s: &str| match s {
                "FullMatch" => 3,
                "PartialMatch" => 2,
                "NoMatch" => 1,
                _ => 0,
            };
            if rank(actual) < rank(&self.sain01_verdict_min) {
                unmet.push(format!(
                    "sain01_verdict_min = {} (host verdict = {})",
                    self.sain01_verdict_min, actual,
                ));
            }
        }
        if unmet.is_empty() { Ok(()) } else { Err(unmet) }
    }

    /// Returns true if NO requirement is set (the manifest has no
    /// `[requires_hardware]` block, or it has only zero/false fields).
    /// Used to skip the probe entirely on hardware-agnostic modules.
    pub(crate) fn is_empty(&self) -> bool {
        !self.avx512_vnni
            && !self.avx512_bf16
            && self.memory_gib_min == 0
            && self.gpu_count_min == 0
            && self.gpu_vram_gib_min == 0
            && self.gpu_power_headroom_watts_min == 0
            && self.wasm_aot_features_required.is_empty()
            && self.sain01_verdict_min.is_empty()
    }
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
    /// SDD-003 D-1: per-profile metadata. Keyed by profile name
    /// (must appear in `available`). Profiles not listed here
    /// inherit the module-level `instanced` value. Used by
    /// modules where one profile is multi-instance-capable
    /// (vpn-bridge's relay-via-server) and others aren't
    /// (tailscale / cloudflare-tunnel, both singleton-service
    /// workloads).
    #[serde(default)]
    pub(crate) details: BTreeMap<String, ProfileDetails>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct ProfileDetails {
    /// Per-profile override of the module-level `instanced`. If
    /// the module declares `instanced = true` but this profile
    /// is `false`, instance suffixes are refused for this
    /// profile.
    #[serde(default)]
    pub(crate) instanced: Option<bool>,
}

impl ProfileSpec {
    /// Whether the named profile supports multi-instance. Falls
    /// back to the module-level `instanced` when no
    /// `[profiles.details.<name>]` entry exists or its `instanced`
    /// field is absent.
    pub(crate) fn profile_instanced(&self, profile: &str, module_default: bool) -> bool {
        self.details
            .get(profile)
            .and_then(|d| d.instanced)
            .unwrap_or(module_default)
    }
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

/// SD-R40: emit the module manifest as structured JSON (with the
/// SD-R39 host_status verdict inlined). Operator-stable schema for
/// tooling consumers (sovereign-osctl, fleet dashboards, future
/// model-fetcher scripts).
pub(crate) fn cmd_info_json(dir: &Path, slug: &str) -> Result<()> {
    let mods = load_all(dir)?;
    let m = mods
        .iter()
        .find(|(s, _)| s == slug)
        .map(|(_, m)| m)
        .with_context(|| format!("no module named `{slug}` in {}", dir.display()))?;
    let caps = match selfdef_hardware::probe() {
        Ok(snap) => Some(selfdef_hardware::derive_capabilities(&snap)),
        Err(_) => None,
    };
    let host_status_json = if m.requires_hardware.is_empty() {
        serde_json::json!({"verdict": "applies-on-any-host", "unmet": []})
    } else {
        match &caps {
            Some(c) => match m.requires_hardware.evaluate(c) {
                Ok(()) => serde_json::json!({"verdict": "passes", "unmet": []}),
                Err(unmet) => serde_json::json!({"verdict": "skipped", "unmet": unmet}),
            },
            None => serde_json::json!({"verdict": "probe-unavailable", "unmet": []}),
        }
    };
    let rh = &m.requires_hardware;
    let doc = serde_json::json!({
        "schema_version": "1.0.0",
        "name": m.name,
        "version": m.version,
        "summary": m.summary,
        "category": m.category,
        "depends_on": m.depends_on,
        "conflicts": m.conflicts,
        "provides": m.provides,
        "consumes": m.consumes,
        "instanced": m.instanced,
        "phase": m.phase.as_str(),
        "requires_hardware": {
            "is_empty": rh.is_empty(),
            "avx512_vnni": rh.avx512_vnni,
            "avx512_bf16": rh.avx512_bf16,
            "memory_gib_min": rh.memory_gib_min,
            "gpu_count_min": rh.gpu_count_min,
            "gpu_vram_gib_min": rh.gpu_vram_gib_min,
            "gpu_power_headroom_watts_min": rh.gpu_power_headroom_watts_min,
            "wasm_aot_features_required": rh.wasm_aot_features_required,
            "sain01_verdict_min": rh.sain01_verdict_min,
        },
        "host_status": host_status_json,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}

/// SD-R39: probe the host + emit the gate verdict for one module
/// as an inline addendum to cmd_info. Doesn't repeat the manifest
/// body (cmd_info already printed it).
pub(crate) fn cmd_info_host_status(dir: &Path, slug: &str) -> Result<()> {
    let mods = load_all(dir)?;
    let m = mods
        .iter()
        .find(|(s, _)| s == slug)
        .map(|(_, m)| m)
        .with_context(|| format!("no module named `{slug}` in {}", dir.display()))?;
    let caps = match selfdef_hardware::probe() {
        Ok(snap) => Some(selfdef_hardware::derive_capabilities(&snap)),
        Err(_) => None,
    };
    println!();
    println!("host_status:");
    if m.requires_hardware.is_empty() {
        println!("  ✓ no [requires_hardware] block — applies on any host");
        return Ok(());
    }
    match &caps {
        Some(c) => match m.requires_hardware.evaluate(c) {
            Ok(()) => println!("  ✓ all hardware requirements met on this host"),
            Err(unmet) => {
                println!("  ✗ {} predicate(s) unmet:", unmet.len());
                for u in &unmet {
                    println!("      - {u}");
                }
            }
        },
        None => {
            println!("  ? hardware probe unavailable — gate would skip this module");
        }
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
    // SD-R35: surface the [requires_hardware] block when non-empty.
    // Operators inspecting a module via `selfdefctl modules info`
    // should see every predicate the gate will enforce — same
    // visibility as `modules check-hardware` but without running
    // the probe.
    let rh = &m.requires_hardware;
    if !rh.is_empty() {
        println!("requires_hardware:");
        if rh.avx512_vnni {
            println!("  - avx512_vnni = true");
        }
        if rh.avx512_bf16 {
            println!("  - avx512_bf16 = true");
        }
        if rh.memory_gib_min > 0 {
            println!("  - memory_gib_min = {}", rh.memory_gib_min);
        }
        if rh.gpu_count_min > 0 {
            println!("  - gpu_count_min = {}", rh.gpu_count_min);
        }
        if rh.gpu_vram_gib_min > 0 {
            println!("  - gpu_vram_gib_min = {}", rh.gpu_vram_gib_min);
        }
        if rh.gpu_power_headroom_watts_min > 0 {
            println!(
                "  - gpu_power_headroom_watts_min = {}",
                rh.gpu_power_headroom_watts_min
            );
        }
        if !rh.wasm_aot_features_required.is_empty() {
            println!(
                "  - wasm_aot_features_required = \"{}\"",
                rh.wasm_aot_features_required
            );
        }
        if !rh.sain01_verdict_min.is_empty() {
            println!("  - sain01_verdict_min = {}", rh.sain01_verdict_min);
        }
    }
    if !m.daemon_requires.is_empty() {
        println!("daemon_requires:");
        for k in m.daemon_requires.keys() {
            println!("  - {k}");
        }
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
        // SDD-003 D-2: per-profile multi-instance gate. For every
        // instance, peek at its config file to learn which profile
        // it'll run under, then reject if that profile is declared
        // `instanced = false` even though the module-level flag is
        // true. Catches the vpn-bridge case where the manifest
        // promises multi-instance but `tailscale` /
        // `cloudflare-tunnel` profile scripts manage singleton
        // host services that can't be parallelised.
        if any_instanced && manifest.profiles.is_some() {
            for (instance, entry) in entries {
                let inst_name = match instance {
                    Some(n) => n,
                    None => continue, // flat entries don't gate
                };
                let cfg_path = entry
                    .config
                    .clone()
                    .unwrap_or_else(|| default_config_path(slug, Some(inst_name)));
                let profile_name = read_profile_from_config(&cfg_path).unwrap_or_else(|| {
                    manifest
                        .profiles
                        .as_ref()
                        .and_then(|p| p.default.clone())
                        .unwrap_or_default()
                });
                if profile_name.is_empty() {
                    continue;
                }
                let profile_instanced = manifest
                    .profiles
                    .as_ref()
                    .map(|p| p.profile_instanced(&profile_name, manifest.instanced))
                    .unwrap_or(manifest.instanced);
                if !profile_instanced {
                    // F-2027-001: embed the exact copy-pasteable
                    // TOML stanza in the diagnostic so operators
                    // don't have to compose it from prose. The
                    // stanza is what they'd paste into the module
                    // manifest to opt the profile into multi-
                    // instance.
                    anyhow::bail!(
                        "module `{slug}` profile `{profile_name}` does not support \
                         multi-instance (host key `{slug}#{inst_name}` refused). \
                         Either pick a different profile, or opt this profile in by \
                         adding to the module manifest:\n\n\
                         [profiles.details.{profile_name}]\n\
                         instanced = true\n"
                    );
                }
            }
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

/// SDD-003 D-2 helper: read just the `profile = "..."` line from a
/// per-module config file. Returns `None` on any failure (file
/// missing, malformed TOML, no `profile` key); callers fall back
/// to the manifest's profile default.
fn read_profile_from_config(path: &Path) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    let value: toml::Value = toml::from_str(&body).ok()?;
    value
        .get("profile")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
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
            details: p.details.clone(),
        }),
        instanced: m.instanced,
        phase: m.phase,
        daemon_requires: m.daemon_requires.clone(),
        requires_hardware: m.requires_hardware.clone(),
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
/// SDD-006 D-2: resolve the path to the shared module-lib that
/// selfdefctl injects via `SELFDEF_MODULE_LIB` for every spawned
/// script. Precedence:
///   1. Operator override: existing `SELFDEF_MODULE_LIB` env var
///      from the parent process (e.g. for debug runs against a
///      patched copy).
///   2. Workspace-relative path
///      (`$CARGO_MANIFEST_DIR/../../packaging/lib/module-lib.sh`)
///      if that file exists. Catches dev workflow / cargo test
///      / cargo run from the workspace root.
///   3. Installed system path
///      (`/usr/share/selfdef/lib/module-lib.sh`) for `.deb`-shipped
///      installations.
///
/// The function never errors on a missing path — modules that
/// don't source the lib (or carry their own helpers in
/// `install/lib.sh`) won't notice the env var is wrong. Modules
/// that DO source it will surface the failure clearly when bash
/// fails to read the file.
pub(crate) fn resolve_module_lib_path() -> PathBuf {
    if let Some(override_) = std::env::var_os("SELFDEF_MODULE_LIB") {
        return PathBuf::from(override_);
    }
    // CARGO_MANIFEST_DIR is `crates/selfdef-cli/`; the workspace
    // root is two levels up.
    let workspace_lib =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/lib/module-lib.sh");
    if workspace_lib.exists() {
        return workspace_lib;
    }
    PathBuf::from("/usr/share/selfdef/lib/module-lib.sh")
}

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
        .env("SELFDEF_MODULE_LIB", resolve_module_lib_path());
    // SDD-003 D-3: surface the instance suffix to profile scripts
    // so they can parameterise state paths. Absent for
    // single-instance applies — scripts that need it should
    // default sensibly.
    if let Some(inst) = &active.instance {
        cmd.env("SELFDEF_INSTANCE_ID", inst);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

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
    /// Per SDD-002: bypass the daemon_requires pre-flight check.
    /// `selfdefctl modules apply --ignore-daemon-requires` sets
    /// this; otherwise a mismatch with the daemon's
    /// `/etc/selfdef/selfdef.toml` halts the apply with exit 2
    /// and a copy-pasteable snippet.
    pub(crate) ignore_daemon_requires: bool,
    /// SD-R42 (SDD-018 D-2 operator override): bypass the SD-R14
    /// `[requires_hardware]` gate. Modules whose predicates would
    /// fail still apply. `selfdefctl modules apply --ignore-hardware`
    /// sets this. Default false → gate enforced normally.
    pub(crate) ignore_hardware: bool,
    /// Override path to the daemon-side `/etc/selfdef/selfdef.toml`
    /// the validator reads. Tests use this; operators leave it
    /// unset (defaults to `/etc/selfdef/selfdef.toml`).
    pub(crate) daemon_config_path: Option<PathBuf>,
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

/// SDD-002 D-2: read `/etc/selfdef/selfdef.toml` (or whatever
/// daemon_config_path points at) into a flat key→value map so the
/// validator can answer "is this dotted key set to this value?"
fn load_daemon_config(path: &Path) -> Result<toml::Value> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::map::Map::new()));
    }
    let body =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str::<toml::Value>(&body).with_context(|| format!("parsing {}", path.display()))
}

/// Walk a dotted path (`collectors.tetragon.enabled`) through a
/// `toml::Value` tree, returning the leaf if present.
fn lookup_dotted<'a>(root: &'a toml::Value, dotted: &str) -> Option<&'a toml::Value> {
    let mut cur = root;
    for segment in dotted.split('.') {
        cur = cur.as_table().and_then(|t| t.get(segment))?;
    }
    Some(cur)
}

/// Compare an expected requirement against the actual daemon value
/// (which may be `None` if the key isn't set). Returns `Ok(())` when
/// satisfied, otherwise a one-line human description of the
/// mismatch.
fn check_requirement(
    actual: Option<&toml::Value>,
    expected: &DaemonRequirement,
) -> Result<(), String> {
    match (actual, expected) {
        (None, _) => Err("key missing".to_string()),
        (Some(toml::Value::Boolean(a)), DaemonRequirement::Bool(e)) if a == e => Ok(()),
        (Some(toml::Value::Integer(a)), DaemonRequirement::Int(e)) if a == e => Ok(()),
        (Some(toml::Value::String(a)), DaemonRequirement::String(e)) if a == e => Ok(()),
        (Some(toml::Value::Array(arr)), DaemonRequirement::Array(expected_items)) => {
            let actual_strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            for item in expected_items {
                if !actual_strs.iter().any(|a| a == item) {
                    return Err(format!("array missing element {item:?}"));
                }
            }
            Ok(())
        }
        (Some(actual), _) => Err(format!("value mismatch (got {})", actual_summary(actual))),
    }
}

fn actual_summary(v: &toml::Value) -> String {
    match v {
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::String(s) => format!("\"{s}\""),
        toml::Value::Array(a) => format!("[…{} item(s)]", a.len()),
        other => other.to_string(),
    }
}

/// Expand `${key}` references against the active module's host
/// config. The substitution is intentionally minimal: only
/// `${<flat-key>}` referencing a top-level scalar in the per-module
/// config file (the one `SELFDEF_<SLUG>_CONFIG` points at). No
/// nesting, no concatenation.
fn expand_substitution(
    expected: &DaemonRequirement,
    host_config: &toml::Value,
) -> Result<DaemonRequirement, String> {
    let expand_one = |s: &str| -> Result<String, String> {
        let mut out = String::new();
        let mut rest = s;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let rest_after = &rest[start + 2..];
            let end = rest_after
                .find('}')
                .ok_or_else(|| format!("unterminated `${{` in {s:?}"))?;
            let key = &rest_after[..end];
            let value = host_config
                .as_table()
                .and_then(|t| t.get(key))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!("substitution `${{{key}}}` did not resolve to a string in the per-module config")
                })?;
            out.push_str(value);
            rest = &rest_after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    };
    Ok(match expected {
        DaemonRequirement::Bool(_) | DaemonRequirement::Int(_) => expected.clone(),
        DaemonRequirement::String(s) => DaemonRequirement::String(expand_one(s)?),
        DaemonRequirement::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(expand_one(item)?);
            }
            DaemonRequirement::Array(out)
        }
    })
}

/// One unmet daemon-config requirement: the dotted key, the
/// (substitution-expanded) expected value, and a human-readable
/// reason for the mismatch.
type UnmetRequirement = (String, DaemonRequirement, String);

/// Per-module list of unmet requirements.
type UnmetByModule = (String, Vec<UnmetRequirement>);

/// Validate every active module's `[daemon_requires]` against the
/// loaded daemon config. Returns the list of unmet requirements per
/// module — empty if everything's satisfied.
fn check_daemon_requires(
    active: &[ActiveModule],
    daemon_cfg: &toml::Value,
) -> Result<Vec<UnmetByModule>, String> {
    let mut out = Vec::new();
    for am in active {
        let mut missing = Vec::new();
        let host_cfg = load_daemon_config(&am.config_path).unwrap_or_else(|_| {
            // A missing per-module config is normal for modules
            // that only ship a profile. Treat it as an empty
            // table for substitution purposes.
            toml::Value::Table(toml::map::Map::new())
        });
        for (key, raw_req) in &am.manifest.daemon_requires {
            let expected = expand_substitution(raw_req, &host_cfg).map_err(|e| {
                format!("module `{}`: substitution failed for `{key}`: {e}", am.slug)
            })?;
            let actual = lookup_dotted(daemon_cfg, key);
            if let Err(reason) = check_requirement(actual, &expected) {
                missing.push((key.clone(), expected, reason));
            }
        }
        if !missing.is_empty() {
            out.push((am.display_name(), missing));
        }
    }
    Ok(out)
}

/// Format the snippet shown to operators when the validator
/// finds unmet requirements.
fn render_requirements_snippet(unmet: &[UnmetByModule], daemon_config_path: &Path) -> String {
    let mut out = String::new();
    out.push_str("selfdefctl: daemon-side config in ");
    out.push_str(&daemon_config_path.display().to_string());
    out.push_str(" does not satisfy every active module's [daemon_requires].\n");
    out.push_str("Add the following keys (or pass --ignore-daemon-requires to skip):\n");
    for (module, items) in unmet {
        out.push_str("\n# ── ");
        out.push_str(module);
        out.push_str(" ──\n");
        for (key, expected, reason) in items {
            out.push_str(&format!(
                "{key} = {}    # {reason}\n",
                expected.render_value()
            ));
        }
    }
    out
}

pub(crate) fn cmd_apply(opts: &LifecycleOpts) -> Result<i32> {
    // SDD-015 § 4: when [perimeter] check_overlap_on_apply is true
    // (auto-true on Sain01 unless overridden), refuse to apply if any
    // selfdef-authored policy would overlap with sovereign-os's
    // host-scoped allowlist. The check runs BEFORE any apply.sh
    // fires — operators don't get partial installs of conflicting
    // policies.
    let pre_code = pre_apply_perimeter_check(opts)?;
    if pre_code != 0 {
        return Ok(pre_code);
    }
    run_lifecycle(opts, Action::Apply, LifecyclePolicy::default())
}

/// SD-R14: hardware-aware module gate.
///
/// Probes the host once + drops modules whose `[requires_hardware]`
/// block isn't satisfied. Skipped modules log a single line citing
/// the unmet predicates so operators understand WHY their module
/// didn't apply. The probe failure (e.g. on minimal hosts) is silent
/// for modules that DON'T declare hardware requirements; modules
/// that DO declare them are skipped with a clear log.
fn apply_hardware_gate(active: Vec<ActiveModule>) -> Vec<ActiveModule> {
    let caps = match selfdef_hardware::probe() {
        Ok(snap) => Some(selfdef_hardware::derive_capabilities(&snap)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "SD-R14: hardware probe failed; modules with [requires_hardware] will be skipped"
            );
            None
        }
    };
    let mut kept = Vec::with_capacity(active.len());
    let mut skipped = Vec::new();
    for m in active {
        if m.manifest.requires_hardware.is_empty() {
            kept.push(m);
            continue;
        }
        match &caps {
            Some(c) => match m.manifest.requires_hardware.evaluate(c) {
                Ok(()) => kept.push(m),
                Err(unmet) => skipped.push((m.display_name(), unmet)),
            },
            None => skipped.push((m.display_name(), vec!["hardware probe unavailable".into()])),
        }
    }
    if !skipped.is_empty() {
        eprintln!(
            "# SD-R14 hardware-aware module gate — skipping {} module(s):",
            skipped.len()
        );
        for (name, reasons) in &skipped {
            eprintln!("  - {name}:");
            for r in reasons {
                eprintln!("      ✗ {r}");
            }
        }
        eprintln!("# To force-apply, remove [requires_hardware] from the module's module.toml");
        eprintln!("# or upgrade the host to meet the requirements.");
    }
    kept
}

/// SDD-015 § 4 + § 6 pre-apply gate. Reads the daemon config to
/// resolve `[perimeter] check_overlap_on_apply` + `policies_dir` +
/// `overlap_warn_only`. Loads policies, runs overlap detection, and:
///   - returns 0 (no gate) when the check is disabled
///   - returns 0 (passed) when no findings
///   - returns 0 (warn-only mode) when findings exist but downgraded
///   - returns 1 (blocked) when findings exist and not in warn-only
fn pre_apply_perimeter_check(opts: &LifecycleOpts) -> Result<i32> {
    let cfg_path = match &opts.daemon_config_path {
        Some(p) => p,
        None => return Ok(0), // no config supplied → no gate
    };
    let cfg = match selfdef_config::Config::load(Some(cfg_path)) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                config = %cfg_path.display(),
                error = %e,
                "modules apply: perimeter pre-check skipped — daemon config unloadable"
            );
            return Ok(0);
        }
    };
    if !selfdef_config::resolve_perimeter_check_overlap(&cfg) {
        return Ok(0);
    }
    let policies = match crate::perimeter::read_policies_dir(&cfg.perimeter.policies_dir) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                dir = %cfg.perimeter.policies_dir.display(),
                error = %e,
                "modules apply: perimeter pre-check skipped — policies dir unreadable"
            );
            return Ok(0);
        }
    };
    let stance = cfg.perimeter.third_party_policy_stance.as_str();
    let findings = crate::perimeter::check_overlap_with_stance(&policies, stance);
    let blocking: Vec<_> = findings
        .iter()
        .filter(|f| crate::perimeter::finding_is_blocking(f))
        .collect();
    if blocking.is_empty() {
        tracing::info!(
            policies = policies.len(),
            "modules apply: perimeter pre-check PASS (SDD-015)"
        );
        return Ok(0);
    }
    let (report, exit) = crate::perimeter::render_check_overlap_report(&policies, &findings);
    eprintln!("# modules apply pre-check (SDD-015):\n");
    eprintln!("{report}");
    if cfg.perimeter.overlap_warn_only {
        eprintln!(
            "[perimeter] overlap_warn_only = true → proceeding with apply despite findings (Q15-B)."
        );
        return Ok(0);
    }
    eprintln!(
        "Refusing to apply: {} blocking finding(s) detected (of {} total). \
         Set `[perimeter] overlap_warn_only = true` to downgrade, or fix the \
         FAIL violations above and re-run.",
        blocking.len(),
        findings.len(),
    );
    Ok(exit.max(1))
}

/// SDD-002 D-5: `selfdefctl modules show-requires` reads every
/// active module's `[daemon_requires]` (substitutions expanded
/// against per-module config) and prints them as a copy-pasteable
/// snippet — even when the daemon-config matches. Useful for
/// previewing what a future module activation will demand.
pub(crate) fn cmd_show_requires(opts: &LifecycleOpts) -> Result<i32> {
    let (_host_path, active) = prepare(opts)?;
    if active.is_empty() {
        println!("(no active modules — host config empty)");
        return Ok(0);
    }
    let mut wrote_any = false;
    for am in &active {
        if am.manifest.daemon_requires.is_empty() {
            continue;
        }
        let host_cfg = load_daemon_config(&am.config_path)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
        println!();
        println!("# ── {} ──", am.display_name());
        for (key, raw_req) in &am.manifest.daemon_requires {
            let expanded = match expand_substitution(raw_req, &host_cfg) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "warning: substitution failed for {} {key}: {e}",
                        am.display_name()
                    );
                    continue;
                }
            };
            println!("{key} = {}", expanded.render_value());
        }
        wrote_any = true;
    }
    if !wrote_any {
        println!("(no active module declares [daemon_requires])");
    }
    Ok(0)
}

pub(crate) fn cmd_check(opts: &LifecycleOpts) -> Result<i32> {
    // `check` never mutates — force dry_run off (it's a no-op for
    // check scripts but keeps the env consistent).
    let mut o = opts.clone();
    o.dry_run = false;
    run_lifecycle(&o, Action::Check, LifecyclePolicy::default())
}

/// SD-R15: dry-run the SD-R14 [requires_hardware] gate without
/// touching any module scripts. Operators planning an install on a
/// new host run this BEFORE `apply` to see which modules will skip.
#[cfg(test)]
pub(crate) fn cmd_check_hardware(opts: &LifecycleOpts, json: bool) -> Result<i32> {
    cmd_check_hardware_with_caps(opts, json, None)
}

/// SD-R38: dry-run the gate against a saved capabilities JSON
/// instead of probing the host. When `caps_path` is None this is
/// equivalent to `cmd_check_hardware` (live probe).
pub(crate) fn cmd_check_hardware_with_caps(
    opts: &LifecycleOpts,
    json: bool,
    caps_path: Option<&Path>,
) -> Result<i32> {
    let (_host_path, active) = prepare(opts)?;
    let caps = if let Some(p) = caps_path {
        match std::fs::read_to_string(p) {
            Ok(body) => match serde_json::from_str::<selfdef_hardware::HardwareCapabilities>(&body)
            {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(error = %e, path = %p.display(), "SD-R38: --caps JSON unreadable");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, path = %p.display(), "SD-R38: --caps file unreadable");
                None
            }
        }
    } else {
        match selfdef_hardware::probe() {
            Ok(snap) => Some(selfdef_hardware::derive_capabilities(&snap)),
            Err(_) => None,
        }
    };
    let mut kept: Vec<(String, String)> = Vec::new(); // (name, reason)
    let mut skipped: Vec<(String, Vec<String>)> = Vec::new();
    let mut probe_ok = caps.is_some();
    for am in &active {
        let name = am.display_name();
        if am.manifest.requires_hardware.is_empty() {
            kept.push((name, "no [requires_hardware] block".into()));
            continue;
        }
        match &caps {
            Some(c) => match am.manifest.requires_hardware.evaluate(c) {
                Ok(()) => kept.push((name, "all hardware requirements met".into())),
                Err(unmet) => skipped.push((name, unmet)),
            },
            None => {
                probe_ok = false;
                skipped.push((name, vec!["hardware probe unavailable".into()]));
            }
        }
    }
    if json {
        // SD-R27: emit the full HardwareCapabilities as the
        // `host_snapshot` field so machine consumers can correlate
        // skip reasons with actual host values without re-probing.
        // serde_json gives us the canonical shape — no hand-rolled
        // JSON for the inner snapshot.
        let total = kept.len() + skipped.len();
        let kept_json: Vec<String> = kept
            .iter()
            .map(|(n, r)| format!(r#"{{"module":"{n}","reason":"{r}"}}"#))
            .collect();
        let skipped_json: Vec<String> = skipped
            .iter()
            .map(|(n, reasons)| {
                let r = reasons
                    .iter()
                    .map(|s| format!(r#""{}""#, s.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#"{{"module":"{n}","unmet":[{r}]}}"#)
            })
            .collect();
        let snap_json = caps
            .as_ref()
            .and_then(|c| serde_json::to_string(c).ok())
            .unwrap_or_else(|| "null".into());
        println!(
            r#"{{"probe_ok":{},"total":{},"kept":[{}],"skipped":[{}],"host_snapshot":{}}}"#,
            probe_ok,
            total,
            kept_json.join(","),
            skipped_json.join(","),
            snap_json,
        );
    } else {
        println!("# SD-R15 hardware gate dry-run");
        if !probe_ok {
            println!("# (hardware probe unavailable — gated modules will be skipped)");
        }
        // SD-R27: host-snapshot block surfaces the actual probed
        // values that the gate evaluates against. Operators see WHY
        // a module skipped without separately running `selfdefctl
        // hardware probe`.
        if let Some(c) = &caps {
            println!();
            println!("HOST SNAPSHOT (what the gate sees):");
            let avx_bits: Vec<&str> = [
                ("avx512f", c.cpu.avx512f),
                ("avx512vnni", c.cpu.avx512vnni),
                ("avx512bf16", c.cpu.avx512bf16),
                ("avx512fp16", c.cpu.avx512fp16),
            ]
            .iter()
            .filter_map(|(name, present)| if *present { Some(*name) } else { None })
            .collect();
            let avx_summary = if avx_bits.is_empty() {
                "none".to_string()
            } else {
                avx_bits.join(", ")
            };
            println!(
                "  CPU      : {} ({})",
                if c.cpu.model_name.is_empty() {
                    "(unknown)"
                } else {
                    c.cpu.model_name.as_str()
                },
                avx_summary,
            );
            println!(
                "  Memory   : {} GiB",
                c.memory.total_bytes / (1024 * 1024 * 1024),
            );
            println!("  GPUs     : {} device(s)", c.gpu.device_count);
            for (i, d) in c.gpu.devices.iter().enumerate() {
                let model = d.model_hint.as_deref().unwrap_or("(unknown model)");
                let vram = d
                    .vram_bytes
                    .map(|b| format!("{} GiB", b / (1024 * 1024 * 1024)))
                    .unwrap_or_else(|| "?".to_string());
                let pwr = match (d.power_draw_watts, d.power_limit_watts) {
                    (Some(draw), Some(limit)) => {
                        format!(
                            "{draw}/{limit} W (headroom {} W)",
                            limit.saturating_sub(draw)
                        )
                    }
                    _ => "no telemetry".to_string(),
                };
                println!("    [{i}] {model} — vram {vram}, power {pwr}");
            }
            let verdict = match c.sain01_match.overall {
                selfdef_hardware::Sain01Verdict::FullMatch => "FullMatch",
                selfdef_hardware::Sain01Verdict::PartialMatch => "PartialMatch",
                selfdef_hardware::Sain01Verdict::NoMatch => "NoMatch",
            };
            println!("  Sain01   : {verdict}");
        }
        println!();
        println!("# {} active module(s):", kept.len() + skipped.len());
        if !kept.is_empty() {
            println!();
            println!("WOULD APPLY ({}):", kept.len());
            for (name, reason) in &kept {
                println!("  ✓ {name}  ({reason})");
            }
        }
        if !skipped.is_empty() {
            println!();
            println!("WOULD SKIP ({}):", skipped.len());
            for (name, reasons) in &skipped {
                println!("  ✗ {name}");
                for r in reasons {
                    println!("      - {r}");
                }
            }
        }
    }
    Ok(0)
}

/// SD-R36: emit active modules as a Graphviz DOT digraph.
/// Operator pipes to `dot -Tsvg > graph.svg` for a visual map of
/// how their modules compose; the raw text is also operator-readable.
///
/// Edges:
///   - `dependency` arrows: `A → B` means B depends on A (apply order)
///   - `instance` dashed edges between multi-instance modules
///
/// When `with_hardware_gate=true`, nodes are coloured by SD-R14
/// verdict (green = passes gate, red = skipped).
/// SD-R41: structured JSON variant of cmd_graph. Same data shape
/// (nodes + edges + per-node gate verdict) but machine-readable.
pub(crate) fn cmd_graph_json(opts: &LifecycleOpts, with_hardware_gate: bool) -> Result<i32> {
    let (_host_path, active) = prepare(opts)?;
    let caps = if with_hardware_gate {
        selfdef_hardware::probe()
            .ok()
            .map(|s| selfdef_hardware::derive_capabilities(&s))
    } else {
        None
    };

    let active_names: std::collections::HashSet<&str> =
        active.iter().map(|a| a.slug.as_str()).collect();

    let mut nodes: Vec<serde_json::Value> = Vec::with_capacity(active.len());
    for am in &active {
        let name = am.display_name();
        let mut node = serde_json::json!({
            "id": name,
            "slug": am.slug,
            "instance": am.instance,
            "phase": am.manifest.phase.as_str(),
        });
        if with_hardware_gate {
            let (verdict, unmet): (&str, Vec<String>) = if am.manifest.requires_hardware.is_empty()
            {
                ("ungated", Vec::new())
            } else {
                match &caps {
                    Some(c) => match am.manifest.requires_hardware.evaluate(c) {
                        Ok(()) => ("kept", Vec::new()),
                        Err(u) => ("skipped", u),
                    },
                    None => ("probe-unavailable", Vec::new()),
                }
            };
            node["gate"] = serde_json::json!({
                "verdict": verdict,
                "unmet": unmet,
            });
        }
        nodes.push(node);
    }

    // Edges
    let mut edges: Vec<serde_json::Value> = Vec::new();
    for am in &active {
        for dep in &am.manifest.depends_on {
            if active_names.contains(dep.as_str()) {
                edges.push(serde_json::json!({
                    "kind": "dependency",
                    "from": dep,
                    "to": am.display_name(),
                }));
            }
        }
    }
    // Instance grouping
    let mut by_slug: std::collections::BTreeMap<&str, Vec<&ActiveModule>> =
        std::collections::BTreeMap::new();
    for am in &active {
        by_slug.entry(am.slug.as_str()).or_default().push(am);
    }
    for (slug, instances) in &by_slug {
        if instances.len() < 2 {
            continue;
        }
        for i in 0..instances.len() - 1 {
            edges.push(serde_json::json!({
                "kind": "instance-sibling",
                "shared_slug": slug,
                "from": instances[i].display_name(),
                "to": instances[i + 1].display_name(),
            }));
        }
    }

    let doc = serde_json::json!({
        "schema_version": "1.0.0",
        "node_count": nodes.len(),
        "edge_count": edges.len(),
        "with_hardware_gate": with_hardware_gate,
        "probe_ok": caps.is_some(),
        "nodes": nodes,
        "edges": edges,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(0)
}

pub(crate) fn cmd_graph(opts: &LifecycleOpts, with_hardware_gate: bool) -> Result<i32> {
    let (_host_path, active) = prepare(opts)?;
    let caps = if with_hardware_gate {
        selfdef_hardware::probe()
            .ok()
            .map(|s| selfdef_hardware::derive_capabilities(&s))
    } else {
        None
    };

    println!("// SD-R36: selfdefctl modules graph");
    println!("// {} active module(s)", active.len());
    if with_hardware_gate {
        println!("// SD-R14 hardware gate: ON (green=kept, red=skipped)");
        if caps.is_none() {
            println!("// (hardware probe unavailable — gates ignored, all nodes default)");
        }
    }
    println!("digraph selfdef_modules {{");
    println!("  rankdir=LR;");
    println!("  node [shape=box, fontname=\"sans-serif\"];");

    // Nodes
    for am in &active {
        let label = am.display_name();
        let mut attrs = vec![format!("label=\"{label}\"")];
        if with_hardware_gate {
            let (style, color) = match &caps {
                Some(c) => {
                    if am.manifest.requires_hardware.is_empty() {
                        ("filled", "lightblue")
                    } else {
                        match am.manifest.requires_hardware.evaluate(c) {
                            Ok(()) => ("filled", "palegreen"),
                            Err(_) => ("filled", "lightcoral"),
                        }
                    }
                }
                None => ("solid", "white"),
            };
            attrs.push(format!("style={style}"));
            attrs.push(format!("fillcolor={color}"));
            // Tooltip carries the unmet predicates list when skipped.
            if let Some(c) = &caps {
                if !am.manifest.requires_hardware.is_empty() {
                    if let Err(unmet) = am.manifest.requires_hardware.evaluate(c) {
                        let tip = unmet
                            .iter()
                            .map(|s| s.replace('"', "\\\""))
                            .collect::<Vec<_>>()
                            .join("\\n");
                        attrs.push(format!("tooltip=\"{tip}\""));
                    }
                }
            }
        }
        println!("  \"{label}\" [{}];", attrs.join(", "));
    }

    // Dependency edges (B → A means B depends_on A; we draw A → B
    // to match apply-order direction).
    let active_names: std::collections::HashSet<&str> =
        active.iter().map(|a| a.slug.as_str()).collect();
    for am in &active {
        for dep in &am.manifest.depends_on {
            if active_names.contains(dep.as_str()) {
                println!(
                    "  \"{dep}\" -> \"{name}\";",
                    dep = dep,
                    name = am.display_name()
                );
            }
        }
    }

    // Instance grouping — dashed edges between instances of the
    // same slug.
    let mut by_slug: std::collections::BTreeMap<&str, Vec<&ActiveModule>> =
        std::collections::BTreeMap::new();
    for am in &active {
        by_slug.entry(am.slug.as_str()).or_default().push(am);
    }
    for (slug, instances) in &by_slug {
        if instances.len() < 2 {
            continue;
        }
        for i in 0..instances.len() - 1 {
            println!(
                "  \"{a}\" -> \"{b}\" [style=dashed, arrowhead=none, color=gray, tooltip=\"shared slug: {slug}\"];",
                a = instances[i].display_name(),
                b = instances[i + 1].display_name(),
            );
        }
    }

    println!("}}");
    Ok(0)
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
    // SD-R14: hardware-aware module gate. On Apply / Check, probe
    // the host hardware once + filter out modules whose
    // [requires_hardware] block isn't met. The unmet modules surface
    // as a single warning block before apply; the filtered set
    // proceeds. Uninstall skips this — tearing a module down doesn't
    // care whether the hardware now matches.
    if matches!(action, Action::Apply | Action::Check)
        && !opts.ignore_hardware
        && active
            .iter()
            .any(|a| !a.manifest.requires_hardware.is_empty())
    {
        active = apply_hardware_gate(active);
    } else if opts.ignore_hardware
        && active
            .iter()
            .any(|a| !a.manifest.requires_hardware.is_empty())
    {
        // SD-R42: operator explicitly suppressed the gate. Emit a
        // warning so the operator sees this on every run — the
        // override is sharp-edged and should not be silent.
        eprintln!(
            "# SD-R42: --ignore-hardware set — gate suppressed, {} gated module(s) will be force-applied",
            active
                .iter()
                .filter(|a| !a.manifest.requires_hardware.is_empty())
                .count()
        );
    }
    // SDD-002 D-2: validate every active module's
    // `[daemon_requires]` against the daemon-side config. Apply
    // and Check both fire the check; Uninstall skips it (tearing
    // a module down doesn't care whether the daemon config still
    // matches).
    if matches!(action, Action::Apply | Action::Check) && !opts.ignore_daemon_requires {
        let daemon_cfg_path = opts
            .daemon_config_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/selfdef/selfdef.toml"));
        let daemon_cfg = load_daemon_config(&daemon_cfg_path)?;
        match check_daemon_requires(&active, &daemon_cfg) {
            Ok(unmet) if !unmet.is_empty() => {
                eprintln!("{}", render_requirements_snippet(&unmet, &daemon_cfg_path),);
                return Ok(2);
            }
            Ok(_) => {}
            Err(e) => anyhow::bail!("daemon_requires validation failed: {e}"),
        }
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
            daemon_requires: BTreeMap::new(),
            requires_hardware: HardwareRequirements::default(),
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

    // -- SDD-003: per-profile multi-instance ------------------------

    fn profile_spec_with_details(
        default: &str,
        available: &[&str],
        details: &[(&str, bool)],
    ) -> ProfileSpec {
        ProfileSpec {
            default: Some(default.to_string()),
            available: available.iter().map(|s| (*s).to_string()).collect(),
            details: details
                .iter()
                .map(|(name, inst)| {
                    (
                        (*name).to_string(),
                        ProfileDetails {
                            instanced: Some(*inst),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn profile_instanced_falls_back_to_module_default_when_unset() {
        let spec = profile_spec_with_details("a", &["a", "b"], &[]);
        // No per-profile detail → use module-level default.
        assert!(spec.profile_instanced("a", true));
        assert!(!spec.profile_instanced("b", false));
    }

    #[test]
    fn profile_instanced_per_profile_override_wins() {
        let spec = profile_spec_with_details(
            "relay",
            &["relay", "tailscale", "cf"],
            &[("relay", true), ("tailscale", false), ("cf", false)],
        );
        assert!(spec.profile_instanced("relay", true));
        assert!(!spec.profile_instanced("tailscale", true));
        assert!(!spec.profile_instanced("cf", true));
        // Profile not declared → module default.
        assert!(spec.profile_instanced("other", true));
    }

    fn manifest_with_profiles(name: &str, instanced: bool, spec: ProfileSpec) -> ModuleManifest {
        let mut m = make_manifest_full(name, &[], &[], instanced, Phase::Main);
        m.profiles = Some(spec);
        m
    }

    #[test]
    fn resolver_rejects_instance_for_singleton_profile() {
        // vpn-bridge#a chooses the tailscale profile, which is
        // instanced=false. Resolver must refuse before running anything.
        let tmp = tempfile::tempdir().unwrap();
        let inst_cfg = tmp.path().join("vpn-bridge.a.toml");
        std::fs::write(&inst_cfg, "profile = \"tailscale\"\n").unwrap();

        let catalog = vec![(
            "vpn-bridge".into(),
            manifest_with_profiles(
                "vpn-bridge",
                true,
                profile_spec_with_details(
                    "relay-via-server",
                    &["relay-via-server", "tailscale", "cloudflare-tunnel"],
                    &[
                        ("relay-via-server", true),
                        ("tailscale", false),
                        ("cloudflare-tunnel", false),
                    ],
                ),
            ),
        )];
        let host = host_from_toml(&format!(
            "[modules.\"vpn-bridge#a\"]\nconfig = \"{}\"\n",
            inst_cfg.display()
        ));
        let err = resolve_active(&host, Path::new("/tmp"), catalog)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("profile `tailscale` does not support"),
            "got: {err}"
        );
    }

    #[test]
    fn resolver_accepts_instance_for_multi_instance_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let inst_cfg = tmp.path().join("vpn-bridge.overlay.toml");
        std::fs::write(&inst_cfg, "profile = \"relay-via-server\"\n").unwrap();

        let catalog = vec![(
            "vpn-bridge".into(),
            manifest_with_profiles(
                "vpn-bridge",
                true,
                profile_spec_with_details(
                    "relay-via-server",
                    &["relay-via-server", "tailscale", "cloudflare-tunnel"],
                    &[
                        ("relay-via-server", true),
                        ("tailscale", false),
                        ("cloudflare-tunnel", false),
                    ],
                ),
            ),
        )];
        let host = host_from_toml(&format!(
            "[modules.\"vpn-bridge#overlay\"]\nconfig = \"{}\"\n",
            inst_cfg.display()
        ));
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].instance.as_deref(), Some("overlay"));
    }

    #[test]
    fn resolver_falls_back_to_default_profile_when_config_missing() {
        // Per-instance config file doesn't exist → use the manifest
        // default profile (`relay-via-server`, which is instanced=true)
        // so the apply succeeds.
        let catalog = vec![(
            "vpn-bridge".into(),
            manifest_with_profiles(
                "vpn-bridge",
                true,
                profile_spec_with_details(
                    "relay-via-server",
                    &["relay-via-server", "tailscale"],
                    &[("relay-via-server", true), ("tailscale", false)],
                ),
            ),
        )];
        let host = host_from_toml(
            "[modules.\"vpn-bridge#overlay\"]\nconfig = \"/nonexistent/missing.toml\"\n",
        );
        let active = resolve_active(&host, Path::new("/tmp"), catalog).unwrap();
        assert_eq!(active.len(), 1);
    }

    // -- SDD-006: shared module-lib resolver ------------------------

    #[test]
    fn resolve_module_lib_path_finds_workspace_by_default() {
        // Workspace path exists in this checkout — the resolver
        // must prefer it over the system path when no override is
        // set. We can only safely test the no-override branch
        // in-process; the env-var override branch is covered by
        // the integration test
        // (`cli_modules_shared_lib::dispatcher_exports_module_lib_env_var`)
        // which spawns a subprocess with the env var set.
        //
        // The test asserts (a) the resolver returns the workspace
        // path, (b) that path actually exists — so the resolver
        // would never silently fall through to the system path
        // when sourced from a workspace.
        let got = resolve_module_lib_path();
        // If $SELFDEF_MODULE_LIB happens to be set in the test
        // env (e.g. operator running tests under a debug shell),
        // skip — the override branch is exercised by integration.
        if std::env::var_os("SELFDEF_MODULE_LIB").is_some() {
            return;
        }
        assert!(
            got.display()
                .to_string()
                .ends_with("packaging/lib/module-lib.sh"),
            "expected workspace path, got: {}",
            got.display()
        );
        assert!(got.exists(), "workspace path must exist for this test");
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
        let body = "#!/usr/bin/env bash\necho '{\"module\":\"only-apply\",\"status\":\"ok\",\"message\":\"\"}'\n";
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

#[cfg(test)]
mod sdd_015_apply_gate_tests {
    //! SDD-015 § 4 + § 6: pre-apply perimeter check.
    //!
    //! We construct a `LifecycleOpts` that points at a temp daemon
    //! config file with explicit `[deployment] target = "sain01"` +
    //! a `[perimeter] policies_dir = <tempdir>` pointing at our
    //! synthesized policy files. Then we call
    //! [`pre_apply_perimeter_check`] directly and assert the exit code.
    //!
    //! This validates the GATE in isolation; the full
    //! `cmd_apply → run_lifecycle` path is exercised by the integration
    //! test suite (no module fixtures wired here).

    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_cfg(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    fn opts(daemon_config_path: PathBuf) -> LifecycleOpts {
        LifecycleOpts {
            host_config: None,
            dir: None,
            only: Vec::new(),
            except: Vec::new(),
            dry_run: false,
            ignore_daemon_requires: false,
            ignore_hardware: false,
            daemon_config_path: Some(daemon_config_path),
        }
    }

    /// SDD-015 § 4: on Generic target, the gate is auto-disabled —
    /// returns 0 regardless of policies dir contents.
    #[test]
    fn sdd_015_apply_gate_skipped_on_generic_target() {
        let dir = tempdir().unwrap();
        let pol_dir = dir.path().join("policies");
        std::fs::create_dir_all(&pol_dir).unwrap();
        // Place a bad agent-guard policy that WOULD fail the check
        std::fs::write(
            pol_dir.join("agent-guard-bad.yaml"),
            "metadata:\n  name: agent-guard-bad\nspec:\n  kprobes:\n    - call: sys_execve\n",
        )
        .unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            &format!(
                r#"
                [deployment]
                target = "generic"

                [perimeter]
                policies_dir = "{}"
                "#,
                pol_dir.display()
            ),
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert_eq!(code, 0, "generic target → gate skipped");
    }

    /// SDD-015 § 4: on SAIN-01 target with a clean policies dir, gate
    /// passes (returns 0).
    #[test]
    fn sdd_015_apply_gate_passes_on_clean_sain01() {
        let dir = tempdir().unwrap();
        let pol_dir = dir.path().join("policies");
        std::fs::create_dir_all(&pol_dir).unwrap();
        // Only a properly-scoped agent-guard policy
        std::fs::write(
            pol_dir.join("agent-guard-shell-exec.yaml"),
            "metadata:\n  name: agent-guard-shell-exec\nspec:\n  kprobes:\n    - call: sys_execve\n      selectors:\n        - matchNamespaces:\n            - operator: In\n              values: [container]\n",
        )
        .unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            &format!(
                r#"
                [deployment]
                target = "sain01"

                [perimeter]
                policies_dir = "{}"
                "#,
                pol_dir.display()
            ),
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert_eq!(code, 0, "clean sain01 policies → gate passes");
    }

    /// SDD-015 § 4 + § 6: on SAIN-01 target with a host-scoped
    /// agent-guard policy, gate BLOCKS apply (returns ≥1).
    #[test]
    fn sdd_015_apply_gate_blocks_on_host_scoped_agent_guard() {
        let dir = tempdir().unwrap();
        let pol_dir = dir.path().join("policies");
        std::fs::create_dir_all(&pol_dir).unwrap();
        std::fs::write(
            pol_dir.join("agent-guard-bad.yaml"),
            "metadata:\n  name: agent-guard-bad\nspec:\n  kprobes:\n    - call: sys_execve\n",
        )
        .unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            &format!(
                r#"
                [deployment]
                target = "sain01"

                [perimeter]
                policies_dir = "{}"
                "#,
                pol_dir.display()
            ),
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert!(code >= 1, "host-scoped agent-guard → blocked (got {code})");
    }

    /// SDD-015 § Q15-B: with `overlap_warn_only = true`, findings are
    /// printed but the gate returns 0 (apply proceeds).
    #[test]
    fn sdd_015_apply_gate_warn_only_downgrades_to_zero() {
        let dir = tempdir().unwrap();
        let pol_dir = dir.path().join("policies");
        std::fs::create_dir_all(&pol_dir).unwrap();
        std::fs::write(
            pol_dir.join("agent-guard-bad.yaml"),
            "metadata:\n  name: agent-guard-bad\nspec:\n  kprobes:\n    - call: sys_execve\n",
        )
        .unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            &format!(
                r#"
                [deployment]
                target = "sain01"

                [perimeter]
                policies_dir = "{}"
                overlap_warn_only = true
                "#,
                pol_dir.display()
            ),
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert_eq!(code, 0, "warn-only → downgrade to 0 despite finding");
    }

    /// Explicit operator override: `check_overlap_on_apply = false` on
    /// SAIN-01 disables the gate (operator-explicit opt-out path).
    #[test]
    fn sdd_015_apply_gate_explicit_disable_overrides_sain01_autoenable() {
        let dir = tempdir().unwrap();
        let pol_dir = dir.path().join("policies");
        std::fs::create_dir_all(&pol_dir).unwrap();
        std::fs::write(
            pol_dir.join("agent-guard-bad.yaml"),
            "metadata:\n  name: agent-guard-bad\nspec:\n  kprobes:\n    - call: sys_execve\n",
        )
        .unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            &format!(
                r#"
                [deployment]
                target = "sain01"

                [perimeter]
                policies_dir = "{}"
                check_overlap_on_apply = false
                "#,
                pol_dir.display()
            ),
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert_eq!(code, 0, "explicit disable wins over sain01 auto-enable");
    }

    /// No daemon config path supplied → gate is a no-op.
    #[test]
    fn sdd_015_apply_gate_noop_when_no_daemon_config_path() {
        let opts = LifecycleOpts {
            host_config: None,
            dir: None,
            only: Vec::new(),
            except: Vec::new(),
            dry_run: false,
            ignore_daemon_requires: false,
            ignore_hardware: false,
            daemon_config_path: None,
        };
        let code = pre_apply_perimeter_check(&opts).unwrap();
        assert_eq!(code, 0, "no daemon config → gate skipped");
    }

    /// Missing policies dir → gate passes (operator without Tetragon
    /// installed doesn't get blocked from running modules apply).
    #[test]
    fn sdd_015_apply_gate_passes_on_missing_policies_dir() {
        let dir = tempdir().unwrap();
        let cfg = dir.path().join("selfdef.toml");
        write_cfg(
            &cfg,
            r#"
            [deployment]
            target = "sain01"

            [perimeter]
            policies_dir = "/nonexistent/path/xyz"
            "#,
        );
        let code = pre_apply_perimeter_check(&opts(cfg)).unwrap();
        assert_eq!(code, 0, "missing policies dir → graceful pass");
    }
}

#[cfg(test)]
mod sdr14_hardware_gate_tests {
    //! SD-R14: hardware-aware module gating.
    //!
    //! [`HardwareRequirements::evaluate`] is the pure decision function;
    //! [`apply_hardware_gate`] wraps it with the partition + skip-block
    //! logging. Tests here pin each predicate branch in isolation and
    //! then exercise the gate against a synthesized [`HardwareCapabilities`].
    //!
    //! These are the operator-stable surface for the
    //! `[requires_hardware]` block in `module.toml` — every assertion
    //! reads as "what an operator declares == what gets enforced".
    use super::*;
    use selfdef_hardware::{
        CpuCapabilities, GpuCapabilities, HardwareCapabilities, MemoryCapabilities,
        PcieCapabilities, Sain01Match, Sain01Verdict,
    };

    fn caps_with(
        avx512_vnni: bool,
        avx512_bf16: bool,
        mem_gib: u64,
        gpu_count: u32,
        verdict: Sain01Verdict,
    ) -> HardwareCapabilities {
        HardwareCapabilities {
            schema_version: "1".into(),
            probed_at: "1970-01-01T00:00:00Z".into(),
            host_tag: None,
            cpu: CpuCapabilities {
                avx512vnni: avx512_vnni,
                avx512bf16: avx512_bf16,
                ..Default::default()
            },
            memory: MemoryCapabilities {
                total_bytes: mem_gib * 1024 * 1024 * 1024,
                at_least_256gb: mem_gib >= 256,
                at_least_512gb: mem_gib >= 512,
            },
            gpu: GpuCapabilities {
                device_count: gpu_count,
                device_nodes: Vec::new(),
                devices: Vec::new(),
            },
            pcie: PcieCapabilities::default(),
            sain01_match: Sain01Match {
                overall: verdict,
                cpu_avx512_vnni: avx512_vnni,
                cpu_avx512_bf16: avx512_bf16,
                memory_at_least_256gb: mem_gib >= 256,
                gpu_count_at_least_2: gpu_count >= 2,
                motherboard_proart_x870e: None,
                pcie_dual_x8_present: false,
            },
            wasm_aot: Default::default(),
        }
    }

    fn full_match_sain01() -> HardwareCapabilities {
        caps_with(true, true, 256, 2, Sain01Verdict::FullMatch)
    }

    fn minimal_host() -> HardwareCapabilities {
        caps_with(false, false, 16, 0, Sain01Verdict::NoMatch)
    }

    #[test]
    fn sdr14_evaluate_empty_passes_any_caps() {
        let req = HardwareRequirements::default();
        assert!(req.is_empty());
        assert!(req.evaluate(&minimal_host()).is_ok());
        assert!(req.evaluate(&full_match_sain01()).is_ok());
    }

    #[test]
    fn sdr14_evaluate_avx512_vnni_required_passes_on_match() {
        let req = HardwareRequirements {
            avx512_vnni: true,
            ..Default::default()
        };
        assert!(!req.is_empty());
        req.evaluate(&full_match_sain01()).unwrap();
    }

    #[test]
    fn sdr14_evaluate_avx512_vnni_required_fails_on_missing() {
        let req = HardwareRequirements {
            avx512_vnni: true,
            ..Default::default()
        };
        let unmet = req.evaluate(&minimal_host()).unwrap_err();
        assert_eq!(unmet.len(), 1);
        assert!(unmet[0].contains("avx512_vnni"), "got: {unmet:?}");
    }

    #[test]
    fn sdr14_evaluate_avx512_bf16_required_fails_on_missing() {
        let req = HardwareRequirements {
            avx512_bf16: true,
            ..Default::default()
        };
        let unmet = req
            .evaluate(&caps_with(true, false, 256, 2, Sain01Verdict::PartialMatch))
            .unwrap_err();
        assert!(unmet[0].contains("avx512_bf16"), "got: {unmet:?}");
    }

    #[test]
    fn sdr14_evaluate_memory_threshold_enforced() {
        let req = HardwareRequirements {
            memory_gib_min: 128,
            ..Default::default()
        };
        let unmet = req
            .evaluate(&caps_with(false, false, 32, 0, Sain01Verdict::NoMatch))
            .unwrap_err();
        assert!(unmet[0].contains("memory_gib_min = 128"), "got: {unmet:?}");
        assert!(unmet[0].contains("32 GiB"), "got: {unmet:?}");
        // Exactly at threshold → passes.
        req.evaluate(&caps_with(false, false, 128, 0, Sain01Verdict::NoMatch))
            .unwrap();
    }

    #[test]
    fn sdr14_evaluate_gpu_count_min_enforced() {
        let req = HardwareRequirements {
            gpu_count_min: 2,
            ..Default::default()
        };
        let unmet = req
            .evaluate(&caps_with(false, false, 16, 1, Sain01Verdict::NoMatch))
            .unwrap_err();
        assert!(unmet[0].contains("gpu_count_min = 2"), "got: {unmet:?}");
        // 2 GPUs → passes.
        req.evaluate(&caps_with(false, false, 16, 2, Sain01Verdict::NoMatch))
            .unwrap();
    }

    #[test]
    fn sdr14_evaluate_sain01_verdict_rank_ordering() {
        let req = HardwareRequirements {
            sain01_verdict_min: "PartialMatch".into(),
            ..Default::default()
        };
        // NoMatch < PartialMatch → fail.
        let unmet = req
            .evaluate(&caps_with(false, false, 16, 0, Sain01Verdict::NoMatch))
            .unwrap_err();
        assert!(unmet[0].contains("PartialMatch"), "got: {unmet:?}");
        // PartialMatch == PartialMatch → pass.
        req.evaluate(&caps_with(true, false, 256, 2, Sain01Verdict::PartialMatch))
            .unwrap();
        // FullMatch > PartialMatch → pass.
        req.evaluate(&full_match_sain01()).unwrap();
    }

    #[test]
    fn sdr14_evaluate_sain01_verdict_full_match_required() {
        let req = HardwareRequirements {
            sain01_verdict_min: "FullMatch".into(),
            ..Default::default()
        };
        // PartialMatch < FullMatch → fail.
        let unmet = req
            .evaluate(&caps_with(true, false, 256, 2, Sain01Verdict::PartialMatch))
            .unwrap_err();
        assert!(unmet[0].contains("FullMatch"), "got: {unmet:?}");
        req.evaluate(&full_match_sain01()).unwrap();
    }

    #[test]
    fn sdr14_evaluate_multiple_failures_listed_together() {
        let req = HardwareRequirements {
            avx512_vnni: true,
            avx512_bf16: true,
            memory_gib_min: 256,
            gpu_count_min: 2,
            gpu_vram_gib_min: 0,
            gpu_power_headroom_watts_min: 0,
            wasm_aot_features_required: String::new(),
            sain01_verdict_min: "FullMatch".into(),
        };
        let unmet = req.evaluate(&minimal_host()).unwrap_err();
        // Every predicate fails on a minimal host: 5 lines (SD-R26
        // gates only fire when their threshold > 0).
        assert_eq!(unmet.len(), 5, "got: {unmet:?}");
    }

    // -- apply_hardware_gate ----------------------------------------

    fn am_with_req(slug: &str, req: HardwareRequirements) -> ActiveModule {
        let manifest = ModuleManifest {
            name: slug.to_string(),
            version: "0.0.0".into(),
            summary: "sdr14 fixture".into(),
            category: "test".into(),
            depends_on: Vec::new(),
            conflicts: Vec::new(),
            provides: Vec::new(),
            consumes: Vec::new(),
            requires: Vec::new(),
            requires_hardware: req,
            install: None,
            profiles: None,
            instanced: false,
            phase: Phase::Main,
            daemon_requires: BTreeMap::new(),
        };
        ActiveModule {
            slug: slug.into(),
            instance: None,
            module_root: PathBuf::from("/tmp/nonexistent-test-root"),
            config_path: PathBuf::from("/tmp/nonexistent-test-cfg"),
            manifest,
        }
    }

    #[test]
    fn sdr14_apply_hardware_gate_keeps_unrestricted_modules() {
        // Hardware-agnostic modules are kept regardless of host caps.
        // The gate must NEVER drop a module whose [requires_hardware]
        // block is empty — that's the contract operators rely on for
        // the 90% of modules that don't care about the host.
        let active = vec![
            am_with_req("alpha", HardwareRequirements::default()),
            am_with_req("beta", HardwareRequirements::default()),
        ];
        let kept = apply_hardware_gate(active);
        let names: Vec<_> = kept.iter().map(|a| a.slug.clone()).collect();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    // -- SD-R26: per-GPU VRAM + power-headroom gates -----------------

    use selfdef_hardware::GpuDeviceCapabilities;

    fn caps_with_gpu_devices(devs: Vec<GpuDeviceCapabilities>) -> HardwareCapabilities {
        let mut c = caps_with(
            false,
            false,
            0,
            u32::try_from(devs.len()).unwrap_or(u32::MAX),
            Sain01Verdict::PartialMatch,
        );
        c.gpu.devices = devs;
        c
    }

    #[test]
    fn sdr26_vram_gate_passes_when_at_least_one_gpu_meets() {
        let req = HardwareRequirements {
            gpu_vram_gib_min: 80,
            ..Default::default()
        };
        // SAIN-01 pair: RTX PRO 6000 (98 GiB) + RTX 3090 (24 GiB).
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                vram_bytes: Some(98 * 1024 * 1024 * 1024),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                vram_bytes: Some(24 * 1024 * 1024 * 1024),
                ..Default::default()
            },
        ]);
        req.evaluate(&caps).unwrap();
    }

    #[test]
    fn sdr26_vram_gate_fails_when_no_gpu_meets() {
        let req = HardwareRequirements {
            gpu_vram_gib_min: 80,
            ..Default::default()
        };
        // Two 24 GiB GPUs — neither big enough for 80.
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                vram_bytes: Some(24 * 1024 * 1024 * 1024),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                vram_bytes: Some(24 * 1024 * 1024 * 1024),
                ..Default::default()
            },
        ]);
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(unmet[0].contains("gpu_vram_gib_min = 80"), "got: {unmet:?}");
        assert!(unmet[0].contains("host best is 24 GiB"), "got: {unmet:?}");
    }

    #[test]
    fn sdr26_vram_gate_fails_when_no_devices_reported() {
        let req = HardwareRequirements {
            gpu_vram_gib_min: 80,
            ..Default::default()
        };
        // No per-device data (probe didn't enrich) — fail closed.
        let caps = caps_with(false, false, 0, 0, Sain01Verdict::NoMatch);
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(unmet[0].contains("host best is 0 GiB"), "got: {unmet:?}");
    }

    #[test]
    fn sdr26_power_headroom_passes_when_sum_meets() {
        let req = HardwareRequirements {
            gpu_power_headroom_watts_min: 400,
            ..Default::default()
        };
        // GPU 0: 600 - 275 = 325 W. GPU 1: 350 - 180 = 170 W. Sum = 495 ≥ 400.
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                power_limit_watts: Some(600),
                power_draw_watts: Some(275),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                power_limit_watts: Some(350),
                power_draw_watts: Some(180),
                ..Default::default()
            },
        ]);
        req.evaluate(&caps).unwrap();
    }

    #[test]
    fn sdr26_power_headroom_fails_when_sum_below_min() {
        let req = HardwareRequirements {
            gpu_power_headroom_watts_min: 600,
            ..Default::default()
        };
        // Sum = 495 W (same caps as above). 495 < 600 → fail.
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                power_limit_watts: Some(600),
                power_draw_watts: Some(275),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                power_limit_watts: Some(350),
                power_draw_watts: Some(180),
                ..Default::default()
            },
        ]);
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(
            unmet[0].contains("gpu_power_headroom_watts_min = 600"),
            "got: {unmet:?}"
        );
        assert!(unmet[0].contains("495 W"), "got: {unmet:?}");
    }

    #[test]
    fn sdr26_power_headroom_fails_when_any_gpu_lacks_telemetry() {
        let req = HardwareRequirements {
            gpu_power_headroom_watts_min: 100,
            ..Default::default()
        };
        // Second GPU has no power telemetry — fail closed (operator
        // asked for headroom guarantee + we can't compute it).
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                power_limit_watts: Some(600),
                power_draw_watts: Some(275),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                power_limit_watts: None,
                power_draw_watts: None,
                ..Default::default()
            },
        ]);
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(unmet[0].contains("lack power telemetry"), "got: {unmet:?}");
    }

    #[test]
    fn sdr26_combined_vram_and_count_gate_on_sain01_dual_gpu() {
        // The canonical "needs the SAIN-01 dual-GPU rig with 80+ GiB
        // headroom on at least one card" inference module gate.
        let req = HardwareRequirements {
            gpu_count_min: 2,
            gpu_vram_gib_min: 80,
            ..Default::default()
        };
        let caps = caps_with_gpu_devices(vec![
            GpuDeviceCapabilities {
                vram_bytes: Some(98 * 1024 * 1024 * 1024),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                vram_bytes: Some(24 * 1024 * 1024 * 1024),
                ..Default::default()
            },
        ]);
        req.evaluate(&caps).unwrap();
        // Single big GPU: passes vram gate but fails count.
        let caps_single = caps_with_gpu_devices(vec![GpuDeviceCapabilities {
            vram_bytes: Some(98 * 1024 * 1024 * 1024),
            ..Default::default()
        }]);
        let unmet = req.evaluate(&caps_single).unwrap_err();
        assert!(
            unmet.iter().any(|u| u.contains("gpu_count_min")),
            "got: {unmet:?}"
        );
    }

    #[test]
    fn sdr26_is_empty_still_true_with_only_old_fields() {
        // Adding new fields must not break the empty short-circuit.
        let req = HardwareRequirements::default();
        assert!(req.is_empty());
        // And asserting any new field flips it correctly.
        let r2 = HardwareRequirements {
            gpu_vram_gib_min: 1,
            ..Default::default()
        };
        assert!(!r2.is_empty());
        let r3 = HardwareRequirements {
            gpu_power_headroom_watts_min: 1,
            ..Default::default()
        };
        assert!(!r3.is_empty());
        // SD-R32: wasm_aot_features_required also flips is_empty.
        let r4 = HardwareRequirements {
            wasm_aot_features_required: "+avx512f".into(),
            ..Default::default()
        };
        assert!(!r4.is_empty());
    }

    // -- SD-R32: wasm_aot_features_required gate ----------------------

    use selfdef_hardware::WasmAotCapabilities;

    fn caps_with_wasm_aot_features(features: &str) -> HardwareCapabilities {
        let mut c = caps_with(true, true, 0, 0, Sain01Verdict::FullMatch);
        c.wasm_aot = WasmAotCapabilities {
            target_triple: "x86_64-unknown-linux-gnu".into(),
            target_cpu: "znver5".into(),
            target_features: features.into(),
            compile_command_hint: String::new(),
        };
        c
    }

    #[test]
    fn sdr32_wasm_aot_features_passes_when_all_present() {
        let req = HardwareRequirements {
            wasm_aot_features_required: "+avx512vnni,+avx512bf16".into(),
            ..Default::default()
        };
        let caps = caps_with_wasm_aot_features("+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma");
        req.evaluate(&caps).unwrap();
    }

    #[test]
    fn sdr32_wasm_aot_features_fails_when_one_missing() {
        let req = HardwareRequirements {
            wasm_aot_features_required: "+avx512vnni,+avx512bf16,+avx512fp16".into(),
            ..Default::default()
        };
        let caps = caps_with_wasm_aot_features("+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma");
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(
            unmet[0].contains("host missing: +avx512fp16"),
            "got: {unmet:?}"
        );
    }

    #[test]
    fn sdr32_wasm_aot_features_fails_on_empty_host_features() {
        // Host has no wasm-AOT features at all → every required
        // feature is "missing".
        let req = HardwareRequirements {
            wasm_aot_features_required: "+avx512f".into(),
            ..Default::default()
        };
        let caps = caps_with_wasm_aot_features("");
        let unmet = req.evaluate(&caps).unwrap_err();
        assert!(
            unmet[0].contains("host missing: +avx512f"),
            "got: {unmet:?}"
        );
    }

    #[test]
    fn sdr32_wasm_aot_features_tolerates_whitespace_in_required_list() {
        let req = HardwareRequirements {
            wasm_aot_features_required: " +avx512vnni , +avx512bf16 ".into(),
            ..Default::default()
        };
        let caps = caps_with_wasm_aot_features("+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma");
        req.evaluate(&caps).unwrap();
    }

    #[test]
    fn sdr32_wasm_aot_features_required_empty_is_no_op() {
        // Empty string in the manifest disables the gate even when
        // the host has no wasm-AOT data.
        let req = HardwareRequirements {
            wasm_aot_features_required: String::new(),
            ..Default::default()
        };
        let caps = caps_with_wasm_aot_features("");
        req.evaluate(&caps).unwrap();
    }

    #[test]
    fn sdr15_check_hardware_runs_against_fixture_catalog() {
        // SD-R15: `selfdefctl modules check-hardware` is read-only;
        // make sure the entry point completes with rc=0 against a
        // catalog where one module is unrestricted and one has a
        // mem-threshold gate. We can't pin exact stdout (the test
        // host's caps vary across CI / dev boxes), but the function
        // must succeed without panicking.
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let cat = dir.path().join("catalog");
        std::fs::create_dir_all(cat.join("alpha")).unwrap();
        std::fs::create_dir_all(cat.join("beta")).unwrap();
        std::fs::write(
            cat.join("alpha/module.toml"),
            "name = \"alpha\"\nversion = \"0.0.0\"\nsummary = \"unrestricted\"\n",
        )
        .unwrap();
        std::fs::write(
            cat.join("beta/module.toml"),
            "name = \"beta\"\nversion = \"0.0.0\"\nsummary = \"hardware-gated\"\n\
             [requires_hardware]\nmemory_gib_min = 9999999\n",
        )
        .unwrap();
        let host = dir.path().join("modules.toml");
        std::fs::write(&host, "[modules.alpha]\n[modules.beta]\n").unwrap();
        let opts = LifecycleOpts {
            host_config: Some(host),
            dir: Some(cat),
            ..Default::default()
        };
        let rc = cmd_check_hardware(&opts, false).unwrap();
        assert_eq!(rc, 0);
        let rc_json = cmd_check_hardware(&opts, true).unwrap();
        assert_eq!(rc_json, 0);
    }

    #[test]
    fn sdr14_filter_active_respects_requires_hardware_field() {
        // Sanity check: the field round-trips through clone_manifest.
        // (Touched in this round; if the new field is forgotten there
        // the gate silently misbehaves for instanced modules.)
        let am = am_with_req(
            "needs-vnni",
            HardwareRequirements {
                avx512_vnni: true,
                ..Default::default()
            },
        );
        let cloned = clone_manifest(&am.manifest);
        assert!(cloned.requires_hardware.avx512_vnni);
        assert!(!cloned.requires_hardware.is_empty());
    }
}
