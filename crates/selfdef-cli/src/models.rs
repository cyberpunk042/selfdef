//! SD-R34: model registry surface — declarative manifest format for
//! 1-bit / ternary / quantised model artifacts the operator wants to
//! land on their host. Each `model.toml` declares the artifact's
//! provenance + hardware requirements; the registry surface lets
//! operators dry-run "would this model apply on THIS host?" using
//! the SAME predicate engine as SD-R14 [requires_hardware].
//!
//! Operator surface:
//!
//!   $ tree /etc/selfdef/models
//!   /etc/selfdef/models
//!   ├── bitnet-b1.58-2B-4T
//!   │   └── model.toml
//!   └── llama-3-8b-q4
//!       └── model.toml
//!
//!   $ selfdefctl models check-hardware
//!   # SD-R34 model-registry dry-run
//!   WOULD APPLY (1):
//!     ✓ bitnet-b1.58-2B-4T (3.2 GiB, ternary; AVX-512 VNNI met)
//!   WOULD SKIP (1):
//!     ✗ llama-3-8b-q4 (8.0 GiB, q4)
//!       - gpu_vram_gib_min = 8 (host best is 0 GiB)
//!
//! Schema is operator-stable and forward-compat: new optional fields
//! land via `#[serde(default)]`.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// SD-R34: top-level manifest for a model the operator wants
/// registered. Format mirrors selfdef module.toml: a `[model]`
/// header block + a `[hardware]` predicate block.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ModelManifest {
    pub(crate) model: ModelSpec,
    /// Hardware requirements gate — same predicate set as SD-R14
    /// (plus SD-R26 + SD-R32 cycle-2 extensions). Empty / absent
    /// means the model applies on any host.
    #[serde(default)]
    pub(crate) hardware: ModelHardwareRequirements,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // SD-R34: schema is operator-stable; some fields are
// currently informational + read by future rounds
// (model fetcher, signature verifier).
pub(crate) struct ModelSpec {
    /// Operator-stable identifier (e.g. `"bitnet-b1.58-2B-4T"`).
    pub(crate) name: String,
    /// Version string.
    #[serde(default)]
    pub(crate) version: String,
    /// Short one-line description.
    #[serde(default)]
    pub(crate) summary: String,
    /// Where to fetch the artifact from. Operators typically
    /// HuggingFace direct-resolve URLs but the registry doesn't
    /// constrain this — local file:// + s3:// are valid.
    #[serde(default)]
    pub(crate) artifact_url: String,
    /// SHA256 of the artifact. Operators MUST set this when they
    /// trust the URL; consumers (sovereign-os build-bitnet, future
    /// model-fetcher hooks) refuse to land an artifact whose digest
    /// doesn't match.
    #[serde(default)]
    pub(crate) artifact_sha256: String,
    /// Disk footprint of the model in bytes (after download +
    /// extraction). Used by the registry to surface "WOULD APPLY"
    /// only when there's headroom on the target filesystem (future
    /// round; this round just records the value).
    #[serde(default)]
    pub(crate) size_bytes: u64,
    /// Weight quantisation format. Operator-stable string; common
    /// values: `"ternary"` (BitNet 1.58-bit), `"int8"`, `"int4"`,
    /// `"q4_k_m"`, `"q5_k_m"`, `"fp16"`, `"fp32"`. Used by
    /// downstream tooling to pick the right loader.
    #[serde(default)]
    pub(crate) weight_format: String,

    // ---- SD-R71: R212 model-class taxonomy mirror -----------------
    //
    // Mirrors the operator-facing taxonomy from sovereign-os R212
    // (schemas/model-catalog.schema.yaml). The fields are all
    // Option-typed / default to "" or empty Vec so pre-SD-R71 model
    // registries keep deserialising cleanly. cmd_list + JSON outputs
    // surface them so operators see the SAME taxonomy on either side.
    /// SD-R71: model class — `"llm" | "slm" | "rlm" | "ternary-lm" |
    /// "lora-adapter" | "embed" | "vision" | "multimodal" | "code" |
    /// "mixture" | "speculative" | "reranker"`. Free-string because
    /// the registry doesn't constrain the operator (sovereign-os
    /// catalog DOES constrain via JSON Schema).
    #[serde(default)]
    pub(crate) class: String,

    /// SD-R71: operator-readable size bucket — `"xs" | "s" | "m" |
    /// "l" | "xl" | "xxl"`. <1B / 1-7B / 7-30B / 30-70B / 70-200B / >200B.
    #[serde(default)]
    pub(crate) size_class: String,

    /// SD-R71: operator-readable purpose tags (chat / reasoning /
    /// code / multimodal / embedding / vision / agent / function-
    /// calling / rag / speculation / reranking / distillation-base).
    /// Multiple allowed; a model can serve several roles.
    #[serde(default)]
    pub(crate) purpose: Vec<String>,

    /// SD-R71: minimum VRAM (GiB) for live inference at the declared
    /// `weight_format` + a small context. Operator-facing reality
    /// check before pulling the artifact.
    #[serde(default)]
    pub(crate) vram_gib_min: f64,

    /// SD-R71: max context window in tokens.
    #[serde(default)]
    pub(crate) context_window_tokens: u64,

    /// SD-R71: when `class == "lora-adapter"`, the base model id
    /// this adapter attaches to. Operator-readable; not enforced
    /// at the schema level (registry is permissive — sovereign-os
    /// catalog is the strict source).
    #[serde(default)]
    pub(crate) base_model: String,
}

/// SD-R34: hardware predicates governing whether a model lands.
/// Mirror of modules::HardwareRequirements with the same SD-R14 +
/// SD-R26 + SD-R32 surface — but kept as a separate struct so the
/// model + module sides can evolve independently when their
/// predicate sets diverge.
#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct ModelHardwareRequirements {
    #[serde(default)]
    pub(crate) avx512_vnni: bool,
    #[serde(default)]
    pub(crate) avx512_bf16: bool,
    #[serde(default)]
    pub(crate) memory_gib_min: u64,
    #[serde(default)]
    pub(crate) gpu_count_min: u32,
    #[serde(default)]
    pub(crate) gpu_vram_gib_min: u64,
    #[serde(default)]
    pub(crate) wasm_aot_features_required: String,
    #[serde(default)]
    pub(crate) sain01_verdict_min: String,
}

impl ModelHardwareRequirements {
    /// Returns Ok iff every set requirement passes; Err with a list
    /// of unmet predicates otherwise. Mirrors
    /// modules::HardwareRequirements::evaluate.
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
        if !self.wasm_aot_features_required.is_empty() {
            let actual: HashSet<&str> = caps
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
}

/// Default model-registry directory: `/etc/selfdef/models` system-wide,
/// or the workspace `models-registry/` fallback for dev runs.
const SYSTEM_MODELS_DIR: &str = "/etc/selfdef/models";

pub(crate) fn resolve_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    let system = PathBuf::from(SYSTEM_MODELS_DIR);
    if system.exists() {
        return system;
    }
    // Workspace fallback for `cargo run`: crates/selfdef-cli/ -> ../../models-registry
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("../../models-registry")
}

/// Load every `model.toml` directly under `dir`. Returns (slug, manifest)
/// pairs in stable directory order. Missing-dir → Ok(empty).
pub(crate) fn load_all(dir: &Path) -> Result<Vec<(String, ModelManifest)>> {
    if !dir.exists() {
        return Ok(Vec::new());
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
        let manifest_path = entry.path().join("model.toml");
        if !manifest_path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("reading {}", manifest_path.display()))?;
        let manifest: ModelManifest = toml::from_str(&content)
            .with_context(|| format!("parsing {}", manifest_path.display()))?;
        out.push((slug, manifest));
    }
    Ok(out)
}

/// SD-R34 `selfdefctl models check-hardware` — dry-run the predicate
/// gate against the host's HardwareCapabilities. Same output shape
/// as SD-R15 modules check-hardware so operators learn one surface.
pub(crate) fn cmd_check_hardware(dir: Option<&Path>, json: bool) -> Result<i32> {
    let resolved = resolve_dir(dir);
    let catalog = load_all(&resolved)?;
    let caps = match selfdef_hardware::probe() {
        Ok(snap) => Some(selfdef_hardware::derive_capabilities(&snap)),
        Err(_) => None,
    };
    let mut kept: Vec<(String, String, u64, String)> = Vec::new();
    // (name, reason, size_bytes, weight_format)
    let mut skipped: Vec<(String, Vec<String>, u64, String)> = Vec::new();
    let mut probe_ok = caps.is_some();
    for (slug, m) in &catalog {
        match &caps {
            Some(c) => match m.hardware.evaluate(c) {
                Ok(()) => kept.push((
                    slug.clone(),
                    "all hardware requirements met".into(),
                    m.model.size_bytes,
                    m.model.weight_format.clone(),
                )),
                Err(unmet) => skipped.push((
                    slug.clone(),
                    unmet,
                    m.model.size_bytes,
                    m.model.weight_format.clone(),
                )),
            },
            None => {
                probe_ok = false;
                skipped.push((
                    slug.clone(),
                    vec!["hardware probe unavailable".into()],
                    m.model.size_bytes,
                    m.model.weight_format.clone(),
                ));
            }
        }
    }
    if json {
        let kept_json: Vec<String> = kept
            .iter()
            .map(|(n, r, sz, fmt)| {
                format!(
                    r#"{{"model":"{n}","reason":"{r}","size_bytes":{sz},"weight_format":"{fmt}"}}"#
                )
            })
            .collect();
        let skipped_json: Vec<String> = skipped
            .iter()
            .map(|(n, reasons, sz, fmt)| {
                let r = reasons
                    .iter()
                    .map(|s| format!(r#""{}""#, s.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"model":"{n}","unmet":[{r}],"size_bytes":{sz},"weight_format":"{fmt}"}}"#
                )
            })
            .collect();
        println!(
            r#"{{"probe_ok":{},"total":{},"kept":[{}],"skipped":[{}]}}"#,
            probe_ok,
            kept.len() + skipped.len(),
            kept_json.join(","),
            skipped_json.join(","),
        );
    } else {
        println!("# SD-R34 model-registry dry-run");
        if !probe_ok {
            println!("# (hardware probe unavailable — gated models will be skipped)");
        }
        println!("# {} registered model(s):", kept.len() + skipped.len());
        if !kept.is_empty() {
            println!();
            println!("WOULD APPLY ({}):", kept.len());
            for (name, reason, sz, fmt) in &kept {
                let size_human = humanize_bytes(*sz);
                println!("  ✓ {name} ({size_human}, {fmt}; {reason})");
            }
        }
        if !skipped.is_empty() {
            println!();
            println!("WOULD SKIP ({}):", skipped.len());
            for (name, reasons, sz, fmt) in &skipped {
                let size_human = humanize_bytes(*sz);
                println!("  ✗ {name} ({size_human}, {fmt})");
                for r in reasons {
                    println!("      - {r}");
                }
            }
        }
    }
    Ok(0)
}

/// SD-R34 `selfdefctl models list` — operator-friendly catalog
/// listing without the gate evaluation. Read-only.
/// SD-R57 (closes SDD-019 T-3 fetch-side): download a model
/// artifact + verify its sha256 against the manifest declaration.
/// Operator workflow:
///
///   $ selfdefctl models fetch bitnet-b1.58-2B-4T --to /mnt/vault/models/bitnet/model.gguf
///
/// Behavior:
///   - Reads the manifest at <dir>/<slug>/model.toml
///   - GETs artifact_url; streams to a tempfile next to --to
///   - Streams through sha256; refuses to rename when digest mismatches
///   - On match, atomic rename to --to
///
/// Mandatory: artifact_sha256 MUST be present in the manifest. The
/// fetcher refuses to write a file we can't verify. Operators pin
/// sha256 at manifest authoring time + commit the pinned value.
///
/// Operator-supplied tokens: env `HUGGINGFACE_HUB_TOKEN` (or
/// `--token <env-name>`) → forwarded as a Bearer header. Never read
/// from the manifest (operator-supplied keys NEVER in-repo).
pub(crate) async fn cmd_fetch(
    dir: Option<&Path>,
    slug: &str,
    to: &Path,
    token_env: Option<&str>,
) -> Result<i32> {
    let resolved = resolve_dir(dir);
    let mods = load_all(&resolved)?;
    let m = mods
        .iter()
        .find(|(s, _)| s == slug)
        .map(|(_, m)| m)
        .with_context(|| format!("no model `{slug}` in {}", resolved.display()))?;
    if m.model.artifact_url.is_empty() {
        anyhow::bail!("model `{slug}` has no artifact_url — operator must pin one in model.toml");
    }
    if m.model.artifact_sha256.is_empty() {
        anyhow::bail!(
            "model `{slug}` has no artifact_sha256 — refusing to fetch unverifiable artifact"
        );
    }

    // Stage a tempfile next to the destination so the atomic rename
    // stays on the same filesystem.
    if let Some(parent) = to.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating destination dir {}", parent.display()))?;
        }
    }
    let mut tmp_path = std::ffi::OsString::from(to);
    tmp_path.push(".partial");
    let tmp_path = std::path::PathBuf::from(tmp_path);

    eprintln!(
        "# SD-R57: fetching {} → {}",
        m.model.artifact_url,
        to.display()
    );
    eprintln!("#   expected sha256: {}", m.model.artifact_sha256);

    let mut req = reqwest::Client::new().get(&m.model.artifact_url);
    if let Some(env_name) = token_env {
        if let Ok(tok) = std::env::var(env_name) {
            if !tok.is_empty() {
                req = req.bearer_auth(tok);
                eprintln!("#   auth: Bearer from ${env_name}");
            }
        }
    }
    let mut resp = req
        .send()
        .await
        .with_context(|| format!("GET {}", m.model.artifact_url))?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {} fetching {}", resp.status(), m.model.artifact_url);
    }

    // Stream → sha256 + tempfile in parallel.
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;
    let mut hasher = Sha256::new();
    let mut bytes_written: u64 = 0;
    let mut f = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("create {}", tmp_path.display()))?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("read chunk from {}", m.model.artifact_url))?
    {
        hasher.update(&chunk);
        f.write_all(&chunk)
            .await
            .with_context(|| format!("write to {}", tmp_path.display()))?;
        bytes_written = bytes_written.saturating_add(chunk.len() as u64);
    }
    f.sync_all().await.ok();
    drop(f);

    let actual = hasher.finalize();
    let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
    let expected = m.model.artifact_sha256.trim().to_ascii_lowercase();

    if actual_hex != expected {
        // Tampered or wrong artifact — refuse to commit.
        let _ = std::fs::remove_file(&tmp_path);
        eprintln!("# SD-R57: ✗ digest MISMATCH — refusing to rename");
        eprintln!("#   expected: {expected}");
        eprintln!("#   actual:   {actual_hex}");
        anyhow::bail!("sha256 mismatch on {slug} ({bytes_written} bytes downloaded)");
    }
    std::fs::rename(&tmp_path, to)
        .with_context(|| format!("rename {} → {}", tmp_path.display(), to.display()))?;
    eprintln!(
        "# SD-R57: ✓ verified {actual_hex} ({bytes_written} bytes) → {}",
        to.display()
    );
    Ok(0)
}

pub(crate) fn cmd_list(dir: Option<&Path>) -> Result<i32> {
    let resolved = resolve_dir(dir);
    let catalog = load_all(&resolved)?;
    if catalog.is_empty() {
        println!("(no models registered in {})", resolved.display());
        return Ok(0);
    }
    // SD-R71: include R212 taxonomy columns when any model in the
    // catalog declares them.
    println!(
        "{:<32}  {:<14}  {:<6}  {:<5}  {:<10}  summary",
        "name", "class", "size", "quant", "footprint"
    );
    for (slug, m) in &catalog {
        let size_human = humanize_bytes(m.model.size_bytes);
        let fmt = if m.model.weight_format.is_empty() {
            "?"
        } else {
            m.model.weight_format.as_str()
        };
        let class = if m.model.class.is_empty() {
            "?"
        } else {
            m.model.class.as_str()
        };
        let size_class = if m.model.size_class.is_empty() {
            "?"
        } else {
            m.model.size_class.as_str()
        };
        println!(
            "{:<32}  {:<14}  {:<6}  {:<5}  {:<10}  {}",
            slug, class, size_class, fmt, size_human, m.model.summary
        );
    }
    Ok(0)
}

fn humanize_bytes(b: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if b == 0 {
        "?".to_string()
    } else if b >= GIB {
        format!("{:.1} GiB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.1} MiB", b as f64 / MIB as f64)
    } else {
        format!("{b} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_hardware::{
        CpuCapabilities, GpuCapabilities, GpuDeviceCapabilities, HardwareCapabilities,
        MemoryCapabilities, PcieCapabilities, Sain01Match, Sain01Verdict, WasmAotCapabilities,
    };

    fn caps_sain01() -> HardwareCapabilities {
        HardwareCapabilities {
            schema_version: "1.2.0".into(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            host_tag: None,
            cpu: CpuCapabilities {
                avx512vnni: true,
                avx512bf16: true,
                ..Default::default()
            },
            memory: MemoryCapabilities {
                total_bytes: 256 * 1024 * 1024 * 1024,
                at_least_256gb: true,
                at_least_512gb: false,
            },
            gpu: GpuCapabilities {
                device_count: 2,
                device_nodes: Vec::new(),
                devices: vec![
                    GpuDeviceCapabilities {
                        vram_bytes: Some(98 * 1024 * 1024 * 1024),
                        ..Default::default()
                    },
                    GpuDeviceCapabilities {
                        vram_bytes: Some(24 * 1024 * 1024 * 1024),
                        ..Default::default()
                    },
                ],
            },
            pcie: PcieCapabilities::default(),
            sain01_match: Sain01Match {
                overall: Sain01Verdict::FullMatch,
                cpu_avx512_vnni: true,
                cpu_avx512_bf16: true,
                memory_at_least_256gb: true,
                gpu_count_at_least_2: true,
                motherboard_proart_x870e: None,
                pcie_dual_x8_present: false,
            },
            wasm_aot: WasmAotCapabilities {
                target_triple: "x86_64-unknown-linux-gnu".into(),
                target_cpu: "znver5".into(),
                target_features: "+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma".into(),
                compile_command_hint: String::new(),
                ternary_kernel_hint: String::new(),
            },
        }
    }

    fn caps_minimal() -> HardwareCapabilities {
        HardwareCapabilities {
            schema_version: "1.2.0".into(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            host_tag: None,
            cpu: CpuCapabilities::default(),
            memory: MemoryCapabilities {
                total_bytes: 8 * 1024 * 1024 * 1024,
                at_least_256gb: false,
                at_least_512gb: false,
            },
            gpu: GpuCapabilities::default(),
            pcie: PcieCapabilities::default(),
            sain01_match: Sain01Match {
                overall: Sain01Verdict::NoMatch,
                cpu_avx512_vnni: false,
                cpu_avx512_bf16: false,
                memory_at_least_256gb: false,
                gpu_count_at_least_2: false,
                motherboard_proart_x870e: None,
                pcie_dual_x8_present: false,
            },
            wasm_aot: WasmAotCapabilities::default(),
        }
    }

    #[test]
    fn sdr34_evaluate_empty_passes() {
        let req = ModelHardwareRequirements::default();
        req.evaluate(&caps_minimal()).unwrap();
        req.evaluate(&caps_sain01()).unwrap();
    }

    #[test]
    fn sdr34_evaluate_bitnet_typical_passes_on_sain01() {
        // Typical BitNet b1.58 model: needs AVX-512 VNNI + BF16 +
        // a couple of GiB RAM.
        let req = ModelHardwareRequirements {
            avx512_vnni: true,
            avx512_bf16: true,
            memory_gib_min: 4,
            ..Default::default()
        };
        req.evaluate(&caps_sain01()).unwrap();
    }

    #[test]
    fn sdr34_evaluate_70b_quantised_fails_on_minimal() {
        // A 70B Q4 model wanting 48 GiB VRAM headroom.
        let req = ModelHardwareRequirements {
            gpu_count_min: 1,
            gpu_vram_gib_min: 48,
            ..Default::default()
        };
        let unmet = req.evaluate(&caps_minimal()).unwrap_err();
        assert!(
            unmet.iter().any(|u| u.contains("gpu_count_min")),
            "got: {unmet:?}"
        );
    }

    #[test]
    fn sdr34_evaluate_wasm_aot_features_required() {
        let req = ModelHardwareRequirements {
            wasm_aot_features_required: "+avx512vnni,+avx512bf16".into(),
            ..Default::default()
        };
        req.evaluate(&caps_sain01()).unwrap();
        let unmet = req.evaluate(&caps_minimal()).unwrap_err();
        assert!(
            unmet[0].contains("wasm_aot_features_required"),
            "got: {unmet:?}"
        );
    }

    #[test]
    fn sdr34_load_all_parses_manifest_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bitnet-2b")).unwrap();
        std::fs::write(
            dir.path().join("bitnet-2b/model.toml"),
            r#"
[model]
name = "bitnet-b1.58-2B-4T"
version = "1.0"
summary = "Microsoft BitNet 1.58-bit 2B-param ternary model"
artifact_url = "https://huggingface.co/microsoft/bitnet-b1.58-2B-4T/resolve/main/model.gguf"
artifact_sha256 = "deadbeef"
size_bytes = 1700000000
weight_format = "ternary"

[hardware]
avx512_vnni = true
memory_gib_min = 4
"#,
        )
        .unwrap();
        let catalog = load_all(dir.path()).unwrap();
        assert_eq!(catalog.len(), 1);
        let (slug, m) = &catalog[0];
        assert_eq!(slug, "bitnet-2b");
        assert_eq!(m.model.name, "bitnet-b1.58-2B-4T");
        assert_eq!(m.model.weight_format, "ternary");
        assert!(m.hardware.avx512_vnni);
        assert_eq!(m.hardware.memory_gib_min, 4);
    }

    #[test]
    fn sdr34_load_all_returns_empty_on_missing_dir() {
        let p = std::path::PathBuf::from("/nonexistent-models-registry-path");
        let catalog = load_all(&p).unwrap();
        assert!(catalog.is_empty());
    }

    #[test]
    fn sdr34_cmd_check_hardware_runs_on_fixture() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("alpha")).unwrap();
        std::fs::write(
            dir.path().join("alpha/model.toml"),
            "[model]\nname=\"alpha\"\nweight_format=\"int8\"\nsize_bytes=1073741824\n",
        )
        .unwrap();
        // Should succeed regardless of host caps (no [hardware] block).
        let rc = cmd_check_hardware(Some(dir.path()), false).unwrap();
        assert_eq!(rc, 0);
        let rc_json = cmd_check_hardware(Some(dir.path()), true).unwrap();
        assert_eq!(rc_json, 0);
    }

    #[test]
    fn sdr34_humanize_bytes() {
        assert_eq!(humanize_bytes(0), "?");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024 + 700_000_000), "1.7 GiB");
    }
}
