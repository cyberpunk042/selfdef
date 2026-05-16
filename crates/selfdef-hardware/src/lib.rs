//! SAIN-01 hardware inventory + fitness verdict (SDD-017).
//!
//! Provides:
//! - [`HardwareSnapshot`] — structured introspection of the host
//!   (CPU features, memory, GPUs, motherboard, PCIe x8 slots).
//! - [`Sain01Match`] — 5-dimensional verdict comparing the snapshot
//!   against the SAIN-01 master-spec target (AVX-512 + 256GB +
//!   2× NVIDIA GPUs + dual PCIe x8 + optional ProArt X870E mobo).
//! - [`probe`] — single entry point. Best-effort: missing files /
//!   absent kernel surfaces produce `None` fields, never panic.
//!
//! Discovery sources:
//! - `/proc/cpuinfo`         — CPU features
//! - `/proc/meminfo`         — MemTotal
//! - `/dev/nvidia*`          — GPU device-node count
//! - `/sys/class/dmi/id/`    — board vendor + product
//!
//! Not in scope (per SDD-017 Non-goals):
//! - Kernel version pinning (sovereign-os SDD-018 owns kernel choice).
//! - AMD ROCm GPU discovery (v1 = NVIDIA only).
//! - Continuous polling (probe is per-call; daemon does it once at startup).

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("time formatting failed")]
    TimeFmt,
}

/// Snapshot of the host hardware at probe time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSnapshot {
    pub cpu: CpuInventory,
    pub memory: MemoryInventory,
    pub gpus: Vec<GpuInventory>,
    pub motherboard: Option<MotherboardInventory>,
    pub pcie: PcieInventory,
    pub probed_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuInventory {
    pub vendor: String,
    pub model_name: String,
    pub physical_cores: u32,
    pub logical_threads: u32,
    pub features: HashSet<String>,
    pub avx512_present: bool,
    pub avx512_vnni: bool,
    pub avx512_bf16: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryInventory {
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInventory {
    pub device_node: PathBuf,
    pub pci_address: Option<String>,
    pub model_hint: Option<String>,
    pub vram_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MotherboardInventory {
    pub vendor: Option<String>,
    pub product_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcieInventory {
    pub gen4_or_higher_x8_slot_count: u32,
}

// ---------------------------------------------------------------- Sain01Match

/// 5-dimensional fitness verdict for the SAIN-01 spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Sain01Verdict {
    FullMatch,
    PartialMatch,
    NoMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sain01Match {
    pub overall: Sain01Verdict,
    pub cpu_avx512_vnni: bool,
    pub cpu_avx512_bf16: bool,
    pub memory_at_least_256gb: bool,
    pub gpu_count_at_least_2: bool,
    /// `None` when DMI is unreadable (operator can't tell ⇒ neutral
    /// for the verdict).
    pub motherboard_proart_x870e: Option<bool>,
    pub pcie_dual_x8_present: bool,
}

const BYTES_256_GB: u64 = 256 * 1024 * 1024 * 1024;

#[must_use]
pub fn matches_sain01(snap: &HardwareSnapshot) -> Sain01Match {
    let cpu_avx512_vnni = snap.cpu.avx512_vnni;
    let cpu_avx512_bf16 = snap.cpu.avx512_bf16;
    let memory_at_least_256gb = snap.memory.total_bytes >= BYTES_256_GB;
    let gpu_count_at_least_2 = snap.gpus.len() >= 2;
    let pcie_dual_x8_present = snap.pcie.gen4_or_higher_x8_slot_count >= 2;
    let motherboard_proart_x870e = snap.motherboard.as_ref().map(motherboard_is_proart_x870e);

    let mut hits = 0_u32;
    let mut total = 4_u32; // cpu_vnni + memory + gpu_count + pcie always count
    if cpu_avx512_vnni {
        hits += 1;
    }
    if memory_at_least_256gb {
        hits += 1;
    }
    if gpu_count_at_least_2 {
        hits += 1;
    }
    if pcie_dual_x8_present {
        hits += 1;
    }
    // CPU bf16 + mobo are bonus dimensions when present.
    if cpu_avx512_bf16 {
        hits += 1;
        total += 1;
    }
    match motherboard_proart_x870e {
        Some(true) => {
            hits += 1;
            total += 1;
        }
        Some(false) => {
            // DMI is readable but the board doesn't match — count
            // toward total but not hits. Operator wanted to know.
            total += 1;
        }
        None => {
            // DMI unreadable — neutral (drops from both sides).
        }
    }
    let overall = match hits {
        n if n == total => Sain01Verdict::FullMatch,
        0 => Sain01Verdict::NoMatch,
        _ => Sain01Verdict::PartialMatch,
    };
    Sain01Match {
        overall,
        cpu_avx512_vnni,
        cpu_avx512_bf16,
        memory_at_least_256gb,
        gpu_count_at_least_2,
        motherboard_proart_x870e,
        pcie_dual_x8_present,
    }
}

fn motherboard_is_proart_x870e(mb: &MotherboardInventory) -> bool {
    let vendor_ok = mb
        .vendor
        .as_deref()
        .is_some_and(|v| v.to_ascii_lowercase().contains("asus"));
    let product_ok = mb.product_name.as_deref().is_some_and(|p| {
        let p = p.to_ascii_lowercase();
        p.contains("proart") && p.contains("x870e")
    });
    vendor_ok && product_ok
}

// ---------------------------------------------------------------- probe

/// Probe the host for a [`HardwareSnapshot`]. Best-effort: missing
/// files don't panic — the affected fields are returned with `None` or
/// default values + a WARN log.
pub fn probe() -> Result<HardwareSnapshot, HardwareError> {
    probe_from_roots(
        Path::new("/proc/cpuinfo"),
        Path::new("/proc/meminfo"),
        Path::new("/dev"),
        Path::new("/sys/class/dmi/id"),
    )
}

/// Test-friendly variant: every source root is explicit so tests can
/// stage a tempdir filesystem.
pub fn probe_from_roots(
    cpuinfo_path: &Path,
    meminfo_path: &Path,
    dev_dir: &Path,
    dmi_dir: &Path,
) -> Result<HardwareSnapshot, HardwareError> {
    let cpu = read_cpuinfo(cpuinfo_path);
    let memory = read_meminfo(meminfo_path);
    let gpus = read_gpu_device_nodes(dev_dir);
    let motherboard = read_motherboard(dmi_dir);
    // SD-R12: PCIe x8 detection via lspci (subprocess). When lspci is
    // unavailable or returns nothing parseable, falls back to 0 — the
    // operator can still run sovereign-os friction-audit for the
    // authoritative read.
    let pcie = probe_pcie_via_lspci();
    let probed_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .map_err(|_| HardwareError::TimeFmt)?;
    Ok(HardwareSnapshot {
        cpu,
        memory,
        gpus,
        motherboard,
        pcie,
        probed_at,
    })
}

// ---------------------------------------------------------------- PCIe (SD-R12)

/// SD-R12: invoke `lspci -vv` and count slots that show
/// `LnkSta: Speed (16|32)GT/s Width x8`. Best-effort — lspci absent /
/// timed out / empty output → returns the default (count = 0).
fn probe_pcie_via_lspci() -> PcieInventory {
    let output = match std::process::Command::new("lspci")
        .arg("-vv")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return PcieInventory::default(),
    };
    let body = String::from_utf8_lossy(&output.stdout);
    PcieInventory {
        gen4_or_higher_x8_slot_count: count_pcie_x8_gen4_plus(&body),
    }
}

/// SD-R12: pure parser for `lspci -vv` output. Counts every line that
/// matches `LnkSta:` AND `Width x8` AND `Speed (16|32)<...>GT/s`
/// (Gen 4 = 16 GT/s, Gen 5 = 32 GT/s — both qualify for the SAIN-01
/// "x8/x8 at Gen 4+" master spec § 1.2 invariant).
///
/// Pure function — tests pin every parsing edge case.
#[must_use]
pub fn count_pcie_x8_gen4_plus(lspci_vv_body: &str) -> u32 {
    let mut count = 0_u32;
    for line in lspci_vv_body.lines() {
        let line = line.trim();
        if !line.starts_with("LnkSta:") {
            continue;
        }
        if !line.contains("Width x8") {
            continue;
        }
        // Speed token: "Speed 16GT/s" or "Speed 32GT/s" — both Gen 4+.
        // Accept the variations "Speed 16.0GT/s" too (older lspci).
        let has_gen4_plus = line.contains("Speed 16GT/s")
            || line.contains("Speed 32GT/s")
            || line.contains("Speed 16.0GT/s")
            || line.contains("Speed 32.0GT/s");
        if has_gen4_plus {
            count += 1;
        }
    }
    count
}

// ---------------------------------------------------------------- /proc/cpuinfo

fn read_cpuinfo(path: &Path) -> CpuInventory {
    let mut inv = CpuInventory::default();
    let body = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cpuinfo unreadable");
            return inv;
        }
    };
    let mut processor_count = 0_u32;
    let mut physical_cores_seen: HashSet<(String, String)> = HashSet::new();
    let mut current_physical_id = String::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("processor") {
            if rest.contains(':') {
                processor_count += 1;
            }
        } else if let Some((k, v)) = split_kv(line) {
            match k.as_str() {
                "vendor_id" => inv.vendor = v,
                "model name" => inv.model_name = v,
                "physical id" => current_physical_id = v,
                "core id" => {
                    physical_cores_seen.insert((current_physical_id.clone(), v));
                }
                "flags" => {
                    for f in v.split_whitespace() {
                        inv.features.insert(f.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    inv.logical_threads = processor_count;
    inv.physical_cores = if physical_cores_seen.is_empty() {
        processor_count
    } else {
        physical_cores_seen.len() as u32
    };
    inv.avx512_present = inv.features.iter().any(|f| f.starts_with("avx512"));
    inv.avx512_vnni = inv.features.contains("avx512_vnni");
    inv.avx512_bf16 = inv.features.contains("avx512_bf16");
    inv
}

fn split_kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim().to_owned(), v.trim().to_owned()))
}

// ---------------------------------------------------------------- /proc/meminfo

fn read_meminfo(path: &Path) -> MemoryInventory {
    let mut inv = MemoryInventory::default();
    let body = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "meminfo unreadable");
            return inv;
        }
    };
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let toks: Vec<_> = rest.split_whitespace().collect();
            if let Some(n) = toks.first().and_then(|s| s.parse::<u64>().ok()) {
                // /proc/meminfo reports kB. Convert to bytes.
                inv.total_bytes = n.saturating_mul(1024);
            }
            break;
        }
    }
    inv
}

// ---------------------------------------------------------------- /dev/nvidia*

fn read_gpu_device_nodes(dev_dir: &Path) -> Vec<GpuInventory> {
    let mut out = Vec::new();
    let read_dir = match fs::read_dir(dev_dir) {
        Ok(r) => r,
        Err(e) => {
            warn!(path = %dev_dir.display(), error = %e, "dev dir unreadable");
            return out;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("nvidia") {
            continue;
        }
        // Skip sub-entries like /dev/nvidiactl, /dev/nvidia-uvm.
        let rest = &name["nvidia".len()..];
        if !rest.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if rest.is_empty() {
            continue;
        }
        out.push(GpuInventory {
            device_node: path,
            pci_address: None,
            model_hint: None,
            vram_bytes: None,
        });
    }
    out.sort_by(|a, b| a.device_node.cmp(&b.device_node));
    out
}

// ---------------------------------------------------------------- /sys/class/dmi/id

fn read_motherboard(dmi_dir: &Path) -> Option<MotherboardInventory> {
    if !dmi_dir.exists() {
        return None;
    }
    let read = |name: &str| -> Option<String> {
        fs::read_to_string(dmi_dir.join(name))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    let vendor = read("board_vendor");
    let product_name = read("board_name");
    if vendor.is_none() && product_name.is_none() {
        return None;
    }
    Some(MotherboardInventory {
        vendor,
        product_name,
    })
}

// ---------------------------------------------------------------- HardwareCapabilities (SDD-017 § 7 — added SD-R10)

/// Structured hardware-capabilities map intended for tool consumption.
///
/// Distinct from [`HardwareSnapshot`] (raw introspection) and
/// [`Sain01Match`] (SAIN-01-fitness verdict): this is the JSON
/// artifact that DOWNSTREAM tooling reads to decide what to do.
/// Canonical consumers:
///
/// 1. **sovereign-os `scripts/pulse/wasm-aot.sh`** — decides which
///    AVX-512 instruction families to enable when compiling Wasm to
///    native AVX-512. Without the capabilities file the script falls
///    back to safe defaults; with it, the script can enable
///    `-mavx512vnni` / `-mavx512bf16` / `-mavx512fp16` exactly when
///    the host supports them.
/// 2. **selfdef agent-guard** — future hardware-aware policy DSL can
///    read the capabilities at apply-time to opt-in policies to
///    features only when the underlying hardware supports them
///    (e.g., GPU memory bomb assertion only when 2+ GPUs present).
/// 3. **Fleet aggregators** — Loki / OpenSearch consumers can ingest
///    the JSON directly to surface fleet-wide hardware drift.
///
/// Schema is OPERATOR-STABLE — the operator wants endless flexibility
/// and configuration; downstream tooling should depend on field names
/// and semantics, not internal Sain01Match logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    /// Schema version for the JSON file. Operators bump this when
    /// adding incompatible changes; consumers refuse unknown majors.
    pub schema_version: String,

    /// ISO8601 timestamp when this capabilities snapshot was taken.
    pub probed_at: String,

    /// Hostname tag (matches selfdef daemon's host_tag when set).
    pub host_tag: Option<String>,

    pub cpu: CpuCapabilities,
    pub memory: MemoryCapabilities,
    pub gpu: GpuCapabilities,
    pub pcie: PcieCapabilities,
    pub sain01_match: Sain01Match,
}

/// CPU instruction-family availability + recommended flags for
/// AOT compilation. These are the load-bearing fields for the
/// Wasm-to-AVX-512 AOT pipeline + future bitnet.cpp builds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuCapabilities {
    pub vendor: String,
    pub model_name: String,
    pub physical_cores: u32,
    pub logical_threads: u32,

    // SSE / AVX baseline
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub fma: bool,

    // AVX-512 family — the load-bearing set for AVX-512 AOT compile
    // recommendations (sovereign-os Wasm-AOT + bitnet.cpp consume
    // these directly).
    pub avx512f: bool,
    pub avx512dq: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
    pub avx512vnni: bool,
    pub avx512bf16: bool,
    pub avx512fp16: bool,
    pub avx512vbmi: bool,
    pub avx512vbmi2: bool,

    /// Convenience: the recommended `-march=` token for GCC/clang when
    /// compiling for this CPU. `znver5` on Zen 5 + AVX-512 hosts;
    /// `native` on others. Operators can override at build time.
    pub recommended_march: String,

    /// Convenience: ordered list of `-m<feature>` flags to add to
    /// CFLAGS / KCFLAGS when compiling targeted at this CPU. Only
    /// flags whose underlying feature is present are emitted.
    pub recommended_compile_flags: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryCapabilities {
    pub total_bytes: u64,
    pub at_least_256gb: bool,
    pub at_least_512gb: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuCapabilities {
    pub device_count: u32,
    pub device_nodes: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcieCapabilities {
    pub gen4_or_higher_x8_slot_count: u32,
    pub dual_x8_present: bool,
}

/// SDD-017 § 7 (SD-R10): derive the capabilities map from a probed
/// snapshot. Pure function — no I/O. Tests pin every recommended
/// compile flag against synthetic feature sets.
#[must_use]
pub fn derive_capabilities(snap: &HardwareSnapshot) -> HardwareCapabilities {
    let feats = &snap.cpu.features;
    let has = |f: &str| feats.contains(f);
    let cpu = CpuCapabilities {
        vendor: snap.cpu.vendor.clone(),
        model_name: snap.cpu.model_name.clone(),
        physical_cores: snap.cpu.physical_cores,
        logical_threads: snap.cpu.logical_threads,
        sse4_2: has("sse4_2"),
        avx: has("avx"),
        avx2: has("avx2"),
        fma: has("fma"),
        avx512f: has("avx512f"),
        avx512dq: has("avx512dq"),
        avx512bw: has("avx512bw"),
        avx512vl: has("avx512vl"),
        avx512vnni: has("avx512_vnni"),
        avx512bf16: has("avx512_bf16"),
        avx512fp16: has("avx512_fp16"),
        avx512vbmi: has("avx512_vbmi"),
        avx512vbmi2: has("avx512_vbmi2"),
        recommended_march: recommended_march_for(&snap.cpu.vendor, feats),
        recommended_compile_flags: recommended_compile_flags(feats),
    };
    let memory = MemoryCapabilities {
        total_bytes: snap.memory.total_bytes,
        at_least_256gb: snap.memory.total_bytes >= 256 * 1024 * 1024 * 1024,
        at_least_512gb: snap.memory.total_bytes >= 512 * 1024 * 1024 * 1024,
    };
    let gpu = GpuCapabilities {
        device_count: u32::try_from(snap.gpus.len()).unwrap_or(u32::MAX),
        device_nodes: snap.gpus.iter().map(|g| g.device_node.clone()).collect(),
    };
    let pcie = PcieCapabilities {
        gen4_or_higher_x8_slot_count: snap.pcie.gen4_or_higher_x8_slot_count,
        dual_x8_present: snap.pcie.gen4_or_higher_x8_slot_count >= 2,
    };
    HardwareCapabilities {
        schema_version: "1.0.0".into(),
        probed_at: snap.probed_at.clone(),
        host_tag: None,
        cpu,
        memory,
        gpu,
        pcie,
        sain01_match: matches_sain01(snap),
    }
}

/// Recommend a `-march=` token. Zen 5 + AVX-512 → `znver5`; AuthenticAMD
/// + AVX-512 but not Zen 5 → `znver4`; anything else → `native`.
fn recommended_march_for(vendor: &str, feats: &HashSet<String>) -> String {
    if feats.contains("avx512_vnni") && feats.contains("avx512_bf16") {
        // Zen 5 + AVX-512 VNNI + BF16 → the SAIN-01 target.
        // sovereign-os master spec § 16 calls for -march=znver5.
        if vendor == "AuthenticAMD" {
            return "znver5".to_string();
        }
        // Intel hosts with the same family — Sapphire Rapids has
        // VNNI + BF16; recommend the generic AVX-512 token.
        return "x86-64-v4".to_string();
    }
    if feats.contains("avx512f") && vendor == "AuthenticAMD" {
        // Zen 4 has AVX-512F but not VNNI/BF16 in the same matrix.
        return "znver4".to_string();
    }
    "native".to_string()
}

/// Ordered list of `-m<feature>` flags appropriate for the host.
/// Mirrors sovereign-os `scripts/pulse/build-bitnet.sh`'s flag list +
/// adds anything else the host actually has.
fn recommended_compile_flags(feats: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for (flag_name, feat) in [
        ("-msse4.2", "sse4_2"),
        ("-mavx", "avx"),
        ("-mavx2", "avx2"),
        ("-mfma", "fma"),
        ("-mavx512f", "avx512f"),
        ("-mavx512dq", "avx512dq"),
        ("-mavx512bw", "avx512bw"),
        ("-mavx512vl", "avx512vl"),
        ("-mavx512vnni", "avx512_vnni"),
        ("-mavx512bf16", "avx512_bf16"),
        ("-mavx512fp16", "avx512_fp16"),
        ("-mavx512vbmi", "avx512_vbmi"),
        ("-mavx512vbmi2", "avx512_vbmi2"),
    ] {
        if feats.contains(feat) {
            out.push(flag_name.to_string());
        }
    }
    out
}

/// SDD-017 § 7 (SD-R10): write the capabilities JSON to `path`
/// atomically (tempfile + rename). Pretty-printed for operator
/// readability; matches the `selfdefctl hardware export` CLI output.
pub fn write_capabilities_json(path: &Path, snap: &HardwareSnapshot) -> Result<(), HardwareError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let caps = derive_capabilities(snap);
    let body = serde_json::to_string_pretty(&caps)
        .map_err(|e| HardwareError::Io(std::io::Error::other(e.to_string())))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    fs::write(&tmp_path, body)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------- Layer B metrics (SDD-017 § 6)

/// snapshot + match. Pure function — no I/O. Operators consume this
/// via node_exporter's textfile collector.
///
/// Metrics emitted:
///   sovereign_os_selfdef_hardware_match{dimension="..."} 0|1
///   sovereign_os_selfdef_hardware_match_overall{verdict="..."} 1
///   sovereign_os_selfdef_hardware_cpu_logical_threads <n>
///   sovereign_os_selfdef_hardware_cpu_physical_cores  <n>
///   sovereign_os_selfdef_hardware_memory_total_bytes  <n>
///   sovereign_os_selfdef_hardware_gpu_count           <n>
///   sovereign_os_selfdef_hardware_probed_at_unix      <epoch>
#[must_use]
pub fn render_layer_b_metrics(snap: &HardwareSnapshot, m: &Sain01Match) -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();

    let bit = |b: bool| -> u8 { if b { 1 } else { 0 } };
    let verdict_label = |v: Sain01Verdict| -> &'static str {
        match v {
            Sain01Verdict::FullMatch => "FullMatch",
            Sain01Verdict::PartialMatch => "PartialMatch",
            Sain01Verdict::NoMatch => "NoMatch",
        }
    };

    writeln!(
        &mut buf,
        "# HELP sovereign_os_selfdef_hardware_match Per-dimension SAIN-01 fitness (1 = match, 0 = miss; missing dimension = absent label)"
    )
    .unwrap();
    writeln!(&mut buf, "# TYPE sovereign_os_selfdef_hardware_match gauge").unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_match{{dimension=\"cpu_avx512_vnni\"}} {}",
        bit(m.cpu_avx512_vnni)
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_match{{dimension=\"cpu_avx512_bf16\"}} {}",
        bit(m.cpu_avx512_bf16)
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_match{{dimension=\"memory_at_least_256gb\"}} {}",
        bit(m.memory_at_least_256gb)
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_match{{dimension=\"gpu_count_at_least_2\"}} {}",
        bit(m.gpu_count_at_least_2)
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_match{{dimension=\"pcie_dual_x8_present\"}} {}",
        bit(m.pcie_dual_x8_present)
    )
    .unwrap();
    if let Some(mb) = m.motherboard_proart_x870e {
        writeln!(
            &mut buf,
            "sovereign_os_selfdef_hardware_match{{dimension=\"motherboard_proart_x870e\"}} {}",
            bit(mb)
        )
        .unwrap();
    }
    // motherboard_proart_x870e == None → omit label per Q17-A
    // (operator can distinguish absent vs 0 via the missing time series).

    writeln!(
        &mut buf,
        "# HELP sovereign_os_selfdef_hardware_match_overall Overall verdict (one label = 1)"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_match_overall gauge"
    )
    .unwrap();
    for v in [
        Sain01Verdict::FullMatch,
        Sain01Verdict::PartialMatch,
        Sain01Verdict::NoMatch,
    ] {
        writeln!(
            &mut buf,
            "sovereign_os_selfdef_hardware_match_overall{{verdict=\"{}\"}} {}",
            verdict_label(v),
            bit(m.overall == v)
        )
        .unwrap();
    }

    writeln!(
        &mut buf,
        "# HELP sovereign_os_selfdef_hardware_cpu_logical_threads Logical thread count from /proc/cpuinfo"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_cpu_logical_threads gauge"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_cpu_logical_threads {}",
        snap.cpu.logical_threads
    )
    .unwrap();
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_cpu_physical_cores gauge"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_cpu_physical_cores {}",
        snap.cpu.physical_cores
    )
    .unwrap();
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_memory_total_bytes gauge"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_memory_total_bytes {}",
        snap.memory.total_bytes
    )
    .unwrap();
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_gpu_count gauge"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_gpu_count {}",
        snap.gpus.len()
    )
    .unwrap();
    let probed_unix = parse_iso8601_to_unix(&snap.probed_at).unwrap_or(0);
    writeln!(
        &mut buf,
        "# TYPE sovereign_os_selfdef_hardware_probed_at_unix gauge"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign_os_selfdef_hardware_probed_at_unix {probed_unix}"
    )
    .unwrap();
    buf
}

fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Iso8601;
    OffsetDateTime::parse(s, &Iso8601::DEFAULT)
        .ok()
        .map(|d| d.unix_timestamp())
}

/// SDD-017 § 6: write the rendered Layer B metrics to `path` atomically
/// (tempfile + rename, matching node_exporter's textfile collector
/// recommendation that consumers see whole files only).
pub fn write_layer_b_metrics(
    path: &Path,
    snap: &HardwareSnapshot,
    m: &Sain01Match,
) -> Result<(), HardwareError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let body = render_layer_b_metrics(snap, m);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    fs::write(&tmp_path, body)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    // ----- cpuinfo --------------------------------------------------

    #[test]
    fn cpu_inventory_parses_proc_cpuinfo() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("cpuinfo");
        write(
            &p,
            "processor : 0\nvendor_id : AuthenticAMD\nmodel name : AMD Ryzen 9 9900X\nphysical id : 0\ncore id : 0\nflags : fpu avx avx2 avx512f avx512vnni avx512bf16\n\nprocessor : 1\nvendor_id : AuthenticAMD\nmodel name : AMD Ryzen 9 9900X\nphysical id : 0\ncore id : 1\nflags : fpu avx avx2 avx512f avx512vnni avx512bf16\n",
        );
        let inv = read_cpuinfo(&p);
        assert_eq!(inv.vendor, "AuthenticAMD");
        assert_eq!(inv.model_name, "AMD Ryzen 9 9900X");
        assert_eq!(inv.logical_threads, 2);
        assert!(inv.features.contains("avx512f"));
    }

    #[test]
    fn cpu_inventory_detects_avx512_vnni_and_bf16() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("cpuinfo");
        // Real Linux /proc/cpuinfo uses underscored tokens for the
        // AVX-512 family: `avx512_vnni`, `avx512_bf16`. The `avx512f`
        // base flag is one token with no underscore.
        write(
            &p,
            "processor : 0\nflags : avx avx512f avx512_vnni avx512_bf16\n",
        );
        let inv = read_cpuinfo(&p);
        assert!(inv.avx512_present);
        assert!(inv.avx512_vnni);
        assert!(inv.avx512_bf16);
    }

    #[test]
    fn cpu_inventory_no_avx512_on_legacy_host() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("cpuinfo");
        write(&p, "processor : 0\nflags : sse2 sse4_1 avx avx2\n");
        let inv = read_cpuinfo(&p);
        assert!(!inv.avx512_present);
        assert!(!inv.avx512_vnni);
        assert!(!inv.avx512_bf16);
    }

    #[test]
    fn cpu_inventory_unreadable_returns_default() {
        let inv = read_cpuinfo(Path::new("/no/such/cpuinfo"));
        assert_eq!(inv.logical_threads, 0);
        assert!(inv.features.is_empty());
    }

    // ----- meminfo --------------------------------------------------

    #[test]
    fn memory_inventory_parses_proc_meminfo() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("meminfo");
        write(&p, "MemTotal:       268435456 kB\nMemFree: 1234\n");
        let inv = read_meminfo(&p);
        // 268435456 kB == 256 GiB == 274_877_906_944 bytes
        assert_eq!(inv.total_bytes, 274_877_906_944);
    }

    #[test]
    fn memory_inventory_unreadable_returns_zero() {
        let inv = read_meminfo(Path::new("/no/such/meminfo"));
        assert_eq!(inv.total_bytes, 0);
    }

    // ----- GPU device nodes ----------------------------------------

    #[test]
    fn gpu_inventory_counts_dev_nvidia_devices() {
        let dir = tempdir().unwrap();
        let dev = dir.path();
        // Stage /dev/nvidia0, /dev/nvidia1 (the SAIN-01 pair) +
        // /dev/nvidiactl (must be skipped) + /dev/nvidia-uvm (skipped)
        for name in ["nvidia0", "nvidia1", "nvidiactl", "nvidia-uvm"] {
            write(&dev.join(name), "");
        }
        let gpus = read_gpu_device_nodes(dev);
        assert_eq!(gpus.len(), 2);
        assert!(gpus[0].device_node.ends_with("nvidia0"));
        assert!(gpus[1].device_node.ends_with("nvidia1"));
    }

    #[test]
    fn gpu_inventory_zero_when_no_devices() {
        let dir = tempdir().unwrap();
        let gpus = read_gpu_device_nodes(dir.path());
        assert!(gpus.is_empty());
    }

    #[test]
    fn gpu_inventory_zero_when_dev_absent() {
        let gpus = read_gpu_device_nodes(Path::new("/no/such/dev"));
        assert!(gpus.is_empty());
    }

    // ----- motherboard ---------------------------------------------

    #[test]
    fn motherboard_inventory_reads_dmi() {
        let dir = tempdir().unwrap();
        let dmi = dir.path();
        write(&dmi.join("board_vendor"), "ASUSTeK COMPUTER INC.\n");
        write(&dmi.join("board_name"), "ProArt X870E-CREATOR WIFI\n");
        let mb = read_motherboard(dmi).expect("expected mobo");
        assert_eq!(mb.vendor.as_deref(), Some("ASUSTeK COMPUTER INC."));
        assert_eq!(
            mb.product_name.as_deref(),
            Some("ProArt X870E-CREATOR WIFI")
        );
    }

    #[test]
    fn motherboard_inventory_none_when_dmi_absent() {
        let mb = read_motherboard(Path::new("/no/such/dmi"));
        assert!(mb.is_none());
    }

    // ----- Sain01Match ---------------------------------------------

    fn synth_snapshot(
        avx512_vnni: bool,
        avx512_bf16: bool,
        mem_bytes: u64,
        gpu_count: usize,
        pcie_x8: u32,
        mobo: Option<(&str, &str)>,
    ) -> HardwareSnapshot {
        let mut features = HashSet::new();
        if avx512_vnni {
            features.insert("avx512_vnni".into());
        }
        if avx512_bf16 {
            features.insert("avx512_bf16".into());
        }
        let mut gpus = Vec::new();
        for i in 0..gpu_count {
            gpus.push(GpuInventory {
                device_node: PathBuf::from(format!("/dev/nvidia{i}")),
                pci_address: None,
                model_hint: None,
                vram_bytes: None,
            });
        }
        HardwareSnapshot {
            cpu: CpuInventory {
                avx512_present: avx512_vnni || avx512_bf16,
                avx512_vnni,
                avx512_bf16,
                features,
                ..CpuInventory::default()
            },
            memory: MemoryInventory {
                total_bytes: mem_bytes,
            },
            gpus,
            motherboard: mobo.map(|(v, p)| MotherboardInventory {
                vendor: Some(v.to_owned()),
                product_name: Some(p.to_owned()),
            }),
            pcie: PcieInventory {
                gen4_or_higher_x8_slot_count: pcie_x8,
            },
            probed_at: String::new(),
        }
    }

    #[test]
    fn sain01_match_full_when_all_dimensions_hit() {
        let snap = synth_snapshot(
            true,
            true,
            BYTES_256_GB,
            2,
            2,
            Some(("ASUSTeK COMPUTER INC.", "ProArt X870E-CREATOR WIFI")),
        );
        let m = matches_sain01(&snap);
        assert_eq!(m.overall, Sain01Verdict::FullMatch);
        assert!(m.cpu_avx512_vnni);
        assert!(m.cpu_avx512_bf16);
        assert!(m.memory_at_least_256gb);
        assert!(m.gpu_count_at_least_2);
        assert_eq!(m.motherboard_proart_x870e, Some(true));
        assert!(m.pcie_dual_x8_present);
    }

    #[test]
    fn sain01_match_partial_when_some_dimensions_hit() {
        let snap = synth_snapshot(true, false, BYTES_256_GB, 1, 1, None);
        let m = matches_sain01(&snap);
        assert_eq!(m.overall, Sain01Verdict::PartialMatch);
        assert!(m.cpu_avx512_vnni);
        assert!(m.memory_at_least_256gb);
        assert!(!m.gpu_count_at_least_2);
        assert!(!m.pcie_dual_x8_present);
        assert_eq!(m.motherboard_proart_x870e, None);
    }

    #[test]
    fn sain01_match_none_when_no_dimensions_hit() {
        let snap = synth_snapshot(false, false, 0, 0, 0, None);
        let m = matches_sain01(&snap);
        assert_eq!(m.overall, Sain01Verdict::NoMatch);
    }

    #[test]
    fn sain01_match_full_without_mobo_when_dmi_unreadable() {
        // DMI unreadable → motherboard = None → mobo dimension drops
        // out (None is neutral). Other 4 dimensions all hit → Full.
        let snap = synth_snapshot(true, true, BYTES_256_GB, 2, 2, None);
        let m = matches_sain01(&snap);
        assert_eq!(m.overall, Sain01Verdict::FullMatch);
        assert_eq!(m.motherboard_proart_x870e, None);
    }

    #[test]
    fn sain01_match_partial_when_mobo_wrong() {
        // Wrong board → mobo dimension counts but fails → Partial.
        let snap = synth_snapshot(
            true,
            true,
            BYTES_256_GB,
            2,
            2,
            Some(("Generic", "Some Other Board")),
        );
        let m = matches_sain01(&snap);
        assert_eq!(m.overall, Sain01Verdict::PartialMatch);
        assert_eq!(m.motherboard_proart_x870e, Some(false));
    }

    #[test]
    fn motherboard_match_is_case_insensitive() {
        let mb = MotherboardInventory {
            vendor: Some("asustek COMPUTER inc.".into()),
            product_name: Some("ProArt X870E-creator WIFI".into()),
        };
        assert!(motherboard_is_proart_x870e(&mb));
    }

    // ----- probe end-to-end (synthetic fs) -------------------------

    #[test]
    fn probe_from_roots_returns_snapshot() {
        let dir = tempdir().unwrap();
        let cpu = dir.path().join("cpuinfo");
        write(
            &cpu,
            "processor : 0\nvendor_id : AuthenticAMD\nmodel name : AMD Ryzen 9 9900X\nflags : avx512f avx512_vnni\n",
        );
        let mem = dir.path().join("meminfo");
        write(&mem, "MemTotal:       268435456 kB\n");
        let dev = dir.path().join("dev");
        fs::create_dir_all(&dev).unwrap();
        write(&dev.join("nvidia0"), "");
        write(&dev.join("nvidia1"), "");
        let dmi = dir.path().join("dmi");
        fs::create_dir_all(&dmi).unwrap();
        write(&dmi.join("board_vendor"), "ASUSTeK COMPUTER INC.\n");
        write(&dmi.join("board_name"), "ProArt X870E-CREATOR WIFI\n");
        let snap = probe_from_roots(&cpu, &mem, &dev, &dmi).unwrap();
        assert_eq!(snap.cpu.vendor, "AuthenticAMD");
        assert!(snap.cpu.avx512_vnni);
        assert_eq!(snap.gpus.len(), 2);
        assert!(snap.motherboard.is_some());
        // 256 GB
        let m = matches_sain01(&snap);
        // 4-dim match (no bf16), so Partial unless we add bf16
        assert!(
            matches!(
                m.overall,
                Sain01Verdict::FullMatch | Sain01Verdict::PartialMatch
            ),
            "{:?}",
            m.overall
        );
    }

    #[test]
    fn probe_on_test_host_returns_some_snapshot() {
        // Smoke: read real /proc/* on the test host. Just verifies no
        // panic + something gets populated.
        let snap = probe().unwrap();
        assert!(snap.cpu.logical_threads > 0);
        assert!(snap.memory.total_bytes > 0);
    }

    // ----- Layer B metrics (SDD-017 § 6) ---------------------------

    #[test]
    fn layer_b_metrics_render_includes_every_dimension() {
        let snap = synth_snapshot(
            true,
            true,
            BYTES_256_GB,
            2,
            2,
            Some(("ASUSTeK COMPUTER INC.", "ProArt X870E-CREATOR WIFI")),
        );
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        for s in [
            "sovereign_os_selfdef_hardware_match{dimension=\"cpu_avx512_vnni\"} 1",
            "sovereign_os_selfdef_hardware_match{dimension=\"cpu_avx512_bf16\"} 1",
            "sovereign_os_selfdef_hardware_match{dimension=\"memory_at_least_256gb\"} 1",
            "sovereign_os_selfdef_hardware_match{dimension=\"gpu_count_at_least_2\"} 1",
            "sovereign_os_selfdef_hardware_match{dimension=\"pcie_dual_x8_present\"} 1",
            "sovereign_os_selfdef_hardware_match{dimension=\"motherboard_proart_x870e\"} 1",
            "sovereign_os_selfdef_hardware_match_overall{verdict=\"FullMatch\"} 1",
            "sovereign_os_selfdef_hardware_match_overall{verdict=\"PartialMatch\"} 0",
            "sovereign_os_selfdef_hardware_match_overall{verdict=\"NoMatch\"} 0",
            "sovereign_os_selfdef_hardware_memory_total_bytes 274877906944",
            "sovereign_os_selfdef_hardware_gpu_count 2",
        ] {
            assert!(out.contains(s), "missing metric line: {s}\nin:\n{out}");
        }
    }

    #[test]
    fn layer_b_metrics_omit_motherboard_when_dmi_unreadable() {
        let snap = synth_snapshot(true, true, BYTES_256_GB, 2, 2, None);
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        // Operator can distinguish "motherboard absent" (no time series)
        // from "motherboard wrong" (=0). Q17-A safety.
        assert!(!out.contains("motherboard_proart_x870e"));
    }

    #[test]
    fn layer_b_metrics_partial_match_rendered() {
        let snap = synth_snapshot(true, false, BYTES_256_GB, 1, 1, None);
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(
            out.contains("sovereign_os_selfdef_hardware_match_overall{verdict=\"PartialMatch\"} 1")
        );
        assert!(
            out.contains("sovereign_os_selfdef_hardware_match_overall{verdict=\"FullMatch\"} 0")
        );
        assert!(
            out.contains("sovereign_os_selfdef_hardware_match{dimension=\"cpu_avx512_bf16\"} 0")
        );
        assert!(
            out.contains(
                "sovereign_os_selfdef_hardware_match{dimension=\"gpu_count_at_least_2\"} 0"
            )
        );
    }

    #[test]
    fn write_layer_b_metrics_atomically_writes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("selfdef-hardware.prom");
        let snap = synth_snapshot(true, true, BYTES_256_GB, 2, 2, None);
        let m = matches_sain01(&snap);
        write_layer_b_metrics(&path, &snap, &m).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("sovereign_os_selfdef_hardware_match"));
        // The .tmp file MUST not survive the rename.
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp_path = PathBuf::from(tmp_name);
        assert!(!tmp_path.exists(), "tmp file must be renamed away");
    }

    #[test]
    fn write_layer_b_metrics_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deep/nested/path/selfdef-hardware.prom");
        let snap = synth_snapshot(true, true, BYTES_256_GB, 2, 2, None);
        let m = matches_sain01(&snap);
        write_layer_b_metrics(&path, &snap, &m).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn parse_iso8601_to_unix_roundtrips_current_time() {
        let now = time::OffsetDateTime::now_utc();
        let s = now
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .unwrap();
        let parsed = parse_iso8601_to_unix(&s).unwrap();
        // Allow ±2 seconds for the formatting precision.
        assert!((parsed - now.unix_timestamp()).abs() <= 2);
    }

    #[test]
    fn parse_iso8601_to_unix_bad_input_returns_none() {
        assert_eq!(parse_iso8601_to_unix("not a date"), None);
        assert_eq!(parse_iso8601_to_unix(""), None);
    }

    // ----- HardwareCapabilities derivation (SD-R10) ---------------

    fn snap_with_features(vendor: &str, features: &[&str]) -> HardwareSnapshot {
        HardwareSnapshot {
            cpu: CpuInventory {
                vendor: vendor.to_string(),
                model_name: "test cpu".into(),
                physical_cores: 12,
                logical_threads: 24,
                features: features.iter().map(|s| s.to_string()).collect(),
                avx512_present: features.iter().any(|f| f.starts_with("avx512")),
                avx512_vnni: features.contains(&"avx512_vnni"),
                avx512_bf16: features.contains(&"avx512_bf16"),
            },
            memory: MemoryInventory {
                total_bytes: BYTES_256_GB,
            },
            gpus: vec![
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia0"),
                    pci_address: None,
                    model_hint: None,
                    vram_bytes: None,
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: None,
                    model_hint: None,
                    vram_bytes: None,
                },
            ],
            motherboard: None,
            pcie: PcieInventory {
                gen4_or_higher_x8_slot_count: 2,
            },
            probed_at: "2026-05-16T00:00:00.000000000Z".into(),
        }
    }

    #[test]
    fn capabilities_recommend_znver5_on_zen5_amd() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &[
                "avx",
                "avx2",
                "fma",
                "avx512f",
                "avx512dq",
                "avx512bw",
                "avx512vl",
                "avx512_vnni",
                "avx512_bf16",
            ],
        );
        let caps = derive_capabilities(&snap);
        assert_eq!(caps.cpu.recommended_march, "znver5");
        assert!(
            caps.cpu
                .recommended_compile_flags
                .contains(&"-mavx512vnni".to_string())
        );
        assert!(
            caps.cpu
                .recommended_compile_flags
                .contains(&"-mavx512bf16".to_string())
        );
        assert!(caps.cpu.avx512vnni);
        assert!(caps.cpu.avx512bf16);
    }

    #[test]
    fn capabilities_recommend_znver4_on_zen4_amd_no_vnni() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &[
                "avx", "avx2", "fma", "avx512f", "avx512dq", "avx512bw", "avx512vl",
            ],
        );
        let caps = derive_capabilities(&snap);
        assert_eq!(caps.cpu.recommended_march, "znver4");
        assert!(!caps.cpu.avx512vnni);
        assert!(!caps.cpu.avx512bf16);
        assert!(
            caps.cpu
                .recommended_compile_flags
                .contains(&"-mavx512f".to_string())
        );
        assert!(
            !caps
                .cpu
                .recommended_compile_flags
                .contains(&"-mavx512vnni".to_string())
        );
    }

    #[test]
    fn capabilities_recommend_x86_64_v4_on_intel_with_avx512_vnni() {
        let snap = snap_with_features(
            "GenuineIntel",
            &["avx", "avx2", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        let caps = derive_capabilities(&snap);
        // Intel + VNNI + BF16 → portable AVX-512 token, not znver5.
        assert_eq!(caps.cpu.recommended_march, "x86-64-v4");
    }

    #[test]
    fn capabilities_recommend_native_on_legacy_host() {
        let snap = snap_with_features("AuthenticAMD", &["sse4_2", "avx", "avx2"]);
        let caps = derive_capabilities(&snap);
        assert_eq!(caps.cpu.recommended_march, "native");
        assert!(
            caps.cpu
                .recommended_compile_flags
                .contains(&"-mavx2".to_string())
        );
        assert!(
            !caps
                .cpu
                .recommended_compile_flags
                .iter()
                .any(|f| f.starts_with("-mavx512"))
        );
    }

    #[test]
    fn capabilities_memory_thresholds() {
        let mut snap = snap_with_features("AuthenticAMD", &["avx2"]);
        snap.memory.total_bytes = 128 * 1024 * 1024 * 1024;
        let c = derive_capabilities(&snap);
        assert!(!c.memory.at_least_256gb);
        assert!(!c.memory.at_least_512gb);
        snap.memory.total_bytes = BYTES_256_GB;
        let c = derive_capabilities(&snap);
        assert!(c.memory.at_least_256gb);
        assert!(!c.memory.at_least_512gb);
        snap.memory.total_bytes = 512 * 1024 * 1024 * 1024;
        let c = derive_capabilities(&snap);
        assert!(c.memory.at_least_256gb);
        assert!(c.memory.at_least_512gb);
    }

    #[test]
    fn capabilities_gpu_count_reflects_snapshot() {
        let snap = snap_with_features("AuthenticAMD", &["avx2"]);
        let c = derive_capabilities(&snap);
        assert_eq!(c.gpu.device_count, 2);
        assert_eq!(c.gpu.device_nodes.len(), 2);
        assert_eq!(c.gpu.device_nodes[0], PathBuf::from("/dev/nvidia0"));
    }

    #[test]
    fn capabilities_pcie_dual_x8_derived() {
        let mut snap = snap_with_features("AuthenticAMD", &["avx2"]);
        snap.pcie.gen4_or_higher_x8_slot_count = 1;
        let c = derive_capabilities(&snap);
        assert!(!c.pcie.dual_x8_present);
        snap.pcie.gen4_or_higher_x8_slot_count = 2;
        let c = derive_capabilities(&snap);
        assert!(c.pcie.dual_x8_present);
    }

    #[test]
    fn capabilities_schema_version_pinned() {
        let snap = snap_with_features("AuthenticAMD", &["avx2"]);
        let c = derive_capabilities(&snap);
        assert_eq!(c.schema_version, "1.0.0");
    }

    #[test]
    fn write_capabilities_json_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hardware-capabilities.json");
        let snap = snap_with_features(
            "AuthenticAMD",
            &["avx2", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        write_capabilities_json(&path, &snap).unwrap();
        assert!(path.exists());
        let body = fs::read_to_string(&path).unwrap();
        let parsed: HardwareCapabilities = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.schema_version, "1.0.0");
        assert_eq!(parsed.cpu.recommended_march, "znver5");
        assert!(parsed.cpu.avx512vnni);
        // Tempfile must be cleaned up.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        assert!(!PathBuf::from(tmp).exists());
    }

    #[test]
    fn write_capabilities_json_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("deep/nested/hardware-capabilities.json");
        let snap = snap_with_features("AuthenticAMD", &["avx2"]);
        write_capabilities_json(&path, &snap).unwrap();
        assert!(path.exists());
    }

    // ----- PCIe lspci parser (SD-R12) ------------------------------

    #[test]
    fn pcie_parser_counts_gen5_x8_slots() {
        let body = "\
01:00.0 VGA compatible controller: NVIDIA ...\n\
\tLnkCap: Port #0, Speed 32GT/s, Width x16\n\
\tLnkSta: Speed 32GT/s, Width x8\n\
03:00.0 VGA compatible controller: NVIDIA ...\n\
\tLnkSta: Speed 32GT/s, Width x8\n\
";
        assert_eq!(count_pcie_x8_gen4_plus(body), 2);
    }

    #[test]
    fn pcie_parser_counts_gen4_x8_slots() {
        let body = "\
01:00.0 dev\n\
\tLnkSta: Speed 16GT/s, Width x8\n\
";
        assert_eq!(count_pcie_x8_gen4_plus(body), 1);
    }

    #[test]
    fn pcie_parser_ignores_x16_x4_x1_slots() {
        let body = "\
01:00.0 dev\n\
\tLnkSta: Speed 32GT/s, Width x16\n\
02:00.0 dev\n\
\tLnkSta: Speed 16GT/s, Width x4\n\
03:00.0 dev\n\
\tLnkSta: Speed 32GT/s, Width x1\n\
";
        assert_eq!(count_pcie_x8_gen4_plus(body), 0);
    }

    #[test]
    fn pcie_parser_ignores_gen3_x8_slots() {
        // Gen 3 = 8GT/s. SAIN-01 master spec § 1.2 requires Gen 4+ —
        // the Blackwell + 3090 pair only deliver full throughput at
        // Gen 4 or Gen 5.
        let body = "\
01:00.0 dev\n\
\tLnkSta: Speed 8GT/s, Width x8\n\
";
        assert_eq!(count_pcie_x8_gen4_plus(body), 0);
    }

    #[test]
    fn pcie_parser_accepts_decimal_speed_tokens() {
        // Older lspci versions render "Speed 16.0GT/s" with a trailing .0
        let body = "\
01:00.0 dev\n\
\tLnkSta: Speed 16.0GT/s, Width x8\n\
02:00.0 dev\n\
\tLnkSta: Speed 32.0GT/s, Width x8\n\
";
        assert_eq!(count_pcie_x8_gen4_plus(body), 2);
    }

    #[test]
    fn pcie_parser_empty_input() {
        assert_eq!(count_pcie_x8_gen4_plus(""), 0);
    }

    #[test]
    fn pcie_parser_mixed_realistic_sain01_topology() {
        // Synthetic ProArt X870E lspci -vv output: 2× GPU at x8 Gen 5
        // + 2× NVMe at x4 Gen 5 + 1× NIC at x4 Gen 4.
        let body = "\
01:00.0 VGA compatible controller: NVIDIA Blackwell\n\
\tLnkCap: Port #0, Speed 32GT/s, Width x16\n\
\tLnkSta: Speed 32GT/s, Width x8\n\
03:00.0 VGA compatible controller: NVIDIA RTX 3090\n\
\tLnkSta: Speed 32GT/s, Width x8\n\
04:00.0 Non-Volatile memory controller: Samsung\n\
\tLnkSta: Speed 32GT/s, Width x4\n\
05:00.0 Non-Volatile memory controller: Samsung\n\
\tLnkSta: Speed 32GT/s, Width x4\n\
06:00.0 Ethernet controller: Aquantia AQC113C\n\
\tLnkSta: Speed 16GT/s, Width x4\n\
";
        // 2 GPUs × x8 @ Gen 5 — exactly the SAIN-01 § 1.2 target.
        assert_eq!(count_pcie_x8_gen4_plus(body), 2);
    }

    #[test]
    fn capabilities_includes_sain01_match() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &["avx2", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        let c = derive_capabilities(&snap);
        // Mobo None → bonus dim drops out; the 4 base dims + bf16 bonus
        // all hit on this synth snapshot → FullMatch.
        assert_eq!(c.sain01_match.overall, Sain01Verdict::FullMatch);
    }
}
