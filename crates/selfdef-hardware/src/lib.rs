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
    /// SD-R17: best-effort thermal readings from /sys/class/hwmon
    /// (CPU package, NVMe drives, motherboard sensors) plus
    /// nvidia-smi temperature.gpu (per-GPU). Empty on hosts without
    /// hwmon exposure. Surfaced as Layer B metrics for the
    /// powerhouse-OS observability stack (the SAIN-01 9900X +
    /// dual-GPU box benefits from continuous thermal visibility).
    #[serde(default)]
    pub thermals: Vec<ThermalReading>,
    pub probed_at: String,
}

/// A single named temperature reading. `celsius` is the measured
/// temperature in degrees Celsius (hwmon stores millidegree integers;
/// we divide by 1000 + round to nearest int). `source` identifies
/// the sensor's hwmon `name` file or the nvidia-smi index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThermalReading {
    /// Sensor identifier — e.g. `"k10temp/Tctl"` for the AMD Ryzen
    /// package sensor, `"nvme/Composite"` for an NVMe controller,
    /// `"nvidia-gpu-0"` for an NVIDIA GPU temperature reading.
    pub source: String,
    /// Temperature in degrees Celsius (whole number; sub-degree
    /// precision is not stable across vendors and not load-bearing
    /// for threshold-based monitoring).
    pub celsius: i32,
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
    /// SD-R24: instantaneous power draw in watts (rounded to whole
    /// watt). `None` when nvidia-smi can't report it (no NVML, GPU
    /// in P-state that doesn't expose telemetry, etc.). Operators
    /// running sustained inference workloads want this for
    /// thermal-budget reasoning + cost tracking.
    #[serde(default)]
    pub power_draw_watts: Option<u32>,
    /// SD-R24: nominal power limit in watts (the cap nvidia-smi
    /// reports). `None` when unreadable. Pairs with
    /// `power_draw_watts` so operators can compute headroom:
    /// `limit - draw = remaining budget`.
    #[serde(default)]
    pub power_limit_watts: Option<u32>,
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
    // SD-R13: enrich GPU entries with model_hint + vram_bytes via
    // nvidia-smi (best-effort). Index-matched against the existing
    // /dev/nvidia<N> device-node list. Failures are silent — the
    // gpus vec keeps its device-node-only entries.
    let gpus = enrich_gpus_via_nvidia_smi(gpus);
    // SD-R24: second nvidia-smi pass for power telemetry. Independent
    // failure path from SD-R13; a host with model+vram exposed but
    // without NVML power telemetry still gets model_hint + vram_bytes
    // and just leaves power_*_watts as None.
    let gpus = enrich_gpus_power_via_nvidia_smi(gpus);
    // SD-R17: thermals via /sys/class/hwmon + nvidia-smi. Best-effort:
    // both sources may be empty on minimal hosts.
    let thermals = read_thermals_from_hwmon(Path::new("/sys/class/hwmon"));
    let thermals = enrich_thermals_via_nvidia_smi(thermals);
    let probed_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .map_err(|_| HardwareError::TimeFmt)?;
    Ok(HardwareSnapshot {
        cpu,
        memory,
        gpus,
        motherboard,
        pcie,
        thermals,
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

// ---------------------------------------------------------------- nvidia-smi (SD-R13)

/// SD-R13: enrich `gpus` with model_hint + vram_bytes via
/// `nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader,nounits`.
/// Failures (nvidia-smi absent, non-zero exit, parse error) leave the
/// existing entries unchanged — never panics, never loses GPUs.
///
/// Output match: by `index` to the existing vec position (nvidia-smi
/// indexes match /dev/nvidia<N> order on a single-host).
pub(crate) fn enrich_gpus_via_nvidia_smi(mut gpus: Vec<GpuInventory>) -> Vec<GpuInventory> {
    if gpus.is_empty() {
        return gpus;
    }
    let output = match std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return gpus,
    };
    let body = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_nvidia_smi_csv(&body);
    for (idx, model, vram) in parsed {
        if let Some(g) = gpus.get_mut(idx) {
            if g.model_hint.is_none() {
                g.model_hint = Some(model);
            }
            if g.vram_bytes.is_none() {
                g.vram_bytes = vram;
            }
        }
    }
    gpus
}

/// SD-R13: pure parser for `nvidia-smi --query-gpu=index,name,memory.total
/// --format=csv,noheader,nounits` output. Returns Vec<(idx, name, vram_bytes)>.
/// Trims whitespace; rejects malformed rows silently.
///
/// Example input:
///   0, NVIDIA RTX PRO 6000 Blackwell, 98304
///   1, NVIDIA GeForce RTX 3090, 24576
#[must_use]
pub fn parse_nvidia_smi_csv(body: &str) -> Vec<(usize, String, Option<u64>)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        let idx = match parts[0].parse::<usize>() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let name = parts[1].to_owned();
        if name.is_empty() {
            continue;
        }
        // memory.total comes in MiB with --format=...,nounits.
        let vram = parts[2]
            .parse::<u64>()
            .ok()
            .map(|mib| mib.saturating_mul(1024 * 1024));
        out.push((idx, name, vram));
    }
    out
}

// ---------------------------------------------------------------- nvidia-smi power (SD-R24)

/// SD-R24: enrich `gpus` with `power_draw_watts` + `power_limit_watts`
/// via a second nvidia-smi invocation:
///   `nvidia-smi --query-gpu=index,power.draw,power.limit --format=csv,noheader,nounits`.
///
/// nvidia-smi reports power as floats with one decimal (`"275.4"`);
/// we round to nearest whole watt to match the operator-readable
/// scale. Failures (nvidia-smi absent, NVML unavailable, `[N/A]`
/// readings) leave the corresponding fields as `None`.
///
/// Kept as a separate query from the SD-R13 enrichment so the two
/// paths can fail independently — a host with vRAM exposure but no
/// NVML power telemetry still gets the model_hint + vram_bytes.
pub(crate) fn enrich_gpus_power_via_nvidia_smi(mut gpus: Vec<GpuInventory>) -> Vec<GpuInventory> {
    if gpus.is_empty() {
        return gpus;
    }
    let output = match std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,power.draw,power.limit",
            "--format=csv,noheader,nounits",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return gpus,
    };
    let body = String::from_utf8_lossy(&output.stdout);
    for (idx, draw, limit) in parse_nvidia_smi_power_csv(&body) {
        if let Some(g) = gpus.get_mut(idx) {
            if g.power_draw_watts.is_none() {
                g.power_draw_watts = draw;
            }
            if g.power_limit_watts.is_none() {
                g.power_limit_watts = limit;
            }
        }
    }
    gpus
}

/// SD-R24: pure parser for `nvidia-smi --query-gpu=index,power.draw,
/// power.limit --format=csv,noheader,nounits`. Returns
/// `Vec<(index, draw_watts, limit_watts)>` where each watt field is
/// `Some(u32)` when parseable, `None` when `[N/A]` / `Not Supported`
/// / unparseable. Malformed rows (missing index) are dropped.
///
/// Example input:
///   0, 275.4, 600.0
///   1, [N/A], 350.0
#[must_use]
pub fn parse_nvidia_smi_power_csv(body: &str) -> Vec<(usize, Option<u32>, Option<u32>)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 3 {
            continue;
        }
        let idx = match parts[0].parse::<usize>() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let parse_watts = |s: &str| -> Option<u32> {
            if s.is_empty()
                || s == "[N/A]"
                || s.eq_ignore_ascii_case("not supported")
                || s.eq_ignore_ascii_case("n/a")
            {
                return None;
            }
            // nvidia-smi returns float watts with one decimal — round
            // to nearest whole watt.
            s.parse::<f64>().ok().map(|f| f.round().max(0.0) as u32)
        };
        out.push((idx, parse_watts(parts[1]), parse_watts(parts[2])));
    }
    out
}

// ---------------------------------------------------------------- thermals (SD-R17)

/// SD-R17: walk `/sys/class/hwmon/hwmonN/` reading each device's
/// `name` file + every `temp<K>_input` file under it. Each temp file
/// contains millidegree Celsius integers; we divide by 1000 and round
/// to the nearest int.
///
/// Pure-fs reads — no subprocesses. Operator's threat model wants
/// `/sys` reads to be lightweight and predictable.
pub fn read_thermals_from_hwmon(dir: &Path) -> Vec<ThermalReading> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    // Collect (path, hwmon_index) so we can sort by hwmon index for
    // stable output ordering (hwmon0, hwmon1, ...).
    let mut hwmon_paths: Vec<(PathBuf, u32)> = Vec::new();
    for ent in entries.flatten() {
        let p = ent.path();
        let fname = match p.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if let Some(rest) = fname.strip_prefix("hwmon") {
            if let Ok(idx) = rest.parse::<u32>() {
                hwmon_paths.push((p, idx));
            }
        }
    }
    hwmon_paths.sort_by_key(|(_, idx)| *idx);
    for (hwmon_dir, _) in hwmon_paths {
        let name = fs::read_to_string(hwmon_dir.join("name"))
            .ok()
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        // Sort temp inputs by index for deterministic output.
        let mut temp_files: Vec<(PathBuf, u32)> = Vec::new();
        if let Ok(items) = fs::read_dir(&hwmon_dir) {
            for f in items.flatten() {
                let fname = match f.file_name().into_string() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if let Some(mid) = fname.strip_prefix("temp") {
                    if let Some(idx_str) = mid.strip_suffix("_input") {
                        if let Ok(idx) = idx_str.parse::<u32>() {
                            temp_files.push((f.path(), idx));
                        }
                    }
                }
            }
        }
        temp_files.sort_by_key(|(_, idx)| *idx);
        for (path, idx) in temp_files {
            let body = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let millideg = match body.trim().parse::<i64>() {
                Ok(n) => n,
                Err(_) => continue,
            };
            // Round half away from zero.
            let celsius_i64 = (millideg + (if millideg >= 0 { 500 } else { -500 })) / 1000;
            let celsius = i32::try_from(celsius_i64).unwrap_or(0);
            // Try to read the per-sensor label (some kernels expose it).
            let label_path = hwmon_dir.join(format!("temp{idx}_label"));
            let label = fs::read_to_string(&label_path)
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());
            let source = match label {
                Some(l) => format!("{name}/{l}"),
                None => format!("{name}/temp{idx}"),
            };
            out.push(ThermalReading { source, celsius });
        }
    }
    out
}

/// SD-R17: extend thermals with `nvidia-smi --query-gpu=index,temperature.gpu`
/// readings. Source labels: `nvidia-gpu-<index>`. Best-effort:
/// nvidia-smi absent / non-zero exit / parse error leaves the input
/// `thermals` unchanged.
pub(crate) fn enrich_thermals_via_nvidia_smi(
    mut thermals: Vec<ThermalReading>,
) -> Vec<ThermalReading> {
    let output = match std::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,temperature.gpu",
            "--format=csv,noheader,nounits",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return thermals,
    };
    let body = String::from_utf8_lossy(&output.stdout);
    for (idx, celsius) in parse_nvidia_smi_gpu_temp_csv(&body) {
        let celsius = i32::try_from(celsius).unwrap_or(0);
        thermals.push(ThermalReading {
            source: format!("nvidia-gpu-{idx}"),
            celsius,
        });
    }
    thermals
}

/// SD-R17: pure parser for `nvidia-smi --query-gpu=index,temperature.gpu`
/// CSV. Returns `(index, celsius)` pairs.
#[must_use]
pub fn parse_nvidia_smi_gpu_temp_csv(body: &str) -> Vec<(usize, i64)> {
    let mut out = Vec::new();
    for line in body.lines() {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            continue;
        }
        let idx = match parts[0].parse::<usize>() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let temp = match parts[1].parse::<i64>() {
            Ok(n) => n,
            Err(_) => continue,
        };
        out.push((idx, temp));
    }
    out
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
            power_draw_watts: None,
            power_limit_watts: None,
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
    /// SD-R30: Wasm-AOT compilation hints derived from the host's
    /// CPU feature set. Lets sovereign-os scripts/pulse/wasm-aot.sh
    /// (and any other AOT pipeline) source canonical wasmtime
    /// `--target-feature` flags + a recommended target CPU without
    /// re-deriving them from raw features. Default (empty struct)
    /// is forward-compat with existing capabilities JSON files.
    #[serde(default)]
    pub wasm_aot: WasmAotCapabilities,
}

/// SD-R30: Pre-computed Wasm-AOT compilation hints.
///
/// Sourced into sovereign-os pulse/wasm-aot.sh + any other host
/// that wants to AOT-compile .wasm into a native shared lib. The
/// `wasmtime_target_features` string is a comma-separated list with
/// `+feature` syntax (wasmtime / LLVM convention); ready to pass
/// to `wasmtime compile --target-feature ${features}`.
///
/// All fields default to empty strings when the host doesn't expose
/// the relevant capabilities — the consumer either falls back to
/// `native` or skips the AOT hint entirely.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmAotCapabilities {
    /// LLVM target triple (e.g. `x86_64-unknown-linux-gnu`).
    pub target_triple: String,
    /// `-target-cpu` token (e.g. `znver5`, `znver4`, `native`).
    pub target_cpu: String,
    /// Comma-separated `+feature` list for `--target-feature`.
    /// Empty when the host lacks AVX-512.
    pub target_features: String,
    /// Worked `wasmtime compile` example command (operator
    /// copy/pasteable). Empty when AOT isn't recommended.
    pub compile_command_hint: String,
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
    /// SD-R25: per-GPU detail map — model hint, VRAM, power draw,
    /// power limit. Index matches `device_nodes[i]` 1:1. Lets
    /// cross-repo consumers (sovereign-os wasm-aot, build-bitnet,
    /// scheduling heuristics) see WHICH GPU has WHICH headroom
    /// instead of just a count. Empty when no GPUs detected.
    #[serde(default)]
    pub devices: Vec<GpuDeviceCapabilities>,
}

/// SD-R25: per-GPU detail surfaced through HardwareCapabilities JSON.
/// All fields Option-typed so the schema remains forward-compatible
/// when probe sources vary (nvidia-smi vs lspci vs AMD ROCm).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuDeviceCapabilities {
    /// `/dev/nvidia<N>` style device node when known.
    pub device_node: Option<PathBuf>,
    /// PCI BDF (e.g. "0000:01:00.0") when lspci enrichment ran.
    pub pci_address: Option<String>,
    /// SD-R13 — nvidia-smi name (e.g. "NVIDIA RTX PRO 6000 Blackwell").
    pub model_hint: Option<String>,
    /// SD-R13 — total VRAM in bytes.
    pub vram_bytes: Option<u64>,
    /// SD-R24 — instantaneous power draw, whole watts.
    pub power_draw_watts: Option<u32>,
    /// SD-R24 — nominal power limit, whole watts.
    pub power_limit_watts: Option<u32>,
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
        // SD-R25: per-GPU detail rows. Index-aligned with device_nodes.
        devices: snap
            .gpus
            .iter()
            .map(|g| GpuDeviceCapabilities {
                device_node: Some(g.device_node.clone()),
                pci_address: g.pci_address.clone(),
                model_hint: g.model_hint.clone(),
                vram_bytes: g.vram_bytes,
                power_draw_watts: g.power_draw_watts,
                power_limit_watts: g.power_limit_watts,
            })
            .collect(),
    };
    let pcie = PcieCapabilities {
        gen4_or_higher_x8_slot_count: snap.pcie.gen4_or_higher_x8_slot_count,
        dual_x8_present: snap.pcie.gen4_or_higher_x8_slot_count >= 2,
    };
    let wasm_aot = derive_wasm_aot_capabilities(&cpu);
    HardwareCapabilities {
        // SD-R30: bumped to 1.2.0 alongside the wasm_aot addition.
        // 1.0.0 = SD-R10; 1.1.0 = SD-R25 per-GPU devices; 1.2.0 =
        // SD-R30 wasm_aot field.
        schema_version: "1.2.0".into(),
        probed_at: snap.probed_at.clone(),
        host_tag: None,
        cpu,
        memory,
        gpu,
        pcie,
        sain01_match: matches_sain01(snap),
        wasm_aot,
    }
}

/// SD-R30: derive the Wasm-AOT hint block from a probed CpuCapabilities.
/// Pure function — no I/O. Tests pin every feature combination.
#[must_use]
pub fn derive_wasm_aot_capabilities(cpu: &CpuCapabilities) -> WasmAotCapabilities {
    // x86_64 only for now — aarch64 / RISC-V hosts get empty hints
    // (operator can override per build pipeline).
    let target_triple = "x86_64-unknown-linux-gnu".to_string();
    let target_cpu = if cpu.recommended_march.is_empty() {
        "native".to_string()
    } else {
        cpu.recommended_march.clone()
    };

    // Build the comma-separated +feature list. Order matches the
    // SAIN-01 hot path: AVX-512 family first (these unlock the
    // 512-bit ZMM register pressure), then AVX2/FMA fallbacks.
    let mut features: Vec<&'static str> = Vec::new();
    if cpu.avx512f {
        features.push("+avx512f");
    }
    if cpu.avx512dq {
        features.push("+avx512dq");
    }
    if cpu.avx512bw {
        features.push("+avx512bw");
    }
    if cpu.avx512vl {
        features.push("+avx512vl");
    }
    if cpu.avx512vnni {
        features.push("+avx512vnni");
    }
    if cpu.avx512bf16 {
        features.push("+avx512bf16");
    }
    if cpu.avx512fp16 {
        features.push("+avx512fp16");
    }
    if cpu.avx512vbmi {
        features.push("+avx512vbmi");
    }
    if cpu.avx512vbmi2 {
        features.push("+avx512vbmi2");
    }
    if cpu.avx2 {
        features.push("+avx2");
    }
    if cpu.fma {
        features.push("+fma");
    }
    let target_features = features.join(",");

    // Worked example. Empty when no AVX-512 — on those hosts
    // operator should just use `native` and skip the explicit
    // feature list to avoid pinning wasmtime to a stale view.
    let compile_command_hint = if cpu.avx512f {
        format!(
            "wasmtime compile --target {target_triple} --target-feature {target_features} module.wasm -o module.cwasm"
        )
    } else {
        String::new()
    };

    WasmAotCapabilities {
        target_triple,
        target_cpu,
        target_features,
        compile_command_hint,
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

/// SD-R29: map an nvidia-smi `model_hint` string to a CUDA SM
/// architecture (e.g. "sm_120" for Blackwell, "sm_86" for RTX 3090
/// Ampere). Pure function — driven purely by substring matching on
/// the model name. Returns `None` when the model is unknown or the
/// hint is empty.
///
/// Reference (NVIDIA Architecture → SM mapping):
///   Blackwell (RTX PRO 6000, B100, B200) → sm_120
///   Hopper    (H100, H200)                → sm_90
///   Ada       (RTX 4090, L40, L40S)       → sm_89
///   Ampere    (RTX 3090, A100)            → sm_86 / sm_80
///   Turing    (RTX 2080 Ti)               → sm_75
///
/// The SAIN-01 case (RTX PRO 6000 + RTX 3090) needs sm_120 + sm_86
/// for fat-binary builds. NVCC accepts these via
/// `-gencode arch=compute_<n>,code=sm_<n>`.
#[must_use]
pub fn nvidia_sm_for_model(model_hint: &str) -> Option<&'static str> {
    let m = model_hint.to_ascii_lowercase();
    // Blackwell: SAIN-01 primary (RTX PRO 6000 Blackwell), B100/B200.
    if m.contains("blackwell")
        || m.contains("rtx pro 6000")
        || m.contains("b100")
        || m.contains("b200")
    {
        return Some("sm_120");
    }
    // Hopper datacenter.
    if m.contains("h100") || m.contains("h200") || m.contains("hopper") {
        return Some("sm_90");
    }
    // Ada Lovelace: RTX 40-series, L40 / L40S.
    if m.contains("rtx 4090")
        || m.contains("rtx 4080")
        || m.contains("rtx 4070")
        || m.contains("rtx 4060")
        || m.contains("l40s")
        || m.contains("l40")
        || m.contains("ada")
    {
        return Some("sm_89");
    }
    // Ampere datacenter: A100 (sm_80) — distinct from A30/A40 (sm_80
    // too) and consumer Ampere RTX 30-series (sm_86).
    if m.contains("a100") {
        return Some("sm_80");
    }
    // Ampere consumer: SAIN-01 secondary (RTX 3090).
    if m.contains("rtx 3090")
        || m.contains("rtx 3080")
        || m.contains("rtx 3070")
        || m.contains("rtx 3060")
        || m.contains("ampere")
    {
        return Some("sm_86");
    }
    // Turing.
    if m.contains("rtx 2080") || m.contains("rtx 2070") || m.contains("turing") {
        return Some("sm_75");
    }
    None
}

/// SD-R29: build the NVCC `-gencode` flag list for a host's GPU
/// fleet. Each detected GPU contributes one `-gencode` entry; unknown
/// models are skipped silently (operator gets a build that targets
/// what we DO know about, plus a JIT fallback at runtime).
///
/// Result is deduplicated (a SAIN-01-style pair of identical cards
/// only emits one entry). Order preserved by first appearance.
#[must_use]
pub fn gencode_flags_for_gpus(caps: &HardwareCapabilities) -> Vec<String> {
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut out = Vec::new();
    for d in &caps.gpu.devices {
        if let Some(hint) = d.model_hint.as_deref() {
            if let Some(sm) = nvidia_sm_for_model(hint) {
                if seen.insert(sm) {
                    out.push(format!("-gencode arch=compute_{},code={}", &sm[3..], sm,));
                }
            }
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
    // SD-R17: per-sensor temperature gauges. Only emitted when at
    // least one thermal reading is present — keeps the textfile
    // collector output empty-label-free on hosts without hwmon.
    if !snap.thermals.is_empty() {
        writeln!(
            &mut buf,
            "# HELP sovereign_os_selfdef_hardware_thermal_celsius Per-sensor temperature in degrees Celsius (SD-R17)"
        )
        .unwrap();
        writeln!(
            &mut buf,
            "# TYPE sovereign_os_selfdef_hardware_thermal_celsius gauge"
        )
        .unwrap();
        for t in &snap.thermals {
            // Sanitize label: replace " characters in source.
            let safe = t.source.replace('"', "\\\"");
            writeln!(
                &mut buf,
                "sovereign_os_selfdef_hardware_thermal_celsius{{sensor=\"{}\"}} {}",
                safe, t.celsius
            )
            .unwrap();
        }
    }
    // SD-R24: per-GPU power draw + limit gauges. Only emitted when at
    // least one GPU has a parseable reading — hosts without NVML or
    // without nvidia-smi don't pollute the textfile collector with
    // empty labels.
    let any_power = snap
        .gpus
        .iter()
        .any(|g| g.power_draw_watts.is_some() || g.power_limit_watts.is_some());
    if any_power {
        writeln!(
            &mut buf,
            "# HELP sovereign_os_selfdef_hardware_gpu_power_draw_watts Per-GPU instantaneous power draw in watts (SD-R24)"
        )
        .unwrap();
        writeln!(
            &mut buf,
            "# TYPE sovereign_os_selfdef_hardware_gpu_power_draw_watts gauge"
        )
        .unwrap();
        for (idx, g) in snap.gpus.iter().enumerate() {
            if let Some(w) = g.power_draw_watts {
                writeln!(
                    &mut buf,
                    "sovereign_os_selfdef_hardware_gpu_power_draw_watts{{gpu=\"{idx}\"}} {w}"
                )
                .unwrap();
            }
        }
        writeln!(
            &mut buf,
            "# HELP sovereign_os_selfdef_hardware_gpu_power_limit_watts Per-GPU nominal power limit in watts (SD-R24)"
        )
        .unwrap();
        writeln!(
            &mut buf,
            "# TYPE sovereign_os_selfdef_hardware_gpu_power_limit_watts gauge"
        )
        .unwrap();
        for (idx, g) in snap.gpus.iter().enumerate() {
            if let Some(w) = g.power_limit_watts {
                writeln!(
                    &mut buf,
                    "sovereign_os_selfdef_hardware_gpu_power_limit_watts{{gpu=\"{idx}\"}} {w}"
                )
                .unwrap();
            }
        }
    }
    // SD-R31: WasmAotCapabilities scrape surface. Operator + fleet
    // scrapers can see at-a-glance which AVX-512 feature set the host
    // surfaced to wasmtime — confirms the cycle-2 SD-R30 bridge is
    // doing what it's expected to.
    let cpu_for_wasm = CpuCapabilities {
        recommended_march: recommended_march_for(&snap.cpu.vendor, &snap.cpu.features),
        avx2: snap.cpu.features.contains("avx2"),
        fma: snap.cpu.features.contains("fma"),
        avx512f: snap.cpu.features.contains("avx512f"),
        avx512dq: snap.cpu.features.contains("avx512dq"),
        avx512bw: snap.cpu.features.contains("avx512bw"),
        avx512vl: snap.cpu.features.contains("avx512vl"),
        avx512vnni: snap.cpu.features.contains("avx512_vnni"),
        avx512bf16: snap.cpu.features.contains("avx512_bf16"),
        avx512fp16: snap.cpu.features.contains("avx512_fp16"),
        avx512vbmi: snap.cpu.features.contains("avx512_vbmi"),
        avx512vbmi2: snap.cpu.features.contains("avx512_vbmi2"),
        ..Default::default()
    };
    let wasm_aot = derive_wasm_aot_capabilities(&cpu_for_wasm);
    if !wasm_aot.target_features.is_empty() {
        writeln!(
            &mut buf,
            "# HELP sovereign_os_selfdef_hardware_wasm_aot_feature_count Number of AVX-512/AVX2 features surfaced to wasmtime (SD-R31)"
        )
        .unwrap();
        writeln!(
            &mut buf,
            "# TYPE sovereign_os_selfdef_hardware_wasm_aot_feature_count gauge"
        )
        .unwrap();
        let count = wasm_aot.target_features.split(',').count();
        writeln!(
            &mut buf,
            "sovereign_os_selfdef_hardware_wasm_aot_feature_count {count}"
        )
        .unwrap();

        // info-style metric carrying the target_cpu + target_features
        // as labels (1.0 value, like cAdvisor's container_info pattern).
        // Operators dashboard joins on this to surface the readable
        // feature string + CPU name without parsing the JSON file.
        writeln!(
            &mut buf,
            "# HELP sovereign_os_selfdef_hardware_wasm_aot_info Static labels carrying SD-R30 wasm_aot.target_cpu + target_features (SD-R31)"
        )
        .unwrap();
        writeln!(
            &mut buf,
            "# TYPE sovereign_os_selfdef_hardware_wasm_aot_info gauge"
        )
        .unwrap();
        let safe_features = wasm_aot.target_features.replace('"', "\\\"");
        let safe_cpu = wasm_aot.target_cpu.replace('"', "\\\"");
        writeln!(
            &mut buf,
            "sovereign_os_selfdef_hardware_wasm_aot_info{{target_cpu=\"{safe_cpu}\",target_features=\"{safe_features}\"}} 1"
        )
        .unwrap();
    }
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

    // ----- SD-R17 thermals -----------------------------------------

    fn write_thermal_fixture(root: &Path, hwmon_idx: u32, name: &str, temps: &[(u32, i64)]) {
        let d = root.join(format!("hwmon{hwmon_idx}"));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("name"), format!("{name}\n")).unwrap();
        for (idx, millideg) in temps {
            fs::write(d.join(format!("temp{idx}_input")), format!("{millideg}\n")).unwrap();
        }
    }

    #[test]
    fn sdr17_read_thermals_from_hwmon_empty_dir() {
        let dir = tempdir().unwrap();
        let out = read_thermals_from_hwmon(dir.path());
        assert!(out.is_empty(), "empty hwmon root → no readings");
    }

    #[test]
    fn sdr17_read_thermals_from_hwmon_nonexistent_path() {
        let out = read_thermals_from_hwmon(Path::new("/this/path/does/not/exist/r17"));
        assert!(out.is_empty(), "nonexistent path → no readings (no panic)");
    }

    #[test]
    fn sdr17_read_thermals_from_hwmon_parses_k10temp_plus_nvme() {
        let dir = tempdir().unwrap();
        // hwmon0: k10temp (AMD Ryzen CPU package), with two temp inputs.
        write_thermal_fixture(dir.path(), 0, "k10temp", &[(1, 52_300), (2, 61_700)]);
        // hwmon1: nvme drive.
        write_thermal_fixture(dir.path(), 1, "nvme", &[(1, 38_400)]);
        // Add a per-sensor label on hwmon0 temp1 — common kernel exposure.
        fs::write(dir.path().join("hwmon0/temp1_label"), "Tctl\n").unwrap();
        let out = read_thermals_from_hwmon(dir.path());
        assert_eq!(out.len(), 3, "got: {out:?}");
        // Sorted by hwmon index, then temp index — stable output.
        assert_eq!(out[0].source, "k10temp/Tctl");
        assert_eq!(out[0].celsius, 52);
        assert_eq!(out[1].source, "k10temp/temp2");
        assert_eq!(out[1].celsius, 62); // round half away from zero
        assert_eq!(out[2].source, "nvme/temp1");
        assert_eq!(out[2].celsius, 38);
    }

    #[test]
    fn sdr17_read_thermals_skips_hwmon_without_name() {
        let dir = tempdir().unwrap();
        let d = dir.path().join("hwmon0");
        fs::create_dir_all(&d).unwrap();
        // No `name` file → entire hwmon device is skipped.
        fs::write(d.join("temp1_input"), "50000\n").unwrap();
        let out = read_thermals_from_hwmon(dir.path());
        assert!(out.is_empty());
    }

    #[test]
    fn sdr17_read_thermals_skips_malformed_temp_input() {
        let dir = tempdir().unwrap();
        let d = dir.path().join("hwmon0");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("name"), "broken\n").unwrap();
        fs::write(d.join("temp1_input"), "not-a-number\n").unwrap();
        fs::write(d.join("temp2_input"), "45000\n").unwrap();
        let out = read_thermals_from_hwmon(dir.path());
        // temp1 dropped (parse error); temp2 kept.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, "broken/temp2");
        assert_eq!(out[0].celsius, 45);
    }

    #[test]
    fn sdr17_parse_nvidia_smi_gpu_temp_csv() {
        let body = "0, 47\n1, 62\n";
        let out = parse_nvidia_smi_gpu_temp_csv(body);
        assert_eq!(out, vec![(0, 47_i64), (1, 62_i64)]);
    }

    #[test]
    fn sdr17_parse_nvidia_smi_gpu_temp_csv_rejects_malformed() {
        let body = "alpha, 47\n2, beta\n3, 71\n";
        let out = parse_nvidia_smi_gpu_temp_csv(body);
        // First row: bad index → drop. Second row: bad temp → drop.
        // Third row: valid → keep.
        assert_eq!(out, vec![(3, 71_i64)]);
    }

    #[test]
    fn sdr17_render_layer_b_emits_thermal_gauge_when_present() {
        let mut snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: Vec::new(),
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        snap.thermals.push(ThermalReading {
            source: "k10temp/Tctl".into(),
            celsius: 53,
        });
        snap.thermals.push(ThermalReading {
            source: "nvidia-gpu-0".into(),
            celsius: 47,
        });
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(out.contains("sovereign_os_selfdef_hardware_thermal_celsius"));
        assert!(out.contains("sensor=\"k10temp/Tctl\"} 53"));
        assert!(out.contains("sensor=\"nvidia-gpu-0\"} 47"));
        assert!(out.contains("# TYPE sovereign_os_selfdef_hardware_thermal_celsius gauge"));
    }

    #[test]
    fn sdr17_render_layer_b_omits_thermal_block_when_empty() {
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: Vec::new(),
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(
            !out.contains("hardware_thermal_celsius"),
            "thermal block should be absent when no readings: {out}"
        );
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
                power_draw_watts: None,
                power_limit_watts: None,
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
            thermals: Vec::new(),
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
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: None,
                    model_hint: None,
                    vram_bytes: None,
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
            ],
            motherboard: None,
            pcie: PcieInventory {
                gen4_or_higher_x8_slot_count: 2,
            },
            probed_at: "2026-05-16T00:00:00.000000000Z".into(),
            thermals: Vec::new(),
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
        assert_eq!(c.schema_version, "1.2.0");
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
        assert_eq!(parsed.schema_version, "1.2.0");
        assert_eq!(parsed.cpu.recommended_march, "znver5");
        assert!(parsed.cpu.avx512vnni);
        // SD-R30: wasm_aot block round-trips with the expected feature
        // string on the Zen 5 + AVX-512 synth snapshot.
        assert_eq!(parsed.wasm_aot.target_cpu, "znver5");
        assert!(parsed.wasm_aot.target_features.contains("+avx512vnni"));
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

    // ----- nvidia-smi CSV parser (SD-R13) --------------------------

    #[test]
    fn nvidia_smi_parses_sain01_dual_gpu_pair() {
        let body = "\
0, NVIDIA RTX PRO 6000 Blackwell, 98304\n\
1, NVIDIA GeForce RTX 3090, 24576\n\
";
        let parsed = parse_nvidia_smi_csv(body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 0);
        assert_eq!(parsed[0].1, "NVIDIA RTX PRO 6000 Blackwell");
        assert_eq!(parsed[0].2, Some(98304_u64 * 1024 * 1024));
        assert_eq!(parsed[1].0, 1);
        assert_eq!(parsed[1].1, "NVIDIA GeForce RTX 3090");
        assert_eq!(parsed[1].2, Some(24576_u64 * 1024 * 1024));
    }

    #[test]
    fn nvidia_smi_parser_tolerates_whitespace_variations() {
        let body = "0,NVIDIA Test GPU,8192\n";
        let parsed = parse_nvidia_smi_csv(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].1, "NVIDIA Test GPU");
    }

    #[test]
    fn nvidia_smi_parser_rejects_malformed_rows() {
        let body = "\
0, NVIDIA OK, 8192\n\
1\n\
malformed,line\n\
2, NVIDIA Also OK, 24576\n\
";
        let parsed = parse_nvidia_smi_csv(body);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 0);
        assert_eq!(parsed[1].0, 2);
    }

    #[test]
    fn nvidia_smi_parser_rejects_empty_name() {
        let body = "0, , 8192\n";
        let parsed = parse_nvidia_smi_csv(body);
        assert!(parsed.is_empty());
    }

    #[test]
    fn nvidia_smi_parser_handles_missing_vram() {
        let body = "0, NVIDIA No-VRAM Token, [Insufficient Permissions]\n";
        let parsed = parse_nvidia_smi_csv(body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].2, None);
    }

    #[test]
    fn nvidia_smi_parser_empty_input() {
        assert!(parse_nvidia_smi_csv("").is_empty());
    }

    // ----- SD-R24 power-telemetry parser ----------------------------

    #[test]
    fn sdr24_power_parser_handles_sain01_dual_gpu() {
        let body = "0, 275.4, 600.0\n1, 180.2, 350.0\n";
        let out = parse_nvidia_smi_power_csv(body);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (0, Some(275), Some(600)));
        assert_eq!(out[1], (1, Some(180), Some(350)));
    }

    #[test]
    fn sdr24_power_parser_rounds_half_away_from_zero() {
        // 275.5 → 276 (round half away from zero per f64::round).
        let out = parse_nvidia_smi_power_csv("0, 275.5, 350.0\n");
        assert_eq!(out[0].1, Some(276));
    }

    #[test]
    fn sdr24_power_parser_handles_na_readings() {
        // [N/A] is what nvidia-smi reports when NVML can't provide it.
        let out = parse_nvidia_smi_power_csv("0, [N/A], 350.0\n");
        assert_eq!(out[0], (0, None, Some(350)));
    }

    #[test]
    fn sdr24_power_parser_handles_not_supported() {
        let out = parse_nvidia_smi_power_csv("0, Not Supported, Not Supported\n");
        assert_eq!(out[0], (0, None, None));
    }

    #[test]
    fn sdr24_power_parser_rejects_malformed_index() {
        let out = parse_nvidia_smi_power_csv("alpha, 275.4, 600.0\n1, 180.2, 350.0\n");
        // First row drops; second survives.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 1);
    }

    #[test]
    fn sdr24_power_parser_clamps_negative_to_zero() {
        // nvidia-smi shouldn't ever report negative watts, but if a
        // future firmware bug does, the saturating cast keeps the
        // metric non-negative.
        let out = parse_nvidia_smi_power_csv("0, -5.0, 350.0\n");
        assert_eq!(out[0].1, Some(0));
    }

    #[test]
    fn sdr24_enrich_power_index_matches_device_node_order() {
        // Round-trip the parser into the enrichment logic without
        // invoking the real nvidia-smi.
        let body = "0, 275.4, 600.0\n1, 180.2, 350.0\n";
        let parsed = parse_nvidia_smi_power_csv(body);
        let mut gpus = [
            GpuInventory {
                device_node: PathBuf::from("/dev/nvidia0"),
                pci_address: None,
                model_hint: None,
                vram_bytes: None,
                power_draw_watts: None,
                power_limit_watts: None,
            },
            GpuInventory {
                device_node: PathBuf::from("/dev/nvidia1"),
                pci_address: None,
                model_hint: None,
                vram_bytes: None,
                power_draw_watts: None,
                power_limit_watts: None,
            },
        ]
        .to_vec();
        for (idx, draw, limit) in parsed {
            if let Some(g) = gpus.get_mut(idx) {
                g.power_draw_watts = draw;
                g.power_limit_watts = limit;
            }
        }
        assert_eq!(gpus[0].power_draw_watts, Some(275));
        assert_eq!(gpus[0].power_limit_watts, Some(600));
        assert_eq!(gpus[1].power_draw_watts, Some(180));
        assert_eq!(gpus[1].power_limit_watts, Some(350));
    }

    #[test]
    fn sdr25_derive_capabilities_populates_per_gpu_devices() {
        // Two GPUs (mirror the SAIN-01 dual-GPU pair) with distinct
        // model_hint + vram + power readings. Capabilities export
        // must surface every per-device field — that's the
        // load-bearing contract for cross-repo schedulers that need
        // to pick the right GPU.
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia0"),
                    pci_address: Some("0000:01:00.0".into()),
                    model_hint: Some("NVIDIA RTX PRO 6000 Blackwell".into()),
                    vram_bytes: Some(98 * 1024 * 1024 * 1024),
                    power_draw_watts: Some(275),
                    power_limit_watts: Some(600),
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: Some("0000:02:00.0".into()),
                    model_hint: Some("NVIDIA GeForce RTX 3090".into()),
                    vram_bytes: Some(24 * 1024 * 1024 * 1024),
                    power_draw_watts: Some(180),
                    power_limit_watts: Some(350),
                },
            ],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        assert_eq!(caps.gpu.device_count, 2);
        assert_eq!(caps.gpu.devices.len(), 2);
        // SAIN-01 primary GPU.
        let g0 = &caps.gpu.devices[0];
        assert_eq!(g0.device_node, Some(PathBuf::from("/dev/nvidia0")));
        assert_eq!(g0.pci_address.as_deref(), Some("0000:01:00.0"));
        assert_eq!(
            g0.model_hint.as_deref(),
            Some("NVIDIA RTX PRO 6000 Blackwell")
        );
        assert_eq!(g0.vram_bytes, Some(98 * 1024 * 1024 * 1024));
        assert_eq!(g0.power_draw_watts, Some(275));
        assert_eq!(g0.power_limit_watts, Some(600));
        // Secondary GPU.
        let g1 = &caps.gpu.devices[1];
        assert_eq!(g1.model_hint.as_deref(), Some("NVIDIA GeForce RTX 3090"));
        assert_eq!(g1.power_draw_watts, Some(180));
        assert_eq!(g1.power_limit_watts, Some(350));
    }

    #[test]
    fn sdr25_capabilities_serializes_devices_into_json() {
        // The forward-compat contract: capabilities.gpu.devices is in
        // the emitted JSON so sovereign-os scripts/hardware/
        // selfdef-modules-gate.py (R170) + future schedulers see it.
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![GpuInventory {
                device_node: PathBuf::from("/dev/nvidia0"),
                pci_address: None,
                model_hint: Some("NVIDIA RTX PRO 6000 Blackwell".into()),
                vram_bytes: Some(98 * 1024 * 1024 * 1024),
                power_draw_watts: Some(275),
                power_limit_watts: Some(600),
            }],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        let json = serde_json::to_string(&caps).expect("serializes");
        assert!(json.contains("\"devices\""), "json: {json}");
        assert!(json.contains("\"model_hint\":"), "json: {json}");
        assert!(json.contains("RTX PRO 6000 Blackwell"), "json: {json}");
        assert!(json.contains("\"power_draw_watts\":275"), "json: {json}");
        assert!(json.contains("\"power_limit_watts\":600"), "json: {json}");
    }

    #[test]
    fn sdr25_capabilities_devices_empty_when_no_gpus() {
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: Vec::new(),
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        assert_eq!(caps.gpu.device_count, 0);
        assert!(caps.gpu.devices.is_empty());
    }

    #[test]
    fn sdr24_render_layer_b_emits_power_gauges_when_present() {
        let mut snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia0"),
                    pci_address: None,
                    model_hint: None,
                    vram_bytes: None,
                    power_draw_watts: Some(275),
                    power_limit_watts: Some(600),
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: None,
                    model_hint: None,
                    vram_bytes: None,
                    power_draw_watts: Some(180),
                    power_limit_watts: Some(350),
                },
            ],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(out.contains("sovereign_os_selfdef_hardware_gpu_power_draw_watts"));
        assert!(out.contains("gpu=\"0\"} 275"));
        assert!(out.contains("gpu=\"0\"} 600"));
        assert!(out.contains("gpu=\"1\"} 180"));
        assert!(out.contains("gpu=\"1\"} 350"));
        // Both HELP+TYPE blocks present.
        assert!(out.contains("# TYPE sovereign_os_selfdef_hardware_gpu_power_draw_watts gauge"));
        assert!(out.contains("# TYPE sovereign_os_selfdef_hardware_gpu_power_limit_watts gauge"));

        // Mutation guard: if no GPU has any power reading, block omitted.
        for g in &mut snap.gpus {
            g.power_draw_watts = None;
            g.power_limit_watts = None;
        }
        let out2 = render_layer_b_metrics(&snap, &m);
        assert!(!out2.contains("hardware_gpu_power_draw_watts"));
        assert!(!out2.contains("hardware_gpu_power_limit_watts"));
    }

    #[test]
    fn sdr24_enrich_power_preserves_existing_values() {
        // Caller-set values aren't overwritten — same contract as
        // SD-R13 model/vram enrichment.
        let mut gpus = [GpuInventory {
            device_node: PathBuf::from("/dev/nvidia0"),
            pci_address: None,
            model_hint: None,
            vram_bytes: None,
            power_draw_watts: Some(42),
            power_limit_watts: Some(99),
        }]
        .to_vec();
        let parsed = parse_nvidia_smi_power_csv("0, 275.4, 600.0\n");
        for (idx, draw, limit) in parsed {
            if let Some(g) = gpus.get_mut(idx) {
                if g.power_draw_watts.is_none() {
                    g.power_draw_watts = draw;
                }
                if g.power_limit_watts.is_none() {
                    g.power_limit_watts = limit;
                }
            }
        }
        assert_eq!(gpus[0].power_draw_watts, Some(42));
        assert_eq!(gpus[0].power_limit_watts, Some(99));
    }

    #[test]
    fn enrich_gpus_index_matches_device_node_order() {
        // Simulate the enrichment without invoking the real
        // nvidia-smi: build the parsed output directly + apply.
        let mut gpus = [
            GpuInventory {
                device_node: PathBuf::from("/dev/nvidia0"),
                pci_address: None,
                model_hint: None,
                vram_bytes: None,
                power_draw_watts: None,
                power_limit_watts: None,
            },
            GpuInventory {
                device_node: PathBuf::from("/dev/nvidia1"),
                pci_address: None,
                model_hint: None,
                vram_bytes: None,
                power_draw_watts: None,
                power_limit_watts: None,
            },
        ];
        let parsed = vec![
            (
                0_usize,
                "NVIDIA RTX PRO 6000 Blackwell".into(),
                Some(98304_u64 * 1024 * 1024),
            ),
            (
                1,
                "NVIDIA GeForce RTX 3090".into(),
                Some(24576_u64 * 1024 * 1024),
            ),
        ];
        for (idx, model, vram) in parsed {
            if let Some(g) = gpus.get_mut(idx) {
                g.model_hint = Some(model);
                g.vram_bytes = vram;
            }
        }
        assert_eq!(
            gpus[0].model_hint.as_deref(),
            Some("NVIDIA RTX PRO 6000 Blackwell")
        );
        assert_eq!(gpus[0].vram_bytes, Some(98304_u64 * 1024 * 1024));
        assert_eq!(
            gpus[1].model_hint.as_deref(),
            Some("NVIDIA GeForce RTX 3090")
        );
    }

    #[test]
    fn enrich_gpus_via_nvidia_smi_no_op_when_empty_input() {
        let gpus = enrich_gpus_via_nvidia_smi(Vec::new());
        assert!(gpus.is_empty());
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

    // ----- SD-R29: per-GPU NVCC arch derivation ---------------------

    #[test]
    fn sdr29_nvidia_sm_recognises_sain01_pair() {
        assert_eq!(
            nvidia_sm_for_model("NVIDIA RTX PRO 6000 Blackwell"),
            Some("sm_120"),
            "SAIN-01 primary GPU"
        );
        assert_eq!(
            nvidia_sm_for_model("NVIDIA GeForce RTX 3090"),
            Some("sm_86"),
            "SAIN-01 secondary GPU"
        );
    }

    #[test]
    fn sdr29_nvidia_sm_handles_common_architectures() {
        assert_eq!(nvidia_sm_for_model("NVIDIA H100"), Some("sm_90"));
        assert_eq!(nvidia_sm_for_model("NVIDIA L40S"), Some("sm_89"));
        assert_eq!(nvidia_sm_for_model("NVIDIA RTX 4090"), Some("sm_89"));
        assert_eq!(nvidia_sm_for_model("NVIDIA A100 80GB"), Some("sm_80"));
        assert_eq!(nvidia_sm_for_model("NVIDIA RTX 2080 Ti"), Some("sm_75"));
    }

    #[test]
    fn sdr29_nvidia_sm_returns_none_on_unknown() {
        assert_eq!(nvidia_sm_for_model(""), None);
        assert_eq!(nvidia_sm_for_model("AMD Radeon RX 7900"), None);
        assert_eq!(nvidia_sm_for_model("Intel Arc A770"), None);
    }

    #[test]
    fn sdr29_nvidia_sm_is_case_insensitive() {
        assert_eq!(
            nvidia_sm_for_model("nvidia rtx pro 6000 blackwell"),
            Some("sm_120")
        );
        assert_eq!(nvidia_sm_for_model("BLACKWELL B100"), Some("sm_120"));
    }

    #[test]
    fn sdr29_gencode_emits_one_per_sm_dedup_pair_of_3090s() {
        // Two identical RTX 3090s — single -gencode entry (sm_86).
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia0"),
                    pci_address: None,
                    model_hint: Some("NVIDIA GeForce RTX 3090".into()),
                    vram_bytes: Some(24 * 1024 * 1024 * 1024),
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: None,
                    model_hint: Some("NVIDIA GeForce RTX 3090".into()),
                    vram_bytes: Some(24 * 1024 * 1024 * 1024),
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
            ],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        let flags = gencode_flags_for_gpus(&caps);
        assert_eq!(flags.len(), 1);
        assert_eq!(flags[0], "-gencode arch=compute_86,code=sm_86");
    }

    #[test]
    fn sdr29_gencode_emits_both_for_sain01_pair() {
        // SAIN-01 pair → sm_120 + sm_86, both ordered by appearance.
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia0"),
                    pci_address: None,
                    model_hint: Some("NVIDIA RTX PRO 6000 Blackwell".into()),
                    vram_bytes: Some(98 * 1024 * 1024 * 1024),
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
                GpuInventory {
                    device_node: PathBuf::from("/dev/nvidia1"),
                    pci_address: None,
                    model_hint: Some("NVIDIA GeForce RTX 3090".into()),
                    vram_bytes: Some(24 * 1024 * 1024 * 1024),
                    power_draw_watts: None,
                    power_limit_watts: None,
                },
            ],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        let flags = gencode_flags_for_gpus(&caps);
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0], "-gencode arch=compute_120,code=sm_120");
        assert_eq!(flags[1], "-gencode arch=compute_86,code=sm_86");
    }

    // ----- SD-R30: wasm-AOT hint derivation -------------------------

    #[test]
    fn sdr30_wasm_aot_empty_features_when_no_avx512() {
        let cpu = CpuCapabilities {
            recommended_march: "native".into(),
            avx2: true,
            fma: true,
            ..Default::default()
        };
        let w = derive_wasm_aot_capabilities(&cpu);
        assert_eq!(w.target_cpu, "native");
        assert_eq!(w.target_features, "+avx2,+fma");
        assert!(
            w.compile_command_hint.is_empty(),
            "no AVX-512 → no hint command"
        );
    }

    #[test]
    fn sdr30_wasm_aot_full_sain01_feature_string() {
        // Zen 5 + every AVX-512 family bit the SAIN-01 9900X exposes.
        let cpu = CpuCapabilities {
            recommended_march: "znver5".into(),
            avx2: true,
            fma: true,
            avx512f: true,
            avx512dq: true,
            avx512bw: true,
            avx512vl: true,
            avx512vnni: true,
            avx512bf16: true,
            avx512vbmi: true,
            avx512vbmi2: true,
            ..Default::default()
        };
        let w = derive_wasm_aot_capabilities(&cpu);
        assert_eq!(w.target_cpu, "znver5");
        // AVX-512 family in order, then AVX2/FMA fallbacks.
        assert!(
            w.target_features.starts_with("+avx512f,"),
            "AVX-512 first: {}",
            w.target_features
        );
        assert!(w.target_features.contains("+avx512vnni"));
        assert!(w.target_features.contains("+avx512bf16"));
        assert!(w.target_features.ends_with(",+avx2,+fma"));
        // Worked example present.
        assert!(w.compile_command_hint.contains("wasmtime compile"));
        assert!(w.compile_command_hint.contains("--target-feature"));
        assert!(w.compile_command_hint.contains("+avx512f"));
    }

    #[test]
    fn sdr30_wasm_aot_target_triple_is_x86_64_linux() {
        let w = derive_wasm_aot_capabilities(&CpuCapabilities::default());
        assert_eq!(w.target_triple, "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn sdr30_capabilities_schema_bumped_to_1_2_0() {
        let snap = snap_with_features("AuthenticAMD", &["avx2"]);
        let c = derive_capabilities(&snap);
        assert_eq!(c.schema_version, "1.2.0");
    }

    #[test]
    fn sdr30_capabilities_carries_wasm_aot_block_in_json() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &["avx2", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        let c = derive_capabilities(&snap);
        let json = serde_json::to_string(&c).expect("serializes");
        assert!(
            json.contains("\"wasm_aot\""),
            "wasm_aot field missing: {json}"
        );
        assert!(json.contains("\"target_features\":\"+avx512f"));
        assert!(json.contains("\"compile_command_hint\""));
    }

    // ----- SD-R31: wasm-AOT Layer B metric --------------------------

    #[test]
    fn sdr31_layer_b_emits_wasm_aot_feature_count_when_avx512_present() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &["avx2", "fma", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(
            out.contains("sovereign_os_selfdef_hardware_wasm_aot_feature_count"),
            "missing feature_count gauge: {out}"
        );
        // The 5 features → 5 entries in target_features.
        assert!(
            out.contains("sovereign_os_selfdef_hardware_wasm_aot_feature_count 5"),
            "wrong feature count: {out}"
        );
    }

    #[test]
    fn sdr31_layer_b_info_metric_carries_target_cpu_and_features_labels() {
        let snap = snap_with_features(
            "AuthenticAMD",
            &["avx2", "fma", "avx512f", "avx512_vnni", "avx512_bf16"],
        );
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(
            out.contains("sovereign_os_selfdef_hardware_wasm_aot_info"),
            "missing info metric: {out}"
        );
        // znver5 because vnni+bf16 both present on AuthenticAMD.
        assert!(
            out.contains("target_cpu=\"znver5\""),
            "missing target_cpu label: {out}"
        );
        assert!(
            out.contains("+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma"),
            "missing target_features label: {out}"
        );
        // info-metric value is always 1.
        assert!(
            out.contains("target_features=\"+avx512f,+avx512vnni,+avx512bf16,+avx2,+fma\"} 1"),
            "info metric value not 1: {out}"
        );
    }

    #[test]
    fn sdr31_layer_b_omits_wasm_aot_block_on_avx2_only_host() {
        // No AVX-512 → target_features is "+avx2,+fma" — still non-empty.
        // The metric block is gated on "non-empty" so AVX2-only hosts
        // still emit. But truly empty (no features at all) → omit.
        let snap = snap_with_features("GenuineIntel", &[]);
        let m = matches_sain01(&snap);
        let out = render_layer_b_metrics(&snap, &m);
        assert!(
            !out.contains("wasm_aot_feature_count"),
            "feature_count should be omitted on empty-feature host: {out}"
        );
    }

    #[test]
    fn sdr29_gencode_empty_when_no_known_gpus() {
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: vec![GpuInventory {
                device_node: PathBuf::from("/dev/nvidia0"),
                pci_address: None,
                model_hint: Some("AMD Radeon Pro W7900".into()),
                vram_bytes: None,
                power_draw_watts: None,
                power_limit_watts: None,
            }],
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
        };
        let caps = derive_capabilities(&snap);
        assert!(gencode_flags_for_gpus(&caps).is_empty());
    }
}
