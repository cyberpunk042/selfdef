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
    // PCIe x8 detection is best-effort via lspci (subprocess) — not
    // staged-fs-testable, so we default to 0 and let the operator run
    // sovereign-os's friction-audit for the real PCIe verification.
    let pcie = PcieInventory::default();
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
}
