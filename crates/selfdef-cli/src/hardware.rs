//! `selfdefctl hardware` — SAIN-01 hardware inventory introspection (SDD-017).
//!
//! Operator-facing entry point to [`selfdef_hardware::probe`] + the
//! [`Sain01Match`] verdict. Human and JSON renderings provided; both
//! the probe and the match function are pure-Rust + best-effort, so
//! `selfdefctl hardware` runs safely on any host (a generic VM
//! produces zero GPUs + a NoMatch verdict, never a crash).

use anyhow::Result;
use selfdef_hardware::{HardwareSnapshot, Sain01Match, Sain01Verdict};

/// `selfdefctl hardware` default rendering — human-readable.
pub(crate) fn run_human() -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let m = selfdef_hardware::matches_sain01(&snap);
    print!("{}", render_human(&snap, &m));
    Ok(verdict_exit(m.overall))
}

/// `selfdefctl hardware --json` — machine-readable rendering.
pub(crate) fn run_json() -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let m = selfdef_hardware::matches_sain01(&snap);
    let doc = serde_json::json!({
        "snapshot": snap,
        "sain01_match": m,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(verdict_exit(m.overall))
}

/// `selfdefctl hardware match` — verdict only.
pub(crate) fn run_match() -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let m = selfdef_hardware::matches_sain01(&snap);
    println!("{}", verdict_label(m.overall));
    Ok(verdict_exit(m.overall))
}

/// Exit code mapping: FullMatch → 0, PartialMatch → 0, NoMatch → 2.
/// (Partial is non-fatal — operators just want awareness, not a block.)
pub(crate) fn verdict_exit(v: Sain01Verdict) -> i32 {
    match v {
        Sain01Verdict::FullMatch | Sain01Verdict::PartialMatch => 0,
        Sain01Verdict::NoMatch => 2,
    }
}

fn verdict_label(v: Sain01Verdict) -> &'static str {
    match v {
        Sain01Verdict::FullMatch => "FullMatch",
        Sain01Verdict::PartialMatch => "PartialMatch",
        Sain01Verdict::NoMatch => "NoMatch",
    }
}

/// Pure human-readable rendering — pulled out so tests can pin the
/// shape without running probe().
pub(crate) fn render_human(snap: &HardwareSnapshot, m: &Sain01Match) -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(&mut buf, "# selfdefctl hardware (SDD-017)").unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## CPU").unwrap();
    writeln!(
        &mut buf,
        "  vendor:           {}",
        if snap.cpu.vendor.is_empty() {
            "(unknown)"
        } else {
            &snap.cpu.vendor
        }
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  model:            {}",
        if snap.cpu.model_name.is_empty() {
            "(unknown)"
        } else {
            &snap.cpu.model_name
        }
    )
    .unwrap();
    writeln!(&mut buf, "  physical_cores:   {}", snap.cpu.physical_cores).unwrap();
    writeln!(&mut buf, "  logical_threads:  {}", snap.cpu.logical_threads).unwrap();
    writeln!(&mut buf, "  avx512_present:   {}", snap.cpu.avx512_present).unwrap();
    writeln!(&mut buf, "  avx512_vnni:      {}", snap.cpu.avx512_vnni).unwrap();
    writeln!(&mut buf, "  avx512_bf16:      {}", snap.cpu.avx512_bf16).unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Memory").unwrap();
    writeln!(
        &mut buf,
        "  total_bytes:      {} ({})",
        snap.memory.total_bytes,
        format_bytes(snap.memory.total_bytes)
    )
    .unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## GPUs").unwrap();
    if snap.gpus.is_empty() {
        writeln!(&mut buf, "  (none detected)").unwrap();
    } else {
        for (i, g) in snap.gpus.iter().enumerate() {
            writeln!(
                &mut buf,
                "  [{i}] device_node = {}",
                g.device_node.display()
            )
            .unwrap();
            if let Some(addr) = &g.pci_address {
                writeln!(&mut buf, "       pci_address = {addr}").unwrap();
            }
            if let Some(model) = &g.model_hint {
                writeln!(&mut buf, "       model = {model}").unwrap();
            }
            if let Some(vram) = g.vram_bytes {
                writeln!(&mut buf, "       vram_bytes = {vram}").unwrap();
            }
        }
    }
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Motherboard").unwrap();
    match &snap.motherboard {
        Some(mb) => {
            writeln!(
                &mut buf,
                "  vendor:           {}",
                mb.vendor.as_deref().unwrap_or("(unknown)")
            )
            .unwrap();
            writeln!(
                &mut buf,
                "  product_name:     {}",
                mb.product_name.as_deref().unwrap_or("(unknown)")
            )
            .unwrap();
        }
        None => writeln!(&mut buf, "  (DMI unreadable)").unwrap(),
    }
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## PCIe").unwrap();
    writeln!(
        &mut buf,
        "  gen4_or_higher_x8_slot_count: {} (run sovereign-osctl friction-audit for authoritative PCIe report)",
        snap.pcie.gen4_or_higher_x8_slot_count
    )
    .unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Sain01Match verdict").unwrap();
    writeln!(
        &mut buf,
        "  overall:               {}",
        verdict_label(m.overall)
    )
    .unwrap();
    writeln!(&mut buf, "  cpu_avx512_vnni:       {}", m.cpu_avx512_vnni).unwrap();
    writeln!(&mut buf, "  cpu_avx512_bf16:       {}", m.cpu_avx512_bf16).unwrap();
    writeln!(
        &mut buf,
        "  memory_at_least_256gb: {}",
        m.memory_at_least_256gb
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  gpu_count_at_least_2:  {}",
        m.gpu_count_at_least_2
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  pcie_dual_x8_present:  {}",
        m.pcie_dual_x8_present
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  motherboard_proart_x870e: {}",
        match m.motherboard_proart_x870e {
            Some(true) => "true",
            Some(false) => "false",
            None => "(DMI unreadable)",
        }
    )
    .unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "probed_at: {}", snap.probed_at).unwrap();
    buf
}

fn format_bytes(b: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if b == 0 {
        return "0".into();
    }
    if b >= GIB {
        let gib = (b as f64) / (GIB as f64);
        format!("{gib:.1} GiB")
    } else {
        format!("{b} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_hardware::{
        CpuInventory, GpuInventory, HardwareSnapshot, MemoryInventory, MotherboardInventory,
        PcieInventory, Sain01Match, Sain01Verdict,
    };
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn synth() -> (HardwareSnapshot, Sain01Match) {
        let snap = HardwareSnapshot {
            cpu: CpuInventory {
                vendor: "AuthenticAMD".into(),
                model_name: "AMD Ryzen 9 9900X".into(),
                physical_cores: 12,
                logical_threads: 24,
                features: ["avx512f", "avx512_vnni", "avx512_bf16"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<HashSet<_>>(),
                avx512_present: true,
                avx512_vnni: true,
                avx512_bf16: true,
            },
            memory: MemoryInventory {
                total_bytes: 274_877_906_944,
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
            motherboard: Some(MotherboardInventory {
                vendor: Some("ASUSTeK COMPUTER INC.".into()),
                product_name: Some("ProArt X870E-CREATOR WIFI".into()),
            }),
            pcie: PcieInventory {
                gen4_or_higher_x8_slot_count: 2,
            },
            probed_at: "2026-05-16T00:00:00Z".into(),
        };
        let m = selfdef_hardware::matches_sain01(&snap);
        (snap, m)
    }

    #[test]
    fn render_human_includes_all_sections_for_full_match() {
        let (snap, m) = synth();
        let out = render_human(&snap, &m);
        for marker in [
            "## CPU",
            "## Memory",
            "## GPUs",
            "## Motherboard",
            "## PCIe",
            "## Sain01Match verdict",
            "Ryzen 9 9900X",
            "256.0 GiB",
            "/dev/nvidia0",
            "/dev/nvidia1",
            "ProArt X870E-CREATOR WIFI",
            "FullMatch",
        ] {
            assert!(out.contains(marker), "render missing {marker}: {out}");
        }
    }

    #[test]
    fn render_human_handles_unknown_fields_gracefully() {
        let snap = HardwareSnapshot {
            cpu: CpuInventory::default(),
            memory: MemoryInventory::default(),
            gpus: Vec::new(),
            motherboard: None,
            pcie: PcieInventory::default(),
            probed_at: "2026-05-16T00:00:00Z".into(),
        };
        let m = selfdef_hardware::matches_sain01(&snap);
        let out = render_human(&snap, &m);
        assert!(out.contains("(unknown)"));
        assert!(out.contains("(none detected)"));
        assert!(out.contains("(DMI unreadable)"));
        assert!(out.contains("NoMatch"));
    }

    #[test]
    fn format_bytes_renders_gib_threshold() {
        assert_eq!(format_bytes(0), "0");
        assert_eq!(format_bytes(1024), "1024 bytes");
        let one_gib = 1024 * 1024 * 1024;
        assert_eq!(format_bytes(one_gib), "1.0 GiB");
    }

    #[test]
    fn verdict_exit_partial_is_zero() {
        // Operator wants awareness without blocking; PartialMatch
        // exits 0 (informational).
        assert_eq!(verdict_exit(Sain01Verdict::FullMatch), 0);
        assert_eq!(verdict_exit(Sain01Verdict::PartialMatch), 0);
        assert_eq!(verdict_exit(Sain01Verdict::NoMatch), 2);
    }
}
