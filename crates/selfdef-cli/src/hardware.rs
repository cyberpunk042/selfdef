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

/// SD-R10: `selfdefctl hardware export` — emit the
/// HardwareCapabilities JSON to stdout (default) or to `--output PATH`.
/// Consumed by sovereign-os Wasm-AOT pipeline + future hardware-aware
/// agent-guard policies.
pub(crate) fn run_export(output: Option<std::path::PathBuf>) -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    match output {
        None => {
            let caps = selfdef_hardware::derive_capabilities(&snap);
            println!("{}", serde_json::to_string_pretty(&caps)?);
            Ok(verdict_exit(caps.sain01_match.overall))
        }
        Some(p) => {
            selfdef_hardware::write_capabilities_json(&p, &snap)?;
            println!("wrote {}", p.display());
            let m = selfdef_hardware::matches_sain01(&snap);
            Ok(verdict_exit(m.overall))
        }
    }
}

/// SD-R17: `selfdefctl hardware thermals` — per-sensor temperatures
/// from /sys/class/hwmon (CPU package, NVMe drives, motherboard
/// sensors) plus nvidia-smi GPU temps when nvidia-smi is available.
/// Read-only; exit code 0 always.
/// SD-R67: `selfdefctl hardware posture` — one-screen
/// hardware-exploit posture summary. Composes SD-R64 + SD-R66 into
/// the "can this box run 1-bit / ternary models at the hot-path lane
/// width?" operator-readable rollup.
pub(crate) fn run_posture(json: bool) -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let caps = selfdef_hardware::derive_capabilities(&snap);
    if json {
        let doc = serde_json::json!({
            "ternary_aot_capable": caps.cpu.ternary_aot_capable,
            "zmm_int8_lane_capacity": caps.cpu.zmm_int8_lane_capacity,
            "ternary_kernel_hint": caps.wasm_aot.ternary_kernel_hint,
            "target_cpu": caps.wasm_aot.target_cpu,
            "target_features": caps.wasm_aot.target_features,
            "sain01_match": caps.sain01_match.overall,
        });
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else {
        print!("{}", render_posture(&caps));
    }
    Ok(verdict_exit(caps.sain01_match.overall))
}

/// SD-R67 — pure render. Tests pin the operator-facing format.
pub(crate) fn render_posture(caps: &selfdef_hardware::HardwareCapabilities) -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(&mut buf, "── selfdef hardware-exploit posture (SD-R67) ──").unwrap();
    writeln!(
        &mut buf,
        "  Sain01 verdict          : {:?}",
        caps.sain01_match.overall
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  Target CPU (LLVM)       : {}",
        caps.wasm_aot.target_cpu
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  Target features         : {}",
        if caps.wasm_aot.target_features.is_empty() {
            "(none — pre-AVX-512 host)"
        } else {
            &caps.wasm_aot.target_features
        }
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  Ternary AOT capable     : {}",
        if caps.cpu.ternary_aot_capable {
            "yes (VNNI + (BF16 or FP16))"
        } else {
            "no — host lacks VNNI or small-FP path"
        }
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  ZMM INT8 lane capacity  : {} (master spec § 16 reading)",
        caps.cpu.zmm_int8_lane_capacity
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  Kernel hint             : {}",
        if caps.wasm_aot.ternary_kernel_hint.is_empty() {
            "(no INT8 SIMD path on this host)"
        } else {
            &caps.wasm_aot.ternary_kernel_hint
        }
    )
    .unwrap();
    buf
}

pub(crate) fn run_thermals(json: bool) -> Result<i32> {
    // Probe once — selfdef_hardware::probe wires the thermal reads
    // into HardwareSnapshot.thermals.
    let snap = selfdef_hardware::probe()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snap.thermals)?);
        return Ok(0);
    }
    if snap.thermals.is_empty() {
        println!("(no thermal sensors exposed — hwmon empty + nvidia-smi unavailable)");
        return Ok(0);
    }
    println!("{:<28}  celsius", "sensor");
    for t in &snap.thermals {
        println!("{:<28}  {}", t.source, t.celsius);
    }
    Ok(0)
}

/// SD-R19: `selfdefctl hardware tune` — emit host-tuned compile
/// flags in the requested format. Direct enabler for Wasm-AOT +
/// bitnet.cpp builds: operators run
///   `source <(selfdefctl hardware tune --format sh)`
/// before invoking the build pipeline + the compiler picks up
/// MARCH / CFLAGS / KCFLAGS reflecting this host's actual feature
/// set (znver5 + AVX-512 VNNI/BF16/FP16/VBMI/VBMI2 on a SAIN-01 box).
pub(crate) fn run_tune(format: &str, output: Option<std::path::PathBuf>) -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let caps = selfdef_hardware::derive_capabilities(&snap);
    let body = render_tune(&caps, format)?;
    match output {
        None => {
            print!("{body}");
            Ok(0)
        }
        Some(p) => {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let mut tmp = p.as_os_str().to_owned();
            tmp.push(".tmp");
            let tmp_path: std::path::PathBuf = tmp.into();
            std::fs::write(&tmp_path, &body)?;
            std::fs::rename(&tmp_path, &p)?;
            println!("wrote {}", p.display());
            Ok(0)
        }
    }
}

/// Pure renderer for [`run_tune`] — pinned by unit tests.
pub(crate) fn render_tune(
    caps: &selfdef_hardware::HardwareCapabilities,
    format: &str,
) -> Result<String> {
    let march = &caps.cpu.recommended_march;
    let cflags = caps.cpu.recommended_compile_flags.join(" ");
    // KCFLAGS gets the same flag set; the kernel build picks up -march
    // via CFLAGS_KCFLAGS in newer kbuild, but operators commonly
    // export both.
    let zmm_extra = if caps.cpu.avx512f {
        // Enable full 512-bit ZMM register pressure (the operator's
        // directive: "A single 512-bit ZMM vector register can hold
        // and manipulate...").
        " -mprefer-vector-width=512"
    } else {
        ""
    };
    // SD-R29: build NVCC -gencode flags from the per-GPU
    // SD-R25/SD-R13 model hints. Empty when no GPUs are recognised
    // (operator falls back to NVCC defaults or PTX JIT).
    let gencodes = selfdef_hardware::gencode_flags_for_gpus(caps);
    let nvcc_flags = gencodes.join(" ");
    // Sort numerically ascending — "86;120" not "120;86". CMake's
    // CMAKE_CUDA_ARCHITECTURES expects this form.
    let mut arches: Vec<u32> = caps
        .gpu
        .devices
        .iter()
        .filter_map(|d| {
            d.model_hint
                .as_deref()
                .and_then(selfdef_hardware::nvidia_sm_for_model)
                .and_then(|sm| sm.trim_start_matches("sm_").parse::<u32>().ok())
        })
        .collect();
    arches.sort_unstable();
    arches.dedup();
    let cuda_arch_list = arches
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(";");
    Ok(match format {
        "sh" => format!(
            "# selfdefctl hardware tune --format sh (SD-R19 + SD-R29)\n\
             # source <(selfdefctl hardware tune --format sh) before invoking your build pipeline.\n\
             export SELFDEF_HARDWARE_MARCH={march}\n\
             export SELFDEF_HARDWARE_CFLAGS=\"-march={march}{zmm_extra} {cflags}\"\n\
             export SELFDEF_HARDWARE_KCFLAGS=\"-march={march}{zmm_extra} {cflags}\"\n\
             export SELFDEF_HARDWARE_AVX512_VNNI={vnni}\n\
             export SELFDEF_HARDWARE_AVX512_BF16={bf16}\n\
             export SELFDEF_HARDWARE_NVCC_FLAGS=\"{nvcc_flags}\"\n\
             export SELFDEF_HARDWARE_CUDA_ARCH_LIST=\"{cuda_arch_list}\"\n",
            vnni = caps.cpu.avx512vnni,
            bf16 = caps.cpu.avx512bf16,
        ),
        "env-file" => format!(
            "SELFDEF_HARDWARE_MARCH={march}\n\
             SELFDEF_HARDWARE_CFLAGS=-march={march}{zmm_extra} {cflags}\n\
             SELFDEF_HARDWARE_KCFLAGS=-march={march}{zmm_extra} {cflags}\n\
             SELFDEF_HARDWARE_AVX512_VNNI={vnni}\n\
             SELFDEF_HARDWARE_AVX512_BF16={bf16}\n\
             SELFDEF_HARDWARE_NVCC_FLAGS={nvcc_flags}\n\
             SELFDEF_HARDWARE_CUDA_ARCH_LIST={cuda_arch_list}\n",
            vnni = caps.cpu.avx512vnni,
            bf16 = caps.cpu.avx512bf16,
        ),
        "make" => format!(
            "# selfdefctl hardware tune --format make (SD-R19 + SD-R29)\n\
             # include this file from your Makefile to pick up host-tuned flags.\n\
             SELFDEF_HARDWARE_MARCH := {march}\n\
             SELFDEF_HARDWARE_CFLAGS := -march={march}{zmm_extra} {cflags}\n\
             SELFDEF_HARDWARE_KCFLAGS := -march={march}{zmm_extra} {cflags}\n\
             SELFDEF_HARDWARE_AVX512_VNNI := {vnni}\n\
             SELFDEF_HARDWARE_AVX512_BF16 := {bf16}\n\
             SELFDEF_HARDWARE_NVCC_FLAGS := {nvcc_flags}\n\
             SELFDEF_HARDWARE_CUDA_ARCH_LIST := {cuda_arch_list}\n",
            vnni = caps.cpu.avx512vnni,
            bf16 = caps.cpu.avx512bf16,
        ),
        "json" => serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": "1.1.0",
            "march": march,
            "cflags": format!("-march={march}{zmm_extra} {cflags}"),
            "kcflags": format!("-march={march}{zmm_extra} {cflags}"),
            "avx512_vnni": caps.cpu.avx512vnni,
            "avx512_bf16": caps.cpu.avx512bf16,
            "compile_flag_list": caps.cpu.recommended_compile_flags,
            "zmm_512_preferred": caps.cpu.avx512f,
            // SD-R29: per-GPU CUDA arch derivation.
            "nvcc_flags": nvcc_flags,
            "cuda_arch_list": cuda_arch_list,
            "nvcc_gencode_list": gencodes,
        }))?,
        other => {
            anyhow::bail!("unknown --format {other:?}; expected one of: sh, env-file, make, json")
        }
    })
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
            motherboard: Some(MotherboardInventory {
                vendor: Some("ASUSTeK COMPUTER INC.".into()),
                product_name: Some("ProArt X870E-CREATOR WIFI".into()),
            }),
            pcie: PcieInventory {
                gen4_or_higher_x8_slot_count: 2,
            },
            probed_at: "2026-05-16T00:00:00Z".into(),
            thermals: Vec::new(),
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
            thermals: Vec::new(),
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

    // ----- run_export to file roundtrip (SD-R10) -------------------

    #[test]
    fn sdr10_run_export_to_file_writes_capabilities_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardware-capabilities.json");
        // run_export probes the test host's real /proc/*; we just
        // verify the file lands + parses + carries the load-bearing
        // top-level keys (schema_version + cpu + memory + gpu + pcie +
        // sain01_match).
        let _exit = run_export(Some(path.clone())).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // SD-R66 bumped to 1.3.0 alongside wasm_aot.ternary_kernel_hint
        // + SD-R64 derived cpu fields. Earlier bumps: SD-R30 1.0→1.2,
        // SD-R25 1.1 conceptual.
        assert_eq!(parsed["schema_version"], "1.3.0");
        for key in ["cpu", "memory", "gpu", "pcie", "sain01_match", "wasm_aot"] {
            assert!(
                !parsed[key].is_null(),
                "exported JSON must carry top-level {key}: {body}"
            );
        }
    }

    // ----- SD-R19 tune renderer -------------------------------------

    fn synth_caps() -> selfdef_hardware::HardwareCapabilities {
        let (snap, _) = synth();
        selfdef_hardware::derive_capabilities(&snap)
    }

    #[test]
    fn sdr19_render_tune_sh_format_emits_exports() {
        let caps = synth_caps();
        let out = render_tune(&caps, "sh").unwrap();
        // The synth box is Zen 5 with VNNI + BF16 → znver5 march.
        assert!(
            out.contains("export SELFDEF_HARDWARE_MARCH=znver5"),
            "got: {out}"
        );
        // CFLAGS exposes the canonical compile flags + zmm width.
        assert!(out.contains("-mavx512vnni"), "got: {out}");
        assert!(out.contains("-mavx512bf16"), "got: {out}");
        assert!(
            out.contains("-mprefer-vector-width=512"),
            "ZMM hint missing: {out}"
        );
        assert!(
            out.contains("source <("),
            "must include `source <(...)` hint"
        );
        assert!(out.contains("SELFDEF_HARDWARE_AVX512_VNNI=true"));
        assert!(out.contains("SELFDEF_HARDWARE_AVX512_BF16=true"));
    }

    #[test]
    fn sdr19_render_tune_env_file_format_has_no_export_prefix() {
        let caps = synth_caps();
        let out = render_tune(&caps, "env-file").unwrap();
        // systemd EnvironmentFile= rejects `export KEY=...` syntax.
        for line in out.lines() {
            assert!(
                !line.starts_with("export "),
                "env-file must not contain 'export', got: {line}"
            );
        }
        assert!(out.contains("SELFDEF_HARDWARE_MARCH=znver5"), "got: {out}");
    }

    #[test]
    fn sdr19_render_tune_make_format_emits_make_assignments() {
        let caps = synth_caps();
        let out = render_tune(&caps, "make").unwrap();
        assert!(
            out.contains("SELFDEF_HARDWARE_MARCH := znver5"),
            "got: {out}"
        );
        assert!(out.contains("-mprefer-vector-width=512"));
    }

    #[test]
    fn sdr19_render_tune_json_format_parses_and_carries_fields() {
        let caps = synth_caps();
        let out = render_tune(&caps, "json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        // SD-R29 bumped the JSON schema to 1.1.0.
        assert_eq!(parsed["schema_version"], "1.1.0");
        assert_eq!(parsed["march"], "znver5");
        assert_eq!(parsed["avx512_vnni"], true);
        assert_eq!(parsed["avx512_bf16"], true);
        assert_eq!(parsed["zmm_512_preferred"], true);
        assert!(parsed["cflags"].as_str().unwrap().contains("-mavx512vnni"));
        assert!(parsed["compile_flag_list"].is_array());
        // SD-R29: NVCC fields land (empty when no GPUs in synth_caps).
        assert!(parsed.get("nvcc_flags").is_some());
        assert!(parsed.get("cuda_arch_list").is_some());
        assert!(parsed["nvcc_gencode_list"].is_array());
    }

    /// SD-R29: synth a caps with the SAIN-01 dual-GPU pair and
    /// verify the tune output carries both `-gencode` entries +
    /// CUDA_ARCH_LIST="86;120" (semicolon sorted by BTreeSet).
    #[test]
    fn sdr29_render_tune_emits_per_gpu_nvcc_flags_for_sain01() {
        use selfdef_hardware::GpuDeviceCapabilities;
        let mut caps = synth_caps();
        caps.gpu.device_count = 2;
        caps.gpu.devices = vec![
            GpuDeviceCapabilities {
                device_node: Some(std::path::PathBuf::from("/dev/nvidia0")),
                model_hint: Some("NVIDIA RTX PRO 6000 Blackwell".into()),
                vram_bytes: Some(98 * 1024 * 1024 * 1024),
                power_draw_watts: Some(275),
                power_limit_watts: Some(600),
                ..Default::default()
            },
            GpuDeviceCapabilities {
                device_node: Some(std::path::PathBuf::from("/dev/nvidia1")),
                model_hint: Some("NVIDIA GeForce RTX 3090".into()),
                vram_bytes: Some(24 * 1024 * 1024 * 1024),
                power_draw_watts: Some(180),
                power_limit_watts: Some(350),
                ..Default::default()
            },
        ];

        let out = render_tune(&caps, "sh").unwrap();
        assert!(
            out.contains("SELFDEF_HARDWARE_NVCC_FLAGS="),
            "missing NVCC_FLAGS var: {out}"
        );
        assert!(
            out.contains("-gencode arch=compute_120,code=sm_120"),
            "missing Blackwell gencode: {out}"
        );
        assert!(
            out.contains("-gencode arch=compute_86,code=sm_86"),
            "missing Ampere gencode: {out}"
        );
        // cuda_arch_list is BTreeSet-sorted ascending: "86;120".
        assert!(
            out.contains("SELFDEF_HARDWARE_CUDA_ARCH_LIST=\"86;120\""),
            "missing arch list: {out}"
        );

        let out_json = render_tune(&caps, "json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out_json).unwrap();
        let list = parsed["nvcc_gencode_list"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(parsed["cuda_arch_list"], "86;120");
    }

    #[test]
    fn sdr19_render_tune_rejects_unknown_format() {
        let caps = synth_caps();
        let err = render_tune(&caps, "perl-mongers-format").unwrap_err();
        assert!(err.to_string().contains("unknown --format"), "got: {err}");
    }

    #[test]
    fn sdr19_render_tune_omits_zmm_hint_when_no_avx512() {
        // A non-AVX-512 host (e.g. an old Ryzen 1900X) should NOT get
        // -mprefer-vector-width=512 — it's a no-op or worse there.
        let mut snap_lo = synth().0;
        snap_lo.cpu.features.clear();
        snap_lo.cpu.features.insert("avx2".into());
        snap_lo.cpu.features.insert("sse4_2".into());
        snap_lo.cpu.avx512_present = false;
        snap_lo.cpu.avx512_vnni = false;
        snap_lo.cpu.avx512_bf16 = false;
        let caps_lo = selfdef_hardware::derive_capabilities(&snap_lo);
        let out = render_tune(&caps_lo, "sh").unwrap();
        assert!(
            !out.contains("-mprefer-vector-width=512"),
            "ZMM hint must not fire on non-AVX-512 host: {out}"
        );
    }

    #[test]
    fn sdr19_run_tune_writes_to_output_path_atomically() {
        // The function does a real selfdef_hardware::probe() — but
        // since run_tune writes whatever's there into the path, we
        // only assert the file exists + is non-empty + parses under
        // the requested format.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tune.env");
        let _exit = run_tune("env-file", Some(path.clone())).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("SELFDEF_HARDWARE_MARCH="));
        // Atomic write contract: no leftover .tmp suffix file.
        let tmp = dir.path().join("tune.env.tmp");
        assert!(!tmp.exists(), "tempfile should have been renamed away");
    }

    // ----- SD-R67 posture renderer ----------------------------------

    #[test]
    fn sdr67_render_posture_emits_all_six_lines() {
        let caps = synth_caps();
        let out = render_posture(&caps);
        for needle in [
            "── selfdef hardware-exploit posture (SD-R67) ──",
            "Sain01 verdict",
            "Target CPU (LLVM)",
            "Target features",
            "Ternary AOT capable",
            "ZMM INT8 lane capacity",
            "Kernel hint",
        ] {
            assert!(out.contains(needle), "missing {needle:?}: {out}");
        }
    }

    #[test]
    fn sdr67_render_posture_reports_sain01_values() {
        // synth_caps is the Zen 5 + VNNI + BF16 SAIN-01 shape.
        let caps = synth_caps();
        let out = render_posture(&caps);
        assert!(
            out.contains("yes (VNNI + (BF16 or FP16))"),
            "expected SAIN-01 ternary YES line: {out}"
        );
        assert!(
            out.contains("64 (master spec § 16 reading)"),
            "expected 64-lane reading + spec citation: {out}"
        );
        assert!(
            out.contains("VPDPBUSD"),
            "expected SAIN-01 kernel-hint: {out}"
        );
    }

    #[test]
    fn sdr67_render_posture_handles_minimal_host_cleanly() {
        // Build a minimal-host caps by hand: no AVX-512, no SIMD path.
        let snap = selfdef_hardware::HardwareSnapshot {
            cpu: selfdef_hardware::CpuInventory {
                vendor: "GenuineIntel".into(),
                model_name: "Old".into(),
                physical_cores: 4,
                logical_threads: 8,
                features: std::collections::HashSet::new(),
                avx512_present: false,
                avx512_vnni: false,
                avx512_bf16: false,
            },
            memory: selfdef_hardware::MemoryInventory {
                total_bytes: 8 * 1024 * 1024 * 1024,
            },
            gpus: vec![],
            motherboard: None,
            pcie: selfdef_hardware::PcieInventory::default(),
            probed_at: "2026-05-17T00:00:00Z".into(),
            thermals: vec![],
        };
        let caps = selfdef_hardware::derive_capabilities(&snap);
        let out = render_posture(&caps);
        assert!(
            out.contains("no — host lacks VNNI or small-FP path"),
            "expected minimal-host ternary NO line: {out}"
        );
        assert!(
            out.contains("0 (master spec § 16 reading)"),
            "expected 0-lane reading: {out}"
        );
        assert!(
            out.contains("(no INT8 SIMD path on this host)"),
            "expected no-SIMD kernel-hint fallback: {out}"
        );
    }
}
