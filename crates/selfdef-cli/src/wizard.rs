//! `selfdefctl wizard` — operator setup walkthrough (SD-R11).
//!
//! Operator directive: "assistant feel + clear path + options +
//! modules combo features and super-features." The wizard is the
//! first-time-operator entry point on a fresh selfdef install. It:
//!
//!   1. Probes hardware (selfdef-hardware → Sain01Match).
//!   2. Reports the verdict and recommends a `deployment.target`.
//!   3. Shows the operator EXACTLY what config block to add to
//!      /etc/selfdef/selfdef.toml — operator copy-pastes; no magic.
//!   4. Surfaces the next-step verbs (init, doctor, hardware export,
//!      modules apply).
//!
//! Pure-read: never writes config. Operator authority always wins;
//! the wizard advises, never decides. Matches the existing `init
//! checklist` philosophy.
//!
//! CLI:
//!   selfdefctl wizard            — interactive-feel walkthrough
//!   selfdefctl wizard --json     — machine-readable recommendations

use anyhow::Result;
use selfdef_hardware::{HardwareCapabilities, Sain01Verdict};

/// `selfdefctl wizard` human-readable rendering.
pub(crate) fn run_human() -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let caps = selfdef_hardware::derive_capabilities(&snap);
    let rec = recommend(&caps);
    print!("{}", render_human(&caps, &rec));
    Ok(verdict_exit(caps.sain01_match.overall))
}

/// `selfdefctl wizard --json` machine-readable rendering.
pub(crate) fn run_json() -> Result<i32> {
    let snap = selfdef_hardware::probe()?;
    let caps = selfdef_hardware::derive_capabilities(&snap);
    let rec = recommend(&caps);
    let doc = serde_json::json!({
        "capabilities": caps,
        "recommendation": rec,
    });
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(verdict_exit(caps.sain01_match.overall))
}

fn verdict_exit(v: Sain01Verdict) -> i32 {
    match v {
        Sain01Verdict::FullMatch | Sain01Verdict::PartialMatch => 0,
        Sain01Verdict::NoMatch => 2,
    }
}

/// Wizard recommendation — what the operator should set in
/// selfdef.toml + which next-step verbs to run.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WizardRecommendation {
    pub recommended_target: &'static str,
    pub recommended_sain01_strict: bool,
    pub recommended_hardware_capabilities_path: &'static str,
    pub recommended_hardware_metrics_path: Option<&'static str>,
    pub config_snippet: String,
    pub next_steps: Vec<&'static str>,
    pub rationale: String,
}

/// SD-R11: derive the operator-facing recommendation from a
/// capabilities snapshot. Pure function — tests pin every branch.
pub(crate) fn recommend(caps: &HardwareCapabilities) -> WizardRecommendation {
    let on_sain01_hardware = matches!(
        caps.sain01_match.overall,
        Sain01Verdict::FullMatch | Sain01Verdict::PartialMatch
    );
    // Recommend `target = sain01` only when at least the CPU + memory
    // dimensions hit (the absolute minimum for SAIN-01 — without
    // AVX-512 + 256 GB, target = sain01 makes no operational sense).
    let recommended_target = if caps.cpu.avx512vnni && caps.memory.at_least_256gb {
        "sain01"
    } else {
        "generic"
    };
    // strict mode is recommended only when ALL dimensions hit
    // (FullMatch — operator can rely on the SAIN-01 invariants).
    let recommended_sain01_strict = matches!(caps.sain01_match.overall, Sain01Verdict::FullMatch);
    // Capabilities export defaults to the canonical path consumed by
    // sovereign-os wasm-aot + build-bitnet (R167 + R168).
    let recommended_hardware_capabilities_path = "/var/lib/selfdef/hardware-capabilities.json";
    // Metrics path recommended only when on SAIN-01 (drift detection
    // is most valuable when the operator claims SAIN-01 hardware).
    let recommended_hardware_metrics_path = if on_sain01_hardware {
        Some("/var/lib/node_exporter/textfile_collector/selfdef-hardware.prom")
    } else {
        None
    };

    let mut rationale = String::new();
    use std::fmt::Write as _;
    write!(
        &mut rationale,
        "Hardware verdict: {:?}. ",
        caps.sain01_match.overall
    )
    .unwrap();
    if recommended_target == "sain01" {
        write!(
            &mut rationale,
            "CPU has AVX-512 VNNI and memory ≥256 GiB → SAIN-01-class. "
        )
        .unwrap();
    } else if !caps.cpu.avx512vnni {
        write!(
            &mut rationale,
            "CPU lacks AVX-512 VNNI → can't run the master-spec § 16 \
             ternary-inference fast path; staying on generic. "
        )
        .unwrap();
    } else if !caps.memory.at_least_256gb {
        write!(
            &mut rationale,
            "Memory below 256 GiB → can't host the Oracle Core deep \
             reasoning tier; staying on generic. "
        )
        .unwrap();
    }
    if recommended_sain01_strict {
        write!(
            &mut rationale,
            "FullMatch verdict → strict mode safe (daemon will refuse \
             to start on hardware drift). "
        )
        .unwrap();
    }

    // Build the config snippet. The wizard NEVER writes; operator
    // copy-pastes. Comments explain each knob so the operator learns.
    let mut snippet = String::new();
    writeln!(
        &mut snippet,
        "# Add to /etc/selfdef/selfdef.toml (selfdefctl wizard, SD-R11):"
    )
    .unwrap();
    writeln!(&mut snippet, "[deployment]").unwrap();
    writeln!(&mut snippet, "target = \"{recommended_target}\"").unwrap();
    if recommended_target == "sain01" {
        writeln!(
            &mut snippet,
            "# Strict mode: daemon refuses to start at non-FullMatch (recommended once verified)."
        )
        .unwrap();
        writeln!(&mut snippet, "sain01_strict = {recommended_sain01_strict}").unwrap();
    }
    writeln!(
        &mut snippet,
        "# Export hardware capabilities JSON (consumed by sovereign-os wasm-aot + build-bitnet):"
    )
    .unwrap();
    writeln!(
        &mut snippet,
        "hardware_capabilities_path = \"{recommended_hardware_capabilities_path}\""
    )
    .unwrap();
    if let Some(p) = recommended_hardware_metrics_path {
        writeln!(
            &mut snippet,
            "# Layer B metrics for Prometheus textfile collector:"
        )
        .unwrap();
        writeln!(&mut snippet, "hardware_metrics_path = \"{p}\"").unwrap();
    }

    let mut next_steps = vec![
        "sudo selfdefctl init config",
        "sudo selfdefctl init modules",
    ];
    if recommended_target == "sain01" {
        next_steps.push(
            "sudo selfdefctl hardware export --output /var/lib/selfdef/hardware-capabilities.json",
        );
        next_steps.push("# (sovereign-os wasm-aot will now read this file automatically)");
    }
    next_steps.extend([
        "sudo systemctl enable --now selfdefd",
        "sudo selfdefctl modules apply",
        "selfdefctl doctor",
    ]);

    WizardRecommendation {
        recommended_target,
        recommended_sain01_strict,
        recommended_hardware_capabilities_path,
        recommended_hardware_metrics_path,
        config_snippet: snippet,
        next_steps,
        rationale,
    }
}

pub(crate) fn render_human(caps: &HardwareCapabilities, rec: &WizardRecommendation) -> String {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(
        &mut buf,
        "# selfdefctl wizard (SD-R11) — first-time setup walkthrough"
    )
    .unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Step 1: Hardware probe").unwrap();
    writeln!(
        &mut buf,
        "  CPU:          {} ({}, {} cores / {} threads)",
        caps.cpu.model_name, caps.cpu.vendor, caps.cpu.physical_cores, caps.cpu.logical_threads
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  AVX-512 VNNI: {} (master spec § 16 fast path)",
        caps.cpu.avx512vnni
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  AVX-512 BF16: {} (BitNet ternary acceleration)",
        caps.cpu.avx512bf16
    )
    .unwrap();
    let mem_gib = (caps.memory.total_bytes as f64) / (1024.0 * 1024.0 * 1024.0);
    writeln!(
        &mut buf,
        "  Memory:       {mem_gib:.1} GiB ({})",
        if caps.memory.at_least_256gb {
            "≥256 GiB"
        } else {
            "<256 GiB"
        }
    )
    .unwrap();
    writeln!(
        &mut buf,
        "  GPUs:         {} device(s)",
        caps.gpu.device_count
    )
    .unwrap();
    writeln!(&mut buf, "  Verdict:      {:?}", caps.sain01_match.overall).unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Step 2: Recommendation").unwrap();
    writeln!(
        &mut buf,
        "  → deployment.target = \"{}\"",
        rec.recommended_target
    )
    .unwrap();
    if rec.recommended_sain01_strict {
        writeln!(
            &mut buf,
            "  → sain01_strict = true (daemon refuses non-FullMatch)"
        )
        .unwrap();
    }
    writeln!(
        &mut buf,
        "  → recommended -march = {}",
        caps.cpu.recommended_march
    )
    .unwrap();
    writeln!(&mut buf, "  rationale: {}", rec.rationale.trim_end()).unwrap();
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Step 3: Copy-paste config").unwrap();
    for line in rec.config_snippet.lines() {
        writeln!(&mut buf, "  {line}").unwrap();
    }
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "## Step 4: Next steps").unwrap();
    for s in &rec.next_steps {
        writeln!(&mut buf, "  $ {s}").unwrap();
    }
    writeln!(&mut buf).unwrap();
    writeln!(&mut buf, "Cross-repo bridge: when you set").unwrap();
    writeln!(
        &mut buf,
        "  hardware_capabilities_path = {:?}",
        rec.recommended_hardware_capabilities_path
    )
    .unwrap();
    writeln!(
        &mut buf,
        "sovereign-os's scripts/pulse/wasm-aot.sh + build-bitnet.sh read"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "the file automatically and use this host's actual AVX-512"
    )
    .unwrap();
    writeln!(
        &mut buf,
        "feature set when compiling — no manual flag-pinning needed."
    )
    .unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_hardware::{
        CpuCapabilities, GpuCapabilities, HardwareCapabilities, MemoryCapabilities,
        PcieCapabilities, Sain01Match, Sain01Verdict,
    };

    fn synth(
        has_vnni: bool,
        has_bf16: bool,
        memory_at_least_256gb: bool,
        gpu_count: u32,
        pcie_dual_x8: bool,
        verdict: Sain01Verdict,
    ) -> HardwareCapabilities {
        HardwareCapabilities {
            schema_version: "1.0.0".into(),
            probed_at: "2026-05-16T00:00:00Z".into(),
            host_tag: None,
            cpu: CpuCapabilities {
                vendor: "AuthenticAMD".into(),
                model_name: "test cpu".into(),
                physical_cores: 12,
                logical_threads: 24,
                avx512vnni: has_vnni,
                avx512bf16: has_bf16,
                recommended_march: if has_vnni {
                    "znver5".into()
                } else {
                    "native".into()
                },
                ..CpuCapabilities::default()
            },
            memory: MemoryCapabilities {
                total_bytes: if memory_at_least_256gb {
                    256 * 1024 * 1024 * 1024
                } else {
                    32 * 1024 * 1024 * 1024
                },
                at_least_256gb: memory_at_least_256gb,
                at_least_512gb: false,
            },
            gpu: GpuCapabilities {
                device_count: gpu_count,
                device_nodes: (0..gpu_count)
                    .map(|i| std::path::PathBuf::from(format!("/dev/nvidia{i}")))
                    .collect(),
                devices: Vec::new(),
            },
            pcie: PcieCapabilities {
                gen4_or_higher_x8_slot_count: if pcie_dual_x8 { 2 } else { 0 },
                dual_x8_present: pcie_dual_x8,
            },
            sain01_match: Sain01Match {
                overall: verdict,
                cpu_avx512_vnni: has_vnni,
                cpu_avx512_bf16: has_bf16,
                memory_at_least_256gb,
                gpu_count_at_least_2: gpu_count >= 2,
                motherboard_proart_x870e: None,
                pcie_dual_x8_present: pcie_dual_x8,
            },
            wasm_aot: Default::default(),
        }
    }

    #[test]
    fn sdr11_recommend_sain01_target_when_avx512_and_256gb() {
        let caps = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        let r = recommend(&caps);
        assert_eq!(r.recommended_target, "sain01");
    }

    #[test]
    fn sdr11_recommend_generic_without_avx512_vnni() {
        let caps = synth(false, false, true, 2, true, Sain01Verdict::PartialMatch);
        let r = recommend(&caps);
        assert_eq!(r.recommended_target, "generic");
        assert!(r.rationale.contains("AVX-512 VNNI"));
    }

    #[test]
    fn sdr11_recommend_generic_with_insufficient_memory() {
        let caps = synth(true, true, false, 2, true, Sain01Verdict::PartialMatch);
        let r = recommend(&caps);
        assert_eq!(r.recommended_target, "generic");
        assert!(r.rationale.contains("256 GiB"));
    }

    #[test]
    fn sdr11_recommend_strict_only_on_full_match() {
        let caps_full = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        assert!(recommend(&caps_full).recommended_sain01_strict);

        let caps_partial = synth(true, false, true, 1, false, Sain01Verdict::PartialMatch);
        assert!(!recommend(&caps_partial).recommended_sain01_strict);

        let caps_none = synth(false, false, false, 0, false, Sain01Verdict::NoMatch);
        assert!(!recommend(&caps_none).recommended_sain01_strict);
    }

    #[test]
    fn sdr11_metrics_path_recommended_only_on_sain01_class_hw() {
        let caps_full = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        assert!(
            recommend(&caps_full)
                .recommended_hardware_metrics_path
                .is_some()
        );

        let caps_none = synth(false, false, false, 0, false, Sain01Verdict::NoMatch);
        assert!(
            recommend(&caps_none)
                .recommended_hardware_metrics_path
                .is_none()
        );
    }

    #[test]
    fn sdr11_capabilities_path_always_recommended() {
        // Even on generic, capabilities export is useful for fleet
        // aggregators — the recommendation is always the canonical path.
        let caps_none = synth(false, false, false, 0, false, Sain01Verdict::NoMatch);
        let r = recommend(&caps_none);
        assert_eq!(
            r.recommended_hardware_capabilities_path,
            "/var/lib/selfdef/hardware-capabilities.json"
        );
    }

    #[test]
    fn sdr11_config_snippet_includes_target_and_path() {
        let caps = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        let r = recommend(&caps);
        assert!(r.config_snippet.contains("target = \"sain01\""));
        assert!(r.config_snippet.contains("hardware_capabilities_path"));
        assert!(r.config_snippet.contains("sain01_strict = true"));
        assert!(r.config_snippet.contains("[deployment]"));
    }

    #[test]
    fn sdr11_next_steps_include_export_when_target_sain01() {
        let caps = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        let r = recommend(&caps);
        assert!(r.next_steps.iter().any(|s| s.contains("hardware export")));
    }

    #[test]
    fn sdr11_next_steps_omit_export_on_generic() {
        let caps = synth(false, false, false, 0, false, Sain01Verdict::NoMatch);
        let r = recommend(&caps);
        assert!(!r.next_steps.iter().any(|s| s.contains("hardware export")));
    }

    #[test]
    fn sdr11_render_human_covers_all_steps() {
        let caps = synth(true, true, true, 2, true, Sain01Verdict::FullMatch);
        let r = recommend(&caps);
        let out = render_human(&caps, &r);
        for marker in [
            "Step 1: Hardware probe",
            "Step 2: Recommendation",
            "Step 3: Copy-paste config",
            "Step 4: Next steps",
            "AVX-512 VNNI",
            "FullMatch",
            "Cross-repo bridge",
        ] {
            assert!(
                out.contains(marker),
                "wizard render missing {marker}: {out}"
            );
        }
    }
}
