//! `selfdef-hardware-requirements` — per-module `[requires_hardware]`
//! gate evaluator. SDD-057 step 3 — type + impl moved from
//! `crates/selfdef-cli/src/modules.rs` lines 185-613.
//!
//! Callers compose:
//!   1. Parse module.toml — `[requires_hardware]` block deserializes
//!      directly into [`HardwareRequirements`]
//!   2. Probe hardware — `selfdef_hardware::probe` →
//!      `HardwareCapabilities`
//!   3. Evaluate — [`HardwareRequirements::evaluate`] returns Ok iff
//!      every predicate passes; Err with a list of unmet predicate
//!      descriptions otherwise
//!
//! Both selfdef-cli (modules apply / modules install-options) and
//! selfdef-api (`/v1/modules/install-options`) consume this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::Deserialize;

/// Schema version pinned to the moved shape. Bumps when the
/// on-disk module.toml `[requires_hardware]` schema changes.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// A module's `[requires_hardware]` table declares minimum host
/// hardware. The apply path skips modules that don't meet the bar
/// with a clear log line; operators can override with
/// `--ignore-hardware` (future round) or by editing the module manifest.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct HardwareRequirements {
    /// When set, requires `cpu.avx512_vnni = true` in the host's
    /// HardwareCapabilities. Match for ternary-inference fast path
    /// modules (master spec § 16).
    #[serde(default)]
    pub avx512_vnni: bool,

    /// When set, requires `cpu.avx512_bf16 = true`. Match for
    /// BitNet acceleration modules.
    #[serde(default)]
    pub avx512_bf16: bool,

    /// Minimum memory in GiB.
    #[serde(default)]
    pub memory_gib_min: u64,

    /// Minimum count of NVIDIA GPUs. 0 disables the gate.
    #[serde(default)]
    pub gpu_count_min: u32,

    /// SD-R26: minimum VRAM (GiB) on AT LEAST ONE GPU. Lets a module
    /// declare "I need to fit a model that takes 80 GiB" — passes
    /// when any GPU in HardwareCapabilities.gpu.devices reports
    /// vram_bytes ≥ this. 0 disables the gate.
    ///
    /// Pairs naturally with `gpu_count_min`: combined "needs 2 GPUs
    /// AND at least one with 80 GiB VRAM" lands inference modules
    /// on the SAIN-01 dual-GPU rig (RTX PRO 6000 → 98 GiB).
    #[serde(default)]
    pub gpu_vram_gib_min: u64,

    /// SD-R51 (closes SDD-019 T-1): ALL-semantics companion to
    /// `gpu_vram_gib_min`. Every GPU in
    /// HardwareCapabilities.gpu.devices must report vram_bytes ≥
    /// this. Use case: fleet-uniformity modules (e.g. a tensor-
    /// parallel inference module that splits a model across BOTH
    /// GPUs and needs each card to host an equal slice). 0 disables.
    ///
    /// Fail-closed when the per-device list is empty (no probe data
    /// → can't prove ALL GPUs satisfy → fail).
    #[serde(default)]
    pub gpu_vram_gib_each_min: u64,

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
    pub gpu_power_headroom_watts_min: u32,

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
    pub wasm_aot_features_required: String,

    /// Required Sain01Match verdict, when set:
    /// `"FullMatch"` / `"PartialMatch"` / `"NoMatch"` (the last
    /// would be weird — operator should rarely use it).
    #[serde(default)]
    pub sain01_verdict_min: String,

    /// SD-R64: ternary AOT readiness predicate. When `true`, the
    /// module requires the CPU to expose the bitnet.cpp / Wasm-AOT
    /// ternary fast path (AVX-512 VNNI + (BF16 or FP16)). Operators
    /// use this to gate 1-bit / ternary inference modules onto hosts
    /// that can actually run them at single-cycle ZMM-register lane
    /// width per master spec § 16. Default `false` disables.
    #[serde(default)]
    pub ternary_aot_capable_required: bool,

    /// SD-R64: minimum widest INT8 dot-product lane count the CPU
    /// must expose (master spec § 16: a single 512-bit ZMM register
    /// holds 64 INT8 lanes via VPDPBUSD). 0 disables the gate. Set
    /// to 64 to require the AVX-512 VNNI hot path; 32 accepts AVX2
    /// fallback; 16 accepts SSSE3 fallback. Operator-readable
    /// hardware-exploitation knob.
    #[serde(default)]
    pub zmm_int8_lanes_min: u32,

    /// SD-R68: generalized cpuinfo-flag gate. Comma-separated list of
    /// raw cpuinfo feature names that MUST be present on the host.
    /// Empty string disables. Operators use this to gate modules on
    /// rare ISA flags WITHOUT selfdef having to add a typed predicate
    /// per flag (the long tail: rdpid, sha_ni, avx512_vbmi2, ...).
    ///
    /// Examples:
    ///   host_features_required = "avx512_vbmi2"
    ///   host_features_required = "avx512_vbmi2,rdpid,sha_ni"
    ///
    /// Distinct from `wasm_aot_features_required` which uses LLVM
    /// `+feature` syntax against the wasmtime target_features string.
    /// This predicate reads raw cpuinfo flags directly via the
    /// SD-R68 `cpu.extended_features` array.
    #[serde(default)]
    pub host_features_required: String,

    /// SD-R77 (SDD-024 X-1): composable OR-predicates. Root-level
    /// predicates above stay AND-composed. Each entry in `any_of`
    /// is a nested HardwareRequirements block; the module passes
    /// iff the root predicates pass AND at least ONE any_of block
    /// passes.
    ///
    /// Operator syntax in module.toml:
    ///
    /// ```toml
    /// [requires_hardware]
    /// memory_gib_min = 8           # root AND-predicate
    ///
    /// [[requires_hardware.any_of]]
    /// avx512_vnni = true           # SAIN-01 path
    /// ternary_aot_capable_required = true
    ///
    /// [[requires_hardware.any_of]]
    /// gpu_count_min = 1            # GPU fallback path
    /// gpu_vram_gib_min = 24
    /// ```
    ///
    /// Empty `any_of` array = no OR-constraint (the original
    /// AND-only behavior; default).
    #[serde(default)]
    pub any_of: Vec<HardwareRequirements>,
}

impl HardwareRequirements {
    /// Returns Ok iff every set requirement passes; Err with a list
    /// of unmet predicates otherwise. Thin wrapper over
    /// [`Self::evaluate_resolved`] for callers that don't need the
    /// any_of branch index (SD-R79 / SDD-025 Y-1).
    pub fn evaluate(
        &self,
        caps: &selfdef_hardware::HardwareCapabilities,
    ) -> Result<(), Vec<String>> {
        self.evaluate_resolved(caps).map(|_| ())
    }

    /// SD-R79 (SDD-025 Y-1): full evaluation that returns WHICH
    /// `any_of` branch matched.
    ///
    /// - `Ok(None)` = root-only pass (no any_of branches involved).
    /// - `Ok(Some(idx))` = passed via the `idx`-th any_of branch
    ///   (after every root predicate also passed).
    /// - `Err` = unmet predicate list (same operator-readable format
    ///   as before).
    ///
    /// The apply path uses the returned branch index to emit a
    /// `# SD-R79: module X resolved via any_of[N]` stderr line so
    /// operators see which OR-path actually exercised on this host.
    pub fn evaluate_resolved(
        &self,
        caps: &selfdef_hardware::HardwareCapabilities,
    ) -> Result<Option<usize>, Vec<String>> {
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
        if self.gpu_vram_gib_each_min > 0 {
            // SD-R51 ALL-semantics. Every GPU must report
            // vram_bytes ≥ this. Empty per-device list → fail (we
            // can't prove ALL are big enough).
            let want_bytes = self
                .gpu_vram_gib_each_min
                .saturating_mul(1024 * 1024 * 1024);
            let all_big_enough = !caps.gpu.devices.is_empty()
                && caps
                    .gpu
                    .devices
                    .iter()
                    .all(|d| d.vram_bytes.is_some_and(|b| b >= want_bytes));
            if !all_big_enough {
                let worst_gib = caps
                    .gpu
                    .devices
                    .iter()
                    .filter_map(|d| d.vram_bytes)
                    .min()
                    .map(|b| b / (1024 * 1024 * 1024))
                    .unwrap_or(0);
                unmet.push(format!(
                    "gpu_vram_gib_each_min = {} (host worst is {} GiB across {} GPU(s))",
                    self.gpu_vram_gib_each_min,
                    worst_gib,
                    caps.gpu.devices.len()
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
        // SD-R64: ternary AOT readiness predicate. Operator declares
        // "I need the bitnet.cpp hot path" and the gate evaluates
        // against the SD-R64 derived flag on CpuCapabilities.
        if self.ternary_aot_capable_required && !caps.cpu.ternary_aot_capable {
            unmet.push(
                "ternary_aot_capable required (host lacks AVX-512 VNNI \
                 + (BF16 or FP16) — bitnet.cpp ternary hot path \
                 unavailable per master spec § 16)"
                    .into(),
            );
        }
        // SD-R64: ZMM INT8 lane width gate. Operator declares "I need
        // ≥N INT8 lanes in the widest dispatch" and the gate evaluates
        // against the SD-R64 derived lane count.
        if self.zmm_int8_lanes_min > 0 && caps.cpu.zmm_int8_lane_capacity < self.zmm_int8_lanes_min
        {
            unmet.push(format!(
                "zmm_int8_lanes_min = {} (host max = {})",
                self.zmm_int8_lanes_min, caps.cpu.zmm_int8_lane_capacity,
            ));
        }
        // SD-R68: generalized cpuinfo-flag gate against the host's
        // SD-R68 extended_features long-tail surface. Comma-separated
        // syntax matches wasm_aot_features_required's shape but
        // operates on raw cpuinfo names (no `+` prefix).
        if !self.host_features_required.is_empty() {
            let actual: std::collections::HashSet<&str> = caps
                .cpu
                .extended_features
                .iter()
                .map(String::as_str)
                .collect();
            let missing: Vec<&str> = self
                .host_features_required
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter(|f| !actual.contains(f))
                .collect();
            if !missing.is_empty() {
                unmet.push(format!(
                    "host_features_required = {:?} (host missing: {})",
                    self.host_features_required,
                    missing.join(",")
                ));
            }
        }
        // SD-R77 (SDD-024 X-1): OR-composition. After the root
        // predicates have been collected, evaluate `any_of` — module
        // passes iff at least ONE inner block fully evaluates clean.
        // Empty `any_of` = no OR-constraint (pass-through).
        // SD-R79 (SDD-025 Y-1): record WHICH branch matched so the
        // apply path can surface it as operator-visible observability.
        let mut matched_branch: Option<usize> = None;
        if !self.any_of.is_empty() {
            let mut per_branch_failures: Vec<Vec<String>> = Vec::new();
            for (i, branch) in self.any_of.iter().enumerate() {
                // evaluate() (not evaluate_resolved()) — flat
                // semantics inside any_of branches keeps the
                // operator-facing model simple (no nested branch
                // indices on stderr).
                match branch.evaluate(caps) {
                    Ok(()) => {
                        matched_branch = Some(i);
                        break;
                    }
                    Err(branch_unmet) => per_branch_failures.push(branch_unmet),
                }
            }
            if matched_branch.is_none() {
                unmet.push(format!(
                    "any_of: NONE of {} OR-branch(es) passed",
                    self.any_of.len()
                ));
                for (i, branch_unmet) in per_branch_failures.iter().enumerate() {
                    unmet.push(format!("  any_of[{}]: {}", i, branch_unmet.join(" | ")));
                }
            }
        }
        if unmet.is_empty() {
            Ok(matched_branch)
        } else {
            Err(unmet)
        }
    }

    /// Returns true if NO requirement is set (the manifest has no
    /// `[requires_hardware]` block, or it has only zero/false fields).
    /// Used to skip the probe entirely on hardware-agnostic modules.
    pub fn is_empty(&self) -> bool {
        !self.avx512_vnni
            && !self.avx512_bf16
            && self.memory_gib_min == 0
            && self.gpu_count_min == 0
            && self.gpu_vram_gib_min == 0
            && self.gpu_vram_gib_each_min == 0
            && self.gpu_power_headroom_watts_min == 0
            && self.wasm_aot_features_required.is_empty()
            && self.sain01_verdict_min.is_empty()
            && !self.ternary_aot_capable_required
            && self.zmm_int8_lanes_min == 0
            && self.host_features_required.is_empty()
            // SD-R77 — any_of is part of the gate surface.
            && self.any_of.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_present() {
        assert!(SCHEMA_VERSION.starts_with("1."));
    }

    // Note: HardwareCapabilities doesn't impl Default — caller-side
    // tests construct one via selfdef_hardware::derive_capabilities
    // from a probed HardwareSnapshot. The integration tests for the
    // gate predicates live in selfdef-cli's modules.rs test module
    // for now; SDD-057 step 6 will port a subset of those here once
    // a HardwareCapabilities builder is available.

    #[test]
    fn round_trips_through_toml() {
        // module.toml uses [requires_hardware] as a TOML subtable;
        // verify the deserialize path keeps working from the new
        // crate's location.
        let body = r#"
            avx512_bf16 = true
            memory_gib_min = 16
            gpu_count_min = 1
        "#;
        let req: HardwareRequirements = toml::from_str(body).unwrap();
        assert!(req.avx512_bf16);
        assert_eq!(req.memory_gib_min, 16);
        assert_eq!(req.gpu_count_min, 1);
    }
}
