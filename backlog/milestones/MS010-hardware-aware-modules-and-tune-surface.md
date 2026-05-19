# MS010 — Hardware-aware modules + tune surface

> Parent: `backlog/milestones/INDEX.md` row MS010.
> Source: `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` (244 lines, SD-R14..R32 arc; 5 locked contracts C-1..C-5; 13 decisions D-1..D-13; cross-repo bridge selfdef SD-R14..R32 → sovereign-os R170..R181) + `crates/selfdef-hardware/` + `modules/hardware-tune-cache/` (module.toml + install/{apply,check,uninstall}.sh) + SDD-017 (hardware inventory). All entries below extract verbatim from these source files. No invention.

> **AVX++ canon update — 2026-05-19**: this milestone is affected by backward-sweep redefinition(s) — Profiles memory-lens-to-authority-gate (BREAKING). See sovereign-os M061 for canonical pinning (commit 6f07dca on sovereign-os main). R-rows below are interpreted under the canonical later definitions per operator standing direction "layered: new direction ON TOP OF prior direction — never discarded".


## Epics (E0101–E0110)

| Epic ID | Phrase | Source |
|---|---|---|
| E0101 | SDD-018 problem statement — modules apply blindly / no dry-run gate / build pipeline lacks single canonical tune source / observability lacks continuous thermal envelope | SDD-018 § Problem |
| E0102 | C-1 [requires_hardware] block in module.toml (SD-R14) — 5-predicate AND-ed gate (avx512_vnni / avx512_bf16 / memory_gib_min / gpu_count_min / sain01_verdict_min) + SD-R26 add (gpu_vram_gib_min / gpu_power_headroom_watts_min) + SD-R32 add (wasm_aot_features_required) | SDD-018 C-1 + SD-R26 + SD-R32 |
| E0103 | C-2 `selfdefctl modules check-hardware` (SD-R15) — dry-run; human + `--json`; exit-0-always; cross-repo Python mirror at sovereign-os R170 | SDD-018 C-2 + cross-repo R170/R177/R181 |
| E0104 | C-3 `selfdefctl hardware thermals` (SD-R17) — hwmon + nvidia-smi; 2-column human + `--json`; Layer-B metric `sovereign_os_selfdef_hardware_thermal_celsius{sensor}` | SDD-018 C-3 |
| E0105 | C-4 `selfdefctl hardware tune` (SD-R19) — 4 formats (sh / env-file / make / json) + 5 emitted vars (MARCH / CFLAGS / KCFLAGS / AVX512_VNNI / AVX512_BF16); atomic write via tempfile+rename | SDD-018 C-4 + SD-R29 NVCC -gencode + SD-R30 wasm_aot block |
| E0106 | C-5 `selfdefctl doctor` hardware.thermals row (SD-R9 / SD-R18) — Ok / Skipped / Warn with target-aware severity | SDD-018 C-5 |
| E0107 | SD-R24..R32 cycle-2 extensions — GPU power telemetry + per-GPU detail + new predicates + HOST SNAPSHOT block + bitnet-gpu-inference demonstrator + NVCC -gencode + wasm_aot block + Layer-B wasm-AOT metrics + wasm-AOT feature predicate | SDD-018 C-1 amendments + decisions D-7..D-13 + cross-repo R177..R181 |
| E0108 | Decision log D-1..D-13 — apply-time gate / skip-not-fail / exit-0-always / single-I/O thermal probe / thermal-classification-elsewhere / ZMM-hint-AVX-512-gated / GPU-power-Option-fail-soft / gpu.devices-index-aligned / vram-max-semantics / power-headroom-sum-fail-closed / NVCC-dedupe-ascending / wasm_aot-AVX-512-first / wasm_aot-strict-AND | SDD-018 § Decision log |
| E0109 | Cross-repo bridge — every selfdef contract has a sovereign-os consumer with documented fallback (R170 falls back to sain01-match.py; R172 reads /sys/class/hwmon directly; R173 falls back to capabilities-JSON parsing then native-march) | SDD-018 § Cross-repo bridge + § non-goals |
| E0110 | Non-goals + deferred — AMD ROCm thermal; per-NUMA-node thermal; predictive thermal modeling; daemon-internal unsafe-code paths (workspace remains forbid-unsafe-code); hardware-aware POLICY scope (TracingPolicy); selfdef-side periodic thermal probe (sovereign-os R172 owns it) | SDD-018 § Non-goals + § Out of scope |

## Modules (M00239–M00264)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00239 | `crates/selfdef-hardware` — host snapshot + capabilities + tune + thermals crate | `crates/selfdef-hardware/src/lib.rs` | E0101 |
| M00240 | `modules/hardware-tune-cache` — first reference module consuming SD-R19 tune surface | `modules/hardware-tune-cache/` | E0105 |
| M00241 | hardware-tune-cache install/apply.sh — apply tune cache to host build pipeline | `modules/hardware-tune-cache/install/apply.sh` | M00240 |
| M00242 | hardware-tune-cache install/check.sh — verify tune cache present + current | `modules/hardware-tune-cache/install/check.sh` | M00240 |
| M00243 | hardware-tune-cache install/uninstall.sh — remove tune cache cleanly | `modules/hardware-tune-cache/install/uninstall.sh` | M00240 |
| M00244 | hardware-tune-cache module.toml manifest — declares [requires_hardware] gate | `modules/hardware-tune-cache/module.toml` | E0102 |
| M00245 | Predicate avx512_vnni (bool, default false) — SD-R14 | SDD-018 C-1 | E0102 |
| M00246 | Predicate avx512_bf16 (bool, default false) — SD-R14 | SDD-018 C-1 | E0102 |
| M00247 | Predicate memory_gib_min (u64, default 0 disabled) — SD-R14 | SDD-018 C-1 | E0102 |
| M00248 | Predicate gpu_count_min (u32, default 0 disabled) — SD-R14 | SDD-018 C-1 | E0102 |
| M00249 | Predicate sain01_verdict_min (FullMatch/PartialMatch/NoMatch, default "") — SD-R14 | SDD-018 C-1 | E0102 |
| M00250 | Predicate gpu_vram_gib_min (max semantics, ANY-GPU-meets-bar) — SD-R26 + D-9 | SDD-018 C-1 + D-9 | E0107 |
| M00251 | Predicate gpu_power_headroom_watts_min (SUM-across-GPUs, fail-closed on partial telemetry) — SD-R26 + D-10 | SDD-018 C-1 + D-10 | E0107 |
| M00252 | Predicate wasm_aot_features_required (strict-AND set semantics) — SD-R32 + D-13 | SDD-018 C-1 + D-13 | E0107 |
| M00253 | selfdefctl modules check-hardware (human format) — WOULD APPLY (n) + WOULD SKIP (n) with predicate citations | SDD-018 C-2 | E0103 |
| M00254 | selfdefctl modules check-hardware --json — probe_ok / total / kept[] / skipped[] | SDD-018 C-2 | E0103 |
| M00255 | selfdefctl hardware thermals — hwmon parsing (millideg → °C) + nvidia-smi GPU query | SDD-018 C-3 | E0104 |
| M00256 | ThermalReading.source label format — `<hwmon-name>/<label>` OR `<hwmon-name>/temp<idx>` OR `nvidia-gpu-<index>` | SDD-018 C-3 | E0104 |
| M00257 | Layer-B metric `sovereign_os_selfdef_hardware_thermal_celsius{sensor}` — emitted only on non-empty thermals | SDD-018 C-3 | E0104 |
| M00258 | selfdefctl hardware tune --format sh (default) — `export KEY=value` lines | SDD-018 C-4 | E0105 |
| M00259 | selfdefctl hardware tune --format env-file — `KEY=value` without export (systemd EnvironmentFile-compatible) | SDD-018 C-4 | E0105 |
| M00260 | selfdefctl hardware tune --format make — `KEY := value` for Makefile include | SDD-018 C-4 | E0105 |
| M00261 | selfdefctl hardware tune --format json — march / cflags / kcflags / avx512_* / compile_flag_list / zmm_512_preferred + schema_version | SDD-018 C-4 | E0105 |
| M00262 | NVCC -gencode list (SD-R29) — deduplicated + ordered by first appearance in gpu.devices; cuda_arch_list ascending-numeric matching CMAKE_CUDA_ARCHITECTURES | SDD-018 SD-R29 + D-11 | E0107 |
| M00263 | wasm_aot block (SD-R30) — target_triple / target_cpu / target_features (LLVM `+feature`, AVX-512 first, AVX2+FMA fallback) | SDD-018 SD-R30 + D-12 | E0107 |
| M00264 | doctor row hardware.thermals — Ok (≥1 sensor) / Skipped (no sensors + target≠sain01) / Warn (no sensors + target==sain01) | SDD-018 C-5 | E0106 |

## Features (F01081–F01200)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01081 | Modules apply blindly or hard-fail at runtime today — operator must read logs + disable manually | SDD-018 § Problem 1 | E0101 | composite | false |
| F01082 | Operators want to dry-run the gate before committing — "what will actually apply on this box?" | SDD-018 § Problem 2 | E0101 | composite | false |
| F01083 | Build pipeline (kernel / Wasm-AOT / bitnet.cpp) needs single canonical tune source | SDD-018 § Problem 3 | E0101 | composite | false |
| F01084 | Observability needs continuous thermal envelope, not probe-time-only | SDD-018 § Problem 4 | E0101 | composite | false |
| F01085 | SD-R14..R19 arc closes all 4 problems | SDD-018 § Problem | E0101 | composite | false |
| F01086 | SDD-018 locks contracts so future evolutions stay backward-compatible | SDD-018 § Problem | E0101 | composite | false |
| F01087 | [requires_hardware] block in module.toml | SDD-018 C-1 | M00244 | composite | true |
| F01088 | Absence of [requires_hardware] OR all-zero/false → hardware-agnostic, always applied | SDD-018 C-1 semantics | E0102 | composite | false |
| F01089 | Any non-zero/non-false field → gated; daemon probes once + drops unmet | SDD-018 C-1 semantics | E0102 | composite | false |
| F01090 | Skipped modules print clear stderr block citing each failed predicate | SDD-018 C-1 semantics | E0102 | composite | false |
| F01091 | Gate runs ONCE per `apply` invocation (single probe, shared) — no per-module probe cost | SDD-018 C-1 semantics + D-1 | E0102 | composite | false |
| F01092 | Predicates AND-ed; module passes iff every set predicate is satisfied | SDD-018 C-1 semantics | E0102 | composite | false |
| F01093 | Field names + value semantics are operator-stable | SDD-018 C-1 stability | E0102 | composite | false |
| F01094 | Adding NEW field is backward-compatible (existing manifests don't mention it → default = no-op) | SDD-018 C-1 stability | E0102 | composite | false |
| F01095 | Renaming/removing fields requires Stage-2+ deprecation cycle | SDD-018 C-1 stability | E0102 | composite | false |
| F01096 | Predicate avx512_vnni (bool, default false) | SDD-018 C-1 | M00245 | composite | true |
| F01097 | Predicate avx512_bf16 (bool, default false) | SDD-018 C-1 | M00246 | composite | true |
| F01098 | Predicate memory_gib_min (u64, default 0 disabled) | SDD-018 C-1 | M00247 | composite | true |
| F01099 | Predicate gpu_count_min (u32, default 0 disabled) | SDD-018 C-1 | M00248 | composite | true |
| F01100 | Predicate sain01_verdict_min (FullMatch / PartialMatch / NoMatch, default "") | SDD-018 C-1 | M00249 | composite | true |
| F01101 | Predicate gpu_vram_gib_min (max semantics — ANY GPU meets the bar) | SDD-018 SD-R26 + D-9 | M00250 | composite | true |
| F01102 | Predicate gpu_power_headroom_watts_min (SUM across all GPUs, saturating arithmetic) | SDD-018 SD-R26 + D-10 | M00251 | composite | true |
| F01103 | gpu_power_headroom_watts_min fail-closed on partial telemetry | SDD-018 D-10 | M00251 | composite | false |
| F01104 | Predicate wasm_aot_features_required (strict AND set semantics — ALL declared features must be present) | SDD-018 SD-R32 + D-13 | M00252 | composite | true |
| F01105 | Operator wanting OR-logic writes multiple modules each with one feature + picks which lands | SDD-018 D-13 | M00252 | composite | false |
| F01106 | selfdefctl modules check-hardware (read-only dry-run of C-1) | SDD-018 C-2 | M00253 | cli_verb | true |
| F01107 | check-hardware human format — WOULD APPLY (n) block | SDD-018 C-2 | M00253 | composite | false |
| F01108 | check-hardware human format — WOULD SKIP (n) block with predicate citations per module | SDD-018 C-2 | M00253 | composite | false |
| F01109 | check-hardware --json — probe_ok (bool) | SDD-018 C-2 | M00254 | composite | true |
| F01110 | check-hardware --json — total field | SDD-018 C-2 | M00254 | composite | true |
| F01111 | check-hardware --json — kept[].{module, reason} | SDD-018 C-2 | M00254 | composite | true |
| F01112 | check-hardware --json — skipped[].{module, unmet[]} | SDD-018 C-2 | M00254 | composite | true |
| F01113 | check-hardware --json schema version implicit 1; breaking changes bump it | SDD-018 C-2 | M00254 | composite | false |
| F01114 | check-hardware exit code always 0 — informational, doesn't block scripts | SDD-018 C-2 + D-3 | M00253 | composite | false |
| F01115 | check-hardware --verdict-only NOT implemented (operator-driven info, not a gate) | SDD-018 D-3 | M00253 | composite | false |
| F01116 | Cross-repo mirror — sovereign-os R170 ships Python equivalent (scripts/hardware/selfdef-modules-gate.py) reading the same capabilities JSON + evaluating same 5 predicates | SDD-018 C-2 cross-repo mirror | E0109 | composite | false |
| F01117 | Two implementations must stay in agreement — any selfdef evaluate() change requires matching Python mirror change | SDD-018 C-2 cross-repo mirror | E0109 | composite | false |
| F01118 | selfdefctl hardware thermals — read-only per-sensor temperature readout | SDD-018 C-3 | M00255 | cli_verb | true |
| F01119 | thermals source 1 — /sys/class/hwmon/hwmonN/{name, temp<K>_input, temp<K>_label} | SDD-018 C-3 | M00255 | composite | false |
| F01120 | thermals source 2 — nvidia-smi --query-gpu=index,temperature.gpu | SDD-018 C-3 | M00255 | composite | true |
| F01121 | thermals millidegree integers parsed + rounded to whole °C | SDD-018 C-3 | M00255 | composite | false |
| F01122 | thermals human format — 2-column table sensor / celsius | SDD-018 C-3 | M00255 | composite | false |
| F01123 | thermals --json — array of {source, celsius} | SDD-018 C-3 | M00255 | composite | true |
| F01124 | ThermalReading.source label format operator-stable | SDD-018 C-3 | M00256 | composite | false |
| F01125 | hwmon-with-label source format — `<hwmon-name>/<label>` (e.g. `k10temp/Tctl`) | SDD-018 C-3 | M00256 | composite | false |
| F01126 | hwmon-without-label source format — `<hwmon-name>/temp<idx>` (e.g. `nvme/temp1`) | SDD-018 C-3 | M00256 | composite | false |
| F01127 | nvidia-smi source format — `nvidia-gpu-<index>` (e.g. `nvidia-gpu-0`) | SDD-018 C-3 | M00256 | composite | false |
| F01128 | Layer-B metric `sovereign_os_selfdef_hardware_thermal_celsius{sensor}` emitted into textfile collector | SDD-018 C-3 | M00257 | composite | true |
| F01129 | Layer-B thermal metric emitted only on non-empty thermals (no empty-label clutter) | SDD-018 C-3 | M00257 | composite | false |
| F01130 | Layer-B thermal metric name operator-stable | SDD-018 C-3 | M00257 | composite | false |
| F01131 | selfdefctl hardware tune — emits host-tuned compile flags | SDD-018 C-4 | M00258 | cli_verb | true |
| F01132 | tune --format sh (default) — `export KEY=value` lines; pipe through `source <(...)` | SDD-018 C-4 | M00258 | composite | false |
| F01133 | tune --format env-file — `KEY=value` without export (systemd EnvironmentFile compatible) | SDD-018 C-4 | M00259 | composite | true |
| F01134 | tune --format make — `KEY := value` for Makefile include | SDD-018 C-4 | M00260 | composite | true |
| F01135 | tune --format json — structured + schema_version | SDD-018 C-4 | M00261 | composite | true |
| F01136 | tune emitted var SELFDEF_HARDWARE_MARCH — znver5 / znver4 / x86-64-v4 / native (per SDD-017 § 7) | SDD-018 C-4 | E0105 | composite | true |
| F01137 | tune emitted var SELFDEF_HARDWARE_CFLAGS — `-march=<...>` + `-mprefer-vector-width=512` (gated) + each detected `-mavx512*` flag | SDD-018 C-4 | E0105 | composite | true |
| F01138 | tune emitted var SELFDEF_HARDWARE_KCFLAGS — same set, intended for kernel builds | SDD-018 C-4 | E0105 | composite | true |
| F01139 | tune emitted var SELFDEF_HARDWARE_AVX512_VNNI — true/false | SDD-018 C-4 | E0105 | composite | true |
| F01140 | tune emitted var SELFDEF_HARDWARE_AVX512_BF16 — true/false | SDD-018 C-4 | E0105 | composite | true |
| F01141 | `-mprefer-vector-width=512` gated on avx512f detection (regression-safe; flag is no-op or worse without AVX-512) | SDD-018 C-4 + D-6 | E0105 | composite | false |
| F01142 | tune --output PATH writes atomically (tempfile + rename) matching SDD-017 § 7 contract | SDD-018 C-4 | M00261 | composite | true |
| F01143 | NVCC -gencode list (SD-R29) — `selfdefctl hardware tune NVCC -gencode list`; SAIN-01 dual-GPU → sm_120 + sm_86 | SDD-018 SD-R29 | M00262 | composite | true |
| F01144 | NVCC -gencode deduplicated + ordered by first appearance in gpu.devices | SDD-018 D-11 | M00262 | composite | false |
| F01145 | cuda_arch_list ascending-numeric (`"86;120"` not `"120;86"`) matching CMAKE_CUDA_ARCHITECTURES | SDD-018 D-11 | M00262 | composite | false |
| F01146 | HardwareCapabilities.wasm_aot block (SD-R30) — target_triple / target_cpu / target_features | SDD-018 SD-R30 | M00263 | composite | true |
| F01147 | wasm_aot.target_features uses LLVM/wasmtime `+feature` convention | SDD-018 D-12 | M00263 | composite | false |
| F01148 | wasm_aot.target_features — AVX-512 family first, AVX2+FMA fallbacks last | SDD-018 D-12 | M00263 | composite | false |
| F01149 | wasm_aot.compile_command_hint — empty on hosts without AVX-512 (no AOT hint signaled) | SDD-018 D-12 | M00263 | composite | false |
| F01150 | Layer-B wasm-AOT scrape metrics (SD-R31) | SDD-018 SD-R31 | M00263 | composite | true |
| F01151 | doctor surface — hardware.thermals (SD-R17+R18) row | SDD-018 C-5 | M00264 | composite | true |
| F01152 | doctor hardware.thermals Ok — ≥1 sensor exposed (detail: count + min/max °C) | SDD-018 C-5 | M00264 | composite | false |
| F01153 | doctor hardware.thermals Skipped — no sensors AND deployment.target != sain01 | SDD-018 C-5 | M00264 | composite | false |
| F01154 | doctor hardware.thermals Warn — no sensors AND deployment.target == sain01 (degraded observability) | SDD-018 C-5 | M00264 | composite | false |
| F01155 | doctor per-row severity ordering is target-aware (SD-R9 invariant) | SDD-018 C-5 | M00264 | composite | false |
| F01156 | SD-R24 — GpuInventory.power_draw_watts + power_limit_watts | SDD-018 cross-repo bridge SD-R24 | E0107 | composite | true |
| F01157 | SD-R25 — HardwareCapabilities.gpu.devices (per-GPU detail) | SDD-018 cross-repo bridge SD-R25 | E0107 | composite | true |
| F01158 | SD-R26 — [requires_hardware] gpu_vram_gib_min + gpu_power_headroom_watts_min | SDD-018 cross-repo bridge SD-R26 | E0107 | composite | true |
| F01159 | SD-R27 — HOST SNAPSHOT block in check-hardware output | SDD-018 cross-repo bridge SD-R27 | E0107 | composite | false |
| F01160 | SD-R28 — modules/bitnet-gpu-inference/ (real 5-predicate demonstrator; emits schedule.json) | SDD-018 cross-repo bridge SD-R28 | E0107 | composite | true |
| F01161 | SD-R30 — HardwareCapabilities.wasm_aot block (target_triple, target_cpu, target_features) | SDD-018 cross-repo bridge SD-R30 | E0107 | composite | true |
| F01162 | SD-R31 — Layer-B wasm-AOT scrape metrics | SDD-018 cross-repo bridge SD-R31 | E0107 | composite | true |
| F01163 | SD-R32 — [requires_hardware] wasm_aot_features_required | SDD-018 cross-repo bridge SD-R32 | E0107 | composite | true |
| F01164 | Cross-repo consumer sovereign-os R170 — selfdef-modules-gate.py | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01165 | Cross-repo consumer sovereign-os R172 — scripts/hardware/thermal-watch.py (thresholds + OCSF events) | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01166 | Cross-repo consumer sovereign-os R173 — scripts/build/lib/selfdef-tune.sh (bridge to SD-R19) | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01167 | Cross-repo consumer sovereign-os R177 — selfdef-modules-gate mirror SD-R25 + R26 predicates | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01168 | Cross-repo consumer sovereign-os R178 — scripts/inference/lib/pick-gpu.py (SD-R28 schedule consumer) | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01169 | Cross-repo consumer sovereign-os R179 — scripts/pulse/wasm-aot.sh consumes SD-R30 wasm_aot block | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01170 | Cross-repo consumer sovereign-os R180 — docs/observability/dashboards/sovereign-os-wasm-aot.json | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01171 | Cross-repo consumer sovereign-os R181 — selfdef-modules-gate mirror SD-R32 predicate | SDD-018 cross-repo bridge | E0109 | composite | true |
| F01172 | Cross-repo fallback — R170 falls back to scripts/hardware/sain01-match.py probe when selfdef daemon absent | SDD-018 cross-repo bridge | E0109 | composite | false |
| F01173 | Cross-repo fallback — R172 reads /sys/class/hwmon directly when selfdef daemon absent | SDD-018 cross-repo bridge | E0109 | composite | false |
| F01174 | Cross-repo fallback — R173 falls back to capabilities-JSON parsing then native-march | SDD-018 cross-repo bridge | E0109 | composite | false |
| F01175 | Decision D-1 — gate runs at apply time, not module-load time (catalog enumeration stays cheap) | SDD-018 D-1 | E0108 | composite | false |
| F01176 | Decision D-2 — unmeetable predicates SKIP (info), don't FAIL; operator overrides by removing the block | SDD-018 D-2 | E0108 | composite | false |
| F01177 | Decision D-3 — exit code 0 always; --verdict-only not implemented | SDD-018 D-3 | E0108 | composite | false |
| F01178 | Decision D-4 — per-sensor probe stays inside probe_from_roots (single I/O pass) | SDD-018 D-4 | E0108 | composite | false |
| F01179 | Decision D-5 — thermal classification (warn/critical) lives in sovereign-os R172, NOT selfdef | SDD-018 D-5 | E0108 | composite | false |
| F01180 | Decision D-6 — ZMM hint gated on avx512f detection | SDD-018 D-6 | E0108 | composite | false |
| F01181 | Decision D-7 — GPU power telemetry OPTIONAL; Option<u32>; fail-soft for plain telemetry, fail-closed for SD-R26 consumers | SDD-018 D-7 | E0108 | composite | false |
| F01182 | Decision D-8 — gpu.devices index-aligned with gpu.device_nodes (same vec order) | SDD-018 D-8 | E0108 | composite | false |
| F01183 | Decision D-9 — gpu_vram_gib_min ANY-GPU-meets-bar (max semantics) | SDD-018 D-9 | E0108 | composite | false |
| F01184 | Decision D-10 — gpu_power_headroom_watts_min SUM across all GPUs (fleet headroom), saturating arithmetic, fail-closed on partial telemetry | SDD-018 D-10 | E0108 | composite | false |
| F01185 | Decision D-11 — NVCC -gencode deduplicated + ordered by first appearance; cuda_arch_list ascending-numeric | SDD-018 D-11 | E0108 | composite | false |
| F01186 | Decision D-12 — wasm_aot.target_features LLVM `+feature`, AVX-512 first, AVX2+FMA last | SDD-018 D-12 | E0108 | composite | false |
| F01187 | Decision D-13 — wasm_aot_features_required strict AND set semantics | SDD-018 D-13 | E0108 | composite | false |
| F01188 | Non-goal — AMD ROCm GPU thermal probing (NVIDIA only via nvidia-smi) | SDD-018 § Non-goals | E0110 | composite | false |
| F01189 | Non-goal — per-NUMA-node thermal binning | SDD-018 § Non-goals | E0110 | composite | false |
| F01190 | Non-goal — predictive thermal modeling (operators get instantaneous readings; trends emerge from textfile-collector timeseries) | SDD-018 § Non-goals | E0110 | composite | false |
| F01191 | Non-goal — hardware-feature-aware unsafe-code paths in daemon (workspace remains `#![forbid(unsafe_code)]`; AVX-512 exploitation lives in safe-Rust crates blake3 / crc32fast with target_feature dispatch OR in sovereign-os build artifacts) | SDD-018 § Non-goals | E0110 | composite | false |
| F01192 | Out-of-scope deferred — hardware-aware POLICY scope (TracingPolicy filters that key off AVX-512) | SDD-018 § Out of scope | E0110 | composite | false |
| F01193 | Out-of-scope deferred — selfdef-side periodic thermal probe + event emission (sovereign-os R172 owns periodic loop via systemd timer) | SDD-018 § Out of scope | E0110 | composite | false |
| F01194 | Project boundary — cross-repo only via documented capabilities JSON + Layer-B textfile collector metrics + MS007 typed mirrors | SDD-018 + MS007 + SDD-038 | E0109 | composite | false |
| F01195 | Project boundary — selfdef NEVER imports sovereign-os crate code directly | architecture | E0109 | composite | false |
| F01196 | Project boundary — sovereign-os R170/R177/R181 are Python consumers reading selfdef artifacts; they're not selfdef crate imports | SDD-018 cross-repo bridge | E0109 | composite | false |
| F01197 | Composite — MS010 builds on SDD-017 (hardware inventory; probe / Sain01Match / HardwareCapabilities JSON export) | SDD-018 § Problem | E0101 | composite | false |
| F01198 | Composite — MS010 SD-R14..R19 merged via PR #190 on 2026-05-16 (cycle 1) + SD-R24..R32 accumulating in PR #191 (cycle 2) | SDD-018 § header | E0107 | composite | false |
| F01199 | Composite — hardware-tune-cache is the FIRST reference module demonstrating C-4 tune surface consumption | `modules/hardware-tune-cache/` | M00240 | composite | false |
| F01200 | Composite — bitnet-gpu-inference module (SD-R28) is the real 5-predicate demonstrator + emits schedule.json for R178 pick-gpu.py | SDD-018 SD-R28 | F01160 | composite | false |

## Requirements (R02161–R02400)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R02161 | SDD-018 closes the doctrine gap "research and continuously evolving specs to drive and evolve SDD and TDD" | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02162 | SDD-018 builds on SDD-017 (hardware INVENTORY surface — probe / Sain01Match / HardwareCapabilities JSON export) | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02163 | SDD-018 builds on sovereign-os R172 (thermal classification + OCSF events) | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02164 | SDD-018 builds on sovereign-os R173 (selfdef-tune.sh) | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02165 | Problem 1 — modules apply blindly OR hard-fail at runtime; operator must read logs + disable manually | SDD-018 § Problem 1 | F01081 | non-negotiable | false | 10 |
| R02166 | Problem 2 — operators want dry-run gate before committing | SDD-018 § Problem 2 | F01082 | non-negotiable | false | 10 |
| R02167 | Problem 3 — build pipeline (kernel / Wasm-AOT / bitnet.cpp) needs single canonical tune source without hand-rolled hardware probing | SDD-018 § Problem 3 | F01083 | non-negotiable | false | 10 |
| R02168 | Problem 4 — observability needs continuous thermal envelope, not probe-time only | SDD-018 § Problem 4 | F01084 | non-negotiable | false | 10 |
| R02169 | SD-R14..R19 arc closes all 4 problems | SDD-018 § Problem | E0101 | non-negotiable | false | 10 |
| R02170 | SDD-018 locks contracts so future evolutions stay backward-compatible | SDD-018 § Problem | E0101 | non-negotiable | false | 10 |
| R02171 | C-1 — module manifests may declare [requires_hardware] block | SDD-018 C-1 | F01087 | non-negotiable | false | 10 |
| R02172 | C-1 predicate avx512_vnni — bool, default false | SDD-018 C-1 | F01096 | non-negotiable | true | 10 |
| R02173 | C-1 predicate avx512_bf16 — bool, default false | SDD-018 C-1 | F01097 | non-negotiable | true | 10 |
| R02174 | C-1 predicate memory_gib_min — u64, default 0 (disabled) | SDD-018 C-1 | F01098 | non-negotiable | true | 10 |
| R02175 | C-1 predicate gpu_count_min — u32, default 0 (disabled) | SDD-018 C-1 | F01099 | non-negotiable | true | 10 |
| R02176 | C-1 predicate sain01_verdict_min — enum (FullMatch / PartialMatch / NoMatch), default "" | SDD-018 C-1 | F01100 | non-negotiable | true | 10 |
| R02177 | C-1 — absence of [requires_hardware] OR all-zero/false → module hardware-agnostic, always applied | SDD-018 C-1 semantics | F01088 | non-negotiable | false | 10 |
| R02178 | C-1 — any non-zero/non-false field → module gated | SDD-018 C-1 semantics | F01089 | non-negotiable | false | 10 |
| R02179 | C-1 — `selfdefctl modules apply` probes once + drops modules with unmet predicates | SDD-018 C-1 semantics | F01089 | non-negotiable | false | 10 |
| R02180 | C-1 — skipped modules print clear stderr block citing each failed predicate | SDD-018 C-1 semantics | F01090 | non-negotiable | false | 10 |
| R02181 | C-1 — gate runs ONCE per apply invocation (single probe, shared across modules) | SDD-018 C-1 semantics + D-1 | F01091 | non-negotiable | false | 10 |
| R02182 | C-1 — no per-module probe cost | SDD-018 C-1 semantics | F01091 | non-negotiable | false | 10 |
| R02183 | C-1 — 5 predicates AND-ed; module passes iff every set predicate is satisfied | SDD-018 C-1 semantics | F01092 | non-negotiable | false | 10 |
| R02184 | C-1 stability — field names + value semantics operator-stable | SDD-018 C-1 stability | F01093 | non-negotiable | false | 10 |
| R02185 | C-1 stability — adding a NEW field is backward-compatible | SDD-018 C-1 stability | F01094 | non-negotiable | false | 10 |
| R02186 | C-1 stability — existing manifests without the new field default to no-op for that field | SDD-018 C-1 stability | F01094 | non-negotiable | false | 10 |
| R02187 | C-1 stability — renaming/removing fields is NOT backward-compatible | SDD-018 C-1 stability | F01095 | non-negotiable | false | 10 |
| R02188 | C-1 stability — rename/remove requires Stage-2+ deprecation cycle | SDD-018 C-1 stability | F01095 | non-negotiable | false | 10 |
| R02189 | C-1 amendment SD-R26 — predicate gpu_vram_gib_min | SDD-018 SD-R26 | F01101 | non-negotiable | true | 10 |
| R02190 | C-1 amendment SD-R26 — predicate gpu_power_headroom_watts_min | SDD-018 SD-R26 | F01102 | non-negotiable | true | 10 |
| R02191 | C-1 amendment SD-R32 — predicate wasm_aot_features_required | SDD-018 SD-R32 | F01104 | non-negotiable | true | 10 |
| R02192 | gpu_vram_gib_min uses MAX semantics — passes when ANY GPU meets the bar | SDD-018 D-9 | F01101 | non-negotiable | false | 10 |
| R02193 | gpu_vram_gib_min — operators wanting all-GPUs-must-fit layer a future gpu_vram_gib_each_min predicate | SDD-018 D-9 | F01101 | non-negotiable | false | 10 |
| R02194 | gpu_power_headroom_watts_min uses SUM across all GPUs (fleet headroom) | SDD-018 D-10 | F01102 | non-negotiable | false | 10 |
| R02195 | gpu_power_headroom_watts_min uses saturating arithmetic — never underflows on noisy telemetry | SDD-018 D-10 | F01102 | non-negotiable | false | 10 |
| R02196 | gpu_power_headroom_watts_min fail-closed on partial telemetry — any GPU missing power data → entire predicate fails | SDD-018 D-10 | F01103 | non-negotiable | false | 10 |
| R02197 | wasm_aot_features_required strict AND set semantics — ALL declared features must be present | SDD-018 D-13 | F01104 | non-negotiable | false | 10 |
| R02198 | wasm_aot_features_required — OR-logic done via multiple modules each declaring one feature; operator picks which lands | SDD-018 D-13 | F01105 | non-negotiable | false | 10 |
| R02199 | C-2 `selfdefctl modules check-hardware` is a read-only dry-run of C-1 | SDD-018 C-2 | F01106 | non-negotiable | false | 10 |
| R02200 | C-2 human output — WOULD APPLY (n) block | SDD-018 C-2 | F01107 | non-negotiable | false | 10 |
| R02201 | C-2 human output — WOULD SKIP (n) block with predicate citations per skipped module | SDD-018 C-2 | F01108 | non-negotiable | false | 10 |
| R02202 | C-2 --json output field — probe_ok (bool) | SDD-018 C-2 | F01109 | non-negotiable | true | 10 |
| R02203 | C-2 --json output field — total | SDD-018 C-2 | F01110 | non-negotiable | true | 10 |
| R02204 | C-2 --json output field — kept[].{module, reason} | SDD-018 C-2 | F01111 | non-negotiable | true | 10 |
| R02205 | C-2 --json output field — skipped[].{module, unmet[]} | SDD-018 C-2 | F01112 | non-negotiable | true | 10 |
| R02206 | C-2 --json schema version implicit 1 | SDD-018 C-2 | F01113 | non-negotiable | false | 10 |
| R02207 | C-2 --json breaking schema changes bump version | SDD-018 C-2 | F01113 | non-negotiable | false | 10 |
| R02208 | C-2 exit code always 0 — informational, doesn't block scripts | SDD-018 C-2 + D-3 | F01114 | non-negotiable | false | 10 |
| R02209 | C-2 --verdict-only NOT implemented per D-3 | SDD-018 D-3 | F01115 | non-negotiable | false | 10 |
| R02210 | Cross-repo mirror — sovereign-os R170 ships scripts/hardware/selfdef-modules-gate.py | SDD-018 C-2 cross-repo | F01116 | non-negotiable | false | 10 |
| R02211 | Cross-repo mirror reads same /var/lib/selfdef/hardware-capabilities.json | SDD-018 C-2 cross-repo | F01116 | non-negotiable | false | 10 |
| R02212 | Cross-repo mirror evaluates same 5 predicates | SDD-018 C-2 cross-repo | F01116 | non-negotiable | false | 10 |
| R02213 | Cross-repo mirror — two implementations must stay in agreement | SDD-018 C-2 cross-repo | F01117 | non-negotiable | false | 10 |
| R02214 | Cross-repo mirror — any selfdef evaluate() change requires matching Python mirror change | SDD-018 C-2 cross-repo | F01117 | non-negotiable | false | 10 |
| R02215 | C-3 `selfdefctl hardware thermals` — read-only per-sensor temperature readout | SDD-018 C-3 | F01118 | non-negotiable | false | 10 |
| R02216 | C-3 source 1 — /sys/class/hwmon/hwmonN/name | SDD-018 C-3 | F01119 | non-negotiable | true | 10 |
| R02217 | C-3 source 1 — /sys/class/hwmon/hwmonN/temp<K>_input | SDD-018 C-3 | F01119 | non-negotiable | true | 10 |
| R02218 | C-3 source 1 — /sys/class/hwmon/hwmonN/temp<K>_label | SDD-018 C-3 | F01119 | non-negotiable | true | 10 |
| R02219 | C-3 source 1 — millidegree integers parsed + rounded to whole °C | SDD-018 C-3 | F01121 | non-negotiable | false | 10 |
| R02220 | C-3 source 2 — nvidia-smi --query-gpu=index,temperature.gpu | SDD-018 C-3 | F01120 | non-negotiable | true | 10 |
| R02221 | C-3 human format — 2-column table sensor / celsius | SDD-018 C-3 | F01122 | non-negotiable | false | 10 |
| R02222 | C-3 --json format — array of {source, celsius} | SDD-018 C-3 | F01123 | non-negotiable | true | 10 |
| R02223 | ThermalReading.source label format operator-stable | SDD-018 C-3 | F01124 | non-negotiable | false | 10 |
| R02224 | ThermalReading.source format — hwmon with label = `<hwmon-name>/<label>` (e.g. `k10temp/Tctl`) | SDD-018 C-3 | F01125 | non-negotiable | true | 10 |
| R02225 | ThermalReading.source format — hwmon without label = `<hwmon-name>/temp<idx>` (e.g. `nvme/temp1`) | SDD-018 C-3 | F01126 | non-negotiable | true | 10 |
| R02226 | ThermalReading.source format — nvidia-smi = `nvidia-gpu-<index>` (e.g. `nvidia-gpu-0`) | SDD-018 C-3 | F01127 | non-negotiable | true | 10 |
| R02227 | Layer-B metric `sovereign_os_selfdef_hardware_thermal_celsius{sensor="..."}` emitted into textfile collector | SDD-018 C-3 | F01128 | non-negotiable | true | 10 |
| R02228 | Layer-B thermal metric emitted ONLY when thermals non-empty (no empty-label clutter) | SDD-018 C-3 | F01129 | non-negotiable | false | 10 |
| R02229 | Layer-B thermal metric name operator-stable | SDD-018 C-3 | F01130 | non-negotiable | false | 10 |
| R02230 | C-4 `selfdefctl hardware tune` — emits host-tuned compile flags | SDD-018 C-4 | F01131 | non-negotiable | false | 10 |
| R02231 | C-4 --format sh (default) — `export KEY=value` lines | SDD-018 C-4 | F01132 | non-negotiable | true | 10 |
| R02232 | C-4 --format sh — pipe through `source <(...)` | SDD-018 C-4 | F01132 | non-negotiable | false | 10 |
| R02233 | C-4 --format env-file — `KEY=value` without `export` | SDD-018 C-4 | F01133 | non-negotiable | true | 10 |
| R02234 | C-4 --format env-file — systemd EnvironmentFile= compatible | SDD-018 C-4 | F01133 | non-negotiable | false | 10 |
| R02235 | C-4 --format make — `KEY := value` for Makefile include | SDD-018 C-4 | F01134 | non-negotiable | true | 10 |
| R02236 | C-4 --format json — structured {march, cflags, kcflags, avx512_*, compile_flag_list, zmm_512_preferred} | SDD-018 C-4 | F01135 | non-negotiable | true | 10 |
| R02237 | C-4 --format json — carries schema_version | SDD-018 C-4 | F01135 | non-negotiable | false | 10 |
| R02238 | C-4 emitted var SELFDEF_HARDWARE_MARCH | SDD-018 C-4 | F01136 | non-negotiable | true | 10 |
| R02239 | C-4 MARCH value — znver5 / znver4 / x86-64-v4 / native (per SDD-017 § 7) | SDD-018 C-4 + SDD-017 § 7 | F01136 | non-negotiable | false | 10 |
| R02240 | C-4 emitted var SELFDEF_HARDWARE_CFLAGS | SDD-018 C-4 | F01137 | non-negotiable | true | 10 |
| R02241 | C-4 CFLAGS value — `-march=<...>` | SDD-018 C-4 | F01137 | non-negotiable | false | 10 |
| R02242 | C-4 CFLAGS value — `-mprefer-vector-width=512` when avx512f detected | SDD-018 C-4 | F01137 | non-negotiable | false | 10 |
| R02243 | C-4 CFLAGS value — each detected `-mavx512*` flag | SDD-018 C-4 | F01137 | non-negotiable | false | 10 |
| R02244 | C-4 emitted var SELFDEF_HARDWARE_KCFLAGS — same set, intended for kernel builds | SDD-018 C-4 | F01138 | non-negotiable | true | 10 |
| R02245 | C-4 emitted var SELFDEF_HARDWARE_AVX512_VNNI — true/false | SDD-018 C-4 | F01139 | non-negotiable | true | 10 |
| R02246 | C-4 emitted var SELFDEF_HARDWARE_AVX512_BF16 — true/false | SDD-018 C-4 | F01140 | non-negotiable | true | 10 |
| R02247 | `-mprefer-vector-width=512` gated on avx512f detection (regression-safe) | SDD-018 C-4 + D-6 | F01141 | non-negotiable | false | 10 |
| R02248 | C-4 --output PATH writes atomically (tempfile + rename) | SDD-018 C-4 | F01142 | non-negotiable | true | 10 |
| R02249 | C-4 atomic write matches SDD-017 § 7 capabilities-JSON contract | SDD-018 C-4 | F01142 | non-negotiable | false | 10 |
| R02250 | C-5 `selfdefctl doctor` emits hardware.thermals row | SDD-018 C-5 | F01151 | non-negotiable | true | 10 |
| R02251 | C-5 doctor hardware.thermals Ok — ≥1 sensor exposed, detail count + min/max °C | SDD-018 C-5 | F01152 | non-negotiable | false | 10 |
| R02252 | C-5 doctor hardware.thermals Skipped — no sensors AND deployment.target != sain01 | SDD-018 C-5 | F01153 | non-negotiable | false | 10 |
| R02253 | C-5 doctor hardware.thermals Warn — no sensors AND deployment.target == sain01 | SDD-018 C-5 | F01154 | non-negotiable | false | 10 |
| R02254 | C-5 doctor per-row severity ordering target-aware (SD-R9 invariant) | SDD-018 C-5 | F01155 | non-negotiable | false | 10 |
| R02255 | SD-R24 — GpuInventory.power_draw_watts field | SDD-018 cross-repo bridge SD-R24 | F01156 | non-negotiable | true | 10 |
| R02256 | SD-R24 — GpuInventory.power_limit_watts field | SDD-018 cross-repo bridge SD-R24 | F01156 | non-negotiable | true | 10 |
| R02257 | SD-R24 — GPU power telemetry OPTIONAL (Option<u32>) | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02258 | SD-R24 — hosts without NVML get None | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02259 | SD-R24 — Layer-B metrics omit power gauge block when telemetry absent | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02260 | SD-R24 fail-soft is the contract for plain power telemetry | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02261 | SD-R24 — modules depending on power telemetry opt in explicitly + fail-closed | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02262 | SD-R25 — HardwareCapabilities.gpu.devices (per-GPU detail) | SDD-018 SD-R25 | F01157 | non-negotiable | true | 10 |
| R02263 | SD-R25 — gpu.devices index-aligned with gpu.device_nodes (same vec order) | SDD-018 D-8 | F01182 | non-negotiable | false | 10 |
| R02264 | SD-R25 — derive_capabilities preserves snap.gpus order | SDD-018 D-8 | F01182 | non-negotiable | false | 10 |
| R02265 | SD-R25 — downstream consumers (R178 pick-gpu.py, SD-R28 schedule.json) rely on index-aligned invariant | SDD-018 D-8 | F01182 | non-negotiable | false | 10 |
| R02266 | SD-R27 — HOST SNAPSHOT block in check-hardware output | SDD-018 SD-R27 | F01159 | non-negotiable | false | 10 |
| R02267 | SD-R28 — modules/bitnet-gpu-inference real 5-predicate demonstrator | SDD-018 SD-R28 | F01160 | non-negotiable | true | 10 |
| R02268 | SD-R28 — bitnet-gpu-inference emits schedule.json | SDD-018 SD-R28 | F01160 | non-negotiable | false | 10 |
| R02269 | SD-R29 — `selfdefctl hardware tune NVCC -gencode list` | SDD-018 SD-R29 | F01143 | non-negotiable | true | 10 |
| R02270 | SD-R29 — SAIN-01 dual-GPU → sm_120 + sm_86 | SDD-018 SD-R29 | F01143 | non-negotiable | false | 10 |
| R02271 | SD-R29 — NVCC -gencode list deduplicated | SDD-018 D-11 | F01144 | non-negotiable | false | 10 |
| R02272 | SD-R29 — NVCC -gencode list ordered by first appearance in gpu.devices | SDD-018 D-11 | F01144 | non-negotiable | false | 10 |
| R02273 | SD-R29 — cuda_arch_list ascending-numeric (`"86;120"` not `"120;86"`) | SDD-018 D-11 | F01145 | non-negotiable | false | 10 |
| R02274 | SD-R29 — cuda_arch_list matches CMAKE_CUDA_ARCHITECTURES convention | SDD-018 D-11 | F01145 | non-negotiable | false | 10 |
| R02275 | SD-R30 — HardwareCapabilities.wasm_aot block | SDD-018 SD-R30 | F01146 | non-negotiable | true | 10 |
| R02276 | SD-R30 — wasm_aot.target_triple field | SDD-018 SD-R30 | F01146 | non-negotiable | true | 10 |
| R02277 | SD-R30 — wasm_aot.target_cpu field | SDD-018 SD-R30 | F01146 | non-negotiable | true | 10 |
| R02278 | SD-R30 — wasm_aot.target_features field | SDD-018 SD-R30 | F01146 | non-negotiable | true | 10 |
| R02279 | SD-R30 — target_features uses LLVM/wasmtime `+feature` convention | SDD-018 D-12 | F01147 | non-negotiable | false | 10 |
| R02280 | SD-R30 — AVX-512 family first in target_features | SDD-018 D-12 | F01148 | non-negotiable | false | 10 |
| R02281 | SD-R30 — AVX2 + FMA fallbacks last in target_features | SDD-018 D-12 | F01148 | non-negotiable | false | 10 |
| R02282 | SD-R30 — empty compile_command_hint on hosts without AVX-512 (no AOT hint signaled) | SDD-018 D-12 | F01149 | non-negotiable | false | 10 |
| R02283 | SD-R31 — Layer-B wasm-AOT scrape metrics | SDD-018 SD-R31 | F01150 | non-negotiable | true | 10 |
| R02284 | SD-R32 — [requires_hardware] wasm_aot_features_required predicate | SDD-018 SD-R32 | F01163 | non-negotiable | true | 10 |
| R02285 | Cross-repo bridge map — selfdef SDD-017 §6 → Layer-B metrics (textfile collector) | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02286 | Cross-repo bridge map — selfdef SDD-017 §7 → /var/lib/selfdef/hardware-capabilities.json | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02287 | Cross-repo bridge map — selfdef SD-R14 → module.toml [requires_hardware] | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02288 | Cross-repo bridge map — selfdef SD-R15 → selfdefctl modules check-hardware | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02289 | Cross-repo bridge map — selfdef SD-R17 → selfdef-hardware ThermalReading | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02290 | Cross-repo bridge map — selfdef SD-R19 → selfdefctl hardware tune --format <fmt> | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02291 | Cross-repo bridge map — selfdef SD-R24 → GpuInventory power telemetry | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02292 | Cross-repo bridge map — selfdef SD-R25 → HardwareCapabilities.gpu.devices | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02293 | Cross-repo bridge map — selfdef SD-R26 → [requires_hardware] gpu_vram_gib_min + gpu_power_headroom_watts_min | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02294 | Cross-repo bridge map — selfdef SD-R27 → HOST SNAPSHOT block in check-hardware output | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02295 | Cross-repo bridge map — selfdef SD-R28 → modules/bitnet-gpu-inference + schedule.json | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02296 | Cross-repo bridge map — selfdef SD-R29 → selfdefctl hardware tune NVCC -gencode list | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02297 | Cross-repo bridge map — selfdef SD-R30 → HardwareCapabilities.wasm_aot block | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02298 | Cross-repo bridge map — selfdef SD-R31 → Layer-B wasm-AOT scrape metrics | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02299 | Cross-repo bridge map — selfdef SD-R32 → [requires_hardware] wasm_aot_features_required | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02300 | Cross-repo consumer — sovereign-os R170 selfdef-modules-gate.py | SDD-018 § Cross-repo bridge | F01164 | non-negotiable | true | 10 |
| R02301 | Cross-repo consumer — sovereign-os R172 thermal-watch.py (thresholds + OCSF events) | SDD-018 § Cross-repo bridge | F01165 | non-negotiable | true | 10 |
| R02302 | Cross-repo consumer — sovereign-os R173 selfdef-tune.sh (bridge to SD-R19) | SDD-018 § Cross-repo bridge | F01166 | non-negotiable | true | 10 |
| R02303 | Cross-repo consumer — sovereign-os R177 selfdef-modules-gate mirror SD-R25 + R26 | SDD-018 § Cross-repo bridge | F01167 | non-negotiable | true | 10 |
| R02304 | Cross-repo consumer — sovereign-os R178 pick-gpu.py (SD-R28 schedule consumer) | SDD-018 § Cross-repo bridge | F01168 | non-negotiable | true | 10 |
| R02305 | Cross-repo consumer — sovereign-os R179 wasm-aot.sh consumes SD-R30 wasm_aot block | SDD-018 § Cross-repo bridge | F01169 | non-negotiable | true | 10 |
| R02306 | Cross-repo consumer — sovereign-os R180 dashboards/sovereign-os-wasm-aot.json | SDD-018 § Cross-repo bridge | F01170 | non-negotiable | true | 10 |
| R02307 | Cross-repo consumer — sovereign-os R181 selfdef-modules-gate mirror SD-R32 predicate | SDD-018 § Cross-repo bridge | F01171 | non-negotiable | true | 10 |
| R02308 | Cross-repo fallback — every cross-repo consumer has a fallback | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02309 | Cross-repo fallback — removing the selfdef side never causes a hard break | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02310 | Cross-repo fallback — R170 falls back to scripts/hardware/sain01-match.py probe | SDD-018 § Cross-repo bridge | F01172 | non-negotiable | false | 10 |
| R02311 | Cross-repo fallback — R172 reads /sys/class/hwmon directly (selfdef daemon not required) | SDD-018 § Cross-repo bridge | F01173 | non-negotiable | false | 10 |
| R02312 | Cross-repo fallback — R173 falls back to capabilities-JSON parsing, then native-march | SDD-018 § Cross-repo bridge | F01174 | non-negotiable | false | 10 |
| R02313 | Decision D-1 — gate runs at apply time, not module-load time | SDD-018 D-1 | F01175 | non-negotiable | false | 10 |
| R02314 | Decision D-1 — catalog enumeration stays cheap | SDD-018 D-1 | F01175 | non-negotiable | false | 10 |
| R02315 | Decision D-2 — unmeetable predicates SKIP (info), don't FAIL | SDD-018 D-2 | F01176 | non-negotiable | false | 10 |
| R02316 | Decision D-2 — operator overrides by removing the [requires_hardware] block | SDD-018 D-2 | F01176 | non-negotiable | false | 10 |
| R02317 | Decision D-3 — exit code 0 always | SDD-018 D-3 | F01177 | non-negotiable | false | 10 |
| R02318 | Decision D-3 — --verdict-only not implemented (operator-driven info, not a gate) | SDD-018 D-3 | F01177 | non-negotiable | false | 10 |
| R02319 | Decision D-4 — per-sensor probe stays inside probe_from_roots (single I/O pass) | SDD-018 D-4 | F01178 | non-negotiable | false | 10 |
| R02320 | Decision D-4 — operators get sensors via HardwareSnapshot.thermals + JSON export + CLI surface | SDD-018 D-4 | F01178 | non-negotiable | false | 10 |
| R02321 | Decision D-5 — thermal classification (warn/critical) lives in sovereign-os R172, NOT selfdef | SDD-018 D-5 | F01179 | non-negotiable | false | 10 |
| R02322 | Decision D-5 — thresholds are profile-dependent (rationale for living in sovereign-os) | SDD-018 D-5 | F01179 | non-negotiable | false | 10 |
| R02323 | Decision D-6 — ZMM hint gated on avx512f detection | SDD-018 D-6 | F01180 | non-negotiable | false | 10 |
| R02324 | Decision D-6 — the `-mprefer-vector-width=512` flag is not universally beneficial | SDD-018 D-6 | F01180 | non-negotiable | false | 10 |
| R02325 | Decision D-7 — GPU power telemetry OPTIONAL | SDD-018 D-7 | F01181 | non-negotiable | false | 10 |
| R02326 | Decision D-8 — gpu.devices index-aligned with gpu.device_nodes | SDD-018 D-8 | F01182 | non-negotiable | false | 10 |
| R02327 | Decision D-9 — gpu_vram_gib_min ANY-meets-bar (max) semantics | SDD-018 D-9 | F01183 | non-negotiable | false | 10 |
| R02328 | Decision D-9 — keep simple semantics primary; layer specialised on demand | SDD-018 D-9 | F01183 | non-negotiable | false | 10 |
| R02329 | Decision D-10 — gpu_power_headroom_watts_min SUM-across-GPUs | SDD-018 D-10 | F01184 | non-negotiable | false | 10 |
| R02330 | Decision D-10 — saturating arithmetic | SDD-018 D-10 | F01184 | non-negotiable | false | 10 |
| R02331 | Decision D-10 — fail-closed on partial telemetry | SDD-018 D-10 | F01184 | non-negotiable | false | 10 |
| R02332 | Decision D-11 — NVCC -gencode deduplicated + ordered by first appearance | SDD-018 D-11 | F01185 | non-negotiable | false | 10 |
| R02333 | Decision D-11 — cuda_arch_list ascending-numeric matching CMAKE_CUDA_ARCHITECTURES | SDD-018 D-11 | F01185 | non-negotiable | false | 10 |
| R02334 | Decision D-12 — wasm_aot.target_features uses LLVM/wasmtime `+feature` convention | SDD-018 D-12 | F01186 | non-negotiable | false | 10 |
| R02335 | Decision D-12 — AVX-512 family first, AVX2+FMA last | SDD-018 D-12 | F01186 | non-negotiable | false | 10 |
| R02336 | Decision D-12 — empty compile_command_hint without AVX-512 | SDD-018 D-12 | F01186 | non-negotiable | false | 10 |
| R02337 | Decision D-13 — wasm_aot_features_required strict-AND set semantics | SDD-018 D-13 | F01187 | non-negotiable | false | 10 |
| R02338 | Decision D-13 — OR-logic via multiple modules each with one feature | SDD-018 D-13 | F01187 | non-negotiable | false | 10 |
| R02339 | Non-goal — AMD ROCm GPU thermal probing | SDD-018 § Non-goals | F01188 | non-negotiable | false | 10 |
| R02340 | Non-goal — NVIDIA only via nvidia-smi | SDD-018 § Non-goals | F01188 | non-negotiable | false | 10 |
| R02341 | Non-goal — per-NUMA-node thermal binning | SDD-018 § Non-goals | F01189 | non-negotiable | false | 10 |
| R02342 | Non-goal — predictive thermal modeling | SDD-018 § Non-goals | F01190 | non-negotiable | false | 10 |
| R02343 | Non-goal — operators get instantaneous readings; trends emerge from textfile-collector timeseries | SDD-018 § Non-goals | F01190 | non-negotiable | false | 10 |
| R02344 | Non-goal — hardware-feature-aware unsafe-code paths in the daemon | SDD-018 § Non-goals | F01191 | non-negotiable | false | 10 |
| R02345 | Non-goal — workspace remains `#![forbid(unsafe_code)]` | SDD-018 § Non-goals | F01191 | non-negotiable | false | 10 |
| R02346 | Non-goal — AVX-512 exploitation lives in safe-Rust crates (blake3 / crc32fast with target_feature dispatch) OR sovereign-os build artifacts | SDD-018 § Non-goals | F01191 | non-negotiable | false | 10 |
| R02347 | Out-of-scope deferred — hardware-aware POLICY scope (TracingPolicy filters that key off AVX-512) | SDD-018 § Out of scope | F01192 | non-negotiable | false | 10 |
| R02348 | Out-of-scope deferred — interesting but not yet operator-needed | SDD-018 § Out of scope | F01192 | non-negotiable | false | 10 |
| R02349 | Out-of-scope deferred — selfdef-side periodic thermal probe + event emission | SDD-018 § Out of scope | F01193 | non-negotiable | false | 10 |
| R02350 | Out-of-scope deferred — sovereign-os R172 currently owns the periodic loop via systemd timer | SDD-018 § Out of scope | F01193 | non-negotiable | false | 10 |
| R02351 | Reference module — hardware-tune-cache exists at modules/hardware-tune-cache/ | `modules/hardware-tune-cache/` | M00240 | non-negotiable | false | 10 |
| R02352 | hardware-tune-cache install/apply.sh applies tune cache to host build pipeline | `modules/hardware-tune-cache/install/apply.sh` | M00241 | non-negotiable | true | 10 |
| R02353 | hardware-tune-cache install/check.sh verifies tune cache present + current | `modules/hardware-tune-cache/install/check.sh` | M00242 | non-negotiable | true | 10 |
| R02354 | hardware-tune-cache install/uninstall.sh removes tune cache cleanly | `modules/hardware-tune-cache/install/uninstall.sh` | M00243 | non-negotiable | true | 10 |
| R02355 | hardware-tune-cache module.toml manifest declares [requires_hardware] gate | `modules/hardware-tune-cache/module.toml` | M00244 | non-negotiable | false | 10 |
| R02356 | crates/selfdef-hardware exists | `crates/selfdef-hardware/` | M00239 | non-negotiable | false | 10 |
| R02357 | crates/selfdef-hardware/src/lib.rs is the canonical implementation entry point | `crates/selfdef-hardware/src/lib.rs` | M00239 | non-negotiable | false | 10 |
| R02358 | crates/selfdef-hardware provides host snapshot probe | `crates/selfdef-hardware/src/lib.rs` | M00239 | non-negotiable | false | 10 |
| R02359 | crates/selfdef-hardware provides capabilities derivation (HardwareCapabilities) | `crates/selfdef-hardware/src/lib.rs` | M00239 | non-negotiable | false | 10 |
| R02360 | crates/selfdef-hardware provides tune emission per C-4 | `crates/selfdef-hardware/src/lib.rs` | M00239 | non-negotiable | false | 10 |
| R02361 | crates/selfdef-hardware provides ThermalReading per C-3 | `crates/selfdef-hardware/src/lib.rs` | M00239 | non-negotiable | false | 10 |
| R02362 | Project boundary — sovereign-os Python consumers (R170/R172/R173/R177/R178/R179/R180/R181) read selfdef artifacts; they DO NOT import selfdef crate code | architecture | F01196 | non-negotiable | false | 10 |
| R02363 | Project boundary — selfdef NEVER imports sovereign-os crate code directly | architecture | F01195 | non-negotiable | false | 10 |
| R02364 | Project boundary — cross-repo binding only via documented capabilities JSON + Layer-B textfile metrics + MS007 typed mirrors | SDD-038 + MS007 | F01194 | non-negotiable | false | 10 |
| R02365 | Project boundary — Oracle-Triage (MS004 E0036) is the only runtime cross-repo bridge for selfdef events | MS004 E0036 + SDD-038 | E0109 | non-negotiable | false | 10 |
| R02366 | MS010 cycle 1 (SD-R14..R23) merged via PR #190 on 2026-05-16 | SDD-018 § header | F01198 | non-negotiable | false | 10 |
| R02367 | MS010 cycle 2 (SD-R24..R32) accumulating in PR #191 | SDD-018 § header | F01198 | non-negotiable | false | 10 |
| R02368 | check-hardware output — predicate citation format per skipped module is operator-readable | SDD-018 C-2 | F01108 | non-negotiable | false | 10 |
| R02369 | check-hardware output — kept modules include the reason they passed (informative) | SDD-018 C-2 | F01111 | non-negotiable | false | 10 |
| R02370 | Cross-repo agreement — selfdef SD-R14..R32 contract is the source of truth; sovereign-os mirrors derive from it | SDD-018 § Cross-repo bridge | E0109 | non-negotiable | false | 10 |
| R02371 | Layer-B textfile collector convention — metric names operator-stable across releases | SDD-018 C-3 | F01130 | non-negotiable | false | 10 |
| R02372 | Hardware probe single-pass — single I/O pass shared across modules + Layer-B + JSON export | SDD-018 D-4 + C-1 | E0102 | non-negotiable | false | 10 |
| R02373 | Hardware probe — operator can re-probe via fresh `selfdefctl modules apply` invocation | SDD-018 C-1 semantics | E0102 | non-negotiable | false | 10 |
| R02374 | Hardware probe — capabilities JSON at /var/lib/selfdef/hardware-capabilities.json (canonical path) | SDD-018 C-2 + SDD-017 § 7 | E0102 | non-negotiable | false | 10 |
| R02375 | Hardware probe — atomic write semantics (tempfile + rename) | SDD-018 C-4 + SDD-017 § 7 | F01142 | non-negotiable | false | 10 |
| R02376 | Module manifest schema — [requires_hardware] is the ONLY hardware-gating block | SDD-018 C-1 | E0102 | non-negotiable | false | 10 |
| R02377 | Module manifest schema — predicate set is closed (extension via SD-R26 / SD-R32 amendments only) | SDD-018 C-1 stability + SD-R26 + SD-R32 | E0102 | non-negotiable | false | 10 |
| R02378 | doctor row hardware.thermals integrates SD-R17 (per-sensor) + SD-R18 (severity-target-aware) | SDD-018 C-5 | F01151 | non-negotiable | false | 10 |
| R02379 | doctor row hardware.thermals — Ok detail format `count + min/max °C` | SDD-018 C-5 | F01152 | non-negotiable | false | 10 |
| R02380 | doctor row hardware.thermals — Warn is target-aware (sain01 only) | SDD-018 C-5 | F01154 | non-negotiable | false | 10 |
| R02381 | bitnet-gpu-inference demonstrator — 5-predicate at minimum (avx512_bf16 + gpu_count_min + sain01_verdict_min + gpu_vram_gib_min + gpu_power_headroom_watts_min, all SET non-default) | SDD-018 SD-R28 | F01160 | non-negotiable | false | 10 |
| R02382 | bitnet-gpu-inference schedule.json — consumed by sovereign-os R178 pick-gpu.py | SDD-018 SD-R28 + cross-repo R178 | F01168 | non-negotiable | false | 10 |
| R02383 | bitnet-gpu-inference schedule.json — schema versioned; selfdef + R178 stay in agreement | SDD-018 SD-R28 + cross-repo | F01168 | non-negotiable | false | 10 |
| R02384 | check-hardware HOST SNAPSHOT block (SD-R27) — operator-readable single-glance hardware summary at top of output | SDD-018 SD-R27 | F01159 | non-negotiable | false | 10 |
| R02385 | tune JSON — `zmm_512_preferred` boolean reflects D-6 gating outcome | SDD-018 C-4 | F01135 | non-negotiable | false | 10 |
| R02386 | tune JSON — `compile_flag_list` is the ordered detected `-mavx512*` flag list | SDD-018 C-4 | F01135 | non-negotiable | false | 10 |
| R02387 | thermals — nvidia-smi unavailable (no NVIDIA GPUs) → silently omit nvidia-gpu-* rows; hwmon rows still emitted | SDD-018 C-3 | F01120 | non-negotiable | false | 10 |
| R02388 | thermals — empty result possible (no sensors at all) → human format prints empty table; --json prints `[]`; Layer-B metric NOT emitted | SDD-018 C-3 | F01129 | non-negotiable | false | 10 |
| R02389 | tune emission — when avx512 absent, CFLAGS/KCFLAGS contain only `-march=<...>` (no AVX-512 flags, no ZMM hint) | SDD-018 C-4 + D-6 | F01141 | non-negotiable | false | 10 |
| R02390 | tune emission — when avx512 absent, AVX512_VNNI=false + AVX512_BF16=false | SDD-018 C-4 | F01139 + F01140 | non-negotiable | false | 10 |
| R02391 | tune emission — march "native" used as last-resort fallback when no specific march detected | SDD-018 C-4 + SDD-017 § 7 | F01136 | non-negotiable | false | 10 |
| R02392 | C-2 — schema_version is implicit 1 today; surface it explicitly in --json output when bumped | SDD-018 C-2 | F01113 | non-negotiable | false | 10 |
| R02393 | hardware-tune-cache module — at least one [requires_hardware] predicate set, demonstrating real-world usage | `modules/hardware-tune-cache/module.toml` + SDD-018 C-1 | M00244 | non-negotiable | false | 10 |
| R02394 | Cross-repo bridge — agreement maintenance is a doctrine, audited in MS009 phase-7/50-integration-audit per cycle | SDD-018 § Cross-repo bridge + MS009 phase-7 | E0109 | non-negotiable | false | 10 |
| R02395 | SDD-018 status = review when MS010 catalog is authored (Stage 2 — locked contracts) | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02396 | SDD-018 owner = operator-supervised; agent-authored | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02397 | SDD-018 last updated 2026-05-16 (cycle 2 amendment) | SDD-018 § header | E0101 | non-negotiable | false | 10 |
| R02398 | MS010 integrates with MS001 daemon + MS003 store/signing (capabilities JSON authoring) + MS006 functional modules (bitnet-gpu-inference / hardware-tune-cache) + MS007 typed mirrors (cross-repo binding) | MS001/MS003/MS006/MS007 | E0102 | non-negotiable | false | 10 |
| R02399 | MS010 integrates with MS009 audit cycles — phase-6/-7 crate audit covers selfdef-hardware; module audit covers hardware-tune-cache + bitnet-gpu-inference | MS009 phase-6/-7 | E0102 | non-negotiable | false | 10 |
| R02400 | Composite — MS010 closes the 4 SDD-018 problems via the 5 locked contracts (C-1..C-5) + 13 decisions (D-1..D-13) + 19 cross-repo bridge rows (SDD-017 §6/§7 + SD-R14/15/17/19/24/25/26/27/28/29/30/31/32 + 8 sovereign-os consumers R170/R172/R173/R177/R178/R179/R180/R181 + 3 fallbacks); 240 selfdef requirements in this milestone | SDD-018 entire document | E0102 + E0103 + E0104 + E0105 + E0106 + E0107 + E0108 + E0109 + E0110 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS009: 4320 + 2400 = 6720 sub-requirements when MS010 lands

## Cross-references

- Sister milestones: MS001 daemon core / MS002 collector fabric / MS003 correlator+store+responder+signing / MS004 14 integrations / MS005 notifier engine+orchestrator / MS006 14 functional modules (hardware-tune-cache + bitnet-gpu-inference are members) / MS007 8/8 typed mirrors / MS008 selfdef-on-SAIN-01 / MS009 audit cycles (phase-7 integration audit covers cross-repo)
- Sister sovereign-os hardware milestones: M005 hardware specs / M006 hardware exploit doctrine — cross-repo consumers R170..R181 live in sovereign-os repo
- Cross-repo binding doctrine: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md`
- SDD-017 (hardware inventory) — direct precursor to SDD-018 (this milestone)
- SDD-022 (hardware exploit doctrine) — derives compile-flag policy informing C-4 tune surface
