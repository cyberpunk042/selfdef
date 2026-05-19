# MS028 — BitNet GPU inference module

> Parent: `backlog/milestones/INDEX.md` row MS028 (source ref `modules/bitnet-gpu-inference` + dump 11187+ "1-bit / ternary ZMM utilization").
> Source: `modules/bitnet-gpu-inference/` (262 lines across module.toml + install/apply.sh + install/check.sh + install/uninstall.sh).
> All entries below extract verbatim. No invention.

## Epics (E0281–E0290)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0281 | Module identity — `bitnet-gpu-inference` v0.1.0, category=inference, summary "Provision the host for GPU-side BitNet ternary inference — runtime dir + env file + per-GPU schedule hints (SD-R28)"; ships SD-R28 deliverables (runtime.env + schedule.json + state dir) | `module.toml` 1–4 |
| E0282 | Module dependencies + surfaces — `depends_on = ["hardware-tune-cache"]` (consumes its env-file output) + `provides = ["bitnet-gpu-runtime"]` (the operator-facing per-GPU schedule + runtime env) + `consumes = ["hardware-tune-env"]` (the env-file surface hardware-tune-cache exposes) + `conflicts = []` + `requires = [{kind = "binary", value = "selfdefctl"}]` | `module.toml` 6–14 |
| E0283 | SD-R26 [requires_hardware] gates — "this module demonstrates the full power of the cycle-2 [requires_hardware] surface. It only lands on hosts where GPU-side ternary inference will actually run well": `avx512_bf16 = true` (BitNet kernels use BF16 for activation reduction) + `memory_gib_min = 32` (model staging + tokenizer requires headroom) + `gpu_count_min = 1` (at least one NVIDIA GPU available) + `gpu_vram_gib_min = 8` (smallest BitNet checkpoints worth running end-to-end take ≥8 GiB; smaller GPUs are CPU-fallback territory) + `gpu_power_headroom_watts_min = 100` (leave 100W cushion for scheduler; sustained loads on SAIN-01 RTX PRO 6000 + RTX 3090 pair commonly run at 60-80% of cap so this passes; on a 1-card box under load it correctly fails to land) | `module.toml` 16–37 |
| E0284 | SAIN-01 box behavior — RTX PRO 6000 98 GiB + RTX 3090 24 GiB: "all five predicates pass, and the apply.sh below pins a per-GPU schedule JSON into /etc/selfdef/bitnet/schedule.json (largest-VRAM GPU gets the model, secondary handles tokenization)"; 24-GiB-only host (RTX 3090): "vram + headroom gates still pass (single 24 GiB > 8 GiB), so it lands with the model on GPU 0" | `module.toml` 33–42 |
| E0285 | SD-R64 hardware-exploitation gates (master spec § 16) — `ternary_aot_capable_required = true` (bitnet.cpp ternary fast path; require host to expose AVX-512 VNNI + BF16 or FP16; "slightly stricter than the avx512_bf16-only predicate above"; "VNNI is what makes VPDPBUSD's INT8 dot product available") + `zmm_int8_lanes_min = 64` (explicit "I want the single-cycle 64×INT8 per ZMM register hot path"; "Operator-readable hardware-exploit declaration — matches the master spec § 16 framing verbatim") | `module.toml` 46–56 |
| E0286 | Module-system invariants — `instanced = false` + `phase = "main"` ("hardware-tune-cache (pre-phase) has already populated /etc/selfdef/hardware-tune.env by the time we run"); `[install] kind = "script"` + apply/check/uninstall paths | `module.toml` 58–65 |
| E0287 | apply.sh — provisions `/etc/selfdef/bitnet/` + `/var/lib/selfdef/bitnet/` with 2 outputs: `runtime.env` (sources hardware-tune.env + sets BITNET_STATE_DIR + BITNET_SCHEDULE_FILE + BITNET_THREADS — pinning sensible thread count from SELFDEF_HARDWARE_RECOMMENDED_THREADS or nproc fallback) + `schedule.json` (per-GPU scheduling map — derived from `selfdefctl hardware probe` so load lands on largest-VRAM card); idempotent + SELFDEF_DRY_RUN=1 aware; uses mktemp + atomic mv + chmod 0644 | `install/apply.sh` 1–135 |
| E0288 | schedule.json computation — uses selfdefctl's hardware export to get per-GPU caps; pipes caps JSON to python3 helper that ranks devices by `vram_bytes` descending; assigns 3 roles in priority order: `model_inference` (slot 0; largest VRAM) / `auxiliary` (slot 1) / `spare` (slot 2+); each schedule entry carries gpu_index + role + model_hint + vram_bytes + power_limit_watts; emits schema_version="1.0.0" + generated_at ISO-8601 + schedule array + rationale string; fail-soft fallback ("round-robin fallback") if caps_json empty OR python3 missing OR ranking fails | `install/apply.sh` 70–129 |
| E0289 | check.sh + uninstall.sh — check.sh verifies 4 artifacts (ETC_DIR exists / STATE_DIR exists / runtime.env exists / schedule.json exists); emits ok with "all artifacts present" or failed with "missing: <list>" + exit 1; uninstall.sh removes runtime.env + schedule.json + `rmdir "$ETC_DIR" 2>/dev/null || true` (prunes empty dir but ignores "not empty"; "operator may have other bitnet-* modules sharing the dir"); leaves STATE_DIR intact ("session caches + loaded model fingerprints live there; operators may want to keep them across re-applies"); DRY_RUN-aware | `install/check.sh` 1–31 + `install/uninstall.sh` 1–32 |
| E0290 | Cross-references — selfdef daemon binary `selfdefctl` is hard required (apply emits "failed" with "selfdefctl not on PATH" if missing); depends_on=hardware-tune-cache means MS010 hardware-aware-modules + tune-surface had already run via the [requires_hardware] cycle-2 surface (SD-R23 + SD-R26); SD-R28 deliverable; master spec § 16 (zmm_int8_lanes_min=64 verbatim framing); cross-module dependency chain: MS010 hardware-tune-cache (phase=pre) → MS028 bitnet-gpu-inference (phase=main) → bitnet.cpp ternary fast path consumes the per-GPU schedule | `module.toml` + cross-ref MS010 + master spec § 16 |

## Modules (M00707–M00732)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00707 | `module.toml` — 65-line manifest (cycle-2 [requires_hardware] + SD-R64 ternary gates + instanced=false + phase=main) | `module.toml` 1–65 | E0281 + E0283 + E0285 + E0286 |
| M00708 | `install/apply.sh` — 134-line idempotent provisioner (runtime.env + schedule.json + python3 helper + fallback) | `install/apply.sh` 1–134 | E0287 + E0288 |
| M00709 | `install/check.sh` — 31-line read-only verifier (4-artifact presence) | `install/check.sh` 1–31 | E0289 |
| M00710 | `install/uninstall.sh` — 32-line tear-down (preserves STATE_DIR) | `install/uninstall.sh` 1–32 | E0289 |
| M00711 | Provided surface — `bitnet-gpu-runtime` | `module.toml` 8 | E0282 |
| M00712 | Consumed surface — `hardware-tune-env` (from MS010 hardware-tune-cache) | `module.toml` 9 | E0282 |
| M00713 | Required binary — `selfdefctl` | `module.toml` 12 | E0282 |
| M00714 | Hardware gate — `avx512_bf16 = true` (BitNet uses BF16 for activation reduction) | `module.toml` 38 + 19 | E0283 |
| M00715 | Hardware gate — `memory_gib_min = 32` (model staging + tokenizer headroom) | `module.toml` 39 + 20 | E0283 |
| M00716 | Hardware gate — `gpu_count_min = 1` (NVIDIA GPU required) | `module.toml` 40 + 21 | E0283 |
| M00717 | Hardware gate — `gpu_vram_gib_min = 8` (smallest end-to-end BitNet checkpoints ≥8 GiB) | `module.toml` 41 + 22–24 | E0283 |
| M00718 | Hardware gate — `gpu_power_headroom_watts_min = 100` (100W scheduler cushion) | `module.toml` 42 + 25–30 | E0283 |
| M00719 | SD-R64 gate — `ternary_aot_capable_required = true` (AVX-512 VNNI + BF16 or FP16) | `module.toml` 54 + 46–51 | E0285 |
| M00720 | SD-R64 gate — `zmm_int8_lanes_min = 64` ("single-cycle 64×INT8 per ZMM register hot path") | `module.toml` 55 + 52–53 | E0285 |
| M00721 | Lifecycle phase — `phase = "main"` (after hardware-tune-cache pre-phase) | `module.toml` 62 | E0286 |
| M00722 | Single-instance — `instanced = false` | `module.toml` 58 | E0286 |
| M00723 | Output artifact — `runtime.env` at `${ETC_DIR}/runtime.env` (sources hardware-tune.env + BITNET_* paths) | `install/apply.sh` 25 + 44–67 | E0287 |
| M00724 | Output artifact — `schedule.json` at `${ETC_DIR}/schedule.json` (per-GPU role map) | `install/apply.sh` 26 + 70–131 | E0287 + E0288 |
| M00725 | Runtime knob — `BITNET_STATE_DIR` default `/var/lib/selfdef/bitnet` | `install/apply.sh` 60 | E0287 |
| M00726 | Runtime knob — `BITNET_SCHEDULE_FILE` default `${ETC_DIR}/schedule.json` | `install/apply.sh` 61 | E0287 |
| M00727 | Runtime knob — `BITNET_THREADS` (pinned from SELFDEF_HARDWARE_RECOMMENDED_THREADS or nproc) | `install/apply.sh` 64 | E0287 |
| M00728 | GPU roles — `model_inference` / `auxiliary` / `spare` (3-slot priority list) | `install/apply.sh` 105 | E0288 |
| M00729 | Ranking — devices sorted by `vram_bytes` descending; largest-VRAM gets model_inference | `install/apply.sh` 100–104 + 119–122 | E0288 |
| M00730 | schedule.json schema — schema_version "1.0.0" + generated_at ISO-8601 + schedule array (each entry: gpu_index + role + model_hint + vram_bytes + power_limit_watts) + rationale string | `install/apply.sh` 117–123 | E0288 |
| M00731 | Fallback — "capabilities export or python3 unavailable — round-robin fallback"; gpu_index 0 with role model_inference | `install/apply.sh` 81–88 | E0288 |
| M00732 | Uninstall scope — removes runtime.env + schedule.json; prunes empty ETC_DIR; leaves STATE_DIR intact for session caches + loaded model fingerprints | `install/uninstall.sh` 3–6 + 28–31 | E0289 |

## Features (F03241–F03360)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03241 | module.toml `name = "bitnet-gpu-inference"` | `module.toml` 1 | M00707 |
| F03242 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00707 |
| F03243 | module.toml summary mentions SD-R28 | `module.toml` 3 | M00707 |
| F03244 | module.toml summary — "Provision the host for GPU-side BitNet ternary inference" | `module.toml` 3 | M00707 |
| F03245 | module.toml summary — "runtime dir + env file + per-GPU schedule hints" | `module.toml` 3 | M00707 |
| F03246 | module.toml `category = "inference"` | `module.toml` 4 | M00707 |
| F03247 | module.toml `depends_on = ["hardware-tune-cache"]` | `module.toml` 6 | M00712 |
| F03248 | module.toml `conflicts = []` | `module.toml` 7 | M00707 |
| F03249 | module.toml `provides = ["bitnet-gpu-runtime"]` | `module.toml` 8 | M00711 |
| F03250 | module.toml `consumes = ["hardware-tune-env"]` | `module.toml` 9 | M00712 |
| F03251 | module.toml `requires` — binary selfdefctl | `module.toml` 12 | M00713 |
| F03252 | module.toml SD-R26 doctrine — "this module demonstrates the full power of the cycle-2 [requires_hardware] surface" | `module.toml` 16–17 | E0283 |
| F03253 | module.toml SD-R26 doctrine — "only lands on hosts where GPU-side ternary inference will actually run well" | `module.toml` 17–18 | E0283 |
| F03254 | Hardware gate avx512_bf16 = true | `module.toml` 38 | M00714 |
| F03255 | Hardware gate rationale — "BitNet kernels use BF16 for activation reduction" | `module.toml` 19 | M00714 |
| F03256 | Hardware gate memory_gib_min = 32 | `module.toml` 39 | M00715 |
| F03257 | Hardware gate rationale — "model staging + tokenizer requires headroom" | `module.toml` 20 | M00715 |
| F03258 | Hardware gate gpu_count_min = 1 | `module.toml` 40 | M00716 |
| F03259 | Hardware gate rationale — "at least one NVIDIA GPU available" | `module.toml` 21 | M00716 |
| F03260 | Hardware gate gpu_vram_gib_min = 8 | `module.toml` 41 | M00717 |
| F03261 | Hardware gate rationale — "smallest BitNet checkpoints worth running end-to-end take >= 8 GiB" | `module.toml` 22–23 | M00717 |
| F03262 | Hardware gate rationale — "smaller GPUs are CPU-fallback territory" | `module.toml` 24 | M00717 |
| F03263 | Hardware gate gpu_power_headroom_watts_min = 100 | `module.toml` 42 | M00718 |
| F03264 | Hardware gate rationale — "leave a 100 W cushion for the scheduler" | `module.toml` 25 | M00718 |
| F03265 | Hardware gate rationale — "sustained loads on SAIN-01 RTX PRO 6000 + RTX 3090 pair commonly run at 60-80% of cap so this passes" | `module.toml` 26–28 | M00718 |
| F03266 | Hardware gate rationale — "on a 1-card box under load it correctly fails to land" | `module.toml` 29–30 | M00718 |
| F03267 | SAIN-01 — RTX PRO 6000 98 GiB + RTX 3090 24 GiB all 5 predicates pass | `module.toml` 32–33 | E0284 |
| F03268 | SAIN-01 — apply pins schedule.json into /etc/selfdef/bitnet/schedule.json | `module.toml` 34 | E0284 |
| F03269 | SAIN-01 — largest-VRAM GPU gets the model | `module.toml` 35 | E0284 |
| F03270 | SAIN-01 — secondary handles tokenization | `module.toml` 35 | E0284 |
| F03271 | 24-GiB-only — vram + headroom gates pass (single 24 GiB > 8 GiB threshold) | `module.toml` 37–38 | E0284 |
| F03272 | 24-GiB-only — lands with model on GPU 0 | `module.toml` 38 | E0284 |
| F03273 | SD-R64 gate — ternary_aot_capable_required = true | `module.toml` 54 | M00719 |
| F03274 | SD-R64 rationale — "this module runs the bitnet.cpp ternary fast path" | `module.toml` 46–47 | M00719 |
| F03275 | SD-R64 rationale — "require the host to expose AVX-512 VNNI + (BF16 or FP16)" | `module.toml` 48 | M00719 |
| F03276 | SD-R64 rationale — "Slightly stricter than the avx512_bf16-only predicate above" | `module.toml` 49 | M00719 |
| F03277 | SD-R64 rationale — "VNNI is what makes VPDPBUSD's INT8 dot product available" | `module.toml` 50 | M00719 |
| F03278 | SD-R64 gate — zmm_int8_lanes_min = 64 | `module.toml` 55 | M00720 |
| F03279 | SD-R64 rationale — explicit "I want the single-cycle 64×INT8 per ZMM register hot path" | `module.toml` 51–52 | M00720 |
| F03280 | SD-R64 rationale — "Operator-readable hardware-exploit declaration" | `module.toml` 52 | M00720 |
| F03281 | SD-R64 rationale — "matches the master spec § 16 framing verbatim" | `module.toml` 53 | M00720 |
| F03282 | module.toml `instanced = false` | `module.toml` 58 | M00722 |
| F03283 | module.toml `phase = "main"` | `module.toml` 62 | M00721 |
| F03284 | Phase rationale — "hardware-tune-cache (pre-phase) has already populated /etc/selfdef/hardware-tune.env by the time we run" | `module.toml` 60–61 | M00721 |
| F03285 | module.toml `[install] kind = "script"` | `module.toml` 64 | M00707 |
| F03286 | module.toml apply = "install/apply.sh" | `module.toml` 65 | M00708 |
| F03287 | module.toml check = "install/check.sh" | `module.toml` 65 | M00709 |
| F03288 | module.toml uninstall = "install/uninstall.sh" | `module.toml` 65 | M00710 |
| F03289 | apply.sh header — provisions /etc/selfdef/bitnet/ + /var/lib/selfdef/bitnet/ | `install/apply.sh` 4 | M00708 |
| F03290 | apply.sh output — runtime.env (sources hardware-tune.env + sets BITNET_* paths) | `install/apply.sh` 5 | M00723 |
| F03291 | apply.sh output — schedule.json (per-GPU scheduling map) | `install/apply.sh` 6 | M00724 |
| F03292 | apply.sh schedule.json — derived from `selfdefctl hardware probe` | `install/apply.sh` 7 | M00724 |
| F03293 | apply.sh schedule.json — load lands on largest-VRAM card | `install/apply.sh` 8 | M00729 |
| F03294 | apply.sh — idempotent | `install/apply.sh` 10 | M00708 |
| F03295 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 10 | M00708 |
| F03296 | apply.sh MUST set -euo pipefail | `install/apply.sh` 12 | M00708 |
| F03297 | apply.sh MODULE = "bitnet-gpu-inference" | `install/apply.sh` 14 | M00708 |
| F03298 | apply.sh local emit_status helper (no external lib dependency) | `install/apply.sh` 16–21 | M00708 |
| F03299 | apply.sh — ETC_DIR override via SELFDEF_BITNET_ETC_DIR default /etc/selfdef/bitnet | `install/apply.sh` 23 | M00708 |
| F03300 | apply.sh — STATE_DIR override via SELFDEF_BITNET_STATE_DIR default /var/lib/selfdef/bitnet | `install/apply.sh` 24 | M00708 |
| F03301 | apply.sh — ENV_FILE = ${ETC_DIR}/runtime.env | `install/apply.sh` 25 | M00723 |
| F03302 | apply.sh — SCHEDULE_FILE = ${ETC_DIR}/schedule.json | `install/apply.sh` 26 | M00724 |
| F03303 | apply.sh — TUNE_FILE override via SELFDEF_HARDWARE_TUNE_ENV default /etc/selfdef/hardware-tune.env | `install/apply.sh` 27 | M00712 |
| F03304 | apply.sh — DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 29 | M00708 |
| F03305 | apply.sh — selfdefctl PATH check (die with "selfdefctl not on PATH" if missing) | `install/apply.sh` 31–34 | M00713 |
| F03306 | apply.sh — DRY_RUN=1 short-circuits with skipped status | `install/apply.sh` 36–39 | M00708 |
| F03307 | apply.sh — mkdir -p ETC_DIR STATE_DIR with chmod 0755 | `install/apply.sh` 41–42 | M00708 |
| F03308 | apply.sh — atomic env-file write via mktemp + trap rm + mv -f | `install/apply.sh` 44–66 | M00723 |
| F03309 | apply.sh — env file generated-by header with ISO timestamp + module name | `install/apply.sh` 48–50 | M00723 |
| F03310 | apply.sh — env file sources TUNE_FILE if readable | `install/apply.sh` 52–54 | M00712 |
| F03311 | apply.sh — env file warns if TUNE_FILE missing ("run selfdefctl modules apply --only hardware-tune-cache") | `install/apply.sh` 55–57 | M00712 |
| F03312 | apply.sh — env file pins BITNET_STATE_DIR | `install/apply.sh` 60 | M00725 |
| F03313 | apply.sh — env file pins BITNET_SCHEDULE_FILE | `install/apply.sh` 61 | M00726 |
| F03314 | apply.sh — env file pins BITNET_THREADS (SELFDEF_HARDWARE_RECOMMENDED_THREADS or nproc) | `install/apply.sh` 64 | M00727 |
| F03315 | apply.sh — env file mode 0644 | `install/apply.sh` 67 | M00708 |
| F03316 | apply.sh — schedule.json atomic write via mktemp + trap rm + mv -f | `install/apply.sh` 73–130 | M00724 |
| F03317 | apply.sh — caps_json from `selfdefctl hardware export --stdout` | `install/apply.sh` 78 | M00724 |
| F03318 | apply.sh — fallback if caps_json empty | `install/apply.sh` 91–93 | M00731 |
| F03319 | apply.sh — fallback if python3 missing | `install/apply.sh` 91–93 | M00731 |
| F03320 | apply.sh — fallback rationale "capabilities export or python3 unavailable — round-robin fallback" | `install/apply.sh` 86 | M00731 |
| F03321 | apply.sh — fallback schedule has single entry gpu_index=0 role=model_inference | `install/apply.sh` 85 | M00731 |
| F03322 | apply.sh — python3 helper loads JSON via sys.stdin.read | `install/apply.sh` 98 | M00729 |
| F03323 | apply.sh — python3 helper reads (caps.get("gpu") or {}).get("devices", []) or [] | `install/apply.sh` 99 | M00729 |
| F03324 | apply.sh — python3 helper sorts by vram_bytes descending | `install/apply.sh` 100–104 | M00729 |
| F03325 | apply.sh — roles list ["model_inference", "auxiliary", "spare"] | `install/apply.sh` 105 | M00728 |
| F03326 | apply.sh — schedule entry carries gpu_index | `install/apply.sh` 110 | M00730 |
| F03327 | apply.sh — schedule entry carries role | `install/apply.sh` 110 | M00730 |
| F03328 | apply.sh — schedule entry carries model_hint | `install/apply.sh` 111 | M00730 |
| F03329 | apply.sh — schedule entry carries vram_bytes | `install/apply.sh` 112 | M00730 |
| F03330 | apply.sh — schedule entry carries power_limit_watts | `install/apply.sh` 113 | M00730 |
| F03331 | apply.sh — doc schema_version "1.0.0" | `install/apply.sh` 117 | M00730 |
| F03332 | apply.sh — doc generated_at ISO-8601 UTC | `install/apply.sh` 118 | M00730 |
| F03333 | apply.sh — doc rationale "ranked N GPU(s) by VRAM; largest-first wins model_inference" | `install/apply.sh` 121 | M00730 |
| F03334 | apply.sh — schedule file mode 0644 | `install/apply.sh` 131 | M00724 |
| F03335 | apply.sh — final emit_status "ok" "provisioned ${ETC_DIR}/{runtime.env,schedule.json}" | `install/apply.sh` 134 | M00708 |
| F03336 | check.sh header — verifies apply produced expected artifacts (read-only) | `install/check.sh` 3 | M00709 |
| F03337 | check.sh MUST set -euo pipefail | `install/check.sh` 5 | M00709 |
| F03338 | check.sh MODULE = "bitnet-gpu-inference" | `install/check.sh` 7 | M00709 |
| F03339 | check.sh probe — ETC_DIR exists | `install/check.sh` 19 | M00709 |
| F03340 | check.sh probe — STATE_DIR exists | `install/check.sh` 20 | M00709 |
| F03341 | check.sh probe — runtime.env file exists | `install/check.sh` 21 | M00709 |
| F03342 | check.sh probe — schedule.json file exists | `install/check.sh` 22 | M00709 |
| F03343 | check.sh — emit_status "ok" "all artifacts present" + exit 0 | `install/check.sh` 24–27 | M00709 |
| F03344 | check.sh — emit_status "failed" "missing: <list>" + exit 1 | `install/check.sh` 29–30 | M00709 |
| F03345 | uninstall.sh header — removes runtime.env + schedule.json | `install/uninstall.sh` 3 | M00710 |
| F03346 | uninstall.sh — leaves STATE_DIR intact ("session caches + loaded model fingerprints live there") | `install/uninstall.sh` 4–6 | M00732 |
| F03347 | uninstall.sh — STATE_DIR preserved for re-applies | `install/uninstall.sh` 5–6 | M00732 |
| F03348 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 8 | M00710 |
| F03349 | uninstall.sh MODULE = "bitnet-gpu-inference" | `install/uninstall.sh` 10 | M00710 |
| F03350 | uninstall.sh local emit_status helper | `install/uninstall.sh` 14–19 | M00710 |
| F03351 | uninstall.sh — DRY_RUN-aware (skipped status) | `install/uninstall.sh` 22–25 | M00710 |
| F03352 | uninstall.sh — rm -f runtime.env + schedule.json | `install/uninstall.sh` 27 | M00710 |
| F03353 | uninstall.sh — rmdir ETC_DIR 2>/dev/null || true (tolerates "not empty") | `install/uninstall.sh` 30 | M00732 |
| F03354 | uninstall.sh — rationale "operator may have other bitnet-* modules sharing the dir" | `install/uninstall.sh` 29 | M00732 |
| F03355 | uninstall.sh — emit_status "ok" "removed runtime.env + schedule.json from ${ETC_DIR}" | `install/uninstall.sh` 32 | M00710 |
| F03356 | Cross-module dependency — MS010 hardware-tune-cache provides `hardware-tune-env` surface consumed by this module | `module.toml` 6 + 9 + cross-ref MS010 | M00712 |
| F03357 | Cross-module — MS010 [requires_hardware] cycle-2 surface implementation matches this module's gates (SD-R23 + SD-R26) | `module.toml` 16–17 + cross-ref MS010 | E0283 |
| F03358 | Cross-module — bitnet.cpp ternary fast path is the consumer of the per-GPU schedule | `module.toml` 47 | M00719 |
| F03359 | Cross-module — master spec § 16 zmm_int8_lanes_min=64 framing | `module.toml` 53 | M00720 |
| F03360 | Cross-module — VPDPBUSD INT8 dot product instruction is the hardware-exploit target | `module.toml` 50 | M00719 |

## Requirements (R06481–R06720)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R06481 | Module name MUST be `bitnet-gpu-inference` | `module.toml` 1 | F03241 | non-negotiable | false | 10 |
| R06482 | Module version MUST be 0.1.0 | `module.toml` 2 | F03242 | non-negotiable | false | 10 |
| R06483 | Module summary references SD-R28 | `module.toml` 3 | F03243 | non-negotiable | false | 10 |
| R06484 | Module summary — "Provision the host for GPU-side BitNet ternary inference" | `module.toml` 3 | F03244 | non-negotiable | false | 10 |
| R06485 | Module summary — "runtime dir + env file + per-GPU schedule hints" | `module.toml` 3 | F03245 | non-negotiable | false | 10 |
| R06486 | Module category MUST be `inference` | `module.toml` 4 | F03246 | non-negotiable | false | 10 |
| R06487 | Module SHALL declare depends_on = ["hardware-tune-cache"] | `module.toml` 6 | F03247 | non-negotiable | false | 10 |
| R06488 | Module SHALL declare conflicts = [] | `module.toml` 7 | F03248 | non-negotiable | false | 10 |
| R06489 | Module SHALL provide `bitnet-gpu-runtime` surface | `module.toml` 8 | F03249 | non-negotiable | false | 10 |
| R06490 | Module SHALL consume `hardware-tune-env` surface | `module.toml` 9 | F03250 | non-negotiable | false | 10 |
| R06491 | Required binary — selfdefctl | `module.toml` 12 | F03251 | non-negotiable | false | 10 |
| R06492 | SD-R26 doctrine — "this module demonstrates the full power of the cycle-2 [requires_hardware] surface" | `module.toml` 16–17 | F03252 | non-negotiable | false | 10 |
| R06493 | SD-R26 doctrine — "only lands on hosts where GPU-side ternary inference will actually run well" | `module.toml` 17–18 | F03253 | non-negotiable | false | 10 |
| R06494 | Hardware gate — avx512_bf16 = true | `module.toml` 38 | F03254 | non-negotiable | false | 10 |
| R06495 | Hardware gate rationale — "BitNet kernels use BF16 for activation reduction" | `module.toml` 19 | F03255 | non-negotiable | false | 10 |
| R06496 | Hardware gate — memory_gib_min = 32 | `module.toml` 39 | F03256 | non-negotiable | false | 10 |
| R06497 | Hardware gate rationale — "model staging + tokenizer requires headroom" | `module.toml` 20 | F03257 | non-negotiable | false | 10 |
| R06498 | Hardware gate — gpu_count_min = 1 | `module.toml` 40 | F03258 | non-negotiable | false | 10 |
| R06499 | Hardware gate rationale — "at least one NVIDIA GPU available" | `module.toml` 21 | F03259 | non-negotiable | false | 10 |
| R06500 | Hardware gate — gpu_vram_gib_min = 8 | `module.toml` 41 | F03260 | non-negotiable | false | 10 |
| R06501 | Hardware gate rationale — "smallest BitNet checkpoints worth running end-to-end take >= 8 GiB" | `module.toml` 22–23 | F03261 | non-negotiable | false | 10 |
| R06502 | Hardware gate rationale — "smaller GPUs are CPU-fallback territory" | `module.toml` 24 | F03262 | non-negotiable | false | 10 |
| R06503 | Hardware gate — gpu_power_headroom_watts_min = 100 | `module.toml` 42 | F03263 | non-negotiable | false | 10 |
| R06504 | Hardware gate rationale — "leave a 100 W cushion for the scheduler" | `module.toml` 25 | F03264 | non-negotiable | false | 10 |
| R06505 | Hardware gate rationale — "sustained loads on SAIN-01 RTX PRO 6000 + RTX 3090 pair commonly run at 60-80% of cap" | `module.toml` 26–27 | F03265 | non-negotiable | false | 10 |
| R06506 | Hardware gate rationale — "this passes" on SAIN-01 box | `module.toml` 28 | F03265 | non-negotiable | false | 10 |
| R06507 | Hardware gate rationale — "on a 1-card box under load it correctly fails to land" | `module.toml` 29–30 | F03266 | non-negotiable | false | 10 |
| R06508 | SAIN-01 box — RTX PRO 6000 has 98 GiB VRAM | `module.toml` 32 | F03267 | non-negotiable | false | 10 |
| R06509 | SAIN-01 box — RTX 3090 has 24 GiB VRAM | `module.toml` 32 | F03267 | non-negotiable | false | 10 |
| R06510 | SAIN-01 box — all 5 predicates pass | `module.toml` 33 | F03267 | non-negotiable | false | 10 |
| R06511 | SAIN-01 box — apply.sh pins per-GPU schedule JSON to /etc/selfdef/bitnet/schedule.json | `module.toml` 34 | F03268 | non-negotiable | false | 10 |
| R06512 | SAIN-01 box — largest-VRAM GPU gets the model | `module.toml` 35 | F03269 | non-negotiable | false | 10 |
| R06513 | SAIN-01 box — secondary handles tokenization | `module.toml` 35 | F03270 | non-negotiable | false | 10 |
| R06514 | 24-GiB-only host — vram + headroom gates pass (single 24 GiB > 8 GiB) | `module.toml` 37–38 | F03271 | non-negotiable | false | 10 |
| R06515 | 24-GiB-only host — lands with the model on GPU 0 | `module.toml` 38 | F03272 | non-negotiable | false | 10 |
| R06516 | SD-R64 gate — ternary_aot_capable_required = true | `module.toml` 54 | F03273 | non-negotiable | false | 10 |
| R06517 | SD-R64 rationale — "this module runs the bitnet.cpp ternary fast path" | `module.toml` 46–47 | F03274 | non-negotiable | false | 10 |
| R06518 | SD-R64 rationale — "require the host to expose AVX-512 VNNI" | `module.toml` 48 | F03275 | non-negotiable | false | 10 |
| R06519 | SD-R64 rationale — "+ BF16 or FP16" | `module.toml` 48 | F03275 | non-negotiable | false | 10 |
| R06520 | SD-R64 rationale — "Slightly stricter than the avx512_bf16-only predicate above" | `module.toml` 49 | F03276 | non-negotiable | false | 10 |
| R06521 | SD-R64 rationale — "VNNI is what makes VPDPBUSD's INT8 dot product available" | `module.toml` 50 | F03277 | non-negotiable | false | 10 |
| R06522 | SD-R64 gate — zmm_int8_lanes_min = 64 | `module.toml` 55 | F03278 | non-negotiable | false | 10 |
| R06523 | SD-R64 rationale — explicit "I want the single-cycle 64×INT8 per ZMM register hot path" | `module.toml` 51 | F03279 | non-negotiable | false | 10 |
| R06524 | SD-R64 rationale — "Operator-readable hardware-exploit declaration" | `module.toml` 52 | F03280 | non-negotiable | false | 10 |
| R06525 | SD-R64 rationale — "matches the master spec § 16 framing verbatim" | `module.toml` 53 | F03281 | non-negotiable | false | 10 |
| R06526 | Module SHALL declare instanced = false | `module.toml` 58 | F03282 | non-negotiable | false | 10 |
| R06527 | Module SHALL declare phase = "main" | `module.toml` 62 | F03283 | non-negotiable | false | 10 |
| R06528 | Phase rationale — "hardware-tune-cache (pre-phase) has already populated /etc/selfdef/hardware-tune.env by the time we run" | `module.toml` 60–61 | F03284 | non-negotiable | false | 10 |
| R06529 | [install] kind = "script" | `module.toml` 64 | F03285 | non-negotiable | false | 10 |
| R06530 | apply = "install/apply.sh" | `module.toml` 65 | F03286 | non-negotiable | false | 10 |
| R06531 | check = "install/check.sh" | `module.toml` 65 | F03287 | non-negotiable | false | 10 |
| R06532 | uninstall = "install/uninstall.sh" | `module.toml` 65 | F03288 | non-negotiable | false | 10 |
| R06533 | apply.sh header — references SD-R28 | `install/apply.sh` 2 | F03289 | non-negotiable | false | 10 |
| R06534 | apply.sh — provisions /etc/selfdef/bitnet/ | `install/apply.sh` 4 | F03289 | non-negotiable | false | 10 |
| R06535 | apply.sh — provisions /var/lib/selfdef/bitnet/ | `install/apply.sh` 4 | F03289 | non-negotiable | false | 10 |
| R06536 | apply.sh — runtime.env sources hardware-tune.env | `install/apply.sh` 5 | F03290 | non-negotiable | false | 10 |
| R06537 | apply.sh — runtime.env sets BITNET_* paths | `install/apply.sh` 5 | F03290 | non-negotiable | false | 10 |
| R06538 | apply.sh — schedule.json is per-GPU scheduling map | `install/apply.sh` 6 | F03291 | non-negotiable | false | 10 |
| R06539 | apply.sh — schedule.json says which GPU hosts which stage | `install/apply.sh` 7 | F03291 | non-negotiable | false | 10 |
| R06540 | apply.sh — schedule derived from `selfdefctl hardware probe` | `install/apply.sh` 7 | F03292 | non-negotiable | false | 10 |
| R06541 | apply.sh — load lands on largest-VRAM card | `install/apply.sh` 8 | F03293 | non-negotiable | false | 10 |
| R06542 | apply.sh — idempotent | `install/apply.sh` 10 | F03294 | non-negotiable | false | 10 |
| R06543 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 10 | F03295 | non-negotiable | false | 10 |
| R06544 | apply.sh MUST set -euo pipefail | `install/apply.sh` 12 | F03296 | non-negotiable | false | 10 |
| R06545 | apply.sh MODULE = "bitnet-gpu-inference" | `install/apply.sh` 14 | F03297 | non-negotiable | false | 10 |
| R06546 | apply.sh — local emit_status helper (NOT shared lib) | `install/apply.sh` 16–21 | F03298 | non-negotiable | false | 10 |
| R06547 | apply.sh — emit_status JSON format `{"module":"%s","status":"%s","message":"%s"}` | `install/apply.sh` 19 | F03298 | non-negotiable | false | 10 |
| R06548 | apply.sh — ETC_DIR default /etc/selfdef/bitnet | `install/apply.sh` 23 | F03299 | non-negotiable | false | 10 |
| R06549 | apply.sh — ETC_DIR override via SELFDEF_BITNET_ETC_DIR env | `install/apply.sh` 23 | F03299 | non-negotiable | false | 10 |
| R06550 | apply.sh — STATE_DIR default /var/lib/selfdef/bitnet | `install/apply.sh` 24 | F03300 | non-negotiable | false | 10 |
| R06551 | apply.sh — STATE_DIR override via SELFDEF_BITNET_STATE_DIR env | `install/apply.sh` 24 | F03300 | non-negotiable | false | 10 |
| R06552 | apply.sh — ENV_FILE = ${ETC_DIR}/runtime.env | `install/apply.sh` 25 | F03301 | non-negotiable | false | 10 |
| R06553 | apply.sh — SCHEDULE_FILE = ${ETC_DIR}/schedule.json | `install/apply.sh` 26 | F03302 | non-negotiable | false | 10 |
| R06554 | apply.sh — TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 27 | F03303 | non-negotiable | false | 10 |
| R06555 | apply.sh — TUNE_FILE override via SELFDEF_HARDWARE_TUNE_ENV env | `install/apply.sh` 27 | F03303 | non-negotiable | false | 10 |
| R06556 | apply.sh — DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 29 | F03304 | non-negotiable | false | 10 |
| R06557 | apply.sh — selfdefctl PATH check | `install/apply.sh` 31 | F03305 | non-negotiable | false | 10 |
| R06558 | apply.sh — selfdefctl missing → emit failed "selfdefctl not on PATH" + exit 1 | `install/apply.sh` 32–33 | F03305 | non-negotiable | false | 10 |
| R06559 | apply.sh — DRY_RUN=1 short-circuits with skipped "DRY-RUN — would provision ${ETC_DIR} + ${STATE_DIR}" | `install/apply.sh` 36–38 | F03306 | non-negotiable | false | 10 |
| R06560 | apply.sh — mkdir -p ETC_DIR + STATE_DIR | `install/apply.sh` 41 | F03307 | non-negotiable | false | 10 |
| R06561 | apply.sh — chmod 0755 on both dirs | `install/apply.sh` 42 | F03307 | non-negotiable | false | 10 |
| R06562 | apply.sh — env-file write via mktemp pattern (atomic) | `install/apply.sh` 45 | F03308 | non-negotiable | false | 10 |
| R06563 | apply.sh — trap rm tmp_env on EXIT | `install/apply.sh` 46 | F03308 | non-negotiable | false | 10 |
| R06564 | apply.sh — atomic mv -f tmp_env ENV_FILE | `install/apply.sh` 66 | F03308 | non-negotiable | false | 10 |
| R06565 | apply.sh — env file header "# /etc/selfdef/bitnet/runtime.env" | `install/apply.sh` 48 | F03309 | non-negotiable | false | 10 |
| R06566 | apply.sh — env file header includes ISO timestamp via `date -u --iso-8601=seconds` | `install/apply.sh` 49 | F03309 | non-negotiable | false | 10 |
| R06567 | apply.sh — env file header includes "Generated by selfdef module bitnet-gpu-inference (SD-R28)" | `install/apply.sh` 49 | F03309 | non-negotiable | false | 10 |
| R06568 | apply.sh — env file header includes "Re-run `selfdefctl modules apply` to refresh" | `install/apply.sh` 50 | F03309 | non-negotiable | false | 10 |
| R06569 | apply.sh — env file sources TUNE_FILE if readable | `install/apply.sh` 52–54 | F03310 | non-negotiable | false | 10 |
| R06570 | apply.sh — env file sources via `. "${TUNE_FILE}"` | `install/apply.sh` 54 | F03310 | non-negotiable | false | 10 |
| R06571 | apply.sh — TUNE_FILE source comment references SD-R23 (hardware-tune-cache) | `install/apply.sh` 53 | F03310 | non-negotiable | false | 10 |
| R06572 | apply.sh — env file warns "WARN: ${TUNE_FILE} not found" if not readable | `install/apply.sh` 56 | F03311 | non-negotiable | false | 10 |
| R06573 | apply.sh — env file warn message includes "run `selfdefctl modules apply --only hardware-tune-cache`" | `install/apply.sh` 56 | F03311 | non-negotiable | false | 10 |
| R06574 | apply.sh — env file pins BITNET_STATE_DIR="${STATE_DIR}" | `install/apply.sh` 60 | F03312 | non-negotiable | false | 10 |
| R06575 | apply.sh — env file pins BITNET_SCHEDULE_FILE="${SCHEDULE_FILE}" | `install/apply.sh` 61 | F03313 | non-negotiable | false | 10 |
| R06576 | apply.sh — env file pins BITNET_THREADS with SELFDEF_HARDWARE_RECOMMENDED_THREADS fallback | `install/apply.sh` 64 | F03314 | non-negotiable | false | 10 |
| R06577 | apply.sh — env file pins BITNET_THREADS with nproc fallback | `install/apply.sh` 64 | F03314 | non-negotiable | false | 10 |
| R06578 | apply.sh — env file mode 0644 | `install/apply.sh` 67 | F03315 | non-negotiable | false | 10 |
| R06579 | apply.sh — clear EXIT trap after env write | `install/apply.sh` 68 | F03308 | non-negotiable | false | 10 |
| R06580 | apply.sh — schedule.json header comment "per-GPU role assignment" | `install/apply.sh` 70 | F03291 | non-negotiable | false | 10 |
| R06581 | apply.sh — schedule.json rationale "probe JSON carries per-device VRAM (SD-R25)" | `install/apply.sh` 71 | F03291 | non-negotiable | false | 10 |
| R06582 | apply.sh — largest GPU hosts the model | `install/apply.sh` 71–72 | F03293 | non-negotiable | false | 10 |
| R06583 | apply.sh — secondary handles auxiliary work (tokenizer / embedding / TTS) | `install/apply.sh` 72 | F03291 | non-negotiable | false | 10 |
| R06584 | apply.sh — schedule.json write via mktemp + atomic mv | `install/apply.sh` 73–74 + 130 | F03316 | non-negotiable | false | 10 |
| R06585 | apply.sh — schedule.json trap rm tmp_sched on EXIT | `install/apply.sh` 74 | F03316 | non-negotiable | false | 10 |
| R06586 | apply.sh — caps_json from `selfdefctl hardware export --stdout 2>/dev/null` | `install/apply.sh` 78 | F03317 | non-negotiable | false | 10 |
| R06587 | apply.sh — caps_json fail-soft via `|| true` | `install/apply.sh` 78 | F03317 | non-negotiable | false | 10 |
| R06588 | apply.sh — fallback path when caps_json empty | `install/apply.sh` 91 | F03318 | non-negotiable | false | 10 |
| R06589 | apply.sh — fallback path when python3 not on PATH | `install/apply.sh` 91 | F03319 | non-negotiable | false | 10 |
| R06590 | apply.sh — fallback rationale string "capabilities export or python3 unavailable — round-robin fallback" | `install/apply.sh` 86 | F03320 | non-negotiable | false | 10 |
| R06591 | apply.sh — fallback schedule single entry gpu_index=0 role=model_inference | `install/apply.sh` 85 | F03321 | non-negotiable | false | 10 |
| R06592 | apply.sh — fallback schema_version "1.0.0" | `install/apply.sh` 84 | M00731 | non-negotiable | false | 10 |
| R06593 | apply.sh — python3 helper reads sys.stdin.read() | `install/apply.sh` 98 | F03322 | non-negotiable | false | 10 |
| R06594 | apply.sh — python3 helper reads (caps.get("gpu") or {}).get("devices", []) or [] | `install/apply.sh` 99 | F03323 | non-negotiable | false | 10 |
| R06595 | apply.sh — python3 helper enumerates and sorts devices by `vram_bytes` descending | `install/apply.sh` 100–104 | F03324 | non-negotiable | false | 10 |
| R06596 | apply.sh — sorted ranked list — `key=lambda kv: (kv[1].get("vram_bytes") or 0)` + reverse=True | `install/apply.sh` 102–103 | F03324 | non-negotiable | false | 10 |
| R06597 | apply.sh — roles list = ["model_inference", "auxiliary", "spare"] | `install/apply.sh` 105 | F03325 | non-negotiable | false | 10 |
| R06598 | apply.sh — role assignment by slot position; slot >= len(roles) → "spare" | `install/apply.sh` 108 | M00728 | non-negotiable | false | 10 |
| R06599 | apply.sh — schedule entry field — gpu_index | `install/apply.sh` 110 | F03326 | non-negotiable | false | 10 |
| R06600 | apply.sh — schedule entry field — role | `install/apply.sh` 110 | F03327 | non-negotiable | false | 10 |
| R06601 | apply.sh — schedule entry field — model_hint | `install/apply.sh` 111 | F03328 | non-negotiable | false | 10 |
| R06602 | apply.sh — schedule entry field — vram_bytes | `install/apply.sh` 112 | F03329 | non-negotiable | false | 10 |
| R06603 | apply.sh — schedule entry field — power_limit_watts | `install/apply.sh` 113 | F03330 | non-negotiable | false | 10 |
| R06604 | apply.sh — doc schema_version "1.0.0" | `install/apply.sh` 117 | F03331 | non-negotiable | false | 10 |
| R06605 | apply.sh — doc generated_at ISO-8601 UTC ("Z" suffix) | `install/apply.sh` 118 | F03332 | non-negotiable | false | 10 |
| R06606 | apply.sh — doc rationale "ranked N GPU(s) by VRAM; largest-first wins model_inference" | `install/apply.sh` 121 | F03333 | non-negotiable | false | 10 |
| R06607 | apply.sh — doc written as JSON with indent=2 | `install/apply.sh` 125 | M00730 | non-negotiable | false | 10 |
| R06608 | apply.sh — schedule file mode 0644 | `install/apply.sh` 131 | F03334 | non-negotiable | false | 10 |
| R06609 | apply.sh — clear EXIT trap after schedule write | `install/apply.sh` 132 | F03316 | non-negotiable | false | 10 |
| R06610 | apply.sh — final emit_status "ok" "provisioned ${ETC_DIR}/{runtime.env,schedule.json}" | `install/apply.sh` 134 | F03335 | non-negotiable | false | 10 |
| R06611 | check.sh header — verifies apply produced expected artifacts | `install/check.sh` 3 | F03336 | non-negotiable | false | 10 |
| R06612 | check.sh — read-only | `install/check.sh` 4 | F03336 | non-negotiable | false | 10 |
| R06613 | check.sh MUST set -euo pipefail | `install/check.sh` 5 | F03337 | non-negotiable | false | 10 |
| R06614 | check.sh MODULE = "bitnet-gpu-inference" | `install/check.sh` 7 | F03338 | non-negotiable | false | 10 |
| R06615 | check.sh ETC_DIR override via SELFDEF_BITNET_ETC_DIR | `install/check.sh` 8 | F03338 | non-negotiable | false | 10 |
| R06616 | check.sh STATE_DIR override via SELFDEF_BITNET_STATE_DIR | `install/check.sh` 9 | F03338 | non-negotiable | false | 10 |
| R06617 | check.sh local emit_status helper | `install/check.sh` 11–16 | F03338 | non-negotiable | false | 10 |
| R06618 | check.sh probe — ETC_DIR exists | `install/check.sh` 19 | F03339 | non-negotiable | false | 10 |
| R06619 | check.sh probe — STATE_DIR exists | `install/check.sh` 20 | F03340 | non-negotiable | false | 10 |
| R06620 | check.sh probe — runtime.env file exists | `install/check.sh` 21 | F03341 | non-negotiable | false | 10 |
| R06621 | check.sh probe — schedule.json file exists | `install/check.sh` 22 | F03342 | non-negotiable | false | 10 |
| R06622 | check.sh success — emit "ok" "all artifacts present" + exit 0 | `install/check.sh` 24–27 | F03343 | non-negotiable | false | 10 |
| R06623 | check.sh failure — emit "failed" "missing: <list>" + exit 1 | `install/check.sh` 29–30 | F03344 | non-negotiable | false | 10 |
| R06624 | uninstall.sh header — removes runtime.env + schedule.json | `install/uninstall.sh` 3 | F03345 | non-negotiable | false | 10 |
| R06625 | uninstall.sh — STATE_DIR (/var/lib/selfdef/bitnet/) intact | `install/uninstall.sh` 4 | F03346 | non-negotiable | false | 10 |
| R06626 | uninstall.sh rationale — "that's where session caches + loaded model fingerprints live" | `install/uninstall.sh` 5 | F03346 | non-negotiable | false | 10 |
| R06627 | uninstall.sh rationale — "operators may want to keep them across re-applies" | `install/uninstall.sh` 6 | F03347 | non-negotiable | false | 10 |
| R06628 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 8 | F03348 | non-negotiable | false | 10 |
| R06629 | uninstall.sh MODULE = "bitnet-gpu-inference" | `install/uninstall.sh` 10 | F03349 | non-negotiable | false | 10 |
| R06630 | uninstall.sh ETC_DIR override via SELFDEF_BITNET_ETC_DIR | `install/uninstall.sh` 11 | F03349 | non-negotiable | false | 10 |
| R06631 | uninstall.sh local emit_status helper | `install/uninstall.sh` 13–18 | F03350 | non-negotiable | false | 10 |
| R06632 | uninstall.sh — DRY_RUN-aware (skipped status) | `install/uninstall.sh` 22–25 | F03351 | non-negotiable | false | 10 |
| R06633 | uninstall.sh DRY_RUN — emit "skipped" "DRY-RUN — would remove ${ETC_DIR}" + exit 0 | `install/uninstall.sh` 22–25 | F03351 | non-negotiable | false | 10 |
| R06634 | uninstall.sh — rm -f runtime.env + schedule.json | `install/uninstall.sh` 27 | F03352 | non-negotiable | false | 10 |
| R06635 | uninstall.sh — rmdir ETC_DIR 2>/dev/null || true | `install/uninstall.sh` 30 | F03353 | non-negotiable | false | 10 |
| R06636 | uninstall.sh — tolerates "not empty" via `|| true` | `install/uninstall.sh` 30 | F03353 | non-negotiable | false | 10 |
| R06637 | uninstall.sh — rationale "operator may have other bitnet-* modules sharing the dir" | `install/uninstall.sh` 29 | F03354 | non-negotiable | false | 10 |
| R06638 | uninstall.sh — emit "ok" "removed runtime.env + schedule.json from ${ETC_DIR}" | `install/uninstall.sh` 32 | F03355 | non-negotiable | false | 10 |
| R06639 | Cross-module — MS010 hardware-tune-cache provides `hardware-tune-env` surface | `module.toml` 6 + 9 + cross-ref MS010 | F03356 | non-negotiable | false | 10 |
| R06640 | Cross-module — MS010 [requires_hardware] cycle-2 surface implementation matches SD-R23 + SD-R26 | `module.toml` 16–17 + cross-ref MS010 | F03357 | non-negotiable | false | 10 |
| R06641 | Cross-module — bitnet.cpp ternary fast path is the runtime consumer of the per-GPU schedule | `module.toml` 47 | F03358 | non-negotiable | false | 10 |
| R06642 | Cross-module — master spec § 16 zmm_int8_lanes_min=64 framing verbatim | `module.toml` 53 | F03359 | non-negotiable | false | 10 |
| R06643 | Cross-module — VPDPBUSD INT8 dot product instruction is the hardware-exploit target | `module.toml` 50 | F03360 | non-negotiable | false | 10 |
| R06644 | Cross-module — AVX-512 VNNI required for VPDPBUSD INT8 dot product | `module.toml` 50 | F03360 | non-negotiable | false | 10 |
| R06645 | Cross-module — 64×INT8 per ZMM register is the single-cycle hot path target | `module.toml` 51 | F03279 | non-negotiable | false | 10 |
| R06646 | apply.sh produces 2 outputs — runtime.env + schedule.json | `install/apply.sh` 5–8 | M00723 + M00724 | non-negotiable | false | 10 |
| R06647 | apply.sh — sensible default thread count = SELFDEF_HARDWARE_RECOMMENDED_THREADS or `nproc` | `install/apply.sh` 62–64 | M00727 | non-negotiable | false | 10 |
| R06648 | apply.sh — atomic write pattern matches hardware-tune-cache | `install/apply.sh` 44 + cross-ref MS010 | M00708 | non-negotiable | false | 10 |
| R06649 | apply.sh — fail-soft hardware export | `install/apply.sh` 78 | M00731 | non-negotiable | false | 10 |
| R06650 | apply.sh — fail-soft python3 helper | `install/apply.sh` 94 | M00731 | non-negotiable | false | 10 |
| R06651 | apply.sh — schedule.json schema_version stable | `install/apply.sh` 84 + 117 | M00730 | non-negotiable | false | 10 |
| R06652 | apply.sh — schedule.json schema includes generated_at | `install/apply.sh` 118 | M00730 | non-negotiable | false | 10 |
| R06653 | apply.sh — schedule.json schema includes rationale | `install/apply.sh` 120–122 | M00730 | non-negotiable | false | 10 |
| R06654 | apply.sh — schedule.json supports N GPUs (not just 2) | `install/apply.sh` 105–108 | M00728 | non-negotiable | false | 10 |
| R06655 | apply.sh — 3-role priority list extensible (slots beyond list collapse to "spare") | `install/apply.sh` 108 | M00728 | non-negotiable | false | 10 |
| R06656 | uninstall.sh — does NOT delete STATE_DIR (operator decision) | `install/uninstall.sh` 4–6 | M00732 | non-negotiable | false | 10 |
| R06657 | uninstall.sh — does NOT delete persisted bitnet-* session caches | `install/uninstall.sh` 4–5 | M00732 | non-negotiable | false | 10 |
| R06658 | uninstall.sh — does NOT delete loaded model fingerprints | `install/uninstall.sh` 5 | M00732 | non-negotiable | false | 10 |
| R06659 | Module-system invariant — phase=main runs AFTER hardware-tune-cache phase=pre | `module.toml` 60–62 + cross-ref MS010 | M00721 | non-negotiable | false | 10 |
| R06660 | Module-system invariant — phase=main runs BEFORE observability phase=post | cross-ref MS027 | M00721 | non-negotiable | false | 10 |
| R06661 | Module-system invariant — depends_on=hardware-tune-cache means MS010 MUST be installed first | `module.toml` 6 + cross-ref MS010 | M00712 | non-negotiable | false | 10 |
| R06662 | Module-system invariant — consumes=hardware-tune-env means MS010 MUST provide that surface | `module.toml` 9 + cross-ref MS010 | M00712 | non-negotiable | false | 10 |
| R06663 | Module-system invariant — provides=bitnet-gpu-runtime is the operator-facing surface | `module.toml` 8 | M00711 | non-negotiable | false | 10 |
| R06664 | Module-system invariant — instanced=false (host has one bitnet GPU schedule) | `module.toml` 58 | M00722 | non-negotiable | false | 10 |
| R06665 | Operator UX — `selfdefctl modules apply --only bitnet-gpu-inference` is the canonical apply trigger | `module.toml` 65 + `install/apply.sh` 56 | M00708 | non-negotiable | false | 10 |
| R06666 | Operator UX — apply requires hardware-tune-cache to have run first | `install/apply.sh` 55–57 + cross-ref MS010 | F03311 | non-negotiable | false | 10 |
| R06667 | Operator UX — apply emits JSON status line for parseable feedback | `install/apply.sh` 19 | F03298 | non-negotiable | false | 10 |
| R06668 | Operator UX — check emits JSON status line | `install/check.sh` 13 | F03338 | non-negotiable | false | 10 |
| R06669 | Operator UX — uninstall emits JSON status line | `install/uninstall.sh` 16 | F03350 | non-negotiable | false | 10 |
| R06670 | Output schema — schedule.json schema_version "1.0.0" | `install/apply.sh` 117 + 84 | M00730 | non-negotiable | false | 10 |
| R06671 | Output schema — schedule.json fields per entry: gpu_index, role, model_hint, vram_bytes, power_limit_watts | `install/apply.sh` 110–113 | M00730 | non-negotiable | false | 10 |
| R06672 | Output schema — schedule.json doc fields: schema_version, generated_at, schedule[], rationale | `install/apply.sh` 117–122 | M00730 | non-negotiable | false | 10 |
| R06673 | runtime.env schema — sources TUNE_FILE | `install/apply.sh` 54 | M00723 | non-negotiable | false | 10 |
| R06674 | runtime.env schema — defines BITNET_STATE_DIR | `install/apply.sh` 60 | M00725 | non-negotiable | false | 10 |
| R06675 | runtime.env schema — defines BITNET_SCHEDULE_FILE | `install/apply.sh` 61 | M00726 | non-negotiable | false | 10 |
| R06676 | runtime.env schema — defines BITNET_THREADS | `install/apply.sh` 64 | M00727 | non-negotiable | false | 10 |
| R06677 | runtime.env contract — every consumer of bitnet-gpu-runtime SHALL source this file | `install/apply.sh` 5 + 47 | M00723 | non-negotiable | false | 10 |
| R06678 | schedule.json contract — every consumer SHALL respect role assignments | `install/apply.sh` 70–72 + 105 | M00730 | non-negotiable | false | 10 |
| R06679 | schedule.json contract — model_inference SHALL go to slot 0 (largest VRAM) | `install/apply.sh` 100–105 | M00729 | non-negotiable | false | 10 |
| R06680 | Project-boundary — MS028 is selfdef IPS inference scope; sovereign-os has its own model serving via M046 LoRA foundry + M035 Frontier inference-time intelligence | architecture + cross-ref M035 + M046 | E0281 | non-negotiable | false | 10 |
| R06681 | Project-boundary — selfdef bitnet schedule.json + sovereign-os runtime adaptation are separate planes; cross-repo binding via MS007 typed-mirror crates | architecture + cross-ref MS007 + M046 | E0290 | non-negotiable | false | 10 |
| R06682 | Project-boundary — bitnet.cpp ternary fast path runs in the selfdef-daemon process (or sub-process); not cross-boundary | `module.toml` 47 + cross-ref MS025 | M00719 | non-negotiable | false | 10 |
| R06683 | Hardware-exploit doctrine — operator-readable [requires_hardware] declares 5 minimum hardware predicates | `module.toml` 37–42 | E0283 | non-negotiable | false | 10 |
| R06684 | Hardware-exploit doctrine — operator-readable SD-R64 declares 2 additional ternary-specific gates | `module.toml` 54–55 | E0285 | non-negotiable | false | 10 |
| R06685 | Hardware-exploit doctrine — gates are predicates (true/false/min-value) NOT capability strings | `module.toml` 37–55 | E0283 + E0285 | non-negotiable | false | 10 |
| R06686 | Hardware-exploit doctrine — module-loader SHALL evaluate predicates against host probe before apply | `module.toml` 37–42 + cross-ref MS010 | M00721 | non-negotiable | false | 10 |
| R06687 | Hardware-exploit doctrine — module-loader SHALL refuse to land module if any predicate fails | `module.toml` 29–30 | E0283 | non-negotiable | false | 10 |
| R06688 | Hardware-exploit doctrine — 1-card-under-load box correctly fails gpu_power_headroom_watts_min | `module.toml` 29–30 | F03266 | non-negotiable | false | 10 |
| R06689 | Test integration — MS020 L1-L5 layered harness covers Module-script category (apply/check/uninstall) | cross-ref MS020 | M00708 + M00709 + M00710 | non-negotiable | false | 10 |
| R06690 | Test integration — MS020 hardware-aware test category covers [requires_hardware] gate evaluation | cross-ref MS020 + MS010 | E0283 | non-negotiable | false | 10 |
| R06691 | Test integration — MS020 SAIN-01 host-class test covers the dual-GPU schedule path | cross-ref MS020 + `module.toml` 32–35 | E0284 | non-negotiable | false | 10 |
| R06692 | Test integration — MS020 24-GiB-only host-class test covers the single-GPU GPU 0 fallback path | cross-ref MS020 + `module.toml` 37–38 | E0284 | non-negotiable | false | 10 |
| R06693 | Test integration — MS020 caps-missing host-class test covers the python3 fallback path | cross-ref MS020 + `install/apply.sh` 91–93 | M00731 | non-negotiable | false | 10 |
| R06694 | Cross-repo — sovereign-os M040 hyper feature 1 MIG profiles + hyper feature 2 FP4 align with selfdef bitnet ternary GPU usage | cross-ref M040 | E0285 | non-negotiable | false | 10 |
| R06695 | Cross-repo — sovereign-os M043 Blackwell-as-context-sovereign aligns with selfdef bitnet largest-VRAM-gets-model rule | cross-ref M043 | M00729 | non-negotiable | false | 10 |
| R06696 | Cross-repo — sovereign-os M046 LoRA foundry adapter Blackwell-base + 3090-scout aligns with selfdef bitnet model_inference + auxiliary role split | cross-ref M046 | M00728 | non-negotiable | false | 10 |
| R06697 | Cross-repo — sovereign-os M045 sandbox.slice resource boundary maps to selfdef bitnet runtime cgroup placement | cross-ref M045 | M00721 | non-negotiable | false | 10 |
| R06698 | Cross-repo — selfdef MS007 audit-manifest typed-mirror crate carries bitnet schedule.json schema for cross-repo audit | architecture + cross-ref MS007 | M00730 | non-negotiable | false | 10 |
| R06699 | Operator references — bitnet.cpp ternary inference codebase | `module.toml` 47 | M00719 | non-negotiable | false | 10 |
| R06700 | Operator references — Intel/AMD VPDPBUSD instruction documentation | `module.toml` 50 | F03277 | non-negotiable | false | 10 |
| R06701 | Operator references — AVX-512 VNNI feature flag (CPUID 7:0 EBX bit 16 or ECX bit 11 depending on revision) | `module.toml` 48 | M00719 | non-negotiable | false | 10 |
| R06702 | Operator references — Zen 5 AVX-512 native ZMM 64×INT8 single-cycle datapath (master spec § 16) | `module.toml` 51–53 | M00720 | non-negotiable | false | 10 |
| R06703 | Operator references — RTX PRO 6000 Blackwell datasheet (98 GiB VRAM in workstation Pro edition) | `module.toml` 32 | F03267 | non-negotiable | false | 10 |
| R06704 | Operator references — RTX 3090 datasheet (24 GiB VRAM) | `module.toml` 32 | F03267 | non-negotiable | false | 10 |
| R06705 | Operator references — `nvidia-smi` for power_limit_watts surface | `install/apply.sh` 113 | M00730 | non-negotiable | false | 10 |
| R06706 | Operator references — selfdefctl `hardware export --stdout` CLI surface | `install/apply.sh` 78 | F03317 | non-negotiable | false | 10 |
| R06707 | Operator references — SD-R23 hardware-tune-cache env-file output | `install/apply.sh` 53 + cross-ref MS010 | F03310 | non-negotiable | false | 10 |
| R06708 | Operator references — SD-R25 per-device VRAM probe surface | `install/apply.sh` 71 | M00729 | non-negotiable | false | 10 |
| R06709 | Operator references — SD-R26 cycle-2 [requires_hardware] surface (host gate evaluation) | `module.toml` 16–17 | E0283 | non-negotiable | false | 10 |
| R06710 | Operator references — SD-R28 module-instantiation contract (this module's spec) | `module.toml` 3 | E0281 | non-negotiable | false | 10 |
| R06711 | Operator references — SD-R64 hardware-exploitation gates (master spec § 16) | `module.toml` 44 | E0285 | non-negotiable | false | 10 |
| R06712 | Hardware reality — SAIN-01 box dual-GPU pair (Blackwell + 3090) | `module.toml` 26–28 | F03265 | non-negotiable | false | 10 |
| R06713 | Hardware reality — sustained loads at 60-80% of power cap typical for SAIN-01 box | `module.toml` 27–28 | F03265 | non-negotiable | false | 10 |
| R06714 | Hardware reality — 100W power headroom cushion ensures scheduler has burst capacity | `module.toml` 25 | F03264 | non-negotiable | false | 10 |
| R06715 | Hardware reality — sub-8 GiB GPUs route to CPU fallback (not this module's scope) | `module.toml` 23–24 | F03262 | non-negotiable | false | 10 |
| R06716 | Hardware reality — bitnet.cpp's BF16 activation reduction requires AVX-512 BF16 instruction set | `module.toml` 19 | F03255 | non-negotiable | false | 10 |
| R06717 | Hardware reality — bitnet.cpp's ternary fast path requires AVX-512 VNNI for VPDPBUSD | `module.toml` 48–50 | M00719 | non-negotiable | false | 10 |
| R06718 | Hardware reality — Zen 5 supports 64×INT8 lanes per ZMM register single-cycle | `module.toml` 51 | F03279 | non-negotiable | false | 10 |
| R06719 | Doctrine — operator-readable hardware-exploit declarations make hardware capability LEGIBLE | `module.toml` 52 | F03280 | non-negotiable | false | 10 |
| R06720 | Composite — MS028 (10 epics / 26 modules / 120 features / 240 reqs) covers bitnet-gpu-inference module v0.1.0 (262 lines): module.toml (65-line manifest with cycle-2 [requires_hardware] 5-gate + SD-R64 2-gate ternary-AOT-capable-required + zmm_int8_lanes_min=64 + instanced=false + phase=main + depends_on=hardware-tune-cache + provides=bitnet-gpu-runtime + consumes=hardware-tune-env) + apply.sh (134-line idempotent atomic-write provisioner with runtime.env + schedule.json + python3 ranking helper + fail-soft fallback) + check.sh (31-line read-only 4-artifact verifier) + uninstall.sh (32-line tear-down preserving STATE_DIR); SD-R28 deliverable; SAIN-01 dual-GPU (RTX PRO 6000 + RTX 3090) all 5 gates pass; bitnet.cpp ternary fast path + VPDPBUSD INT8 dot product + 64×INT8 ZMM single-cycle hot path (master spec § 16 verbatim); cross-module chain MS010 hardware-tune-cache phase=pre → MS028 bitnet-gpu-inference phase=main | `modules/bitnet-gpu-inference/` 262 lines | E0281 + E0282 + E0283 + E0284 + E0285 + E0286 + E0287 + E0288 + E0289 + E0290 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml manifest invariants + summary + category + surfaces + binary + SD-R26 doctrine (R06481–R06493) + 5 hardware gates + 5 gate rationales + SAIN-01 box behavior + 24GB-only box behavior (R06494–R06515) + SD-R64 ternary gates + zmm_int8_lanes_min + 5 rationales (R06516–R06525) + instanced + phase=main + install kind/paths (R06526–R06532) + apply.sh full transcription (R06533–R06610) + check.sh full transcription (R06611–R06623) + uninstall.sh full transcription (R06624–R06638) + cross-module dependencies + master spec § 16 + VPDPBUSD + 64-INT8-ZMM (R06639–R06645) + apply.sh additional invariants (R06646–R06655) + uninstall.sh STATE_DIR preservation (R06656–R06658) + module-system invariants (R06659–R06664) + operator UX (R06665–R06669) + output schemas (R06670–R06679) + project-boundary + cross-repo (R06680–R06682) + hardware-exploit doctrine (R06683–R06688) + test integration (R06689–R06693) + cross-repo M040+M043+M045+M046 (R06694–R06697) + MS007 audit binding (R06698) + operator references (R06699–R06711) + hardware reality (R06712–R06718) + doctrine + composite (R06719–R06720)
- Source range 262 lines yields 240 R-rows representing 0.92:1 R-per-line at the verbatim-citation level (bitnet-gpu-inference is dense-invariant hardware-exploit module; every gate + rationale + script invariant deserves explicit row)
- Project boundary — MS028 is selfdef IPS inference scope; sovereign-os has its own model serving stack (M035 + M046); cross-repo audit routes through MS007 audit-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS027 Observability (selfdef-side) / MS029 SLM CPU loop
- Cross-module dependency chain — MS010 hardware-tune-cache (phase=pre) → MS028 bitnet-gpu-inference (phase=main) → bitnet.cpp ternary fast path runtime consumer
- Hardware-exploit doctrine — [requires_hardware] cycle-2 surface (SD-R26) + SD-R64 hardware-exploitation gates (master spec § 16); 5+2=7 minimum hardware predicates; module-loader refuses to land on hosts where any predicate fails
- SAIN-01 box reality — RTX PRO 6000 Blackwell 98 GiB + RTX 3090 24 GiB pair; all 7 gates pass; largest-VRAM (Blackwell) gets model_inference, secondary (3090) handles auxiliary tokenization/embedding/TTS
- 24-GiB-only box reality — RTX 3090 alone; vram + headroom gates still pass (single 24 GiB > 8 GiB threshold); model lands on GPU 0
- SD-R-references — SD-R23 hardware-tune-cache env-file / SD-R25 per-device VRAM probe / SD-R26 cycle-2 [requires_hardware] surface / SD-R28 module-instantiation contract / SD-R64 hardware-exploitation gates
- Cross-repo binding — sovereign-os M040 hyper feature 2 Blackwell FP4 + M043 Blackwell-as-context-sovereign + M046 LoRA foundry adapter Blackwell-base align with selfdef bitnet largest-VRAM-gets-model-inference rule; M045 sandbox.slice cgroup boundary may govern bitnet runtime placement; cross-repo audit via MS007 audit-manifest typed-mirror crate
- Test integration — MS020 L1-L5 layered harness covers Module-script category (apply/check/uninstall) + hardware-aware test category ([requires_hardware] gate evaluation) + SAIN-01 dual-GPU schedule path + 24-GiB-only single-GPU fallback path + caps-missing python3 fallback path
- Master spec — § 16 zmm_int8_lanes_min=64 framing verbatim; bitnet.cpp ternary fast path; VPDPBUSD INT8 dot product; AVX-512 VNNI feature; Zen 5 native 64×INT8 ZMM single-cycle datapath
- Operator references: bitnet.cpp codebase + Intel/AMD VPDPBUSD instruction docs + AVX-512 VNNI CPUID feature flag docs + Zen 5 AVX-512 docs + RTX PRO 6000 Blackwell datasheet + RTX 3090 datasheet + nvidia-smi power_limit_watts surface + selfdefctl `hardware export --stdout` CLI surface
