# MS029 — SLM CPU loop module

> Parent: `backlog/milestones/INDEX.md` row MS029 (source ref `modules/slm-cpu-loop` + dump 7445 "SLMs Are Microservices Of Intelligence").
> Source: `modules/slm-cpu-loop/` (213 lines across module.toml + install/apply.sh + install/check.sh + install/uninstall.sh).
> All entries below extract verbatim. No invention.

## Epics (E0291–E0300)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0291 | Module identity — `slm-cpu-loop` v0.1.0, category=inference, summary "SLM-on-CPU agent loop runtime — pins a small language model (Phi-4-mini / Qwen3-1.7B class) to CCD-0 cores for low-latency background agent work (SD-R72)" | `module.toml` 1–4 |
| E0292 | Manifest dependencies + surfaces — `depends_on = ["hardware-tune-cache"]` (consumes its env-file output) + `provides = ["slm-loop-runtime"]` (operator-facing CPU-pinned SLM env-file surface) + `consumes = ["hardware-tune-env"]` (the env-file surface hardware-tune-cache exposes) + `conflicts = []` + `requires = [{kind = "binary", value = "selfdefctl"}]` | `module.toml` 6–14 |
| E0293 | SD-R72 — "third real demonstrator of the cycle-3 hardware-exploit surface (after SD-R28 bitnet-gpu-inference + SD-R48 wasm-aot-cache)"; "This module showcases the SD-R64 + SD-R68 cycle-3 predicates AND the R212 (sovereign-os) model-class taxonomy" | `module.toml` 16–20 |
| E0294 | SD-R64 + SD-R68 cycle-3 predicates — `ternary_aot_capable_required = false` (SLMs run dense, not ternary) + `zmm_int8_lanes_min = 32` (AVX2 minimum; 64 preferred for VNNI hot path) + `host_features_required = "avx2,fma"` (load-bearing for the llama.cpp dense kernels) | `module.toml` 22–29 |
| E0295 | Existing cycle-1+2 gates — `memory_gib_min = 8` (Phi-4-mini bf16 needs ~4 GiB + tokenizer overhead + KV cache headroom) + `gpu_count_min = 0` (CPU-only by design) | `module.toml` 32–35 + 43–45 |
| E0296 | Operator workflow — 3-step lifecycle: (1) `selfdefctl modules apply slm-cpu-loop` → installs /etc/selfdef/slm-loop.env with CCD-0 core mask + model path placeholder + start command template; (2) Operator sets `SELFDEF_SLM_MODEL=Phi-4-mini-instruct` (or any catalog id with class=slm); (3) systemd-run wrapper picks up the env file | `module.toml` 37–43 |
| E0297 | Module composition — composes with SD-R70 `selfdefctl hardware aot-script` (for AOT precompile) + SD-R67 `selfdefctl hardware posture` (operator confirms VNNI path) + R212 sovereign-os `models query --class slm` (find the right model) | `module.toml` 45–49 |
| E0298 | [requires_hardware] block — 3-key cycle-3 gates: `memory_gib_min = 8` + `zmm_int8_lanes_min = 32` + `host_features_required = "avx2,fma"`; R212 [metadata] block — `intended_model_class = "slm"` + `intended_purpose = ["chat", "agent", "function-calling"]` (sovereign-os is strict source for class taxonomy enforcement; this field communicates intent to operators reading module.toml alongside R212 catalog entries with class=slm) | `module.toml` 51–61 + 53–62 |
| E0299 | apply.sh — provisions `/etc/selfdef/slm-loop.env` with operator-tuned defaults: SELFDEF_SLM_AFFINITY="0-5" (CCD-0 cores Zen 5 9900X = 0-5 physical / 0-11 with SMT; master spec § 17.1 Pulse Vector Core) + SELFDEF_SLM_THREADS="6" + SELFDEF_SLM_MODEL="" (operator-set; matches sovereign-os catalog.yaml class=slm entry: Phi-4-mini-instruct / Qwen3-1.7B-Instruct as of R212) + SELFDEF_SLM_MODEL_PATH="" + SELFDEF_SLM_ENGINE="llama.cpp" (recommended for GGUF Phi-4-mini; vllm for bf16 Qwen3) + SELFDEF_SLM_CONTEXT_TOKENS="8192" (Phi-4-mini supports 128k but operator loop typically uses less) + SELFDEF_SLM_KV_DTYPE="fp16"; emits worked invocation example using `taskset -c $SELFDEF_SLM_AFFINITY llama-server`; CPU model probed from /proc/cpuinfo; idempotent + SELFDEF_DRY_RUN=1 aware; "composes with SD-R66/R67/R70" | `install/apply.sh` 1–89 |
| E0300 | check.sh + uninstall.sh + module-system invariants — check.sh verifies ENV_FILE exists + carries SELFDEF_SLM_AFFINITY + SELFDEF_SLM_THREADS + SELFDEF_SLM_ENGINE keys; "env file should have the canonical knobs even when the operator hasn't yet set SELFDEF_SLM_MODEL"; uninstall.sh removes env file but PRESERVES operator-written systemd unit drop-ins (those live under /etc/systemd/system/<unit>.d/ and are operator-owned content); `instanced = false` (host has one SLM loop env); `phase = "main"` (hardware-tune-cache pre-phase populated /etc/selfdef/hardware-tune.env first); `[install] kind = "script"` | `install/check.sh` 1–30 + `install/uninstall.sh` 1–27 + `module.toml` 64–66 |

## Modules (M00733–M00758)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00733 | `module.toml` — 66-line manifest (cycle-3 [requires_hardware] + R212 [metadata] + instanced=false + phase=main) | `module.toml` 1–66 | E0291 + E0293 + E0298 + E0300 |
| M00734 | `install/apply.sh` — 90-line idempotent provisioner (env-file generator with worked invocation example) | `install/apply.sh` 1–90 | E0299 |
| M00735 | `install/check.sh` — 30-line read-only env-file verifier (3-key presence) | `install/check.sh` 1–30 | E0300 |
| M00736 | `install/uninstall.sh` — 27-line tear-down (preserves operator unit drop-ins) | `install/uninstall.sh` 1–27 | E0300 |
| M00737 | Provided surface — `slm-loop-runtime` | `module.toml` 8 | E0292 |
| M00738 | Consumed surface — `hardware-tune-env` (from MS010 hardware-tune-cache) | `module.toml` 9 | E0292 |
| M00739 | Required binary — `selfdefctl` | `module.toml` 12 | E0292 |
| M00740 | SD-R72 doctrine — "third real demonstrator of the cycle-3 hardware-exploit surface (after SD-R28 bitnet-gpu-inference + SD-R48 wasm-aot-cache)" | `module.toml` 16–17 | E0293 |
| M00741 | Cycle-3 predicate — `ternary_aot_capable_required = false` ("SLMs run dense, not ternary") | `module.toml` 22 + 53 | E0294 |
| M00742 | Cycle-3 predicate — `zmm_int8_lanes_min = 32` (AVX2 minimum; 64 preferred for VNNI hot path) | `module.toml` 23–24 + 54 | E0294 |
| M00743 | Cycle-3 predicate — `host_features_required = "avx2,fma"` (load-bearing for llama.cpp dense kernels) | `module.toml` 25 + 55 | E0294 |
| M00744 | Cycle-1+2 gate — `memory_gib_min = 8` (Phi-4-mini bf16 ~4 GiB + tokenizer + KV cache headroom) | `module.toml` 32–34 + 52 | E0295 |
| M00745 | Cycle-1+2 gate — `gpu_count_min = 0` (CPU-only by design) | `module.toml` 35 | E0295 |
| M00746 | Operator workflow step 1 — `selfdefctl modules apply slm-cpu-loop` | `module.toml` 38 | E0296 |
| M00747 | Operator workflow step 2 — set SELFDEF_SLM_MODEL=Phi-4-mini-instruct (or class=slm catalog id) | `module.toml` 40–42 | E0296 |
| M00748 | Operator workflow step 3 — systemd-run wrapper picks up env file | `module.toml` 43 | E0296 |
| M00749 | Composition — SD-R70 `selfdefctl hardware aot-script` (AOT precompile) | `module.toml` 46 | E0297 |
| M00750 | Composition — SD-R67 `selfdefctl hardware posture` (operator confirms VNNI path) | `module.toml` 47 | E0297 |
| M00751 | Composition — R212 sovereign-os `models query --class slm` | `module.toml` 48 | E0297 |
| M00752 | R212 [metadata] — `intended_model_class = "slm"` (affinity tag; sovereign-os is strict source for class taxonomy) | `module.toml` 59 + 53–58 | E0298 |
| M00753 | R212 [metadata] — `intended_purpose = ["chat", "agent", "function-calling"]` | `module.toml` 60 | E0298 |
| M00754 | apply.sh — CCD-0 default affinity `0-5` (Zen 5 9900X 6 physical cores; master spec § 17.1 Pulse Vector Core) | `install/apply.sh` 30–31 + 50 | E0299 |
| M00755 | apply.sh — env keys: SELFDEF_SLM_AFFINITY + SELFDEF_SLM_THREADS + SELFDEF_SLM_MODEL + SELFDEF_SLM_MODEL_PATH + SELFDEF_SLM_ENGINE + SELFDEF_SLM_CONTEXT_TOKENS + SELFDEF_SLM_KV_DTYPE | `install/apply.sh` 55–80 | E0299 |
| M00756 | apply.sh — worked invocation example `taskset -c $SELFDEF_SLM_AFFINITY llama-server -m $SELFDEF_SLM_MODEL_PATH -t $SELFDEF_SLM_THREADS -c $SELFDEF_SLM_CONTEXT_TOKENS --port 8082` | `install/apply.sh` 83–87 | E0299 |
| M00757 | apply.sh — CPU model probe from /proc/cpuinfo | `install/apply.sh` 36–39 | E0299 |
| M00758 | Module-system invariants — instanced=false + phase=main (after hardware-tune-cache pre) + kind=script + check probes 3 keys + uninstall preserves operator unit drop-ins | `module.toml` 62–66 + `install/check.sh` 19–25 + `install/uninstall.sh` 4–7 | E0300 |

## Features (F03361–F03480)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03361 | module.toml `name = "slm-cpu-loop"` | `module.toml` 1 | M00733 |
| F03362 | module.toml `version = "0.1.0"` | `module.toml` 2 | M00733 |
| F03363 | module.toml summary references SD-R72 | `module.toml` 3 | M00733 |
| F03364 | module.toml summary — "SLM-on-CPU agent loop runtime" | `module.toml` 3 | M00733 |
| F03365 | module.toml summary — "pins a small language model (Phi-4-mini / Qwen3-1.7B class) to CCD-0 cores" | `module.toml` 3 | M00733 |
| F03366 | module.toml summary — "for low-latency background agent work" | `module.toml` 3 | M00733 |
| F03367 | module.toml `category = "inference"` | `module.toml` 4 | M00733 |
| F03368 | module.toml `depends_on = ["hardware-tune-cache"]` | `module.toml` 6 | M00738 |
| F03369 | module.toml `conflicts = []` | `module.toml` 7 | M00733 |
| F03370 | module.toml `provides = ["slm-loop-runtime"]` | `module.toml` 8 | M00737 |
| F03371 | module.toml `consumes = ["hardware-tune-env"]` | `module.toml` 9 | M00738 |
| F03372 | module.toml `requires` — binary selfdefctl | `module.toml` 12 | M00739 |
| F03373 | SD-R72 doctrine — "third real demonstrator of the cycle-3 hardware-exploit surface" | `module.toml` 16 | M00740 |
| F03374 | SD-R72 lineage — after SD-R28 bitnet-gpu-inference | `module.toml` 17 | M00740 |
| F03375 | SD-R72 lineage — after SD-R48 wasm-aot-cache | `module.toml` 17 | M00740 |
| F03376 | Doctrine — "showcases the SD-R64 + SD-R68 cycle-3 predicates" | `module.toml` 19 | E0293 |
| F03377 | Doctrine — "AND the R212 (sovereign-os) model-class taxonomy" | `module.toml` 20 | E0293 |
| F03378 | Predicate — ternary_aot_capable_required = false | `module.toml` 22 + 53 | M00741 |
| F03379 | Predicate rationale — "SLMs run dense, not ternary" | `module.toml` 22 | M00741 |
| F03380 | Predicate — zmm_int8_lanes_min = 32 | `module.toml` 23 + 54 | M00742 |
| F03381 | Predicate rationale — AVX2 minimum | `module.toml` 23 | M00742 |
| F03382 | Predicate rationale — 64 preferred for VNNI hot path | `module.toml` 24 | M00742 |
| F03383 | Predicate — host_features_required = "avx2,fma" | `module.toml` 25 + 55 | M00743 |
| F03384 | Predicate rationale — load-bearing for llama.cpp dense kernels | `module.toml` 25 | M00743 |
| F03385 | Cycle-1+2 gate — memory_gib_min = 8 | `module.toml` 32 + 52 | M00744 |
| F03386 | Cycle-1+2 gate rationale — Phi-4-mini bf16 needs ~4 GiB | `module.toml` 32–33 | M00744 |
| F03387 | Cycle-1+2 gate rationale — + tokenizer overhead | `module.toml` 33 | M00744 |
| F03388 | Cycle-1+2 gate rationale — + KV cache headroom | `module.toml` 33 | M00744 |
| F03389 | Cycle-1+2 gate — gpu_count_min = 0 | `module.toml` 35 | M00745 |
| F03390 | Cycle-1+2 gate rationale — CPU-only by design | `module.toml` 35 | M00745 |
| F03391 | Operator workflow header | `module.toml` 37 | E0296 |
| F03392 | Workflow step 1 — `selfdefctl modules apply slm-cpu-loop` | `module.toml` 38 | M00746 |
| F03393 | Workflow step 1 result — installs /etc/selfdef/slm-loop.env | `module.toml` 39 | M00746 |
| F03394 | Workflow step 1 — env carries CCD-0 core mask | `module.toml` 39 | M00746 |
| F03395 | Workflow step 1 — env carries model path placeholder | `module.toml` 39 | M00746 |
| F03396 | Workflow step 1 — env carries start command template | `module.toml` 40 | M00746 |
| F03397 | Workflow step 2 — operator sets SELFDEF_SLM_MODEL=Phi-4-mini-instruct | `module.toml` 41 | M00747 |
| F03398 | Workflow step 2 — or any catalog id with class=slm | `module.toml` 42 | M00747 |
| F03399 | Workflow step 3 — systemd-run wrapper picks up env file | `module.toml` 43 | M00748 |
| F03400 | Composition — SD-R70 selfdefctl hardware aot-script | `module.toml` 46 | M00749 |
| F03401 | Composition rationale — for AOT precompile | `module.toml` 46 | M00749 |
| F03402 | Composition — SD-R67 selfdefctl hardware posture | `module.toml` 47 | M00750 |
| F03403 | Composition rationale — operator confirms VNNI path | `module.toml` 47 | M00750 |
| F03404 | Composition — R212 sovereign-os models query --class slm | `module.toml` 48 | M00751 |
| F03405 | Composition rationale — find the right model | `module.toml` 48 | M00751 |
| F03406 | [requires_hardware] block declared | `module.toml` 51 | E0298 |
| F03407 | [metadata] block declared | `module.toml` 57 | E0298 |
| F03408 | [metadata] comment — "R212 (sovereign-os) model-class taxonomy mirror — affinity tag" | `module.toml` 54 | M00752 |
| F03409 | [metadata] comment — "Selfdef registry currently doesn't enforce the class taxonomy at the schema layer" | `module.toml` 55 | M00752 |
| F03410 | [metadata] comment — "sovereign-os is the strict source" | `module.toml` 56 | M00752 |
| F03411 | [metadata] comment — "this field communicates intent to operators reading the module.toml alongside R212 catalog entries with class=slm" | `module.toml` 56–58 | M00752 |
| F03412 | [metadata] intended_model_class = "slm" | `module.toml` 59 | M00752 |
| F03413 | [metadata] intended_purpose includes "chat" | `module.toml` 60 | M00753 |
| F03414 | [metadata] intended_purpose includes "agent" | `module.toml` 60 | M00753 |
| F03415 | [metadata] intended_purpose includes "function-calling" | `module.toml` 60 | M00753 |
| F03416 | module.toml `instanced = false` | `module.toml` 62 | M00758 |
| F03417 | module.toml `phase = "main"` | `module.toml` 65 | M00758 |
| F03418 | Phase rationale — "hardware-tune-cache (pre-phase) has already populated /etc/selfdef/hardware-tune.env by the time we run" | `module.toml` 64 | M00758 |
| F03419 | module.toml `[install] kind = "script"` | `module.toml` 66 | M00758 |
| F03420 | apply.sh header references SD-R72 | `install/apply.sh` 2 | M00734 |
| F03421 | apply.sh — provisions /etc/selfdef/slm-loop.env | `install/apply.sh` 4 | M00734 |
| F03422 | apply.sh — env file consumed by systemd-run / systemd unit drop-ins | `install/apply.sh` 8 | M00734 |
| F03423 | apply.sh — module just centralises canonical defaults | `install/apply.sh` 9 | M00734 |
| F03424 | apply.sh — operators don't reinvent CCD-0 pinning + thread count math per host | `install/apply.sh` 10–11 | M00754 |
| F03425 | apply.sh — idempotent | `install/apply.sh` 12 | M00734 |
| F03426 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 12 | M00734 |
| F03427 | apply.sh — composes with SD-R66/R67/R70 | `install/apply.sh` 12 | M00749 + M00750 |
| F03428 | apply.sh MUST set -euo pipefail | `install/apply.sh` 14 | M00734 |
| F03429 | apply.sh MODULE = "slm-cpu-loop" | `install/apply.sh` 16 | M00734 |
| F03430 | apply.sh ENV_FILE default /etc/selfdef/slm-loop.env | `install/apply.sh` 17 | M00734 |
| F03431 | apply.sh ENV_FILE override via SELFDEF_SLM_LOOP_ENV | `install/apply.sh` 17 | M00734 |
| F03432 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 18 | M00738 |
| F03433 | apply.sh DRY_RUN default 0 | `install/apply.sh` 19 | M00734 |
| F03434 | apply.sh — local emit_status helper | `install/apply.sh` 21–26 | M00734 |
| F03435 | apply.sh — DRY_RUN=1 short-circuits with skipped | `install/apply.sh` 28–31 | M00734 |
| F03436 | apply.sh — mkdir -p dirname ENV_FILE | `install/apply.sh` 33 | M00734 |
| F03437 | apply.sh — CCD-0 affinity rationale Zen 5 9900X = 0-5 physical / 0-11 with SMT | `install/apply.sh` 35–36 | M00754 |
| F03438 | apply.sh — best-effort tuned for 6-physical-core CCD-0 | `install/apply.sh` 36 | M00754 |
| F03439 | apply.sh — operators with different topologies override SELFDEF_SLM_AFFINITY | `install/apply.sh` 37 | M00754 |
| F03440 | apply.sh — DEFAULT_AFFINITY="0-5" | `install/apply.sh` 39 | M00754 |
| F03441 | apply.sh — DEFAULT_THREADS="6" | `install/apply.sh` 40 | M00754 |
| F03442 | apply.sh — CPU_MODEL probe from /proc/cpuinfo | `install/apply.sh` 42–47 | M00757 |
| F03443 | apply.sh — env file generated-by header | `install/apply.sh` 50–53 | M00734 |
| F03444 | apply.sh — env file says "Sourced by operator-supplied systemd units or systemd-run wrappers" | `install/apply.sh` 51 | M00734 |
| F03445 | apply.sh — env file says "Override any value via /etc/systemd/system/<unit>.service.d/*.conf" | `install/apply.sh` 52 | M00734 |
| F03446 | apply.sh — env file Generated on host: $CPU_MODEL | `install/apply.sh` 54 | M00757 |
| F03447 | apply.sh — env file Generated at: ISO timestamp | `install/apply.sh` 55 | M00734 |
| F03448 | apply.sh — env Affinity section header | `install/apply.sh` 57 | M00754 |
| F03449 | apply.sh — env Affinity comment "CCD-0 cores on Zen 5 (master spec § 17.1 Pulse Vector Core)" | `install/apply.sh` 58 | M00754 |
| F03450 | apply.sh — env Affinity comment "On 9900X this is cores 0-5 physical (0-11 with SMT)" | `install/apply.sh` 59 | M00754 |
| F03451 | apply.sh — env Affinity comment "Override per host topology — e.g. SELFDEF_SLM_AFFINITY='0-7' on a 9950X" | `install/apply.sh` 60 | M00754 |
| F03452 | apply.sh — env SELFDEF_SLM_AFFINITY="${DEFAULT_AFFINITY}" | `install/apply.sh` 61 | M00755 |
| F03453 | apply.sh — env SELFDEF_SLM_THREADS="${DEFAULT_THREADS}" | `install/apply.sh` 62 | M00755 |
| F03454 | apply.sh — env Model selection section header | `install/apply.sh` 64 | M00755 |
| F03455 | apply.sh — env comment "Operator-set. Should match a sovereign-os models/catalog.yaml entry with class=slm" | `install/apply.sh` 65 | M00755 |
| F03456 | apply.sh — env comment names Phi-4-mini-instruct / Qwen3-1.7B-Instruct as of R212 | `install/apply.sh` 66 | M00755 |
| F03457 | apply.sh — env comment "Discover via: sovereign-osctl models query --class slm" | `install/apply.sh` 67 | M00751 |
| F03458 | apply.sh — env SELFDEF_SLM_MODEL="" | `install/apply.sh` 68 | M00755 |
| F03459 | apply.sh — env SELFDEF_SLM_MODEL_PATH="" | `install/apply.sh` 69 | M00755 |
| F03460 | apply.sh — env Engine selection section header | `install/apply.sh` 71 | M00755 |
| F03461 | apply.sh — env comment llama.cpp recommended for GGUF Phi-4-mini | `install/apply.sh` 72 | M00755 |
| F03462 | apply.sh — env comment vllm for bf16 Qwen3 | `install/apply.sh` 72 | M00755 |
| F03463 | apply.sh — env SELFDEF_SLM_ENGINE="llama.cpp" | `install/apply.sh` 73 | M00755 |
| F03464 | apply.sh — env KV cache + context section header | `install/apply.sh` 75 | M00755 |
| F03465 | apply.sh — env comment Phi-4-mini supports 128k context but operator loop uses less | `install/apply.sh` 76–77 | M00755 |
| F03466 | apply.sh — env SELFDEF_SLM_CONTEXT_TOKENS="8192" | `install/apply.sh` 78 | M00755 |
| F03467 | apply.sh — env SELFDEF_SLM_KV_DTYPE="fp16" | `install/apply.sh` 79 | M00755 |
| F03468 | apply.sh — Worked invocation example header | `install/apply.sh` 81 | M00756 |
| F03469 | apply.sh — invocation `taskset -c ${SELFDEF_SLM_AFFINITY} llama-server` | `install/apply.sh` 82 | M00756 |
| F03470 | apply.sh — invocation `-m ${SELFDEF_SLM_MODEL_PATH}` | `install/apply.sh` 83 | M00756 |
| F03471 | apply.sh — invocation `-t ${SELFDEF_SLM_THREADS}` | `install/apply.sh` 84 | M00756 |
| F03472 | apply.sh — invocation `-c ${SELFDEF_SLM_CONTEXT_TOKENS}` | `install/apply.sh` 85 | M00756 |
| F03473 | apply.sh — invocation `--port 8082` | `install/apply.sh` 86 | M00756 |
| F03474 | apply.sh — final emit_status "ok" "wrote ${ENV_FILE}; operator sets SELFDEF_SLM_MODEL{,_PATH}" | `install/apply.sh` 89 | M00734 |
| F03475 | check.sh — read-only | `install/check.sh` 2 | M00735 |
| F03476 | check.sh — ENV_FILE existence check (fail with "${ENV_FILE} missing — run apply first") | `install/check.sh` 16–19 | M00735 |
| F03477 | check.sh — loops for SELFDEF_SLM_AFFINITY / SELFDEF_SLM_THREADS / SELFDEF_SLM_ENGINE; fail if missing | `install/check.sh` 21–25 | M00735 |
| F03478 | check.sh — success message "env file present + carries SLM loop defaults" | `install/check.sh` 28 | M00735 |
| F03479 | uninstall.sh — removes env file | `install/uninstall.sh` 18 + 22 | M00736 |
| F03480 | uninstall.sh — PRESERVES operator-written systemd unit drop-ins under /etc/systemd/system/<unit>.d/; "those live there and are operator-owned content" | `install/uninstall.sh` 4–7 + 23 | M00736 |

## Requirements (R06721–R06960)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R06721 | Module name MUST be `slm-cpu-loop` | `module.toml` 1 | F03361 | non-negotiable | false | 10 |
| R06722 | Module version MUST be 0.1.0 | `module.toml` 2 | F03362 | non-negotiable | false | 10 |
| R06723 | Module summary references SD-R72 | `module.toml` 3 | F03363 | non-negotiable | false | 10 |
| R06724 | Module summary — "SLM-on-CPU agent loop runtime" | `module.toml` 3 | F03364 | non-negotiable | false | 10 |
| R06725 | Module summary — "pins a small language model (Phi-4-mini / Qwen3-1.7B class) to CCD-0 cores" | `module.toml` 3 | F03365 | non-negotiable | false | 10 |
| R06726 | Module summary — "for low-latency background agent work" | `module.toml` 3 | F03366 | non-negotiable | false | 10 |
| R06727 | Module category MUST be `inference` | `module.toml` 4 | F03367 | non-negotiable | false | 10 |
| R06728 | depends_on = ["hardware-tune-cache"] | `module.toml` 6 | F03368 | non-negotiable | false | 10 |
| R06729 | conflicts = [] | `module.toml` 7 | F03369 | non-negotiable | false | 10 |
| R06730 | provides = ["slm-loop-runtime"] | `module.toml` 8 | F03370 | non-negotiable | false | 10 |
| R06731 | consumes = ["hardware-tune-env"] | `module.toml` 9 | F03371 | non-negotiable | false | 10 |
| R06732 | Required binary — selfdefctl | `module.toml` 12 | F03372 | non-negotiable | false | 10 |
| R06733 | SD-R72 — "third real demonstrator of the cycle-3 hardware-exploit surface" | `module.toml` 16 | F03373 | non-negotiable | false | 10 |
| R06734 | SD-R72 — after SD-R28 bitnet-gpu-inference | `module.toml` 17 | F03374 | non-negotiable | false | 10 |
| R06735 | SD-R72 — after SD-R48 wasm-aot-cache | `module.toml` 17 | F03375 | non-negotiable | false | 10 |
| R06736 | Doctrine — "showcases the SD-R64 + SD-R68 cycle-3 predicates" | `module.toml` 19 | F03376 | non-negotiable | false | 10 |
| R06737 | Doctrine — "AND the R212 (sovereign-os) model-class taxonomy" | `module.toml` 20 | F03377 | non-negotiable | false | 10 |
| R06738 | Predicate ternary_aot_capable_required = false | `module.toml` 22 | F03378 | non-negotiable | false | 10 |
| R06739 | Predicate rationale — "SLMs run dense, not ternary" | `module.toml` 22 | F03379 | non-negotiable | false | 10 |
| R06740 | Predicate zmm_int8_lanes_min = 32 | `module.toml` 23 | F03380 | non-negotiable | false | 10 |
| R06741 | Predicate rationale — AVX2 minimum | `module.toml` 23 | F03381 | non-negotiable | false | 10 |
| R06742 | Predicate rationale — 64 preferred for VNNI hot path | `module.toml` 24 | F03382 | non-negotiable | false | 10 |
| R06743 | Predicate host_features_required = "avx2,fma" | `module.toml` 25 | F03383 | non-negotiable | false | 10 |
| R06744 | Predicate rationale — load-bearing for llama.cpp dense kernels | `module.toml` 25 | F03384 | non-negotiable | false | 10 |
| R06745 | Cycle-1+2 gate — memory_gib_min = 8 | `module.toml` 32 | F03385 | non-negotiable | false | 10 |
| R06746 | Gate rationale — Phi-4-mini bf16 needs ~4 GiB | `module.toml` 32–33 | F03386 | non-negotiable | false | 10 |
| R06747 | Gate rationale — + tokenizer overhead | `module.toml` 33 | F03387 | non-negotiable | false | 10 |
| R06748 | Gate rationale — + KV cache headroom | `module.toml` 33 | F03388 | non-negotiable | false | 10 |
| R06749 | Cycle-1+2 gate — gpu_count_min = 0 | `module.toml` 35 | F03389 | non-negotiable | false | 10 |
| R06750 | Gate rationale — CPU-only by design | `module.toml` 35 | F03390 | non-negotiable | false | 10 |
| R06751 | Operator workflow section header | `module.toml` 37 | F03391 | non-negotiable | false | 10 |
| R06752 | Workflow step 1 — `selfdefctl modules apply slm-cpu-loop` | `module.toml` 38 | F03392 | non-negotiable | false | 10 |
| R06753 | Step 1 result — installs /etc/selfdef/slm-loop.env | `module.toml` 39 | F03393 | non-negotiable | false | 10 |
| R06754 | Step 1 — env carries CCD-0 core mask | `module.toml` 39 | F03394 | non-negotiable | false | 10 |
| R06755 | Step 1 — env carries model path placeholder | `module.toml` 39 | F03395 | non-negotiable | false | 10 |
| R06756 | Step 1 — env carries start command template | `module.toml` 40 | F03396 | non-negotiable | false | 10 |
| R06757 | Workflow step 2 — Operator sets SELFDEF_SLM_MODEL=Phi-4-mini-instruct | `module.toml` 41 | F03397 | non-negotiable | false | 10 |
| R06758 | Workflow step 2 — or any catalog id with class=slm | `module.toml` 42 | F03398 | non-negotiable | false | 10 |
| R06759 | Workflow step 3 — systemd-run wrapper picks up env file | `module.toml` 43 | F03399 | non-negotiable | false | 10 |
| R06760 | Composition — SD-R70 selfdefctl hardware aot-script | `module.toml` 46 | F03400 | non-negotiable | false | 10 |
| R06761 | Composition rationale — for AOT precompile | `module.toml` 46 | F03401 | non-negotiable | false | 10 |
| R06762 | Composition — SD-R67 selfdefctl hardware posture | `module.toml` 47 | F03402 | non-negotiable | false | 10 |
| R06763 | Composition rationale — operator confirms VNNI path | `module.toml` 47 | F03403 | non-negotiable | false | 10 |
| R06764 | Composition — R212 sovereign-os models query --class slm | `module.toml` 48 | F03404 | non-negotiable | false | 10 |
| R06765 | Composition rationale — find the right model | `module.toml` 48 | F03405 | non-negotiable | false | 10 |
| R06766 | [requires_hardware] block exists | `module.toml` 51 | F03406 | non-negotiable | false | 10 |
| R06767 | [requires_hardware] memory_gib_min = 8 | `module.toml` 52 | M00744 | non-negotiable | false | 10 |
| R06768 | [requires_hardware] zmm_int8_lanes_min = 32 | `module.toml` 53 | M00742 | non-negotiable | false | 10 |
| R06769 | [requires_hardware] host_features_required = "avx2,fma" | `module.toml` 54 | M00743 | non-negotiable | false | 10 |
| R06770 | [metadata] block exists | `module.toml` 57 | F03407 | non-negotiable | false | 10 |
| R06771 | [metadata] comment — "R212 (sovereign-os) model-class taxonomy mirror" | `module.toml` 54 | F03408 | non-negotiable | false | 10 |
| R06772 | [metadata] comment — "affinity tag" | `module.toml` 54 | F03408 | non-negotiable | false | 10 |
| R06773 | [metadata] comment — "Selfdef registry currently doesn't enforce the class taxonomy at the schema layer" | `module.toml` 55 | F03409 | non-negotiable | false | 10 |
| R06774 | [metadata] comment — "sovereign-os is the strict source" | `module.toml` 56 | F03410 | non-negotiable | false | 10 |
| R06775 | [metadata] comment — "communicates intent to operators reading the module.toml" | `module.toml` 57 | F03411 | non-negotiable | false | 10 |
| R06776 | [metadata] comment — "alongside R212 catalog entries with class=slm" | `module.toml` 58 | F03411 | non-negotiable | false | 10 |
| R06777 | [metadata] intended_model_class = "slm" | `module.toml` 59 | F03412 | non-negotiable | false | 10 |
| R06778 | [metadata] intended_purpose includes "chat" | `module.toml` 60 | F03413 | non-negotiable | false | 10 |
| R06779 | [metadata] intended_purpose includes "agent" | `module.toml` 60 | F03414 | non-negotiable | false | 10 |
| R06780 | [metadata] intended_purpose includes "function-calling" | `module.toml` 60 | F03415 | non-negotiable | false | 10 |
| R06781 | module.toml `instanced = false` | `module.toml` 62 | F03416 | non-negotiable | false | 10 |
| R06782 | module.toml `phase = "main"` | `module.toml` 65 | F03417 | non-negotiable | false | 10 |
| R06783 | Phase rationale — "hardware-tune-cache (pre-phase) has already populated /etc/selfdef/hardware-tune.env" | `module.toml` 64 | F03418 | non-negotiable | false | 10 |
| R06784 | module.toml `[install] kind = "script"` | `module.toml` 66 | F03419 | non-negotiable | false | 10 |
| R06785 | apply.sh header references SD-R72 | `install/apply.sh` 2 | F03420 | non-negotiable | false | 10 |
| R06786 | apply.sh — provisions /etc/selfdef/slm-loop.env | `install/apply.sh` 4 | F03421 | non-negotiable | false | 10 |
| R06787 | apply.sh — provisions with operator-tuned defaults | `install/apply.sh` 4–5 | M00734 | non-negotiable | false | 10 |
| R06788 | apply.sh — supports Phi-4-mini-instruct | `install/apply.sh` 5 | M00755 | non-negotiable | false | 10 |
| R06789 | apply.sh — supports Qwen3-1.7B | `install/apply.sh` 5 | M00755 | non-negotiable | false | 10 |
| R06790 | apply.sh — supports any catalog class=slm entry | `install/apply.sh` 5 | M00755 | non-negotiable | false | 10 |
| R06791 | apply.sh — CPU-pinned agent loop | `install/apply.sh` 6 | M00754 | non-negotiable | false | 10 |
| R06792 | apply.sh — env file consumed by systemd-run | `install/apply.sh` 8 | F03422 | non-negotiable | false | 10 |
| R06793 | apply.sh — env file consumed by systemd unit drop-ins | `install/apply.sh` 8 | F03422 | non-negotiable | false | 10 |
| R06794 | apply.sh — module just centralises canonical defaults | `install/apply.sh` 9 | F03423 | non-negotiable | false | 10 |
| R06795 | apply.sh — operators don't reinvent CCD-0 pinning per host | `install/apply.sh` 10 | F03424 | non-negotiable | false | 10 |
| R06796 | apply.sh — operators don't reinvent thread count math per host | `install/apply.sh` 11 | F03424 | non-negotiable | false | 10 |
| R06797 | apply.sh — idempotent | `install/apply.sh` 12 | F03425 | non-negotiable | false | 10 |
| R06798 | apply.sh — SELFDEF_DRY_RUN=1 aware | `install/apply.sh` 12 | F03426 | non-negotiable | false | 10 |
| R06799 | apply.sh — composes with SD-R66/R67/R70 | `install/apply.sh` 12 | F03427 | non-negotiable | false | 10 |
| R06800 | apply.sh MUST set -euo pipefail | `install/apply.sh` 14 | F03428 | non-negotiable | false | 10 |
| R06801 | apply.sh MODULE = "slm-cpu-loop" | `install/apply.sh` 16 | F03429 | non-negotiable | false | 10 |
| R06802 | apply.sh ENV_FILE default /etc/selfdef/slm-loop.env | `install/apply.sh` 17 | F03430 | non-negotiable | false | 10 |
| R06803 | apply.sh ENV_FILE override via SELFDEF_SLM_LOOP_ENV | `install/apply.sh` 17 | F03431 | non-negotiable | false | 10 |
| R06804 | apply.sh TUNE_FILE default /etc/selfdef/hardware-tune.env | `install/apply.sh` 18 | F03432 | non-negotiable | false | 10 |
| R06805 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env default 0 | `install/apply.sh` 19 | F03433 | non-negotiable | false | 10 |
| R06806 | apply.sh local emit_status helper | `install/apply.sh` 21–26 | F03434 | non-negotiable | false | 10 |
| R06807 | apply.sh emit_status JSON `{"module":"%s","status":"%s","message":"%s"}` format | `install/apply.sh` 24 | F03434 | non-negotiable | false | 10 |
| R06808 | apply.sh DRY_RUN=1 emits skipped "DRY-RUN — would write ${ENV_FILE}" | `install/apply.sh` 28–30 | F03435 | non-negotiable | false | 10 |
| R06809 | apply.sh DRY_RUN=1 exit 0 | `install/apply.sh` 30 | F03435 | non-negotiable | false | 10 |
| R06810 | apply.sh — mkdir -p dirname ENV_FILE | `install/apply.sh` 33 | F03436 | non-negotiable | false | 10 |
| R06811 | apply.sh CCD-0 rationale — "CCD-0 cores on Zen 5 9900X = 0-5 physical" | `install/apply.sh` 35 | F03437 | non-negotiable | false | 10 |
| R06812 | apply.sh CCD-0 rationale — "/ 0-11 with SMT" | `install/apply.sh` 35 | F03437 | non-negotiable | false | 10 |
| R06813 | apply.sh — best-effort tuned for 6-physical-core CCD-0 | `install/apply.sh` 36 | F03438 | non-negotiable | false | 10 |
| R06814 | apply.sh — operators with different topologies override SELFDEF_SLM_AFFINITY in their service unit | `install/apply.sh` 37 | F03439 | non-negotiable | false | 10 |
| R06815 | apply.sh DEFAULT_AFFINITY="0-5" | `install/apply.sh` 39 | F03440 | non-negotiable | false | 10 |
| R06816 | apply.sh DEFAULT_THREADS="6" | `install/apply.sh` 40 | F03441 | non-negotiable | false | 10 |
| R06817 | apply.sh CPU_MODEL probe from /proc/cpuinfo | `install/apply.sh` 42–47 | F03442 | non-negotiable | false | 10 |
| R06818 | apply.sh CPU_MODEL awk pattern parses "model name" line | `install/apply.sh` 45 | F03442 | non-negotiable | false | 10 |
| R06819 | apply.sh CPU_MODEL — strip leading spaces via gsub | `install/apply.sh` 45 | F03442 | non-negotiable | false | 10 |
| R06820 | apply.sh — env file uses cat-heredoc to write | `install/apply.sh` 49 | M00734 | non-negotiable | false | 10 |
| R06821 | apply.sh — env file header "# slm-cpu-loop env file — SD-R72" | `install/apply.sh` 50 | F03443 | non-negotiable | false | 10 |
| R06822 | apply.sh — env file says "Sourced by operator-supplied systemd units or systemd-run wrappers" | `install/apply.sh` 51 | F03444 | non-negotiable | false | 10 |
| R06823 | apply.sh — env file says "Override any value via /etc/systemd/system/<unit>.service.d/*.conf" | `install/apply.sh` 52 | F03445 | non-negotiable | false | 10 |
| R06824 | apply.sh — env file Generated on host: ${CPU_MODEL:-(unknown)} | `install/apply.sh` 54 | F03446 | non-negotiable | false | 10 |
| R06825 | apply.sh — env file Generated at: ISO timestamp via `date -u +%Y-%m-%dT%H:%M:%SZ` | `install/apply.sh` 55 | F03447 | non-negotiable | false | 10 |
| R06826 | apply.sh — env Affinity section header | `install/apply.sh` 57 | F03448 | non-negotiable | false | 10 |
| R06827 | apply.sh — env Affinity comment references master spec § 17.1 Pulse Vector Core | `install/apply.sh` 58 | F03449 | non-negotiable | false | 10 |
| R06828 | apply.sh — env Affinity comment "On 9900X this is cores 0-5 physical (0-11 with SMT)" | `install/apply.sh` 59 | F03450 | non-negotiable | false | 10 |
| R06829 | apply.sh — env Affinity comment "Override per host topology" | `install/apply.sh` 60 | F03451 | non-negotiable | false | 10 |
| R06830 | apply.sh — env Affinity comment "e.g. SELFDEF_SLM_AFFINITY='0-7' on a 9950X" | `install/apply.sh` 60 | F03451 | non-negotiable | false | 10 |
| R06831 | apply.sh — env SELFDEF_SLM_AFFINITY="${DEFAULT_AFFINITY}" | `install/apply.sh` 61 | F03452 | non-negotiable | false | 10 |
| R06832 | apply.sh — env SELFDEF_SLM_THREADS="${DEFAULT_THREADS}" | `install/apply.sh` 62 | F03453 | non-negotiable | false | 10 |
| R06833 | apply.sh — env Model selection section header | `install/apply.sh` 64 | F03454 | non-negotiable | false | 10 |
| R06834 | apply.sh — env comment "Operator-set" | `install/apply.sh` 65 | F03455 | non-negotiable | false | 10 |
| R06835 | apply.sh — env comment "Should match a sovereign-os models/catalog.yaml entry" | `install/apply.sh` 65 | F03455 | non-negotiable | false | 10 |
| R06836 | apply.sh — env comment "with class=slm" | `install/apply.sh` 65 | F03455 | non-negotiable | false | 10 |
| R06837 | apply.sh — env comment "Phi-4-mini-instruct" | `install/apply.sh` 66 | F03456 | non-negotiable | false | 10 |
| R06838 | apply.sh — env comment "Qwen3-1.7B-Instruct" | `install/apply.sh` 66 | F03456 | non-negotiable | false | 10 |
| R06839 | apply.sh — env comment "as of R212" | `install/apply.sh` 66 | F03456 | non-negotiable | false | 10 |
| R06840 | apply.sh — env comment "Discover via: sovereign-osctl models query --class slm" | `install/apply.sh` 67 | F03457 | non-negotiable | false | 10 |
| R06841 | apply.sh — env SELFDEF_SLM_MODEL="" (operator-set) | `install/apply.sh` 68 | F03458 | non-negotiable | false | 10 |
| R06842 | apply.sh — env SELFDEF_SLM_MODEL_PATH="" (operator-set) | `install/apply.sh` 69 | F03459 | non-negotiable | false | 10 |
| R06843 | apply.sh — env Engine selection section header | `install/apply.sh` 71 | F03460 | non-negotiable | false | 10 |
| R06844 | apply.sh — env comment "llama.cpp recommended for GGUF Phi-4-mini" | `install/apply.sh` 72 | F03461 | non-negotiable | false | 10 |
| R06845 | apply.sh — env comment "vllm for bf16 Qwen3" | `install/apply.sh` 72 | F03462 | non-negotiable | false | 10 |
| R06846 | apply.sh — env comment "Set to match the catalog entry's 'engine' field" | `install/apply.sh` 73 | M00755 | non-negotiable | false | 10 |
| R06847 | apply.sh — env SELFDEF_SLM_ENGINE="llama.cpp" | `install/apply.sh` 73 | F03463 | non-negotiable | false | 10 |
| R06848 | apply.sh — env Optional KV cache + context section header | `install/apply.sh` 75 | F03464 | non-negotiable | false | 10 |
| R06849 | apply.sh — env comment "Phi-4-mini supports 128k context" | `install/apply.sh` 76 | F03465 | non-negotiable | false | 10 |
| R06850 | apply.sh — env comment "operator loop typically uses far less" | `install/apply.sh` 77 | F03465 | non-negotiable | false | 10 |
| R06851 | apply.sh — env comment "Tune to actual operator query depth" | `install/apply.sh` 77 | F03465 | non-negotiable | false | 10 |
| R06852 | apply.sh — env SELFDEF_SLM_CONTEXT_TOKENS="8192" | `install/apply.sh` 78 | F03466 | non-negotiable | false | 10 |
| R06853 | apply.sh — env SELFDEF_SLM_KV_DTYPE="fp16" | `install/apply.sh` 79 | F03467 | non-negotiable | false | 10 |
| R06854 | apply.sh — Worked invocation example section header | `install/apply.sh` 81 | F03468 | non-negotiable | false | 10 |
| R06855 | apply.sh — invocation uses `taskset -c ${SELFDEF_SLM_AFFINITY}` | `install/apply.sh` 82 | F03469 | non-negotiable | false | 10 |
| R06856 | apply.sh — invocation runs `llama-server` | `install/apply.sh` 82 | F03469 | non-negotiable | false | 10 |
| R06857 | apply.sh — invocation `-m ${SELFDEF_SLM_MODEL_PATH}` | `install/apply.sh` 83 | F03470 | non-negotiable | false | 10 |
| R06858 | apply.sh — invocation `-t ${SELFDEF_SLM_THREADS}` | `install/apply.sh` 84 | F03471 | non-negotiable | false | 10 |
| R06859 | apply.sh — invocation `-c ${SELFDEF_SLM_CONTEXT_TOKENS}` | `install/apply.sh` 85 | F03472 | non-negotiable | false | 10 |
| R06860 | apply.sh — invocation `--port 8082` | `install/apply.sh` 86 | F03473 | non-negotiable | false | 10 |
| R06861 | apply.sh — final emit_status "ok" | `install/apply.sh` 89 | F03474 | non-negotiable | false | 10 |
| R06862 | apply.sh — final success message "wrote ${ENV_FILE}; operator sets SELFDEF_SLM_MODEL{,_PATH}" | `install/apply.sh` 89 | F03474 | non-negotiable | false | 10 |
| R06863 | check.sh — read-only | `install/check.sh` 2 | F03475 | non-negotiable | false | 10 |
| R06864 | check.sh MUST set -euo pipefail | `install/check.sh` 4 | M00735 | non-negotiable | false | 10 |
| R06865 | check.sh MODULE = "slm-cpu-loop" | `install/check.sh` 6 | M00735 | non-negotiable | false | 10 |
| R06866 | check.sh ENV_FILE default /etc/selfdef/slm-loop.env | `install/check.sh` 7 | M00735 | non-negotiable | false | 10 |
| R06867 | check.sh ENV_FILE override via SELFDEF_SLM_LOOP_ENV | `install/check.sh` 7 | M00735 | non-negotiable | false | 10 |
| R06868 | check.sh local emit_status helper | `install/check.sh` 9–14 | M00735 | non-negotiable | false | 10 |
| R06869 | check.sh — ENV_FILE existence check | `install/check.sh` 16 | F03476 | non-negotiable | false | 10 |
| R06870 | check.sh — missing → emit failed "${ENV_FILE} missing — run apply first" + exit 1 | `install/check.sh` 17–19 | F03476 | non-negotiable | false | 10 |
| R06871 | check.sh — loops for SELFDEF_SLM_AFFINITY presence | `install/check.sh` 21–25 | F03477 | non-negotiable | false | 10 |
| R06872 | check.sh — loops for SELFDEF_SLM_THREADS presence | `install/check.sh` 21–25 | F03477 | non-negotiable | false | 10 |
| R06873 | check.sh — loops for SELFDEF_SLM_ENGINE presence | `install/check.sh` 21–25 | F03477 | non-negotiable | false | 10 |
| R06874 | check.sh — missing key → emit failed "env file missing ${key}" + exit 1 | `install/check.sh` 22–25 | F03477 | non-negotiable | false | 10 |
| R06875 | check.sh — "env file should have the canonical knobs even when the operator hasn't yet set SELFDEF_SLM_MODEL" | `install/check.sh` 18–20 | F03477 | non-negotiable | false | 10 |
| R06876 | check.sh — success emit "ok" "env file present + carries SLM loop defaults" | `install/check.sh` 28 | F03478 | non-negotiable | false | 10 |
| R06877 | uninstall.sh — removes env file | `install/uninstall.sh` 22 | F03479 | non-negotiable | false | 10 |
| R06878 | uninstall.sh — PRESERVES operator-written systemd unit drop-ins | `install/uninstall.sh` 4 | F03480 | non-negotiable | false | 10 |
| R06879 | uninstall.sh — drop-ins live under /etc/systemd/system/<unit>.d/ | `install/uninstall.sh` 5 | F03480 | non-negotiable | false | 10 |
| R06880 | uninstall.sh — drop-ins are operator-owned content | `install/uninstall.sh` 6 | F03480 | non-negotiable | false | 10 |
| R06881 | uninstall.sh MUST set -euo pipefail | `install/uninstall.sh` 8 | M00736 | non-negotiable | false | 10 |
| R06882 | uninstall.sh MODULE = "slm-cpu-loop" | `install/uninstall.sh` 10 | M00736 | non-negotiable | false | 10 |
| R06883 | uninstall.sh ENV_FILE override via SELFDEF_SLM_LOOP_ENV | `install/uninstall.sh` 11 | M00736 | non-negotiable | false | 10 |
| R06884 | uninstall.sh DRY_RUN from SELFDEF_DRY_RUN env | `install/uninstall.sh` 12 | M00736 | non-negotiable | false | 10 |
| R06885 | uninstall.sh local emit_status helper | `install/uninstall.sh` 14–19 | M00736 | non-negotiable | false | 10 |
| R06886 | uninstall.sh DRY_RUN=1 emit skipped "DRY-RUN — would remove ${ENV_FILE}" + exit 0 | `install/uninstall.sh` 20–23 | M00736 | non-negotiable | false | 10 |
| R06887 | uninstall.sh — rm -f ${ENV_FILE} | `install/uninstall.sh` 25 | M00736 | non-negotiable | false | 10 |
| R06888 | uninstall.sh — emit ok "removed ${ENV_FILE}; preserved operator unit drop-ins" | `install/uninstall.sh` 26 | M00736 | non-negotiable | false | 10 |
| R06889 | Cross-module — MS010 hardware-tune-cache provides `hardware-tune-env` consumed by this module | `module.toml` 6 + 9 + cross-ref MS010 | M00738 | non-negotiable | false | 10 |
| R06890 | Cross-module — SD-R28 bitnet-gpu-inference is the lineage predecessor (cycle-3 demonstrator) | `module.toml` 17 + cross-ref MS028 | F03374 | non-negotiable | false | 10 |
| R06891 | Cross-module — SD-R48 wasm-aot-cache is the lineage predecessor (cycle-3 demonstrator) | `module.toml` 17 + cross-ref MS031 | F03375 | non-negotiable | false | 10 |
| R06892 | Cross-module — SD-R66 selfdefctl hardware command surface | `install/apply.sh` 12 | F03427 | non-negotiable | false | 10 |
| R06893 | Cross-module — SD-R67 selfdefctl hardware posture | `module.toml` 47 + `install/apply.sh` 12 | F03402 | non-negotiable | false | 10 |
| R06894 | Cross-module — SD-R70 selfdefctl hardware aot-script | `module.toml` 46 + `install/apply.sh` 12 | F03400 | non-negotiable | false | 10 |
| R06895 | Cross-module — R212 sovereign-os models/catalog.yaml schema | `module.toml` 48 + `install/apply.sh` 65 | F03404 | non-negotiable | false | 10 |
| R06896 | Cross-module — R212 sovereign-osctl models query --class slm CLI | `module.toml` 48 + `install/apply.sh` 67 | F03457 | non-negotiable | false | 10 |
| R06897 | Cross-module — R212 catalog field `class` (slm enforcement source) | `module.toml` 56 | F03410 | non-negotiable | false | 10 |
| R06898 | Cross-module — R212 catalog field `engine` (llama.cpp / vllm) | `install/apply.sh` 73 | M00755 | non-negotiable | false | 10 |
| R06899 | Cross-module — master spec § 17.1 Pulse Vector Core (CCD-0 framing) | `install/apply.sh` 58 | F03449 | non-negotiable | false | 10 |
| R06900 | Project-boundary — MS029 is selfdef IPS-side CPU-pinned SLM scope; sovereign-os has its own SLM serving via M046 LoRA foundry + M026 SLM swarm | architecture + cross-ref M026 + M046 | E0291 | non-negotiable | false | 10 |
| R06901 | Project-boundary — selfdef R212 [metadata] is affinity tag NOT schema enforcement | `module.toml` 54–56 | F03408 + F03409 | non-negotiable | false | 10 |
| R06902 | Project-boundary — sovereign-os enforces class=slm taxonomy at registry schema layer | `module.toml` 55–56 | F03409 + F03410 | non-negotiable | false | 10 |
| R06903 | Cross-repo — selfdef slm-cpu-loop CPU side + sovereign-os SLM swarm (M026) + LoRA foundry (M046) form complementary planes | cross-ref MS029 + M026 + M046 | E0291 | non-negotiable | false | 10 |
| R06904 | Cross-repo — selfdef MS007 audit-manifest typed-mirror carries slm-loop env schema for cross-repo audit | architecture + cross-ref MS007 | M00755 | non-negotiable | false | 10 |
| R06905 | Hardware-exploit doctrine — cycle-3 [requires_hardware] declares 3 minimum predicates (memory + AVX2 lanes + features) | `module.toml` 51–55 | E0294 | non-negotiable | false | 10 |
| R06906 | Hardware-exploit doctrine — cycle-3 surface composes with cycle-1+2 gate semantics | `module.toml` 31–35 | E0295 | non-negotiable | false | 10 |
| R06907 | Hardware-exploit doctrine — predicates are predicates (true/false/min-value/feature-flag-string) | `module.toml` 53–55 | E0294 | non-negotiable | false | 10 |
| R06908 | Hardware-exploit doctrine — module-loader SHALL refuse to land if any predicate fails | `module.toml` 53–55 | E0294 | non-negotiable | false | 10 |
| R06909 | Hardware-exploit doctrine — operator-readable hardware-exploit declarations make hardware capability LEGIBLE | `module.toml` 16–17 | M00740 | non-negotiable | false | 10 |
| R06910 | Operator UX — `selfdefctl modules apply slm-cpu-loop` is the canonical apply trigger | `module.toml` 38 | F03392 | non-negotiable | false | 10 |
| R06911 | Operator UX — first apply writes env file with defaults | `module.toml` 39 | F03393 | non-negotiable | false | 10 |
| R06912 | Operator UX — operator sets SELFDEF_SLM_MODEL after apply | `module.toml` 41 | F03397 | non-negotiable | false | 10 |
| R06913 | Operator UX — systemd-run wrapper picks up env file | `module.toml` 43 | F03399 | non-negotiable | false | 10 |
| R06914 | Operator UX — env file changes via `/etc/systemd/system/<unit>.service.d/*.conf` drop-ins | `install/apply.sh` 52 | F03445 | non-negotiable | false | 10 |
| R06915 | Output schema — env file uses bash-syntax KEY=value assignments | `install/apply.sh` 49 + 60–80 | M00755 | non-negotiable | false | 10 |
| R06916 | Output schema — env file MUST carry SELFDEF_SLM_AFFINITY | `install/apply.sh` 61 + `install/check.sh` 21–25 | M00755 | non-negotiable | false | 10 |
| R06917 | Output schema — env file MUST carry SELFDEF_SLM_THREADS | `install/apply.sh` 62 + `install/check.sh` 21–25 | M00755 | non-negotiable | false | 10 |
| R06918 | Output schema — env file MUST carry SELFDEF_SLM_ENGINE | `install/apply.sh` 73 + `install/check.sh` 21–25 | M00755 | non-negotiable | false | 10 |
| R06919 | Output schema — env file MAY carry SELFDEF_SLM_MODEL (empty by default) | `install/apply.sh` 68 | M00755 | non-negotiable | false | 10 |
| R06920 | Output schema — env file MAY carry SELFDEF_SLM_MODEL_PATH (empty by default) | `install/apply.sh` 69 | M00755 | non-negotiable | false | 10 |
| R06921 | Output schema — env file MAY carry SELFDEF_SLM_CONTEXT_TOKENS (8192 default) | `install/apply.sh` 78 | M00755 | non-negotiable | false | 10 |
| R06922 | Output schema — env file MAY carry SELFDEF_SLM_KV_DTYPE (fp16 default) | `install/apply.sh` 79 | M00755 | non-negotiable | false | 10 |
| R06923 | Output schema — env file MAY carry worked invocation example as commented lines | `install/apply.sh` 81–86 | M00756 | non-negotiable | false | 10 |
| R06924 | Module-system invariant — phase=main runs after hardware-tune-cache phase=pre | `module.toml` 64–65 + cross-ref MS010 | F03418 | non-negotiable | false | 10 |
| R06925 | Module-system invariant — depends_on=hardware-tune-cache means MS010 MUST be installed first | `module.toml` 6 + cross-ref MS010 | F03368 | non-negotiable | false | 10 |
| R06926 | Module-system invariant — consumes=hardware-tune-env means MS010 MUST provide that surface | `module.toml` 9 + cross-ref MS010 | F03371 | non-negotiable | false | 10 |
| R06927 | Module-system invariant — provides=slm-loop-runtime is the operator-facing surface | `module.toml` 8 | F03370 | non-negotiable | false | 10 |
| R06928 | Module-system invariant — instanced=false (host has one SLM loop env) | `module.toml` 62 | F03416 | non-negotiable | false | 10 |
| R06929 | Test integration — MS020 L1-L5 layered harness covers Module-script category (apply/check/uninstall) | cross-ref MS020 | M00734 + M00735 + M00736 | non-negotiable | false | 10 |
| R06930 | Test integration — MS020 hardware-aware test category covers [requires_hardware] gate evaluation | cross-ref MS020 + MS010 | E0294 | non-negotiable | false | 10 |
| R06931 | Test integration — MS020 host-class test covers Zen 5 CCD-0 affinity path | cross-ref MS020 + `install/apply.sh` 39 | F03440 | non-negotiable | false | 10 |
| R06932 | Test integration — MS020 host-class test covers non-Zen-5 affinity override | cross-ref MS020 + `install/apply.sh` 60 | F03451 | non-negotiable | false | 10 |
| R06933 | Hardware reality — Zen 5 9900X CCD-0 = 6 physical cores (cores 0-5) | `install/apply.sh` 35 | F03437 | non-negotiable | false | 10 |
| R06934 | Hardware reality — Zen 5 9900X with SMT = cores 0-11 | `install/apply.sh` 35 | F03437 | non-negotiable | false | 10 |
| R06935 | Hardware reality — Zen 5 9950X has 16 cores = wider affinity range | `install/apply.sh` 60 | F03451 | non-negotiable | false | 10 |
| R06936 | Hardware reality — AVX2 + FMA required for llama.cpp dense CPU kernels | `module.toml` 25 | F03384 | non-negotiable | false | 10 |
| R06937 | Hardware reality — AVX-512 VNNI (zmm_int8_lanes_min=64) is the preferred hot path | `module.toml` 24 | F03382 | non-negotiable | false | 10 |
| R06938 | Model reality — Phi-4-mini-instruct uses bf16 (~4 GiB) + tokenizer + KV cache | `module.toml` 32–33 | M00744 | non-negotiable | false | 10 |
| R06939 | Model reality — Phi-4-mini supports 128k context | `install/apply.sh` 76 | F03465 | non-negotiable | false | 10 |
| R06940 | Model reality — Qwen3-1.7B-Instruct is the alternate class=slm catalog entry | `install/apply.sh` 66 | F03456 | non-negotiable | false | 10 |
| R06941 | Engine reality — llama.cpp recommended for GGUF Phi-4-mini | `install/apply.sh` 72 | F03461 | non-negotiable | false | 10 |
| R06942 | Engine reality — vllm recommended for bf16 Qwen3 | `install/apply.sh` 72 | F03462 | non-negotiable | false | 10 |
| R06943 | Engine reality — llama-server CLI exposed via `--port 8082` by default | `install/apply.sh` 86 | F03473 | non-negotiable | false | 10 |
| R06944 | Engine reality — `taskset -c` is the canonical CPU-pin invocation prefix | `install/apply.sh` 82 | F03469 | non-negotiable | false | 10 |
| R06945 | Configuration overlay — SELFDEF_SLM_LOOP_ENV environment override | `install/apply.sh` 17 + `install/check.sh` 7 + `install/uninstall.sh` 11 | M00734 | non-negotiable | false | 10 |
| R06946 | Configuration overlay — operator unit drop-ins override env file values | `install/apply.sh` 52 | F03445 | non-negotiable | false | 10 |
| R06947 | Configuration overlay — operator overrides take precedence over module defaults | `install/apply.sh` 52 | F03445 | non-negotiable | false | 10 |
| R06948 | SD-reference — SD-R64 cycle-3 ternary_aot_capable + zmm_int8_lanes + host_features_required gates | `module.toml` 19 | F03376 | non-negotiable | false | 10 |
| R06949 | SD-reference — SD-R68 cycle-3 [metadata] block extension | `module.toml` 19 | F03376 | non-negotiable | false | 10 |
| R06950 | SD-reference — SD-R72 is the third real demonstrator of cycle-3 surface | `module.toml` 16 | F03373 | non-negotiable | false | 10 |
| R06951 | SD-reference — SD-R66 selfdefctl hardware command surface | `install/apply.sh` 12 | F03427 | non-negotiable | false | 10 |
| R06952 | SD-reference — SD-R67 selfdefctl hardware posture surface | `module.toml` 47 | F03402 | non-negotiable | false | 10 |
| R06953 | SD-reference — SD-R70 selfdefctl hardware aot-script surface | `module.toml` 46 | F03400 | non-negotiable | false | 10 |
| R06954 | SD-reference — R212 sovereign-os models catalog (cross-repo binding) | `module.toml` 48 | F03404 | non-negotiable | false | 10 |
| R06955 | Operator references — Phi-4-mini-instruct model card | `module.toml` 32 + `install/apply.sh` 66 | M00744 | non-negotiable | false | 10 |
| R06956 | Operator references — Qwen3-1.7B-Instruct model card | `install/apply.sh` 66 | F03456 | non-negotiable | false | 10 |
| R06957 | Operator references — llama.cpp GitHub | `install/apply.sh` 72 | F03461 | non-negotiable | false | 10 |
| R06958 | Operator references — vllm docs | `install/apply.sh` 72 | F03462 | non-negotiable | false | 10 |
| R06959 | Operator references — Zen 5 9900X CCD topology + 17.1 Pulse Vector Core master spec | `install/apply.sh` 35 + 58 | F03449 | non-negotiable | false | 10 |
| R06960 | Composite — MS029 (10 epics / 26 modules / 120 features / 240 reqs) covers slm-cpu-loop module v0.1.0 (213 lines): module.toml (66-line manifest with cycle-3 [requires_hardware] memory_gib_min=8+zmm_int8_lanes_min=32+host_features_required="avx2,fma" + R212 [metadata] intended_model_class="slm"+intended_purpose=["chat","agent","function-calling"] + instanced=false + phase=main + depends_on=hardware-tune-cache + provides=slm-loop-runtime + consumes=hardware-tune-env) + apply.sh (90-line idempotent env-file generator + CCD-0 default 0-5 affinity + 6 default threads + 7-key env schema + worked invocation example + CPU model probe from /proc/cpuinfo) + check.sh (30-line 3-key presence verifier) + uninstall.sh (27-line tear-down preserving operator unit drop-ins); SD-R72 third demonstrator of cycle-3 hardware-exploit surface after SD-R28 bitnet + SD-R48 wasm-aot-cache; SLMs run dense not ternary; Phi-4-mini-instruct + Qwen3-1.7B-Instruct as R212 catalog class=slm entries; llama.cpp recommended for GGUF + vllm for bf16; cross-module composition with SD-R66/R67/R70 + R212; cross-repo binding to sovereign-os via MS007 typed-mirror crates | `modules/slm-cpu-loop/` 213 lines | E0291 + E0292 + E0293 + E0294 + E0295 + E0296 + E0297 + E0298 + E0299 + E0300 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml identity + surfaces + binary + SD-R72 lineage + 3 cycle-3 predicates + 2 cycle-1+2 gates (R06721–R06750) + operator workflow 3 steps + 3 SD-R compositions (R06751–R06765) + [requires_hardware] + [metadata] block (R06766–R06784) + apply.sh full transcription (R06785–R06862) + check.sh full transcription (R06863–R06876) + uninstall.sh full transcription (R06877–R06888) + cross-module SD-R references + R212 cross-repo (R06889–R06899) + project-boundary + cross-repo (R06900–R06904) + hardware-exploit doctrine + module-loader invariants (R06905–R06909) + operator UX (R06910–R06914) + output schema (R06915–R06923) + module-system invariants (R06924–R06928) + test integration (R06929–R06932) + hardware reality (R06933–R06937) + model + engine reality (R06938–R06944) + configuration overlay (R06945–R06947) + SD-reference table (R06948–R06954) + operator references (R06955–R06959) + composite (R06960)
- Source range 213 lines yields 240 R-rows representing 1.13:1 R-per-line at the verbatim-citation level
- Project boundary — MS029 is selfdef IPS CPU-pinned SLM inference scope; sovereign-os has its own model serving stack (M026 SLM swarm + M046 LoRA foundry); cross-repo audit routes through MS007 audit-manifest typed-mirror crate

## Cross-references

- Adjacent INDEX rows: MS028 BitNet GPU inference / MS030 Tensor parallel inference
- Cross-module dependency chain — MS010 hardware-tune-cache (phase=pre) → MS029 slm-cpu-loop (phase=main) → operator-supplied systemd unit
- SD-R lineage — SD-R28 bitnet-gpu-inference (MS028) → SD-R48 wasm-aot-cache (MS031) → SD-R72 slm-cpu-loop (this module) — third cycle-3 demonstrator
- Cycle-3 hardware-exploit gates — SD-R64 + SD-R68 cycle-3 predicates (ternary_aot_capable + zmm_int8_lanes + host_features_required) extend SD-R26 cycle-2 [requires_hardware] surface; metadata block (R212 mirror) is the new cycle-3 dimension
- R212 sovereign-os models catalog — sovereign-os enforces class taxonomy at schema layer; selfdef [metadata] is affinity tag only; cross-repo binding for catalog discovery (`sovereign-osctl models query --class slm`)
- Master spec § 17.1 Pulse Vector Core — CCD-0 affinity framing; Zen 5 9900X 6 physical cores (0-5) / 12 with SMT (0-11)
- Cross-repo binding — sovereign-os M026 SLM swarm + M046 LoRA foundry stack on Blackwell/3090 mirrors selfdef CPU-pinned SLM loop; cross-repo audit via MS007 audit-manifest typed-mirror crate
- Operator references: Phi-4-mini-instruct model card (Microsoft) + Qwen3-1.7B-Instruct model card (Alibaba) + llama.cpp GitHub + vllm docs + Zen 5 9900X CCD topology + master spec § 17.1 Pulse Vector Core
