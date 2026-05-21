# SDD-035 — BitNet GPU inference module — MS028

> Status: **implemented** — Stage-2 architectural spec for the
> shipped `bitnet-gpu-inference` module under
> `modules/bitnet-gpu-inference/`. The module provisions the host for
> GPU-side BitNet ternary inference (1-bit / ternary kernels exploiting
> AVX-512 BF16 ZMM utilization per dump line 11187+) and ships in
> production today: module manifest + install/apply.sh + install/
> check.sh + L2 bats coverage + `/v1/modules/:name/check` per-module
> health probe (cross-cutting, commit c1f41c6) + `/v1/modules/diff`
> activation tracking + dashboard "Modules" panel.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21 (status: draft → implemented; body always
> said "ships in production today" — the header had drifted).
> Implements milestone: MS028 (catalog
> `backlog/milestones/MS028-bitnet-gpu-inference-module.md`)
> Builds on: SDD-018 (MS010 hardware-tune-cache — upstream substrate
> this module consumes via `consumes = ["hardware-tune-env"]` +
> `depends_on = ["hardware-tune-cache"]`)
> Companions: L2 bats suite at
> `packaging/test/L2-bitnet-gpu-inference.bats` (21 tests with
> mocked-selfdefctl dry-run smoke + idempotency)

## Problem

The sovereign AI workstation needs GPU-side ternary inference (BitNet)
to extract the full power of the SAIN-01 GPU pair (RTX PRO 6000 98 GiB
+ RTX 3090 24 GiB). BitNet kernels use BF16 for activation reduction
which means:
- the AVX-512 BF16 instruction set must be present (CPU side
  pre-processing)
- the GPU must have ≥ 8 GiB VRAM (the smallest BitNet checkpoints
  worth running end-to-end)
- the host must have ≥ 32 GiB system memory headroom
- the scheduler needs schedule.json that pins the model to the
  largest-VRAM GPU and tokenization to the secondary GPU

Without this module, every operator deploying BitNet has to write
their own runtime.env + schedule.json against `selfdefctl hardware
probe` output, fragmenting the compute-stack contract.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO
>  EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base
>  reason being."

Translation for MS028: BitNet provisioning must EXPLOIT THE STACK —
AVX-512 BF16 + multi-GPU schedule pinning + the MS010 hardware-tune-env
cache must compose into a single `selfdefctl modules apply` invocation
that lights up ternary inference on a SAIN-01-class workstation.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/bitnet-gpu-inference/module.toml` | depends_on=[hardware-tune-cache], consumes=[hardware-tune-env], provides=[bitnet-gpu-runtime], `[requires_hardware]` with 5 predicates |
| Apply | `modules/bitnet-gpu-inference/install/apply.sh` | Renders `/etc/selfdef/bitnet/{runtime.env, schedule.json}` from `selfdefctl hardware export` output |
| Check | `modules/bitnet-gpu-inference/install/check.sh` | Read-only verifier; 4 expected artifact paths |
| Uninstall | `modules/bitnet-gpu-inference/install/uninstall.sh` | Idempotent tear-down |
| L2 tests | `packaging/test/L2-bitnet-gpu-inference.bats` | 21 tests |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Five `[requires_hardware]` predicates

| Predicate | Value | Why |
|---|---|---|
| `avx512_bf16` | `true` | BitNet kernels use BF16 for activation reduction |
| `memory_gib_min` | `32` | Model staging + tokenizer needs headroom |
| `gpu_count_min` | `1` | At least one NVIDIA GPU available |
| `gpu_vram_gib_min` | `8` | Smallest BitNet checkpoints worth running end-to-end |
| `gpu_power_headroom_watts_min` | `100` | Scheduler cushion for sustained loads on RTX PRO 6000 + RTX 3090 pair |

On a SAIN-01 box (RTX PRO 6000 98 GiB + RTX 3090 24 GiB + AVX-512
BF16 capable CPU) all five predicates pass. On a 24-GiB-only host
(RTX 3090 alone) the vram + headroom gates still pass (single 24 GiB
> 8 GiB).

### Deliverable 2 — Two output artifacts

| File | Content |
|---|---|
| `/etc/selfdef/bitnet/runtime.env` | Sources MS010 `hardware-tune.env` + sets `BITNET_*` paths (BITNET_ETC_DIR, BITNET_STATE_DIR, BITNET_MODEL_PATH, BITNET_TOKENIZER_PATH) |
| `/etc/selfdef/bitnet/schedule.json` | Per-GPU scheduling map derived from `selfdefctl hardware export`; largest-VRAM GPU hosts the model, secondary handles tokenization |

The schedule.json is operator-readable JSON so the operator can
inspect the per-GPU pinning before the runtime takes effect.

### Deliverable 3 — Override env vars (testability)

| Env var | Default | Purpose |
|---|---|---|
| `SELFDEF_BITNET_ETC_DIR` | `/etc/selfdef/bitnet` | ETC root override (L2 test harness) |
| `SELFDEF_BITNET_STATE_DIR` | `/var/lib/selfdef/bitnet` | State root override |
| `SELFDEF_HARDWARE_TUNE_ENV` | `/etc/selfdef/hardware-tune.env` | Upstream tune env override |
| `SELFDEF_DRY_RUN` | `0` | When `1`, print intended changes; no FS writes |

L2 bats smoke uses all four to point at a tmpdir without touching
the host's `/etc/selfdef/`.

### Deliverable 4 — Cross-module integration with MS010

`apply.sh` sources `${SELFDEF_HARDWARE_TUNE_ENV}` so the generated
`runtime.env` inherits the host-tuned compile flags from MS010. This
is the integration that lets bitnet.cpp rebuilds pick up the host's
actual AVX-512 capabilities (BF16/FP16/VNNI flags + ZMM-width hint)
without each build script doing its own hardware probe.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest declares MS010 dependency | L2 bats test 3 |
| All 5 `[requires_hardware]` predicates declared | L2 bats test 7 |
| 3 install scripts shipped + executable | L2 bats test 8 |
| apply.sh writes runtime.env + schedule.json | L2 bats tests 12, 13 |
| apply.sh consumes hardware-tune.env | L2 bats test 14 |
| apply.sh calls `selfdefctl hardware export` | L2 bats test 15 |
| Fails fast when selfdefctl is missing | L2 bats test 16 |
| Dry-run smoke + idempotency | L2 bats tests 20, 21 |
| Coherence harness includes L2-bitnet-gpu-inference | `make coherence` discovers it |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with `[requires_hardware]` 5-predicate gate
2. ✅ `install/apply.sh` with hardware-tune.env consumption + per-GPU
   schedule derivation from `selfdefctl hardware export`
3. ✅ `install/check.sh` verifying 4 artifact paths
4. ✅ `install/uninstall.sh` idempotent tear-down
5. ✅ L2 bats coverage (21 tests including dry-run smoke with
   mocked selfdefctl emitting a plausible per-GPU JSON)

## Authorization for Stage-3+ work

This SDD authorizes:

- Multi-checkpoint support — extend schedule.json with checkpoint
  rotation by adding a `[checkpoints]` section to the module config
- Quantization profiles — INT8 / INT4 / ternary as `[profiles]`
  values (currently single `default` profile)
- Cross-watchdog handoff — the MS048 Goldilocks scheduler can route
  inference requests to this module via the bitnet-gpu-runtime
  provides contract once its routing config knows about the
  contract surface
- Profiling integration — emit `selfdef_bitnet_*` Prometheus series
  via a new collector that reads /var/lib/selfdef/bitnet/ counters

Mark a Stage-3+ extension DONE only when it reaches operator-visible
production (visible in `selfdefctl modules info bitnet-gpu-inference`
+ verifiable via L2 bats).

— End of SDD-035 / MS028 Stage-2.
