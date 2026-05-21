# SDD-037 — Tensor-parallel inference module — MS030

> Status: **implemented** — Stage-2 architectural spec for the
> shipped `tensor-parallel-inference` module under
> `modules/tensor-parallel-inference/`. The module provisions
> tensor-parallel inference splits where every GPU hosts a slice —
> demonstrating SD-R51 ALL-semantics + SD-R55 signing composition per
> SD-R58.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS030 (catalog
> `backlog/milestones/MS030-tensor-parallel-inference-module.md`)
> Builds on: SDD-018 (MS010 hardware-tune-cache substrate)
> Companions: SDD-035 (MS028 BitNet GPU inference — single-GPU path),
> SDD-036 (MS029 SLM CPU loop — CPU path), L2 bats suite at
> `packaging/test/L2-tensor-parallel-inference.bats` (8 tests)

## Problem

Large language model inference benefits from tensor-parallel splits
across multiple GPUs — the model's tensor weights are partitioned
column-wise across GPUs, and each GPU computes a slice of every
matmul. This gives near-linear speedup for memory-bound layers + lets
checkpoints larger than any single GPU's VRAM fit by aggregating
total VRAM.

For the SAIN-01 box (RTX PRO 6000 98 GiB + RTX 3090 24 GiB = 122 GiB
aggregate), tensor-parallel inference unlocks 70B-class models that
neither GPU alone could host.

Without this module, every operator running tensor-parallel inference
has to write their own per-GPU partition config + worry about NCCL /
device-to-device transport + manage the lifecycle of the runtime.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO
>  EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base
>  reason being. This will be the ultimate local network AI
>  workstation."

Translation for MS030: tensor-parallel splits must EXPLOIT every GPU
on the host (SD-R51 ALL-semantics — when `instanced = true` with an
ALL fan-out, every GPU gets a slice). Composition with MS003 signing
(SD-R55) means the splits' weights are signature-verified end-to-end
before loading.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/tensor-parallel-inference/module.toml` | depends_on=[hardware-tune-cache], provides=[tensor-parallel-runtime] |
| Apply | `modules/tensor-parallel-inference/install/apply.sh` | Renders per-GPU partition config under `/etc/selfdef/tensor-parallel/` |
| Check | `modules/tensor-parallel-inference/install/check.sh` | Read-only verifier |
| Uninstall | `modules/tensor-parallel-inference/install/uninstall.sh` | Idempotent tear-down |
| L2 tests | `packaging/test/L2-tensor-parallel-inference.bats` | 8 tests with dry-run smoke using a 2-GPU mocked-selfdefctl JSON |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — ALL-semantics fan-out

When `instanced = true` with ALL fan-out (per SD-R51), this module
materializes one partition per GPU discovered via `selfdefctl
hardware export`. On SAIN-01 that's 2 partitions (one per RTX). On
a 4-GPU box that's 4 partitions. On a 1-GPU box this module still
applies — it just degenerates to a single-GPU "tensor-parallel"
config that's equivalent to non-tensor-parallel, but kept for
operator consistency (one apply path covers all topologies).

### Deliverable 2 — Per-GPU partition config

For a 2-GPU SAIN-01 (RTX 3090 = 24 GiB at index 0, RTX PRO 6000 =
98 GiB at index 1), `apply.sh` writes
`/etc/selfdef/tensor-parallel/partition-0.toml` +
`/etc/selfdef/tensor-parallel/partition-1.toml`. Each partition file
declares:

```toml
gpu_index = 0                # which CUDA_VISIBLE_DEVICES slot
vram_gib = 24                # this partition's VRAM cap
tensor_split_weight = 0.20   # fraction of total weights (24 / 122 ≈ 0.20)
nccl_rank = 0                # rank in the NCCL world
nccl_world_size = 2          # total partitions
```

Weight-by-VRAM partitioning is the default (proportional to each
GPU's VRAM). Operator-overridable via the module config TOML.

### Deliverable 3 — MS010 hardware-tune.env consumption

`apply.sh` reads `${SELFDEF_HARDWARE_TUNE_ENV}` to inherit CPU-side
flags (matters because the host-side glue code that orchestrates
NCCL ranks is itself CPU-compiled). This is the same integration
pattern as MS028 and MS029.

### Deliverable 4 — SD-R55 signing composition

The partition configs land under `/etc/selfdef/tensor-parallel/`
which is one of the dirs covered by the MS026 integrity-sentinel
module's baseline (per its `paths.txt` default monitored path list).
Drift on these configs is detectable + alertable via the existing
integrity-sentinel + observability pipelines.

### Deliverable 5 — Override env vars (testability)

| Env var | Default | Purpose |
|---|---|---|
| `SELFDEF_TENSOR_PARALLEL_ETC_DIR` | `/etc/selfdef/tensor-parallel` | ETC root override |
| `SELFDEF_HARDWARE_TUNE_ENV` | `/etc/selfdef/hardware-tune.env` | Upstream tune env override |
| `SELFDEF_DRY_RUN` | `0` | Print-only mode |

L2 bats smoke uses these + a mocked `selfdefctl hardware export`
that returns a 2-GPU JSON (RTX 3090 + RTX PRO 6000) so the dry-run
exercises the full multi-GPU dispatch path.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest declares MS010 dependency | L2 bats test 2 |
| Provides tensor-parallel-runtime contract | L2 bats test 3 |
| 3 install scripts shipped + executable | L2 bats test 4 |
| apply.sh DRY_RUN aware | L2 bats test 5 |
| ETC_DIR override env exposed | L2 bats test 6 |
| hardware-tune.env consumed | L2 bats test 7 |
| Dry-run smoke with mocked selfdefctl 2-GPU output | L2 bats test 8 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with hardware-tune-cache dependency
2. ✅ `install/apply.sh` with per-GPU partition rendering from
   `selfdefctl hardware export`
3. ✅ `install/check.sh` verifying ETC dir + partition files
4. ✅ `install/uninstall.sh` removing the partition configs
5. ✅ L2 bats coverage with 2-GPU mocked selfdefctl JSON

## Authorization for Stage-3+ work

This SDD authorizes:

- Pipeline-parallel + tensor-parallel composition — additional
  `partition-N-stage-M.toml` files when both axes are partitioned
- NCCL transport config — IB vs TCP fallback, P2P enable, ring vs
  tree topologies
- Multi-host extension via MS018 vpn-bridge — tensor-parallel
  across hosts on the same overlay network
- Runtime sister-module — currently the operator wires the
  partition configs into their inference runtime (vLLM, TensorRT-LLM,
  llama.cpp tensor-parallel branch); a sister module could ship a
  reference runtime that auto-loads these
- Profiling integration — emit `selfdef_tensor_parallel_*`
  Prometheus series via a sister collector

Mark a Stage-3+ extension DONE only when it reaches operator-visible
production.

— End of SDD-037 / MS030 Stage-2.
