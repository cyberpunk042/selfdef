# SDD-036 — SLM-on-CPU agent loop module — MS029

> Status: **implemented** — Stage-2 architectural spec for the
> shipped `slm-cpu-loop` module under `modules/slm-cpu-loop/`. The
> module pins a small language model (Phi-4-mini / Qwen3-1.7B class)
> to CCD-0 cores for low-latency background agent work per SD-R72
> ("SLMs Are Microservices Of Intelligence", dump line 7445).
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS029 (catalog
> `backlog/milestones/MS029-slm-cpu-loop-module.md`)
> Builds on: SDD-018 (MS010 hardware-tune-cache substrate)
> Companions: SDD-035 (MS028 BitNet GPU inference — sister module
> covering the GPU-side compute path), L2 bats suite at
> `packaging/test/L2-slm-cpu-loop.bats` (10 tests)

## Problem

Background agent loops (typeahead, completion, autonomous task
spawning) need a small language model running on CPU with very low
tail latency — sub-50ms p95 for a few-token completion. Achieving
this requires:
- Pinning the SLM to a specific CCD (chiplet) so the model weights
  stay in the same L3 cache slice across calls
- Limiting the thread count so the CPU side doesn't oversubscribe
  and cause context switches
- Inheriting AVX-512 BF16/VNNI flags from MS010 hardware-tune-env
  so the SLM build uses the right instruction surface

Without this module, every operator embedding an SLM loop has to
write their own systemd drop-in, set affinity by hand, and re-do
the hardware-tune integration.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO
>  EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base
>  reason being."

Translation for MS029: SLM-on-CPU must EXPLOIT the AVX-512 BF16/VNNI
+ CCD-aware core pinning + L3 cache locality on a Zen 5 (9950X / SAIN-01
class) box. Defaults must work out-of-the-box for the SAIN-01
topology; operator-overridable for other CPUs.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/slm-cpu-loop/module.toml` | depends_on=[hardware-tune-cache], provides=[slm-loop-runtime] |
| Apply | `modules/slm-cpu-loop/install/apply.sh` | Renders `/etc/selfdef/slm-loop.env` |
| Check | `modules/slm-cpu-loop/install/check.sh` | Verifies env file exists |
| Uninstall | `modules/slm-cpu-loop/install/uninstall.sh` | Idempotent tear-down |
| L2 tests | `packaging/test/L2-slm-cpu-loop.bats` | 10 tests including dry-run + idempotency |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — CCD-0 core affinity defaults

| Default | Value | Source rationale |
|---|---|---|
| `DEFAULT_AFFINITY` | `0-5` | Cores 0-5 = CCD-0 on Zen 5 9950X (16 cores / 2 CCDs of 8 each, but reserving 6 of 8 for the SLM leaves 2 for the kernel scheduler) |
| `DEFAULT_THREADS` | `6` | Matches the affinity range; thread count = available cores in the affinity |

Override via `SELFDEF_SLM_AFFINITY` env or per-installation TOML
config. On a non-9950X CPU (different CCD layout), the operator
sets `SELFDEF_SLM_AFFINITY="0-7"` for a CCD that's 8 cores wide,
or a custom range for asymmetric topologies.

### Deliverable 2 — MS010 hardware-tune.env consumption

`apply.sh` reads `${SELFDEF_HARDWARE_TUNE_ENV:-/etc/selfdef/hardware-tune.env}`
and propagates its variables into the generated `slm-loop.env`. This
gives the SLM runtime access to the host's AVX-512 BF16/VNNI flags
without each consumer doing its own hardware probe.

### Deliverable 3 — Generated `/etc/selfdef/slm-loop.env`

Sourced by the SLM systemd unit (operator-shipped, NOT this module —
the runtime is the operator's choice: llama.cpp + a Phi-4-mini
checkpoint, Qwen3-1.7B via llamafile, etc.). The env file exports:

```sh
SELFDEF_SLM_AFFINITY="0-5"      # or operator override
SELFDEF_SLM_THREADS="6"         # or operator override
# Inherited from hardware-tune.env:
CFLAGS="-march=native -mavx512f -mavx512vnni -mavx512bf16"
RUSTFLAGS="-Ctarget-cpu=native"
```

The operator's SLM service unit then does
`EnvironmentFile=/etc/selfdef/slm-loop.env` +
`ExecStart=taskset -c ${SELFDEF_SLM_AFFINITY} /usr/local/bin/llama.cpp-cli -t ${SELFDEF_SLM_THREADS} -m <model>`.

### Deliverable 4 — Override env vars (testability)

| Env var | Default | Purpose |
|---|---|---|
| `SELFDEF_SLM_LOOP_ENV` | `/etc/selfdef/slm-loop.env` | Output path override (L2 test) |
| `SELFDEF_HARDWARE_TUNE_ENV` | `/etc/selfdef/hardware-tune.env` | Upstream tune env override |
| `SELFDEF_DRY_RUN` | `0` | Print-only mode |

L2 bats smoke uses these to land the env file in a tmpdir without
touching `/etc/selfdef/`.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest declares MS010 dependency | L2 bats test 2 |
| Manifest provides slm-loop-runtime contract | L2 bats test 3 |
| 3 install scripts shipped + executable | L2 bats test 4 |
| apply.sh consumes hardware-tune.env | L2 bats test 7 |
| apply.sh declares CCD-0 affinity defaults | L2 bats test 8 |
| Dry-run smoke + idempotency | L2 bats tests 9, 10 |
| Coherence harness includes L2-slm-cpu-loop | `make coherence` discovers it |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with hardware-tune-cache dependency
2. ✅ `install/apply.sh` writing slm-loop.env with affinity defaults
   + hardware-tune.env sourcing
3. ✅ `install/check.sh` verifying env file exists
4. ✅ `install/uninstall.sh` removing the env file
5. ✅ L2 bats coverage (10 tests)

## Authorization for Stage-3+ work

This SDD authorizes:

- A shipped systemd unit (currently the operator owns the SLM
  service) — would compose this module with a sibling `slm-runtime`
  module that owns the systemd unit + llama.cpp install
- Per-topology profiles — `[profiles]` block in the manifest with
  `9950x`, `7950x3d`, `epyc-9374f`, `apple-m4-pro` profiles each
  shipping their own DEFAULT_AFFINITY values
- Multi-model serving — extend the env file with a list of model
  paths and have the runtime cycle through them
- Latency telemetry — emit `selfdef_slm_loop_*` Prometheus series
  via a sister collector + add panels to the MS027 observability
  dashboard

Mark a Stage-3+ extension DONE only when it reaches operator-visible
production (visible in `selfdefctl modules info slm-cpu-loop`).

— End of SDD-036 / MS029 Stage-2.
