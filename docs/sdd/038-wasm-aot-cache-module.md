# SDD-038 — WASM AOT cache module — MS031

> Status: **draft** — Stage-2 architectural spec retrofitted for the
> shipped `wasm-aot-cache` module under `modules/wasm-aot-cache/`. The
> module provisions `/var/lib/selfdef/wasm-aot/` for cached `.cwasm`
> artifacts produced by `wasmtime compile` against the SD-R30
> target-feature surface (per SD-R48 + dump line 6495
> "WASM As Tool ABI").
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS031 (catalog
> `backlog/milestones/MS031-wasm-aot-cache-module.md`)
> Builds on: SDD-018 (MS010 hardware-tune-cache substrate)
> Companions: SDD-035-037 (compute-stack sister modules), L2 bats
> suite at `packaging/test/L2-wasm-aot-cache.bats` (10 tests)

## Problem

WebAssembly is the operator-facing tool ABI for sovereign-OS — tools
ship as `.wasm` modules and run inside `wasmtime` (or sister
runtimes) sandboxed from the host. Ahead-of-time compilation
(`wasmtime compile`) yields `.cwasm` (compiled WASM) artifacts that:
- skip the JIT warmup cost on first invocation (sub-100ms cold-start
  for AI agent tool calls)
- can be signed and integrity-verified at the binary level (vs JIT
  output which is rebuilt every load)
- pick up the host's target-feature surface (AVX-512, BMI2, BF16
  intrinsics) when compiled with `wasmtime compile --cranelift-flags
  '...'`

Without a shared AOT cache:
- every tool invocation either pays the JIT warmup (bad UX) or each
  caller maintains its own cache directory (fragmented + no signing
  composition)
- integrity-sentinel can't watch a known cache path

This module provisions the canonical cache directory and integrates
with MS010 hardware-tune.env so `.cwasm` builds inherit the host's
SD-R30 target-feature flags.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR, NOR THE NEED TO
>  EXPLOIT THE STACK AND TECHNO TO THE MAX, avx-plus-plus base
>  reason being."

Translation for MS031: WASM AOT caching must EXPLOIT the host's
target-feature surface. A `.cwasm` compiled on a non-AVX-512 build
host but deployed to a SAIN-01 box wastes ZMM lanes — so the cache
build pipeline must run ON the SAIN-01-class host with the right
`-Ctarget-cpu=native` equivalent for wasmtime.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/wasm-aot-cache/module.toml` | depends_on=[hardware-tune-cache], provides=[wasm-aot-cache-dir] |
| Apply | `modules/wasm-aot-cache/install/apply.sh` | Provisions `/var/lib/selfdef/wasm-aot/` |
| Check | `modules/wasm-aot-cache/install/check.sh` | Verifies cache dir exists |
| Uninstall | `modules/wasm-aot-cache/install/uninstall.sh` | Idempotent tear-down |
| L2 tests | `packaging/test/L2-wasm-aot-cache.bats` | 10 tests including dry-run + idempotency |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Canonical cache directory

Default `${SELFDEF_WASM_AOT_CACHE_DIR:-/var/lib/selfdef/wasm-aot}`.
This is the path:
- WASM tool launchers look in for `.cwasm` artifacts before falling
  back to JIT
- Build pipelines write to with `wasmtime compile -o
  ${cache_dir}/<tool>.cwasm`
- Integrity-sentinel (MS026) can watch via `paths.txt` if the
  operator wants to alert on unexpected mutations

Permissions: owned by `selfdef:selfdef`, mode 0750, allowing the
selfdef-daemon's wasmtime invocations + the operator-launched build
tools to read; not world-readable since `.cwasm` may encode tool
secrets via embedded config.

### Deliverable 2 — MS010 hardware-tune.env consumption

`apply.sh` reads `${SELFDEF_HARDWARE_TUNE_ENV}` so the cache
provisioning step inherits the host's target-feature flags. This is
the integration that lets the operator's build pipeline do:

```sh
. /etc/selfdef/hardware-tune.env
wasmtime compile \
    --cranelift-flags "${CRANELIFT_FLAGS:-}" \
    -o /var/lib/selfdef/wasm-aot/${tool}.cwasm \
    ${tool}.wasm
```

Where `CRANELIFT_FLAGS` is populated by `hardware-tune-cache` to
include the host's AVX-512 / BMI2 / BF16 enable flags.

### Deliverable 3 — Override env vars (testability)

| Env var | Default | Purpose |
|---|---|---|
| `SELFDEF_WASM_AOT_CACHE_DIR` | `/var/lib/selfdef/wasm-aot` | Cache dir override (L2 test) |
| `SELFDEF_HARDWARE_TUNE_ENV` | `/etc/selfdef/hardware-tune.env` | Upstream tune env override |
| `SELFDEF_DRY_RUN` | `0` | Print-only mode |

L2 bats smoke uses these to land the cache dir in a tmpdir without
touching `/var/lib/selfdef/`.

### Deliverable 4 — SD-R30 target-feature surface

SD-R30 (from the avx-plus-plus dump) enumerates the target features
that wasmtime should be compiled-against on SAIN-01-class hardware:
AVX-512F, AVX-512DQ, AVX-512BW, AVX-512VL, AVX-512BF16, AVX-512VNNI,
BMI2, ADX. The MS010 hardware-tune.env exports these in a form
wasmtime's Cranelift backend can consume.

`.cwasm` artifacts compiled with these flags on SAIN-01 run faster
than generic-x86-64 `.cwasm` by margins of 1.3x-3x for matmul-heavy
WASM tools (per the SD-R48 baseline measurements).

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest declares MS010 dependency | L2 bats test 2 |
| Provides wasm-aot-cache-dir contract | L2 bats test 3 |
| 3 install scripts shipped + executable | L2 bats test 4 |
| apply.sh DRY_RUN aware | L2 bats test 5 |
| Cache dir override env exposed | L2 bats test 6 |
| hardware-tune.env consumed | L2 bats test 7 |
| Default cache dir = `/var/lib/selfdef/wasm-aot` | L2 bats test 8 |
| Dry-run smoke + idempotency | L2 bats tests 9, 10 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with hardware-tune-cache dependency
2. ✅ `install/apply.sh` provisioning the cache dir + sourcing
   hardware-tune.env
3. ✅ `install/check.sh` verifying cache dir exists
4. ✅ `install/uninstall.sh` removing the cache dir
5. ✅ L2 bats coverage (10 tests including dry-run + idempotency)

## Authorization for Stage-3+ work

This SDD authorizes:

- Per-tool sub-cache layout — `wasm-aot/<tool>/<sha256>.cwasm` for
  content-addressed caching across tool versions
- Signing composition — `.cwasm` artifacts signed via MS003
  signing-chain on the build side, verified before load via the
  same minisign-verify infrastructure
- GC policy — bounded cache size with LRU eviction (currently
  unbounded; operator can manually rm artifacts)
- Cross-host distribution — sister module that mirrors `.cwasm`
  artifacts over MS018 vpn-bridge to peer hosts so the build cost
  is amortized across a fleet
- Build pipeline runner — a sister module that wraps `wasmtime
  compile` with the right Cranelift flags pre-populated from the
  hardware-tune.env

Mark a Stage-3+ extension DONE only when it reaches operator-visible
production.

— End of SDD-038 / MS031 Stage-2.
