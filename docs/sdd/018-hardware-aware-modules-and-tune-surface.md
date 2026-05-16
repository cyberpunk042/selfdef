# SDD-018 — Hardware-aware module gating + tune surface (SD-R14..R19 arc)

> Status: **review** — captures the SD-R14..R19 in-arc design + closes
> the doctrine gap operators asked for ("research and continuously
> evolving specs to drive and evolve the SDD and TDD").
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-16
> Builds on: SDD-017 (hardware inventory); sovereign-os R172 (thermal
> classification + OCSF events); sovereign-os R173 (selfdef-tune.sh).

## Problem

SDD-017 gave selfdef a hardware INVENTORY surface (probe, Sain01Match,
HardwareCapabilities JSON export). What it didn't give was:

1. A way for **modules** to declare that they require specific hardware
   to apply correctly. Today, modules either apply blindly and
   half-break on unsupported hosts, or they hard-fail at runtime
   forcing the operator to read logs and disable manually.
2. A way for **operators** to dry-run the gate before committing —
   answering "what will actually apply on this box?".
3. A way for the **build pipeline** (kernel, Wasm-AOT, bitnet.cpp) to
   pick up host-tuned compile flags from a single canonical source
   without hand-rolled hardware probing.
4. A way for **observability** to see thermal envelope continuously,
   not just at probe time.

The SD-R14..R19 arc closes all four. This SDD locks the contracts
operators rely on so future evolutions stay backward-compatible.

## Contracts locked in by this SDD

### C-1: `[requires_hardware]` block in module.toml (SD-R14)

Module manifests may declare:

```toml
[requires_hardware]
avx512_vnni        = true              # bool, default false
avx512_bf16        = true              # bool, default false
memory_gib_min     = 64                # u64, default 0 (disabled)
gpu_count_min      = 1                 # u32, default 0 (disabled)
sain01_verdict_min = "PartialMatch"    # "FullMatch"|"PartialMatch"|"NoMatch", default ""
```

**Semantics:**
- Absence of `[requires_hardware]` OR all-zero/false fields → module
  is hardware-agnostic, always applied.
- Any non-zero/non-false field → module is gated. At `selfdefctl
  modules apply` time, the daemon probes once + drops modules whose
  predicates are unmet. Skipped modules print a clear stderr block
  citing each failed predicate.
- The gate runs ONCE per `apply` invocation (single probe, shared
  across modules) — no per-module probe cost.
- The 5 predicates are AND-ed; a module passes iff every set
  predicate is satisfied.

**Stability:** the field names + value semantics are operator-stable.
Adding a NEW field is backward-compatible (existing manifests don't
mention it → default = no-op). Renaming or removing fields is NOT
backward-compatible and requires a Stage-2+ deprecation cycle.

### C-2: `selfdefctl modules check-hardware` (SD-R15)

Read-only dry-run of C-1. Outputs:
- Human: "WOULD APPLY (n)" + "WOULD SKIP (n)" blocks with predicate
  citations for each skipped module.
- `--json`: structured document with `probe_ok` (bool), `total`,
  `kept[].{module, reason}`, `skipped[].{module, unmet[]}`. Schema
  version is implicit (1); breaking changes bump it.

Exit code is always 0 — informational, doesn't block scripts.

**Cross-repo mirror:** sovereign-os R170 ships an equivalent Python
implementation (`scripts/hardware/selfdef-modules-gate.py`) that
reads the same /var/lib/selfdef/hardware-capabilities.json and
evaluates the same 5 predicates. The two implementations must stay
in agreement; any logic change to evaluate() in selfdef requires a
matching change in the Python mirror.

### C-3: `selfdefctl hardware thermals` (SD-R17)

Read-only per-sensor temperature readout from:
1. `/sys/class/hwmon/hwmonN/{name, temp<K>_input, temp<K>_label}` —
   millidegree integers parsed + rounded to whole °C
2. `nvidia-smi --query-gpu=index,temperature.gpu` — GPU sensors

Output formats:
- Human: 2-column table `sensor` / `celsius`
- `--json`: array of `{source, celsius}`

The `ThermalReading.source` label format is operator-stable:
- hwmon with label: `<hwmon-name>/<label>` (e.g. `k10temp/Tctl`)
- hwmon without label: `<hwmon-name>/temp<idx>` (e.g. `nvme/temp1`)
- nvidia-smi: `nvidia-gpu-<index>` (e.g. `nvidia-gpu-0`)

**Layer B metric:** `sovereign_os_selfdef_hardware_thermal_celsius{sensor="..."}`
is emitted into the textfile collector only when `thermals` is non-empty
(no empty-label clutter). The metric name is operator-stable.

### C-4: `selfdefctl hardware tune` (SD-R19)

Emits host-tuned compile flags in 4 formats:
- `--format sh` (default): `export KEY=value` lines, pipe through
  `source <(...)`
- `--format env-file`: `KEY=value` without `export` (systemd
  `EnvironmentFile=` compatible)
- `--format make`: `KEY := value` for Makefile include
- `--format json`: structured `{march, cflags, kcflags, avx512_*,
  compile_flag_list, zmm_512_preferred}` with `schema_version`

**Emitted variables:**
- `SELFDEF_HARDWARE_MARCH` — `znver5` / `znver4` / `x86-64-v4` /
  `native` per SDD-017 § 7
- `SELFDEF_HARDWARE_CFLAGS` — `-march=<...>` + `-mprefer-vector-width=512`
  (when avx512f) + each detected `-mavx512*` flag
- `SELFDEF_HARDWARE_KCFLAGS` — same set, intended for kernel builds
- `SELFDEF_HARDWARE_AVX512_VNNI` — `true`/`false`
- `SELFDEF_HARDWARE_AVX512_BF16` — `true`/`false`

The `-mprefer-vector-width=512` flag is gated on avx512f detection —
on non-AVX-512 hosts it is omitted (regression-safe; the flag is a
no-op or worse without AVX-512 support).

**Output path:** `--output PATH` writes atomically (tempfile +
rename) matching the SDD-017 § 7 capabilities-JSON contract.

### C-5: doctor surface (SD-R9 / SD-R18)

`selfdefctl doctor` emits a `hardware.thermals (SD-R17+R18)` row:
- `Ok` when ≥1 sensor exposed (detail: count + min/max °C)
- `Skipped` when no sensors AND `deployment.target != sain01`
- `Warn` when no sensors AND `deployment.target == sain01`
  (degraded observability — k10temp/nvme should always be exposed)

Per-row severity ordering is target-aware (SD-R9 invariant).

## Cross-repo bridge

```
selfdef SDD-017 §6   →  Layer B metrics (textfile collector)
selfdef SDD-017 §7   →  /var/lib/selfdef/hardware-capabilities.json
selfdef SD-R14        →  module.toml [requires_hardware]
selfdef SD-R15        →  selfdefctl modules check-hardware (dry-run)
selfdef SD-R17        →  selfdef-hardware ThermalReading
selfdef SD-R19        →  selfdefctl hardware tune --format <fmt>
                          │
                          ▼
sovereign-os R170     →  scripts/hardware/selfdef-modules-gate.py
sovereign-os R172     →  scripts/hardware/thermal-watch.py (thresholds + OCSF events)
sovereign-os R173     →  scripts/build/lib/selfdef-tune.sh (bridge to SD-R19)
```

Every cross-repo consumer has a fallback so removing the selfdef
side never causes a hard break:
- R170 falls back to scripts/hardware/sain01-match.py probe
- R172 reads /sys/class/hwmon directly (selfdef daemon not required)
- R173 falls back to capabilities-JSON parsing, then native-march

## Decision log

- **D-1** (SD-R14): gate runs at apply time, not module-load time, so
  catalog enumeration stays cheap.
- **D-2** (SD-R14): unmeetable predicates SKIP (info), don't FAIL —
  operator can override by removing the block.
- **D-3** (SD-R15): exit code 0 always; `--verdict-only` not
  implemented (operator-driven info, not a gate).
- **D-4** (SD-R17): per-sensor probe stays inside `probe_from_roots`
  (single I/O pass); operators get them via `HardwareSnapshot.thermals`
  + JSON export + CLI surface.
- **D-5** (SD-R18): thermal classification (warn/critical) lives in
  sovereign-os R172, NOT selfdef — thresholds are profile-dependent.
- **D-6** (SD-R19): ZMM hint gated on avx512f detection; the flag is
  not universally beneficial.

## Non-goals

- AMD ROCm GPU thermal probing (NVIDIA only via nvidia-smi).
- Per-NUMA-node thermal binning.
- Predictive thermal modeling (operators get instantaneous readings;
  trends emerge from the textfile-collector timeseries).
- Hardware-feature-aware unsafe-code paths in the daemon itself
  (workspace remains `#![forbid(unsafe_code)]`; AVX-512 exploitation
  lives in safe-Rust crates like blake3 / crc32fast with
  target_feature dispatch, OR in sovereign-os build artifacts).

## Out of scope (deferred to next SDD)

- Hardware-aware POLICY scope (TracingPolicy filters that key off
  AVX-512 capability) — interesting but not yet operator-needed.
- Selfdef-side periodic thermal probe + event emission (currently
  sovereign-os R172 owns the periodic loop via systemd timer).
