# SDD-017 — SAIN-01 hardware inventory awareness

> Status: **implemented** — fifth Stage-2 SDD; shipped end-to-end
> alongside the parent SDD-018 (hardware-aware modules):
>  - `selfdef_hardware::probe` — CPU (AVX-512 family detection),
>    memory, GPUs (nvidia-smi CSV parsers), motherboard DMI, PCIe
>    inventory, thermals (/sys/class/hwmon walk)
>  - `Sain01Match` + `Sain01Verdict` (FullMatch / PartialMatch /
>    NoMatch) — 5-axis match (CPU AVX-512 VNNI/BF16, ≥256 GB memory,
>    ≥2 GPUs, motherboard ProArt X870E, PCIe dual x8)
>  - `selfdefctl hardware {match, posture}` CLI verbs surface the
>    verdict + per-axis breakdown
>  - Doctor `check_hardware` integration
>    (`crates/selfdef-cli/src/doctor.rs:432`)
>  - `GET /v1/hardware/sain01` HTTP surface (commit 520501d)
>  - Dashboard "Host hardware" panel renders the sain-01 badge
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-21 (status: review → implemented)
> Closes findings: net-new — operator goal: "powerhouse OS" with
> "personalization" + "advanced features so well suited" for the
> SAIN-01 spec (AVX-512 + RTX PRO 6000 + RTX 3090 + 256GB RAM).
> Derived from: SDD-012 (integration design); SDD-013 (deployment.target);
> SDD-015 (perimeter); sovereign-os profiles/sain-01.yaml § hardware

## Problem

Selfdef today has no hardware-inventory surface. Operators wanting to
write agent-guard policies that assert on specific GPU device nodes
(`/dev/nvidia0` = RTX PRO 6000; `/dev/nvidia1` = RTX 3090), or that
rate-limit operations by host memory bandwidth, or that scope syscall
allowlists by AVX-512 capability, have to hand-code those paths /
thresholds with no validation.

The SAIN-01 master spec is concrete: two specific GPUs, a specific
amount of RAM, specific CPU capabilities. Selfdef should DISCOVER this
hardware at startup, surface it via a structured introspection API +
`selfdefctl hardware` subverb, and make those facts available to policy
authors so they can write hardware-aware policies that gracefully no-op
when the host doesn't match (e.g. on a generic VM, the GPU-related
policies disable themselves instead of asserting on nonexistent devices).

## Required coverage

### 1. New crate

`crates/selfdef-hardware/` — minimal, dependency-light. Reads from:
- `/proc/cpuinfo`         — CPU features (avx, avx2, avx512f, avx512vnni, avx512bf16, …)
- `/proc/meminfo`         — `MemTotal:` → bytes
- `/sys/class/dmi/id/`    — board vendor + product name (ProArt-X870E-Creator on SAIN-01)
- `/dev/nvidia*`          — GPU device nodes (count + paths)
- `lspci` (subprocess)    — PCIe link state (x8/x8 confirmation, gen 4/5)
- `nvidia-smi --query-gpu=...` (subprocess, optional) — model name +
  VRAM size if NVIDIA driver installed

All readers are best-effort + graceful — missing files / unavailable
binaries return `None` for the affected field, never panic.

### 2. Introspection API

```rust
pub struct HardwareSnapshot {
    pub cpu: CpuInventory,
    pub memory: MemoryInventory,
    pub gpus: Vec<GpuInventory>,
    pub motherboard: Option<MotherboardInventory>,
    pub pcie: PcieInventory,
    pub probed_at: time::OffsetDateTime,
}

pub struct CpuInventory {
    pub vendor: String,             // "AuthenticAMD" / "GenuineIntel"
    pub model_name: String,
    pub physical_cores: u32,
    pub logical_threads: u32,
    pub features: HashSet<String>,  // "avx", "avx512f", "avx512vnni", ...
    pub avx512_present: bool,       // convenience: any avx512* feature
    pub avx512_vnni: bool,          // master-spec § 22 § 01 target
    pub avx512_bf16: bool,          // master-spec § 22 § 01 target
}

pub struct MemoryInventory {
    pub total_bytes: u64,
}

pub struct GpuInventory {
    pub device_node: PathBuf,       // /dev/nvidia0
    pub pci_address: Option<String>,
    pub model_hint: Option<String>, // from nvidia-smi when available
    pub vram_bytes: Option<u64>,    // from nvidia-smi when available
}

pub struct MotherboardInventory {
    pub vendor: Option<String>,     // "ASUSTeK COMPUTER INC."
    pub product_name: Option<String>, // "ProArt X870E-CREATOR WIFI"
}

pub struct PcieInventory {
    pub gen4_or_higher_x8_slot_count: u32, // SAIN-01 target: ≥2
}

pub fn probe() -> Result<HardwareSnapshot, HardwareError>;
```

The snapshot is owned + cheap to clone. `selfdefctl hardware` produces
a human-readable rendering; `selfdefctl hardware --json` produces a
machine-readable rendering for fleet aggregation.

### 3. SAIN-01 detection

```rust
pub fn matches_sain01(snap: &HardwareSnapshot) -> Sain01Match;

pub struct Sain01Match {
    pub overall: Sain01Verdict,     // FullMatch | PartialMatch | NoMatch
    pub cpu_avx512_vnni: bool,
    pub cpu_avx512_bf16: bool,
    pub memory_at_least_256gb: bool,
    pub gpu_count_at_least_2: bool,
    pub motherboard_proart_x870e: Option<bool>, // None when DMI unreadable
    pub pcie_dual_x8_present: bool,
}
```

Returns a structured verdict — operators see exactly which dimensions
match + which don't. `FullMatch` requires ALL 5 dimensions hit
(cpu+mem+gpu_count+pcie + (mobo confirmed OR DMI unreadable)).
`PartialMatch` = any subset. `NoMatch` = none.

This is the surface that resolvers in selfdef-config + integrations
read to make hardware-aware decisions.

### 4. CLI

```sh
sudo selfdefctl hardware              # human-readable snapshot + Sain01Match verdict
sudo selfdefctl hardware --json       # machine-readable
sudo selfdefctl hardware probe        # alias for default (explicit subverb)
sudo selfdefctl hardware match        # just print Sain01Match verdict (exit 0/1/2 by overall)
```

### 5. Selfdef config integration

When `[deployment].target = "sain01"`, the daemon runs `hardware::probe()`
at startup and logs the Sain01Match verdict:

```
INFO selfdefd: hardware probe complete
INFO selfdefd: sain01_match.overall = PartialMatch
INFO selfdefd: sain01_match.cpu_avx512_vnni = false  (target=sain01 + missing → operator should verify build host)
```

The daemon does NOT refuse to start on a non-matching host — this is
informational + surfaces drift. Operators can opt into strict-mode via
config:

```toml
[deployment]
sain01_strict = false   # default; warn-only

# When true, deployment.target = "sain01" but Sain01Match.overall != FullMatch
# causes the daemon to refuse startup with a clear error.
```

### 6. Layer B metric

```
sovereign_os_selfdef_hardware_match{dimension="cpu_avx512_vnni"} 1
sovereign_os_selfdef_hardware_match{dimension="memory_at_least_256gb"} 1
sovereign_os_selfdef_hardware_match{dimension="gpu_count_at_least_2"} 0
sovereign_os_selfdef_hardware_match{dimension="pcie_dual_x8_present"} 1
sovereign_os_selfdef_hardware_match{dimension="motherboard_proart_x870e"} 1
sovereign_os_selfdef_hardware_match_overall{verdict="PartialMatch"} 1
```

Metric label set is fleet-aggregation-ready: ops dashboards graph
hardware-drift across fleets.

### 7. Regression-prevention tests

```rust
#[test]
fn cpu_inventory_parses_proc_cpuinfo() { /* synthetic /proc/cpuinfo fixture */ }

#[test]
fn cpu_inventory_detects_avx512_vnni() { /* feature flag present */ }

#[test]
fn cpu_inventory_no_avx512_on_legacy_host() { /* feature flag absent */ }

#[test]
fn memory_inventory_parses_proc_meminfo() { /* synthetic /proc/meminfo */ }

#[test]
fn gpu_inventory_counts_dev_nvidia_devices() { /* tempdir with /dev/nvidia0..N */ }

#[test]
fn gpu_inventory_zero_when_no_devices() { /* no /dev/nvidia at all */ }

#[test]
fn motherboard_inventory_reads_dmi() { /* synthetic /sys/class/dmi/id */ }

#[test]
fn motherboard_inventory_none_when_dmi_absent() { /* missing dir */ }

#[test]
fn sain01_match_full_when_all_dimensions_hit() { /* synthetic snapshot */ }

#[test]
fn sain01_match_partial_when_subset_hit() { /* synthetic */ }

#[test]
fn sain01_match_none_when_no_dimensions_hit() { /* synthetic */ }

#[test]
fn probe_on_test_host_returns_some_snapshot() { /* smoke; reads real /proc */ }
```

## Goals

1. **Hardware introspection as a first-class selfdef surface.**
   Operators don't write hand-coded paths anymore.
2. **Graceful on every host.** Missing files / missing binaries
   → fields are `None`; selfdef daemon never refuses to start on a
   generic VM because of hardware-inventory failure.
3. **SAIN-01 fitness verdict** — the 5-dimensional `Sain01Match` is
   the operator's truth-source for "is this the right machine for my
   `target=sain01` config".
4. **Fleet-aggregation-ready** — JSON output + per-dimension Layer B
   metric for dashboard rollup across multiple SAIN-01-like hosts.
5. **Personalization** — operators can write hardware-aware policies
   that adapt to the host without manual config edits.

## Non-goals (this SDD)

- Does NOT pin specific kernel versions (sovereign-os SDD-018 owns kernel choice).
- Does NOT discover non-NVIDIA GPUs in v1 (AMD ROCm path deferred).
- Does NOT poll continuously — `probe()` is per-call; daemon runs it once at startup.
- Does NOT modify agent-guard policy YAMLs based on hardware (operators
  still author policies by hand; SDD-017 makes the FACTS available, not
  the actions).
- Does NOT integrate with sovereign-os master spec § 22 friction-audit
  directly — sovereign-os already owns its check at boot; selfdef
  uses the same `/proc/*` sources for its own purpose.

## Open sub-questions

- **Q17-A** — Should `Sain01Match` factor in CPU model name (e.g.
  reject Zen 4 even if AVX-512 features are software-reported)?
  Recommend: **NO** — AVX-512 feature flags are the load-bearing
  signal; CPU brand checks are anti-patterns (vendors fork frequently).
- **Q17-B** — Should hardware probing be done by an unprivileged
  user / namespace? Recommend: **NOT in v1** — `/proc/cpuinfo` and
  `/proc/meminfo` are world-readable; nvidia-smi may need privileges
  but is best-effort + skips on EPERM. selfdef-daemon already runs
  privileged; the discovery cost is small.
- **Q17-C** — Should there be an `--include-pcie-tree` option that
  walks the full PCIe topology? Recommend: **DEFER** — sovereign-os's
  `friction-audit.sh` already does this; selfdef can shell out to it
  via a sovereign-os bridge later (Stage-2+ next round).
- **Q17-D** — Should fleet aggregation produce a CSV / OpenSCAP
  format? Recommend: **DEFER** — JSON output is consumed by the
  existing Loki / OpenSearch channels; CSV is a thin output adapter
  if operators ever need it.

## Way forward

1. **This PR** — spec.
2. **Impl PR** — new crate + Sain01Match + `selfdefctl hardware`
   surface + daemon startup integration + tests. Lands on the
   sain01-integration-arc branch as SD-R7.
3. **Future rounds** — hardware-aware agent-guard policy DSL,
   sovereign-os bridge for friction-audit reuse, AMD ROCm path.

## Cross-references

- SDD-013 (`deployment.target` — gates sain01-specific behavior; this
  SDD ADDS the hardware-discovery dimension to that gate).
- SDD-015 (`perimeter` — orthogonal; no overlap).
- SDD-016 (oracle-triage — could surface hardware match in the triage
  context window; deferred follow-up).
- sovereign-os `profiles/sain-01.yaml` `§ hardware` (the source of
  truth for what SAIN-01 actually is — this SDD makes selfdef aware
  of those facts).
- sovereign-os `scripts/bootstrap/verify.sh` (master spec § 22 6-check
  grid; runs the same AVX-512 + memory + PCIe checks on the boot
  side. Selfdef's Sain01Match is the runtime-process-side mirror.)
