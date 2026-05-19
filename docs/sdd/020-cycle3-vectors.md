# SDD-020 — Cycle 3 vectors (post-SDD-019-closure forward-looking spec)

> Status: **draft** — captures fresh cycle-2 learnings (SD-R50..R52)
> + lays out unscoped cycle-3 design vectors operators may ratify.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-16 (cycle 2 closing).
> Builds on: SDD-018 (cycle-1+2 gate doctrine); SDD-019 (cycle-3
> forward-looking with 5/6 tensions already closed in cycle 2).

## Why this SDD exists

SDD-019 documented the forward-looking pattern: each cycle's closing
spec carries the next cycle's vectors. SDD-019's 6 tensions are now
5/6 ✓ closed + 1 ⏸ partial (T-3 fetch-side). SDD-020 continues the
pattern — captures the cycle-3 vectors that emerged from cycle-2's
final stretch (SD-R50..R52).

The forward-looking SDD is now a STANDING ARTIFACT: every cycle has
one, every cycle's vectors get closed within the next cycle (or
sooner — SDD-019 closed in same-cycle), and the doctrine layer
moves continuously with the code.

## SDD-019 closing status

| Tension | Round | Status |
|---------|-------|--------|
| T-1 (ANY-vs-ALL VRAM semantics) | SD-R51 | ✓ closed cycle 2 |
| T-2 (override audit trail) | SD-R47 | ✓ closed cycle 2 |
| T-3 (model artifact fetch) | R190 (verify); cycle 3 (fetch) | ⏸ partial |
| T-4 (cross-repo schema drift) | R189 | ✓ closed cycle 2 |
| T-5 (recommendation matrix dup) | R188 | ✓ closed cycle 2 |
| T-6 (schedule.json schema) | SD-R46 | ✓ closed cycle 2 |

## Cycle-3 vectors (V-N, NEW)

These emerged from cycle-2's final stretch:

### V-1 — Per-module audit trail subjects beyond `--ignore-hardware`

SD-R47 audits ONE operator action (`--ignore-hardware`). Cycle 3:
audit every operator-visible mutation (`--strict-hardware` refusal,
`uninstall --force`, `apply --only`) for full fleet-action history.
Same OCSF schema; category prefix would distinguish.

  - Recommendation: prefix per-action (`selfdef.modules.skip-strict`,
    `selfdef.modules.uninstall-force`); operators dashboard joins
    on category.

### V-2 — Per-predicate Layer B metrics

Today's SD-R31 emits aggregate wasm-AOT info; not per-predicate. A
cycle-3 vector: `sovereign_os_selfdef_hardware_gate_predicate_pass{name="..."}`
gauge — operator sees fleet-wide pass rate per predicate, fast
fleet-uniformity reasoning ("80% of fleet passes
gpu_vram_gib_each_min ≥ 24; that's the right threshold to standardise on").

  - Recommendation: emit on every apply (cached for read).

### V-3 — Operator-defined custom predicates

The 8 built-in predicates cover SAIN-01 + adjacent hardware. What
about operators with niche needs (e.g. RDMA-NIC presence,
specific PCIe slot configurations)? Cycle 3: allow a module to
declare `[requires_custom]` blocks evaluated by an operator-supplied
hook script. Sharp-edged (operator owns the hook contract) but
opens the predicate surface to fleet-specific needs.

  - Recommendation: gated behind an explicit feature flag in
    /etc/selfdef/selfdef.toml — operators opt-in.

### V-4 — Per-module RBAC integration

selfdef already has SDD-004 RBAC posture for agent-guard. Cycle 3:
extend `[requires_rbac]` to module manifests so a module can declare
"requires Kubernetes RBAC `ClusterRole/X`". Apply checks the RBAC
graph; modules that need cluster-admin land only where allowed.

  - Recommendation: scope to k8s-flavored hosts (skip on bare-metal).

### V-5 — Module manifest signing

Operators want supply-chain assurance. Cycle 3: optional
`[signing]` block in module.toml with minisign signature; apply
refuses to land modules whose signatures don't verify against
operator's trust root.

  - Recommendation: composes with SD-R34 model registry signing
    (T-3 fetch-side); same minisign infrastructure.

### V-6 — Predictive thermal modelling

SDD-018 § Non-goals: "Predictive thermal modelling — operators get
instantaneous readings; trends emerge from the textfile-collector
timeseries." Cycle 3 vector: a thin selfdef-side
`sovereign_os_selfdef_hardware_thermal_trend_celsius_per_hour` gauge
computed via 5-min textfile snapshots in a ring buffer. Operators
get a fleet-thermal-trend dashboard alarm before the hard limit.

  - Recommendation: ONLY emit the trend when ≥3 datapoints in the
    last hour — otherwise noisy.

## Mid-cycle emergence: V-7 (post-hoc) — hardware-exploitation rollup

SD-R64 (added mid-cycle-3) introduced a vector the original V-1..V-6
list did not anticipate: an operator-readable hardware-exploitation
rollup that surfaces the master spec § 15-16 ternary fast path
geometry WITHOUT the operator having to mentally map ISA flags to
vector lane widths.

Two new derived fields on `CpuCapabilities`:

- `ternary_aot_capable: bool` — true when AVX-512 VNNI is present
  AND at least one of BF16/FP16 (the bitnet.cpp / Wasm-AOT ternary
  hot path requirement, master spec § 16).
- `zmm_int8_lane_capacity: u32` — widest INT8 lane count the host
  can multiply-accumulate per dispatch: 64 (AVX-512 VNNI VPDPBUSD on
  ZMM/512-bit), 32 (AVX2 VPMADDUBSW on YMM), 16 (SSSE3 PMADDUBSW on
  XMM), 0 (no INT8 SIMD).

Two new predicates on `HardwareRequirements`:

- `ternary_aot_capable_required: bool` — gates 1-bit / ternary
  inference modules onto hosts that can actually run them at the
  hot-path lane width.
- `zmm_int8_lanes_min: u32` — operator-readable hardware-exploitation
  knob (set to 64 to require AVX-512 VNNI, lower for fallback
  acceptance).

Two new Layer B exports:

- `sovereign_os_selfdef_hardware_gate_capable{predicate="ternary_aot_capable"}`
  (rides the SD-R54 per-predicate map; gauges 0/1).
- `sovereign_os_selfdef_hardware_zmm_int8_lanes` (numeric gauge,
  0-64).

Rationale for the emergence: the operator directive explicitly named
"Wasm-to-AVX-512 AOT" + "A single 512-bit ZMM vector register can
hold and manipulate" + "1-bit models" as the load-bearing
hardware-exploit surface. Reading these as design constraints (not
as code commentary) revealed that selfdef had the raw ISA flags but
no operator-readable rollup. V-7 closes that gap.

JSON forward-compat: both new `CpuCapabilities` fields carry
`#[serde(default)]` so pre-SD-R64 capability dumps deserialize
cleanly (ternary reads `false`, lane count reads `0` — safe
fail-closed defaults for gating).

## Cycle-3 priority ranking

| Priority | Vector | Effort | Rationale |
|----------|--------|--------|-----------|
| HIGH     | T-3 fetch | medium | Closes the model-registry loop (SDD-019 carry-over) |
| HIGH     | V-1 audit | small  | Cheap extension of SD-R47; closes operator-action observability |
| HIGH     | V-7 hw-exploit rollup | small | SD-R64 — operator-named master spec § 16 surface; CLOSED |
| MEDIUM   | V-2 metrics | small | Operator fleet-uniformity tool |
| MEDIUM   | V-5 signing | medium | Supply-chain assurance |
| LOW      | V-3 custom predicates | medium | YAGNI; wait for a real need |
| LOW      | V-4 RBAC | small  | Niche; only k8s |
| LOW      | V-6 thermal trend | small | Convenience over existing observability |

## Non-goals for cycle 3

Inherits SDD-018 § Non-goals + adds:
- Full GUI dashboard (textfile + Grafana JSON stays the surface).
- Per-host signature root distribution (operator-owned per-host).
- Real-time gate re-evaluation (carry forward from SDD-018; gate
  fires at apply-time only).

## How operators ratify

Edit this file → replace "Recommendation:" with "Decision:" on each
V-N. Commit. Cycle-3 implementation rounds reference the decisions.

Same pattern as SDD-019. The arc never closes; the SDDs do.
