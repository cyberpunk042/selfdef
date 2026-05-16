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

## Cycle-3 priority ranking

| Priority | Vector | Effort | Rationale |
|----------|--------|--------|-----------|
| HIGH     | T-3 fetch | medium | Closes the model-registry loop (SDD-019 carry-over) |
| HIGH     | V-1 audit | small  | Cheap extension of SD-R47; closes operator-action observability |
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
