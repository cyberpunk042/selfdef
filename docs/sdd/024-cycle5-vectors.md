# SDD-024 — Cycle 5 vectors (post-cycle-4-closure forward-looking spec)

> Status: **draft** — captures fresh cycle-3 + cycle-4 learnings
> (SD-R59..R73) + lays out unscoped cycle-5 design vectors operators
> may ratify.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-17 (cycle 4 opening — PR #192 merged).
> Builds on: SDD-018 (cycle-1+2 gate doctrine); SDD-019 (cycle-3
> forward-looking, 6/6 closed); SDD-020 (cycle-3 vectors V-1..V-7,
> 4/7 closed); SDD-021 (cycle-4 forward-looking, 4/6 closed);
> SDD-022 (hardware-exploit doctrine, post-hoc V-7 codification);
> SDD-023 (cross-repo model-taxonomy mirror doctrine).

## Why this SDD exists

Fourth iteration of the forward-looking doctrine cadence:

  SDD-018  → cycle 1+2 gate doctrine
  SDD-019  → cycle-3 forward-looking (6/6 closed in cycle 2+3)
  SDD-020  → cycle-3 vectors V-1..V-7 (4/7 closed in cycle 3)
  SDD-021  → cycle-4 forward-looking (4/6 closed in cycle 3)
  SDD-024  → cycle-5 forward-looking (this file)

The arc never closes; the SDDs do. Cycle 3 shipped 20 rounds
(SD-R54..R73 — PR #192 merged) covering the operator-named
hardware-exploit + model-class taxonomy surfaces end-to-end.
SDD-024 captures the design tensions that emerged during cycle-3
closing and lays out cycle-5 candidate vectors.

## Cycle-3 + cycle-4 closing status

Closed in cycle 3:

- **SDD-019** — 6/6 T-vectors closed (T-1 SD-R51, T-2 SD-R52, T-3
  SD-R57, T-4 R189 lockstep, T-5 SD-R45/R47 audit, T-6 SD-R46
  schema-doc cadence)
- **SDD-020 V-1** — SD-R53 strict-hardware audit subject
- **SDD-020 V-2** — SD-R54 per-predicate Layer B metrics
- **SDD-020 V-5** — SD-R55 module manifest signing (+ R195 cross-repo
  audit)
- **SDD-020 V-7** (post-hoc) — SD-R64 hardware-exploitation rollup
  (ternary_aot_capable + zmm_int8_lane_capacity); composed into
  SD-R66 ternary kernel hint, SD-R67 posture verb, SD-R68 generalized
  host_features_required, SD-R70 aot-script
- **SDD-021 W-1** — SD-R60 tensor-parallel slice-plan schema
- **SDD-021 W-2** — SD-R62 keyring directory for trust_root
- **SDD-021 W-6** — SD-R61 per-module resource quotas

Open at cycle 3 close (carry-forward):

- **SDD-020 V-3** — operator-defined custom predicates (deferred-LOW)
- **SDD-020 V-4** — per-module RBAC integration (deferred-LOW)
- **SDD-020 V-6** — predictive thermal modelling (deferred-LOW)
- **SDD-021 W-3 daemon-push variant** — fleet-aggregate via
  HTTP push (file-based variant landed sovereign-os R199; selfdef
  daemon-side push still open)
- **SDD-021 W-4** — real-hardware test (operator-driven, SAIN-01-only)
- **SDD-021 W-5** — sigstore alternative to minisign (deferred-LOW)

## Cycle-5 design tensions (X-N, NEW)

### X-1 — Composable predicates (AND/OR combinators)

Current `[requires_hardware]` predicates are AND-composed implicitly.
Operators have asked for OR semantics: "VNNI on the CPU OR
gpu_count_min ≥ 1" — meaning the module lands when either path is
viable. Today operators must split into two near-identical modules.

  - Recommendation: extend the TOML schema with an optional
    `[[requires_hardware.any_of]]` array — list of inner predicate
    blocks; module passes if ANY block fully evaluates. Existing
    flat predicates stay AND-composed at the root.

### X-2 — Cross-module dependency negotiation (`depends_optional`)

Modules already have `depends_on` (hard) + `provides`/`consumes`
(soft data flow). Operators want a third tier: `depends_optional`
— "I'd prefer hardware-tune-cache to have run first, but I'll fall
back if it's absent." This avoids the current binary land/skip
behaviour for soft dependencies.

  - Recommendation: optional `depends_optional = ["..."]` array in
    module.toml. apply.sh receives a `SELFDEF_OPTIONAL_PRESENT` env
    var enumerating which optional deps did actually land.

### X-3 — Per-module preflight `simulate` mode

Apply runs the install script. Sometimes operators want a deeper
preview than DRY-RUN — actually execute apply against a tempfs
overlay (FUSE-style) so the operator sees the COMPLETE set of files
the module would touch, without committing to the real filesystem.

  - Recommendation: SELFDEF_SIMULATE=1 env var + per-module
    convention for redirecting writes (DEST_PREFIX pattern from
    sovereign-os hardening drop-ins).

### X-4 — Real LoRA-adapter lifecycle on the registry

SD-R71 added `class="lora-adapter"` + `base_model` field as a
TAXONOMY mirror. Cycle 5: actual LIFECYCLE support — the selfdef
runtime tracks which adapters are attached to which base models,
exposes `selfdefctl models lora attach/detach/list`, emits Layer B
metrics on active adapter count per base.

  - Recommendation: composes with R213 sovereign-os
    `models query --class lora-adapter --base-model X`. selfdef-side
    daemon owns the live state; sovereign-os catalog declares the
    intent. Both surfaces become read-write on the LoRA dimension.

### X-5 — Apply-time hardware re-probe (`--reprobe-hardware`)

The hardware gate evaluates against a cached capabilities snapshot
(set at boot or last `hardware export` invocation). On a host where
the operator changes BIOS settings (enables AVX-512, swaps a GPU
in), the cached snapshot diverges from reality.

  - Recommendation: `selfdefctl modules apply --reprobe-hardware`
    flag forces a fresh probe before the gate runs. Operator-friendly
    safety knob; defaults to using the cache.

### X-6 — Module-class taxonomy (parallel to R212 model class)

R212 + SD-R71 carry the MODEL class taxonomy. Cycle 5: extend the
same idea to MODULES. Tag each module with a `category` ENUM
(observability / hardening / inference / network / supply-chain /
storage / lifecycle) + a `lifecycle_phase` (pre-install /
during-install / post-install / recurrent — already encoded in
SD-R23 `phase` field). Then `selfdefctl modules list` gains
`--category` + `--phase` filters that mirror sovereign-os
`models query`.

  - Recommendation: low-effort field add + UI surface; high-value
    for fleets with dozens of modules.

## Cycle-5 priority ranking

| Priority | Vector | Effort | Rationale |
|----------|--------|--------|-----------|
| HIGH     | X-1 any_of predicates | medium | Operators have asked; clean spec |
| HIGH     | X-6 module category taxonomy | small | Symmetry with R212 model taxonomy; cheap |
| MEDIUM   | X-5 --reprobe-hardware | small | Operator safety knob |
| MEDIUM   | X-4 LoRA lifecycle | large | High value but big surface |
| LOW      | X-2 depends_optional | medium | Soft-dependency complexity |
| LOW      | X-3 simulate mode | large | Sharp-edged + niche |

## Non-goals for cycle 5

Inherits SDD-018 + SDD-020 + SDD-021 non-goals + adds:

- Module hot-reload (apply at runtime, no service restart) —
  systemd handles this fine; selfdef doesn't need to.
- Multi-host module orchestration — sovereign-os fleet layer owns this.
- Operator-supplied custom Rust predicates compiled at runtime —
  YAGNI; SD-R68 host_features_required + X-1 any_of cover the
  flexibility the operator named.

## How operators ratify

Edit this file → replace "Recommendation:" with "Decision:" on
each X-N. Commit. Cycle-5 implementation rounds reference the
decisions.

Same pattern as SDD-019 → SDD-020 → SDD-021. The arc never closes;
the SDDs do.

## Cross-references

- SDD-018 — hardware-aware modules + tune surface (cycle-1+2)
- SDD-019/020/021 — cycle-3 + cycle-4 forward-looking spec cadence
- SDD-022 — hardware-exploitation doctrine
- SDD-023 — cross-repo model-taxonomy mirror doctrine
- PR #192 (merged) — cycle-3 arc shipping SD-R54..R73
- sovereign-os R209-R218 — cross-repo arc closing in lockstep
