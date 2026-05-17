# SDD-025 — Cycle 6 vectors (post-cycle-5-closure forward-looking spec)

> Status: **draft** — captures fresh cycle-5 learnings (SD-R74..R77)
> + lays out unscoped cycle-6 design vectors operators may ratify.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-17 (cycle 6 opening — PR #194 merged).
> Builds on: SDD-018 (cycle-1+2 gate doctrine); SDD-019/020/021/024
> (forward-looking cadence); SDD-022 (hardware-exploit doctrine);
> SDD-023 (cross-repo model-taxonomy mirror doctrine).

## Why this SDD exists

Fifth iteration of the forward-looking doctrine cadence:

  SDD-018  → cycle 1+2 gate doctrine
  SDD-019  → cycle-3 forward-looking (6/6 closed in cycle 2+3)
  SDD-020  → cycle-3 vectors V-1..V-7 (4/7 closed in cycle 3)
  SDD-021  → cycle-4 forward-looking (4/6 closed in cycle 3)
  SDD-024  → cycle-5 forward-looking (3/6 closed across PR #193 + #194)
  SDD-025  → cycle-6 forward-looking (this file)

The arc never closes; the SDDs do. PR #194 (cycle-5) shipped
SD-R76 (X-5 `--reprobe-hardware`) and SD-R77 (X-1 composable
`any_of` OR-predicates) — both operator-named priorities. Three
SDD-024 vectors carry forward; SDD-025 records that + lays out
fresh cycle-6 tensions.

## Cycle-5 closing status

Closed in cycle 5 (PR #193 + PR #194):

- **SDD-024 X-6** — module category taxonomy (SD-R75:
  `modules list --category C --phase P` filters)
- **SDD-024 X-5** — `--reprobe-hardware` safety knob (SD-R76)
- **SDD-024 X-1** — composable `[[requires_hardware.any_of]]`
  OR-predicates (SD-R77)

Open at cycle-5 close (carry-forward to cycle 6+):

- **SDD-024 X-4** — real LoRA-adapter lifecycle on the registry
- **SDD-024 X-2** — `depends_optional` soft-dep tier (LOW)
- **SDD-024 X-3** — per-module simulate mode (LOW)
- **SDD-020 V-3/V-4/V-6** — operator-defined predicates / RBAC /
  thermal trend (deferred-LOW from cycle 3)
- **SDD-021 W-3 daemon-push** — fleet-aggregate via HTTP push
- **SDD-021 W-4** — real-hardware test (operator-driven)
- **SDD-021 W-5** — sigstore alternative (LOW)

## Cycle-6 design tensions (Y-N, NEW)

### Y-1 — `any_of` Layer-B observability

SD-R77 added OR-composition to the gate predicate. When a module
passes via its 3rd `any_of` branch (not the 1st), operators today
don't see WHICH branch matched. Cycle 6: emit a
`sovereign_os_selfdef_module_anyof_branch_total{module,branch_idx}`
counter so fleet dashboards show which OR-paths are actually
exercised.

  - Recommendation: piggyback on the existing SD-R54 Layer B
    `sovereign_os_selfdef_hardware_*` emission cadence; same
    textfile-collector mechanics; same operator workflow.

### Y-2 — LoRA registry state file format

SDD-024 X-4 (large surface). Cycle-6 sub-vector: pin the on-disk
state file the daemon writes to track active adapters. Suggested:
`/var/lib/selfdef/loras.json` with shape
`{schema_version, adapters: [{adapter_id, base_model, attached_at,
status}]}`. This is the smallest contractual brick of the X-4
arc — once the format lands, attach/detach + list verbs build on
top in subsequent rounds.

  - Recommendation: ship the JSON Schema + an empty seed file +
    the loader/parser in selfdef-cli; defer the attach/detach
    verbs to a follow-up.

### Y-3 — `models suggest` cross-repo bridge

sovereign-os R214 has the profile-aware model suggester surface.
Cycle 6: bridge it from selfdef-cli so operators on hosts with
selfdefctl-but-no-sovereign-osctl get the same advice. Mirror the
catalog reader + the analyser; no separate runtime profile concept
(selfdef-side bridge reads sovereign-os profile YAMLs by path).

  - Recommendation: defer until SD-R71 ModelSpec gets the
    runtime_profile_bindings field (currently selfdef-side
    permissive; sovereign-os-side strict).

### Y-4 — `modules show-effective` after any_of evaluation

With SD-R77 OR-predicates, a module's "effective requirements" on a
specific host depend on WHICH branch matched. Cycle 6:
`selfdefctl modules info <slug> --resolved` prints the resolved
requirement set (root + chosen any_of branch) instead of the raw
manifest. Operators learn "this host would land via branch 1: VNNI
+ ternary path."

  - Recommendation: pure renderer over existing evaluate() output;
    no new state.

### Y-5 — `--reprobe-hardware` actually does something

SD-R76 wired the flag + the stderr banner; selfdef-hardware
probe() is already fresh per-invocation so the flag is a no-op at
the probe layer. Cycle 6: introduce a daemon-emitted capabilities
cache at `/var/lib/selfdef/hardware-capabilities.json` (already
emitted by `selfdefctl hardware export --output`); the gate reads
the cache by default + bypasses it under `--reprobe-hardware`.

  - Recommendation: cache invalidation is hard. Start by treating
    cache files older than 24h as automatically stale (silent
    refresh); --reprobe-hardware forces refresh regardless of age.

### Y-6 — Module `[whitelabel]` block

Operators with multiple sovereign-os profiles (per the R212 catalog
+ runtime profile binding) want per-module display tweaks. Tag
each module with an optional `[whitelabel]` block (display_name,
color hint, icon) so the wizard + osctl overview render with the
operator's brand-flavored names. Composes with sovereign-os
SDD-007 whitelabel taxonomy.

  - Recommendation: defer until R212 model catalog gets a sibling
    `display_name` field on its own taxonomy; keep the pattern
    consistent across surfaces.

## Cycle-6 priority ranking

| Priority | Vector | Effort | Rationale |
|----------|--------|--------|-----------|
| HIGH     | Y-1 any_of observability | small | Operator dashboard win on SD-R77 |
| HIGH     | Y-4 show-effective renderer | small | Operator-readable resolved manifest |
| MEDIUM   | Y-2 LoRA state file format | medium | Foundation for X-4 arc |
| MEDIUM   | Y-5 capabilities cache + reprobe semantics | medium | Closes the SD-R76 future-round commitment |
| LOW      | Y-3 cross-repo models suggest bridge | medium | Depends on cross-repo design |
| LOW      | Y-6 module whitelabel block | small | Cosmetic |

## Non-goals for cycle 6

Inherits SDD-018 + SDD-020 + SDD-021 + SDD-024 non-goals + adds:

- Multi-host LoRA orchestration — sovereign-os fleet layer owns this.
- Module hot-reload (apply at runtime, no service restart) —
  carry-forward non-goal.
- Closed-set validation of `[whitelabel]` enum values on the
  selfdef side — selfdef stays permissive per SDD-023.

## How operators ratify

Edit this file → replace "Recommendation:" with "Decision:" on
each Y-N. Commit. Cycle-6 implementation rounds reference the
decisions.

Same pattern as SDD-019 → SDD-020 → SDD-021 → SDD-024. The arc
never closes; the SDDs do.

## Cross-references

- SDD-018 — hardware-aware modules + tune surface (cycle-1+2)
- SDD-019/020/021/024 — forward-looking spec cadence
- SDD-022 — hardware-exploitation doctrine
- SDD-023 — cross-repo model-taxonomy mirror doctrine
- PR #193 (merged) — cycle-4 arc (SD-R74..R75)
- PR #194 (merged) — cycle-5 arc (SD-R76..R77)
