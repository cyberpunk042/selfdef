# SDD-019 — Cycle 3 forward-looking spec (post-PR-#191 horizons)

> Status: **draft** — captures learnings from the cycle-2 arc (SD-R24..R48
> in PR #191) + lays out vectors operators may ratify for cycle 3.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-16 (cycle 2 amendment — 5/6 tensions closed
> in same cycle).
> Builds on: SDD-018 (cycle-1 + cycle-2 module gate doctrine).

## In-cycle tension closures (R43 SDD authoring → R48)

The forward-looking nature of this SDD turned out to be FASTER than
expected: 5 of 6 identified tensions closed in cycle 2 itself rather
than waiting for cycle 3.

| Tension | Cycle | Round | Status |
|---------|-------|-------|--------|
| T-1 (ANY-vs-ALL semantics) | open | — | YAGNI; deferred |
| T-2 (override audit trail) | cycle 2 | SD-R47 | ✓ closed |
| T-3 (model artifact verification) | cycle 2 | R190 (verify) | ⏸ partial (fetch-side cycle 3) |
| T-4 (cross-repo schema drift) | cycle 2 | R189 | ✓ closed |
| T-5 (recommendation matrix dup) | cycle 2 | R188 | ✓ closed |
| T-6 (schedule.json schema) | cycle 2 | SD-R46 | ✓ closed |

This is the "continuous evolution" pattern operating at sub-cycle
granularity: the doctrine layer (forward-looking spec) moves at the
same tempo as the code, not as an afterthought delayed by one cycle.

The remaining open vectors for cycle 3 are: T-1 (YAGNI — wait for a
real module to need it) and T-3 fetch-side (HTTP + token plumbing
— bigger lift, deserves dedicated round).

## Why this SDD exists

Operator directive: "research and continuously evolving specs to drive
and evolve the SDD and TDD". Cycle 2 closed dozens of practical gaps;
this SDD inventories the design tensions + open questions that emerged
WHILE building cycle 2, so cycle 3 starts from a known position
instead of rediscovering them.

This is not a commitment — every `Q-N` below is operator-pending.
Cycle 3 implementation rounds will reference + close them.

## Cycle-2 learnings (delivered surface)

The cycle-2 arc shipped:

- 7 `[requires_hardware]` predicates (cycle 1 = 5; cycle 2 added
  `gpu_vram_gib_min`, `gpu_power_headroom_watts_min`,
  `wasm_aot_features_required`)
- Per-GPU detail in HardwareCapabilities (`gpu.devices` array)
- Pre-computed `wasm_aot` block (target_triple/cpu/features +
  worked compile_command_hint)
- NVCC `-gencode` derivation (Blackwell sm_120 + Ampere sm_86)
- Real SD-R28 demonstrator module (`bitnet-gpu-inference`)
- 1-bit/ternary model registry + dry-run surface
- Module dependency graph (DOT + JSON modes)
- Layer B Prometheus scrape for wasm-AOT
- HOST SNAPSHOT block in check-hardware (live + saved snapshot)
- `--json` mode on every cycle-2 surface (info, graph,
  check-hardware, models, doctor)
- Operator override flag (`--ignore-hardware`)
- 11 cross-repo mirrors in sovereign-os
- Comprehensive cycle-2 readiness report (R187)

Surface count: ~17 selfdef rounds + ~11 sovereign-os rounds in cycle 2.
Workspace test count: 1067 (up from 947 at session resume after PR #190).

## Open design tensions

The following emerged in cycle 2 but were deferred to keep PR #191
scoped:

### T-1 — Gate predicate semantics: ANY vs ALL

`gpu_vram_gib_min` passes when ANY GPU meets the bar (max semantics
— SDD-018 D-9). A complementary `gpu_vram_gib_each_min` (every GPU
must meet) might be valuable for fleet uniformity — but adds
complexity. Cycle 3 decision: do we add the `_each_min` variant or
keep operators on per-module ANY semantics?

### T-2 — Operator override audit trail

`--ignore-hardware` (SD-R42) emits a banner but doesn't persist the
override. Audit-conscious deployments may want every override
recorded to the JSONL eventstream (so the operator's bypass shows
up in OCSF alerts). Cycle 3: emit an OCSF "operator action: gate
override" event when the flag is set.

### T-3 — Model registry artifact verification

SD-R34 records `artifact_sha256` but no consumer verifies it yet.
The future model-fetcher should refuse to land an artifact whose
digest doesn't match. Cycle 3: build `selfdefctl models fetch <slug>`
that downloads + verifies + drops into `/mnt/vault/models`.

### T-4 — Cross-repo schema drift detection

Both repos parse the capabilities JSON independently. A future schema
addition (e.g. SD-R30 added `wasm_aot` and bumped 1.0.0 → 1.2.0)
requires both sides to read the new fields. Cycle 3: a schema-lockstep
test in each repo asserting the FIELDS the consumer needs are
present in the FIXTURE the producer ships.

### T-5 — Recommendation matrix codified vs inlined

R185 (osctl install suggest-modules) + R186 (wizard) hardcode the
same recommendation matrix in TWO places. Cycle 3: factor into a
single source — either a TOML matrix file or a shared Python helper.

### T-6 — Schedule.json schema

SD-R28 emits `schedule.json` with a basic schema. R178 pick-gpu.py
consumes it but the schema is implicit. Cycle 3: write a JSON schema
file + lockstep test.

## Open operator questions (cycle 3)

These need operator answers before implementation:

- **Q-019.1**: Should `--ignore-hardware` (SD-R42) AUDIT the override
  to the eventstream automatically, or stay banner-only?
  - Recommendation: AUDIT (T-2 above) — operator overrides should be
    visible in fleet-wide alert logs.

- **Q-019.2**: Should we add a `gpu_vram_gib_each_min` predicate (per
  T-1)? Or is ANY-semantics enough?
  - Recommendation: defer until a real module needs it. YAGNI.

- **Q-019.3**: `selfdefctl models fetch` — what's the trust model?
  Operator-supplied tokens? Local mirror? Refuse fetch if no signature?
  - Recommendation: artifact_sha256 mandatory; signature optional;
    operator-supplied HuggingFace token via env var only.

- **Q-019.4**: BitNet schedule.json — strict schema (refuse invalid)
  or fail-soft (apply defaults)?
  - Recommendation: fail-soft (cycle-2 already does); cycle 3 just
    adds explicit schema doc.

- **Q-019.5**: Cycle-3 cross-repo: should sovereign-osctl OWN the
  hardware-tune cache file path, or should selfdef? Currently selfdef
  writes; sovereign-os reads.
  - Recommendation: keep current (selfdef writes via hardware-tune-cache
    module; sovereign-os reads only). Single-writer invariant.

## Recommended cycle-3 priorities (operator-rankable)

| Priority | Round target | Effort | Rationale |
|----------|--------------|--------|-----------|
| HIGH     | T-2 audit    | small  | Closes operator-override observability |
| HIGH     | T-3 verify   | medium | Model-fetcher must verify by design |
| HIGH     | T-4 schema lockstep | small | Prevent silent cross-repo drift |
| MEDIUM   | T-5 matrix factor | small | Removes duplication |
| MEDIUM   | T-6 schedule schema | small | Tightens cross-repo contract |
| LOW      | T-1 ANY-vs-ALL | small | YAGNI unless a module demands it |

## Non-goals for cycle 3

Carrying SDD-018 § Non-goals forward unchanged:
- AMD ROCm GPU probing (NVIDIA only).
- Per-NUMA-node thermal binning.
- `unsafe` AVX-512 intrinsics in selfdef itself (`#![forbid(unsafe_code)]`
  remains; AVX-512 exploitation lives in safe crates with
  target_feature dispatch + sovereign-os build artifacts).

NEW non-goals identified during cycle 2:
- Multi-host coordination (the selfdef daemon stays per-host).
- Real-time gate re-evaluation (gate fires at apply-time; runtime
  hardware-state drift surfaces via the SD-R22 periodic probe loop
  + OCSF events, not via a re-gate).
- AI-assisted module recommendation (the R185/R186 matrix is
  explicit + auditable; no LLM-derived rules).

## How operators ratify

Edit this file → answer the `Q-019.N` questions inline (e.g. change
"Recommendation: …" to "Decision: …"); commit to main. Cycle-3 rounds
reference the decisions when closing each T-N tension.

The next SDD (020+) will capture cycle-3's accumulated learnings — same
forward-looking pattern. The arc never closes; the SDDs do.
