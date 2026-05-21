# SDD-057 — selfdef-hardware-requirements shared-crate split

> Status: **scoping** — Stage-2 plan for the refactor that unblocks
> MS011 Z-13 SD-R86 hardware-gate enrichment + the future MS035 +
> MS042 caller-integration arcs that need the same gate logic.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS011 (catalog row Z-13 SD-R86 portion);
> indirectly unblocks the caller-integration arcs of multiple
> partial milestones per SDD-055.
> Builds on: SDD-055 (partial milestone landscape — identifies this
> as a recommended next-session target).

## Problem

The `HardwareRequirements` struct + its `evaluate(&caps)` /
`evaluate_resolved(&caps)` impl live in `crates/selfdef-cli/src/
modules.rs` as `pub(crate)` items (lines 190-613, ~423 LOC). They
implement the per-module hardware-gate check that compares a
module's `[requires_hardware]` block against the runtime
`HardwareCapabilities`.

Multiple downstream callers need this gate:

1. **selfdef-api** — `/v1/modules/install-options` currently
   classifies dep-readiness ONLY (SD-R86 partial portion).
   Hardware-gate enrichment (`blocked-by-hardware`,
   `needs-review`) is deferred because the gate logic lives in
   the CLI binary, not a crate the API can depend on.

2. **Future MS035 caller integration** — capability-token issue
   path needs to gate by hardware (e.g. issue a `gpu-inference`
   token only on hosts where the matching gate passes).

3. **Future MS042 tool-authority caller integration** — tool
   invocations gated by hardware (e.g. `ToolId::ModelInference`
   refuses on hosts with no GPU).

A CLI binary cannot be a Cargo dependency. The fix is to extract
the type + impl into a new workspace crate
`selfdef-hardware-requirements` and have both selfdef-cli +
selfdef-api depend on it.

## Goals

1. Move `HardwareRequirements` + `RequirementError` + `EvaluatedRequirement`
   + the `evaluate*` impl to `crates/selfdef-hardware-requirements/`
2. Re-export from selfdef-cli's modules module so existing callers
   continue to compile without changes
3. Add a dep from selfdef-api so the install-options handler can
   call the gate
4. Preserve every existing selfdef-cli unit test through the move
5. Add unit tests in the new crate (canonical-shape + each gate
   predicate exercised)

## Non-goals

- Does NOT change the gate semantics — predicates evaluate
  identically before + after
- Does NOT consume the new crate from any other crate beyond
  selfdef-cli + selfdef-api in this round
- Does NOT split out `ModuleManifest` (the parent struct) — that's
  a separate refactor with its own surface area

## Recommended design

### Crate skeleton

```
crates/selfdef-hardware-requirements/
├── Cargo.toml          // depends on selfdef-hardware (capability shape)
└── src/lib.rs          // ~450 LOC after move (struct + impl + tests)
```

### Migration sequence

1. **Single commit** — author this SDD (scope locked) ← THIS COMMIT
2. **Single commit** — scaffold the new crate:
   - `crates/selfdef-hardware-requirements/Cargo.toml`
   - `src/lib.rs` with stub `pub struct HardwareRequirements`
   - workspace `Cargo.toml` path entry
3. **Single commit** — move the type + impl from selfdef-cli:
   - Copy struct + impl + 5 supporting types verbatim
   - Convert `pub(crate)` → `pub` on every moved item
   - Add `#![forbid(unsafe_code)]` + `#![warn(missing_docs)]`
   - Cover every moved fn with a brief `///` doc
4. **Single commit** — re-export from selfdef-cli:
   - `crates/selfdef-cli/Cargo.toml` adds the dep
   - `crates/selfdef-cli/src/modules.rs` deletes the moved code +
     adds `pub(crate) use selfdef_hardware_requirements::*;` so
     existing pub(crate) callers continue to resolve
   - Run `cargo test -p selfdef-cli` — all tests must pass
5. **Single commit** — hook the API:
   - `crates/selfdef-api/Cargo.toml` adds the dep
   - `crates/selfdef-api/src/modules.rs::install_options` extends
     classification: `blocked-by-hardware` when gate fails;
     `needs-review` when probe is unavailable
6. **Single commit** — extend `/v1/modules/install-options`
   integration test for the new classifications
7. **Single commit** — promote SDD-057 scoping → implemented +
   close MS011 Z-13 SD-R86 hardware-gate row

### Risk vs. benefit

**Risk**:
- 423 LOC move touches load-bearing CLI code; CI tests must catch
  any regression
- Workspace deps tree change (new crate inserted between bins +
  api + selfdef-hardware)
- Some `pub(crate)` items may need wider visibility — surfaces
  any unexpected `pub(crate)` boundary violations

**Benefit**:
- Unblocks Z-13 SD-R86 hardware-gate enrichment (closes 1 of the
  6 remaining partial milestone arcs per SDD-055)
- Unblocks future MS035 + MS042 caller-integration arcs
- Reduces selfdef-cli's binary size (~400 LOC less linked into
  the bin)
- Makes the gate logic independently testable + benchmarkable

## Implementation status

**This SDD only — Stage-2 plan locked.**

## Open questions

- **D-1**: Should `HardwareRequirements::evaluate*` return
  `Result<EvaluatedRequirement, RequirementError>` or
  `EvaluationOutcome` enum? **Recommendation**: keep the
  `Result<...>` shape — it's what the CLI callers already
  consume; minimizes downstream churn.

- **D-2**: Should the new crate own `ModuleManifest` deserialization
  too, so callers can parse module.toml directly without going
  through selfdef-cli? **Recommendation**: defer to a future SDD —
  this round is just the gate logic move; the manifest parser is
  a separate concern (selfdef-api already has its own
  ModuleSummary deserializer).

- **D-3**: Should the gate offer a `dry_run(&caps)` mode that
  returns ALL unmet predicates without short-circuiting on the
  first failure? **Recommendation**: yes — it's what the SD-R86
  enrichment surface wants (the dashboard should show ALL reasons
  a module can't install, not just the first). Add as a
  follow-up method `evaluate_all_unmet(&caps) -> Vec<String>`.

- **D-4**: Should the new crate split the `evaluate()` /
  `evaluate_resolved()` distinction? **Recommendation**: no —
  the resolved-branch-index is operator-debugging info that
  callers want preserved. Keep both methods.

## Cross-references

- SDD-055 § Recommended next-session targets — names this as the
  3rd target (multi-commit; unblocks Z-13 SD-R86 hardware-gate)
- SDD-026 Z-13 — original ratification for SD-R86
- `crates/selfdef-api/src/modules.rs::install_options` —
  deferred hardware-gate enrichment cited in the doc comment
- `crates/selfdef-cli/src/modules.rs` lines 190-613 — current
  location of the moved code
