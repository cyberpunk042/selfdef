# Phase 5 — findings ledger

> Status: **wrapped** — all 7 explorers complete, 0 findings total.
> Vintage prefix: **F-2030-NNN**
> Last updated: 2026-05-14

This ledger tracks Phase 5 findings as they surface across the
seven explorers (recent-PRs, crate, module, integration, docs,
tests, security). Each finding is `F-2030-NNN` and either ships
in a closure PR or graduates to an SDD when the fix is
design-shaped.

> See [Phase 1](../99-findings-ledger.md),
> [Phase 2](../phase-2/99-findings-ledger.md),
> [Phase 3](../phase-3/99-findings-ledger.md), and
> [Phase 4](../phase-4/99-findings-ledger.md) ledgers for
> prior vintages.

## Triage legend

- **blocker** — must fix before shipping.
- **important** — should fix.
- **nice** — cosmetic / non-blocking / ergonomic.
- **SDD-debt** — fix is design-shaped; spawn an SDD.
- **demoted** — auditor flagged but cross-check showed no
  action needed; left in the ledger for the audit trail.

## Findings

*(none yet from the recent-PRs explorer — first explorer with
zero findings on the first pass since Phase 1's baseline. The
Phase 4 closure cycle was exceptionally clean execution.)*

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |

## Status

- **0 findings raised across all seven Phase 5 explorers**
  (recent-PRs + crate + module + integration + docs + tests +
  security). **First Phase in this audit programme to land
  bytewise clean across the entire explorer suite.** A
  milestone-grade outcome for the closure-cycle programme.
- Phase 5 security auditor verified that the Phase 4 closure
  cycle's production surface diff is overwhelmingly negative
  (less exposed surface, not more):
  - `TokenFingerprint` Debug truncation — strictly defensive
    (4-byte prefix, 28 bytes of entropy unrevealed); no
    `Debug` in the derive list, no `Display`/hex escape
    hatches.
  - Zero-cap fallback test — pins existing `n > 0` guard; no
    new code path.
  - Config round-trip tests — harden operator-facing TOML
    contract; no new code path.
  - `apply.sh` doc-comment — documents existing dispatcher
    behaviour; no code change.
  - SECURITY.md § API surface — clarifies operator-facing cap
    semantics; reduces configuration-error blast radius.
  - Re-audits of F-2028-037 (dual-counter SSE quota),
    F-2028-018 (SseParser bytes refactor), F-2028-015
    (vpn-bridge manifest cleanup), F-2028-004/-005
    (token-reader symmetry), and F-2028-001 (paths.rs
    compile-time invariants) all hold; no regression.
- Phase 5 tests auditor verified the three incremental tests
  (`events_stream_zero_caps_fall_back_to_defaults`,
  `sse_cap_knobs_round_trip_from_toml`,
  `sse_cap_knobs_default_to_none_when_unset`) are isolated,
  deterministic, free of real-time sleeps (SDD-005 compliant),
  and pin precisely the contracts their docstrings claim. The
  TOML → `ApiConfig` → `SseCaps` → `try_acquire` chain is now
  test-covered at every hop with no remaining coverage gap on
  the SDD-007 D-4 cap surface.
- Phase 5 integration auditor traced all five seams from the
  Phase 4 closure cycle end-to-end:
  - TOML → daemon → ApiState chain test-covered at both ends.
  - `Some(0)` fallback's `n > 0` guard correctly pinned by
    test.
  - `TokenFingerprint` Debug impl + tracing-safety contract
    sound (defensive for future field-expansion usage).
  - `vpn-bridge` `apply.sh` header claims verified against
    `profile_apply` impl.
  - `SECURITY.md` per-token SSE cap text verifies bytewise
    against `handlers.rs` + `config.rs`.
- **Trajectory comparison** (full seven-explorer view):

  | Cycle | recent-PRs | crate | module | integration | docs | tests | security |
  | --- | --- | --- | --- | --- | --- | --- | --- |
  | Phase 2 | many | 11 nice | 6 nice | 9 mixed | 9 nice | 11 mixed | 5 mixed |
  | Phase 3 | 4 nice | 10 mixed | 1 important | 4 nice | 5 mixed | 5 mixed | 3 nice |
  | Phase 4 | 1 demoted | 2 nice | 1 nice | 2 nice | 1 nice | 1 demoted | 1 demoted |
  | **Phase 5** | **0** | **0** | **0** | **0** | **0** | **0** | **0** |

- All explorers complete. No Phase 5 SDD-debt findings.
  Phase 5 closes as **0 findings across 7 explorers** — the
  convergence trajectory (64 → 39 → 9 → 0) has reached a steady
  state. The closure-cycle programme is operating as designed:
  audit → ship → re-audit → confirm no regression.

## Phase 1 / Phase 2 / Phase 3 / Phase 4 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
