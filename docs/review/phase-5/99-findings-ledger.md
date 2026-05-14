# Phase 5 — findings ledger

> Status: in progress
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

- **0 findings raised** across three Phase 5 explorers
  (recent-PRs + crate + module). **All three 100% clean on
  first-pass scrutiny.**
- The Phase 4 closure cycle was exceptionally clean
  execution. The module-side surface (vpn-bridge dispatcher
  header doc-refresh) verifies correct against the actual
  `profile_apply` behaviour; v2 migration coverage is
  re-verified at 7/8 modules (suricata correctly exempt);
  legacy-fallback dedup in `profile_uninstall` is sound
  (only runs on empty-manifest branch).
- **Trajectory comparison**:

  | Cycle | recent-PRs | crate | module |
  | --- | --- | --- | --- |
  | Phase 2 | many | 11 nice | 6 nice |
  | Phase 3 | 4 nice | 10 mixed | 1 important |
  | Phase 4 | 1 demoted | 2 nice | 1 nice |
  | **Phase 5** | **0** | **0** | **0** |

- Four explorers remain: integration, docs, tests, security.
- No Phase 5 SDD-debt findings yet.

## Phase 1 / Phase 2 / Phase 3 / Phase 4 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
