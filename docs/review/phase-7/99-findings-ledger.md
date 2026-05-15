# Phase 7 — findings ledger

> Status: **open** — charter just landed; explorers pending.
> Vintage prefix: **F-2032-NNN**
> Last updated: 2026-05-15

This ledger tracks Phase 7 findings as they surface across the
seven explorers (recent-PRs, crate, module, integration, docs,
tests, security). Each finding is `F-2032-NNN` and either ships
in a closure PR or graduates to an SDD when the fix is
design-shaped.

> See [Phase 1](../99-findings-ledger.md),
> [Phase 2](../phase-2/99-findings-ledger.md),
> [Phase 3](../phase-3/99-findings-ledger.md),
> [Phase 4](../phase-4/99-findings-ledger.md),
> [Phase 5](../phase-5/99-findings-ledger.md), and
> [Phase 6](../phase-6/99-findings-ledger.md) ledgers for
> prior vintages.

## Triage legend

- **blocker** — must fix before shipping.
- **important** — should fix.
- **nice** — cosmetic / non-blocking / ergonomic.
- **SDD-debt** — fix is design-shaped; spawn an SDD.
- **demoted** — auditor flagged but cross-check showed no
  action needed; left in the ledger for the audit trail.

## Findings

*(none yet — explorers run in follow-up PRs.)*

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |

## Status

- Charter (this PR) opens Phase 7.
- Seven explorers ship in follow-up PRs:
  1. `10-inventory.md` — structured catalog of the post-Phase-6
     cycle (7 PRs, 4 new crates, schema migrations v2+v3,
     ~93 new tests).
  2. `20-recent-prs-audit.md` — PR-by-PR audit of #140..#146.
  3. `30-crate-audit.md` — 4 new Q-G channel crates' shapes.
  4. `40-module-audit.md` — D-4 HTTP ack flow end-to-end.
  5. `50-integration-audit.md` — schema migrations on disk,
     ack_link_base round-trip, ApiState engine handle wiring.
  6. `60-docs-audit.md` — SDD-008 status table, STARTER_CONFIG
     5 new blocks, SECURITY.md row deltas.
  7. `70-tests-audit.md` — `EngineHarness` pattern, Q-G test
     count variance.
  8. `80-security-audit.md` — schema v2+v3 migration safety,
     new unauth `/notify/ack/:token` route, 4 new credential
     surfaces.
- Phase 7 closes when every important / blocker has either a
  "closed by <PR>" back-reference or a tracked SDD.

## Trajectory snapshot

For context — full closure-cycle convergence to date:

| Cycle | recent-PRs | crate | module | integration | docs | tests | security |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phase 2 | many | 11 nice | 6 nice | 9 mixed | 9 nice | 11 mixed | 5 mixed |
| Phase 3 | 4 nice | 10 mixed | 1 important | 4 nice | 5 mixed | 5 mixed | 3 nice |
| Phase 4 | 1 demoted | 2 nice | 1 nice | 2 nice | 1 nice | 1 demoted | 1 demoted |
| Phase 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Phase 6 | 3 nice + 1 demoted | 1 important + 2 nice | 2 important + 1 nice + 1 SDD-debt | 1 nice + stopgap | 3 nice | 1 SDD-debt + 1 demoted | 1 important + 2 nice |
| **Phase 7** | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |

Phase 6 audited a 22-PR / 9-new-crate feature cycle and
caught 3 important production-relevant defects; Phase 7
audits a 7-PR / 4-new-crate **pattern-instance + 2-seam**
cycle, where most of the surface is variations on a known
template. Realistic outcome: 3-8 findings, mostly nice.

## Phase 1 / 2 / 3 / 4 / 5 / 6 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
- Phase 5: [`../phase-5/99-findings-ledger.md`](../phase-5/99-findings-ledger.md)
- Phase 6: [`../phase-6/99-findings-ledger.md`](../phase-6/99-findings-ledger.md)
