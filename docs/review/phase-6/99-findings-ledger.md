# Phase 6 — findings ledger

> Status: **open** — charter just landed; explorers pending.
> Vintage prefix: **F-2031-NNN**
> Last updated: 2026-05-15

This ledger tracks Phase 6 findings as they surface across the
seven explorers (recent-PRs, crate, module, integration, docs,
tests, security). Each finding is `F-2031-NNN` and either ships
in a closure PR or graduates to an SDD when the fix is
design-shaped.

> See [Phase 1](../99-findings-ledger.md),
> [Phase 2](../phase-2/99-findings-ledger.md),
> [Phase 3](../phase-3/99-findings-ledger.md),
> [Phase 4](../phase-4/99-findings-ledger.md), and
> [Phase 5](../phase-5/99-findings-ledger.md) ledgers for
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

- Charter landed; this is the empty ledger template.
- Inventory + seven explorers ship in follow-up PRs:
  1. `10-inventory.md` — structured catalog of what was added
     during the SDD-008 cycle (9 new crates, 22 PRs).
  2. `20-recent-prs-audit.md` — PR-by-PR audit of `#109`..`#130`.
  3. `30-crate-audit.md` — 9 new crates' shapes + invariants.
  4. `40-module-audit.md` — dispatcher path + daemon wiring +
     event-to-payload bridge.
  5. `50-integration-audit.md` — startup wiring, config round-trip,
     wake-task lifecycle.
  6. `60-docs-audit.md` — SDD-008, ARCHITECTURE.md, integrations
     contributor doc, SECURITY.md additions, init.rs starter
     config.
  7. `70-tests-audit.md` — engine + dispatcher + wake-task +
     channel-validation + profile tests.
  8. `80-security-audit.md` — credentials, TTY broadcast, SQLite
     injection surface, rung-advance race, TLS posture.
- Phase 6 closes when every important / blocker has either a
  "closed by <PR>" back-reference or a tracked SDD.

## Trajectory snapshot

For context — full closure-cycle convergence to date:

| Cycle | recent-PRs | crate | module | integration | docs | tests | security |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phase 2 | many | 11 nice | 6 nice | 9 mixed | 9 nice | 11 mixed | 5 mixed |
| Phase 3 | 4 nice | 10 mixed | 1 important | 4 nice | 5 mixed | 5 mixed | 3 nice |
| Phase 4 | 1 demoted | 2 nice | 1 nice | 2 nice | 1 nice | 1 demoted | 1 demoted |
| Phase 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Phase 6** | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* | *pending* |

Phase 5's zero-finding result reflected its audit surface (a
documentation-heavy closure cycle); Phase 6 audits an
opposite-shaped cycle (9 new crates, persistent storage,
outbound credentials, background tasks). Carry-forward of the
0-finding prediction would be unsound.

## Phase 1 / Phase 2 / Phase 3 / Phase 4 / Phase 5 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
- Phase 5: [`../phase-5/99-findings-ledger.md`](../phase-5/99-findings-ledger.md)
