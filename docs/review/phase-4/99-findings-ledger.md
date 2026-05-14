# Phase 4 — findings ledger

> Status: in progress
> Vintage prefix: **F-2029-NNN**
> Last updated: 2026-05-14

This ledger tracks Phase 4 findings as they surface across the
seven explorers (recent-PRs, crate, module, integration, docs,
tests, security). Each finding is `F-2029-NNN` and either ships
in a closure PR or graduates to an SDD when the fix is
design-shaped.

> See [Phase 1](../99-findings-ledger.md), [Phase 2](../phase-2/99-findings-ledger.md),
> and [Phase 3](../phase-3/99-findings-ledger.md) ledgers for
> prior vintages.

## Triage legend

- **blocker** — must fix before shipping.
- **important** — should fix.
- **nice** — cosmetic / non-blocking / ergonomic.
- **SDD-debt** — fix is design-shaped; spawn an SDD.
- **demoted** — auditor flagged but cross-check showed no
  action needed; left in the ledger for the audit trail.

## Findings

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2029-001 | demoted | SDD-007 implementation PR claims D-4 deferred while D-4 ships 13 minutes later | Recent-PRs auditor flagged that PR `a1d6823`'s commit message says "D-4 deferred to a thin follow-up" while PR `8b44322` (shipped immediately after) implements D-4 fully. Cross-check: the defer-and-pair pattern is intentional — each PR's commit message is accurate at its own write time; the SDD-007 status doc (`docs/sdd/007-per-token-sse-subscriber-quota.md`) is updated by `8b44322` to "all five Ds shipped". No code drift, no feature gap. Kept in ledger for audit-trail completeness. | none |

## Status

- **1 finding raised** by the first Phase 4 explorer
  (recent-PRs). **0 blockers**, **0 important**, **0 nice**,
  **1 demoted** (F-2029-001 — defer-and-pair pattern
  cross-checked clean).
- The Phase 3 closure cycle was the cleanest yet: 16/17 PRs
  review-clean (94%), no actionable observations.
- Six explorers remain: crate, module, integration, docs,
  tests, security. Each will add findings in follow-up PRs.
- No Phase 4 SDD-debt findings yet.

## Phase 1 / Phase 2 / Phase 3 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
