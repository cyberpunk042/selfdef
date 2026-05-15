# Phase 7 — findings ledger

> Status: **open** — 4 explorers landed (inventory, recent-PRs, crate, module); 4 explorers pending.
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

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2032-001 | nice | engine (schema v2 + v3 migration) | The v2 and v3 migration blocks in `EscalationEngine::migrate` run `ALTER TABLE` + back-fill (v3 only) + index + `user_version` bump as separate statements outside a transaction. If a step fails mid-block (e.g. disk-full on the back-fill UPDATE), `user_version` stays at the prior level and the next daemon restart re-runs the migration — but `ALTER TABLE ADD COLUMN` is non-idempotent in SQLite, so the retry errors with "duplicate column name" and refuses startup. | Integration + security explorers. Fix: wrap each `if current < N` block in `unchecked_transaction()`. |
| F-2032-002 | referral | security (API auth surface) | PR #142 introduces `GET /notify/ack/:token` — the **first unauthenticated** API route selfdef ships. PR documents the "token IS the auth" model explicitly. Recompute the brute-force math; enumerate third-party-log-leak risk. | Security explorer (re-audit token-IS-auth model against SECURITY.md's four primary adversaries). |
| F-2032-003 | nice | docs (SDD-008 PR labels) | The 4 Q-G commit titles use `feat(sdd-008): Q-G — <service> integration`. SDD-008's `Q-G` is an open-question identifier (not a design point); casual readers might confuse "Q-G" for D-N-shaped naming. Extends Phase 6's F-2031-001 family of "PR-label disambiguation" concerns. | Docs explorer (verify SDD-008's "PR labels — appendix" covers the Q-G commits cleanly). |
| F-2032-004 | nice (closed) | crate (pagerduty) | PagerDuty's `from_config` duplicated the `Client::builder().timeout(10s)` block inline instead of routing through `Self::new` like the other 3 Q-G adapters do. Drift on a contract that's invisible until a future client-config change has to be applied twice. | **Closed by Phase 7 crate explorer** — `from_config` now returns `Self::new(routing_key, source).with_endpoint(endpoint)`. 12 existing tests still pass. |
| F-2032-005 | **important** (closed) | module (dispatcher_adapter + engine) | DispatcherAdapter mints a fresh UUIDv7 ack_token on every `notify()` call; engine's `enqueue` ON-CONFLICT-preserve clause keeps the OLD token. On re-submits of the same event_id, the channel fires with URL containing T2 but the engine has T1 → click → 404 silently. Operator-visible correctness defect on D-4 HTTP ack. | **Closed by Phase 7 module explorer** — new `EscalationEngine::lookup_or_mint_token` API; adapter calls it before constructing payload so the URL bytes match the engine's canonical state. 4 new tests pin the contract. |

## Status

- Module explorer landed; closes F-2032-005 in-place
  (important — D-4 HTTP ack token-stability bug). Inventory,
  recent-PRs, crate explorers shipped previously.
- Four explorers remain (ship in follow-up PRs):
  1. `50-integration-audit.md` — schema migrations on disk,
     ack_link_base round-trip, ApiState engine handle wiring.
  4. `60-docs-audit.md` — SDD-008 status table, STARTER_CONFIG
     5 new blocks, SECURITY.md row deltas.
  5. `70-tests-audit.md` — `EngineHarness` pattern, Q-G test
     count variance, schema-migration test coverage gap.
  6. `80-security-audit.md` — schema v2+v3 migration safety,
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
| **Phase 7** | **2 nice + 1 referral** | **1 nice (closed)** | **1 important (closed)** | *pending* | *pending* | *pending* | *pending* |

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
