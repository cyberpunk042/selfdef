# Phase 7 — findings ledger

> Status: **wrapped** — all 7 explorers complete, 6 findings raised, 6 closed in-place (incl. 1 referral-via-docs), 0 open, 0 demoted, 0 SDD-debt.
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
| F-2032-001 | nice (closed) | engine (schema v2 + v3 migration) | The v2 and v3 migration blocks in `EscalationEngine::migrate` ran `ALTER TABLE` + back-fill (v3 only) + index + `user_version` bump as separate statements outside a transaction. If a step failed mid-block (e.g. disk-full), `user_version` stayed at the prior level but the column was already added → next restart hit `ALTER TABLE ADD COLUMN`'s non-idempotency and refused startup. | **Closed by Phase 7 integration explorer** — each `if current < N` block now wrapped in `unchecked_transaction()`; same shape `record_ack_by_token` uses. 2 new tests pin migration idempotency. |
| F-2032-002 | referral (closed) | security (API auth surface) | PR #142 introduces `GET /notify/ack/:token` — the **first unauthenticated** API route selfdef ships. PR documents the "token IS the auth" model explicitly. Recompute the brute-force math; enumerate third-party-log-leak risk. | **Closed by Phase 7 security explorer** — brute-force math confirms UUIDv7 ~74 bits post-timestamp entropy is well above online-brute-force threshold (~893 years at 10K req/s). Realistic surface is third-party-log leakage via 5 human-facing channels (smtp/slack/discord/twilio/wall include the URL; the 4 Q-G adapters don't). SECURITY.md addendum documents the per-channel inclusion map + mitigation recommendations. |
| F-2032-003 | nice (closed) | docs (SDD-008 PR labels) | The 4 Q-G commit titles use `feat(sdd-008): Q-G — <service> integration`. SDD-008's `Q-G` is an open-question identifier (not a design point); casual readers might confuse "Q-G" for D-N-shaped naming. Extends Phase 6's F-2031-001 family of "PR-label disambiguation" concerns. | **Closed by Phase 7 docs explorer** — SDD-008 PR-labels appendix extended with a "Post-Phase-6 cycle commits" section covering PRs #140-#146 + a shorthand convention (`D-N` / `Q-X` / no prefix). Impl-status table normalized with actual PR numbers. |
| F-2032-004 | nice (closed) | crate (pagerduty) | PagerDuty's `from_config` duplicated the `Client::builder().timeout(10s)` block inline instead of routing through `Self::new` like the other 3 Q-G adapters do. Drift on a contract that's invisible until a future client-config change has to be applied twice. | **Closed by Phase 7 crate explorer** — `from_config` now returns `Self::new(routing_key, source).with_endpoint(endpoint)`. 12 existing tests still pass. |
| F-2032-005 | **important** (closed) | module (dispatcher_adapter + engine) | DispatcherAdapter mints a fresh UUIDv7 ack_token on every `notify()` call; engine's `enqueue` ON-CONFLICT-preserve clause keeps the OLD token. On re-submits of the same event_id, the channel fires with URL containing T2 but the engine has T1 → click → 404 silently. Operator-visible correctness defect on D-4 HTTP ack. | **Closed by Phase 7 module explorer** — new `EscalationEngine::lookup_or_mint_token` API; adapter calls it before constructing payload so the URL bytes match the engine's canonical state. 4 new tests pin the contract. |
| F-2032-006 | nice (closed) | tests (engine migration upgrades) | The existing migration tests (`migration_idempotent_when_re_opening_at_current_version`, `migration_handles_existing_rows_during_v3_backfill`, `open_creates_empty_engine`) all start from a **fresh DB**. The v0 → v1 → v2 → v3 sequence runs on every fresh test, but no test exercises the operator-side upgrade scenario: a v1 or v2 schema on disk getting upgraded to v3 across an entire daemon-version bump. F-2032-001's transactional-wrap fix's correctness on upgrade paths was reasoning-pinned, not test-pinned. | **Closed by Phase 7 tests explorer** — 2 new tests hand-write v1- and v2-shaped DBs (raw SQL + manual `user_version`) + insert pre-existing rows, then re-open the engine and verify v2 + v3 migrations run cleanly + back-fill rows with 32-char hex tokens. |

## Status

**WRAPPED.** The Phase 7 closure-cycle audit programme has
completed all seven explorers over the post-Phase-6 cycle
(7 PRs `#140`..`#146` shipping D-5e + SDD-005 impl-PR + D-4
HTTP ack + the 4 Q-G adapter pattern-instances).

### Closure summary

- **6 findings raised** (F-2032-001 through F-2032-006).
- **6 closed**, all in-place during the audit cycle:
  - F-2032-001 (schema v2 + v3 migration transactional wrap)
  - F-2032-002 (token-IS-auth audit + SECURITY.md addendum)
  - F-2032-003 (SDD-008 PR-labels appendix extension)
  - F-2032-004 (PagerDuty client-builder uniformity)
  - F-2032-005 (D-4 ack-token resubmit-stability) — **important**
  - F-2032-006 (schema-migration upgrade-path test coverage)
- **0 open**, **0 demoted**, **0 SDD-debt**.

### The important finding — Phase 7's catch

**F-2032-005**: DispatcherAdapter minted a fresh UUIDv7
ack_token on every `notify()`; engine's ON-CONFLICT-preserve
clause kept the OLD token; on re-submits of the same
event_id, the channel fired with a URL containing T2 while
the engine had T1 — clicking the URL returned 404 silently.
Operator-visible D-4 correctness defect.

**Closed**: new `EscalationEngine::lookup_or_mint_token`
API; adapter calls it before constructing the Payload so
the channel URL matches the engine's canonical state. 4 new
tests pin the contract.

### Cumulative trajectory (Phases 2–7)

| Phase | Cycle audited | Findings | Important | Closed | SDD-debt | Demoted |
| --- | --- | --- | --- | --- | --- | --- |
| Phase 2 | Phase 1 closure cycle | 64 | 3 | 60 | 1 | — |
| Phase 3 | Phase 2 closure cycle | 39 | 2 | 16 | 1 | — |
| Phase 4 | Phase 3 closure cycle | 9 | 0 | 5 | 0 | 0 |
| Phase 5 | Phase 4 closure cycle | 0 | 0 | 0 | 0 | 0 |
| Phase 6 | SDD-008 cycle (22 PRs / 9 crates) | 16 | 3 | 14 | 2 (both closed) | 2 |
| **Phase 7** | **post-Phase-6 cycle (7 PRs / 4 crates)** | **6** | **1** | **6** | **0** | **0** |

Phase 7's all-in-place closure rate (6/6) reflects the
smaller, denser surface vs. Phase 6: 7 PRs (4 pattern-
instance Q-G crates + 2 substantial seam changes + 1 test
implementation PR) where most of the audit work was
verification-shaped rather than discovery-shaped.

### Open SDD-debt (none — none carried forward)

Phase 6 had two open SDD-debt items at wrap (F-2031-009
D-5e subscription wiring, F-2031-013 SDD-005 daemon-pipeline
tests). Both closed via PRs #140 and #141 during the
post-Phase-6 cycle — which is precisely the cycle Phase 7
audited.

**Phase 7 closes with 0 open SDD-debt.** Future phases pick
up new code when it lands.

## Trajectory snapshot

For context — full closure-cycle convergence to date:

| Cycle | recent-PRs | crate | module | integration | docs | tests | security |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phase 2 | many | 11 nice | 6 nice | 9 mixed | 9 nice | 11 mixed | 5 mixed |
| Phase 3 | 4 nice | 10 mixed | 1 important | 4 nice | 5 mixed | 5 mixed | 3 nice |
| Phase 4 | 1 demoted | 2 nice | 1 nice | 2 nice | 1 nice | 1 demoted | 1 demoted |
| Phase 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Phase 6 | 3 nice + 1 demoted | 1 important + 2 nice | 2 important + 1 nice + 1 SDD-debt | 1 nice + stopgap | 3 nice | 1 SDD-debt + 1 demoted | 1 important + 2 nice |
| **Phase 7** | **2 nice + 1 referral (3 closed)** | **1 nice (closed)** | **1 important (closed)** | **1 nice (closed)** | **1 nice (closed)** | **1 nice (closed)** | **referral closed** |

Phase 6 audited a 22-PR / 9-new-crate feature cycle and
caught 3 important production-relevant defects; Phase 7
audited a 7-PR / 4-new-crate **pattern-instance + 2-seam**
cycle and caught 1 important defect (F-2032-005, D-4
token-stability). The smaller surface produced a tighter
finding distribution: 6 findings total, all in-place
closure, no SDD-debt, no demotions. Outcome matches the
Phase 7 charter's prediction (3-8 findings, mostly nice,
0-2 important).

## Phase 1 / 2 / 3 / 4 / 5 / 6 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
- Phase 5: [`../phase-5/99-findings-ledger.md`](../phase-5/99-findings-ledger.md)
- Phase 6: [`../phase-6/99-findings-ledger.md`](../phase-6/99-findings-ledger.md)
