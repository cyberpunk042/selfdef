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
| F-2029-002 | nice | `TokenFingerprint` `Debug` derive prints the full 32-byte hash | `crates/selfdef-api/src/transport.rs` derives `Debug` for `TokenFingerprint(pub [u8; 32])`. `tracing` field-formatting via `?token_fingerprint` would dump the raw bytes into the log, linking every log line carrying it to a stable identifier of the token holder. Fingerprints aren't secrets but they ARE persistent identifiers — an attacker who later acquires the token can recompute the fingerprint and link past log lines to the holder. Custom `Debug` impl that prints a truncated hex prefix (e.g. `TokenFingerprint(a3b9…)`) keeps the diagnostic value without the linkage. | implement |
| F-2029-003 | nice | `SseCaps` `Some(0)` fallback edge case lacks explicit test | `crates/selfdef-api/src/handlers.rs::SubscriberGuard::try_acquire` treats `Some(0)` the same as `None` (both fall back to the compiled-in default), per the SDD-007 D-4 doc-comment intent. The behaviour is correct but the existing override tests use `Some(2)` and `Some(1)` — neither exercises the `Some(0)` path. A future refactor that drops the `n > 0` guard would silently break the contract. Add a defensive test that sets `SseCaps { global: Some(0), per_token: Some(0) }` and asserts the defaults apply. | implement |

## Status

- **3 findings raised** across two Phase 4 explorers (recent-PRs
  and crate). **0 blockers**, **0 important**, **2 nice**
  (F-2029-002 TokenFingerprint Debug, F-2029-003 SseCaps zero-
  cap test gap), **1 demoted** (F-2029-001).
- The Phase 3 closure cycle was the cleanest yet: 16/17 PRs
  review-clean (94%) on the recent-PRs side; 2 small `nice`
  findings on the crate side (no blockers or important).
- Five explorers remain: module, integration, docs, tests,
  security.
- No Phase 4 SDD-debt findings yet.

## Phase 1 / Phase 2 / Phase 3 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
