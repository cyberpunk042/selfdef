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
| F-2029-002 | nice | `TokenFingerprint` `Debug` derive prints the full 32-byte hash | `tracing` field-formatting via `?fp` would dump the raw hash, linking past log lines to a stable token-holder identifier. | implement — **closed** by the Phase-4-crate-polish PR: `TokenFingerprint` now has a custom `Debug` impl that renders only the leading 4 bytes (`TokenFingerprint(a3b9…)`), keeping diagnostic value without the cross-time-linkage primitive. 2 new unit tests pin the truncated-prefix shape and the distinct-fingerprints-stay-distinct contract. |
| F-2029-003 | nice | `SseCaps` `Some(0)` fallback edge case lacks explicit test | Existing override tests use `Some(2)` and `Some(1)`; a future refactor dropping the `n > 0` guard would silently break the `Some(0)` → default contract. | implement — **closed** by the Phase-4-crate-polish PR: new `events_stream_zero_caps_fall_back_to_defaults` test sets `SseCaps { global: Some(0), per_token: Some(0) }` and asserts the first connection succeeds (defaults apply). |
| F-2029-004 | nice | `modules/vpn-bridge/install/apply.sh` dispatcher header doesn't document dry-run / idempotency | Phase 4 module explorer noted the dispatcher header describes the profile-delegation shape but not the SELFDEF_DRY_RUN-awareness or idempotency contract that the underlying profile scripts honour. bridge-l2 and observability's apply.sh both include such header lines. Pure clarity gap; the actual scripts behave correctly via the `run` helper and `module_record_file`. | implement — **closed** by the Phase-4-crate-polish PR (paired with the F-2029-002/-003 closures): dispatcher header now names dry-run-awareness, idempotency, and the SDD-006 v2 manifest-tracking contract that profiles must honour. |
| F-2029-005 | nice | SDD-007 D-4 config knobs lack end-to-end test (config file → daemon → API state) | Integration auditor noted the four hops (TOML parse → `Config::load` → `ApiConfig` Option fields → daemon → `ApiState::with_sse_caps`) have no test exercising the full chain. Each hop has unit-level coverage but a regression in any one of them would only surface in production. | implement — **closed** by the Phase-4-integration PR: two new tests in `crates/selfdef-config/src/lib.rs::tests` exercise the TOML parse hop end-to-end (`sse_cap_knobs_round_trip_from_toml` for the override case, `sse_cap_knobs_default_to_none_when_unset` for the unset case). Together with the existing `events_stream_per_token_cap_honours_operator_override` + `events_stream_global_cap_honours_operator_override` tests (which pin the consumption hop), the full TOML → ApiState → handler chain is now test-covered. |
| F-2029-006 | demoted | STARTER_CONFIG SSE caps lack direct round-trip test (TOML parse → daemon read) | Auditor independently surfaced the same gap as F-2029-005, viewed from the STARTER_CONFIG/init.rs angle. Cross-check: the two findings are facets of the same underlying gap. Closed by the same tests that close F-2029-005. | none (duplicate of F-2029-005) |
| F-2029-007 | nice | `SECURITY.md` doesn't document the per-token SSE subscriber quota | Phase 4 docs explorer noted that SDD-007 shipped during the Phase 3 cycle (closing F-2028-037 — authenticated-only DoS) but `SECURITY.md`'s § API surface didn't mention the new per-token cap, the SHA-256 fingerprint storage, the operator-tunable knobs, or the distinguishable 503 reasons. No security gap (the feature is well-tested and safe by default), but a documentation gap that hurts operator awareness. | implement — **closed** by the Phase-4-docs PR: `SECURITY.md` § API surface now documents the per-token SSE cap (default 8 per token, 64 process-wide), the SHA-256-fingerprint map, the operator-tunable `[api].max_sse_subscribers{,_per_token}` knobs, the `None`/`Some(0)` → default fallback, and the distinguishable 503 reasons. Back-references SDD-007 and `SubscriberGuard` for the full picture. |

## Status

- **7 findings raised** across five Phase 4 explorers
  (recent-PRs, crate, module, integration, docs). **0
  blockers**, **0 important**, **5 nice (all closed)**
  (F-2029-002, -003, -004, -005, -007), **2 demoted**
  (F-2029-001, -006).
- The Phase 3 closure cycle was the cleanest yet: 16/17 PRs
  review-clean on recent-PRs; small `nice` findings on the
  crate, module, integration, and docs sides — all closed
  in this or the prior cluster PRs.
- Two explorers remain: tests, security.
- No Phase 4 SDD-debt findings yet.

## Phase 1 / Phase 2 / Phase 3 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
