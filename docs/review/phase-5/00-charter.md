# Phase 5 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-14

## Why Phase 5 now

Phase 4's [findings ledger](../phase-4/99-findings-ledger.md)
closed out in this session: 9 findings across all seven
explorers (0 blockers, 0 important, 5 nice — all closed,
4 demoted, 0 SDD-debt). The closure-cycle audit trajectory has
been converging:

| Phase | Findings | Blockers | Important | Nice (closed) | SDD-debt |
| --- | --- | --- | --- | --- | --- |
| Phase 2 | 64 | 0 | 3 (closed) | 60 (closed) | 1 (closed) |
| Phase 3 | 39 | 0 | 2 (closed) | 16 (15 closed) | 1 (closed) |
| Phase 4 | 9 | 0 | 0 | 5 (all closed) | 0 |

Phase 5 audits the **8 PRs from the Phase 4 closure cycle**
(`22ff461 docs: Phase 4 audit kickoff scaffold` through
`d239dad docs: Phase 4 security explorer`). The surface is
thin — most Phase 4 PRs were doc-only audits; the three
code-bearing PRs (Phase 4 crate+module cluster, integration
explorer config round-trip tests, docs explorer SECURITY.md
entry) shipped small, well-scoped changes.

Same methodology as Phases 1, 2, 3, 4 (seven explorers,
F-NNNN findings, SDDs where the fix is design-shaped),
different vintage prefix: **F-2030-NNN** so the five ledgers
never collide.

## What changed during the Phase 4 cycle

New SECURITY.md entry:

- **§ API surface** documents the SDD-007 per-token SSE
  subscriber quota (default 8 per token, 64 process-wide),
  the SHA-256-fingerprint storage, the operator-tunable
  `[api].max_sse_subscribers{,_per_token}` knobs, the
  `None`/`Some(0)` → default fallback, and the
  distinguishable 503 reasons. Closes F-2029-007.

Modified Rust code (all `selfdef-api`):

- **`TokenFingerprint`** — derived `Debug` removed; custom
  impl renders only the 4-byte leading hex prefix
  (`TokenFingerprint(a3b9c012…)`). Closes F-2029-002.
- **2 new unit tests** in `crates/selfdef-api/src/transport.rs::fingerprint_tests`
  pin the truncated-prefix shape + distinct-prefix-for-
  distinct-tokens contract.

Modified module-side machinery:

- **`modules/vpn-bridge/install/apply.sh`** — dispatcher
  header now documents dry-run-awareness + idempotency +
  SDD-006 v2 manifest-tracking contract (one-line
  doc-comment addition). Closes F-2029-004.

New `selfdef-config` round-trip tests:

- **`sse_cap_knobs_round_trip_from_toml`** — TOML override
  case: `[api].max_sse_subscribers = 16`,
  `max_sse_subscribers_per_token = 4` → `Some(16)` + `Some(4)`
  in `ApiConfig`.
- **`sse_cap_knobs_default_to_none_when_unset`** — pins the
  unset-defaults-to-None contract so a future
  `#[serde(default)]` regression yielding `Some(0)` is caught
  at parse time.
- Closes F-2029-005 + F-2029-006.

New `selfdef-api` SSE quota tests:

- **`events_stream_zero_caps_fall_back_to_defaults`** — sets
  `SseCaps { global: Some(0), per_token: Some(0) }` and
  asserts the first connection succeeds. A future refactor
  dropping the `n > 0` guard would saturate immediately and
  fail this test. Closes F-2029-003.

New docs under `docs/review/phase-4/`:

- `00-charter.md`, `10-inventory.md`, `20-recent-prs-audit.md`,
  `30-crate-audit.md`, `40-module-audit.md`, `50-integration-audit.md`,
  `60-docs-audit.md`, `70-tests-audit.md`, `80-security-audit.md`,
  `99-findings-ledger.md` — the seven Phase 4 explorer docs +
  charter + inventory + ledger.

## Scope of this Phase

Same shape as Phases 1, 2, 3, 4 — seven explorers:

| Explorer | Scope for Phase 5 |
| --- | --- |
| Crate audit | The custom `Debug` impl on `TokenFingerprint`; the 2 new fingerprint unit tests + 1 zero-cap test. |
| Module audit | The vpn-bridge `apply.sh` dispatcher doc-comment + verification that v2 migration coverage hasn't regressed. |
| Integration audit | The TOML round-trip tests' interaction with the daemon startup wiring (already heavily covered in Phase 4; expect a re-audit verifying it holds). |
| Docs audit | SECURITY.md per-token SSE cap entry; the seven Phase 4 audit docs themselves; CHANGELOG entries for the 8 closure PRs. |
| Tests audit | The 3 new tests in `selfdef-config` + `selfdef-api` (zero-cap, round-trip, default-to-None). |
| Recent-PRs audit | The 8 Phase 4 closure PRs. Trajectory suggests very few findings. |
| Security audit | New attack surface (none, really — the closure cycle was almost entirely documentation). Re-audit prior closures: F-2029-002 (TokenFingerprint Debug truncation) + F-2029-005/-006 (round-trip tests don't introduce new exposure). |

## Out of scope (defer to Phase 6)

- Cross-host fleet behaviour.
- Performance benchmarks.
- Real-cluster k8s integration.
- Phase 1 / 2 / 3 / 4 findings already closed — Phase 5
  doesn't re-litigate.

## Methodology

Same as prior Phases:

1. Each explorer surveys their area; lists every concrete
   observation.
2. Triage: blocker / important / nice / SDD-debt / demoted.
3. Each observation becomes an `F-2030-NNN` entry in the
   Phase 5 findings ledger.
4. SDD-debt findings spawn SDDs under `docs/sdd/` (next free
   number is 008).

## Predicted outcome

The convergence trajectory (64 → 39 → 9 findings) suggests
Phase 5 may surface **0–3 findings total**. The audit-trail
value of "I checked, nothing actionable" is real — confirming
the closure-cycle stability has reached a steady state.

If Phase 5 produces 0 findings, that's a milestone worth
calling out in the wrap entry.

## Status

This PR opens Phase 5 with:
- the charter (this file)
- a structured inventory of what was added during the
  Phase 4 cycle
- one explorer's first-pass output (recent-PRs audit)
- the Phase 5 ledger with the initial findings

The remaining explorers will run in follow-up PRs. Phase 5
closes when every important / blocker has either a
"closed by <PR>" back-reference or a tracked SDD — which,
given the trajectory, likely means "as soon as the seventh
explorer's PR lands".

## Naming

Phase 1 = `F-2026-NNN`, Phase 2 = `F-2027-NNN`, Phase 3 =
`F-2028-NNN`, Phase 4 = `F-2029-NNN`, Phase 5 = **`F-2030-NNN`**.
