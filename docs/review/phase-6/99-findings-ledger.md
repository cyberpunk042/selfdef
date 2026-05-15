# Phase 6 — findings ledger

> Status: **open** — inventory + recent-PRs + crate explorers landed; 4 explorers pending.
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

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2031-001 | nice | docs (SDD-008) | PR #114's commit title labels the SMTP integration crate as `D-7` even though SDD-008's D-7 is the panic floor (which shipped under PR #127 with the correct label). Pre-history label collision. | Phase 6 docs explorer to decide on SDD-008 "PR labels" appendix. |
| F-2031-002 | nice (closed) | crate (ntfy + signal) | Ntfy (4 tests) and Signal (3 tests) integration crates lack the wiremock / subprocess-exec end-to-end coverage that the later channel crates adopted (twilio, slack, discord, wall: 12–16 tests each). Coverage parity gap. | **Closed by Phase 6 crate explorer** — both crates raised to 7+ tests (ntfy at 9, signal at 7) with wiremock + coreutils stand-ins exercising the `post()` / subprocess paths. |
| F-2031-003 | nice | supply-chain (deny.toml) | `0BSD` was added to `deny.toml`'s `licenses.allow` to permit `quoted_printable` 0.5.2 (transitive via `lettre`). Documented in-line, but should be re-audited end-to-end. | Phase 6 security explorer. |
| F-2031-004 | demoted | tooling (rustfmt) | PR #127 needed a `chore(fmt)` fix-up commit (`3b80a85`) to satisfy CI's rustfmt 1.88.0 chain-collapse on the panic-floor parsing path. Local rustfmt produced different output. Single observed incident; CI caught it before merge. | None — re-flag if a second occurrence appears in a future cycle. |
| F-2031-005 | nice (closed) | crate (ntfy) | `NtfyNotifier` derived `Debug`, which would render the bearer token verbatim in any `tracing` log. Out of step with the secret-elision posture of slack/discord/twilio/smtp. | **Closed by Phase 6 crate explorer** — custom `Debug` impl elides token to `<redacted>`; 2 tests pin elision shape. |
| F-2031-006 | **important** (closed) | crate (wall) | `selfdef-integration-wall::broadcast()` failed eagerly on EPIPE when the child exited before reading stdin. Manifested as a flaky CI failure on `ubuntu-latest`; also a latent production defect for wall(1) on TTY-less hosts. | **Closed by Phase 6 crate explorer** — tolerate `BrokenPipe` on both `write_all` and `shutdown`, fall through to wait-on-exit. Stress-tested 15× green. |

## Status

- Charter (PR #131) landed.
- This PR ships `10-inventory.md` + `20-recent-prs-audit.md` —
  the inventory of the 9 new crates / 22 PRs / 159 new tests
  / 13 new TOML surface elements, and the PR-by-PR audit
  raising 3 nice findings + 1 demoted observation.
- This PR ships `30-crate-audit.md` plus closes F-2031-002
  and F-2031-005 in-place.
- Four explorers remain (ship in follow-up PRs):
  1. `40-module-audit.md` — dispatcher path + daemon wiring +
     event-to-payload bridge.
  2. `50-integration-audit.md` — startup wiring, config round-trip,
     wake-task lifecycle.
  3. `60-docs-audit.md` — SDD-008, ARCHITECTURE.md, integrations
     contributor doc, SECURITY.md additions, init.rs starter
     config.
  4. `70-tests-audit.md` — engine + dispatcher + wake-task +
     channel-validation + profile tests.
  5. `80-security-audit.md` — credentials, TTY broadcast, SQLite
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
| **Phase 6** | **3 nice + 1 demoted** | **1 important + 2 nice (all closed)** | *pending* | *pending* | *pending* | *pending* | *pending* |

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
