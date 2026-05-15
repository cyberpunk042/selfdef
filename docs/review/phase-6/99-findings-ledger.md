# Phase 6 — findings ledger

> Status: **open** — 6 explorers landed (inventory, recent-PRs, crate, module, integration, docs); 2 pending.
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
| F-2031-001 | nice (closed) | docs (SDD-008) | PR #114's commit title labels the SMTP integration crate as `D-7` even though SDD-008's D-7 is the panic floor (which shipped under PR #127 with the correct label). Pre-history label collision. | **Closed by Phase 6 docs explorer** — SDD-008 gains a "PR labels — appendix" disambiguating exhaustively, plus an "Implementation status" table mapping each D → PR. |
| F-2031-002 | nice (closed) | crate (ntfy + signal) | Ntfy (4 tests) and Signal (3 tests) integration crates lack the wiremock / subprocess-exec end-to-end coverage that the later channel crates adopted (twilio, slack, discord, wall: 12–16 tests each). Coverage parity gap. | **Closed by Phase 6 crate explorer** — both crates raised to 7+ tests (ntfy at 9, signal at 7) with wiremock + coreutils stand-ins exercising the `post()` / subprocess paths. |
| F-2031-003 | nice | supply-chain (deny.toml) | `0BSD` was added to `deny.toml`'s `licenses.allow` to permit `quoted_printable` 0.5.2 (transitive via `lettre`). Documented in-line, but should be re-audited end-to-end. | Phase 6 security explorer. |
| F-2031-004 | demoted | tooling (rustfmt) | PR #127 needed a `chore(fmt)` fix-up commit (`3b80a85`) to satisfy CI's rustfmt 1.88.0 chain-collapse on the panic-floor parsing path. Local rustfmt produced different output. Single observed incident; CI caught it before merge. | None — re-flag if a second occurrence appears in a future cycle. |
| F-2031-005 | nice (closed) | crate (ntfy) | `NtfyNotifier` derived `Debug`, which would render the bearer token verbatim in any `tracing` log. Out of step with the secret-elision posture of slack/discord/twilio/smtp. | **Closed by Phase 6 crate explorer** — custom `Debug` impl elides token to `<redacted>`; 2 tests pin elision shape. |
| F-2031-006 | **important** (closed) | crate (wall) | `selfdef-integration-wall::broadcast()` failed eagerly on EPIPE when the child exited before reading stdin. Manifested as a flaky CI failure on `ubuntu-latest`; also a latent production defect for wall(1) on TTY-less hosts. | **Closed by Phase 6 crate explorer** — tolerate `BrokenPipe` on both `write_all` and `shutdown`, fall through to wait-on-exit. Stress-tested 15× green. |
| F-2031-007 | **important** (closed) | module (dispatcher-adapter) | `DispatcherAdapter` set the initial deadline via the legacy `DEFAULT_RUNG_INTERVAL_SECS = 300` hardcoded constant instead of `profile.ack_window_for(0)`. Operators selecting `aggressive` (rung 0 = 60s) saw the first rung-advance fire 5 min later instead of 60s — exact opposite of the profile's stated purpose. | **Closed by Phase 6 module explorer** — adapter now reads `self.dispatcher.profile().ack_window_for(0)`; test pins the new contract. |
| F-2031-008 | nice (closed) | module (wake_task) | `wake_task::run` doc-comment referenced the legacy `MAX_RUNG` constant, `dispatch_payload` (no-rung-filter), and `RUNG_INTERVAL` — all replaced by `profile.max_rung()`, `dispatch_payload_for_rung`, and `profile.ack_window_for`. Doc-vs-code drift. | **Closed by Phase 6 module explorer** — doc-comment rewritten to match D-6b/D-6c shipping shape. |
| F-2031-009 | **important** (SDD-debt, stopgap shipped) | module (dispatcher path) | Per-channel subscription filter (D-3: `[notifier.subscriptions.<channel>]`) silently stops being applied when the operator switches to the engine path (`escalations_path` set). `build_channel_set` strips subscription metadata; `fire_channels_filtered` walks every configured channel regardless. Silent broadening of channel firing on the operator's principal noise-reduction lever. | **Stopgap shipped by Phase 6 integration explorer** — startup warn fires when `[notifier.subscriptions]` is non-empty on engine path. Principled fix defers to SDD-008 D-5e follow-up PR. |
| F-2031-010 | nice (closed) | integration (config parse) | `parse_dispatcher_profile` silently mapped any non-positive `ack_window_secs` in a custom profile rung to 300 — operator typos like `ack_window_secs = 0` or `-60` produced 5-minute waits with no indication anything was wrong. | **Closed by Phase 6 integration explorer** — invalid values now log a structured `warn!` naming the profile, rung index, configured value, and fallback. |
| F-2031-011 | nice (closed) | docs (SDD-008) | SDD-008's "Implementation status" said "Charter only. No implementation has shipped." (stale — D-1..D-8 all shipped). Two open-question working assumptions (Q-C "deferred channels", Q-G `[notifications]` namespace) were revised by reality during implementation, not just confirmed; the doc kept them as live questions. | **Closed by Phase 6 docs explorer** — Implementation-status table with per-D shipping PRs; each open question annotated `→ confirmed` / `→ revised on implementation` with the shipped behaviour. |
| F-2031-012 | nice (closed) | docs (init.rs STARTER_CONFIG) | STARTER_CONFIG documents per-channel subscription filters in detail but never mentions F-2031-009 — operators following the starter config faithfully would set both `escalations_path` and `[notifier.subscriptions.*]` and silently get every event on every channel. The daemon-side stopgap warning (PR #135) catches this at runtime; the operator should learn about the gap at config-write time. Also: D-6c past-tense "lands in follow-up Ds" was stale (D-6c has shipped). | **Closed by Phase 6 docs explorer** — subscription block carries the F-2031-009 caveat inline; D-6c reference fixed to present tense. |

## Status

- Charter (PR #131) landed.
- This PR ships `10-inventory.md` + `20-recent-prs-audit.md` —
  the inventory of the 9 new crates / 22 PRs / 159 new tests
  / 13 new TOML surface elements, and the PR-by-PR audit
  raising 3 nice findings + 1 demoted observation.
- Docs explorer landed (this PR ships `60-docs-audit.md`),
  closes F-2031-001 + F-2031-011 + F-2031-012 in-place.
  SDD-008 now reflects shipped state with an
  Implementation-status table and PR-labels appendix;
  init.rs STARTER_CONFIG carries the F-2031-009 operator-
  discovery caveat at config-write time (paired with the
  daemon-side warn shipped in PR #135).
- Two explorers remain (ship in follow-up PRs):
  1. `70-tests-audit.md` — engine + dispatcher + wake-task +
     channel-validation + profile tests; SDD-005 pipeline-
     determinism compliance.
  2. `80-security-audit.md` — credentials, TTY broadcast,
     SQLite injection surface, rung-advance race, TLS
     posture; address F-2031-003 (0BSD allow-list re-audit).
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
| **Phase 6** | **2 nice (closed) + 1 nice + 1 demoted** | **1 important + 2 nice (all closed)** | **2 important + 1 nice (closed) + 1 important (SDD-debt stopgap)** | **1 nice (closed) + stopgap landed** | **3 nice (closed)** | *pending* | *pending* |

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
