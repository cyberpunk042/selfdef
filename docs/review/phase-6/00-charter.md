# Phase 6 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-15

## Why Phase 6 now

Phase 5's [findings ledger](../phase-5/99-findings-ledger.md)
closed out a few days ago — **0 findings across all 7
explorers**, the first totally-clean phase of the audit
programme. The convergence trajectory now reads:

| Phase | Findings | Blockers | Important | Nice (closed) | SDD-debt |
| --- | --- | --- | --- | --- | --- |
| Phase 2 | 64 | 0 | 3 (closed) | 60 (closed) | 1 (closed) |
| Phase 3 | 39 | 0 | 2 (closed) | 16 (15 closed) | 1 (closed) |
| Phase 4 | 9 | 0 | 0 | 5 (all closed) | 0 |
| Phase 5 | 0 | 0 | 0 | 0 | 0 |

Phase 5 happened to land on a quiet patch — the cycle it
audited was almost entirely documentation. **Phase 6 is the
opposite**: it audits the **22 PRs from the SDD-008
notifications-orchestration cycle** (`#109` SDD charter →
`#130` D-6c custom-profile TOML), which shipped:

- **9 new crates** (`selfdef-notifier-orchestrator`,
  `selfdef-notifier-engine`, and 7 channel integration crates).
- **A new persistence layer** (`notification_escalations`
  SQLite table, WAL, rung-monotonic advancement).
- **A new background task** (`wake_task` rung-advance loop).
- **A new CLI verb cluster** (`selfdefctl notify
  {ack,forget,list}`).
- **Operator-facing knobs across 4 new dimensions** — modes
  (enforce/audit), profiles (auto/aggressive/patient +
  TOML-defined custom), per-rung channel filters, panic floor.
- **Channel-credential surface** across 7 transports —
  ntfy, Signal-CLI, SMTP, Twilio, Slack, Discord, wall(1).

That is more new attack surface and operator-facing
configuration than Phases 2 through 5 combined. The
trajectory-prediction model that worked for Phase 5 (0 → 0)
explicitly **does not** carry forward; Phase 6 should be
sized like Phase 2 or 3.

## What changed during the SDD-008 cycle

The closure cycle ran 22 PRs (`#109`..`#130`) across roughly
two days of execution. Mapped to the SDD-008 design points:

| PR | Design point | Substance |
| --- | --- | --- |
| #109 | charter | SDD-008 doc — 9 design points D-1..D-9, 7 open questions Q-A..Q-G. |
| #110 | D-1 taxonomy | ARCHITECTURE.md integrations-layer section, `docs/dev/integrations.md` contributor template. |
| #111 | D-2a | `selfdef-notifier-orchestrator` trait crate — `Channel`, `Payload`, `PayloadId`, `EventId`, `DeliveryReceipt`, `ChannelError`, `AckReplyHint`. |
| #112 | D-2b | `selfdef-integration-ntfy` — HTTP push channel + daemon wire. |
| #113 | D-2c | `selfdef-integration-signal` — Signal-CLI JSON-RPC channel. |
| #114 | D-7 (prep) | `selfdef-integration-smtp` — lettre-based SMTP channel; `0BSD` added to `deny.toml` for `quoted_printable` transitive. |
| #115 | D-3 (wire) | SMTP wired into daemon notifier chain. |
| #116 | D-2 | `selfdef-integration-twilio` — Programmable-Messaging adapter (Basic-Auth, sandbox-aware). |
| #117 | D-3 | Per-channel subscription model — `severity_floor` + `event_kinds` filter in `NotifierConfig`. |
| #118 | D-5a | `selfdef-notifier-engine` — escalation persistence (SQLite WAL, rung-monotonic guards). |
| #119 | D-5b | `PayloadDispatcher` façade — engine + channel-set glue. |
| #120 | Q-C | `selfdef-integration-slack` — incoming-webhook adapter. |
| #121 | — | `selfdef-integration-discord` — webhook adapter. |
| #122 | D-5c | `wake_task` background loop — rung advancement, deadline-driven sleep. |
| #123 | D-4 | `selfdefctl notify {ack,forget,list}` CLI verbs. |
| #124 | D-5d | Daemon wiring — engine + dispatcher + wake task with cancellation token. |
| #125 | D-6a | Dispatcher operating modes — `Enforce` / `Audit` (dry-run). |
| #126 | D-6b | Named escalation profiles — `auto` / `aggressive` / `patient`. |
| #127 | D-7 | Panic floor — severity threshold that bypasses audit mode. |
| #128 | D-8 | `selfdef-integration-wall` — wall(1) session-attention channel. |
| #129 | D-6c | Per-rung channel filtering + operator-defined custom profiles. |
| #130 | D-6c (TOML) | TOML schema for custom profiles — `[notifier.profiles.<name>.rungs]`. |

**SDD-008 design points D-1 through D-8 all shipped.** D-9
(dashboard) is explicitly deferred — the operator owns that
spec in a separate design conversation. D-4's HTTP
`/notify/ack/<token>` complement remains an open follow-up
(the column exists but is `None` today).

## Scope of this Phase

Same shape as Phases 1–5 — seven explorers:

| Explorer | Scope for Phase 6 |
| --- | --- |
| Crate audit | 9 new crates. `selfdef-notifier-orchestrator` trait shape (forward-compat, async-trait, Send-bound, error taxonomy); `selfdef-notifier-engine` SQLite schema + WAL contract + rung-monotonic guards + clock dependencies; 7 channel integrations' `from_config` validation + secret-elision Debug impls + outbound-HTTP error mapping. |
| Module audit | Dispatcher path (`PayloadDispatcher::submit` → engine persist → channels fire) plus the daemon wiring (`build_notifier_path` branch on `escalations_path`). `DispatcherAdapter` Event→Payload bridging. |
| Integration audit | Daemon startup wiring for the new optional escalations path; config round-trip for the 4 new operator dimensions (mode / profile / panic-floor / per-channel subscriptions); wake-task lifecycle with `CancellationToken`. |
| Docs audit | SDD-008 doc itself; ARCHITECTURE.md integrations-layer section; `docs/dev/integrations.md` template; SECURITY.md additions for credential storage + wall(1) TTY broadcast; init.rs `STARTER_CONFIG` knob comments. |
| Tests audit | Engine SQLite tests (open, enqueue, advance_rung, take_due, monotonic guard, ack races); dispatcher tests (panic-floor bypass, mode behaviour, per-rung filter empty=WUPHF); wake-task tests; channel `from_config` validation tests; profile builtin tests. Pin missing seams. |
| Recent-PRs audit | 22 SDD-008 PRs. Verify each one's claimed scope matches its diff; look for "while I'm in there" creep, dead code, behind-the-back refactors, missed clippy follow-ups (we shipped two fmt/clippy fix-up commits during the cycle — flag any others). |
| Security audit | Credential storage paths for all 7 channels; `wall(1)` TTY broadcast as a session-attention covert-channel vector; SQLite injection surface (parameter binding); rung-advance race against operator-ack; secret-elision Debug shapes; outbound-HTTP TLS posture (reqwest defaults); 0BSD-license addition to `deny.toml`. |

## Out of scope (defer to Phase 7 or later)

- D-9 dashboard (no SDD yet, separate conversation).
- HTTP `/notify/ack/<token>` endpoint (open follow-up; the
  surface doesn't exist yet so there's nothing to audit).
- Future integrations not yet shipped (OpenSearch, Loki,
  PagerDuty, TheHive — Q-G adapter ideas).
- Cross-host fleet behaviour, real-cluster k8s integration,
  performance benchmarks.
- Phase 1–5 findings already closed.

## Methodology

Same as prior Phases:

1. Each explorer surveys their area; lists every concrete
   observation.
2. Triage: blocker / important / nice / SDD-debt / demoted.
3. Each observation becomes an `F-2031-NNN` entry in the
   Phase 6 findings ledger.
4. SDD-debt findings spawn SDDs under `docs/sdd/` (next free
   number is 009).

## Predicted outcome

The convergence trajectory says **don't predict**. Phase 5's
0-findings result was the audit of a documentation-heavy
cycle; Phase 6 audits a 9-crate, 22-PR, 4-operator-dimension
**new feature stack** with persistent storage, background
tasks, and outbound credentials. Realistic expectation: **5–20
findings**, most of them in the "nice" tier (typing
ergonomics, doc-comment coverage, missing test seams), with
0–2 important findings on the credential-handling or
rung-advance-race surface.

If Phase 6 surfaces an SDD-debt finding, it most likely lands
on:

- **rung-advance race** with operator-ack (already partly
  addressed by the `acked_at IS NULL AND rung_index < new_rung`
  guard, but the surrounding state machine could still benefit
  from explicit documentation).
- **channel credential rotation** (no rotation contract today;
  config-reload-on-SIGHUP is unspecified).
- **D-4 HTTP ack endpoint** (open follow-up; could go from
  "future work" to "SDD-009 ack-link" if the auditor finds the
  asymmetry actionable).

## Status

This PR opens Phase 6 with:

- the charter (this file)
- the Phase 6 findings ledger template

The inventory + seven explorers will follow in subsequent
PRs (same cadence as Phases 4 and 5).

Phase 6 closes when every important / blocker has either a
"closed by <PR>" back-reference or a tracked SDD.

## Naming

Phase 1 = `F-2026-NNN`, Phase 2 = `F-2027-NNN`, Phase 3 =
`F-2028-NNN`, Phase 4 = `F-2029-NNN`, Phase 5 = `F-2030-NNN`,
Phase 6 = **`F-2031-NNN`**.
