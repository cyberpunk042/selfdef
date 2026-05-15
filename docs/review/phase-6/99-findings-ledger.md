# Phase 6 — findings ledger

> Status: **wrapped** — all 7 explorers complete, 16 findings raised, 12 closed in-place, 2 SDD-debt open with tracked closure PRs, 2 demoted.
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
| F-2031-003 | nice (closed) | supply-chain (deny.toml) | `0BSD` was added to `deny.toml`'s `licenses.allow` to permit `quoted_printable` 0.5.2 (transitive via `lettre`). Documented in-line, but should be re-audited end-to-end. | **Closed by Phase 6 security explorer** — `cargo deny check licenses` confirms 0BSD matches only `quoted_printable`; single inbound edge from `lettre`; 0BSD is functionally public-domain-equivalent and strictly more permissive than BSD-2-Clause already in allow list. Addition is safe; no code change. |
| F-2031-004 | demoted | tooling (rustfmt) | PR #127 needed a `chore(fmt)` fix-up commit (`3b80a85`) to satisfy CI's rustfmt 1.88.0 chain-collapse on the panic-floor parsing path. Local rustfmt produced different output. Single observed incident; CI caught it before merge. | None — re-flag if a second occurrence appears in a future cycle. |
| F-2031-005 | nice (closed) | crate (ntfy) | `NtfyNotifier` derived `Debug`, which would render the bearer token verbatim in any `tracing` log. Out of step with the secret-elision posture of slack/discord/twilio/smtp. | **Closed by Phase 6 crate explorer** — custom `Debug` impl elides token to `<redacted>`; 2 tests pin elision shape. |
| F-2031-006 | **important** (closed) | crate (wall) | `selfdef-integration-wall::broadcast()` failed eagerly on EPIPE when the child exited before reading stdin. Manifested as a flaky CI failure on `ubuntu-latest`; also a latent production defect for wall(1) on TTY-less hosts. | **Closed by Phase 6 crate explorer** — tolerate `BrokenPipe` on both `write_all` and `shutdown`, fall through to wait-on-exit. Stress-tested 15× green. |
| F-2031-007 | **important** (closed) | module (dispatcher-adapter) | `DispatcherAdapter` set the initial deadline via the legacy `DEFAULT_RUNG_INTERVAL_SECS = 300` hardcoded constant instead of `profile.ack_window_for(0)`. Operators selecting `aggressive` (rung 0 = 60s) saw the first rung-advance fire 5 min later instead of 60s — exact opposite of the profile's stated purpose. | **Closed by Phase 6 module explorer** — adapter now reads `self.dispatcher.profile().ack_window_for(0)`; test pins the new contract. |
| F-2031-008 | nice (closed) | module (wake_task) | `wake_task::run` doc-comment referenced the legacy `MAX_RUNG` constant, `dispatch_payload` (no-rung-filter), and `RUNG_INTERVAL` — all replaced by `profile.max_rung()`, `dispatch_payload_for_rung`, and `profile.ack_window_for`. Doc-vs-code drift. | **Closed by Phase 6 module explorer** — doc-comment rewritten to match D-6b/D-6c shipping shape. |
| F-2031-009 | **important** (SDD-debt, stopgap shipped) | module (dispatcher path) | Per-channel subscription filter (D-3: `[notifier.subscriptions.<channel>]`) silently stops being applied when the operator switches to the engine path (`escalations_path` set). `build_channel_set` strips subscription metadata; `fire_channels_filtered` walks every configured channel regardless. Silent broadening of channel firing on the operator's principal noise-reduction lever. | **Stopgap shipped by Phase 6 integration explorer** — startup warn fires when `[notifier.subscriptions]` is non-empty on engine path. Principled fix defers to SDD-008 D-5e follow-up PR. |
| F-2031-010 | nice (closed) | integration (config parse) | `parse_dispatcher_profile` silently mapped any non-positive `ack_window_secs` in a custom profile rung to 300 — operator typos like `ack_window_secs = 0` or `-60` produced 5-minute waits with no indication anything was wrong. | **Closed by Phase 6 integration explorer** — invalid values now log a structured `warn!` naming the profile, rung index, configured value, and fallback. |
| F-2031-011 | nice (closed) | docs (SDD-008) | SDD-008's "Implementation status" said "Charter only. No implementation has shipped." (stale — D-1..D-8 all shipped). Two open-question working assumptions (Q-C "deferred channels", Q-G `[notifications]` namespace) were revised by reality during implementation, not just confirmed; the doc kept them as live questions. | **Closed by Phase 6 docs explorer** — Implementation-status table with per-D shipping PRs; each open question annotated `→ confirmed` / `→ revised on implementation` with the shipped behaviour. |
| F-2031-012 | nice (closed) | docs (init.rs STARTER_CONFIG) | STARTER_CONFIG documents per-channel subscription filters in detail but never mentions F-2031-009 — operators following the starter config faithfully would set both `escalations_path` and `[notifier.subscriptions.*]` and silently get every event on every channel. The daemon-side stopgap warning (PR #135) catches this at runtime; the operator should learn about the gap at config-write time. Also: D-6c past-tense "lands in follow-up Ds" was stale (D-6c has shipped). | **Closed by Phase 6 docs explorer** — subscription block carries the F-2031-009 caveat inline; D-6c reference fixed to present tense. |
| F-2031-013 | nice (SDD-debt) | tests (daemon integration) | The 22-PR SDD-008 cycle shipped 159 new tests but **zero Category-2 (pipeline) tests** for the engine path. Operator-visible promises ("an unacked notification re-fires at its rung deadline", "ack from a separate process stops further re-fires", "mode=audit honoured at daemon startup") lack daemon-level end-to-end coverage. Same pattern as F-2026-082 (the SDD-005 parent). | **Open — follow-up PR under SDD-005's implementation-PR pattern.** New `m_notify_engine.rs` + `EngineHarness` helper; needs `tokio::time::pause()` for deterministic wake-task driving. |
| F-2031-014 | demoted | tests (wake_task) | `wake_task::run_exits_on_cancellation` uses `tokio::time::sleep(50ms)` to give the spawned task time to reach its `tokio::select` arm before cancelling. Initially flagged as SDD-005 pipeline-determinism concern. | Cross-checked: this is a Cat-4 seam test for cancellation propagation, not a pipeline test. The sleep is scheduler-jitter absorption with a 2s timeout absorbing scheduler stalls. Pattern-distinct from "pipeline tests must be deterministic". Demoted. |
| F-2031-015 | **important** (closed) | security (ntfy creds) | `selfdef-integration-ntfy::from_config` used `.ok()` on the `token_file` read — any IO error (file missing / wrong permissions / typo) silently produced an unauthenticated client. Operator who configured `token_file` believed auth was enforced when it wasn't. Other 4 credential-bearing channels (smtp/twilio/slack/discord) propagate the IO error and refuse to construct. | **Closed by Phase 6 security explorer** — `from_config` rewritten as explicit `match`; unreadable/empty file degrades-with-`warn!` naming the path + error. 5 new tests pin the contract. |
| F-2031-016 | nice (closed) | docs (SECURITY.md) | `[notifier.escalations_path]` SQLite file holds rendered title+body of every persisted alert (hostnames, IPs, ATT&CK ids, command lines) — cleartext at rest. WAL adds `-wal`+`-shm` siblings with same sensitivity. Cycle's SECURITY.md additions documented credentials + TTY broadcast but missed the escalations file itself. | **Closed by Phase 6 security explorer** — new SECURITY.md row documents the escalations store as sensitive data-at-rest, including WAL siblings and the SQLite-doesn't-zero-freelist gotcha on close. |

## Status

**WRAPPED**. The Phase 6 closure-cycle audit programme has
completed all seven explorers over the 22-PR SDD-008
notifications-orchestration cycle (`#109`..`#130`,
charter `#131`, explorers `#132`..`#138`, wrap this PR).

### Closure summary

- **16 findings raised** (F-2031-001 through F-2031-016).
- **12 closed in-place** during the audit cycle:
  - F-2031-001 (PR-label collision → SDD-008 appendix)
  - F-2031-002 (ntfy + signal test-coverage parity)
  - F-2031-003 (0BSD allow-list re-audit, no code change)
  - F-2031-005 (ntfy Debug elision)
  - F-2031-006 (wall EPIPE production fix) — **important**
  - F-2031-007 (DispatcherAdapter rung-0 timing) — **important**
  - F-2031-008 (wake_task doc drift)
  - F-2031-010 (custom-profile ack_window_secs warn)
  - F-2031-011 (SDD-008 implementation status + Q-letter revisions)
  - F-2031-012 (init.rs STARTER_CONFIG subscription caveat)
  - F-2031-015 (ntfy silent-degrades-to-unauth) — **important**
  - F-2031-016 (escalations SQLite data-at-rest in SECURITY.md)
- **2 SDD-debt open** with tracked closure PRs outside the
  audit programme:
  - F-2031-009 — subscription filter bypass on engine path.
    Stopgaps shipped daemon-side (PR #135) +
    STARTER_CONFIG-side (PR #136). Principled fix:
    `feat(sdd-008): D-5e — wire SubscriptionConfig through
    PayloadDispatcher` PR.
  - F-2031-013 — Category-2 daemon-pipeline-test gap for
    the engine path. Closure under SDD-005's
    implementation-PR pattern (new `m_notify_engine.rs` +
    `EngineHarness` helper using `tokio::time::pause()`).
- **2 demoted** on cross-check:
  - F-2031-004 (rustfmt 1.88.0 fmt-drift, single incident).
  - F-2031-014 (50ms cancel-propagation sleep, not a
    pipeline-determinism concern).

### Important findings — Phase 6's catch list

Phase 6 surfaced **3 important production-relevant defects**
on the SDD-008 surface, all closed in-place:

1. **F-2031-006** (`selfdef-integration-wall`): `broadcast()`
   failed eagerly on EPIPE when wall(1) exited before reading
   stdin. Caught initially as a flaky `ubuntu-latest` CI
   failure; the deeper diagnosis revealed a latent production
   defect for any TTY-less host. Fix: tolerate
   `BrokenPipe` on both `write_all` and `shutdown`,
   fall through to the wait-on-exit path. Stress-tested
   15× green.

2. **F-2031-007** (`selfdef-daemon::dispatcher_adapter`):
   initial submit deadline used the legacy
   `DEFAULT_RUNG_INTERVAL_SECS = 300` constant instead of
   `profile.ack_window_for(0)`. Operators selecting the
   `aggressive` profile (rung 0 = 60s) saw the first rung-
   advance fire 5 minutes later instead of 60 seconds —
   exact opposite of the profile's stated purpose. Fix:
   adapter reads the profile's rung-0 window; test pins the
   `Profile::aggressive` deadline to ~now+60s.

3. **F-2031-015** (`selfdef-integration-ntfy`): `from_config`
   silently swallowed IO errors on the bearer-token file
   read via `.ok()`, producing an unauthenticated client
   when the operator configured a token. The 4 other
   credential-bearing channels propagate the IO error;
   ntfy was the outlier. Fix: explicit `match` with
   `warn!` on unreadable + empty-after-trim; 5 new tests.

This is the audit programme's **first phase since Phase 3 to
surface production-relevant code bugs** — proportionate to
the 9-crate, 159-test, persistent-storage, outbound-credential
nature of the SDD-008 cycle, and a sharp validation of the
"don't carry forward Phase 5's 0-finding prediction" stance
the charter took.

### Cumulative trajectory (Phases 2–6, summary)

| Phase | Cycle audited | Findings | Important | Closed | SDD-debt |
| --- | --- | --- | --- | --- | --- |
| Phase 2 | Phase 1 closure cycle | 64 | 3 | 3 imp + 60 nice | 1 |
| Phase 3 | Phase 2 closure cycle | 39 | 2 | 2 imp + 15 nice | 1 |
| Phase 4 | Phase 3 closure cycle | 9 | 0 | 5 nice | 0 |
| Phase 5 | Phase 4 closure cycle | 0 | 0 | 0 | 0 |
| **Phase 6** | **SDD-008 cycle (22 PRs / 9 crates)** | **16** | **3** | **12** | **2** |

The convergence trajectory (64 → 39 → 9 → 0) was an artifact
of the cycles' shapes, not the programme's diminishing
utility. Phase 6 audits an opposite-shaped cycle (large
feature-stack vs. closure-doc) and surfaces a finding rate
+ severity proportionate to its surface area.

### Open SDD-debt — closure path

The two open findings close outside the Phase 6 audit
programme:

- **F-2031-009 → SDD-008 D-5e PR**. Wires the operator's
  `[notifier.subscriptions.<channel>]` filter through the
  engine path's dispatcher. Currently shipped: daemon
  startup-warn (PR #135) + STARTER_CONFIG inline caveat
  (PR #136), so operators discover the gap at runtime
  AND at config-write time.
- **F-2031-013 → SDD-005 implementation PR**. Adds the
  missing Category-2 (daemon-pipeline) tests for the engine
  path. Pattern follows SDD-005's D-3 ("Implementation PR
  breakdown") — new `crates/selfdef-daemon/tests/m_notify_
  engine.rs` plus a reusable `EngineHarness` helper in
  `crates/selfdef-daemon/tests/common/` for future SDD-008
  follow-ups to inherit.

Phase 7 (when material new code lands) picks up the SDD-008
D-5e + SDD-005 implementation PRs in its recent-PRs explorer.

## Trajectory snapshot

For context — full closure-cycle convergence to date:

| Cycle | recent-PRs | crate | module | integration | docs | tests | security |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Phase 2 | many | 11 nice | 6 nice | 9 mixed | 9 nice | 11 mixed | 5 mixed |
| Phase 3 | 4 nice | 10 mixed | 1 important | 4 nice | 5 mixed | 5 mixed | 3 nice |
| Phase 4 | 1 demoted | 2 nice | 1 nice | 2 nice | 1 nice | 1 demoted | 1 demoted |
| Phase 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Phase 6** | **2 nice (closed) + 1 nice + 1 demoted** | **1 important + 2 nice (all closed)** | **2 important + 1 nice (closed) + 1 important (SDD-debt stopgap)** | **1 nice (closed) + stopgap landed** | **3 nice (closed)** | **1 nice (SDD-debt) + 1 demoted** | **1 important + 2 nice (all closed)** |

Phase 5's zero-finding result reflected its audit surface (a
documentation-heavy closure cycle); Phase 6 audited an
opposite-shaped cycle (9 new crates, persistent storage,
outbound credentials, background tasks). The 16-finding
outcome is proportionate to the surface area; the
trajectory's apparent "convergence" was an artifact of cycle
shape, not programme utility.

## Phase 1 / Phase 2 / Phase 3 / Phase 4 / Phase 5 references

- Phase 1: [`../99-findings-ledger.md`](../99-findings-ledger.md)
- Phase 2: [`../phase-2/99-findings-ledger.md`](../phase-2/99-findings-ledger.md)
- Phase 3: [`../phase-3/99-findings-ledger.md`](../phase-3/99-findings-ledger.md)
- Phase 4: [`../phase-4/99-findings-ledger.md`](../phase-4/99-findings-ledger.md)
- Phase 5: [`../phase-5/99-findings-ledger.md`](../phase-5/99-findings-ledger.md)
