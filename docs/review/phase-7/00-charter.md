# Phase 7 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-15

## Why Phase 7 now

Phase 6's [findings ledger](../phase-6/99-findings-ledger.md)
wrapped a few hours ago with **14 of 16 findings closed (12
in-place + 2 post-wrap), 2 demoted, 0 open**. Three important
production-relevant defects were caught and fixed (F-2031-006
wall EPIPE, F-2031-007 dispatcher rung-0 timing, F-2031-015
ntfy silent-degrade-to-unauth). The convergence trajectory
now reads:

| Phase | Findings | Blockers | Important | Nice (closed) | SDD-debt |
| --- | --- | --- | --- | --- | --- |
| Phase 2 | 64 | 0 | 3 (closed) | 60 (closed) | 1 (closed) |
| Phase 3 | 39 | 0 | 2 (closed) | 16 (15 closed) | 1 (closed) |
| Phase 4 | 9 | 0 | 0 | 5 (all closed) | 0 |
| Phase 5 | 0 | 0 | 0 | 0 | 0 |
| Phase 6 | 16 | 0 | 3 (all closed) | 9 (closed) | 2 (both closed post-wrap) |

Phase 6 wrapped with two open SDD-debt findings (F-2031-009
subscription filter wiring, F-2031-013 daemon-pipeline-test
gap). Both **closed during the post-wrap follow-up cycle** —
the same cycle Phase 7 audits.

## What changed during the post-Phase-6 cycle

**7 PRs merged** between Phase 6 wrap (`#139`) and this
charter, in order:

| PR | Substance |
| --- | --- |
| `#140` | `feat(sdd-008): D-5e — subscription filter on engine path` — closes F-2031-009. Payload + Subscription extended in orchestrator; engine schema v2 adds `event_kind` column + ALTER migration; dispatcher gains `with_subscriptions()` builder; daemon wires `build_channel_subscriptions`. 13 new tests. Removes the F-2031-009 stopgap warning. |
| `#141` | `test(sdd-005): daemon-level pipeline tests for engine path` — closes F-2031-013. New `crates/selfdef-daemon/tests/m_notify_engine.rs` with reusable `EngineHarness`; 3 tests cover the wake-task rung-advance, separate-process ack, and audit-mode promises. `wake_task::process_due_at(dispatcher, now)` promoted to `pub` to drive iterations deterministically (sidesteps the `start_paused` × `spawn_blocking` race). |
| `#142` | `feat(sdd-008): D-4 HTTP ack endpoint — GET /notify/ack/<token>` — closes the SDD-008 D-4 HTTP complement that had been "open follow-up" since Phase 6 charter. Engine schema v3 adds `ack_token` column with partial UNIQUE index + back-fill migration; new `record_ack_by_token` API; ApiState gains optional engine handle; `[notifier].ack_link_base` config knob; DispatcherAdapter mints UUIDv7 tokens + renders ack_link URLs. 11 new tests. |
| `#143` | `feat(sdd-008): Q-G — PagerDuty Events API v2 integration` — first of the SDD-008 Q-G adapter ideas. New `selfdef-integration-pagerduty` crate (559 LOC, 12 tests). Pattern-instance of `docs/dev/integrations.md`. Severity collapse (OCSF 6 → PD 4); routing_key secret-elision Debug; HTTPS-only endpoint guard. |
| `#144` | `feat(sdd-008): Q-G — Grafana Loki push-API integration` — second Q-G adapter. New `selfdef-integration-loki` crate (600 LOC, 16 tests). Three-mode auth (self-hosted single-tenant / multi-tenant via X-Scope-OrgID / Grafana Cloud Bearer); newline-to-`·` collapse in line rendering. |
| `#145` | `feat(sdd-008): Q-G — OpenSearch / Elasticsearch document-index integration` — third Q-G. New `selfdef-integration-opensearch` crate (792 LOC, 22 tests). Three-mode auth (none / Basic / ApiKey); explicit `auth_kind` operator-chosen with unknown-string rejection; RFC-3339 `@timestamp` formatting. |
| `#146` | `feat(sdd-008): Q-G — TheHive integration (ALL Q-G COMPLETE)` — fourth and final Q-G. New `selfdef-integration-thehive` crate (578 LOC, 16 tests). Severity collapse OCSF 6 → TheHive 4; TLP=Amber default for SOC-internal posture; tag composition. |

**By the numbers:**
- 7 PRs merged.
- 4 new crates (the 4 Q-G channels).
- 1 new SDD design point shipped (D-4 HTTP ack endpoint).
- 1 SDD-debt finding closed (F-2031-013 via SDD-005 impl PR).
- 1 SDD-debt finding closed (F-2031-009 via SDD-008 D-5e PR).
- 2 schema migrations (v2 `event_kind`, v3 `ack_token`).
- 1 new operator config knob (`[notifier].ack_link_base`).
- 1 new public API route (`GET /notify/ack/:token`).
- ~93 new tests added across the 7 PRs.

## Scope of this Phase

Same shape as Phases 4-6 — seven explorers. The audit surface
is **smaller than Phase 6** (no new core crate / dispatcher
rewrite this time) but **denser per PR**:

| Explorer | Scope for Phase 7 |
| --- | --- |
| Recent-PRs audit | 7 PRs (#140..#146). Verify each PR's claimed scope matches its diff; the four Q-G adapters are pattern-instances and should be near-uniform in shape — flag drift. |
| Crate audit | 4 new channel crates (`pagerduty`, `loki`, `opensearch`, `thehive`). `from_config` validation, secret-elision `Debug`, HTTPS-only endpoint guard, severity-collapse correctness, name parity Notifier↔Channel. The 12-16-22-16 test counts are unusually variable for pattern-instances — investigate. |
| Module audit | The D-4 HTTP ack flow end-to-end: DispatcherAdapter mints token → engine persists in schema-v3 column → channel sends with ack_link → HTTP handler records ack. Module-level race window between handler and wake_task. |
| Integration audit | Schema-v3 migration (back-fill + UNIQUE index) — does it leave a v1-only daemon with corrupted state if rolled back? `[notifier].ack_link_base` config round-trip. ApiState's new optional engine handle + `with_escalation_engine` builder. Subscription-filter wiring (D-5e) across the two paths now that it's on by default. |
| Docs audit | SDD-008's "Implementation status" table — every D-N and Q-G row now claims "shipped"; verify against the actual PR mapping. STARTER_CONFIG gains 5 new commented blocks (ack_link_base + 4 Q-G channels); each should match its `from_config` contract. SECURITY.md notification-credentials row absorbed 4 new credential paths. |
| Tests audit | The new `m_notify_engine.rs` daemon pipeline test (3 tests via `EngineHarness` + `process_due_at`) is a new in-codebase pattern under SDD-005; verify it actually exercises the engine path end-to-end rather than only the dispatcher API. The 4 Q-G adapters' wiremock tests vary 12-22 per crate; investigate whether the variance reflects real coverage differences or just test-style drift. |
| Security audit | Schema v2 + v3 migrations on disk: idempotency, fallback on corruption, freelist after ALTER. `ack_token` URL contents are operator-trusted out-of-band routing — what attacker can derive from a token? The 4 new channel-credential files (PD routing_key, Loki bearer, OS Basic/ApiKey, Hive API key). 0 new dependencies entered the tree post-PagerDuty's reqwest + lettre footprint — re-confirm cargo-deny clean. The `/notify/ack/:token` route is the first **unauthenticated** API endpoint selfdef ships — re-audit the token-IS-auth model under the four PD-pattern adversaries from SECURITY.md. |

## Out of scope (defer to Phase 8 or later)

- SDD-009 dashboard (still deferred to a separate design
  conversation with a design agent — operator's stated
  preference).
- Future channel adapters beyond the Q-G four (e.g.
  bidirectional ack receivers from PD / Hive — needs the
  daemon-side webhook receiver pattern).
- Phase 1-6 findings already closed.
- Cross-host fleet behaviour, performance benchmarks,
  real-cluster k8s integration.

## Methodology

Same as prior Phases:

1. Each explorer surveys their area; lists every concrete
   observation.
2. Triage: blocker / important / nice / SDD-debt / demoted.
3. Each observation becomes an `F-2032-NNN` entry in the
   Phase 7 findings ledger.
4. SDD-debt findings spawn SDDs under `docs/sdd/` (next free
   number is 009; D-9 dashboard claimed it but if Phase 7
   spawns SDD-debt the operator's deferral applies — file as
   SDD-010+ instead).

## Predicted outcome

The post-Phase-6 cycle's character is **routine pattern-
instance work** (4 of 7 PRs are Q-G adapters) plus **two
substantial seam changes** (D-5e wiring across crates, D-4
HTTP ack with schema-v3 migration). Realistic Phase 7
expectation:

- **3-8 findings total**, mostly nice-level on the Q-G
  adapter uniformity axis.
- **0-2 important** likely on the schema-v3 migration path
  (back-fill correctness, rollback semantics) or the new
  unauth `/notify/ack/:token` route.
- **0 SDD-debt** expected (the design surface is closed-out
  SDD-008 + closed-out F-2031-013).

If the security explorer finds the schema-v3 back-fill ALTER
unsafe under a partial-write scenario, that's a real
production-relevant bug deserving an important rating.
Otherwise the audit should converge fast.

## Status

This PR opens Phase 7 with:

- the charter (this file)
- the Phase 7 findings ledger template

The inventory + seven explorers ship in follow-up PRs (same
cadence as Phases 5 and 6).

Phase 7 closes when every important / blocker has either a
"closed by <PR>" back-reference or a tracked SDD.

## Naming

Phase 1 = `F-2026-NNN`, Phase 2 = `F-2027-NNN`, Phase 3 =
`F-2028-NNN`, Phase 4 = `F-2029-NNN`, Phase 5 = `F-2030-NNN`,
Phase 6 = `F-2031-NNN`, Phase 7 = **`F-2032-NNN`**.
