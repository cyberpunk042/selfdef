# Phase 7 — recent-PRs audit (post-Phase-6 closure)

Companion to Phase 6's [20-recent-prs-audit.md](../phase-6/20-recent-prs-audit.md).
Same shape: walk the 7 PRs shipped between Phase 6 wrap and
the Phase 7 charter (`8008a41..e91d0ed`) and flag observations
that didn't get caught at PR-review time.

## Methodology

For each PR: read the commit message, the diff, the schema
migrations (if any), and the resulting tree state. Look for:

- **Scope drift** — claims in commit/PR messages that don't
  match the diff.
- **Pattern uniformity** — the four Q-G adapters all
  pattern-instance `docs/dev/integrations.md`; deviations are
  worth flagging.
- **Migration safety** — schema v2 and v3 each ALTER + back-
  fill + reindex; partial-failure recovery semantics
  matter.
- **Test-count proportionality** — wide variance across
  similar-looking PRs signals either real coverage drift or
  test-style drift.
- **API auth surface deltas** — D-4 introduces selfdef's
  first unauthenticated route.

Outcomes feed `F-2032-NNN` entries in the section below.

## PRs surveyed

| # | Topical commit | Title | Audit pass |
| --- | --- | --- | --- |
| 1 | `97c3b3a` | `feat(sdd-008): D-5e — subscription filter on the engine path (closes F-2031-009)` | **review-clean** |
| 2 | `142b7f9` | `test(sdd-005): daemon-level pipeline tests for engine path (closes F-2031-013)` | **review-clean** |
| 3 | `f4f4538` | `feat(sdd-008): D-4 HTTP ack endpoint — GET /notify/ack/<token>` | **F-2032-001** + **F-2032-002** referrals |
| 4 | `7cc101d` | `feat(sdd-008): Q-G — PagerDuty Events API v2 integration` | review-clean |
| 5 | `9606588` | `feat(sdd-008): Q-G — Grafana Loki push-API integration` | review-clean |
| 6 | `38b3fa9` | `feat(sdd-008): Q-G — OpenSearch / Elasticsearch document-index integration` | review-clean |
| 7 | `8752fe8` | `feat(sdd-008): Q-G — TheHive incident-management integration (ALL Q-G COMPLETE)` | **F-2032-003** (nice) |

## Observations

### Pattern uniformity across the four Q-G adapters

All four follow the same skeleton (struct → custom Debug
elision → `new`/`from_config`/`post`-shaped delivery core →
two trait impls → wiremock tests). Spot-checked uniformity:

| Property | pagerduty | loki | opensearch | thehive |
| --- | --- | --- | --- | --- |
| HTTPS-only endpoint guard | ✓ | ✓ | ✓ | ✓ |
| Custom `Debug` elides secret | ✓ (routing_key prefix) | ✓ (token redacted) | ✓ (token redacted) | ✓ (api_key prefix) |
| `from_config` rejects empty endpoint | N/A (default endpoint) | ✓ | ✓ | ✓ |
| `from_config` rejects empty token file | ✓ | ✓ | ✓ | ✓ |
| Trailing-slash stripped from endpoint | N/A | N/A | ✓ | ✓ |
| `name()` parity test | ✓ | ✓ | ✓ | ✓ |
| Wiremock happy-path Notifier | ✓ | ✓ | ✓ | ✓ |
| Wiremock happy-path Channel | ✓ | ✓ | ✓ | ✓ |
| Non-success → Remote error mapping | ✓ (429) | ✓ (500) | ✓ (403) | ✓ (401) |

**Test-count variance** (12 / 16 / 22 / 16) reflects real
auth-mode complexity differences:

- PagerDuty has one auth shape (`routing_key`) → fewer
  rejection paths.
- Loki has 0/1/2 auth combinations → moderate rejection
  paths.
- OpenSearch has 3 explicit `auth_kind` modes → ~6 extra
  rejection tests (basic-missing-user, basic-missing-token,
  apikey-missing-token, empty-token-file, unknown-auth-kind,
  …).
- TheHive has one auth shape (`api_key` Bearer) → moderate.

**Verdict**: real coverage difference, not drift. No
finding. The trailing-slash trim is missing on PagerDuty +
Loki but they don't need it — PD's endpoint is documented
as a single canonical URL the operator pastes literally;
Loki's typical endpoint includes a fixed `/loki/api/v1/push`
path that wouldn't tolerate stray trailing slash anyway.
**OpenSearch + TheHive correctly strip** because operators
naturally write base URLs both with and without the trailing
slash.

### F-2032-001 referral (nice): schema v3 migration's partial-failure recovery

**Surface**: `selfdef-notifier-engine/src/lib.rs::migrate`,
the `if current < 3` block.

The v3 migration runs three statements in sequence outside a
transaction:

```rust
if current < 3 {
    conn.execute_batch("ALTER TABLE … ADD COLUMN ack_token TEXT NULL;")?;
    conn.execute_batch("UPDATE notification_escalations \
        SET ack_token = lower(hex(randomblob(16))) \
        WHERE ack_token IS NULL;")?;
    conn.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS \
        idx_escalations_ack_token \
        ON notification_escalations(ack_token);")?;
    conn.pragma_update(None, "user_version", 3_i64)?;
}
```

If the ALTER succeeds but a subsequent step fails (e.g.
disk-full during back-fill), the daemon's restart sees
`user_version = 2` but the schema already has the `ack_token`
column. Re-running the v3 migration block fails immediately
because `ALTER TABLE … ADD COLUMN ack_token` errors with
"duplicate column name" — and the engine open path bubbles
that as `EngineError::Sqlite(...)`, refusing daemon startup.

**Severity = nice**: in practice, the UPDATE + CREATE INDEX
steps are extremely unlikely to fail mid-statement (no
constraints, no input pressure, randomblob is in-memory).
Disk-full on the back-fill UPDATE is the realistic case;
SQLite's `disk full` error is well-defined and the same
class of "operator must intervene" outcome the daemon would
hit anyway. But the **non-idempotent ALTER** is a foot-gun
for any future migration that combines schema + data steps.

**Recommendation**: hand off to the **integration explorer**
+ **security explorer**. Fix options:

- Wrap the v3 block in an explicit
  `conn.unchecked_transaction()` so SQLite atomically commits
  the ALTER + UPDATE + index + user_version bump.
- Or check via `PRAGMA table_info` whether `ack_token` exists
  before attempting ALTER.

The v2 migration has the same shape (ALTER + pragma bump)
but only one ALTER step, so partial-failure-then-retry would
hit the same `duplicate column name` issue. Worth tracking
together.

### F-2032-002 referral (security): first unauthenticated route

**Surface**: `selfdef-api/src/lib.rs` route table; PR #142.

The `GET /notify/ack/:token` route is the **first
unauthenticated** API endpoint selfdef ships. Every prior
route is either UNIX-socket-gated (Full-cap middleware via
`with_capability`) or bearer-token-gated (TCP transport).
The PR documents this explicitly: "the token IS the auth"
(UUIDv7, ~122 bits of post-timestamp entropy, rides
out-of-band over operator-trusted channels).

**Recommendation**: the **security explorer** should
re-audit the token-IS-auth model against the four primary
adversaries from SECURITY.md, plus:

- Token sniffing on the egress channel (e.g. operator
  forwards an email containing the ack URL to a colleague —
  now the colleague can ack).
- Token leakage in third-party-service logs (PagerDuty,
  ntfy, smtp relays all see the URL in plain).
- Brute-force feasibility (UUIDv7 has a timestamp prefix;
  the random suffix is ~62 bits — well above brute-force
  threshold but worth confirming the math).

Not a defect at the PR level — PR #142 was upfront about
the choice. Documentation hand-off, not a code-fix
recommendation.

### F-2032-003 (nice): commit-message D-N drift on the Q-G commits

The 4 Q-G commit titles use the form `feat(sdd-008): Q-G —
<service> integration`. SDD-008's design points are D-1
through D-9 with Q-A through Q-G as **open questions** (not
design points). Strictly, the commit prefix `Q-G` references
"the open question Q-G whose working assumption we
implemented".

Cross-check: SDD-008's Q-G text says:

> Q-G — Future channels (OpenSearch, Loki, PagerDuty,
> TheHive). Working assumption: implement as Q-G adapter
> pattern instances per the integration crate template; no
> new design point per channel.

So the `Q-G` prefix is accurate as the question id, but a
casual reader might think "Q-G" is a design point. **No
material problem** — the SDD-008 Implementation-status
table in the doc disambiguates clearly. But for future
audit ledgers that index by D-N label, the `Q-G — <service>`
convention extends Phase 6's F-2031-001 family of "PR-label
disambiguation" concerns.

**Severity = nice**. Recommendation: docs explorer should
verify the SDD-008 "PR labels — appendix" (added by Phase 6
F-2031-001 closure) covers the four Q-G commits cleanly.

## Notes — no finding

### PR #140 (D-5e wiring): substantial cross-crate change

Walking the diff: orchestrator gets Payload field + Subscription
type; engine gets schema v2 ALTER + dispatcher subscriptions
HashMap; daemon gets `build_channel_subscriptions` helper +
removed F-2031-009 stopgap warn. 13 new tests pin behaviour.
Path equivalence between legacy chain and engine paths is
documented as bytewise-equivalent on the subscription axis.

No scope drift; the F-2031-009 closure references all
flow through.

### PR #141 (SDD-005 pipeline tests): new in-codebase pattern

Introduces `EngineHarness` + `process_due_at` as the
canonical pattern for engine-path Category-2 (pipeline)
tests under SDD-005. The PR's commit message + the test
file's module-level rustdoc explain why `tokio::test(start_paused
= true)` doesn't work cleanly for this surface (the
`spawn_blocking` race).

The harness is **scoped to the single test file** — not
yet promoted to `crates/selfdef-daemon/tests/common/`. The
test file's rustdoc anticipates the graduate-to-common move
if a second SDD-008 follow-up needs the pattern. For Phase
7's audit window, only the original 3 tests use it. **Not a
finding**; the **tests explorer** should verify the pattern
is reusable as documented.

### PR #142 (D-4 HTTP ack): substantial schema + API change

Schema v3 (see F-2032-001 above), new public route,
Payload + DispatcherAdapter extended, `ApiState` gains
optional engine handle. The handler is intentionally
simple: bearer-free, returns 200/404/503. Token contents
are deliberately undocumented from the daemon's side — they
exist only to be received via channels and replayed back.

In-cycle clippy fix-up: `clippy::type_complexity` allowed on
the `build_notifier_path` return tuple via explicit
`#[allow(...)]`. Documented; no follow-up needed.

## Trajectory comparison

| Cycle | PRs audited | Recent-PRs findings | Pass rate | SDD-debt? |
| --- | --- | --- | --- | --- |
| Phase 3 | 29 | 4 nice | 86% (25/29 clean) | none |
| Phase 4 | 17 | 1 demoted | 94% (16/17 clean) | none |
| Phase 5 | 8 | 0 | 100% | none |
| Phase 6 | 22 | 3 nice + 1 demoted | 86% (19/22 clean) | none from recent-PRs |
| **Phase 7** | **7** | **2 nice + 1 referral** | **57% (4/7 clean)** | **none from recent-PRs** |

The Phase 7 raw pass rate (57%) looks low compared to
Phases 3-6, but the absolute numbers are tiny (3 of 7
flagged something). One of the 3 (F-2032-002) is a docs-
hand-off, not a defect; one (F-2032-003) is a nice-level
label-pedantry note; the only PR with a substantive PR-
level observation is **PR #142** (F-2032-001 schema v3
migration).

No SDD-debt findings from the recent-PRs explorer. The D-5e
+ D-4 + Q-G cluster shipped tight — no half-done bits, no
behind-the-back refactors, no missed clippy follow-ups
(beyond the documented `type_complexity` allow).

## Hand-off to subsequent explorers

- **Crate explorer**: investigate the test-count variance
  across the 4 Q-G adapters; verify it tracks auth-mode
  complexity (12/16/22/16) and not test-style drift.
- **Integration explorer**: pick up F-2032-001 (schema v3
  migration partial-failure recovery). Concrete fix: wrap
  v2 + v3 migration blocks in `unchecked_transaction()`.
- **Security explorer**: pick up F-2032-002 (token-IS-auth
  audit on the `/notify/ack/:token` route). Recompute the
  brute-force threshold; document the third-party-log-leak
  threat.
- **Docs explorer**: pick up F-2032-003 (verify SDD-008's
  "PR labels — appendix" covers the Q-G commits).
