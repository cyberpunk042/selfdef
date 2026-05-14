# Phase 3 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-14

## Why Phase 3 now

Phase 2's [findings ledger](../phase-2/99-findings-ledger.md)
closed out in this session: every blocker, important, nice, and
SDD-debt finding either shipped via one of the explorer-cluster
closure PRs (init-template hygiene, SSE backpressure, remaining
security cluster, tests cluster) or, in F-2027-010's case, via a
deliberate operator design decision (bundle a reqwest SSE
client). The Phase 2 ledger's status line now reads "Phase 2 is
fully wrapped" — 0 blockers, 3 important (closed), 60 nice
(closed), 1 SDD-debt (closed).

The closure cadence shipped **~28 PRs** in tight sequence
(`2d918ac` Phase 2 audit kickoff → `ee0e1a9` F-2027-010 closure).
Each one went through PR review and CI, but the cadence didn't
include a structural audit pass over what the *closures
themselves* shipped. Phase 3 is that pass: a Phase-2-of-Phase-2
that audits the closure code (test patterns, doc-comment
refreshes, the new reqwest client, the new SSE
backpressure machinery, the rbac validator, etc.) for drift,
coverage gaps, and inconsistencies that didn't get caught at
PR-review time.

Same methodology as Phases 1 and 2 (seven explorers, F-NNNN
findings, SDDs where the fix is design-shaped), different
vintage prefix: **F-2028-NNN** so the three ledgers never
collide.

## What changed during the Phase 2 cycle

New CLI capability:
- `selfdefctl events follow --url <http(s)://host:port>` —
  reqwest-backed SSE client for the daemon's TCP transport
  (PR closing F-2027-010). New `--token-file <path>` knob.

Refactored CLI internals:
- `crates/selfdef-cli/src/follow.rs` — shared `SseParser`
  state machine + `handle_frame` printer. Both UNIX-socket
  HTTP/1.1 and TCP reqwest paths feed the same parser.
- `crates/selfdef-cli/src/main.rs` — new `validate_rbac_subject`
  charset/length validator for operator-supplied `--as`.

Daemon-side hardening:
- `selfdef-api::events_stream` — per-process subscriber cap
  (`MAX_SSE_SUBSCRIBERS = 64`) via RAII `SubscriberGuard` +
  per-`tx.send` `tokio::time::timeout(30s)`.
- `selfdef-api::ApiError::store` — generic
  `"store unavailable"` body + server-side WARN log.

New docs:
- `docs/review/phase-2/{20..80}-*.md` — seven Phase 2 explorer
  audit docs.
- `init.rs` STARTER_CONFIG + STARTER_MODULES doc-comment
  refreshes (TOCTOU hint, control_token_file split,
  module-config trust-boundary hint).

Test-infrastructure refactors:
- `crates/selfdef-cli/tests/common/mod.rs` adoption across 17
  test files (workspace_root / module_dir / write_executable /
  prepended_path / last_stdout_line / snapshot_tree).
- `m4_alert` + `m8_honeytokens` pipeline tests now run on
  `tokio::test(start_paused = true)`.
- `m12_api` build_state returns the TempDir handle; metrics
  assertions use the format-strict prom parser.

New test cases (~25 new tests):
- `validate_rbac_subject` unit tests + integration test for
  shell-meta refusal.
- `events_stream_rejects_over_cap_with_503` — RAII
  guard + slot reuse.
- `live_apply_invokes_nft_load_and_systemctl_start` for
  suricata.
- 9 SseParser unit tests + 5 TCP-follow integration tests.

## Scope of this Phase

Same shape as Phases 1 and 2's seven explorers:

| Explorer | Scope for Phase 3 |
| --- | --- |
| Crate audit | The new code introduced by closure PRs — `SseParser` state machine, `SubscriberGuard` cap, `validate_rbac_subject`, `ApiError::store` rework, `TokenReloader` interactions with the new cap. |
| Module audit | The init-template hygiene refreshes (`STARTER_CONFIG` / `STARTER_MODULES`). Re-survey of every module's `apply.sh` / `uninstall.sh` for the SDD-006 v2 manifest-helpers migration completeness. |
| Integration audit | New seams: TCP-follow ↔ events_stream ↔ subscriber cap; init-template ↔ daemon ingest; ApiError::store ↔ store call sites. |
| Docs audit | Seven Phase 2 audit docs themselves + CHANGELOG entries for the closure PRs. The audit docs are read as docs in their own right. |
| Tests audit | The ~25 new tests + the test-infrastructure refactors (common-mod adoption gaps, pause()-conversion completeness across other pipeline tests not yet converted). |
| Recent-PRs audit | The ~28 closure PRs shipped during Phase 2. Same retrospective shape as Phase 1's and Phase 2's recent-PRs audits. |
| Security audit | New attack surfaces: the TCP-follow client's URL parsing, the bearer-token-file read path, the `validate_rbac_subject` charset (false-negatives / over-restriction), the `ApiError::store` log line for sensitive-error leaks. Re-audit Phase 2's F-2027-061 (SSE cap), F-2027-062 (SSE timeout) closures. |

## Out of scope (defer to Phase 4)

- Cross-host fleet behaviour (NATS bridge under load).
- Performance / load benchmarks.
- Real-cluster k8s integration (`rbac check --probe` against a
  live cluster).
- Phase 1 / Phase 2 findings that flipped to "closed" — Phase 3
  doesn't re-litigate already-closed findings; if a closure is
  broken, that's a new finding under Phase 3's prefix.

## Methodology

Same as Phases 1 and 2:

1. Each explorer surveys their area, lists every concrete
   observation that's actionable.
2. Observations get triaged into:
   - **blocker** — must fix before shipping;
   - **important** — should fix;
   - **nice** — cosmetic or non-blocking;
   - **SDD-debt** — needs a design doc to scope the fix.
3. Each observation becomes an `F-2028-NNN` entry in the Phase 3
   findings ledger with surface, summary, and next-phase
   recommendation.
4. SDD-debt findings cluster into one or more SDDs under
   `docs/sdd/00N-*.md` (continuing the existing numbering).

## Status

This PR opens Phase 3 with:
- the charter (this file)
- a structured inventory of what's been added during the
  Phase 2 cycle
- one explorer's first-pass output (recent-PRs audit)
- the Phase 3 ledger with the initial findings

The remaining explorers will run in follow-up PRs. Phase 3
closes when every important / blocker has either a "closed by
<PR>" back-reference or a tracked SDD.

## Naming

Phase 1 findings used `F-2026-NNN`, Phase 2 used `F-2027-NNN`,
Phase 3 uses `F-2028-NNN`. The vintage prefix maps the
finding's audit cycle at a glance and prevents collisions
across the three ledgers. As before, the number does not roll
over within a phase — F-2028-001 is the first finding in
Phase 3, F-2028-100 is the hundredth, whether they land on
the same day or six months apart.
