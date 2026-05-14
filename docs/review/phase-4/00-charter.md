# Phase 4 audit — charter

> Status: in progress
> Owner: audit team
> Last updated: 2026-05-14

## Why Phase 4 now

Phase 3's [findings ledger](../phase-3/99-findings-ledger.md)
closed out in this session: every blocker, important, nice, and
SDD-debt finding either shipped via one of the explorer-cluster
closure PRs (token-reader symmetry, vpn-bridge v2 migration,
SSE parser bytes refactor, docs polish, CLI doc clarity, SSE 503
typed reason, nice-cluster wrap-up) or via the SDD-007
implementation + D-4 follow-up. The Phase 3 ledger now reads
"Phase 3 is closed for blockers, important, and SDD-debt
findings" — 0 blockers, 2 important (closed), 15/16 nice
(closed; F-2028-008 explicit `defer`), 1/1 SDD-debt (closed).

The closure cadence shipped **~17 PRs** in tight sequence (`f40bf05`
Phase 3 audit kickoff scaffold → `8b44322` SDD-007 D-4 operator-
tunable SSE caps, plus the SDD-007 scoping doc and design PRs).
Each one went through PR review and CI, but the cadence didn't
include a structural audit pass over what the *closures
themselves* shipped — including the SDD-007 implementation, the
TokenFingerprint + SubscriberGuard refactor, and the operator-
tunable cap surface. Phase 4 is that pass.

Same methodology as Phases 1, 2, and 3 (seven explorers,
F-NNNN findings, SDDs where the fix is design-shaped), different
vintage prefix: **F-2029-NNN** so the four ledgers never collide.

## What changed during the Phase 3 cycle

New `selfdef-api` machinery:

- **`TokenFingerprint`** — SHA-256-keyed bearer-token identity in
  `crates/selfdef-api/src/transport.rs`. Computed in `bearer_auth`
  after auth succeeds, threaded via `request.extensions()`.
- **`SseCaps`** — operator-overridable per-process and per-token
  caps in `crates/selfdef-api/src/state.rs` (SDD-007 D-4).
- **Per-token `SubscriberGuard`** — `Arc<Mutex<HashMap<…>>>`
  alongside the global `AtomicUsize`; CAS-acquire on per-token
  first, then global; `Drop` decrements both and prunes the
  map entry to zero (SDD-007 D-2).
- **Distinguishable 503 bodies** — `"sse subscriber cap reached"`
  vs `"per-token sse cap reached"` (SDD-007 D-6).

Refactored `selfdef-cli` internals:

- **SSE parser bytes refactor** — `SseParser::feed_bytes(&[u8])`
  buffers raw bytes; UTF-8 conversion happens line-at-a-time so
  multi-byte codepoints surviving chunk-boundary splits is now
  guaranteed by construction.
- **Token-reader symmetry** — `read_token_file` mirrors the
  daemon-side `read_token` byte-for-byte: 0o600 mode check +
  Unicode `.trim()`.
- **CLI doc-clarity** — module header + Bearer-format note +
  `Follow` clap constraint structure documented in prose.
- **TCP 503 typed reason extraction** — JSON-body parse → typed
  reason in stderr.

New `[api]` config knobs:

- `max_sse_subscribers` / `max_sse_subscribers_per_token` (both
  `Option<usize>`); fall back to compiled-in defaults when unset.

New module-side machinery:

- **vpn-bridge SDD-006 v2 migration** — `lib.sh` bumped to
  `VERSION_REQUIRED=2`; `relay-via-server.sh` writes manifest +
  uninstalls via `module_render_files` iteration with legacy
  fallback.

New SDDs:

- **SDD-007 — Per-token SSE subscriber quota** (implemented; all
  five Ds shipped).

New docs:

- `docs/review/phase-3/{20..80}-*.md` — seven Phase 3 explorer
  audit docs.
- `docs/sdd/007-per-token-sse-subscriber-quota.md` —
  implementation + scope.
- `init.rs` `STARTER_CONFIG` / `STARTER_MODULES` template
  refreshes (mode hints + SSE cap knobs).

Test-infrastructure refactors:

- `crates/selfdef-cli/tests/common/mod.rs` `assert_tree_unchanged`
  / `snapshot_tree` are now explicitly imported (not
  fully-qualified) in 10 module-test files.
- New `with_full_capability_for_fingerprint` test helper in
  `selfdef-api` for in-process per-token testing.

New test cases (~10 new tests):

- `events_stream_per_token_cap_reached` +
  `events_stream_per_token_cap_does_not_affect_other_tokens` +
  `events_stream_per_token_counter_drops_to_zero_on_disconnect`
  (SDD-007 D-5).
- `events_stream_per_token_cap_honours_operator_override` +
  `events_stream_global_cap_honours_operator_override` (D-4).
- `events_follow_url_surfaces_cap_reached_reason_on_503`
  (F-2028-017).
- `events_follow_token_file_refuses_world_readable_mode`
  (F-2028-004).
- `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it`
  (F-2028-015).
- SseParser multibyte round-trip tests (F-2028-018).

## Scope of this Phase

Same shape as Phases 1, 2, 3:

| Explorer | Scope for Phase 4 |
| --- | --- |
| Crate audit | The new `TokenFingerprint` + `SseCaps` types; the refactored `SubscriberGuard` (now dual-counter with HashMap pruning); the `SseParser::feed_bytes` byte-buffer; the TCP 503 typed-reason extraction. |
| Module audit | vpn-bridge's v2 migration completeness; STARTER_MODULES per-block mode hints; suricata's v1 exemption still correct? |
| Integration audit | New seams: TCP-follow ↔ events_stream ↔ per-token + global caps; bearer-auth ↔ TokenFingerprint extension; daemon config ↔ `SseCaps`; init-template ↔ daemon parse. Re-audit the F-2028-018 chunk-boundary fix under chunked HTTP. |
| Docs audit | Seven Phase 3 audit docs themselves + CHANGELOG entries for ~17 closure PRs; SDD-007 + STARTER_CONFIG/STARTER_MODULES refreshes. |
| Tests audit | The ~10 new tests + the F-2028-025 import-style consistency landed across 10 files. Coverage gaps on the SseCaps override path? |
| Recent-PRs audit | The ~17 Phase 3 closure PRs. Same retrospective shape as Phases 1/2/3. |
| Security audit | New attack surfaces: the SHA-256-fingerprint storage in the HashMap (does a malicious operator gain anything by collecting fingerprints?); the operator-overridable caps (could an attacker exploit a misconfigured 0 / very-large value?); the JSON 503 extraction path (could a malformed body crash the CLI?). Re-audit F-2028-037 closure under the SDD-007 implementation. |

## Out of scope (defer to Phase 5)

- Cross-host fleet behaviour (NATS bridge under load).
- Performance / load benchmarks.
- Real-cluster k8s integration.
- Phase 1 / 2 / 3 findings already closed — Phase 4 doesn't
  re-litigate. If a closure is broken, that's a new finding
  under Phase 4's prefix.

## Methodology

Same as prior Phases:

1. Each explorer surveys their area; lists every concrete
   observation that's actionable.
2. Observations get triaged into:
   - **blocker** — must fix before shipping;
   - **important** — should fix;
   - **nice** — cosmetic / non-blocking;
   - **SDD-debt** — needs a design doc to scope;
   - **demoted** — auditor flagged but cross-check showed no
     action needed; kept for audit-trail transparency.
3. Each observation becomes an `F-2029-NNN` entry in the
   Phase 4 findings ledger with surface, summary, and
   next-phase recommendation.
4. SDD-debt findings cluster into SDDs under `docs/sdd/`
   (continuing the existing numbering from 007).

## Status

This PR opens Phase 4 with:
- the charter (this file)
- a structured inventory of what's been added during the
  Phase 3 cycle
- one explorer's first-pass output (recent-PRs audit)
- the Phase 4 ledger with the initial findings

The remaining explorers will run in follow-up PRs. Phase 4
closes when every important / blocker has either a "closed by
<PR>" back-reference or a tracked SDD.

## Naming

Phase 1 = `F-2026-NNN`, Phase 2 = `F-2027-NNN`, Phase 3 =
`F-2028-NNN`, Phase 4 = **`F-2029-NNN`**. The vintage prefix
maps the finding's audit cycle at a glance and prevents
collisions across the four ledgers.
