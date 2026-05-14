# Phase 5 inventory — what changed during the Phase 4 cycle

Hand-counted from `git log` covering the 8 PRs that closed
Phase 4 findings (commits `22ff461` Phase 4 audit kickoff
scaffold → `d239dad` Phase 4 security explorer). Used by the
seven Phase 5 explorers as the starting point for "what's the
new surface I'm auditing?"

## New crates

None. Phase 4's closure cycle added no new workspace members.

## New SDDs

None. SDD-007's D-4 was already covered by the Phase 3 cycle.

## Modified crates

### selfdef-api

- **`src/transport.rs::TokenFingerprint`** — derived `Debug`
  removed; custom impl renders only the 4-byte leading hex
  prefix (`TokenFingerprint(a3b9c012…)`). Closes F-2029-002.
- **`src/transport.rs::fingerprint_tests`** — new `#[cfg(test)]`
  module with two tests:
  - `debug_renders_truncated_prefix`: shape assertion
    (`TokenFingerprint(<8 hex chars>…)`) + char-class check.
  - `distinct_tokens_produce_distinct_debug_prefixes`: two
    different inputs produce distinct Debug forms.

- **`tests/m12_api.rs::events_stream_zero_caps_fall_back_to_defaults`**
  — new integration test. Sets
  `SseCaps { global: Some(0), per_token: Some(0) }`, asserts
  the first connection succeeds (falls back to default 64
  global / 8 per-token). Closes F-2029-003.

### selfdef-config

- **`src/lib.rs::tests::sse_cap_knobs_round_trip_from_toml`**
  — new unit test. Writes a TOML file with
  `[api].max_sse_subscribers = 16` and
  `max_sse_subscribers_per_token = 4`; asserts
  `Config::load` yields `Some(16)` + `Some(4)`. Closes
  F-2029-005.
- **`src/lib.rs::tests::sse_cap_knobs_default_to_none_when_unset`**
  — new unit test. Writes a TOML with only `[api].enabled =
  true`; asserts both cap fields parse as `None`. Closes
  F-2029-006 (duplicate of F-2029-005).

## Module-side machinery

- **`modules/vpn-bridge/install/apply.sh`** — dispatcher
  header gains a one-paragraph doc-comment documenting:
  - dry-run-awareness (SELFDEF_DRY_RUN=1 delegated to
    profile_apply via the shared `run` helper).
  - Idempotency (re-running with same config + present
    target = no-op).
  - SDD-006 v2 manifest-tracking contract (profiles use
    `module_record_file` so uninstall enumerates from disk).
  Closes F-2029-004.

## Configuration surface

No new TOML knobs in Phase 4. The Phase 3 cycle already
shipped the `[api].max_sse_subscribers{,_per_token}` knobs
(SDD-007 D-4); Phase 4 only added the test coverage that
pins their round-trip.

## Documentation surface

New `SECURITY.md` section:

- § API surface now documents the per-token SSE subscriber
  quota (default 8 per token, 64 process-wide), the SHA-256
  fingerprint storage, the operator-tunable
  `[api].max_sse_subscribers{,_per_token}` knobs, the
  `None`/`Some(0)` → default fallback, and the distinguishable
  503 reasons (`"sse subscriber cap reached"` global vs
  `"per-token sse cap reached"`). Back-references SDD-007 and
  `SubscriberGuard` for full implementation context. Closes
  F-2029-007.

New under `docs/review/phase-4/`:

- `00-charter.md`, `10-inventory.md`, `20-recent-prs-audit.md`,
  `30-crate-audit.md`, `40-module-audit.md`,
  `50-integration-audit.md`, `60-docs-audit.md`,
  `70-tests-audit.md`, `80-security-audit.md`,
  `99-findings-ledger.md`.

CHANGELOG: every closure PR adds a section.

## Test surface (post-Phase-4 additions)

- `crates/selfdef-api/src/transport.rs::fingerprint_tests` — 2 unit tests.
- `crates/selfdef-api/tests/m12_api.rs::events_stream_zero_caps_fall_back_to_defaults` — 1 integration test.
- `crates/selfdef-config/src/lib.rs::tests::sse_cap_knobs_round_trip_from_toml` — 1 unit test.
- `crates/selfdef-config/src/lib.rs::tests::sse_cap_knobs_default_to_none_when_unset` — 1 unit test.

Total: **5 new tests** across the Phase 4 cycle.

## Numbers

- 8 PRs merged during the Phase 4 closure cycle.
- 0 new crates.
- 0 new SDDs.
- 0 new TOML knobs.
- 1 new operator-facing doc section (SECURITY.md § API
  surface entry for per-token SSE cap).
- 1 dispatcher header doc-comment refresh
  (vpn-bridge/install/apply.sh).
- 1 custom `Debug` impl (`TokenFingerprint`).
- 5 new tests.
- ~500 lines added net per `git diff --stat 22ff461..d239dad`
  (the vast majority is the seven Phase 4 audit docs +
  CHANGELOG + ledger entries).
