# Phase 4 inventory — what changed during the Phase 3 cycle

Hand-counted from `git log` covering the ~17 PRs that closed
Phase 3 findings (commits `f40bf05` Phase 3 audit kickoff
scaffold → `8b44322` SDD-007 D-4). Used by the seven Phase 4
explorers as the starting point for "what's the new surface I'm
auditing?"

## New crates

None. Phase 3's closure cycle added no new workspace members.

## New SDDs

- **SDD-007 — Per-token SSE subscriber quota** (implemented).
  All five Ds shipped:
  - D-1: `TokenFingerprint` SHA-256 identity.
  - D-2: dual-counter `SubscriberGuard` + HashMap pruning.
  - D-3: revocation deferred (rotation blocks new connections
    via bearer-auth refusal; existing drain via slow-client
    timeout).
  - D-4: two operator-tunable `[api]` config knobs
    (`max_sse_subscribers`, `max_sse_subscribers_per_token`).
  - D-5: 5 new integration tests (per-token cap, per-token
    isolation, drop-prunes, per-token override, global
    override).
  - D-6: distinguishable 503 bodies (`"sse subscriber cap
    reached"` global vs `"per-token sse cap reached"`).

## Modified crates

### selfdef-api

- **`src/transport.rs`** — new `TokenFingerprint(pub [u8; 32])`
  type (SHA-256). `bearer_auth` middleware threads it into
  `request.extensions()` after auth succeeds. Computed once per
  request, never stores the raw token.

- **`src/state.rs`** — `ApiState` gains:
  - `sse_subscribers_per_token: Arc<Mutex<HashMap<TokenFingerprint,
    AtomicUsize>>>` (per-token counter map, `std::sync::Mutex`
    for sync `Drop`).
  - `sse_caps: SseCaps` (operator overrides; SDD-007 D-4).
  - `with_sse_caps(SseCaps { global, per_token })` builder.
  - `sse_subscribers_per_token_keys()` test-helper for the
    leak-check test.

- **`src/handlers.rs`** — `SubscriberGuard` refactored:
  - `MAX_SSE_SUBSCRIBERS_PER_TOKEN = 8` const.
  - `try_acquire(state, fingerprint)` consults operator caps
    first, then defaults; checks per-token before global.
  - `Drop` decrements both counters with
    `debug_assert!(prev > 0)`; prunes HashMap entry when count
    hits zero.
  - `events_stream` reads fingerprint from extensions; returns
    distinguishable 503s.

- **`src/lib.rs`** — re-exports:
  - `pub use TokenFingerprint, SseCaps`.
  - `#[cfg(feature = "test-helpers")] pub const
    MAX_SSE_SUBSCRIBERS_PER_TOKEN`.
  - `#[cfg(feature = "test-helpers")] pub fn
    with_full_capability_for_fingerprint(router, fp)`.

- **`Cargo.toml`** — new workspace dep `sha2 = "0.10"`.

### selfdef-cli

- **`src/follow.rs`** — major refactor:
  - `SseParser::feed_bytes(&[u8])` replaces `feed(&str)`. The
    buffer is `Vec<u8>`; UTF-8 conversion at line boundaries
    (newline-bounded). Multi-byte codepoints split across
    chunks reassemble cleanly (F-2028-018 closure).
  - `read_token_file` mirrors daemon-side `read_token`:
    `mode & 0o077 == 0` check + Unicode `.trim()` (F-2028-004
    + -005 closures).
  - `events_follow_tcp` parses `{"error": "..."}` JSON 503
    bodies and surfaces the typed reason (F-2028-016 closure).
  - Module `//!` header lists all three entry points + names
    the byte-semantic parity requirement between transports
    (F-2028-007 + -019 closures).
  - `events_follow_tcp` doc-comment names the
    `Authorization: Bearer <t>` wire format (F-2028-006
    closure).

- **`src/main.rs`** — `Follow` clap variant's doc-comment now
  explicitly names the `conflicts_with` / `requires` constraint
  structure in prose (F-2028-010 closure).

- **`src/paths.rs`** — compile-time `const _: () = { … }` block
  asserts every default path constant starts with
  `/etc/selfdef/` and `AGENT_GUARD_CONFIG` lives under
  `MODULES_PER_MODULE_DIR` (F-2028-001 closure).

- **`src/init.rs::STARTER_CONFIG`** — `[api]` block now
  documents `max_sse_subscribers` + `max_sse_subscribers_per_token`
  (commented at defaults).

- **`src/init.rs::STARTER_MODULES`** — each per-module block now
  has a trailing `# 0640 root:selfdef` comment naming the safe-
  copy invariant. Mid-section reminder added (F-2028-022
  closure).

- **`Cargo.toml`** — no new deps in Phase 3.

### selfdef-config

- **`src/lib.rs::ApiConfig`** — two new optional fields:
  `max_sse_subscribers: Option<usize>` and
  `max_sse_subscribers_per_token: Option<usize>`, both
  `#[serde(default)]` so existing TOML configs keep working
  unchanged.

### selfdef-daemon

- **`src/main.rs`** — API startup now passes the two new
  config values to `ApiState::with_sse_caps(SseCaps { global,
  per_token })`. Empty/None falls back to compiled-in defaults.

## Module-side machinery

- **vpn-bridge** completed SDD-006 v2 manifest helpers migration
  (closure of F-2028-015). `lib.sh` bumped to `VERSION_REQUIRED=2`;
  `relay-via-server.sh::profile_apply` calls
  `module_record_file "$nft_path"`; `profile_uninstall` iterates
  `module_render_files` with legacy fallback for pre-v2 installs.

## Documentation surface

Phase 3 itself shipped seven explorer docs + one SDD:

- `docs/review/phase-3/00-charter.md`
- `docs/review/phase-3/10-inventory.md`
- `docs/review/phase-3/20-recent-prs-audit.md`
- `docs/review/phase-3/30-crate-audit.md`
- `docs/review/phase-3/40-module-audit.md`
- `docs/review/phase-3/50-integration-audit.md`
- `docs/review/phase-3/60-docs-audit.md`
- `docs/review/phase-3/70-tests-audit.md`
- `docs/review/phase-3/80-security-audit.md`
- `docs/review/phase-3/99-findings-ledger.md`
- `docs/sdd/007-per-token-sse-subscriber-quota.md` (implemented).

CHANGELOG: every closure PR adds a section.

## Test-infrastructure refactors

- **`crates/selfdef-cli/tests/common/mod.rs`** — no API changes;
  10 test files in `crates/selfdef-cli/tests/` now import
  `assert_tree_unchanged` and `snapshot_tree` directly (F-2028-025
  closure).

- **`crates/selfdef-api/tests/m12_api.rs`** — gains 7 new test
  cases (per-token cap, per-token isolation, drop-prunes,
  per-token override, global override; plus the SSE-503 typed-
  reason test in `cli_events_follow_tcp.rs`).

- **`crates/selfdef-cli/tests/cli_events_follow_tcp.rs`** — gains
  2 new cases:
  - `events_follow_token_file_refuses_world_readable_mode`
    (F-2028-004 closure).
  - `events_follow_url_surfaces_cap_reached_reason_on_503`
    (F-2028-017 closure).

- **`crates/selfdef-cli/tests/module_vpn_bridge.rs`** — gains
  `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it`
  (F-2028-015 closure).

## Numbers

- ~17 PRs merged during the Phase 3 closure cycle.
- 0 new crates.
- 1 new SDD (SDD-007).
- 2 new operator-tunable `[api]` config knobs.
- 1 new module migration to SDD-006 v2 (vpn-bridge → 100% v2
  coverage for non-exempt modules).
- ~10 new tests across the workspace.
- ~700 lines added net per `git diff --stat f40bf05..8b44322`.
