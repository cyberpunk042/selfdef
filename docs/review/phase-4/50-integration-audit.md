# Phase 4 — Integration audit

> Scope (per the Phase 4 charter): the seven new post-Phase-3 integration seams
> introduced by the ~17 closure PRs (commits `f40bf05` → `8b44322`). Per-seam ids
> prefix `I4-` and roll up to the ledger as `F-2029-NNN`.
>
> What this audit doesn't re-litigate: Phase 3's six integration flows
> (every `I3-NNN` / `F-2028-016..019` that closed in those PRs). If a Phase 3
> fix is broken, that's a new `F-2029-NNN` with a back-reference.

## Headlines

- **2 nice findings, 0 blockers, 0 important**. Five of the seven seams hold
  under the closure code with no integration gaps. Two observations are
  test-coverage refinements that surface edge cases in the operator-config
  knob wiring. No integration contract drift.

## Seam-by-seam notes

### Seam 1 — `bearer_auth` → `TokenFingerprint` → `events_stream` extension flow

**Verification path**: `crates/selfdef-api/src/transport.rs::bearer_auth` (lines 382-426) →
`crates/selfdef-api/src/handlers.rs::events_stream` (line 253).

The middleware computes `TokenFingerprint::of(presented_token)` at line 420 and
threads it into `request.extensions_mut()` at line 423. The handler reads it
back at line 253: `request.extensions().get::<TokenFingerprint>().copied()`.

The fingerprint is never stored in memory longer than the request scope. Anonymous
UNIX-socket requests (via `with_full_capability`) don't get a fingerprint at all
— the middleware only inserts it when `presented` is `Some(...)` (line 422), which
only happens when bearer-auth succeeds (line 405-408). The per-token cap guard
correctly treats `None` as "skip per-token; only count global" (lines 160-177 in
handlers.rs).

**Observations**:
- Extension threading is correct. The fingerprint survives the middleware boundary
  and reaches the cap-check code unmolested.
- Anonymous UNIX-socket clients (Full-capability + no fingerprint) correctly bypass
  per-token capping and count only against the global cap. This is the intended
  behaviour (comments at lines 129 + 252 in handlers.rs confirm the design).
- ✓ No seam gap.

### Seam 2 — Per-token cap ↔ global cap ↔ operator config knobs

**Verification path**: `crates/selfdef-api/src/handlers.rs::SubscriberGuard::try_acquire`
(lines 142-209), reading `state.sse_caps: SseCaps` (state.rs line 65).

The `try_acquire` function:
1. Consults `state.sse_caps.global` and falls back to `MAX_SSE_SUBSCRIBERS = 64`
   when `None` or `Some(0)` (lines 149-152).
2. Consults `state.sse_caps.per_token` and falls back to `MAX_SSE_SUBSCRIBERS_PER_TOKEN = 8`
   (lines 153-156).
3. Checks per-token first (lines 160-177); returns `PerTokenCap` error if saturated.
4. Falls back to global (lines 179-208); returns `GlobalCap` error if saturated.

Critically, when per-token rejection happens at line 171, the function **returns
immediately** without incrementing the global counter — the per-token rejection
prevents the global CAS loop (line 194+) from ever running. This is correct: no
per-token slot leak.

Operator-override tests (`events_stream_per_token_cap_honours_operator_override` +
`events_stream_global_cap_honours_operator_override` in m12_api.rs) verify that
per-token `Some(2)` saturates at the 3rd connection and global `Some(1)` saturates
at the 2nd. The `Some(0)` fallback contract is pinned by `events_stream_zero_caps_fall_back_to_defaults`.

**Observations**:
- Cap interaction is correct. Per-token rejection short-circuits before global
  increment, so no slot leak. ✓
- Override contract is tested at per-token and global level; both pass. ✓
- No seam gap.

### Seam 3 — SDD-007 D-4 config knobs ↔ daemon startup wiring

**Verification path**: `crates/selfdef-config/src/lib.rs::ApiConfig` (lines 512-519) →
`crates/selfdef-daemon/src/main.rs` (lines 194-197) → `crates/selfdef-api/src/state.rs::ApiState::with_sse_caps`
(line 103).

Hop 1: `selfdef-config` parses `[api].max_sse_subscribers` and `max_sse_subscribers_per_token`
as `Option<usize>` with `#[serde(default)]` (lines 512, 519). Both default to `None`.

Hop 2: The daemon's startup (lines 194-197 in main.rs) reads `cfg.api.max_sse_subscribers`
and `cfg.api.max_sse_subscribers_per_token`, wraps them in a `SseCaps { global, per_token }`
struct, and passes to `.with_sse_caps(…)`.

Hop 3: `ApiState::with_sse_caps` (state.rs line 103) mutates `self.sse_caps = caps`
and returns `self`.

Hop 4: `events_stream` calls `SubscriberGuard::try_acquire(&s, fingerprint)`, which
reads `s.sse_caps.global` and `s.sse_caps.per_token` (handlers.rs lines 149, 153).

Each hop preserves the operator's value correctly. `None` propagates through all
four layers and is treated identically as "use the default" at the final check
(handlers.rs lines 150-151, 154-155).

**Observations**:
- **I4-001**: The config knobs flow through the daemon startup pipeline correctly
  (Hops 1-3 are verified). However, there is **no end-to-end test** that exercises
  the full chain: a TOML config file with `max_sse_subscribers` set → daemon loads it →
  API state carries the value → a cap-saturating request observes the operator's
  override and refuses at the right limit. The API-level tests mock the `SseCaps`
  struct directly (e.g., `with_sse_caps(SseCaps { global: Some(2), … })`), and the
  daemon startup code reads the config and threads it through (manually verified).
  But no test exercise both together. A future refactor of the cap-check logic or
  the config field name could drift without triggering a test failure.
  
  Add a fixture in `crates/selfdef-daemon/tests/` (if one exists) or create a new
  integration test that: (1) writes a selfdef.toml with `[api].max_sse_subscribers = 2`,
  (2) loads the config via `Config::load()`, (3) passes it to the daemon's API startup,
  (4) verifies the ApiState's `sse_caps` field has the value 2. **(I4-001, nice)**

### Seam 4 — TCP-follow ↔ JSON-503 ↔ typed reasons

**Verification path**: `crates/selfdef-cli/src/follow.rs::events_follow_tcp` (lines 349-357) →
`crates/selfdef-api/src/handlers.rs::events_stream` (lines 259-270).

When `events_stream` saturates, it returns `ApiError::with_status(StatusCode::SERVICE_UNAVAILABLE, "per-token sse cap reached")`
or `"sse subscriber cap reached"` (lines 260-269 in handlers.rs). The middleware
serializes this to JSON: `{"error": "per-token sse cap reached"}`.

The TCP-follow client receives the 503 response body (line 342), parses it as JSON,
extracts the `error` field, and surfaces it in the error message (lines 349-357):
`anyhow::bail!("daemon refused /events/stream: HTTP {} {}", status, detail)`.

The test `events_follow_url_surfaces_cap_reached_reason_on_503` in cli_events_follow_tcp.rs
verifies this: saturate the cap, trigger a 503, assert the CLI's error message names
the reason.

**Observations**:
- JSON extraction logic is correct. The parser handles non-JSON bodies gracefully
  (unwraps to the raw text at line 352 if JSON parse fails). ✓
- Test coverage exists. ✓
- No seam gap.

### Seam 5 — vpn-bridge SDD-006 v2 ↔ manifest persistence

**Verification path**: `modules/vpn-bridge/install/lib.sh` (provides `module_record_file`) →
`modules/vpn-bridge/install/profiles/relay-via-server.sh::profile_apply` (line 122) →
`profile_uninstall` (lines 200-217).

On apply (line 122), the profile calls `module_record_file "$nft_path"` to write the
rendered nftables config path into the manifest file at `${MODULE_INSTALLED_MANIFEST}`
(default `/var/lib/selfdef/installed/vpn-bridge.manifest`).

On uninstall (lines 206-212), the profile iterates the manifest via `module_render_files`
and removes each file. Legacy fallback (lines 213-216) handles pre-v2 installs where
the manifest doesn't exist.

The test `relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it` in
module_vpn_bridge.rs verifies: (1) apply writes the path, (2) manifest contains it,
(3) uninstall reads it and clears it.

The manifest persists across config changes (apply → uninstall → apply with different config)
because the manifest file is re-written by each apply's `module_record_file` call.
Pre-v2 → v2 upgrade path works: uninstall checks the manifest first (line 206); if empty,
falls back to the hard-coded path (line 213).

**Observations**:
- Manifest tracking is correct. The enumeration-based uninstall is more robust than
  hard-coding (supports multi-instance deployments where paths include `${SELFDEF_INSTANCE_ID}`).
- Test coverage exists and verifies the round-trip. ✓
- Legacy fallback is present. ✓
- No seam gap.

### Seam 6 — STARTER_CONFIG SSE caps ↔ daemon parse

**Verification path**: `crates/selfdef-cli/src/init.rs::STARTER_CONFIG` (lines 200-206) →
`crates/selfdef-config/src/lib.rs::ApiConfig` (parsing) → `crates/selfdef-daemon/src/main.rs`
(startup).

The init template documents the two knobs at lines 200-206:
```toml
# max_sse_subscribers           = 64
# max_sse_subscribers_per_token = 8
```

The config struct parses them (selfdef-config/src/lib.rs lines 512, 519). The daemon
startup wires them (main.rs lines 195-196). All documented, all wired.

**Observations**:
- **I4-002**: The STARTER_CONFIG documentation is correct and the parsing/wiring
  is present. However, there is **no test fixture** that directly exercises the
  documented template. A future operator who copies the STARTER_CONFIG as-is
  (with the two lines commented out) and expects the defaults to take effect
  is covered. But a test that (1) writes a real TOML using the STARTER_CONFIG
  template, (2) sets the two knobs to non-default values, (3) verifies the
  daemon's ApiState reads them would catch drift in the field names or parsing.
  
  Add a config-round-trip test: parse STARTER_CONFIG (or a snippet of it),
  verify the default fallback works, then override the two fields and verify
  the daemon reads the overrides. **(I4-002, nice)**

### Seam 7 — SseParser `feed_bytes` ↔ both transports

**Verification path**: `crates/selfdef-cli/src/follow.rs::SseParser::feed_bytes` (lines 97-161) ←
`events_follow_unix` (line 300) + `events_follow_tcp` (line 370).

Both transports feed raw bytes:
- UNIX: `let frames = parser.feed_bytes(&body);` where `body: Vec<u8>` (line 300).
- TCP: `for frame in parser.feed_bytes(&bytes)` where `bytes: reqwest::Bytes` (line 370).

The parser buffers raw bytes internally (line 82: `buf: Vec<u8>`), scans for `\n`
(line 101), then decodes to UTF-8 **line-at-a-time** (line 113). A multi-byte UTF-8
sequence split across chunk boundaries is reassembled in the buffer before decoding,
so no U+FFFD corruption.

The test suite includes unit tests for multi-byte round-trips (module doc lines 71-79
reference F-2028-018 closure). The transports themselves are tested end-to-end
(`events_follow_unix` and `events_follow_tcp` have integration tests in
cli_events_follow_tcp.rs).

**Observations**:
- Byte-semantic parity is correct. Both transports feed raw bytes; the parser
  handles reassembly. ✓
- Unit tests cover multi-byte split-boundary cases. ✓
- Module doc (lines 24-29 in follow.rs) explicitly names the requirement:
  "both transports hand the parser **raw bytes** via `SseParser::feed_bytes`".
- No seam gap.

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| I4-001 | nice | SDD-007 D-4 config knobs lack end-to-end test (config file → daemon → API state) | seam-3 |
| I4-002 | nice | STARTER_CONFIG SSE caps lack direct round-trip test (TOML parse → daemon read) | seam-6 |

Both findings are test-coverage shaped. All seven seams hold under the closure
code. No breaking integration contracts.
