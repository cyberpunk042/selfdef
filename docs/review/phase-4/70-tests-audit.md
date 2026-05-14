# Phase 4 — Tests audit

> Scope (per the Phase 4 charter): the new test cases and test
> infrastructure shipped during the Phase 3 closure cycle
> (commits `f40bf05` → `8b44322`). Audit the ~10 new tests, the
> F-2028-025 common-mod import migration adoption across 10 module-test
> files, the new SDD-007 per-token SSE cap tests, the SseParser multibyte
> UTF-8 split tests, and the new test-helpers in `selfdef-api/src/lib.rs`.
>
> This audit mirrors the Phase 3 tests explorer's methodology: search for
> real-time sleeps (SDD-005 forbids them outside specific scenarios),
> parallel-isolation gaps, flaky patterns, and coverage gaps.

## Headlines

- **No blockers, no important findings**. The Phase 3 closure-cycle
  test work is clean: all 10 new tests are well-scoped, integration tests
  properly use per-test `tempfile::tempdir()` isolation, and the UTF-8
  split tests correctly pin their boundary-case claims. The common-mod
  import migration from F-2028-025 is complete.
- **1 nice finding** — the per-token cap drop-to-zero test (D-5.5) uses
  a real-time `100ms` sleep without `start_paused`, but this is
  deliberate and documented. The test's purpose (verify that a HashMap
  entry is pruned after the last subscriber drops) requires async task
  scheduling, not virtual time.
- **0 demoted findings**.

## Per-area observations

### Area 1 — Per-token SSE cap tests (SDD-007 D-4 / D-5)

All five tests in `crates/selfdef-api/tests/m12_api.rs` correctly pin
the contract:

- **`events_stream_zero_caps_fall_back_to_defaults`** (lines 891–916):
  sets `SseCaps { global: Some(0), per_token: Some(0) }` and asserts the
  first stream succeeds. Pins the contract that `Some(0)` is not treated
  as "cap at zero" but as "operator explicitly chose zero → fall back to
  default". **(closure of F-2029-003)**

- **`events_stream_per_token_cap_honours_operator_override`** (lines
  922–962): sets `per_token: Some(2)`, opens 2 streams, and asserts the
  3rd is refused with 503 carrying the per-token typed reason. Covers D-4
  (operator override) + D-6 (distinguishable 503 body). **(D-4/-5.1 coverage)**

- **`events_stream_global_cap_honours_operator_override`** (lines
  966–998): sets `global: Some(1)`, opens 1 stream, asserts the 2nd is
  refused with 503 carrying the global typed reason. Covers D-4 + D-6.
  **(D-4 coverage)**

- **`events_stream_per_token_cap_reached`** (lines 1003–1040): D-5.1 —
  uses `MAX_SSE_SUBSCRIBERS_PER_TOKEN` (8) to saturate a single token's
  slice; the 9th request is refused with the per-token typed reason.
  Each test run creates a fresh state so fingerprints don't cross-pollute.

- **`events_stream_per_token_cap_does_not_affect_other_tokens`** (lines
  1044–1080): D-5.2 — saturates token A's slice, then shows token B can
  still connect. Both routers use the same cloned state so per-token
  isolation is tested in-process. **(D-5.2 coverage)**

- **`events_stream_per_token_counter_drops_to_zero_on_disconnect`** (lines
  1085–1130): D-5.5 — opens a stream, drops the response, publishes an
  event to wake the writer, yields 10 times, then sleeps 100ms real-time
  (line 1121), and asserts the HashMap entry was pruned. **(D-5.5 coverage,
  see F-2029-008 for timing note)**

All tests use `app_for_token(state, fingerprint)` to wrap the router with
`with_full_capability_for_fingerprint` (lines 880–882), which threads the
fingerprint into extensions post-auth (exactly the daemon's bearer-auth
state). State is cloned across token calls so the HashMap is shared and
per-token isolation is verified.

### Area 2 — SseParser multibyte UTF-8 split tests

Both tests in `crates/selfdef-cli/src/follow.rs::tests` (lines 517–561)
correctly exercise the F-2028-018 boundary cases:

- **`parser_reassembles_multibyte_utf8_split_across_chunks`** (lines
  522–539): 4-byte sequence for 🦀 (`[0xF0, 0x9F, 0xA6, 0x80]`). First
  call feeds 2 bytes (prefix + `crab[..2]`), second feeds the remaining 2
  bytes + suffix. Asserts the output is the complete codepoint, not
  replacement characters. The test correctly isolates the UTF-8-split
  scenario by cutting mid-codepoint. **(F-2028-018 / 4-byte coverage)**

- **`parser_reassembles_3byte_utf8_split_across_chunks`** (lines 546–561):
  3-byte sequence for 漢 (`[0xE6, 0xBC, 0xA2]`). First call feeds only 1
  byte (prefix + `han[0]`), second feeds remaining 2 bytes + suffix.
  Asserts the complete codepoint is present. Tests the most-common non-ASCII
  case (BMP CJK glyphs, Latin-1 extended). **(F-2028-018 / 3-byte coverage)**

Both tests use `SseParser::feed_bytes(&[u8])` (the post-refactor API), not
the pre-refactor `feed(&str)`, confirming the integration of the bytes-buffer
fix.

### Area 3 — CLI integration tests

Three new tests added to CLI test files verify surface behavior:

- **`events_follow_token_file_refuses_world_readable_mode`** (cli_events_follow_tcp.rs,
  lines 271–297): creates a token file with mode `0o644`, invokes the
  CLI, asserts stderr names the offending mode. Uses `tempfile::tempdir()`
  per-test. **(F-2028-004 closure / mode-check parity)**

- **`events_follow_url_surfaces_cap_reached_reason_on_503`** (cli_events_follow_tcp.rs,
  lines 207–262): spawns the API on loopback, saturates the global cap with
  in-process reqwest streams, invokes the CLI subprocess within `spawn_blocking`,
  and asserts stderr contains both "503" and "sse subscriber cap reached".
  Isolates subprocess spawning from the current_thread runtime. **(F-2028-017
  closure / TCP 503 typed reason)**

- **`relay_apply_records_nft_path_in_manifest_then_uninstall_clears_it`** (module_vpn_bridge.rs,
  lines 248–319): runs the vpn-bridge relay apply, verifies nft_path is
  recorded in the manifest via SDD-006 v2 helpers, runs uninstall,
  asserts the path is removed. Uses `tempfile::tempdir()` for scratch
  paths and stubs for nft/systemctl/wg. **(F-2028-015 closure /
  manifest round-trip)**

All three tests use per-test isolation (tempdir or current_thread + spawn_blocking).
No shared host-global paths or environment pollution observed.

### Area 4 — Config round-trip tests (selfdef-config)

Two new tests in `crates/selfdef-config/src/lib.rs::tests` (lines
596–645) pin the D-4 TOML parse hop:

- **`sse_cap_knobs_round_trip_from_toml`** (lines 597–622): writes TOML
  with `max_sse_subscribers = 16` and `max_sse_subscribers_per_token = 4`,
  loads via `Config::load`, asserts both fields are `Some(16)` and `Some(4)`.
  Pins the parse → Option conversion. **(F-2029-005 closure)**

- **`sse_cap_knobs_default_to_none_when_unset`** (lines 630–645): writes
  TOML with no cap knobs, loads via `Config::load`, asserts both fields
  are `None`. Pins the unset → `None` contract (fallback to defaults
  happens downstream in the daemon). **(F-2029-005/-006 closure)**

Together with the handler-side tests (`events_stream_per_token_cap_honours_operator_override`
+ `events_stream_global_cap_honours_operator_override`), the TOML → ApiConfig
→ SseCaps → handler chain is end-to-end tested.

### Area 5 — TokenFingerprint Debug-impl tests

Two new tests in `crates/selfdef-api/src/transport.rs::tests` (lines
675–713) pin the custom Debug impl (F-2029-002 closure):

- **`debug_renders_truncated_prefix`** (lines 676–703): calls `format!("{fp:?}")`
  on a fingerprint, asserts it starts with `TokenFingerprint(`, ends with
  `…)`, and contains exactly 8 hex characters (4-byte prefix). The test
  explicitly notes it asserts shape rather than the exact 32-byte hash so
  future algorithm changes don't require lockstep test updates. **(F-2029-002
  closure)**

- **`distinct_tokens_produce_distinct_debug_prefixes`** (lines 706–713):
  calls Debug on two different fingerprints ("alice-token" vs "bob-token"),
  asserts the Debug forms are distinct. Verifies the prefix is not
  accidentally constant. **(F-2029-002 closure)**

Both tests verify the truncation contract (full hash not exposed) without
over-pinning the exact bytes.

### Area 6 — Common-mod import migration (F-2028-025)

All 10 module-test files now import `assert_tree_unchanged` and
`snapshot_tree` directly (not via qualified paths):

Files checked:
- `module_agent_guard.rs`
- `module_bridge_l2.rs`
- `module_integrity_sentinel.rs`
- `module_observability.rs`
- `module_polarproxy.rs`
- `module_suricata.rs`
- `module_tetragon.rs`
- `module_tetragon_signing.rs`
- `module_vpn_bridge.rs`
- `module_vpn_bridge_cloudflare.rs`
- `module_vpn_bridge_tailscale.rs`

(Note: `module_tetragon_signing.rs` does not call `snapshot_tree` or
`assert_tree_unchanged`, so it correctly omits them from imports.)

All files now use `use common::{…snapshot_tree…assert_tree_unchanged…}`
consistently. **(F-2028-025 closure)**

### Area 7 — Test-helper additions (lib.rs)

Both test-helpers are cleanly gated behind the `test-helpers` Cargo
feature:

- **`with_full_capability_for_fingerprint(router, fp)`** (lib.rs, lines
  64–82): wraps the router with a middleware that threads both
  `Capability::Full` and a specific `TokenFingerprint` into extensions.
  Gated by `#[cfg(feature = "test-helpers")]` so it disappears from
  release builds. Used by the per-token cap tests to pin fingerprint
  isolation without real bearer-auth. **(SDD-007 D-5 test support)**

- **`MAX_SSE_SUBSCRIBERS_PER_TOKEN` re-export** (lib.rs, line 94): re-exports
  the constant from `handlers` behind `#[cfg(feature = "test-helpers")]`.
  Used by the per-token cap saturation tests to drive the cap
  deterministically. **(SDD-007 D-5 test support)**

Both exports are feature-gated and carry explicit comments about the test-only
nature. No production code can accidentally depend on them.

## Observation: D-5.5 drop-to-zero test timing

### F-2029-008 — Per-token drop-to-zero test uses real-time sleep

**Severity:** nice  
**Surface:** `events_stream_per_token_counter_drops_to_zero_on_disconnect`
(m12_api.rs:1085–1130) at line 1121 uses `tokio::time::sleep(100ms)`
without the test being marked `#[tokio::test(start_paused = true)]`.  
**Evidence:**  
- Test decorator is `#[tokio::test]` (line 1085), not `#[tokio::test(flavor = "current_thread", start_paused = true)]`.
- Calls `tokio::time::sleep(std::time::Duration::from_millis(100))` at line 1121.
- Comments at lines 1102–1105 explain why: "The drop chain is async, so we
  publish a bus event to wake the writer + give the runtime a tick."
- The test's purpose is to verify that the HashMap entry is pruned after
  the last subscriber drops — a process involving async task scheduling
  (writer task's `tx.send` fails → `SubscriberGuard::Drop` executes).

**Analysis:**  
The real-time sleep is deliberate and documented. The test spawns a bus
event to wake the writer task, then needs the task scheduler to actually
run the drop chain. While the test yields 10 times before sleeping, that's
not guaranteed to let an async task complete; the sleep provides the
runtime scheduling breathing room. A `start_paused` test with `pause()`
would deadlock here because the writer task is parked (not actively polling)
when the response is dropped, and no further event is forthcoming to wake it
after the drop.

However, SDD-005 (Phase 2's SDD) established that real-time sleeps are
forbidden outside specific scenarios (pub/sub task timing, I/O blocking).
This test falls into the "async task scheduling" gray area — it's not
virtual-time testable without refactoring the handler to be more
drop-eager or using a notification-based synchronization primitive
(Channel, Condvar, etc.).

**Next phase:** nice — This is a known pattern (async task scheduling
breathing room). No action needed; document in future test-pattern guide.
The test correctly pins the D-5.5 contract despite the timing hazard.

## Triage

| ID | Severity | Surface | Next phase |
| --- | --- | --- | --- |
| F-2029-008 | nice | Per-token drop-to-zero test uses 100ms real-time sleep for async task scheduling | none (documented pattern; SDD-005 gray area) |

## Summary

The Phase 3 closure cycle's test additions are thorough and well-scoped:

- **Per-token cap tests**: 5 tests cover D-4 (operator override) and D-5
  (isolation, saturation, pruning) with correct fingerprint threading.
- **UTF-8 split tests**: 2 tests correctly exercise 4-byte and 3-byte
  boundary cases at precise split points.
- **CLI integration tests**: 3 tests verify cap-reached reason, token-mode
  refusal, and manifest round-trip with proper isolation.
- **Config round-trip tests**: 2 tests pin the TOML parse hop for the
  D-4 config knobs.
- **TokenFingerprint Debug tests**: 2 tests verify truncated-prefix shape
  and distinctness without over-pinning exact bytes.
- **Common-mod migration**: All 10 module-test files complete the F-2028-025
  import consistency migration.
- **Test-helpers**: Both `with_full_capability_for_fingerprint` and
  `MAX_SSE_SUBSCRIBERS_PER_TOKEN` are feature-gated and clean.

**0 blockers, 0 important, 1 nice.** The nice finding is a documented
pattern (async task scheduling breathing room) that doesn't warrant action.
