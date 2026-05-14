# Phase 5 — Crate audit

> Scope: Rust code introduced during the Phase 4 closure cycle
> (8 PRs, commits `22ff461` Phase 4 audit kickoff scaffold → `d239dad`
> Phase 4 security explorer).
>
> Audits: `TokenFingerprint` custom `Debug` impl (4-byte hex prefix
> truncation); two new fingerprint unit tests; one integration test for
> `Some(0)` cap fallback; two `selfdef-config` round-trip tests for SSE
> cap knobs.
>
> Methodology: same as Phase 4's crate explorer. Verify each test correctly
> pins what it claims; check isolation; cross-check claims against impl;
> verify edge case handling. Does not re-litigate Phase 4's findings
> (F-2029-002..007) — those are closed.

## Headlines

- **No findings.** The Phase 4 closure cycle's thin Rust surface is sound.
  The `TokenFingerprint` `Debug` impl is correctly implemented and
  defended by shape/hex/length assertions. The `Some(0)` fallback test
  explicitly pins the guarded pattern (`n > 0` check) so a future refactor
  dropping the guard fails immediately. The config round-trip tests verify
  the parse hop under both override and default cases, closing the gap
  between TOML and in-memory representation.

## Per-file notes

### selfdef-api: transport.rs — TokenFingerprint custom Debug impl

Lines 366-379: custom `impl std::fmt::Debug for TokenFingerprint` replaces
the derived version, rendering only the leading 4 bytes (8 hex chars) as
`TokenFingerprint(a3b9c012…)`.

#### Observations

**Zero findings.** The impl is correct:
- Byte order is the standard little-endian slice indexing (`self.0[0]` through
  `self.0[3]` yields the first 4 bytes of the 32-byte array).
- The `{:02x}` format specifier produces exactly 2 hex digits per byte × 4 = 8
  hex chars, matching the comment claim.
- The Unicode ellipsis character (U+2026, `…`) is consistent between the impl
  and the test assertions (verified at UTF-8 level: both use
  `\xe2\x80\xa6`).
- The doc-comment (lines 342-348) correctly describes the threat model
  (fingerprints as stable identifiers) and the mitigation (32-bit entropy
  remains unrevealed).

### selfdef-api: transport.rs — fingerprint_tests unit tests

Lines 668-714: new `#[cfg(test)]` module with two unit tests.

#### Observations

**Zero findings.** Both tests are well-isolated and correctly verify the
contract:

- **`debug_renders_truncated_prefix` (lines 675-703):** Constructs a
  `TokenFingerprint` from `"alice"`, formats it with `{:?}`, and asserts:
  - Prefix `"TokenFingerprint("`
  - Suffix `"…)"` (the ellipsis)
  - Exactly 8 hex chars between them (4 bytes)
  - All chars are ASCII hex digits
  
  The test does not hard-code the exact bytes (wisely, to avoid re-binding
  on SHA-256 implementation changes). The shape assertions are tight
  enough to catch format regressions.

- **`distinct_tokens_produce_distinct_debug_prefixes` (lines 705-713):**
  Computes Debug forms for `"alice-token"` and `"bob-token"`, asserts
  they're different. The comment correctly notes that 2^32 collisions are
  negligible at the SHA-256 level.

Both tests run in isolation (no shared state, each creates fresh
`TokenFingerprint` instances). No flakiness risk.

### selfdef-api: tests/m12_api.rs — events_stream_zero_caps_fall_back_to_defaults

Lines 890-916: integration test that sets both SSE caps to `Some(0)` and
asserts the first `/events/stream` request succeeds (200 OK).

#### Observations

**Zero findings.** The test correctly pins the fallback contract:

- **Setup:** `SseCaps { global: Some(0), per_token: Some(0) }` (lines 895-898).
  The test uses `app_for_token()` helper (line 880-881) which wraps the
  router with a test-gated helper `with_full_capability_for_fingerprint`
  that injects a specific `TokenFingerprint` without real bearer-auth.

- **Assertion:** Expects 200 OK (line 911-914). The comment on line 904
  correctly describes the regression it catches: if `try_acquire` ever
  stops checking `n > 0` and treats `Some(0)` as "disable the cap"
  (unlimited subscribers), this test saturates immediately and fails.

- **Cross-check:** Verified in handlers.rs line 150-151 and 156 that the
  guard exists: `Some(n) if n > 0 => n, _ => MAX_SSE_SUBSCRIBERS`. The
  `Some(0)` case falls through to the default. The test failure mode
  (saturate on first request if guard is removed) is tight.

- **Isolation:** Each test gets fresh `ApiState` via `build_state()`
  (lines 25-63), which creates a new tempdir, Bus, and SqliteStore. No
  cross-test interference.

### selfdef-config: src/lib.rs — config round-trip tests

Lines 596-645: two new unit tests in the `tests` module.

#### Observations

**Zero findings.** Both tests are well-formed and correctly verify the
round-trip:

- **`sse_cap_knobs_round_trip_from_toml` (lines 597-622):** Creates a
  temporary TOML file with:
  ```toml
  [api]
  enabled = true
  max_sse_subscribers = 16
  max_sse_subscribers_per_token = 4
  ```
  Calls `Config::load(Some(tmp.path()))` and asserts the parsed result
  has `Some(16)` and `Some(4)` (lines 613-621). The test correctly verifies
  the parse hop: TOML → `Option<usize>`.

- **`sse_cap_knobs_default_to_none_when_unset` (lines 630-645):** Creates
  a minimal TOML with only `[api].enabled = true`, asserts both cap fields
  parse as `None`. This test pins the default contract: when the TOML omits
  the knobs, `ApiConfig::default()` (lines 537-550) yields `None` for both,
  which the daemon's fallback logic (handlers.rs line 150-151, 156) later
  interprets as "use compiled-in defaults".

  The test guards against a future `#[serde(default)]` regression that
  could inadvertently yield `Some(0)` instead of `None` — the integration
  test above would then catch the semantics change, but this config test
  catches the parse change at the source.

- **Isolation:** Each test creates a fresh `NamedTempFile` (via
  `tempfile::NamedTempFile::new()`). No cross-test state sharing.

- **Cross-check:** Verified that both fields carry `#[serde(default)]`
  (lines 511, 518) which ensures missing fields parse as `None` (the trait
  default for `Option<T>`). The doc-comments (lines 507-519) correctly
  document the fallback semantics: "`None` (or 0) means use hardcoded
  default".

## Edge case analysis

### Debug impl edge cases
- **All-zero bytes** (worst case for distinctness): Renders as
  `TokenFingerprint(00000000…)`. Distinct from other fingerprints.
- **All-0xFF bytes**: Renders as `TokenFingerprint(ffffffff…)`. Distinct
  from others. Tests don't require exact bytes; shape assertions are
  sufficient.
- **Unicode ellipsis encoding:** Consistent across impl and tests (verified
  UTF-8 byte-level match `\xe2\x80\xa6`). No encoding risk.

### Config parsing edge cases
- **Negative values:** `Option<usize>` rejects negative literals at parse
  time (Rust's unsigned type constraint). No sign-extension risk.
- **Overflow:** TOML parser and `Option::into()` handle usize limits. Out
  of scope for this audit (parser layer, not domain logic).
- **Whitespace/trimming:** The TOML crate (figment) handles standard
  whitespace. No injection risk.

## Triage

**Zero findings.** All three code paths (custom Debug impl, 3 unit tests, 2
integration tests) are correct, well-isolated, and defend their contracts
against the specific regressions they were designed to catch.

### Summary

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| *(none)* | | | | |

## Closing notes

The Phase 4 closure cycle's Rust surface is the smallest yet (net ~5 tests
+ 1 impl refactor), and every piece is sound. The `TokenFingerprint` Debug
elision successfully removes the cross-time-linkage primitive while keeping
diagnostic value. The `Some(0)` fallback test is tight and would catch a
guard removal immediately. The config round-trip tests close the gap
between TOML deserialization and in-memory representation, guarding both
the override and default-unset cases.

Phase 5's recent-PRs explorer reported 0 findings. This crate explorer
also reports **0 findings**. The Phase 4 closure delivery was exceptionally
clean.
