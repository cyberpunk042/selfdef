# Phase 5 — Tests audit

> Scope (per the Phase 5 charter): the 3 incremental tests shipped during the
> Phase 4 closure cycle that fall outside the crate-explorer's remit:
>
> - `events_stream_zero_caps_fall_back_to_defaults` (selfdef-api integration)
> - `sse_cap_knobs_round_trip_from_toml` (selfdef-config unit)
> - `sse_cap_knobs_default_to_none_when_unset` (selfdef-config unit)
>
> The two new `fingerprint_tests` unit tests in
> `crates/selfdef-api/src/transport.rs` were audited in
> [`30-crate-audit.md`](./30-crate-audit.md) (Debug-impl side) and are not
> re-litigated here.
>
> Methodology mirrors the Phase 4 tests explorer: hunt for real-time sleeps
> (SDD-005 boundary), parallel-isolation gaps, flaky patterns, false-confidence
> assertions, and coverage gaps relative to the contract each test claims to
> pin.

## Headlines

- **No findings.** Sixth consecutive Phase 5 explorer to come up clean. The
  three incremental tests are well-isolated, deterministic, and pin precisely
  the contract their docstrings claim. No real-time sleeps were introduced
  (the only SDD-005 gray-area test in the broader closure cycle, the
  drop-to-zero D-5.5 test from F-2029-008, was flagged and demoted during
  Phase 4 and is not re-litigated).
- The TOML → `ApiConfig` → `SseCaps` → `try_acquire` chain is now end-to-end
  pinned by tests at every hop, with the new round-trip pair closing the gap
  between the disk format and the daemon's in-memory representation.

## Per-test observations

### Test 1 — `events_stream_zero_caps_fall_back_to_defaults`

**File:** `crates/selfdef-api/tests/m12_api.rs:891–916`
**Decorator:** `#[tokio::test]` (multi-thread, no `start_paused`)
**Closes:** F-2029-003

The test wires `SseCaps { global: Some(0), per_token: Some(0) }` into a
fresh `ApiState`, attaches a unique fingerprint (`alice-zero-cap`), and
asserts that the very first `/events/stream` request returns `200 OK`.

#### What it pins

The `n > 0` guard in `SubscriberGuard::try_acquire`
(`handlers.rs:149–156`):

```rust
let cap_global = match state.sse_caps.global {
    Some(n) if n > 0 => n,
    _ => MAX_SSE_SUBSCRIBERS,
};
let cap_per_token = match state.sse_caps.per_token {
    Some(n) if n > 0 => n,
    _ => MAX_SSE_SUBSCRIBERS_PER_TOKEN,
};
```

If a future refactor drops the `if n > 0` arm and lets `Some(0)` flow
through literally, both caps would saturate at `current >= 0` immediately
and the first request would 503. The test is the canary for that
regression — exactly the contract the docstring claims.

#### Isolation

- `build_state().await` returns a fresh `ApiState` with its own `tempfile::TempDir`
  on every call (verified at `m12_api.rs:25`); no shared on-disk state.
- The token fingerprint `alice-zero-cap` is unique to this test (greppable
  across the file as a one-off literal).
- The `with_full_capability_for_fingerprint` middleware (feature-gated, see
  the crate audit) threads the fingerprint into request extensions
  post-auth without touching real bearer-auth machinery.
- Multi-threaded `#[tokio::test]` is appropriate here: the test does not
  rely on timer behaviour, so virtual time would buy nothing.

#### Coverage edge

The assertion is strictly "the first connection succeeds". One might ask
why the test doesn't open multiple connections to verify the *default* cap
(8 per-token, 64 global) actually applies. Answer: that contract is already
pinned by the sibling test
`events_stream_per_token_cap_reached` (m12_api.rs:1003–1040), which
saturates a single token's slice up to `MAX_SSE_SUBSCRIBERS_PER_TOKEN` and
asserts the next request is refused with the per-token typed reason.
Pinning "Some(0) falls back to *some* default" in one test and "the default
is exactly 8 per-token" in another is the right factoring — coupling them
would over-pin and create false-failure surface on future cap-default
tuning.

#### Real-time sleep / determinism

No sleeps. Single `oneshot` request, no timer interaction, no race surface.
Cleanly deterministic.

**Verdict:** clean. No finding.

### Test 2 — `sse_cap_knobs_round_trip_from_toml`

**File:** `crates/selfdef-config/src/lib.rs:597–622`
**Decorator:** `#[test]` (sync)
**Closes:** F-2029-005

The test writes a minimal TOML with `[api].enabled = true`,
`max_sse_subscribers = 16`, `max_sse_subscribers_per_token = 4` to a
`tempfile::NamedTempFile`, loads it through `Config::load(Some(tmp.path()))`,
and asserts the two cap fields round-trip as `Some(16)` and `Some(4)`.

#### What it pins

The `Option<usize>` parse hop for `ApiConfig` (selfdef-config/src/lib.rs:511–519):

```rust
#[serde(default)]
pub max_sse_subscribers: Option<usize>,
#[serde(default)]
pub max_sse_subscribers_per_token: Option<usize>,
```

A future regression that, say, changes `Option<usize>` to `usize` with
`#[serde(default)]` (so 0 means "unset") would either fail to compile (cap
fields become non-optional) or, more subtly, fold operator intent of "set
to 16" into the same in-memory representation as "unset". The test
catches both shapes.

The supporting commentary at lines 612–620 also pins the dual-axis claim
(global *and* per-token round-trip independently), so a regression that
only fixes one knob doesn't sneak through.

#### Isolation

- `tempfile::NamedTempFile::new()` per test — the file is auto-deleted on
  drop at end of test (RAII). No `TMPDIR` collisions or leak surface.
- No env-var manipulation (`Config::load` reads from the supplied path
  directly).
- `#[test]` (not `#[tokio::test]`): the loader is sync, so no runtime
  overhead.

#### Real-time sleep / determinism

None. Pure file I/O + parse. Cleanly deterministic.

#### Coverage edge

The TOML uses leading-whitespace indentation:

```toml
[api]
enabled = true
max_sse_subscribers           = 16
max_sse_subscribers_per_token = 4
```

TOML is whitespace-tolerant around `=`, so the column-aligned style is
purely cosmetic and does not affect parsing. The aligned style is, if
anything, slightly more readable than `key=value`; not worth a nice
finding.

**Verdict:** clean. No finding.

### Test 3 — `sse_cap_knobs_default_to_none_when_unset`

**File:** `crates/selfdef-config/src/lib.rs:630–645`
**Decorator:** `#[test]` (sync)
**Closes:** F-2029-006 (also touches F-2029-005)

The test writes a TOML with only `[api].enabled = true` (cap knobs
omitted), loads via `Config::load`, and asserts both
`cfg.api.max_sse_subscribers` and `cfg.api.max_sse_subscribers_per_token`
are `None`.

#### What it pins

The `#[serde(default)]` → `Option::None` mapping for the two cap fields,
combined with the `ApiConfig::default()` impl (selfdef-config/src/lib.rs:547–548)
which sets both to `None`. A regression that switches `#[serde(default)]`
to a `default_fn` returning `Some(0)` — which the daemon's `n > 0` guard
would absorb silently in production but a 0-cap regression in the guard
would activate — is caught right here at parse time.

This is the exact paired test that the F-2029-006 finding called out: the
"unset" case is contractually `None`, not `Some(0)`. Without this test,
the two states would be indistinguishable from outside the config layer.

#### Isolation

- Same `NamedTempFile::new()` pattern as test 2; per-test RAII cleanup.
- No env-var or working-directory dependence.
- No interaction with test 2 — each test creates its own `NamedTempFile`.

#### Real-time sleep / determinism

None. Pure parse. Deterministic.

#### Coverage edge

The test only asserts the cap fields are `None` — it does not also assert
`ApiConfig::default()` matches the empty-`[api]` case in *every* field. A
broader "ApiConfig defaults round-trip" test could be useful for catching
serde-tag drift on other ApiConfig fields, but that's outside this PR's
scope and would belong as a separate audit-driven test. Not a Phase 5
finding.

**Verdict:** clean. No finding.

## Cross-cutting observations

### Decorator-vs-runtime fit

| Test | Decorator | Justification |
| --- | --- | --- |
| `events_stream_zero_caps_fall_back_to_defaults` | `#[tokio::test]` | axum router + `oneshot`; needs an async runtime. No timer interaction → multi-thread default is fine. |
| `sse_cap_knobs_round_trip_from_toml` | `#[test]` | Sync file I/O + parse only. |
| `sse_cap_knobs_default_to_none_when_unset` | `#[test]` | Same. |

No mismatch. None of the three would benefit from `start_paused = true`
(no timer interaction in any of them).

### Naming consistency

All three names follow the `<subject>_<verb>_<expected>` convention used
throughout the test suite. `events_stream_zero_caps_fall_back_to_defaults`
sits cleanly alongside the existing `events_stream_per_token_cap_reached`,
`events_stream_per_token_cap_does_not_affect_other_tokens`,
`events_stream_per_token_counter_drops_to_zero_on_disconnect` cluster in
the same file. The two config tests share a `sse_cap_knobs_*` prefix that
groups them in the test output.

### Test-helper feature gating

`events_stream_zero_caps_fall_back_to_defaults` reaches into
`selfdef_api::with_full_capability_for_fingerprint` via the
`app_for_token` helper at m12_api.rs:880–882. That helper is gated by
`#[cfg(feature = "test-helpers")]` (see Phase 4 tests audit Area 7), so
the test only compiles when the integration test build enables the
feature. The selfdef-api crate's `[dev-dependencies]` for this test
target activate the feature; production builds cannot accidentally see
the helper. Verified by inspection of the crate audit; no regression
since Phase 4.

### SDD-005 compliance

SDD-005 forbids real-time sleeps outside the documented pub/sub-task and
I/O-blocking gray areas. None of the 3 new tests sleep at all. The only
remaining gray-area sleep in the broader closure cycle is the F-2029-008
drop-to-zero test from Phase 3, which Phase 4's tests explorer already
demoted with a documented rationale; Phase 5 does not re-litigate it.

### Coverage of the operator-tunable cap surface

After these three additions, the SDD-007 D-4 cap surface is now
test-covered at every hop:

| Hop | Test | Vintage |
| --- | --- | --- |
| TOML → `ApiConfig` (override) | `sse_cap_knobs_round_trip_from_toml` | F-2029-005 closure |
| TOML → `ApiConfig` (unset) | `sse_cap_knobs_default_to_none_when_unset` | F-2029-006 closure |
| `ApiConfig` → `SseCaps` → `try_acquire` (override) | `events_stream_per_token_cap_honours_operator_override` + `events_stream_global_cap_honours_operator_override` | Phase 3 closure |
| `SseCaps::Some(0)` → default fallback | `events_stream_zero_caps_fall_back_to_defaults` | F-2029-003 closure |
| Default cap saturation | `events_stream_per_token_cap_reached` | Phase 3 closure |
| Per-token isolation | `events_stream_per_token_cap_does_not_affect_other_tokens` | Phase 3 closure |
| Drop-to-zero pruning | `events_stream_per_token_counter_drops_to_zero_on_disconnect` | Phase 3 closure |

No coverage gap remains in the SDD-007 cap surface. A future surface
expansion (e.g., per-route caps, per-client-IP caps) would extend this
table; today it is complete.

## Triage

| ID | Severity | Surface | Next phase |
| --- | --- | --- | --- |

(no findings)

## Summary

Three new tests, all clean:

- **`events_stream_zero_caps_fall_back_to_defaults`** — pins the `n > 0`
  guard; canary for a regression that would saturate caps at zero.
- **`sse_cap_knobs_round_trip_from_toml`** — pins the TOML override hop;
  catches `Option<usize>` → `usize` shape drift.
- **`sse_cap_knobs_default_to_none_when_unset`** — pins the unset → `None`
  contract; catches `default_fn` regressions that would fold "set to 0"
  and "unset" into one state.

**0 blockers, 0 important, 0 nice, 0 demoted.** Sixth consecutive Phase 5
explorer at zero findings. One explorer remains (security); the
trajectory continues to suggest a clean Phase 5 wrap.
