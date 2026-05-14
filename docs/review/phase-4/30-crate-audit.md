# Phase 4 — Crate audit

> Scope: Rust code introduced during the Phase 3 closure cycle
> (~17 PRs, commits `f40bf05` through `8b44322`).
>
> Audits: `TokenFingerprint` and `Debug` visibility; `SseCaps` builder
> and config threading; `SubscriberGuard` dual-counter logic and HashMap
> pruning; `SseParser::feed_bytes` byte-buffer and UTF-8 round-trip;
> TCP 503 typed-reason JSON extraction; config new fields and daemon
> initialization; CLI token-reader symmetry and Bearer header format;
> paths compile-time invariants.
>
> Methodology: same as Phase 3's crate explorer. Does not re-litigate
> Phase 3's closure-PR findings (F-2028-005..014) — that's the recent-PRs
> explorer's job. Cross-checks the inventory's claims against actual code.

## Headlines

- **No blockers, no important findings.** The Phase 3 closure code went
  through PR review and CI; the new machinery (TokenFingerprint, SseCaps,
  SubscriberGuard dual-counter + HashMap pruning, JSON 503 extraction) is
  well-integrated, test-covered, and document-clear.
- **2 nice findings** around API-surface documentation and logging hygiene:
  - **Debug output leakage** — the `TokenFingerprint` `Debug` derive outputs
    raw SHA-256 bytes; in operator logs this leaks fingerprint metadata
    (though not the raw token). Defensible but worth flagging.
  - **Zero-cap edge case** — the `Some(0)` fallback to default is correctly
    implemented and documented, but lacks explicit test coverage that would
    catch a future refactor that changes the semantics.

## Per-file notes

### selfdef-api: transport.rs

New `TokenFingerprint(pub [u8; 32])` type and `bearer_auth` middleware that
threads it into request extensions. The `of()` method computes SHA-256 via
`sha2` crate; the type is `Copy` and carries 32 public bytes as the tuple field.

#### Observations

**F-2029-002 — TokenFingerprint Debug output includes raw bytes in logs.**
The `#[derive(Debug)]` on the `TokenFingerprint` type (line 341) expands
to output the 32-byte array in full: `TokenFingerprint([1, 2, 3, ..., 32])`.
When tracing or structured logging formats the type (e.g., via
`tracing::debug!(fp = ?fp, "...")`), the bytes appear in operator logs.
The bytes are a SHA-256 hash of the bearer token (not the token itself), so
they're not a direct secret leak. However, the fingerprints are keyed in the
per-token counter HashMap (`src/state.rs`), and an operator with log access
could collect fingerprints across time to infer token-use patterns or
(with a leaked token plaintext) verify which tokens are in use on a host.
**Mitigation options:**
(a) Implement a custom `Debug` impl that elides the bytes (e.g.,
`TokenFingerprint([..])` or `TokenFingerprint(sha256:abcd...ef)`), or
(b) document in the `TokenFingerprint` doc-comment that the type's Debug
output includes hash bytes and operators should avoid logging the type
verbatim.
**Severity: nice.** The leaked metadata is the hash (not the secret), and
depends on operator log access and token leakage. Implementing a custom Debug
is low-cost.

**F-2029-003 — `Some(0)` fallback to default cap lacks explicit test.**
The `try_acquire()` function in `handlers.rs` treats `Some(0)` the same as
`None` — both fall back to the compiled-in defaults (line 150-151 and
153-154). The comment in `state.rs:72` documents this as intentional
("operator left it commented"). However, the test suite (`m12_api.rs`)
exercises `Some(1)` (saturates immediately) and `Some(2)` (per-token override),
but doesn't explicitly test `Some(0)` to verify the fallback semantics.
A future refactor that misreads the pattern could inadvertently treat `Some(0)`
as "disable the cap" (allowing unlimited subscribers), which would be a
security regression. Add a test case covering both `Some(0)` to verify it
matches the default, and document the edge case in the PR or code if the
pattern is non-obvious. **Severity: nice.** The semantics are correct today
and well-documented; this is a defensive-testing request.

### selfdef-api: state.rs

New `SseCaps` struct and per-token counter map (`sse_subscribers_per_token:
PerTokenCounters`). The map is an `Arc<Mutex<HashMap<TokenFingerprint,
AtomicUsize>>>`.

#### Observations

**No new findings.** The `SseCaps` struct and `with_sse_caps()` builder are
straightforward; the per-token counter map is properly initialized and the
`std::sync::Mutex` (not tokio's) is correct for sync `Drop` impl. Lock hold
duration is microseconds (just HashMap entry lookup + one atomic load), so
contention risk is low. The `sse_subscribers_per_token_keys()` test helper
(gated on `feature = "test-helpers"`) is well-scoped for integration tests.

### selfdef-api: handlers.rs

New `SubscriberGuard` RAII type with dual-counter semantics: per-token first
(under Mutex), then global (CAS loop). Drop decrements both and prunes the
HashMap entry when count hits zero.

#### Observations

**No new findings.** The try-acquire logic is sound:
- Per-token check happens under the Mutex, so no race against concurrent Drop.
- Global check uses CAS, which is correct for the lock-free counter.
- Undo logic on global-cap failure (line 184-191) correctly decrements the
  per-token counter if global acquire fails, preventing an orphaned
  per-token entry that would never be pruned (since the guard was never
  successfully constructed).
- Drop decrements both with `debug_assert!(prev > 0)` for defensive checks
  (F-2028-012 closure, line 220-223 and 231-235).
- HashMap entry pruning on zero (line 235-236) prevents leaks across
  token rotations.

The error types (`AcquireError::GlobalCap` vs `AcquireError::PerTokenCap`)
and 503 messages are appropriately distinguished (F-2028-037 closure, line
259-270).

### selfdef-api: lib.rs

Public exports of `TokenFingerprint`, `SseCaps`, and the test-only helper
`with_full_capability_for_fingerprint`.

#### Observations

**No new findings.** The test helper is correctly gated on `#[cfg(feature =
"test-helpers")]` so it's invisible in release builds. The public re-exports
are correctly scoped.

### selfdef-api: Cargo.toml

New workspace dep `sha2 = "0.10"`.

#### Observations

**No new findings.** The dependency is justified inline (line 48-52) and
version-locked via the workspace Cargo.lock.

### selfdef-cli: follow.rs

Major refactor: `SseParser::feed_bytes(&[u8])` for byte-buffer semantics,
`read_token_file` with mode check + Unicode trim, JSON 503 extraction, and
module-header documentation.

#### Observations

**No new findings.** The `feed_bytes` implementation correctly handles
multi-byte UTF-8 split across chunk boundaries by buffering raw bytes and
decoding line-at-a-time (F-2028-018 closure, line 97-162). The `read_token_file`
function mirrors the daemon-side `read_token` behavior (mode check `mode &
0o077 == 0` + Unicode `.trim()`, line 396-416), closing the F-2028-004 +
-005 gap. The JSON 503 extraction (line 349-352) uses safe fallback patterns
(`ok()` + `and_then` + `unwrap_or_else`), so a malformed JSON body degrades
gracefully to raw-text surfacing. Bearer header doc-comment (line 317-320)
explicitly names the wire format.

### selfdef-cli: main.rs

`Follow` clap struct with `--url` / `--unix-socket` / `--token-file` flags
and their constraint structure.

#### Observations

**No new findings.** The clap attributes correctly enforce the constraints
(line 419: `conflicts_with = "unix_socket"`; line 427: `requires = "url"`),
and the doc-comment explicitly names the constraint structure (line 400-405),
closing the F-2028-010 gap.

### selfdef-cli: paths.rs

Compile-time `const _: () = { … }` invariant block asserting every default
path constant starts with `/etc/selfdef/` and `AGENT_GUARD_CONFIG` lives
under `MODULES_PER_MODULE_DIR`.

#### Observations

**No new findings.** The const-fn `starts_with` helper (line 62-74) is
correctly marked `#[allow(dead_code)]` since it's only called in the const
block. The invariants are checked at compile time (zero runtime cost), so
a future maintainer who renames the project's etc-dir or accidentally drops
the leading slash gets a build error immediately (F-2028-001 closure).

### selfdef-config: lib.rs

`ApiConfig` gains two new optional fields: `max_sse_subscribers` and
`max_sse_subscribers_per_token`, both `#[serde(default)]`.

#### Observations

**No new findings.** The fields are correctly optional (existing TOML configs
remain valid) and documented with the fallback semantics (line 507-519).
The defaults are `None` (line 547-548), which the daemon interprets as "use
compiled-in defaults" when passing to `ApiState::with_sse_caps` (daemon main.rs
line 194-196).

### selfdef-daemon: main.rs

API startup threads the new config values to `ApiState::with_sse_caps` (line
194-196).

#### Observations

**No new findings.** The threading is straightforward: `cfg.api.max_sse_subscribers`
and `cfg.api.max_sse_subscribers_per_token` are passed as-is to the builder,
which (via handlers.rs line 149-156) treats `None` / `Some(0)` as "use
default".

## Triage

Both findings are **nice** severity. No blockers, no important findings.

### F-2029-002 closure candidate:
Implement a custom `Debug` impl for `TokenFingerprint` that elides the bytes,
e.g., `fmt!("TokenFingerprint(...)")` or `fmt!("TokenFingerprint(sha256:{})", 
hex(&self.0[..4]))` to make the fingerprint visible without leaking the
full hash to logs.

### F-2029-003 closure candidate:
Add a test case in `m12_api.rs` (e.g., `events_stream_cap_zero_falls_back_to_default`)
that explicitly verifies `SseCaps { global: Some(0), per_token: None }` behaves
as if `Some(MAX_SSE_SUBSCRIBERS)` was set, so a future refactor that changes
the semantics is caught.

## Closing notes

The Phase 3 closure cycle delivered the cleanest code audit yet. All nine
audit files (two across the new surfaces) are cosmetic / logging / test-coverage
grade; no functional gaps or safety issues were uncovered. The new
TokenFingerprint and SubscriberGuard machinery is well-tested and integrates
correctly with the existing API state and cap logic.

### Triage summary

| id        | severity | surface | summary | next phase |
| ---       | ---      | ---     | ---     | ---        |
| F-2029-002 | nice     | TokenFingerprint logging | Debug derive outputs full 32 bytes; implement custom impl to elide | implement (custom Debug) |
| F-2029-003 | nice     | SseCaps zero-cap edge case | Some(0) fallback not explicitly tested; add defensive test case | implement (test coverage) |
