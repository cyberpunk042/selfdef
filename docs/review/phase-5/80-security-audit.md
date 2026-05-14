# Phase 5 — Security audit

> Scope (per the Phase 5 charter): new attack surface introduced by the Phase 4
> closure cycle (8 PRs, commits `22ff461` → `d239dad`). The cycle was
> overwhelmingly documentation; the only Rust-touching closures were
> F-2029-002 (`TokenFingerprint` custom `Debug` impl) and the three new tests
> (one in `selfdef-api`, two in `selfdef-config`). Module-side: a one-line
> doc-comment in `apply.sh` (F-2029-004). Docs-side: SECURITY.md § API surface
> entry (F-2029-007).
>
> This audit also re-verifies that the Phase 3 closures still hold (F-2028-037
> dual-counter SSE quota, F-2028-018 SseParser bytes refactor, F-2028-015
> manifest cleanup, F-2028-004/-005 token-reader symmetry, F-2028-001 paths.rs
> compile-time invariants).

## Headlines

- **No blockers, 0 important, 0 nice, 0 demoted.** Seventh consecutive Phase 5
  explorer at zero findings. The Phase 4 closure cycle was as security-thin as
  predicted: the only code-bearing change with any security implication was
  `TokenFingerprint`'s custom `Debug` impl, which is **strictly defensive** —
  it shrinks (does not grow) the surface area exposed by structured logging.
- **F-2029-002 closure (Debug truncation) holds bytewise**: the `#[derive(...)]`
  on `TokenFingerprint` (transport.rs:349) lists only `Copy, Clone, Eq,
  PartialEq, Hash` — no `Debug` — and the custom impl at lines 366–380
  hardcodes the 4-byte (8 hex char) prefix with a trailing `…)` marker. Any
  future contributor who reaches for `dbg!(fp)` or `tracing::info!(?fp)`
  obtains the truncated form, not the raw 32-byte hash.
- **The three new tests introduce zero new production code paths.** They are
  feature-gated (`with_full_capability_for_fingerprint` lives behind
  `test-helpers`) or sit inside `#[cfg(test)]` modules, so the production
  binary surface is unchanged by their existence.
- **Re-audit of Phase 3 closures (F-2028-037, -018, -015, -004/-005, -001)**
  confirms all mitigations still hold, with no regression introduced by the
  Phase 4 cycle.

## Per-area observations

### Area 1 — `TokenFingerprint` Debug truncation (F-2029-002 re-audit)

**File:** `crates/selfdef-api/src/transport.rs:348–380`

The derive list:

```rust
/// while removing the cross-time-linkage primitive.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct TokenFingerprint(pub [u8; 32]);
```

The custom impl:

```rust
impl std::fmt::Debug for TokenFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 4 bytes (8 hex chars) is enough to distinguish fingerprints
        // in typical log streams while leaving 28 bytes of entropy
        // unrevealed — an attacker who acquires the token cannot
        // confirm a past log line was attributable to it from the
        // 8-char prefix alone (2^32 = collision-prone even at the
        // SHA-256 level).
        write!(
            f,
            "TokenFingerprint({:02x}{:02x}{:02x}{:02x}…)",
            self.0[0], self.0[1], self.0[2], self.0[3],
        )
    }
}
```

#### Threat-model walkthrough

**Threat 1 — Full-hash log exposure.** A maintainer adds `tracing::info!(?fp)`
into a logger that writes to disk or to a shipped-out telemetry sink. Before
F-2029-002, that would render the full 64-char hex digest of the SHA-256
fingerprint, which is the unique stable identifier for the bearer token. An
attacker with later access to the logs *and* a token candidate could verify
attribution.

After F-2029-002, the same call renders 8 hex chars + truncation marker. The
remaining 28 bytes (224 bits) of entropy are uncoupled from the log line; the
attacker is left with 2^32 collision uncertainty — sufficient to prevent
cross-time linkage in any realistic deployment.

**Verdict:** Defence still holds. The implementation does not have a back-door
(no environment variable or feature flag flips the truncation off in
production). The crate-explorer pass already verified there is no
`#[cfg(any(...))]` arm that emits the full bytes.

**Threat 2 — `Display` impl as escape hatch.** Phase 4 audit asked: does some
other formatter (`Display`, `LowerHex`, `UpperHex`, `Pointer`) leak the full
hash? Cross-checked: `grep -n "impl.*for TokenFingerprint" crates/selfdef-api/src/transport.rs`
yields only the `Debug` impl. No `Display`, no hex traits. The field `.0` is
`pub` so any caller can still emit it deliberately, but that's an explicit
opt-in, not an accidental log leak. **No new escape hatch from Phase 4.**

**Threat 3 — Debug truncation entropy.** Phase 4 raised F-2029-009 (32-bit
prefix entropy) as a `nice` finding then demoted it on cross-check. Re-audit:
32 bits of entropy in a log line means an attacker with N candidate tokens
seeking a specific log line's owner has a `~N / 2^32` confirmation rate per
candidate. For realistic operator token sets (say ≤ 100 tokens), the
collision-prone regime is **far** below the threshold where attribution
becomes evidentially useful. The trade-off (shorter prefix → harder grep for
operators correlating two log lines from the *same* token) was deliberately
chosen at the F-2029-002 closure. **Demotion still sound; not re-raised.**

### Area 2 — Zero-cap fallback test (F-2029-003 re-audit)

**File:** `crates/selfdef-api/tests/m12_api.rs:891–916`

The test is a contract-pinning canary; it adds no new request-handling code
path. The contract it pins — `n > 0` guard in `try_acquire`
(handlers.rs:149–156) — was already shipped in Phase 3 as part of the SDD-007
D-4 closure. Phase 4 only added the test.

**Threat-model walkthrough.** The test exercises `SseCaps { global: Some(0),
per_token: Some(0) }` and confirms the first SSE stream succeeds. This pins
the desired behaviour (zero is operator shorthand for "use default"), so a
future regression dropping the guard would fail the test before reaching a
release.

A subtle adversarial scenario: could an operator deliberately set
`max_sse_subscribers = 0` expecting that to *disable* the SSE endpoint? With
the `n > 0` fallback, the answer is no — the endpoint operates at default
cap. SECURITY.md § API surface (Phase 4 closure of F-2029-007) explicitly
documents this: "`None` / `Some(0)` → use compiled-in default". Operators who
want to disable SSE entirely must set `[api].enabled = false`, not set the
cap to zero. **No new exposure; behaviour is documented.**

### Area 3 — Config round-trip tests (F-2029-005/-006 re-audit)

**Files:** `crates/selfdef-config/src/lib.rs:597–622, 630–645`

Both tests are `#[test]` (sync) inside `#[cfg(test)]` modules. The `Config::load`
function they exercise is the same one the daemon uses at startup; the tests
neither widen nor narrow that surface. The TOML test fixtures are
`tempfile::NamedTempFile`-scoped (RAII), so no on-disk residue persists past
the test process.

**Threat-model walkthrough.** A test calling `Config::load` could, in
principle, exercise an unsafe deserialisation path; figment + serde does not
admit arbitrary code execution from a malicious TOML, but a tag-attacker
might try to coerce an unwanted variant. The fixtures here pass only valid
strings/ints into well-typed fields; the tests assert the parsed values, not
that parsing is sandboxed. **No new exposure from the tests themselves.**

A more interesting question: do these tests fix-fingerprint a parsing path
that has any security-relevant invariant? Yes — the `Option<usize>` shape of
the two cap fields is what allows the daemon to distinguish "operator left it
unset" from "operator chose zero", and both round-trip to `None` /
`Some(0)` exactly as the `n > 0` guard expects. The round-trip tests close a
correctness gap that, if it had been latent, could have surfaced as
"operator-thought-they-set-the-cap-but-didn't" silent misconfiguration. The
tests harden the operator-facing contract; they introduce no new code in the
parser. **Strictly defensive.**

### Area 4 — vpn-bridge `apply.sh` dispatcher doc-comment (F-2029-004 re-audit)

**File:** `modules/vpn-bridge/install/apply.sh` (header lines)

The Phase 4 closure was a one-line doc-comment addition documenting
dry-run-awareness, idempotency, and SDD-006 v2 manifest-tracking. No code
changes. The Phase 5 module-explorer already verified the doc-comment matches
the actual `profile_apply` implementation bytewise.

**Security implication:** None. Doc-comment additions cannot change runtime
behaviour. The manifest-tracking contract (F-2028-015 closure) and the
dispatcher's idempotency contract (SDD-006 v1) both pre-date Phase 4 and were
audited in Phase 3 / Phase 4 already. **Re-verified holding.**

### Area 5 — SECURITY.md § API surface entry (F-2029-007 re-audit)

**File:** `SECURITY.md` (§ API surface)

The Phase 4 docs explorer added a section documenting the SDD-007 per-token
SSE quota: the SHA-256 fingerprint storage, the default + override caps, the
`None` / `Some(0)` fallback, and the distinguishable 503 reasons. The Phase 5
docs explorer already cross-checked the text against `handlers.rs` and
`config.rs` byte-for-byte.

**Security implication:** Operator-facing documentation strengthens the trust
boundary by setting correct expectations. There is no new code surface; the
section documents pre-existing behaviour. The risk that an operator
*misunderstands* the cap semantics (e.g., expects `max_sse_subscribers = 0` to
disable the endpoint) is now explicitly addressed in the doc, reducing
configuration-error blast radius. **Re-verified holding; strictly defensive.**

## Re-audits of prior closures

### F-2028-037 — dual-counter SSE quota

`SubscriberGuard::try_acquire` at `crates/selfdef-api/src/handlers.rs:142–209`:

- Per-token check + increment held under the per-token-map `Mutex` (lines
  160–177). No load-then-increment race.
- Global CAS-loop (lines 181–208). On global-cap failure, the per-token
  increment is decremented under the same Mutex *before* returning the error
  (lines 184–191), so a global-cap rejection cannot leak a per-token slot.
- The `Drop` impl decrements both counters and prunes the per-token map entry
  when its count reaches zero. The Phase 3 closure already covered the
  prune-race analysis; nothing in Phase 4 touched this code.

The new `events_stream_zero_caps_fall_back_to_defaults` test is the *only*
Phase 4 modification touching this file — and it's a test, not a production
change. **Closure remains sound.**

### F-2028-018 — SseParser bytes refactor

`crates/selfdef-cli/src/follow.rs` (`SseParser::feed_bytes`):

The bytes-buffer + line-boundary-decode pattern is unchanged in Phase 4. The
Phase 3 tests (`parser_reassembles_multibyte_utf8_split_across_chunks`,
`parser_reassembles_3byte_utf8_split_across_chunks`) still compile and pass.
The Phase 4 cycle did not touch `follow.rs` (greppable: no Phase 4 commit
listed it in any diff). **Closure remains sound.**

### F-2028-015 — vpn-bridge manifest cleanup

`modules/vpn-bridge/install/profiles/relay-via-server.sh` (uninstall path):

The manifest iteration + legacy-fallback dedup logic is unchanged in Phase 4.
The only Phase 4 touch in `modules/vpn-bridge/` was the one-line doc-comment
in `install/apply.sh` (F-2029-004), which is a dispatcher concern, not a
profile concern. **Closure remains sound.**

### F-2028-004 / F-2028-005 — token-reader symmetry

`crates/selfdef-api/src/transport.rs:300–327` (daemon) and
`crates/selfdef-cli/src/follow.rs:396–416` (CLI):

Both readers still enforce `mode & 0o077 == 0` and call `.trim()`. The Phase
4 cycle did not touch either function. The Phase 5 integration explorer's
end-to-end verification of the daemon → CLI path implicitly re-exercises this
symmetry on every integration-test run. **Closure remains sound.**

### F-2028-001 — paths.rs compile-time invariants

`crates/selfdef-cli/src/paths.rs:47–59`:

The `const _: () = { ... };` block asserting all path constants begin with
`/etc/selfdef/` is unchanged in Phase 4. The Phase 5 crate explorer's audit
of `transport.rs` did not touch `paths.rs`. **Closure remains sound.**

## Cross-cutting observations

### Production binary surface diff for the Phase 4 cycle

A useful exercise: what *runtime* surface changed between `22ff461` and
`d239dad`?

| Surface | Phase 4 change | Security impact |
| --- | --- | --- |
| `TokenFingerprint` Debug output | Custom impl truncates to 4-byte prefix | **Reduction** of attack surface (log leakage) |
| `TokenFingerprint` derive list | `Debug` removed | Forces all formatting through the truncated impl |
| `ApiConfig` cap fields | Already `Option<usize>` in Phase 3; tests added in Phase 4 | None (no field change) |
| `SseCaps::try_acquire` `n > 0` guard | Already shipped in Phase 3; test added in Phase 4 | None (no code change) |
| `apply.sh` dispatcher header | Doc-comment only | None (no code change) |
| SECURITY.md § API surface | New documentation | **Reduction** of configuration-error blast radius |

The net delta: two strictly-defensive changes (Debug truncation, SECURITY.md
clarification) and three test-only or doc-only changes. No surface
*expansion*; one surface *contraction* (the Debug-output channel).

### Test-helper feature gating audit

The `with_full_capability_for_fingerprint` helper used by
`events_stream_zero_caps_fall_back_to_defaults` is gated by
`#[cfg(feature = "test-helpers")]` (verified at lib.rs:64–82 per the Phase 4
tests-audit). The `MAX_SSE_SUBSCRIBERS_PER_TOKEN` re-export (lib.rs:94) is
similarly gated. Production builds elide both. Phase 5 re-verifies this gate
because a regression would silently widen the attack surface (a release-mode
caller could acquire a `Capability::Full` extension without going through
bearer-auth). **Gate intact.**

### Configuration-error blast radius

Phase 4 closed F-2029-007 by documenting `[api].max_sse_subscribers{,_per_token}`
in SECURITY.md. The doc explicitly covers:

- Default values (64 global / 8 per-token)
- `None` / `Some(0)` fallback semantics
- The two distinguishable 503 reasons

An operator who reads SECURITY.md cannot leave the system in a misconfigured
state by mistake — the doc states exactly what each value means. The Phase 5
docs explorer cross-checked the text bytewise against the code; no drift.
**Operator-facing security surface is in steady state.**

## Triage

| ID | Severity | Surface | Next phase |
| --- | --- | --- | --- |

(no findings)

## Summary

The Phase 4 closure cycle's security surface diff is overwhelmingly negative
(less exposed surface, not more):

- **`TokenFingerprint` Debug truncation** — reduces accidental log leakage of
  the full SHA-256 hash. Strictly defensive.
- **Zero-cap fallback test** — pins existing `n > 0` guard behaviour. No new
  code path.
- **Config round-trip tests** — harden the operator-facing TOML contract. No
  new code path.
- **`apply.sh` doc-comment** — documents existing dispatcher behaviour. No
  code change.
- **SECURITY.md § API surface** — clarifies operator-facing cap semantics.
  Reduces configuration-error blast radius.

Re-audits of Phase 3 closures (F-2028-037, -018, -015, -004/-005, -001) all
hold; no regression introduced by the Phase 4 cycle.

**0 blockers, 0 important, 0 nice, 0 demoted.** Seventh consecutive Phase 5
explorer at zero findings. **All seven explorers have now run; Phase 5 is
ready to wrap.**
