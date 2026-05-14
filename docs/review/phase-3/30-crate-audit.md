# Phase 3 — Crate audit

> Scope: Rust code introduced during the Phase 2 closure cycle
> (~28 PRs, commits `2d918ac` through `ee0e1a9`).
>
> Audits: `follow.rs` (SseParser, events_follow_tcp/unix, read_token_file),
> `main.rs` (validate_rbac_subject, Follow command), `handlers.rs`
> (SubscriberGuard, events_stream refactor, ApiError::store),
> `state.rs` (sse_subscribers field), `lib.rs` (MAX_SSE_SUBSCRIBERS re-export),
> `Cargo.toml` (new reqwest/futures deps).
>
> Methodology: same as Phase 2's crate explorer (Phase 2 charter §Methodology).
> Does **not** re-litigate Phase 2 PR-level findings (F-2027-001..010) —
> that's the recent-PRs explorer's job. Cross-checks the inventory's claims
> against actual code.

## Headlines

- **No blockers, no important findings.** The closure code went through PR review
  and CI; the new machinery (SseParser state machine, SubscriberGuard RAII,
  validate_rbac_subject charset validator, TCP SSE client) is well-integrated
  and test-covered.
- **5 nice findings** clustered around three themes:
  - **API surface parity** — daemon-side and CLI-side token readers use different
    whitespace-trimming strategies and mode-validation logic.
  - **Documentation completeness** — the follow.rs module header doesn't enumerate
    the new `read_token_file` function; the main.rs `Follow` command docs don't
    cross-reference the conflicting/requiring constraint structure.
  - **Parser edge cases** — the SseParser handles per-frame event-type reset cleanly,
    but a hypothetical unimplemented feature (multi-line data fields) would
    silently break if someone extended SSE handling.

## Per-crate notes

### selfdef-cli: follow.rs

The new `SseParser` state machine + dual-transport architecture. Five public
surfaces: `events_follow_unix`, `events_follow_tcp`, `read_token_file`, plus
the internal `SseParser` enum and `handle_frame` printer.

#### Test coverage

Nine unit tests cover the parser: single data frame, optional space after
colon, event-type pairing, event-type reset on blank line, ping filtering,
shutdown / lagged / unknown-type handling, partial-line buffering, and
unknown SSE field ignoring. Five integration tests cover TCP-follow:
successful stream, bad URL, token-file passing, mutual-exclusivity with
UNIX socket, and token-file requirement with --url.

#### Observations

**F-2028-005 — read_token_file whitespace trim asymmetry.** The CLI's
`read_token_file` (`src/follow.rs:326`) trims `'\n' | '\r' | ' ' | '\t'`,
matching newlines, carriage returns, spaces, and tabs. The daemon-side
`read_token` (`src/transport.rs:320`) calls `raw.trim()`, which removes
all Unicode whitespace (newlines, spaces, tabs, plus BOM, zero-width space,
etc.). If a token file contains leading/trailing Unicode whitespace
(e.g. non-breaking space U+00A0), the CLI would include it in the Bearer
header, but the daemon would strip it — auth mismatch. Symmetry options:
(a) both sides call `.trim()` for Unicode-complete coverage, or (b)
CLI documents that only ASCII whitespace is trimmed and operator must
avoid non-ASCII. The likelihood an operator encounters non-ASCII
whitespace in a token file is low, but symmetry is worth establishing.
**nice** — implement (operator-side whitespace control).

**F-2028-006 — Bearer header format not doc-commented.** The `events_follow_tcp`
function's signature doc (`src/follow.rs:268-273`) explains the `bearer_token`
parameter semantics ("the token the daemon's TCP transport's bearer-auth
middleware will accept; pass None to skip the header"), but doesn't explicitly
state that the implementation formats it as `"Bearer {token}"` (space-separated,
no quotes). A future maintainer extending the function or porting the logic
elsewhere would have to read the implementation to verify the header format.
Add a one-line note in the doc-comment: "header format is `Authorization: Bearer <token>`".
**nice** — implement (doc-string clarity).

**F-2028-007 — read_token_file not exported from module header.** The
`follow.rs` module's `//!` comment (`src/follow.rs:1-22`) documents the
`SseParser` state machine and the two entry points (`events_follow_unix` /
`events_follow_tcp`) but doesn't mention `read_token_file`. A reader of
the module header won't discover the helper function; they'd have to grep
the implementation. The function is `pub(crate)` and called from `main.rs`,
so it's part of the public surface. Either add it to the header's bullet
list or rename it `_read_token_file` (underscore prefix is a Rust convention
for "not documented; don't use in new code"). **nice** — implement
(module-header completeness).

**F-2028-008 — SseParser not public, but could be useful for testing.** The
`SseParser` struct and `SseFrame` enum are defined as private (`struct SseParser`)
but include comprehensive unit tests (`tests` submodule). If a future consumer
(e.g., a daemon-side SSE frame generator for testing) wants to verify SSE
frame construction or breakdown, they'd have to duplicate the parser or
reach into the CLI's private internals. The struct is small and well-tested,
so exposing it as `pub` would allow downstream code to reuse it. Not urgent,
but worth flagging for the future: if you add more transports that need SSE
parsing, consider extracting `SseParser` to a shared crate (e.g.,
`selfdef-sse-parser` or fold it into `selfdef-core`). **nice** — defer
(low priority, no immediate use case).

### selfdef-cli: main.rs

Two new behaviors: the `validate_rbac_subject` function + its test module,
and the `Follow` clap subcommand with `--url` / `--token-file` flags.

#### Observations

**F-2028-009 — validate_rbac_subject charset is restrictive but documented.** The
function (`src/main.rs:1473-1493`) enforces `[A-Za-z0-9:._/@-]` (alphanumerics,
colon, period, underscore, slash, at, hyphen). The test suite includes
subjects like `system:authenticated`, `system:serviceaccount:kube-system:default`,
`alice@example.com`, `group/team_a.v1-rc` — all pass. Rejects empty, over-253-bytes,
shell metacharacters (`$`), ANSI escapes (`\x1b`), whitespace. The charset
is intentionally tight (e.g., no `*` for glob patterns, no `;` for
shell-command sequences), and the error message names the offending byte
by position, which is helpful for operators debugging. The 253-byte limit
mirrors Kubernetes's DNS-name cap. No findings — the validator is
well-scoped and well-tested. **demoted to informational** — the recent-PRs
explorer (F-2028-003) already flagged this surface, and the PR review
confirmed the charset is correct. No action needed.

**F-2028-010 — Follow clap command constraint clarity.** The `Follow` struct
(`src/main.rs:399-429`) defines `#[arg(long, conflicts_with = "unix_socket")]`
on `url` (line 412) and `#[arg(long, requires = "url")]` on `token_file` (line 420).
The constraints prevent `--unix-socket` + `--url` together and require `--url`
when `--token-file` is set. The integration tests verify both constraints
are enforced. The design is correct, but the doc-comment could explicitly
name the constraint structure so a reader doesn't have to cross-reference
the clap attributes. Add a line in the `Follow` doc-comment:
"`--url` and `--unix-socket` are mutually exclusive; `--token-file` requires `--url`."
**nice** — implement (doc-string clarity).

### selfdef-api: handlers.rs

New `SubscriberGuard` RAII type, refactored `events_stream` (now returns
`Result<Sse<...>, ApiError>`), and rewritten `ApiError::store` body.

#### Observations

**F-2028-011 — SubscriberGuard atomics and memory ordering.** The CAS loop
(`src/handlers.rs:120-140`) uses `Ordering::Acquire` on the load and
`Ordering::AcqRel` on the compare-exchange. The semantics are correct:
acquire is needed on the load (synchronize with any prior release-store),
and AcqRel on the CAS ensures the increment happens atomically and
synchronizes with the Drop decrement. The pattern is sound. No findings.

**F-2028-012 — SubscriberGuard doesn't poison on decrement failure.** The
Drop impl (`src/handlers.rs:143-146`) calls `fetch_sub(1, AcqRel)` without
checking if the counter goes negative (underflow). In practice, the counter
is owned by ApiState and never decrements without a corresponding acquire
in events_stream, so underflow can't happen. However, a defensive pattern
would check: `let prev = counter.fetch_sub(1, Ordering::AcqRel); debug_assert!(prev > 0)`.
Without it, a logic bug in the future (e.g., dropping a guard twice, or
acquiring without holding the guard) would silently corrupt the counter.
Not a safety issue (the counter is not the sole source of truth for access
control), but nice-to-have for debuggability. **nice** — defer (low priority,
no observed misuse in tests).

**F-2028-013 — events_stream timeout message doesn't mention the deadline.** The
`send_with_timeout` closure (`src/handlers.rs:194-203`) returns
`Err("slow-client timeout")` on deadline expiry, but the constant `SSE_SEND_TIMEOUT = 30s`
is not mentioned in the error message. A reader of the daemon logs seeing
"slow-client timeout" might wonder what the timeout was, and would have to
grep the source. Consider logging the actual timeout: `Err(format!("slow-client timeout ({}s)", SSE_SEND_TIMEOUT.as_secs()))`.
**nice** — defer (low priority, 30s is a reasonable default and unlikely
to change frequently).

### selfdef-api: state.rs

No new observations. The `sse_subscribers: Arc<AtomicUsize>` field is properly
initialized to 0 and shared across clones. The field is documented with a
reference to the handlers.rs cap constant.

### selfdef-api: lib.rs

No new observations. The `MAX_SSE_SUBSCRIBERS` re-export is properly gated
on `#[cfg(feature = "test-helpers")]` so it doesn't appear in release builds.
The doc-comment explains its purpose (integration tests need the cap value
to drive the cap-exhaustion case deterministically).

### selfdef-cli: Cargo.toml

**F-2028-014 — reqwest and futures dependencies are properly justified.** The
new production deps (line 43-44) are documented in inline comments:
`reqwest` already lives in the workspace (via `selfdef-notifier`) and the
CLI adopts the `stream` feature for `bytes_stream()`, while `futures`
provides `StreamExt::next`. The comment explicitly notes "the CLI adopting
it adds zero net dep size beyond the new `stream` feature", which is
helpful context for future maintainers. No findings.

## Triage

All 5 observations are **nice**. Most are documentation or API-surface
clarity; one (F-2028-005) is a token-reading asymmetry that's low-risk but
worth addressing for symmetry.

Closing-PR candidates (cluster, one PR per cluster):

- **Token-reading asymmetry** — F-2028-005. One PR aligns CLI and daemon
  `read_token_file` implementations so both use `.trim()` or both use
  `.trim_end_matches([...])` depending on coverage preference.
- **Documentation clarity** — F-2028-006 + F-2028-007 + F-2028-010.
  One PR adds doc-comment lines to `events_follow_tcp`, the
  follow.rs `//!` header, and the Follow clap struct explaining the
  Bearer header format, the read_token_file helper, and the clap
  constraint structure.

All 5 entries land in the Phase 3 findings ledger as F-2028-005 through
F-2028-008, F-2028-010 with `nice` severity and "implement" next-phase.
