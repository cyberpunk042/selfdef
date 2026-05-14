# Phase 3 inventory — what changed during the Phase 2 cycle

Hand-counted from `git log` covering the ~28 PRs that closed
Phase 2 findings (commits `2d918ac` Phase 2 audit kickoff →
`ee0e1a9` F-2027-010 closure). Used by the seven Phase 3
explorers as the starting point for "what's the new surface I'm
auditing?"

## New crates

None. Phase 2's closure cycle added no new workspace members.

## New CLI capability

- **`selfdefctl events follow --url <http(s)://host:port>`**
  (closure of F-2027-010) — reqwest-backed SSE client for the
  daemon's TCP transport. New `--token-file <path>` flag.
  Mutually-exclusive with `--unix-socket`; `--token-file`
  requires `--url`. Reads bearer from file (kept out of
  `ps` / shell history). Reconnect-on-disconnect deliberately
  deferred.

## Modified crates

### selfdef-cli

- **`src/follow.rs`** — refactored from a single UNIX-socket
  HTTP/1.1 hand-roll into two transport-specific entry points
  sharing a `SseParser` state machine + a `handle_frame` printer.
  - `events_follow_unix(socket_path, alerts_only, limit)` —
    the previous code, structurally unchanged but parser pulled
    out.
  - `events_follow_tcp(base_url, bearer_token, alerts_only, limit)`
    — new, uses `reqwest::Client::get(...).send().await.bytes_stream()`.
  - `SseParser::{new,feed}` — partial-line buffer + per-frame
    `event:` accumulator. Emits one of 5 `SseFrame` variants:
    `Data` / `Shutdown` / `Lagged` / `UnknownEventType` /
    `Comment`.
  - `read_token_file(path)` — trims trailing whitespace,
    rejects empty.

- **`src/main.rs`** — three new behaviours:
  - `Follow` clap subcommand gains `--url` + `--token-file`
    with `conflicts_with` / `requires` constraints.
  - `validate_rbac_subject(s)` — defense-in-depth charset
    `[A-Za-z0-9:._/@-]` + 1..=253 char window. Runs on every
    probe subject before any `kubectl` invocation or stdout
    echo. New `rbac_subject_tests` cfg-test module.

- **`src/init.rs` STARTER_CONFIG + STARTER_MODULES** —
  doc-comment refreshes (no byte-write change beyond comment
  lines):
  - `[collectors.eventstream]` block names the F-2027-035
    `O_NOFOLLOW`+fstat-on-FD mitigation, warns about symlinked
    targets.
  - `[api]` block documents `control_token_file` alongside
    `token_file` (read-vs-control audience split).
  - `STARTER_MODULES` header documents per-module `config = "..."`
    as a trust boundary, ships `install -m 0640 -o root -g selfdef
    /usr/share/selfdef/modules/<slug>.toml.example ...` invocation.

### selfdef-api

- **`src/state.rs`** — `ApiState` carries
  `sse_subscribers: Arc<AtomicUsize>`, constructed at zero in
  `new`. Shared across clones.

- **`src/handlers.rs`** — two new constructs:
  - `SubscriberGuard` (RAII) — CAS-acquire a slot, decrement on
    drop. `try_acquire(counter, cap)` returns `None` when at
    cap.
  - `events_stream` — returns `Result<Sse<...>, ApiError>`
    (was infallible). On cap saturation: `503 Service
    Unavailable` with `{"error":"sse subscriber cap reached"}`.
    Otherwise the guard moves into the spawned writer task; on
    every `tx.send(frame)` the closure wraps the call in
    `tokio::time::timeout(SSE_SEND_TIMEOUT = 30s, ...)` — on
    timeout the task logs `reason = "slow-client timeout"` and
    returns, dropping the guard.
  - `ApiError::store(e)` — now logs the error via
    `warn!(error = %e, "api: store error")` and returns a
    generic `"store unavailable"` body instead of
    `format!("store: {e}")`.

- **`src/lib.rs`** — new test-helper re-export gated on
  `test-helpers`: `pub const MAX_SSE_SUBSCRIBERS: usize =
  handlers::MAX_SSE_SUBSCRIBERS`.

### selfdef-collector-eventstream

- **`src/lib.rs::open_with_integrity_check`** — `O_NOFOLLOW |
  O_NONBLOCK` open + fstat-on-FD + `is_file()` refusal.
  Closure of F-2027-035 (TOCTOU + symlink).

### selfdef-correlator

- **`src/lib.rs`** — verifier observability: rule-verify failures
  emit one structured log line per refused rule (closure of
  F-2027-019/-020/-021).

### selfdef-signing

- **`src/lib.rs`** — error-surface cleanup: `SigningError`
  variants made non-exhaustive, public `Verifier::verify_bytes`
  consolidated with internal call sites (closure of
  F-2027-011/-012/-013).

## Daemon-side machinery

- **SIGUSR2 fan-out** — now reloads bearer-token, rule-signing
  verifier, *and* re-verifies loaded rules under the new key
  (closure of F-2027-005). One summary log line per reload.

- **`api.token_file` mode check** — daemon-startup refuses
  world-readable `token_file` (closure of F-2027-031). Same
  pattern applied to `control_token_file` (closure of
  F-2027-032).

## Module-side machinery

- **SDD-006 v2 manifest-helpers migration** (closure of
  F-2027-024). At Phase 2 close: 6 modules at v2, suricata
  correctly exempt (writes no persistent files), vpn-bridge
  still at v1 — discovered by the Phase 3 module explorer as
  F-2028-015 and closed by PR #87. **As of PR #87**: every
  non-exempt module is v2 (`apply.sh` calls `module_record_file`,
  `uninstall.sh` iterates `module_render_files`). Time-anchor:
  this section was written at Phase 3 kickoff and claimed "all
  8 migrated"; that was wrong-at-write-time and is now accurate
  post-F-2028-015's closure.

- **integrity-sentinel** test fixture propagates
  `MODULE_INSTALLED_MANIFEST` to inline `Command` sites so
  parallel test runs don't trample each other.

## Documentation surface

Phase 2 audit itself shipped seven explorer docs:

- `docs/review/phase-2/20-recent-prs-audit.md`
- `docs/review/phase-2/30-crate-audit.md`
- `docs/review/phase-2/40-module-audit.md`
- `docs/review/phase-2/50-integration-audit.md`
- `docs/review/phase-2/60-docs-audit.md`
- `docs/review/phase-2/70-tests-audit.md`
- `docs/review/phase-2/80-security-audit.md`

Plus the running ledger (`99-findings-ledger.md`) and the
charter / inventory.

CHANGELOG: every closure PR adds a section.

## Test-infrastructure refactors

- **`crates/selfdef-cli/tests/common/mod.rs`** — exports
  `workspace_root()`, `module_dir(slug)`, `write_file()`,
  `write_executable()`, `last_stdout_line()`,
  `prepended_path()`, `snapshot_tree()`,
  `assert_tree_unchanged()`. 17 test files migrated to import
  from `common`; 45 duplicate fn definitions removed
  (closure of F-2027-049/-050/-051).

- **`crates/selfdef-api/tests/m12_api.rs`** — `build_state()`
  returns `(state, bus, store, TempDir)`. Both
  `std::mem::forget(dir)` sites replaced (closure of
  F-2027-055). `dummy_action_set` per-call `tempfile::tempdir()`
  (closure of F-2027-054). Metrics assertions use the
  format-strict prom parser (closure of F-2027-056).

- **`crates/selfdef-daemon/tests/m4_alert.rs` +
  `m8_honeytokens.rs`** — `#[tokio::test(start_paused = true)]`
  so the test runtime auto-advances virtual time on every
  `tokio::time::sleep` / `timeout` (closure of
  F-2027-052/-053).

## New test cases

- `validate_rbac_subject` — 7 unit tests + 1 CLI integration
  test (F-2027-060).
- `events_stream_rejects_over_cap_with_503` — 1 integration
  test (F-2027-061 + -062).
- `live_apply_invokes_nft_load_and_systemctl_start` —
  suricata live-positive (F-2027-046).
- `SseParser::*` — 9 unit tests (F-2027-010 follow-on).
- `cli_events_follow_tcp` — 5 integration tests (F-2027-010
  follow-on).
- `cloudflare_dry_run_must_be_a_noop_on_disk` +
  `tailscale_dry_run_must_be_a_noop_on_disk` — P-1
  backfill (F-2027-048).

## Numbers

- ~28 PRs merged during Phase 2 cycle.
- 0 new crates.
- 1 new operator-facing CLI capability (`events follow --url`).
- 0 new operator runbooks (the Phase 2 closure cycle was
  audit-driven, not feature-driven).
- ~25 new tests across the workspace.
- ~3000 lines added net per `git diff --stat 2d918ac..ee0e1a9`.
