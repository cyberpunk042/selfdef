# Phase 6 — crate audit

Audit pass over the **9 new crates** shipped by the SDD-008
cycle: `selfdef-notifier-orchestrator`, `selfdef-notifier-engine`,
and the seven `selfdef-integration-*` channel crates. Closes
the F-2031-002 coverage-parity gap raised by the recent-PRs
explorer.

## Methodology

For each crate: read `Cargo.toml`, top-level lib docs, every
public type and trait impl, every error variant, every
secret-bearing field's `Debug` shape (if customized), and every
test. Walk the dependency graph downward — each integration
crate's deps must match the contract codified by
`docs/dev/integrations.md` (workspace-managed; thin
adapter-only).

Look for:

- **API shape drift** vs. SDD-008 (trait crate vs. engine vs.
  channel adapters).
- **Error taxonomy** — `ChannelError` / `NotifierError`
  mappings consistent across the 7 channels.
- **Secret handling** — derived `Debug` would leak credentials;
  channels carrying secrets must have custom impls that elide.
- **Test seams** — every reachable success/error edge has
  proportionate coverage.
- **Cross-crate idiom drift** — patterns established in one
  channel honoured in the others.

## Trait crate: `selfdef-notifier-orchestrator`

**Shape (346 LOC, 8 tests).** Pure ABI layer:

- `Payload` — plain-data struct (id, optional event_id, title,
  body, severity, optional ack_link). Read-only for channels.
- `PayloadId(Uuid)` — UUIDv7 (sortable by issuance);
  `as_short_str` for log inclusion; `Default` via `new`.
- `EventId(Uuid)` — structural newtype to prevent
  `PayloadId↔EventId` swap at compile time.
- `DeliveryReceipt` — `Option<String>` native message id;
  `native(id)` + `empty()` constructors.
- `ChannelError` — `Transport(String)`, `Remote { status u16,
  body }`, `Timeout`, `Other(String)`. Two convenience ctors.
- `AckReplyHint` — enum of `HttpClickLink` / `NativeButton` /
  `TextReply` / `SlashCommand`.
- `Channel` async-trait, `Send + Sync` bound: `name() ->
  &str`, `async send(&Payload) -> Result<DeliveryReceipt,
  ChannelError>`, `supports_ack_reply() -> bool` (defaults
  false), `ack_reply_format() -> Option<AckReplyHint>`
  (defaults None).
- Re-exports `SeverityId` from `selfdef-core`.

**Observations**:

- Default impls on `supports_ack_reply` / `ack_reply_format`
  mean a new channel starts in the "no native ack" posture by
  default. Safe default.
- `StubChannel` compile-time test pins the trait shape; any
  signature drift breaks this test before downstream channel
  crates rebuild.
- `Channel: Send + Sync` is correct for sharing across
  rung-fan-out tasks.

No findings. Trait crate is **clean**.

## Engine crate: `selfdef-notifier-engine` (4 modules)

**Shape (2,631 LOC, 71 tests):**

- `src/lib.rs` (701 LOC, 16 tests) — `EscalationEngine` around
  `Arc<Mutex<rusqlite::Connection>>`. Schema:

  ```sql
  notification_escalations(
    event_id     TEXT PRIMARY KEY,
    payload_id   TEXT NOT NULL,
    title        TEXT NOT NULL,
    body         TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    ack_link     TEXT,
    rung_index   INTEGER NOT NULL,
    deadline_at  INTEGER NOT NULL,
    acked_at     INTEGER,
    created_at   INTEGER NOT NULL
  );
  ```

  All access goes through `spawn_blocking` so the SQLite
  lock never crosses an async yield-point. WAL journal mode
  enables concurrent reads (the CLI's `notify list` verb
  reads while the daemon writes).

- `src/dispatcher.rs` (1,048 LOC, 31 tests) —
  `PayloadDispatcher` façade. Builds: engine handle, channel
  vec, `Mode`, `Profile`, optional panic-floor. Builders
  `with_mode` / `with_profile` / `with_panic_floor`. APIs:
  `submit` (persist + fire), `dispatch_payload` (fire no
  persist), `dispatch_payload_for_rung` (D-6c per-rung
  filter), `record_ack`, `close_event`. The
  `crosses_panic_floor` predicate compares
  `SeverityId::repr() as u32` — works because severity is
  enum-with-explicit-discriminants in `selfdef-core`.

- `src/profile.rs` (346 LOC, 13 tests) — `Rung {
  ack_window_secs: u64, channels: Vec<String> }`;
  `Rung::new` (empty channels = WUPHF), `Rung::with_channels`
  (per-rung filter), `Rung::allows_channel`. `Profile`
  carries name + rungs; `Profile::auto` (3 rungs, 60s/300s/
  1800s), `Profile::aggressive` (3 rungs, 30s/60s/300s),
  `Profile::patient` (3 rungs, 300s/1800s/7200s).
  `Profile::custom(name, rungs)` returns
  `ProfileBuildError::EmptyRungs` when given an empty vec.
  `Profile::from_name` for builtin lookup.

- `src/wake_task.rs` (536 LOC, 11 tests) — background loop
  with `tokio::select` biased on the `CancellationToken`.
  `compute_sleep` derives sleep duration from
  `engine.next_pending_at()`. `process_due` walks rows
  returned by `engine.take_due()` and calls
  `handle_row` per. `handle_row` advances the rung (subject
  to monotonic + `acked_at IS NULL` guard) and calls
  `dispatcher.dispatch_payload_for_rung`.

**Observations:**

- The schema embeds `event_id TEXT PRIMARY KEY` — one row
  per event, not per attempt. The escalation state machine
  walks rungs *in place* (update `rung_index`,
  `deadline_at`); failed deliveries don't double the row
  count. Sound choice; the alternative (one row per attempt)
  would explode for retried channels.
- The monotonic-advance guard is implemented as
  `WHERE event_id = ?1 AND acked_at IS NULL AND rung_index <
  ?2` — operator-ack racing wake-task advance loses
  (`acked_at` set by ack path; subsequent advance query
  matches 0 rows). Sound.
- WAL mode + `spawn_blocking` is the correct posture for
  daemon (writer) + CLI (concurrent reader) coexistence.
- Severity-as-`u32` for panic-floor comparison relies on
  `SeverityId`'s representation contract; if `selfdef-core`
  ever migrates to non-explicit discriminants, this breaks
  silently. Mitigation: 13 panic-floor tests in
  `dispatcher.rs` pin the expected ordering bytewise.

No findings. Engine + dispatcher + profile + wake-task are
**clean** at the shape level. Module-level audit (PR 4) will
walk the dispatcher path end-to-end.

## Channel integration crates (7)

Each crate implements both `Notifier` (legacy M4 ABI) and
`Channel` (orchestrator ABI). The `from_config` constructor
validates operator-shaped inputs; per-channel error variants
bridge into both `NotifierError` and `ChannelError`. Below,
each crate's audit notes:

### `selfdef-integration-ntfy` (284 LOC → 7 tests after this PR)

- `NtfyNotifier { url, topic, token, client }`. Derived
  `Debug` would print the bearer-token. **Observation**: the
  current `#[derive(Debug)]` prints the `Option<String>`
  field verbatim. **Closed in this PR**: see
  F-2031-005 below.
- `from_config(url, topic, token_file)` reads token from
  disk if present, trims whitespace, treats empty as `None`.
  No URL-scheme validation — accepts `http://` (vs.
  Slack/Discord which require `https`).
- `post()` retries up to 3× with exponential backoff
  (200/400/800ms). Maps:
  - `NtfyDeliveryError::NotConfigured` → `Other` /
    `NotConfigured`.
  - `Transport(String)` → both `Transport` variants.
  - `Remote { status, message }` → `Remote { status, body }`.
- Tag derivation: `shield` baseline + ATT&CK technique-ids
  appended when present. Helper `ntfy_tags_for(&Event)`
  shared between legacy + Channel paths via the post() core.

**Closes F-2031-002 in part:**

- `wiremock_tests::happy_path_against_wiremock` — POST to
  mock server with all headers present (Title, Priority,
  Tags) → 200 OK.
- `wiremock_tests::non_success_status_maps_to_remote_error`
  — 403 from server → `ChannelError::Remote(403)` after the
  3-attempt retry loop exhausts.
- `wiremock_tests::bearer_token_attached_when_configured` —
  `Authorization: Bearer secret-token-xyz` header asserted
  on the mock matcher.

**Raises F-2031-005:** see the cross-channel `Debug`
elision finding below.

### `selfdef-integration-signal` (229 LOC → 7 tests after this PR)

- `SignalCliNotifier { binary, account, recipient }`.
  No secrets in fields; derived `Debug` is acceptable.
- `run()` shells `signal-cli -a <account> send -m <message>
  <recipient>` via `tokio::process::Command`. No shell
  interpolation; args passed via `.arg()` (no command
  injection vector).
- Subprocess exit mapping: `Subprocess { status, stderr }` →
  `ChannelError::Remote { status: status.unsigned_abs() as
  u16, body: stderr }`. Documented in-code: "subprocess exit
  codes don't naturally map to HTTP-style statuses".
- Acks deliberately disabled (`supports_ack_reply() →
  false`); SDD-008 Q-B working assumption is that v1 uses
  CLI / HTTP-link paths instead of signal-cli daemon-mode
  JSONRPC parsing.

**Closes F-2031-002 in part:**

- `run_succeeds_when_binary_exits_zero` — binary=
  `/bin/true` (coreutils) → `Ok`.
- `run_maps_nonzero_exit_to_remote_error` — binary=
  `/bin/false` → `ChannelError::Remote(1)`.
- `run_maps_missing_binary_to_transport_error` — binary=
  `/nonexistent/path/...` → `ChannelError::Transport(_)`.
- `legacy_notify_succeeds_when_binary_exits_zero` — same
  shape against the legacy `Notifier` ABI to pin the
  bytewise-identical behaviour the SDD-008 D-2c migration
  contract requires.

The tests use coreutils `/bin/true` and `/bin/false` which
are universally available on the daemon's target platforms;
no real `signal-cli` is required.

### `selfdef-integration-smtp` (445 LOC, 7 tests)

- `SmtpNotifier` — host, port, username, password, from-
  addr, to-addr, starttls. Custom `Debug` elides
  `password`; only host:port + from/to surface. Verified.
- `from_config` validates: non-empty host, non-empty username,
  non-empty `from`/`to`, password loaded from
  `password_file` (mirrors ntfy's token pattern).
- Uses `lettre` for SMTP transport; STARTTLS configurable.
- Subprocess-shaped is N/A — SMTP is HTTP-class transport.

### `selfdef-integration-twilio` (589 LOC, 12 tests)

- `TwilioNotifier { account_sid, auth_token, from,
  recipients, base_url }`. Custom `Debug` elides
  `auth_token` and `account_sid`. Verified.
- `from_config` validates account_sid prefix (Twilio SIDs
  start with `AC`), auth-token-file non-empty, from-number
  E.164 shape, recipients non-empty.
- `wiremock` end-to-end tests pin Basic-Auth header
  (`base64(account_sid:auth_token)`), per-recipient POST,
  Twilio's `From=...&To=...&Body=...` form-encoded body.

### `selfdef-integration-slack` (432 LOC, 12 tests)

- `SlackNotifier { webhook_url, username, icon_emoji }`.
  Custom `Debug` elides the webhook (T-id/B-id/secret
  fragments hidden). Verified.
- `from_config` enforces `https://hooks.slack.com/...` and
  rejects plaintext / wrong-host.
- Severity → emoji map: `:rotating_light:` (high), `:fire:`
  (critical), `:information_source:` (info), …
- `wiremock` tests pin happy-path 200, 404 → Remote, ack-link
  rendering when present.

### `selfdef-integration-discord` (443 LOC, 13 tests)

- `DiscordNotifier { webhook_url, username }`. Custom
  `Debug` elides webhook token. Verified.
- `from_config` enforces `https://discord.com/api/webhooks/...`
  prefix.
- Renders as Discord embed JSON; color-code per severity.
- `wiremock` tests pin happy-path, 4xx → Remote, embed
  structure.

### `selfdef-integration-wall` (483 LOC, 16 tests)

- `WallChannel { binary: PathBuf, severity_floor: SeverityId
  }`. No secrets; derived `Debug` is fine.
- `from_config` accepts an optional binary path; default
  `/usr/bin/wall`.
- Spawns `tokio::process::Command` with stdin piped — message
  bytes go through stdin, never the argv. No shell
  interpretation. No PATH lookup (`from_config` resolves to
  absolute path or errors).
- 16 tests is the highest test count of the 7 channel crates;
  the wall(1) surface required exhaustive coverage of the
  pipe-stdin / no-binary / non-zero-exit / kill-signal paths.

**Raises F-2031-006 (important, closed in this PR):** the
`broadcast()` stdin path fails eagerly on EPIPE if the child
exits before reading stdin. Manifested as a flaky CI failure
on `ubuntu-latest` (test `at_or_above_floor_spawns_and_uses_
exit_status` saw `Broken pipe (os error 32)` writing to
`/bin/true`'s closed stdin). Same race latent in
`nonzero_exit_surfaces_as_remote_error_via_channel` for
`/bin/false`. **Closed in this PR** by tolerating EPIPE on
both `write_all` and `shutdown` in `broadcast()` and falling
through to the wait-on-exit path. Stress-tested 15× green;
matches the production-correct semantics that a real wall(1)
on a TTY-less host can also exit before consuming stdin.

## Findings

### F-2031-006 (important, closed-in-place)

`selfdef-integration-wall::broadcast()` failed eagerly on
EPIPE when the child process exited before the parent
finished writing stdin. Surfaced as a flaky CI failure on
`ubuntu-latest` (caught after PR #133's first push; the
prior wall PR #128 had latent flakiness that hadn't yet
fired on the cycle's CI runs). Two tests exposed it
(`at_or_above_floor_spawns_and_uses_exit_status` against
`/bin/true`; `nonzero_exit_surfaces_as_remote_error_via_
channel` against `/bin/false`). The race is scheduler-
dependent: on faster runners the child exits before the
parent's `write_all` resolves; the syscall returns EPIPE
and `WriteStdin` swallows the more-informative exit-status
that the wait-path would have surfaced.

Marked **important** because:

- CI-blocking when it fires.
- Production-relevant: a real `wall(1)` invocation on a host
  with zero logged-in TTYs (cron context, headless CI) may
  exit before consuming stdin, which under the pre-fix
  semantics surfaces as a `Transport`-class error instead of
  the more-informative `Subprocess { status: 0 }` Ok-path.

**Closed in this PR** by tolerating
`io::ErrorKind::BrokenPipe` on both `write_all` and
`shutdown` and falling through to `wait_with_output`. Other
IO error kinds (permission denied, OS-level resource
exhaustion) still escalate as before. Stress-tested 15×
green locally.

### F-2031-002: closed-in-place

The 4-test ntfy / 3-test signal coverage gap is closed by
this PR. Both crates are now at 7 tests each and exercise
their respective `post()` / subprocess-exec paths against
wiremock and coreutils stand-ins.

### F-2031-005 (nice): cross-channel `Debug` shape inconsistency

Walking the 7 channel crates, the secret-elision posture is
*almost* uniform but not quite:

| Crate | Has secret field? | Custom `Debug`? |
| --- | --- | --- |
| ntfy | `token: Option<String>` (bearer) | **derived** ← leaks |
| signal | none | derived (fine) |
| smtp | `password: String` | custom (elides) ✓ |
| twilio | `auth_token, account_sid` | custom (elides) ✓ |
| slack | `webhook_url` (carries secret token segment) | custom (elides) ✓ |
| discord | `webhook_url` (carries secret token segment) | custom (elides) ✓ |
| wall | none | derived (fine) |

`NtfyNotifier` carries an `Option<String>` bearer token but
derives `Debug`, which would render the token verbatim in any
`tracing::error!("{notifier:?}", …)` log statement. The legacy
`selfdef-notifier` path predates the secret-elision pattern
the later channels adopted; the migration to a separate
`selfdef-integration-ntfy` crate (PR #112) didn't catch the
upgrade.

**Severity**: nice. There is no current code path
constructing a `Debug` of `NtfyNotifier` in production (the
daemon doesn't `tracing::debug!("{:?}", notifier)`); the
leak surface is reachable only by future code or operator-
filed bug reports that paste `Debug` output. The fix is a
one-line custom impl + a test pinning the elision shape, on
the model of `SlackNotifier`'s `debug_elides_webhook_secret`
test.

**Closed in this PR**: `NtfyNotifier`'s derived `Debug` is
replaced with a custom impl that elides the bearer token to
`<redacted>` (showing only its presence/absence, never its
value). Two tests pin the contract:

- `debug_elides_bearer_token` — secret value never appears in
  the `Debug` form even when configured.
- `debug_shows_no_token_when_none` — no `<redacted>` marker
  surfaces when the token is `None`.

The 7 channel crates now have **uniform secret-elision
posture**.

## Status

- Trait crate (`selfdef-notifier-orchestrator`): **clean**.
- Engine crate (`selfdef-notifier-engine`, 4 modules):
  **clean** at the shape level (module-level audit follows).
- 7 channel integration crates: **clean** after this PR
  closes F-2031-002 (ntfy + signal coverage), F-2031-005
  (ntfy Debug elision), and F-2031-006 (wall EPIPE-on-stdin
  flake). The flake on F-2031-006 was caught by CI on this
  PR; the underlying defect predates the PR (introduced in
  PR #128's D-8 work) and was not exercised by previous
  CI runs.

## Hand-off

- **Module explorer (PR 4)**: walk the dispatcher path end-
  to-end (engine → channel-vec → wake-task) and the daemon
  wiring. No findings hand-off; the engine + dispatcher
  shapes audit clean at the crate level.
- **Security explorer**: re-audit the secret-elision posture
  in the security pass to confirm no other channel-side
  Debug-leak vectors remain. F-2031-005 ↔ closed by this PR;
  no carry-forward expected.
