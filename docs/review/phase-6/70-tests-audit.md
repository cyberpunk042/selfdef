# Phase 6 — tests audit

Audits the **159 new tests** added by the SDD-008 cycle against
SDD-005's four test-category contract (translation / pipeline
/ module-script / seam). Raises **F-2031-013** (nice → SDD-debt)
and **F-2031-014** (demoted on cross-check).

## Methodology

For each crate's test suite, sort tests against SDD-005's
categories and assess:

- **Translation tests** (Cat 1) — does every input-shape
  branch have positive + tolerance coverage?
- **Pipeline tests** (Cat 2) — does every operator-visible
  "promise" of the SDD-008 surface have at least one daemon-
  level pipeline test that would fail if the promise
  regressed?
- **Module-script tests** (Cat 3) — N/A for SDD-008 (no
  module work).
- **Seam tests** (Cat 4) — does every cross-crate boundary
  (orchestrator trait ↔ channels; engine ↔ dispatcher;
  dispatcher ↔ adapter; CLI ↔ engine) have a test?

Cross-check: real-time sleeps in tests (SDD-005 prefers
`tokio::time::pause()` for pipeline-determinism); test
isolation (no shared state across tests); deterministic
ordering.

## Test inventory by crate

| Crate | Tests | Categories represented |
| --- | --- | --- |
| `selfdef-notifier-orchestrator` | 8 | translation (Payload/PayloadId/error constructors) + seam (`StubChannel` compile-time fixture) |
| `selfdef-notifier-engine::lib` (EscalationEngine) | 16 | translation + seam (advance_rung monotonicity, acked-state-machine, take_due semantics) |
| `selfdef-notifier-engine::dispatcher` | 31 | seam (engine ↔ channels), behavioural (mode + profile + panic-floor) |
| `selfdef-notifier-engine::profile` | 13 | translation (Profile builders, from_name parser) |
| `selfdef-notifier-engine::wake_task` | 11 | seam (process_due, compute_sleep, handle_row) + lifecycle (cancellation) |
| `selfdef-integration-ntfy` | 9 | seam (wiremock HTTP) + translation (tag derivation) + Debug elision |
| `selfdef-integration-signal` | 7 | seam (subprocess exec via /bin/{true,false}) |
| `selfdef-integration-smtp` | 7 | translation (from_config validation) + behavioural |
| `selfdef-integration-twilio` | 12 | seam (wiremock) + translation |
| `selfdef-integration-slack` | 12 | seam (wiremock) + translation |
| `selfdef-integration-discord` | 13 | seam (wiremock) + translation |
| `selfdef-integration-wall` | 16 | seam (subprocess spawn) + behavioural (severity-floor, EPIPE) |
| `selfdef-cli::notify` | 9 | seam (CLI ↔ engine WAL) + translation (UUID parse, JSON escape) |
| `selfdef-daemon::dispatcher_adapter` | 5 | seam (legacy Notifier ABI ↔ orchestrator Payload) |
| `selfdef-config` (Phase 6 additions) | 2 | translation (TOML round-trip + unset-defaults) |

**Total: 171 tests** (159 cycle additions + the 2 Phase 6
integration-explorer round-trip tests + 7 additions from
the crate explorer). All exit zero on `cargo test --workspace
--locked`.

## Category-1 coverage — translation tests

Every channel crate has `from_config` validation tests
asserting both positive (well-formed config → valid
notifier) and tolerance (empty file / missing scheme / wrong
prefix → typed error variant) branches. Slack rejects
non-`https://hooks.slack.com/...`; Discord rejects
non-`https://discord.com/api/webhooks/...`; SMTP rejects
empty host/from/to; Twilio rejects wrong account_sid prefix.

Profile parsing has 13 tests covering builtin construction
(`auto`/`aggressive`/`patient`), `from_name` case-
insensitivity + unknown-name None, `custom` empty-rungs
rejection, `channels_for` / `max_rung` / `ack_window_for`
boundary indexing.

**Clean.** SDD-005 Cat-1 contract met.

## Category-2 coverage — pipeline tests

This is the gap. **F-2031-013 below**.

The SDD-008 cycle ships zero `crates/selfdef-daemon/tests/
m*.rs` integration test that exercises the engine path
end-to-end. The 31 dispatcher tests + 11 wake_task tests
cover the surface in isolation via direct API calls; no
test spins the full daemon (`bus + correlator + responder +
dispatcher_adapter + engine + wake_task + channels`) and
asserts the operator-visible promise "an unacked notification
re-fires at its deadline".

Existing daemon integration tests for the cycle's surface:

```
crates/selfdef-daemon/tests/
├── m10_ebpf.rs        — eBPF collector
├── m11_forensics.rs   — forensics module
├── m3_pipeline.rs     — generic pipeline (pre-SDD-008)
├── m4_alert.rs        — M4 legacy chain path
├── m5_sigma.rs        — sigma rules
├── m6_collectors.rs   — collector wiring
├── m8_honeytokens.rs  — honeytokens module
├── m9_ssh_wrap.rs     — ssh-wrap module
└── m_ai_machine.rs    — ai-machine pipeline
```

None of these exercises the engine path. `m4_alert.rs` is
the closest analog (M4 legacy notifier chain path); a
hypothetical `m4_engine.rs` would be its engine-path
counterpart.

## Category-4 coverage — seam tests

The 7 channel integration crates each carry seam tests
(wiremock for HTTP transports; coreutils stand-ins for
subprocess transports). The orchestrator trait crate's
`StubChannel` compile-time fixture pins trait-shape stability
across downstream crates.

Engine-side seam tests:

- `dispatcher_adapter.rs` (5 tests): Event → Payload
  conversion, engine persistence, profile-driven deadline
  computation.
- `notify.rs` (9 tests): CLI ↔ engine read/write via WAL.
- `wake_task.rs` (11 tests): process_due semantics,
  cancellation propagation.

**Clean.** SDD-005 Cat-4 contract met for every seam present.

## Findings

### F-2031-013 (nice → SDD-debt — open)

**Surface**: `crates/selfdef-daemon/tests/`.

The SDD-008 cycle ships **zero Category-2 (pipeline) tests**
for the engine path. Operator-visible promises that lack
daemon-level test coverage:

1. **"An unacked notification re-fires at its rung deadline"**
   — wake_task tests exercise `process_due` against a
   pre-populated engine row, but no daemon-spin-up test
   drives an event from the bus → through the responder →
   into `DispatcherAdapter::notify` → wait-for-deadline →
   verify the wake task re-fires.
2. **"`selfdefctl notify ack <id>` from a separate process
   stops further re-fires"** — `notify.rs` tests open the
   engine directly; no test verifies that the daemon's
   in-flight wake task observes the ack made by the CLI
   reader.
3. **"Mode = audit suppresses every send except panic-floor
   crossings"** — dispatcher.rs tests this in isolation;
   no daemon-level test verifies the daemon's startup
   wiring honours `[notifier].mode = "audit"`.

This is the same pattern flagged by **F-2026-082** in Phase
1 (the parent SDD-debt finding that spawned SDD-005). The
22-PR SDD-008 cycle shipped 159 tests — none Category-2.

**Severity = nice, escalating to SDD-debt** because the fix
is design-shaped:

- Need a deterministic-time harness (`tokio::time::pause()`
  with explicit virtual-time advances) — neither
  `m4_alert.rs` nor any other existing daemon integration
  test uses paused-time today, so this would be a new
  in-codebase pattern.
- Need to inject a mock `Channel` impl into the daemon at
  test time. The daemon currently constructs channels from
  `Config` via `build_channel_set`; tests would either need
  a config-construction path that accepts pre-built channels
  or a test-only `Channel` registry seam.
- The integration test surface area is large: covering all
  three promises above probably needs 3-5 tests in a new
  `m_notify_engine.rs` file.

**Recommendation**: file as SDD-debt under SDD-005's
implementation-PR pattern. The closure PR adds:

- New `m_notify_engine.rs` daemon integration test file.
- Three+ tests covering the promises listed above.
- A reusable `EngineHarness` helper in
  `crates/selfdef-daemon/tests/common/` (creating that
  file in the process) so future SDD-008 follow-ups
  (D-5e subscription filter, D-9 dashboard) inherit the
  pattern.

Not blocking Phase 6 closure: the operator-facing surface
**is** tested via the isolated unit tests; the gap is in
the audit-grade end-to-end pinning. Phase 6 closes with this
finding open and tracked.

### F-2031-014 (demoted)

**Surface**: `wake_task.rs::run_exits_on_cancellation`, line
393.

```rust
// Give the task a moment to enter the loop, then cancel.
tokio::time::sleep(Duration::from_millis(50)).await;
```

The only real-time sleep in the new test surface. Initially
flagged as a SDD-005 pipeline-determinism concern (real-time
sleeps make pipeline tests flake under scheduler pressure).

Cross-check:

- This is **not a pipeline test** in SDD-005's
  taxonomy — it's a Category-4 seam test for cancellation
  propagation. The sleep is scheduler-jitter absorption ("let
  the spawned task reach its `tokio::select` arm before we
  cancel"), not pipeline-determinism waiting.
- The assertion is timeout-bounded
  (`tokio::time::timeout(Duration::from_secs(2), …)`) so a
  scheduler-stall longer than 50ms fails with a clear
  message rather than flaking silently.
- A `tokio::time::pause()` rewrite is feasible
  (yield-loop-until-task-is-parked) but the resulting test
  is harder to read for marginal robustness gain on a single
  50ms point. The 2s timeout already absorbs the contingency
  the rewrite would address.

**Demoted**. The sleep is documented, deliberate, and pattern-
distinct from "pipeline tests must be deterministic". If a
second such sleep appears in a future cycle (e.g. a wake-task
follow-up using sleeps to drive virtual-time advance instead
of `tokio::time::advance`), the recommendation flips back to
nice.

## Misc observations — no finding

- **CLI `list` output is not asserted**. `list_after_enqueue`
  and `list_on_empty_engine` call `list(&cfg, ...)` and
  verify it returns `Ok` cleanly, but don't capture stdout.
  This matches SDD-005's Cat-3-shaped contract for CLI
  verbs (functions return cleanly on documented happy
  paths; format-level regressions land via operator
  observation). The `serde_json_string_escapes_quotes_and_
  control_chars` test pins the load-bearing JSON-escape
  helper, which is the most regression-prone bit.

- **Engine state-machine invariants are exhaustively
  pinned**. 16 tests across `EscalationEngine`:
  `advance_rung_updates_index_and_deadline`,
  `advance_rung_refuses_after_ack`,
  `advance_rung_refuses_backward_or_same_rung`,
  `advance_rung_unknown_event_is_noop`,
  `record_ack_is_idempotent`,
  `close_event_is_idempotent`, etc. Pre-merge regressions
  on the monotonic rung-advance guard would fail at least
  three of these.

- **Wake-task uses `tokio::time::sleep` in production**
  (line 90, `wake_task::run` body). Pipeline tests for it
  (F-2031-013 above) would need `tokio::time::pause()` +
  `advance` to drive the loop deterministically.

## Status

- F-2031-013 raised + open (SDD-debt for daemon-level
  pipeline test of engine path).
- F-2031-014 demoted on cross-check (50ms sleep is scheduler-
  jitter absorption, not pipeline-determinism).
- Categories 1, 4 audit clean.
- Category 2 has a documented gap; Category 3 is N/A.

## Hand-off

- **Security explorer (next, final)**: pick up F-2031-003
  (0BSD allow-list re-audit) plus credential-handling for
  all 7 channels and wall(1) TTY broadcast.
- **Follow-up PR (outside audit programme)**: implementation
  of F-2031-013 closure (daemon-level pipeline tests for
  the engine path). Ships under SDD-005's D-3 implementation-
  PR pattern.
