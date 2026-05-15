# Phase 6 — integration audit

Walks the SDD-008 startup-time and config-time seams: how
operator config crosses the boundary from `selfdef.toml` →
`Config::load` → daemon-startup wiring → engine + dispatcher
+ wake-task lifecycle. Also ships the F-2031-009 stopgap
warning raised by the module explorer.

## Methodology

For each operator-facing knob added by SDD-008, follow the
data flow from TOML to runtime effect:

1. **TOML parse** — `selfdef-config` deserializes into typed
   structs.
2. **Daemon construction** — `build_notifier_path` /
   `build_channel_set` translate config types into engine /
   dispatcher / wake-task inputs.
3. **Runtime effect** — the choice is visible in a log line,
   a channel filter, a deadline computation, or a mode-bypass
   decision.

Cross-check: do the parse hops have round-trip test
coverage? Are misconfigurations either rejected loudly or
documented in a startup warn? Is the wake-task lifecycle
joined cleanly into the daemon's shutdown sequence?

## Seams audited

| # | TOML key | Parse hop | Runtime hop |
| --- | --- | --- | --- |
| 1 | `[notifier].escalations_path` | `NotifierConfig::escalations_path: Option<PathBuf>` | branches `build_notifier_path`: `Some` → engine, `None` → legacy chain |
| 2 | `[notifier].mode` | `NotifierConfig::mode: String` (default `"enforce"`) | `parse_dispatcher_mode` → `Mode::Enforce` / `Mode::Audit` |
| 3 | `[notifier].profile` | `NotifierConfig::profile: String` (default `"auto"`) | `parse_dispatcher_profile` → `Profile::auto`/`aggressive`/`patient`/custom |
| 4 | `[notifier].panic_floor` | `NotifierConfig::panic_floor: Option<String>` | `parse_severity_floor` → `Option<SeverityId>` → dispatcher panic-floor |
| 5 | `[notifier.profiles.<name>]` | `HashMap<String, ProfileConfig>` | `parse_dispatcher_profile` builds `Profile::custom` with `Rung::with_channels` |
| 6 | `[notifier.subscriptions.<channel>]` | `HashMap<String, SubscriptionConfig>` | applied **only** in legacy chain path (F-2031-009) |
| 7 | `[notifier.ntfy]` etc. (7 channel sections) | typed struct per channel | `build_channel_set` / `build_notifier_chain` construct channel instances |
| 8 | wake-task lifecycle | N/A | spawned in `build_notifier_path`; joined with 5s timeout after `shutdown.cancel()` |

## Findings

### F-2031-009 (important, SDD-debt — **stopgap shipped in this PR**)

The module explorer raised F-2031-009: per-channel
subscription filters silently stop being applied when the
operator switches to the engine path. The principled fix
(wiring `SubscriptionConfig` through `PayloadDispatcher`)
ships under a separate `feat(sdd-008): D-5e` PR.

**Stopgap landed in this PR**: `build_notifier_path` now
emits a structured `warn!` at daemon startup when both
`escalations_path` is set **and** `[notifier.subscriptions]`
is non-empty:

```text
WARN [notifier.subscriptions] is configured but ignored on
     the engine path (escalations_path set). Per-channel
     severity_floor + event_kinds filters apply only on the
     legacy chain path until SDD-008 D-5e ships.
     See docs/review/phase-6/40-module-audit.md F-2031-009.
     subscription_channels=["discord", "slack"]
```

The warning fires once at startup (not per event) — the
right cardinality, since the misconfiguration is a static
property of `selfdef.toml`. The `subscription_channels`
field lists the affected channels so the operator can
quickly check which filters are inert.

Status: F-2031-009 remains **open** in the ledger (the
underlying defect is unfixed; only the operator-discovery
problem is mitigated). The D-5e PR closes it for real.

### F-2031-010 (nice, closed-in-place)

**Surface**: `selfdef-daemon/src/main.rs::parse_dispatcher_profile`.

The custom-profile rung builder silently mapped any
non-positive `ack_window_secs` to 300:

```rust
let window = if r.ack_window_secs > 0 {
    r.ack_window_secs
} else {
    300
};
```

An operator who typoed `ack_window_secs = 0` (or `-60`) on a
custom profile rung saw their `aggressive`-shaped profile
silently use 5-minute waits on that rung. No warn, no
indication anything was wrong. Closely related to the
F-2031-007 class of "operator-config-doesn't-match-runtime-
behaviour" defects.

**Severity = nice** — surface area is small (only operator-
defined custom profiles, not the three builtins), and the
fallback value is the legacy default rather than something
unsafe. But the silence is the wrong cost-benefit trade:
the fix is a one-line warn, the benefit is operators notice
their config is wrong.

**Closed in this PR**: `parse_dispatcher_profile` now logs a
structured warn naming the profile, the rung index, the
operator's invalid value, and the fallback. The structural
change uses `.iter().enumerate()` so the rung index can be
included in the warn (operator can grep the log directly).

## Config round-trip coverage

The `selfdef-config` crate's existing test set covered the
SDD-007 D-4 SSE-cap surface (F-2029-005 / F-2029-006) but
**zero** coverage of the SDD-008 13-element surface. This
audit closes the gap with two new tests:

- `sdd_008_notifier_surface_round_trips_from_toml` —
  end-to-end round-trip of a representative
  config covering escalations_path + mode + profile +
  panic_floor + an ntfy channel section + a discord
  subscription + a custom profile with two filtered rungs.
- `sdd_008_notifier_surface_defaults_when_unset` — pins the
  unset-defaults contract: `escalations_path = None` (legacy
  chain path), `mode = "enforce"`, `profile = "auto"`,
  `panic_floor = None`, empty `profiles`/`subscriptions`
  maps.

Together they pin the schema shape; any future refactor
that drops a `#[serde(default)]` or renames a key gets
caught at parse time. **`selfdef-config` test count: 4 → 6.**

## Startup wiring trace

`build_notifier_path` (`crates/selfdef-daemon/src/main.rs`):

1. If `escalations_path` is `None`: build the legacy chain,
   warn if empty, return `(Arc<NotifierChain>, None)`.
2. Else open the engine (`EscalationEngine::open`). On error,
   log + fall back to the legacy chain — operator's daemon
   stays up even if the engine file is wedged.
3. Build channel set via `build_channel_set`. Warn if empty.
4. **F-2031-009 stopgap**: warn if `[notifier.subscriptions]`
   is non-empty.
5. Parse mode + profile + panic_floor (each with its own
   warn-on-unknown).
6. Construct `PayloadDispatcher` with mode + profile + optional
   panic_floor.
7. Spawn `wake_task::run` with a clone of the dispatcher and
   the daemon-wide `CancellationToken`.
8. Return `(Arc<DispatcherAdapter>, Some(wake_handle))`.

**Clean**. The fallback-to-legacy-chain branch in (2) is
the right call — engine wedging shouldn't take the daemon
down with it.

## Wake-task lifecycle

Spawn: `tokio::spawn` inside `build_notifier_path` (step 7
above). The `JoinHandle` returns to `main` and lives in the
local `wake_task_handle: Option<JoinHandle<()>>`.

Shutdown sequence in `main`:

```rust
shutdown.cancel();
// ...
let _ = tokio::time::timeout(Duration::from_secs(5), responder_task).await;
if let Some(h) = wake_task_handle {
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    info!("escalation wake_task stopped");
}
```

- Wake task joined **after** the responder. Correct: the
  responder is the source of `dispatcher.submit` calls; we
  want it drained before the wake task exits.
- 5-second timeout matches all other task handles in the
  shutdown sequence. The wake task's biased
  `tokio::select` returns immediately on cancel; 5s is more
  headroom than needed.
- No "wake task panicked" → "daemon hangs" path because of
  the timeout.

**Clean.**

## Path equivalence — same Event, two paths

Picked an arbitrary `DETECTION_FINDING` event and traced
the wire output both paths produce:

| Element | Legacy chain | Engine path |
| --- | --- | --- |
| `render_title(event)` | Yes (per-channel) | Yes (in DispatcherAdapter) |
| `render_body(event)` | Yes (per-channel) | Yes (in DispatcherAdapter) |
| `priority_for(severity)` | Yes (in NtfyNotifier) | Yes (in NtfyNotifier::send) |
| Per-channel subscription filter | **Yes** (chain applies) | **No** (F-2031-009) |
| Initial-deadline | N/A | `profile.ack_window_for(0)` after F-2031-007 |
| Channel order | Operator config order | Operator config order |
| First-success-wins | Yes (chain) | Yes (fire_channels) |
| Retry on failure | Per-channel retry (ntfy) | Per-channel retry + rung re-fire |

The two paths diverge **only** on the subscription filter
(F-2031-009 documents and warns) and on the engine's
persistence + retry contract (intentional — that's the
engine path's value-add). Wire-bytewise output for a
configured-on-both-channels event is identical.

## Misc observations (not findings)

- `Mode::Audit` is opt-in via `[notifier].mode = "audit"`.
  The daemon logs `mode = "audit"` at startup but does not
  *warn* — the operator chose it, so an info-level log is
  the right cardinality. No finding.
- The `[notifier].panic_floor` warn-on-unknown path
  correctly falls back to "no floor", which is the safe
  failure mode (audit mode then suppresses everything).
- `dispatch_payload` (no-rung-filter) remains `pub` with no
  production caller. Used by 5 tests in
  `dispatcher.rs`. Either harmless test-API or smell of
  unstated contract; the docs explorer can decide if a
  rustdoc caveat is worth adding.

## Status

- **F-2031-009 stopgap shipped**: startup warn when
  `[notifier.subscriptions]` is non-empty on engine path.
  The underlying defect is still tracked for D-5e PR.
- **F-2031-010 closed in-place**: silent 300s fallback on
  invalid custom-profile `ack_window_secs` now warns.
- **`selfdef-config` test count: 4 → 6** — SDD-008 surface
  round-trip + unset-defaults pinned.
- Wake-task lifecycle, engine open-on-failure fallback,
  path equivalence, panic-floor parse all audit clean.

## Hand-off

- **Docs explorer**: pick up F-2031-001 (D-7 commit-title
  label collision) and consider whether SDD-008 should
  document the new startup warning surface (F-2031-009
  stopgap, F-2031-010 invalid-ack-window warn).
- **Tests explorer**: audit the 159 new tests for SDD-005
  pipeline-determinism compliance (no real-time sleeps in
  pipeline tests) — the orchestrator + engine + wake-task
  test suite is a candidate area to scrutinize.
- **Security explorer**: pick up F-2031-003 (0BSD allow-list
  re-audit) plus credential-handling for all 7 channels.
