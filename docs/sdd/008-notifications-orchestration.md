# SDD-008 — Notifications orchestration + integrations taxonomy

> Status: **draft (charter)** — not yet implemented; design under
> review.
> Owner: design team
> Last updated: 2026-05-14
> Closes findings: none yet — net-new design.

## Implementation status

**All design points D-1..D-8 shipped** during the Phase-6 cycle
(PRs `#109`..`#130`). D-9 (dashboard) remains explicitly
deferred — separate design conversation. The Phase 6
closure-cycle audit (`docs/review/phase-6/`) walks the
implementation; findings raised under that audit are tracked
in the F-2031-NNN ledger.

Per-D status:

| D | Title | Status | PR(s) |
| --- | --- | --- | --- |
| D-1 | Taxonomy: modules ≠ integrations | shipped | #110 |
| D-2a | `selfdef-notifier-orchestrator` trait crate | shipped | #111 |
| D-2b | `selfdef-integration-ntfy` carve | shipped | #112 |
| D-2c | `selfdef-integration-signal` carve | shipped | #113 |
| D-3 | Per-channel subscription model | shipped (legacy chain path) | #115 + #117 |
| D-5e | Subscription filter on engine path | shipped (closes Phase 6 F-2031-009) | post-Phase-6 PR |
| D-4 HTTP ack | `GET /notify/ack/<token>` endpoint + ack_token column + ack_link rendering | shipped (Phase 6 "remaining backlog" item from charter) | post-D-4 PR |
| Q-G PagerDuty | Events API v2 channel (`selfdef-integration-pagerduty`) | shipped | this PR |
| D-4 | `selfdefctl notify {ack,forget,list}` | shipped | #123 |
| D-5a | `EscalationEngine` persistent layer | shipped | #118 |
| D-5b | `PayloadDispatcher` façade | shipped | #119 |
| D-5c | Wake task + rung advancement | shipped | #122 |
| D-5d | Daemon wiring | shipped | #124 |
| D-6a | Operating modes (enforce / audit) | shipped | #125 |
| D-6b | Named profiles (auto / aggressive / patient) | shipped | #126 |
| D-6c | Per-rung channel filtering + custom profiles | shipped | #129 + #130 |
| D-7 | Panic floor (audit-mode bypass) | shipped | #127 |
| D-8 | wall(1) session-attention | shipped | #128 |
| D-9 | Dashboard | **deferred** — separate SDD when scoped |

Plus 4 channel crates ship under SDD-008 even though they
landed under Q-letter open questions rather than numbered Ds:
**smtp** (Q-E, PR #114), **twilio** (Q-D, PR #116),
**slack** (Q-C, PR #120), **discord** (PR #121). See the
"PR labels" appendix below.

## Why now

Two pressures converge:

1. **Operator pull for more channels.** M4 shipped the `Notifier`
   trait with `NtfyNotifier` + `SignalCliNotifier` chained via
   `NotifierChain` (`crates/selfdef-notifier`). Operators want
   SMS (Twilio), email (SendGrid or SMTP), Slack, Discord, and the
   ability to escalate when nobody is responding. The current
   `try-each-in-order, first-success-wins` model has no concept of
   acknowledgement, escalation, or operator-tunable personality.

2. **Architecture pull for a clean integrations boundary.** Right
   now the notifier ships *both* a chain abstraction and the two
   concrete channels in one crate. Adding 5+ more channels turns
   `selfdef-notifier` into a god-crate with `reqwest`,
   `signal-cli`-shaped subprocess, future `twilio` SDK, future
   `lettre`/SMTP, etc. all glued together. We need an
   **integrations** layer that is distinct from **modules**: one
   crate per external service, each a pure adapter with no install
   responsibility, no host mutation, no topology ownership.

The SDD covers both at once because the orchestrator design
constrains the integration shape, and vice versa.

## Goals

1. **Multi-channel orchestration with operator-controlled
   escalation** — if an operator does not acknowledge a high-
   severity event within an operator-configurable window, the
   orchestrator escalates to the next-rung channel automatically.
2. **Channel separation is structural** — each external service
   lives in its own `crates/selfdef-integration-<service>` crate
   that depends only on `selfdef-core` (event types) +
   `selfdef-notifier-orchestrator` (trait); never on host
   installation code, never on `selfdef-daemon`.
3. **Ack-driven, not blind-retry** — the orchestrator advances the
   escalation chain only on (ack timeout) → next rung, never on
   "we sent it, hope it landed." First-success-wins is replaced by
   first-ack-wins.
4. **Operator profiles for personality** — named profiles bundle
   subscriptions + escalation cadence + DEFCON dial. Built-in
   profiles cover `auto`, `sms-first`, `secure-first`, `wuphf`,
   `silent`, `audit`, `test`. Operators may define custom
   profiles by inheriting + overriding.
5. **Crash-safe escalation state** — escalation deadlines persist
   in SQLite so a daemon restart resumes pending escalations
   correctly. No "the alert was lost because the daemon
   restarted between rungs."
6. **Panic floor that bypasses silent/audit/test modes** — events
   above a configurable severity threshold (the **panic floor**)
   *always* fire on the highest-aggressivity rung regardless of
   operator profile. An operator misconfiguration cannot leave a
   blocker-class event un-notified.
7. **Audit + test modes that do not actually emit** — `audit`
   logs what would have been sent; `test` ships to a designated
   developer channel only. Both preserve full orchestrator
   behaviour (escalation, ack, DEFCON) so misconfiguration
   surfaces under dry-run, not during an incident.
8. **Test contract honoured** — the orchestrator obeys SDD-005's
   real-time-sleep prohibition. All escalation timing tests use
   `tokio::time` virtual clock.

## Non-goals

- **Not shipping every channel in this SDD.** This charter scopes
  the orchestrator + the taxonomy + a small set of channels
  sufficient to validate both. New channels follow as small PRs
  using the established crate pattern. First-ship target:
  - `selfdef-integration-ntfy` (refactor of existing `NtfyNotifier`)
  - `selfdef-integration-signal` (refactor of existing
    `SignalCliNotifier`)
  - one new channel (Q-E decides between SendGrid and SMTP for the
    first email channel)
  - Twilio, Slack, Discord, OpenSearch, Loki ship as follow-ups
    once the orchestrator pattern proves out.
- **Not building a mobile push backend.** Mobile push is the
  dashboard's concern (tracked separately under SDD-009 if and
  when the dashboard ships). ntfy already covers push-to-phone
  for operators who self-host or use the public ntfy.sh.
- **Not LLM-generated message content.** Bodies render from event
  fields through a deterministic template. Future AI-shaped
  summarisation is a separate concern.
- **Not two-way conversational workflows.** Ack is one bit of
  feedback ("seen / acted on"). Multi-turn ChatOps (e.g.
  `/quarantine pod-x`) is a follow-up SDD.
- **Not retrofitting the existing notifier callers eagerly.** The
  M4 `NotifierChain` consumers in `selfdef-correlator` keep
  working through the orchestrator's compatibility shim until
  the orchestrator API stabilises.

## Glossary

- **Channel** — one `crates/selfdef-integration-*` crate that
  emits a notification payload to exactly one external service.
- **Integration crate** — same thing, the architectural label.
- **Subscription** — operator preference *per channel*: severity
  floor, event-type filter, quiet hours, device hints.
- **Profile** — named bundle of subscriptions + escalation
  cadence + DEFCON dial, selected by the operator at startup or
  via `selfdefctl notify profile <name>`.
- **Mode** — runtime posture: `enforce` (default, sends for
  real), `audit` (logs only, no sends), `test` (sends to one
  designated dev channel only).
- **DEFCON** — 1..5 aggressivity dial. 1 = most aggressive
  (immediate WUPHF on every event), 5 = least (silent unless
  panic floor). Auto-derived from event severity by default; the
  operator may pin it.
- **Ack** — explicit operator confirmation that they've seen an
  event. Sources: CLI verb, HTTP click-link, channel-native
  reply (where the channel supports it).
- **Escalation** — automatic advance to the next rung when the
  current rung's ack window expires.
- **Rung** — one step in the escalation chain. Each rung names
  one or more channels and a wait-for-ack window.
- **WUPHF** — parallel send across every channel at once,
  bypassing the rung ordering. Profile setting *and* the
  panic-floor behaviour.
- **Panic floor** — severity threshold above which the operator's
  mode/profile/silent setting cannot suppress notification.

## Design

### D-1 — Taxonomy: modules ≠ integrations

Codify the boundary as a top-level architectural rule:

> **Modules** own host topology: install scripts, kernel state,
> service lifecycle, file ownership. They live under `modules/`
> and have an `install/apply.sh` dispatcher.
>
> **Integrations** are pure adapters: they take a typed payload
> and emit it to one external service. They live as crates
> named `selfdef-integration-<service>`. They MUST NOT install
> anything, mutate host topology, or own service lifecycle.

Concretely, ARCHITECTURE.md gets a new section enumerating the
rule. `docs/dev/integrations.md` (new) names the integration crate
template:

- Cargo.toml depends only on:
  - `selfdef-core` (event types)
  - `selfdef-notifier-orchestrator` (trait, see D-2)
  - one outbound HTTP / subprocess crate (`reqwest`, `lettre`,
    `tokio::process::Command`, etc.)
- src/lib.rs exposes one struct implementing the orchestrator's
  channel trait
- src/lib.rs does NOT touch the filesystem outside of reading a
  config-supplied credentials file
- No `install/` directory exists for integrations

### D-2 — `selfdef-notifier` graduates into `selfdef-notifier-orchestrator`

The existing crate gets renamed (via a deprecation alias for one
release) and its content split:

- `crates/selfdef-notifier-orchestrator/` — the trait, the
  escalation engine, the profile loader, the ack tracker, the
  panic-floor logic, the SQLite persistence layer. **No channels
  here.**
- `crates/selfdef-integration-ntfy/` — `NtfyNotifier` moves here
  unchanged in behaviour.
- `crates/selfdef-integration-signal/` — `SignalCliNotifier`
  moves here unchanged in behaviour.

The orchestrator's channel trait is the single integration ABI:

```rust
#[async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &str;
    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError>;
    fn supports_ack_reply(&self) -> bool { false }
    fn ack_reply_format(&self) -> Option<AckReplyHint> { None }
}
```

`DeliveryReceipt` carries the channel's native message-id (when
present), used later to correlate channel-native acks (Signal
reply, ntfy action button) back to the event.

### D-3 — Subscription model

The operator config gets a new `[notifications]` section.
Per-channel subscriptions live under `[notifications.channels.<name>]`:

```toml
[notifications.channels.ntfy]
enabled       = true
severity_floor = "warning"    # info | warning | high | critical
event_kinds    = ["security", "honeytoken", "policy.violation"]
quiet_hours    = "22:00..07:00"   # local-time, daemon-host TZ
device_hint    = "phone-primary"  # opaque tag; channel may use

[notifications.channels.signal]
enabled        = true
severity_floor = "high"
recipients     = ["+15551234567"]   # required by signal-cli
```

A missing channel = disabled. Missing fields = sensible defaults
(no quiet hours, accept all event kinds, severity floor = info).

### D-4 — Acknowledgement primitives (three paths, channel-shaped)

An ack is an `(event_id, ack_source)` tuple posted to the
orchestrator. Sources:

1. **CLI** — `selfdefctl notify ack <event_id>` (always available;
   the universal escape hatch).
2. **HTTP click-link** — the orchestrator's `/notify/ack/<token>`
   endpoint on the existing API (capability-gated, bearer-auth or
   one-shot signed token). Channel messages include the link.
3. **Channel-native** — when the integration crate sets
   `supports_ack_reply() = true`:
   - **ntfy** — action button → ntfy server → daemon webhook
   - **Signal** — text reply with the displayed token, parsed by
     signal-cli daemon mode
   - **Slack/Discord** — interactive component callback
   - **SMS (Twilio)** — reply containing the displayed token →
     Twilio inbound webhook
   - **email (SendGrid/SMTP)** — click-link only (no inbound
     reply parsing in v1)

The orchestrator is the integration-side write-through:
`Orchestrator::record_ack(event_id, source)` is called by each
channel-specific ingest path. The orchestrator deduplicates acks
(first wins) and short-circuits any pending escalation timers.

### D-5 — Escalation engine (persistent, deadline-driven)

A new SQLite table `notification_escalations` stores:

```
event_id           TEXT NOT NULL   -- joins to events
rung_index         INTEGER         -- which rung is active
deadline_at        INTEGER         -- unix-seconds: when to advance
channels_pending   TEXT            -- JSON: [channel_name, ...] still owed
acked_at           INTEGER NULL    -- nullable: first ack timestamp
profile            TEXT            -- profile name in effect at fire-time
PRIMARY KEY (event_id)
```

The orchestrator runs one task that wakes on the earliest
`deadline_at` across all rows. On wake:
- if `acked_at IS NOT NULL` → row is closed, skip
- else → advance to the next rung (per the active profile),
  send to that rung's channels, update `rung_index` +
  `deadline_at`, repeat

Daemon restart: the wake task does an initial pass against the
table and resumes from wherever it was. No state is lost.

WUPHF rung: a special rung_index value (e.g. `-1`) that fans out
to every enabled channel in parallel. Reached when the profile's
last rung ack window expires *or* when the panic floor triggers
it directly.

### D-6 — Mode profiles (built-in + operator-defined)

Built-in profiles ship in `crates/selfdef-notifier-orchestrator/src/profiles/`:

| Profile | Behaviour |
| --- | --- |
| `auto` | Default. DEFCON from severity. Rungs: ntfy → email → Signal → WUPHF. 5-minute ack window per rung. |
| `sms-first` | First rung is Twilio SMS. Useful for on-call rotations. |
| `secure-first` | First rung is Signal (end-to-end encrypted). Email/SMS later. |
| `wuphf` | One rung: every channel at once on every event. Named per *The Office* reference per operator request. |
| `silent` | Suppress every channel below the panic floor. Above the panic floor, behaves as `wuphf`. |
| `audit` | Log to stderr + SQLite what would have fired; never send. Mode-level setting; orthogonal to profile. |
| `test` | Like `enforce`, but every channel routes to its `test_destination` field (e.g. dev's own phone number). |

Operators may define custom profiles in the config:

```toml
[notifications.profiles.weekend-mode]
inherits   = "auto"
rungs      = [
    { channels = ["ntfy"],   ack_window = "30m" },
    { channels = ["signal"], ack_window = "1h" },
    { wuphf = true },
]
```

### D-7 — DEFCON dial + panic floor

DEFCON is computed per-event:

```
defcon = if event.severity ≥ panic_floor { 1 }
        else if profile.pinned_defcon.is_some() { profile.pinned_defcon }
        else { map_severity_to_defcon(event.severity) }
```

The dial affects:
- Which rungs are active (DEFCON 1 = all rungs collapse to WUPHF)
- Ack window length (DEFCON 1 = 30s; DEFCON 5 = 1h)
- Whether quiet_hours is honoured (DEFCON ≤ 2 ignores quiet_hours)

Panic floor lives in the config:

```toml
[notifications]
panic_floor = "critical"   # info | warning | high | critical | fatal
```

Above the panic floor, *no* profile/mode setting can suppress
delivery. `silent` mode + `audit` mode + `test` mode all
short-circuit to enforce-mode-with-WUPHF.

### D-8 — Session-attention responder (deliberately not an integration)

A separate crate `crates/selfdef-responder-session-attention/`
provides the wall/write capability. It is a **responder**, not a
notifier, because:

- it mutates local host state (writes to TTY devices)
- it requires consent: the daemon must be in the `tty` group OR
  the target user must opt-in by setting their TTY group-writable
- the target is a live local session, not an external service

Trigger model: the orchestrator may *invoke* the session-attention
responder as the final rung before WUPHF, when:

1. The event severity is at or above an operator-set
   `session_attention_floor` (default `high`)
2. The user has at least one active SSH/local TTY session (queried
   via `utmpx`)
3. The orchestrator has been unacked for `> N` minutes (operator
   set; default 5)
4. The user opted-in via `[notifications.session_attention]`

Message format: a single-line `wall`-style broadcast with the
event id + a CLI ack hint:

```
[selfdef] CRITICAL event E-1234 — ack with: selfdefctl notify ack E-1234
```

This is loud-by-design. Operators who do not want this set
`enabled = false`.

### D-9 — Test contract

Mirrors SDD-005:

- Every escalation timing test uses `#[tokio::test(start_paused = true)]`.
- No real network calls; channels under test use a
  `MockChannel` that records `send` invocations + can be told to
  fail or to receive an ack.
- Crash-recovery test: write a row to the escalations table,
  restart the orchestrator in-process, verify the wake task
  resumes correctly.
- Panic-floor test: set mode = `silent`, fire a `fatal` event,
  assert every channel still receives it.

## Open questions

> **Status note** (updated after Phase-6 cycle): each working
> assumption below is annotated `→ confirmed` /
> `→ revised`. Q-F remains the only one not exercised yet —
> v1 wall(1) targets all TTYs.

- **Q-A — Schema location.** New table `notification_escalations`
  in the existing SQLite store, or split into a new sqlite
  database (e.g. `notifications.sqlite`) so the main events store
  stays focused? **Working assumption: same store.**
  → **Revised on implementation**: shipped as a dedicated
  database file at the operator-configured
  `[notifier].escalations_path` (default unset → engine path
  disabled). The events store stays focused; concurrent access
  from the daemon writer + CLI reader uses SQLite WAL.

- **Q-B — Signal ack mechanism.** Signal replies need a long-
  running signal-cli daemon to ingest them. We can either (a)
  run signal-cli in daemon-mode and parse JSONRPC replies, or
  (b) skip channel-native ack for Signal and rely on the
  HTTP click-link path. **Working assumption: (b) for v1**,
  upgrade to (a) once daemon-mode is stable. → **Confirmed**;
  shipped as (b). `SignalCliNotifier::supports_ack_reply`
  returns `false`.

- **Q-C — Which channels in the first ship.** Charter assumes
  ntfy + Signal + one email channel land in the SDD-008
  implementation cycle. Twilio + Slack + Discord ship as
  follow-up SDDs. → **Revised on implementation**: all seven
  channels (ntfy, signal, smtp, twilio, slack, discord,
  wall) landed in the SDD-008 cycle. The "follow-up SDD" plan
  was abandoned once the integration crate template
  (`docs/dev/integrations.md`) made each new channel a
  routine pattern instance.

- **Q-D — Twilio inbound webhook reachability.** Twilio reply-
  based ack requires the daemon to expose an HTTP endpoint
  reachable from the public internet. Most selfdef deployments
  are inside a trust boundary (no public IP). **Working
  assumption: (c) for v1** (click-link only). → **Confirmed**;
  Twilio shipped with `supports_ack_reply = false`. The
  `/notify/ack/<token>` daemon endpoint that backs the
  click-link path is still an open follow-up (PR-level — not
  blocking SDD-008 closure).

- **Q-E — Email channel: SendGrid or SMTP?** **Working
  assumption: SMTP via lettre** (`selfdef-integration-smtp`);
  SendGrid ships later as an alternative if operators ask.
  → **Confirmed**; `selfdef-integration-smtp` shipped under
  PR #114. SendGrid never asked for.

- **Q-F — Session-attention multi-user.** **Working
  assumption: per-user opt-in list in config**; only opted-in
  users see broadcasts. → **Revised on implementation**: v1
  wall(1) broadcasts to every logged-in TTY (the default
  Unix `wall` behaviour). Per-user opt-in is a future
  refinement once a second session-attention transport (e.g.
  `write(1)`) lands — see `crates/selfdef-integration-wall`
  module rustdoc.

- **Q-G — Config layout.** **Working assumption: new
  `[notifications]` section**; the old `[notifier]` becomes
  a deprecated alias for one release. → **Revised on
  implementation**: kept the existing `[notifier]` namespace
  and extended it with the new sub-keys (`escalations_path`,
  `mode`, `profile`, `panic_floor`, `[notifier.profiles.*]`,
  `[notifier.subscriptions.*]`, and the 7 channel sub-
  sections). The rename was rejected as needless churn —
  operators on existing `[notifier]` configs see zero break
  on upgrade.

## Why a charter, not a single-shot PR

This SDD is a charter because:

- The orchestrator + first-ship integrations are too large for
  one PR.
- The Ds are independently mergeable in sequence (D-2 first, then
  D-3, then D-4 paired with D-5, then D-6, then D-7, with D-8
  optional).
- The taxonomy decision (D-1) needs to land before any new
  integration crate so the pattern is set.

Implementation PRs will close this charter incrementally; the
ledger entries graduate from `draft (charter)` →
`implemented (D-N shipped)` → `implemented (all Ds shipped)` as
each PR merges.

## Naming

Phase prefix for any findings raised during the implementation
cycle: F-2031-NNN (one beyond Phase 5's F-2030-NNN). The
closure-cycle audit programme is **active as Phase 6**;
findings tracked under
[`docs/review/phase-6/99-findings-ledger.md`](../review/phase-6/99-findings-ledger.md).

## PR labels — appendix

> Background: Phase 6 recent-PRs explorer (F-2031-001) found
> that the SDD-008 implementation cycle reused the `D-7` label
> on two PRs with different meanings — PR #114 titled
> `feat(sdd-008): D-7 Q-E — selfdef-integration-smtp first
> email channel` and PR #127 titled `feat(sdd-008): D-7 —
> panic floor`. Only the second matches SDD-008's actual D-7.

The cycle's commit-message D-N labels are not perfectly 1:1
with the design points in this SDD. The authoritative mapping
is the "Implementation status" table above. For navigating the
commit graph, the disambiguation below is exhaustive:

- **`feat(sdd-008): D-7 Q-E — selfdef-integration-smtp first
  email channel` (PR #114)** — this is the **D-2 pattern**
  (channel-adapter carve, like ntfy / signal under D-2b/c)
  serving the **Q-E open question** (SMTP vs SendGrid). The
  `D-7` in the title is a labeling slip; D-7 properly refers
  to the panic floor.
- **`feat(sdd-008): D-7 — panic floor` (PR #127)** — the true
  D-7 implementation.
- **`feat(sdd-008): Twilio` (PR #116), `Slack` (PR #120),
  `Discord` (PR #121)** — each is the **D-2 pattern** serving
  its Q-letter open question (Q-D / Q-C / no explicit Q for
  Discord). No D-N number was minted; these crates are pattern
  instances rather than design points.
- **`feat(sdd-008): D-8 — wall(1) session-attention channel`
  (PR #128)** — the wall(1) crate is **simultaneously** D-8
  (session-attention responder) AND a D-2 pattern instance.
  The D-8 label dominates because the design point is
  load-bearing for the operator-discovery story.

If SDD-008 is ever published externally, this appendix should
be moved up into the design-point cross-reference. For now,
the audit programme's recent-PRs ledger (Phase 6, F-2031-001)
is the authoritative cross-reference.
