# SDD-009 — Operator dashboard (requirements + scope)

> Status: **superseded** — Stage-1 scoping requirements captured here
> have been realized + extended across the following implementation
> SDDs as of 2026-05-21:
>   - **SDD-026** (operator dashboard architecture + flex-profile) —
>     8-tab restructure + 13 Z-vectors; status implemented
>   - **SDD-054** (dashboard architecture as shipped) — Stage-2
>     retrospective canonicalizing the 17-panel single-page-with-
>     anchor-nav layout
>   - **SDD-056** (dashboard 8-tab restructure) — UX migration plan;
>     all 5 steps shipped; status implemented
>   - **SDD-060** (dashboard-prefs persistence + sync) — daemon-side
>     persistence + PWA sync; status implemented
> Together these specs cover every requirement originally captured
> here PLUS:
>   - per-panel visibility menu (MS043 UX batch 10)
>   - refresh-rate selector (batch 11)
>   - operator-named view presets + URL-hash deep-link (batches 12 + post-batch-14)
>   - daemon-side `GET/PUT /v1/dashboard-prefs` + PWA sync (batches 13 + 14)
>   - `GET /v1/dashboards` discovery + `selfdefctl dashboards` CLI verb
> This SDD is retained as the historical scope-capture; consult
> SDD-026 + SDD-054 + SDD-056 + SDD-060 for current doctrine.
> Owner: superseded; further evolution lives in the implementation
> SDDs above.
> Last updated: 2026-05-21 (status: scoping → superseded).
> Derived from: `docs/decisions.md` D-001 (dashboard scope requirements)

## Implementation status

**Superseded.** The Stage-1 requirements below were captured before
SDD-026 / SDD-054 / SDD-056 / SDD-060 ratified the actual shipped
architecture. Reading order for the current dashboard surface:
1. SDD-026 — vector-by-vector spec (Z-1 through Z-13)
2. SDD-054 — as-shipped retrospective (17-panel + 8-tab)
3. SDD-056 — UX migration plan + the always-visible strip
4. SDD-060 — daemon-side preference persistence + PWA sync

The remainder of this file preserves the original Stage-1 scope
capture for historical reference; the implementation has moved
beyond it.

This SDD intentionally does **not** pick implementation choices. It
captures the operator's scope-of-required-coverage so that whoever
takes up the design chat starts from a stable requirements baseline.
The design-shaped decisions (auth model, hosting model, UI technology,
ack flow, bulk operations, etc.) are open questions enumerated below,
not pre-answered.

When the design conversation lands:
- A successor SDD or a major revision of this one captures the
  selected design points (D-1, D-2, ... shape, matching SDDs 001-008).
- The Q-A..Q-N open questions resolve via `/questions solve` + the
  `docs/decisions.md` audit log (same flow used by SDD-008 D-9 → D-001).
- Until then, this doc reads as a **scope contract**, not an
  implementation plan.

## Problem

selfdef's operator-facing surfaces today are:

- **CLI** — `selfdefctl notify {ack,forget,list}` (SDD-008 D-4) for
  individual escalation triage.
- **HTTP ack URL** — `GET /notify/ack/:token` (SDD-008 D-4 HTTP)
  one click per escalation.
- **Channel-side notifications** — operator reads alerts from the
  configured channels (slack/discord/wall/etc.) and acts on each.
- **`/metrics`** — Prometheus exposition for off-host scraping
  (operational, not interactive).

What's **missing** is a single operator-facing surface that exposes
**the full state of the system** in one place: which modules are
running, which integrations are configured and healthy, what events
are flowing, what escalations are pending, what messages have been
sent, what operations the operator can take. Without it, an operator
debugging a problem must compose state from multiple disconnected
surfaces (CLI for escalations, log files for events, `/metrics` for
counters, per-channel apps for notification history).

D-001 captured the operator's stated requirement:

> The dashboard's scope is **comprehensive operator visibility into
> selfdef's full surface — all modules, integrations, configurations,
> status, events, messages, and operations**.

This SDD formalizes that scope so the eventual design conversation
starts from it.

## Required coverage — what the dashboard must surface

Per D-001, the dashboard provides comprehensive visibility into:

### 1. Modules

Every module declared in `/etc/selfdef/modules.toml`, with:

- Activation state (active / inactive / pending-apply).
- Profile selected (where the module supports multiple).
- Apply status from the most recent `apply.sh` invocation
  (`ok` / `failed` / `dry-run` / `not-yet-applied`).
- Check status from the most recent `check.sh` invocation.
- Module-specific signals (e.g. `tetragon`'s loaded policy count,
  `integrity-sentinel`'s baselined paths count,
  `agent-guard`'s scope and pod-label selector).

### 2. Integrations

Every channel listed in `[notifier].channels`, with:

- Configured status (binary path / endpoint / credentials present).
- Healthcheck status if the integration exposes one (HTTP HEAD,
  auth probe, etc.).
- Subscription filter (severity floor + event-kinds — SDD-008 D-3 / D-5e).
- Delivery history visibility (recent successes / failures / skipped-below-floor).

### 3. Configurations

The full `selfdef.toml` + per-module config files, read-only,
with operator-visible diffs from defaults. Operators should be able
to confirm "what is the daemon actually running with right now" without
SSH'ing to inspect filesystem state.

### 4. Status

- Daemon liveness (uptime, version, build SHA).
- Bus / store / collector queues (depths, error counters,
  drop counters per source).
- Wake-task state (pending escalations, due rungs, recent fires).
- Per-module / per-collector heartbeat.

### 5. Events

The current event stream (filterable):

- Recent findings + observations + informational events.
- Per-event metadata: source, severity, time, dedup-key, originator.
- Drill-down to the underlying eventstream JSONL or NATS message.
- Search / filter by severity / source / time window / dedup-key.

### 6. Messages

Notification history (sent / pending / acked):

- Per outbound: channel, target, content, timestamp, delivery receipt.
- Escalation chain: rung sequence, ack state, deadlines, profile in use.
- Audit-trail link to the underlying event(s).
- Per-channel breakdown (e.g. "how many slack notifications fired this hour").

### 7. Operations

What the operator can **do** from the dashboard:

- Ack / forget / dismiss pending escalations.
- Mute / unmute channels temporarily.
- Apply / re-check a module (subject to permissions).
- Rotate credentials (SDD-004 — `selfdefctl api rotate-token` etc.).
- Tail logs / drill into specific events.
- Read-only operations always available; mutate operations gated
  by the chosen auth model (see open questions).

## Goals

1. **Single surface for everything**. Operators stop composing state
   across 4-5 disconnected tools. One place, full picture.
2. **Read-first**. The dashboard is primarily a viewing surface;
   write/mutate operations are optional capabilities gated by the
   auth model the design chat selects.
3. **Operator-driven taxonomy**. The seven coverage areas above
   match the operator's mental model ("modules / integrations /
   configurations / status / events / messages / operations"). The
   UI should mirror that decomposition rather than mapping 1:1 to
   the codebase's crate layout.
4. **Composable with existing surfaces**. `/metrics` keeps working
   for Prometheus; CLI keeps working for scripted ack flows; the
   HTTP ack URLs keep working for inline click-to-ack. The
   dashboard adds a new surface; it doesn't replace any.
5. **Honest about trust boundaries**. Inherits SECURITY.md's
   posture: token-IS-auth where it's already the design (D-4 HTTP
   ack); whatever the design chat picks for operator-auth must
   compose cleanly with the existing posture, not contradict it.

## Non-goals (this SDD)

This SDD intentionally does **not** decide:

- **Auth model** — open question (see Q-A).
- **Hosting model** — open question (see Q-B).
- **UI technology** — open question (see Q-C).
- **Ack flow semantics** — open question (see Q-D).
- **Bulk operations** — open question (see Q-E).
- **Real-time vs polling refresh** — open question (see Q-F).
- **Multi-host scope** — open question (see Q-G).
- **Implementation effort sizing** — design-chat output.

Picking these prematurely would foreclose options the operator may
want to keep open. The design chat selects; this scoping doc only
defines the surface.

## Glossary

- **Comprehensive visibility** — every operator-relevant state in
  the daemon is reachable from this surface, even if it's a link to
  a more specialized tool (e.g. `/metrics` → Grafana).
- **Operator** — the human or service-account running selfdef on a
  host or fleet. Scope: single-host today; multi-host out-of-scope
  per Q-G.
- **Read-only** — the dashboard observes state but does not mutate
  daemon configuration, channel credentials, or event records.
- **Read+ack** — the dashboard can also mutate escalation state
  (ack, forget, dismiss) but no other config.
- **Read+ack+admin** — the dashboard can additionally mutate
  configuration / re-apply modules / rotate credentials.

## Open questions (for the separate design chat)

These are deliberately enumerated rather than answered. Each is a
distinct design decision the eventual SDD will need to resolve.

- **Q-A — Auth model**. Token-IS-auth (extending the D-4 HTTP
  pattern)? Bearer token in HTTP header (extending `/metrics`'s
  auth)? OIDC / SAML? mTLS? Local Unix-socket only (no auth
  beyond filesystem perms)? Each option has a different threat
  surface; the choice composes with SECURITY.md.
- **Q-B — Hosting model**. In-daemon HTTP handler (extending the
  existing `selfdef-api` crate)? Separate process? Static-asset
  bundle served by the daemon? External SPA hosted elsewhere with
  CORS to the daemon? Implications for the deb package, systemd
  unit, port allocation.
- **Q-C — UI technology**. Server-rendered HTML (no JS framework)?
  HTMX? Lightweight SPA (Svelte, Solid)? React? Terminal UI
  (`ratatui` / `textual`) as a sister CLI experience? Build pipeline
  + maintenance cost varies by ~10x across options.
- **Q-D — Ack flow semantics**. Per-escalation click-to-ack (extends
  D-4 HTTP)? Bulk-select-and-ack? Snooze / mute (vs the hard ack)?
  Per-rung ack vs whole-escalation ack? Operator-friction matters
  here.
- **Q-E — Bulk operations**. Can operators bulk-mute a noisy
  channel? Bulk-ack escalations sharing an event_kind?
  Bulk-acknowledge from a specific rung? Threat model: bulk ops
  amplify mistakes.
- **Q-F — Real-time vs polling refresh**. SSE (extending the
  existing `/events/stream`)? WebSocket? Plain polling? "Live tail"
  UX vs "snapshot view"?
- **Q-G — Multi-host scope**. Single-host only (matches selfdef's
  v1 NATS posture)? Federate across the existing NATS bridge?
  Operator chooses one host's dashboard at a time? Aggregated view
  across the fleet?

## Way forward

1. **Trigger** for the design chat: operator initiates a separate
   conversation (per D-001 + the operator's reiterated direction
   this session). This SDD is the read-in.
2. **Output** of the design chat: a successor SDD (or major revision
   of this one) that resolves Q-A..Q-G as D-1..D-N design points,
   matching the shape SDDs 001-008 have today. Each design point
   appears in `docs/decisions.md` via the standard `/questions
   solve` flow.
3. **Implementation cycle** follows the design SDD, gated on
   operator approval per the established cadence (one PR per
   cycle, ready-for-review default).

## Cross-references

- `docs/decisions.md` D-001 — Dashboard scope requirements (the
  decision this SDD elaborates).
- `docs/sdd/008-notifications-orchestration.md` D-9 — the originally-
  deferred design point that pointed at this future SDD.
- `docs/sdd/004-security-threat-model.md` — operator-auth posture
  must compose with this threat model.
- `SECURITY.md` "Known gaps" + URL-leakage map (lines 198+, 244+) —
  constraints any new HTTP surface inherits.
- `crates/selfdef-api/src/handlers.rs::notify_ack` — the precedent
  for token-IS-auth in the existing API surface.
- `crates/selfdef-cli/src/notify.rs` — the precedent CLI for ack /
  forget / list operations the dashboard exposes.
