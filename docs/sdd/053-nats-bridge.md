# SDD-053 — NATS messaging backbone — multi-host event bus (MS015)

> Status: **implemented** — `selfdef-nats` crate shipped as a two-
> way pump between the local in-proc `selfdef-bus` and a NATS
> subject-prefix tree. Stage-2 SDD authored retroactively.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS015 (catalogued in
> `backlog/milestones/MS015-nats-messaging-backbone.md`)
> Builds on: SDD-001 (ai-machine-end-to-end — selfdef-bus is the
> in-proc bus this bridges), SDD-004 (security threat model —
> cross-host event integrity), SDD-007 (audit chain — events
> received from the bridge must respect the chain invariant).

## Problem

Single-host selfdef works against a single-machine adversary. A
defender's fleet (operator's homelab + sain-01 + remote SSH hops)
needs cross-host event visibility:

1. **No cross-host correlation** — a perimeter event on sain-01
   stays on sain-01; operator can't see it from the laptop's
   dashboard.
2. **No fleet response** — guardian on sain-01 can't notify
   responders on other hosts.
3. **Echo loops** — naïve "subscribe + republish" creates O(N²)
   loops across N hosts.

## Goals

Per dump references + the shipped `selfdef-nats` crate:

1. Two-way pump:
   - **Outbound**: subscribe to local bus, publish every locally-
     originated event to `<subject_prefix>.<host_tag>`.
   - **Inbound**: subscribe to `<subject_prefix>.>`, republish
     received events onto the local bus.
2. Echo defense: drop inbound events whose `host_tag` matches
   our own (R-rule guards against the obvious self-loop).
3. Two operator modes: passive (mirror-only) + active (full pump).
4. Subject-prefix isolation so different operator fleets coexist
   on a shared NATS server without crosstalk.
5. Preserve `selfdef_core::Event` schema across the bridge —
   serialize/deserialize round-trips lossless.

## Non-goals

- This SDD does NOT cover the NATS server operations (operator
  runs NATS however they want — selfdef is a client).
- It does NOT cover NATS auth/TLS configuration — operator
  configures the client connection via existing NATS env / config
  conventions.
- It does NOT cover cross-host audit-chain composition (different
  hosts' chains stay independent; the bridge does NOT merge them
  into a single chain).

## Recommended design

### Connection model

The bridge runs as a long-lived task started by the daemon at boot
when `[nats]` config is set. Single NATS connection per daemon.
Per-host `host_tag` is fixed at daemon startup from the existing
`selfdef-config` value.

### Subject schema

- Outbound publish: `<subject_prefix>.<host_tag>` (e.g.
  `selfdef.events.sain-01`).
- Inbound subscribe: `<subject_prefix>.>` (wildcard subtopic).
- Echo defense: when an inbound message's deserialized
  `Event::host_tag` equals our own, drop it.

### Caller contract

The bridge is daemon-owned; no CLI invocation is required. Operator
controls via `[nats]` config block:

```toml
[nats]
url           = "tls://nats.example.com:4222"
subject_prefix = "selfdef.events"
mode          = "active"   # passive | active
```

## Implementation status

**Crate**: shipped under `crates/selfdef-nats/`. Two-way pump
implementation with echo defense.

**Cross-host bus integration**: the crate exists + tests pass. The
operator integration arc (multi-host NATS server provisioning +
per-fleet subject-prefix coordination) is the deferred follow-up.

## Open questions

- **D-1**: `selfdefctl nats {status, peers, publish-test}` CLI?
  **Recommendation: yes** — `status` prints connection state +
  subject prefix; `peers` lists last-seen `host_tag`s; `publish-test`
  emits a known event for round-trip verification.
- **D-2**: `GET /v1/nats/status` HTTP surface returning connection
  state + outbound/inbound event counters? **Recommendation: yes**
  after D-1.
- **D-3**: Cross-host audit-chain composition — should events
  received from other hosts be marked + filtered out of the local
  audit chain? **Recommendation: yes already; verify the existing
  store + correlator respect host_tag boundaries.**
