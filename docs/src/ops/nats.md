# NATS bridge

selfdef ships an optional bridge that pumps events between hosts via
[NATS](https://nats.io). The local in-proc broadcast stays the source
of truth for collectors, the correlator, and the responder. The bridge
is a sidecar task — one daemon publishes locally-originated events to
NATS, and each daemon's bridge subscribes back to NATS and republishes
remote events onto its local bus.

A typical deployment runs one detection daemon per host plus one
"hub" daemon that subscribes to everything for cross-host
correlation. Nothing in selfdef demands that topology — it just falls
out of how the subject space is laid out.

## Subject layout

| Direction | Subject |
|-----------|---------|
| publish   | `<subject_prefix>.<host_tag>` |
| subscribe | `<subject_prefix>.>` |

Default prefix: `selfdef.events`. So a daemon with `host_tag =
"workstation-01"` publishes to `selfdef.events.workstation-01` and
subscribes to `selfdef.events.>`.

Each event is the standard OCSF-aligned envelope, JSON-serialized.
The bridge doesn't translate or reshape the payload — what comes out
of the local bus is what goes on the wire.

## Loop avoidance

When daemon **A** publishes event X to NATS, daemon **B** receives it
on `selfdef.events.A` and pushes it onto its local bus. But daemon
**B** is also subscribed to its local bus and forwards everything to
NATS — naïvely it would republish X right back, daemon A would
receive it on its own subscription, and the loop never ends.

selfdef avoids this two ways at once:

1. **Outbound filter.** The bridge only publishes events whose
   `host_tag` matches the local daemon's. Events that came in *from*
   NATS keep their original (remote) `host_tag`, so the outbound
   task simply skips them.
2. **Inbound filter.** The bridge drops messages whose `host_tag` ==
   our own — defense in depth against a NATS subject filter mistake
   or a downstream rewriting an event's host tag.

The UUIDv7 on each envelope also lets the store sink dedupe (events
are keyed by id), but the bridge doesn't rely on that — the
host_tag check is O(1) and stops the loop at the source.

## Configuration

```toml
[bus.nats]
enabled = true
url = "nats://nats.internal:4222"
subject_prefix = "selfdef.events"
```

Multiple servers can be comma-separated per the async-nats URL
grammar. TLS is supported via the `tls://` scheme. Authentication is
out of scope for selfdef itself — operators put the cluster behind
mTLS / firewalls / NATS auth callouts as needed.

## Modes: Core vs JetStream

The bridge runs in one of two modes, picked by config:

### Core (default)

Fire-and-forget pub/sub. Lowest latency, no durability. A daemon that
drops off the network misses messages that pass while it's away.
Good for live multi-host correlation on a stable LAN.

```toml
[bus.nats]
enabled = true
url = "nats://nats.internal:4222"
```

### JetStream (durable)

Outbound publishes go to a JetStream stream; inbound reads from a
per-host durable pull consumer with explicit acks. A daemon that
restarts resumes from its last acked message rather than starting
from "now".

```toml
[bus.nats]
enabled = true
url = "nats://nats.internal:4222"

[bus.nats.jetstream]
enabled = true
stream_name = "selfdef-events"
durable_consumer_prefix = "selfdef-bridge"
max_age_secs = 604800     # 7 days; 0 = unlimited
max_bytes = -1            # unlimited
max_msgs = -1             # unlimited
```

The bridge calls `get_or_create_stream` on startup, so the first
daemon to come up creates the stream; subsequent daemons reuse it.
The durable consumer is `<durable_consumer_prefix>-<host_tag>` so
each host tracks its own progress independently. Operators who want
to change retention later run `nats stream edit selfdef-events` —
the bridge doesn't reconcile config drift.

The outbound publish awaits the server ack, so an outage stalls
publishes rather than silently dropping them. Inbound acks every
message after it's been republished onto the local bus (or
identified as a self-echo). Redeliveries are safe — events carry a
UUIDv7 and the store sink dedupes by id.

## Federation signing — per-event authentication (F-2026-111 c)

NATS transport auth (mTLS / NKey / JWT) authenticates the *connection*
to the broker, not each *event*. A compromised broker, or any peer with
publish rights, can otherwise forge a finding carrying a local pid/user
and — if you run auto-response — drive a destructive action on this host
chosen remotely. selfdef's federation trust boundary has two opt-in
layers:

1. **Fail-closed** (`[responder].act_on_federated = false`): the
   responder refuses destructive actions (kill / quarantine / isolate /
   egress-lockdown) for any finding that arrived from another host. Alerts,
   evidence, and escalation are still delivered; operator `selfdefctl`
   actions always act. Watch `selfdef_responder_federated_refused_total`.
2. **Per-event signing** (this section): cryptographically authenticate
   cross-host events so a *verified* one from a trusted peer may drive
   response **even when fail-closed** — while forged / unknown-peer events
   are dropped.

### Set it up

Each daemon signs its outbound events with an **unencrypted** minisign
key (the daemon signs unattended, so it can't be password-gated):

```bash
# On every participating host — generate this host's event-signing key.
# -W writes an UNENCRYPTED key (required; an encrypted key won't load).
minisign -G -W -p /etc/selfdef/keys/federation.pub \
                -s /etc/selfdef/keys/federation.key
sudo chmod 0600 /etc/selfdef/keys/federation.key
```

Distribute each host's **public** key (`federation.pub`) to every peer,
naming each peer by its `host_tag`. Then on each daemon:

```toml
[bus.nats]
enabled = true
url = "nats://nats.lan:4222"
# This host's own unencrypted secret key.
signing_key_file = "/etc/selfdef/keys/federation.key"

# Every OTHER host you trust: its host_tag -> its public key file.
[bus.nats.peer_keys]
"host-b" = "/etc/selfdef/keys/peers/host-b.pub"
"host-c" = "/etc/selfdef/keys/peers/host-c.pub"

[responder]
# Recommended with signing: refuse UNauthenticated cross-host triggers.
act_on_federated = false
```

### Behavior

- Outbound events are wrapped in a signed envelope `{kid, event, sig}`
  (`kid` = sender `host_tag`).
- An inbound event is `federation_verified` only if its `kid` is in
  `peer_keys` AND its signature checks out against that key. Such events
  bypass the fail-closed gate.
- A signed envelope from an **unknown** peer, or one whose signature
  **fails**, is dropped (not republished locally).
- A **raw** (unsigned) event from a peer is accepted but stays
  *unverified* — so the fail-closed gate still refuses destructive
  response to it. (This lets a mixed fleet migrate incrementally.)
- A bad key-load logs an error and the bridge runs **unsigned** rather
  than killing fan-out.

Watch `selfdef_nats_inbound_federated_verified_total` (the verified
subset) against `selfdef_nats_inbound_federated_events_total` (all
cross-host ingress) to confirm your peers' events are authenticating.

> The signed envelope embeds the event JSON as a string, so the wire
> payload is larger and every outbound event costs one minisign
> signature. Federation signing is opt-in precisely because of that
> cost — leave it off on hosts that don't span the trust boundary.

## What it isn't

- **Not** a replacement for the local in-proc bus. Every subscriber
  inside the daemon (correlator, responder, store sink, API SSE
  stream) still reads from the local broadcast.
- **Not** transport-authenticated by selfdef itself — bring your own
  NATS cluster auth (mTLS, NKey, JWT, …). *Per-event* authentication is
  available separately via federation signing (above).
- **Not** a transaction system. JetStream gives you "at-least-once"
  delivery, not "exactly-once" — that's why the dedupe story on the
  consumer side matters.

## Manual smoke test

```bash
# In one terminal:
nats-server -p 4222

# In another:
# (with [bus.nats] enabled and url=nats://127.0.0.1:4222 in selfdef.toml)
selfdefd &
nats sub 'selfdef.events.>'        # see every host's outbound traffic

# Trigger a finding via the API on a second daemon configured the same
# way, then watch the first daemon's `selfdefctl events tail` to see
# the remote event arrive.
```
