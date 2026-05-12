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
out of scope for this milestone — operators put the cluster behind
mTLS / firewalls / NATS auth callouts as needed.

## What it isn't

- **Not** a replacement for the local in-proc bus. Every subscriber
  inside the daemon (correlator, responder, store sink, API SSE
  stream) still reads from the local broadcast.
- **Not** durable. The bridge uses NATS Core publish/subscribe — a
  daemon that drops off the network misses messages that pass while
  it's away. JetStream durability is the obvious next step but
  hasn't shipped.
- **Not** authenticated by selfdef itself. Bring your own NATS
  cluster auth (mTLS, NKey, JWT, …).

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
