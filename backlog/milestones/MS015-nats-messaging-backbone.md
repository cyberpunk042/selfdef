# MS015 — NATS messaging backbone

> Parent: `backlog/milestones/INDEX.md` row MS015.
> Source: `crates/selfdef-nats/` (Cargo.toml + src/lib.rs 589 lines + tests/) + `docs/src/ops/nats.md` (NATS bridge operator-facing doc; subject layout / loop avoidance 2-way / configuration / Core vs JetStream modes / "What it isn't" / manual smoke test) + `docs/src/ops/config.md` `[bus.nats]` reference. All entries below extract verbatim. No invention.

## Epics (E0151–E0160)

| Epic ID | Phrase | Source |
|---|---|---|
| E0151 | Mission — optional bridge that pumps events between hosts via NATS (nats.io); local in-proc broadcast stays source of truth for collectors / correlator / responder; bridge is sidecar task (one daemon publishes locally-originated events to NATS, each daemon's bridge subscribes back + republishes remote events onto local bus) | `docs/src/ops/nats.md` § header |
| E0152 | Topology — typical deployment runs one detection daemon per host + one "hub" daemon subscribing to everything for cross-host correlation; "Nothing in selfdef demands that topology — it just falls out of how the subject space is laid out" | `docs/src/ops/nats.md` § header |
| E0153 | Subject layout — publish to `<subject_prefix>.<host_tag>` (e.g. `selfdef.events.workstation-01`); subscribe to `<subject_prefix>.>`; default prefix `selfdef.events`; each event is the standard OCSF-aligned envelope, JSON-serialized; bridge doesn't translate or reshape payload | `docs/src/ops/nats.md` § Subject layout |
| E0154 | Loop avoidance — 2-way protection (1 Outbound filter: bridge only publishes events whose host_tag matches local daemon's; events from NATS keep original remote host_tag → outbound task skips them; 2 Inbound filter: bridge drops messages whose host_tag == our own — defense in depth against NATS subject-filter mistake or downstream rewrite); UUIDv7 envelope dedupe at store-sink as belt-and-suspenders (bridge doesn't rely on it — host_tag check is O(1) at source) | `docs/src/ops/nats.md` § Loop avoidance |
| E0155 | Configuration — `[bus.nats]` block (enabled / url / subject_prefix); multiple servers comma-separated per async-nats URL grammar; TLS supported via `tls://` scheme; authentication OUT OF SCOPE for selfdef itself (operators put cluster behind mTLS / firewalls / NATS auth callouts) | `docs/src/ops/nats.md` § Configuration |
| E0156 | Mode 1 — Core (default) — fire-and-forget pub/sub; lowest latency, no durability; daemon that drops off network misses messages passing while away; good for live multi-host correlation on stable LAN | `docs/src/ops/nats.md` § "Core (default)" |
| E0157 | Mode 2 — JetStream (durable) — outbound publishes go to JetStream stream; inbound reads from per-host durable pull consumer with explicit acks; daemon that restarts resumes from last acked message; `[bus.nats.jetstream]` block (enabled / stream_name "selfdef-events" / durable_consumer_prefix "selfdef-bridge" / max_age_secs 604800=7days 0=unlimited / max_bytes=-1 unlimited / max_msgs=-1 unlimited); `get_or_create_stream` on startup (first daemon creates; rest reuse); durable consumer = `<durable_consumer_prefix>-<host_tag>`; `nats stream edit selfdef-events` for retention changes (bridge does NOT reconcile config drift); outbound await server ack (outage stalls vs silently drops); inbound acks after republish (or self-echo identified); UUIDv7 store-sink dedupe makes redeliveries safe | `docs/src/ops/nats.md` § JetStream |
| E0158 | What it isn't — NOT replacement for local in-proc bus (every subscriber inside daemon — correlator / responder / store sink / API SSE stream — still reads from local broadcast); NOT authenticated by selfdef itself (BYO NATS cluster auth via mTLS / NKey / JWT); NOT a transaction system (JetStream gives at-least-once not exactly-once → dedupe on consumer side matters) | `docs/src/ops/nats.md` § "What it isn't" |
| E0159 | Manual smoke test — Terminal 1 `nats-server -p 4222`; Terminal 2 `selfdefd &` with `[bus.nats]` enabled + url `nats://127.0.0.1:4222`; `nats sub 'selfdef.events.>'` sees every host's outbound traffic; trigger finding via API on a second daemon configured same way → first daemon's `selfdefctl events tail` shows the remote event arrive | `docs/src/ops/nats.md` § Manual smoke test |
| E0160 | Crate `selfdef-nats` (589 lines `src/lib.rs` + `tests/`) — implements the bridge per all above contracts; `[bus.nats]` config block referenced from `docs/src/ops/config.md`; documented in `docs/src/SUMMARY.md` § NATS bridge | `crates/selfdef-nats/` + `docs/src/ops/config.md` + `docs/src/SUMMARY.md` |

## Modules (M00369–M00394)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00369 | Crate `selfdef-nats` workspace member (Cargo.toml + src/ + tests/) | `crates/selfdef-nats/Cargo.toml` | E0160 |
| M00370 | `src/lib.rs` (589 lines) — bridge implementation | `crates/selfdef-nats/src/lib.rs` | E0160 |
| M00371 | tests/ — integration tests for bridge | `crates/selfdef-nats/tests/` | E0160 |
| M00372 | Local in-proc broadcast — source of truth for collectors / correlator / responder / store sink / API SSE | `docs/src/ops/nats.md` § header + "What it isn't" | E0151 + E0158 |
| M00373 | Sidecar task pattern — bridge is sidecar; not the local-bus replacement | `docs/src/ops/nats.md` § header | E0151 |
| M00374 | Outbound publisher — publishes locally-originated events to NATS | `docs/src/ops/nats.md` § header | E0151 |
| M00375 | Inbound subscriber — receives remote events from NATS + republishes onto local bus | `docs/src/ops/nats.md` § header | E0151 |
| M00376 | Topology — typical hub-and-spoke (one daemon per host + one "hub" daemon for cross-host correlation) | `docs/src/ops/nats.md` § header | E0152 |
| M00377 | Subject prefix — default `selfdef.events`; operator-configurable | `docs/src/ops/nats.md` § Subject layout | E0153 |
| M00378 | Publish subject pattern — `<subject_prefix>.<host_tag>` (e.g. `selfdef.events.workstation-01`) | `docs/src/ops/nats.md` § Subject layout | E0153 |
| M00379 | Subscribe subject pattern — `<subject_prefix>.>` (wildcard for all hosts) | `docs/src/ops/nats.md` § Subject layout | E0153 |
| M00380 | Envelope format — standard OCSF-aligned envelope, JSON-serialized | `docs/src/ops/nats.md` § Subject layout | E0153 |
| M00381 | Bridge preserves payload — no translation / no reshape | `docs/src/ops/nats.md` § Subject layout | E0153 |
| M00382 | Loop avoidance mechanism 1 — Outbound filter (publish only events whose host_tag matches local daemon's) | `docs/src/ops/nats.md` § Loop avoidance 1 | E0154 |
| M00383 | Loop avoidance mechanism 2 — Inbound filter (drop messages whose host_tag == our own) | `docs/src/ops/nats.md` § Loop avoidance 2 | E0154 |
| M00384 | UUIDv7 envelope dedupe — at store sink (events keyed by id); bridge doesn't rely on it | `docs/src/ops/nats.md` § Loop avoidance | E0154 |
| M00385 | Config knob — `enabled` (bool) | `docs/src/ops/nats.md` § Configuration | E0155 |
| M00386 | Config knob — `url` (string; supports comma-separated multi-server async-nats URL grammar; `tls://` scheme for TLS) | `docs/src/ops/nats.md` § Configuration | E0155 |
| M00387 | Config knob — `subject_prefix` (string; default `selfdef.events`) | `docs/src/ops/nats.md` § Configuration | E0155 |
| M00388 | Mode — Core (default) fire-and-forget pub/sub | `docs/src/ops/nats.md` § Core | E0156 |
| M00389 | Mode — JetStream (durable) outbound stream + per-host durable pull consumer + explicit acks | `docs/src/ops/nats.md` § JetStream | E0157 |
| M00390 | JetStream config block — `[bus.nats.jetstream]` (enabled / stream_name / durable_consumer_prefix / max_age_secs / max_bytes / max_msgs) | `docs/src/ops/nats.md` § JetStream | E0157 |
| M00391 | JetStream stream bootstrap — `get_or_create_stream` on startup (first daemon creates; rest reuse) | `docs/src/ops/nats.md` § JetStream | E0157 |
| M00392 | JetStream durable consumer naming — `<durable_consumer_prefix>-<host_tag>` | `docs/src/ops/nats.md` § JetStream | E0157 |
| M00393 | JetStream publish semantics — awaits server ack (outage stalls vs silently drops); inbound acks after republish OR self-echo identification; redeliveries safe due to UUIDv7 dedupe | `docs/src/ops/nats.md` § JetStream | E0157 |
| M00394 | Manual smoke test workflow — 4 commands (`nats-server -p 4222` / `selfdefd &` / `nats sub 'selfdef.events.>'` / trigger finding on 2nd daemon → `selfdefctl events tail` on 1st daemon) | `docs/src/ops/nats.md` § Manual smoke test | E0159 |

## Features (F01681–F01800)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01681 | NATS bridge ships as OPTIONAL component (operator opts in via `[bus.nats]` block) | `docs/src/ops/nats.md` § header + § Configuration | E0151 | composite | true |
| F01682 | NATS bridge pumps events between hosts | `docs/src/ops/nats.md` § header | E0151 | composite | false |
| F01683 | NATS bridge cites nats.io as upstream | `docs/src/ops/nats.md` § header | E0151 | composite | false |
| F01684 | Local in-proc broadcast remains source of truth for collectors | `docs/src/ops/nats.md` § header + "What it isn't" | M00372 | composite | false |
| F01685 | Local in-proc broadcast remains source of truth for correlator | `docs/src/ops/nats.md` § header + "What it isn't" | M00372 | composite | false |
| F01686 | Local in-proc broadcast remains source of truth for responder | `docs/src/ops/nats.md` § header + "What it isn't" | M00372 | composite | false |
| F01687 | Local in-proc broadcast remains source of truth for store sink | `docs/src/ops/nats.md` § "What it isn't" | M00372 | composite | false |
| F01688 | Local in-proc broadcast remains source of truth for API SSE stream | `docs/src/ops/nats.md` § "What it isn't" | M00372 | composite | false |
| F01689 | Bridge is sidecar task (not local-bus replacement) | `docs/src/ops/nats.md` § header | M00373 | composite | false |
| F01690 | Outbound — one daemon publishes locally-originated events to NATS | `docs/src/ops/nats.md` § header | M00374 | composite | false |
| F01691 | Inbound — each daemon's bridge subscribes back to NATS + republishes remote events onto local bus | `docs/src/ops/nats.md` § header | M00375 | composite | false |
| F01692 | Typical deployment — one detection daemon per host + one "hub" daemon | `docs/src/ops/nats.md` § header | M00376 | composite | true |
| F01693 | Hub daemon subscribes to everything for cross-host correlation | `docs/src/ops/nats.md` § header | M00376 | composite | true |
| F01694 | Topology not mandated — falls out of subject space layout | `docs/src/ops/nats.md` § header | M00376 | composite | false |
| F01695 | Publish subject — `<subject_prefix>.<host_tag>` | `docs/src/ops/nats.md` § Subject layout | M00378 | composite | false |
| F01696 | Subscribe subject — `<subject_prefix>.>` | `docs/src/ops/nats.md` § Subject layout | M00379 | composite | false |
| F01697 | Default subject_prefix — `selfdef.events` | `docs/src/ops/nats.md` § Subject layout | M00377 | composite | false |
| F01698 | Subject example — daemon with `host_tag = "workstation-01"` publishes to `selfdef.events.workstation-01` | `docs/src/ops/nats.md` § Subject layout | M00378 | composite | true |
| F01699 | Subject example — same daemon subscribes to `selfdef.events.>` | `docs/src/ops/nats.md` § Subject layout | M00379 | composite | true |
| F01700 | Each event is the standard OCSF-aligned envelope, JSON-serialized | `docs/src/ops/nats.md` § Subject layout | M00380 | composite | false |
| F01701 | Bridge doesn't translate or reshape payload | `docs/src/ops/nats.md` § Subject layout | M00381 | composite | false |
| F01702 | "What comes out of local bus is what goes on the wire" | `docs/src/ops/nats.md` § Subject layout | M00381 | composite | false |
| F01703 | Loop avoidance — daemon A publishes event X to NATS; daemon B receives on `selfdef.events.A`; pushes onto its local bus; would naïvely republish X back; loop never ends without protection | `docs/src/ops/nats.md` § Loop avoidance | E0154 | composite | false |
| F01704 | Loop avoidance — two ways at once | `docs/src/ops/nats.md` § Loop avoidance | E0154 | composite | false |
| F01705 | Loop avoidance 1 — Outbound filter: bridge only publishes events whose host_tag matches local daemon's | `docs/src/ops/nats.md` § Loop avoidance 1 | M00382 | composite | false |
| F01706 | Outbound filter — events that came in *from* NATS keep their original (remote) host_tag | `docs/src/ops/nats.md` § Loop avoidance 1 | M00382 | composite | false |
| F01707 | Outbound filter — outbound task simply skips them | `docs/src/ops/nats.md` § Loop avoidance 1 | M00382 | composite | false |
| F01708 | Loop avoidance 2 — Inbound filter: bridge drops messages whose host_tag == our own | `docs/src/ops/nats.md` § Loop avoidance 2 | M00383 | composite | false |
| F01709 | Inbound filter — defense in depth against NATS subject-filter mistake | `docs/src/ops/nats.md` § Loop avoidance 2 | M00383 | composite | false |
| F01710 | Inbound filter — defense in depth against downstream rewriting an event's host tag | `docs/src/ops/nats.md` § Loop avoidance 2 | M00383 | composite | false |
| F01711 | UUIDv7 dedupe at store-sink — events keyed by id | `docs/src/ops/nats.md` § Loop avoidance | M00384 | composite | false |
| F01712 | UUIDv7 dedupe — bridge doesn't rely on it (host_tag check is O(1) at source) | `docs/src/ops/nats.md` § Loop avoidance | M00384 | composite | false |
| F01713 | host_tag check stops the loop at the source | `docs/src/ops/nats.md` § Loop avoidance | M00383 + M00382 | composite | false |
| F01714 | Config example block `[bus.nats]` | `docs/src/ops/nats.md` § Configuration | E0155 | composite | true |
| F01715 | Config knob — `enabled = true` | `docs/src/ops/nats.md` § Configuration | M00385 | composite | true |
| F01716 | Config knob — `url = "nats://nats.internal:4222"` (example) | `docs/src/ops/nats.md` § Configuration | M00386 | composite | true |
| F01717 | Config knob — `subject_prefix = "selfdef.events"` | `docs/src/ops/nats.md` § Configuration | M00387 | composite | true |
| F01718 | Multiple servers can be comma-separated per async-nats URL grammar | `docs/src/ops/nats.md` § Configuration | M00386 | composite | true |
| F01719 | TLS supported via `tls://` scheme | `docs/src/ops/nats.md` § Configuration | M00386 | composite | true |
| F01720 | Authentication out of scope for selfdef itself | `docs/src/ops/nats.md` § Configuration | E0155 | composite | false |
| F01721 | Operators put cluster behind mTLS / firewalls / NATS auth callouts as needed | `docs/src/ops/nats.md` § Configuration | E0155 | composite | false |
| F01722 | Two modes picked by config — Core (default) OR JetStream (durable) | `docs/src/ops/nats.md` § "Modes: Core vs JetStream" | E0156 + E0157 | composite | false |
| F01723 | Core mode — fire-and-forget pub/sub | `docs/src/ops/nats.md` § Core | M00388 | composite | true |
| F01724 | Core mode — lowest latency | `docs/src/ops/nats.md` § Core | M00388 | composite | false |
| F01725 | Core mode — no durability | `docs/src/ops/nats.md` § Core | M00388 | composite | false |
| F01726 | Core mode — daemon that drops off network misses messages passing while away | `docs/src/ops/nats.md` § Core | M00388 | composite | false |
| F01727 | Core mode — good for live multi-host correlation on stable LAN | `docs/src/ops/nats.md` § Core | M00388 | composite | false |
| F01728 | Core mode config example — only `[bus.nats]` block needed | `docs/src/ops/nats.md` § Core | M00388 | composite | true |
| F01729 | JetStream mode — durable | `docs/src/ops/nats.md` § JetStream | M00389 | composite | true |
| F01730 | JetStream — outbound publishes go to JetStream stream | `docs/src/ops/nats.md` § JetStream | M00389 | composite | false |
| F01731 | JetStream — inbound reads from per-host durable pull consumer with explicit acks | `docs/src/ops/nats.md` § JetStream | M00389 | composite | false |
| F01732 | JetStream — daemon that restarts resumes from last acked message (not from "now") | `docs/src/ops/nats.md` § JetStream | M00389 | composite | false |
| F01733 | JetStream config block — `[bus.nats.jetstream]` | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01734 | JetStream knob — `enabled = true` | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01735 | JetStream knob — `stream_name = "selfdef-events"` | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01736 | JetStream knob — `durable_consumer_prefix = "selfdef-bridge"` | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01737 | JetStream knob — `max_age_secs = 604800` (7 days; 0 = unlimited) | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01738 | JetStream knob — `max_bytes = -1` (unlimited) | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01739 | JetStream knob — `max_msgs = -1` (unlimited) | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01740 | JetStream bootstrap — `get_or_create_stream` on startup | `docs/src/ops/nats.md` § JetStream | M00391 | composite | false |
| F01741 | JetStream bootstrap — first daemon to come up creates the stream | `docs/src/ops/nats.md` § JetStream | M00391 | composite | false |
| F01742 | JetStream bootstrap — subsequent daemons reuse it | `docs/src/ops/nats.md` § JetStream | M00391 | composite | false |
| F01743 | JetStream durable consumer name — `<durable_consumer_prefix>-<host_tag>` | `docs/src/ops/nats.md` § JetStream | M00392 | composite | false |
| F01744 | JetStream durable consumer — each host tracks its own progress independently | `docs/src/ops/nats.md` § JetStream | M00392 | composite | false |
| F01745 | JetStream retention change — `nats stream edit selfdef-events` | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01746 | JetStream — bridge does NOT reconcile config drift | `docs/src/ops/nats.md` § JetStream | M00391 | composite | false |
| F01747 | JetStream outbound publish — awaits server ack | `docs/src/ops/nats.md` § JetStream | M00393 | composite | false |
| F01748 | JetStream — outage stalls publishes rather than silently dropping | `docs/src/ops/nats.md` § JetStream | M00393 | composite | false |
| F01749 | JetStream inbound — acks every message after it's been republished onto local bus | `docs/src/ops/nats.md` § JetStream | M00393 | composite | false |
| F01750 | JetStream inbound — acks every message after it's been identified as self-echo | `docs/src/ops/nats.md` § JetStream | M00393 | composite | false |
| F01751 | JetStream redeliveries — safe because events carry UUIDv7 + store sink dedupes by id | `docs/src/ops/nats.md` § JetStream | M00393 + M00384 | composite | false |
| F01752 | What it isn't — NOT a replacement for the local in-proc bus | `docs/src/ops/nats.md` § "What it isn't" | M00372 | composite | false |
| F01753 | What it isn't — every subscriber inside the daemon still reads from local broadcast | `docs/src/ops/nats.md` § "What it isn't" | M00372 | composite | false |
| F01754 | What it isn't — NOT authenticated by selfdef itself | `docs/src/ops/nats.md` § "What it isn't" | E0158 | composite | false |
| F01755 | What it isn't — Bring your own NATS cluster auth (mTLS, NKey, JWT, …) | `docs/src/ops/nats.md` § "What it isn't" | E0158 | composite | true |
| F01756 | What it isn't — NOT a transaction system | `docs/src/ops/nats.md` § "What it isn't" | E0158 | composite | false |
| F01757 | What it isn't — JetStream gives "at-least-once" delivery, not "exactly-once" | `docs/src/ops/nats.md` § "What it isn't" | M00393 | composite | false |
| F01758 | What it isn't — dedupe story on consumer side matters (because at-least-once) | `docs/src/ops/nats.md` § "What it isn't" | M00384 | composite | false |
| F01759 | Manual smoke test — Terminal 1 `nats-server -p 4222` | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01760 | Manual smoke test — `[bus.nats]` enabled + url `nats://127.0.0.1:4222` in selfdef.toml | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01761 | Manual smoke test — Terminal 2 `selfdefd &` | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01762 | Manual smoke test — `nats sub 'selfdef.events.>'` shows every host's outbound traffic | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01763 | Manual smoke test — trigger finding via API on second daemon configured the same way | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01764 | Manual smoke test — first daemon's `selfdefctl events tail` shows remote event arrive | `docs/src/ops/nats.md` § Manual smoke test | M00394 | composite | true |
| F01765 | Crate `selfdef-nats/Cargo.toml` workspace member | `crates/selfdef-nats/Cargo.toml` | M00369 | composite | false |
| F01766 | Crate `selfdef-nats/src/lib.rs` 589 lines | `crates/selfdef-nats/src/lib.rs` | M00370 | composite | false |
| F01767 | Crate `selfdef-nats/tests/` integration tests | `crates/selfdef-nats/tests/` | M00371 | composite | false |
| F01768 | Documentation `docs/src/ops/nats.md` covers all bridge contracts | `docs/src/ops/nats.md` | E0151 | composite | false |
| F01769 | Documentation `docs/src/ops/config.md` references `[bus.nats]` | `docs/src/ops/config.md` | E0155 | composite | false |
| F01770 | Documentation `docs/src/SUMMARY.md` lists NATS bridge | `docs/src/SUMMARY.md` | E0151 | composite | false |
| F01771 | Cross-host correlation pattern — hub daemon receives all events; per-host daemons receive only their own subscriptions | `docs/src/ops/nats.md` § header | E0152 | composite | true |
| F01772 | Hub-and-spoke is one of many possible topologies (mesh / partitioned mesh / fan-in / fan-out all valid) | `docs/src/ops/nats.md` § header | E0152 | composite | true |
| F01773 | Subject prefix is operator-configurable (multi-tenant deployments use distinct prefixes) | `docs/src/ops/nats.md` § Subject layout | M00377 | composite | true |
| F01774 | host_tag is per-daemon operator-configured (typically hostname) | `docs/src/ops/nats.md` § Subject layout | M00378 | composite | false |
| F01775 | OCSF envelope crossing the wire matches OCSF envelope on local bus (byte-equal) | `docs/src/ops/nats.md` § Subject layout | M00380 + M00381 | composite | false |
| F01776 | Outbound filter implements `event.host_tag == local.host_tag` predicate | `docs/src/ops/nats.md` § Loop avoidance 1 | M00382 | composite | false |
| F01777 | Inbound filter implements `event.host_tag != local.host_tag` predicate | `docs/src/ops/nats.md` § Loop avoidance 2 | M00383 | composite | false |
| F01778 | Defense-in-depth — both filters active simultaneously (not either/or) | `docs/src/ops/nats.md` § Loop avoidance | M00382 + M00383 | composite | false |
| F01779 | Config schema — `[bus.nats]` is the top-level block | `docs/src/ops/nats.md` § Configuration | E0155 | composite | false |
| F01780 | Config schema — `[bus.nats.jetstream]` is the optional JetStream sub-block | `docs/src/ops/nats.md` § JetStream | M00390 | composite | true |
| F01781 | TLS scheme — `tls://nats.example.com:4222` is valid URL | `docs/src/ops/nats.md` § Configuration | M00386 | composite | true |
| F01782 | Multi-server — `nats://a.example.com:4222,nats://b.example.com:4222` is valid URL | `docs/src/ops/nats.md` § Configuration | M00386 | composite | true |
| F01783 | Bridge integration with MS002 — collector fabric publishes events to local bus; bridge subscribes to local bus | MS002 + `docs/src/ops/nats.md` § header | E0151 | composite | false |
| F01784 | Bridge integration with MS003 — correlator receives both local AND bridge-republished remote events from local bus | MS003 + `docs/src/ops/nats.md` § "What it isn't" | F01685 | composite | false |
| F01785 | Bridge integration with MS003 — responder receives both local AND remote events | MS003 + `docs/src/ops/nats.md` § "What it isn't" | F01686 | composite | false |
| F01786 | Bridge integration with MS006 — agent-guard / SSH-wrap / etc. modules emit events; bridge propagates | MS006 + `docs/src/ops/nats.md` § header | F01690 | composite | false |
| F01787 | Bridge integration with MS007 — typed-mirror crates may carry NATS subject prefix conventions for cross-repo deployments | MS007 + SDD-038 | E0151 | composite | false |
| F01788 | Bridge integration with MS008 — selfdef-on-SAIN-01 may run a hub daemon for cross-host correlation across the workstation fleet | MS008 + `docs/src/ops/nats.md` § header | E0152 | composite | false |
| F01789 | Bridge integration with MS009 — audit cycles phase-6/-7 crate audit covers selfdef-nats; integration audit covers cross-host correlation | MS009 phase-6/-7 | M00369 | composite | false |
| F01790 | Bridge enables operator scenario — single workstation deployment with NATS DISABLED (default) | `docs/src/ops/nats.md` § Configuration | F01715 | composite | true |
| F01791 | Bridge enables operator scenario — multi-host LAN deployment with Core mode + stable network | `docs/src/ops/nats.md` § Core | M00388 | composite | true |
| F01792 | Bridge enables operator scenario — multi-host deployment with intermittent connectivity + JetStream durability | `docs/src/ops/nats.md` § JetStream | M00389 | composite | true |
| F01793 | Bridge enables operator scenario — fleet of detection daemons + hub aggregator using `selfdef.events.>` subscription pattern | `docs/src/ops/nats.md` § header + § Subject layout | E0152 | composite | true |
| F01794 | NATS bridge respects local-bus-is-source-of-truth invariant — every subscriber inside daemon reads local broadcast, NOT NATS directly | `docs/src/ops/nats.md` § "What it isn't" | M00372 | composite | false |
| F01795 | NATS bridge respects no-payload-translation invariant — what comes out of local bus is what goes on wire (byte-equal) | `docs/src/ops/nats.md` § Subject layout | M00381 | composite | false |
| F01796 | NATS bridge respects loop-free invariant — host_tag filter at outbound + inbound stops the loop at source O(1) | `docs/src/ops/nats.md` § Loop avoidance | E0154 | composite | false |
| F01797 | NATS bridge respects at-least-once invariant — JetStream + UUIDv7 dedupe handles the at-least-once-not-exactly-once trade-off | `docs/src/ops/nats.md` § "What it isn't" + § Loop avoidance | M00384 + M00393 | composite | false |
| F01798 | NATS bridge respects auth-out-of-scope invariant — selfdef does NOT implement NATS auth; operator wires mTLS / NKey / JWT externally | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | E0155 + E0158 | composite | false |
| F01799 | NATS bridge respects optional-not-mandatory invariant — default is `enabled = false`; operator opts in | `docs/src/ops/nats.md` § Configuration | F01715 | composite | false |
| F01800 | Composite — NATS messaging backbone is the selfdef cross-host event-propagation channel; preserves local-bus-source-of-truth invariant; 2-way loop avoidance; 2 modes Core (default) + JetStream (durable); at-least-once delivery + UUIDv7 dedupe at store sink; auth out of scope (BYO mTLS/NKey/JWT); 589-line crate `selfdef-nats` implements; operator-facing doc `docs/src/ops/nats.md` covers all contracts | `crates/selfdef-nats/` + `docs/src/ops/nats.md` | E0151–E0160 | composite | false |

## Requirements (R03361–R03600)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R03361 | NATS bridge ships as OPTIONAL bridge | `docs/src/ops/nats.md` § header | F01681 | non-negotiable | true | 10 |
| R03362 | NATS bridge pumps events between hosts | `docs/src/ops/nats.md` § header | F01682 | non-negotiable | false | 10 |
| R03363 | NATS bridge cites nats.io as upstream | `docs/src/ops/nats.md` § header | F01683 | non-negotiable | false | 10 |
| R03364 | Local in-proc broadcast remains source of truth for collectors | `docs/src/ops/nats.md` § header | F01684 | non-negotiable | false | 10 |
| R03365 | Local in-proc broadcast remains source of truth for correlator | `docs/src/ops/nats.md` § header | F01685 | non-negotiable | false | 10 |
| R03366 | Local in-proc broadcast remains source of truth for responder | `docs/src/ops/nats.md` § header | F01686 | non-negotiable | false | 10 |
| R03367 | Local in-proc broadcast remains source of truth for store sink | `docs/src/ops/nats.md` § "What it isn't" | F01687 | non-negotiable | false | 10 |
| R03368 | Local in-proc broadcast remains source of truth for API SSE stream | `docs/src/ops/nats.md` § "What it isn't" | F01688 | non-negotiable | false | 10 |
| R03369 | Bridge is sidecar task, NOT local-bus replacement | `docs/src/ops/nats.md` § header | F01689 | non-negotiable | false | 10 |
| R03370 | Outbound — one daemon publishes locally-originated events to NATS | `docs/src/ops/nats.md` § header | F01690 | non-negotiable | false | 10 |
| R03371 | Inbound — each daemon's bridge subscribes back to NATS + republishes remote events onto local bus | `docs/src/ops/nats.md` § header | F01691 | non-negotiable | false | 10 |
| R03372 | Typical deployment runs one detection daemon per host + one "hub" daemon | `docs/src/ops/nats.md` § header | F01692 | non-negotiable | true | 10 |
| R03373 | Hub daemon subscribes to everything for cross-host correlation | `docs/src/ops/nats.md` § header | F01693 | non-negotiable | true | 10 |
| R03374 | "Nothing in selfdef demands that topology — it just falls out of how the subject space is laid out" | `docs/src/ops/nats.md` § header | F01694 | non-negotiable | false | 10 |
| R03375 | Publish subject pattern — `<subject_prefix>.<host_tag>` | `docs/src/ops/nats.md` § Subject layout | F01695 | non-negotiable | false | 10 |
| R03376 | Subscribe subject pattern — `<subject_prefix>.>` | `docs/src/ops/nats.md` § Subject layout | F01696 | non-negotiable | false | 10 |
| R03377 | Default subject_prefix — `selfdef.events` | `docs/src/ops/nats.md` § Subject layout | F01697 | non-negotiable | false | 10 |
| R03378 | Subject example — daemon with `host_tag = "workstation-01"` publishes to `selfdef.events.workstation-01` | `docs/src/ops/nats.md` § Subject layout | F01698 | non-negotiable | true | 10 |
| R03379 | Subject example — same daemon subscribes to `selfdef.events.>` | `docs/src/ops/nats.md` § Subject layout | F01699 | non-negotiable | true | 10 |
| R03380 | Each event is the standard OCSF-aligned envelope, JSON-serialized | `docs/src/ops/nats.md` § Subject layout | F01700 | non-negotiable | false | 10 |
| R03381 | Bridge does NOT translate the payload | `docs/src/ops/nats.md` § Subject layout | F01701 | non-negotiable | false | 10 |
| R03382 | Bridge does NOT reshape the payload | `docs/src/ops/nats.md` § Subject layout | F01701 | non-negotiable | false | 10 |
| R03383 | "What comes out of local bus is what goes on the wire" | `docs/src/ops/nats.md` § Subject layout | F01702 | non-negotiable | false | 10 |
| R03384 | Loop scenario — daemon A publishes event X; daemon B receives on selfdef.events.A; pushes onto local bus; naïvely republishes; loop never ends | `docs/src/ops/nats.md` § Loop avoidance | F01703 | non-negotiable | false | 10 |
| R03385 | Loop avoidance — selfdef uses TWO mechanisms at once | `docs/src/ops/nats.md` § Loop avoidance | F01704 | non-negotiable | false | 10 |
| R03386 | Outbound filter — bridge only publishes events whose host_tag matches local daemon's | `docs/src/ops/nats.md` § Loop avoidance 1 | F01705 | non-negotiable | false | 10 |
| R03387 | Outbound filter — events that came in from NATS keep their original (remote) host_tag | `docs/src/ops/nats.md` § Loop avoidance 1 | F01706 | non-negotiable | false | 10 |
| R03388 | Outbound filter — outbound task simply skips remote-origin events | `docs/src/ops/nats.md` § Loop avoidance 1 | F01707 | non-negotiable | false | 10 |
| R03389 | Inbound filter — bridge drops messages whose host_tag == our own | `docs/src/ops/nats.md` § Loop avoidance 2 | F01708 | non-negotiable | false | 10 |
| R03390 | Inbound filter — defense in depth against NATS subject-filter mistake | `docs/src/ops/nats.md` § Loop avoidance 2 | F01709 | non-negotiable | false | 10 |
| R03391 | Inbound filter — defense in depth against downstream rewriting an event's host tag | `docs/src/ops/nats.md` § Loop avoidance 2 | F01710 | non-negotiable | false | 10 |
| R03392 | UUIDv7 envelope dedupe — events keyed by id at store sink | `docs/src/ops/nats.md` § Loop avoidance | F01711 | non-negotiable | false | 10 |
| R03393 | UUIDv7 dedupe — bridge doesn't rely on it | `docs/src/ops/nats.md` § Loop avoidance | F01712 | non-negotiable | false | 10 |
| R03394 | host_tag check is O(1) | `docs/src/ops/nats.md` § Loop avoidance | F01712 | non-negotiable | false | 10 |
| R03395 | host_tag check stops the loop at the source | `docs/src/ops/nats.md` § Loop avoidance | F01713 | non-negotiable | false | 10 |
| R03396 | Config block top-level — `[bus.nats]` | `docs/src/ops/nats.md` § Configuration | F01779 | non-negotiable | false | 10 |
| R03397 | Config knob — `enabled` (bool; default false; operator opts in) | `docs/src/ops/nats.md` § Configuration | F01715 | non-negotiable | true | 10 |
| R03398 | Config knob — `url` (string; e.g. `nats://nats.internal:4222`) | `docs/src/ops/nats.md` § Configuration | F01716 | non-negotiable | true | 10 |
| R03399 | Config knob — `subject_prefix` (string; default `selfdef.events`) | `docs/src/ops/nats.md` § Configuration | F01717 | non-negotiable | true | 10 |
| R03400 | URL — multi-server comma-separated per async-nats URL grammar | `docs/src/ops/nats.md` § Configuration | F01718 | non-negotiable | true | 10 |
| R03401 | URL — TLS supported via `tls://` scheme | `docs/src/ops/nats.md` § Configuration | F01719 | non-negotiable | true | 10 |
| R03402 | Authentication — OUT OF SCOPE for selfdef itself | `docs/src/ops/nats.md` § Configuration | F01720 | non-negotiable | false | 10 |
| R03403 | Authentication — operators put cluster behind mTLS / firewalls / NATS auth callouts as needed | `docs/src/ops/nats.md` § Configuration | F01721 | non-negotiable | true | 10 |
| R03404 | Mode selection — by config | `docs/src/ops/nats.md` § "Modes: Core vs JetStream" | F01722 | non-negotiable | false | 10 |
| R03405 | Mode Core (default) — fire-and-forget pub/sub | `docs/src/ops/nats.md` § Core | F01723 | non-negotiable | true | 10 |
| R03406 | Mode Core — lowest latency | `docs/src/ops/nats.md` § Core | F01724 | non-negotiable | false | 10 |
| R03407 | Mode Core — no durability | `docs/src/ops/nats.md` § Core | F01725 | non-negotiable | false | 10 |
| R03408 | Mode Core — daemon that drops off network misses messages passing while away | `docs/src/ops/nats.md` § Core | F01726 | non-negotiable | false | 10 |
| R03409 | Mode Core — good for live multi-host correlation on a stable LAN | `docs/src/ops/nats.md` § Core | F01727 | non-negotiable | false | 10 |
| R03410 | Mode Core config — only `[bus.nats]` block | `docs/src/ops/nats.md` § Core | F01728 | non-negotiable | true | 10 |
| R03411 | Mode JetStream — durable | `docs/src/ops/nats.md` § JetStream | F01729 | non-negotiable | true | 10 |
| R03412 | JetStream — outbound publishes go to a JetStream stream | `docs/src/ops/nats.md` § JetStream | F01730 | non-negotiable | false | 10 |
| R03413 | JetStream — inbound reads from a per-host durable pull consumer with explicit acks | `docs/src/ops/nats.md` § JetStream | F01731 | non-negotiable | false | 10 |
| R03414 | JetStream — daemon that restarts resumes from last acked message (not from "now") | `docs/src/ops/nats.md` § JetStream | F01732 | non-negotiable | false | 10 |
| R03415 | JetStream config block — `[bus.nats.jetstream]` | `docs/src/ops/nats.md` § JetStream | F01733 | non-negotiable | true | 10 |
| R03416 | JetStream knob — `enabled` (bool) | `docs/src/ops/nats.md` § JetStream | F01734 | non-negotiable | true | 10 |
| R03417 | JetStream knob — `stream_name = "selfdef-events"` | `docs/src/ops/nats.md` § JetStream | F01735 | non-negotiable | true | 10 |
| R03418 | JetStream knob — `durable_consumer_prefix = "selfdef-bridge"` | `docs/src/ops/nats.md` § JetStream | F01736 | non-negotiable | true | 10 |
| R03419 | JetStream knob — `max_age_secs` (default 604800 = 7 days; 0 = unlimited) | `docs/src/ops/nats.md` § JetStream | F01737 | non-negotiable | true | 10 |
| R03420 | JetStream knob — `max_bytes` (default -1 = unlimited) | `docs/src/ops/nats.md` § JetStream | F01738 | non-negotiable | true | 10 |
| R03421 | JetStream knob — `max_msgs` (default -1 = unlimited) | `docs/src/ops/nats.md` § JetStream | F01739 | non-negotiable | true | 10 |
| R03422 | JetStream bootstrap — bridge calls `get_or_create_stream` on startup | `docs/src/ops/nats.md` § JetStream | F01740 | non-negotiable | false | 10 |
| R03423 | JetStream bootstrap — first daemon to come up creates the stream | `docs/src/ops/nats.md` § JetStream | F01741 | non-negotiable | false | 10 |
| R03424 | JetStream bootstrap — subsequent daemons reuse the stream | `docs/src/ops/nats.md` § JetStream | F01742 | non-negotiable | false | 10 |
| R03425 | JetStream durable consumer name — `<durable_consumer_prefix>-<host_tag>` | `docs/src/ops/nats.md` § JetStream | F01743 | non-negotiable | false | 10 |
| R03426 | JetStream — each host tracks its own progress independently | `docs/src/ops/nats.md` § JetStream | F01744 | non-negotiable | false | 10 |
| R03427 | JetStream retention change — `nats stream edit selfdef-events` (operator-side) | `docs/src/ops/nats.md` § JetStream | F01745 | non-negotiable | true | 10 |
| R03428 | JetStream — bridge does NOT reconcile config drift | `docs/src/ops/nats.md` § JetStream | F01746 | non-negotiable | false | 10 |
| R03429 | JetStream outbound publish — awaits server ack | `docs/src/ops/nats.md` § JetStream | F01747 | non-negotiable | false | 10 |
| R03430 | JetStream outage behavior — stalls publishes rather than silently dropping | `docs/src/ops/nats.md` § JetStream | F01748 | non-negotiable | false | 10 |
| R03431 | JetStream inbound — acks after republish onto local bus | `docs/src/ops/nats.md` § JetStream | F01749 | non-negotiable | false | 10 |
| R03432 | JetStream inbound — acks after self-echo identification | `docs/src/ops/nats.md` § JetStream | F01750 | non-negotiable | false | 10 |
| R03433 | JetStream redeliveries — safe (UUIDv7 + store-sink dedupe by id) | `docs/src/ops/nats.md` § JetStream | F01751 | non-negotiable | false | 10 |
| R03434 | What it isn't — NOT replacement for local in-proc bus | `docs/src/ops/nats.md` § "What it isn't" | F01752 | non-negotiable | false | 10 |
| R03435 | What it isn't — every subscriber inside daemon still reads from local broadcast | `docs/src/ops/nats.md` § "What it isn't" | F01753 | non-negotiable | false | 10 |
| R03436 | What it isn't — NOT authenticated by selfdef itself | `docs/src/ops/nats.md` § "What it isn't" | F01754 | non-negotiable | false | 10 |
| R03437 | What it isn't — Bring your own NATS cluster auth (mTLS) | `docs/src/ops/nats.md` § "What it isn't" | F01755 | non-negotiable | true | 10 |
| R03438 | What it isn't — Bring your own NATS cluster auth (NKey) | `docs/src/ops/nats.md` § "What it isn't" | F01755 | non-negotiable | true | 10 |
| R03439 | What it isn't — Bring your own NATS cluster auth (JWT) | `docs/src/ops/nats.md` § "What it isn't" | F01755 | non-negotiable | true | 10 |
| R03440 | What it isn't — NOT a transaction system | `docs/src/ops/nats.md` § "What it isn't" | F01756 | non-negotiable | false | 10 |
| R03441 | What it isn't — JetStream gives "at-least-once" delivery, not "exactly-once" | `docs/src/ops/nats.md` § "What it isn't" | F01757 | non-negotiable | false | 10 |
| R03442 | What it isn't — dedupe story on consumer side matters | `docs/src/ops/nats.md` § "What it isn't" | F01758 | non-negotiable | false | 10 |
| R03443 | Smoke test — `nats-server -p 4222` | `docs/src/ops/nats.md` § Manual smoke test | F01759 | non-negotiable | true | 10 |
| R03444 | Smoke test — selfdef.toml configured with `[bus.nats]` enabled + url `nats://127.0.0.1:4222` | `docs/src/ops/nats.md` § Manual smoke test | F01760 | non-negotiable | true | 10 |
| R03445 | Smoke test — `selfdefd &` (start daemon in background) | `docs/src/ops/nats.md` § Manual smoke test | F01761 | non-negotiable | true | 10 |
| R03446 | Smoke test — `nats sub 'selfdef.events.>'` (observe outbound traffic) | `docs/src/ops/nats.md` § Manual smoke test | F01762 | non-negotiable | true | 10 |
| R03447 | Smoke test — trigger finding via API on second daemon configured same way | `docs/src/ops/nats.md` § Manual smoke test | F01763 | non-negotiable | true | 10 |
| R03448 | Smoke test — verify remote event arrives via first daemon's `selfdefctl events tail` | `docs/src/ops/nats.md` § Manual smoke test | F01764 | non-negotiable | true | 10 |
| R03449 | Crate `selfdef-nats` exists at `crates/selfdef-nats/` | `crates/selfdef-nats/` | M00369 | non-negotiable | false | 10 |
| R03450 | Crate `selfdef-nats/Cargo.toml` is a workspace member | `crates/selfdef-nats/Cargo.toml` | F01765 | non-negotiable | false | 10 |
| R03451 | Crate `selfdef-nats/src/lib.rs` exists (589 lines at audit-cycle snapshot) | `crates/selfdef-nats/src/lib.rs` | F01766 | non-negotiable | false | 10 |
| R03452 | Crate `selfdef-nats/tests/` contains integration tests | `crates/selfdef-nats/tests/` | F01767 | non-negotiable | false | 10 |
| R03453 | Documentation `docs/src/ops/nats.md` operator-facing | `docs/src/ops/nats.md` | F01768 | non-negotiable | false | 10 |
| R03454 | Documentation `docs/src/ops/config.md` references `[bus.nats]` | `docs/src/ops/config.md` | F01769 | non-negotiable | false | 10 |
| R03455 | Documentation `docs/src/SUMMARY.md` lists "NATS bridge" entry | `docs/src/SUMMARY.md` | F01770 | non-negotiable | false | 10 |
| R03456 | Topology — hub-and-spoke is one valid topology (NOT the only one) | `docs/src/ops/nats.md` § header | F01772 | non-negotiable | true | 10 |
| R03457 | Topology — mesh / partitioned mesh / fan-in / fan-out are all valid topologies (operator-decided) | `docs/src/ops/nats.md` § header | F01772 | non-negotiable | true | 10 |
| R03458 | Subject prefix configurable for multi-tenant deployments | `docs/src/ops/nats.md` § Subject layout | F01773 | non-negotiable | true | 10 |
| R03459 | host_tag is per-daemon operator-configured (typically hostname) | `docs/src/ops/nats.md` § Subject layout | F01774 | non-negotiable | false | 10 |
| R03460 | OCSF envelope is byte-equal on local bus and across the wire | `docs/src/ops/nats.md` § Subject layout | F01775 | non-negotiable | false | 10 |
| R03461 | Outbound filter predicate — `event.host_tag == local.host_tag` | `docs/src/ops/nats.md` § Loop avoidance 1 | F01776 | non-negotiable | false | 10 |
| R03462 | Inbound filter predicate — `event.host_tag != local.host_tag` | `docs/src/ops/nats.md` § Loop avoidance 2 | F01777 | non-negotiable | false | 10 |
| R03463 | Defense-in-depth — both filters active simultaneously | `docs/src/ops/nats.md` § Loop avoidance | F01778 | non-negotiable | false | 10 |
| R03464 | TLS config example — `tls://nats.example.com:4222` is valid URL | `docs/src/ops/nats.md` § Configuration | F01781 | non-negotiable | true | 10 |
| R03465 | Multi-server example — `nats://a.example.com:4222,nats://b.example.com:4222` is valid URL | `docs/src/ops/nats.md` § Configuration | F01782 | non-negotiable | true | 10 |
| R03466 | Integration with MS002 — collector fabric publishes events to local bus; bridge subscribes to local bus | MS002 | F01783 | non-negotiable | false | 10 |
| R03467 | Integration with MS003 — correlator receives both local AND bridge-republished remote events from local bus | MS003 | F01784 | non-negotiable | false | 10 |
| R03468 | Integration with MS003 — responder receives both local AND remote events | MS003 | F01785 | non-negotiable | false | 10 |
| R03469 | Integration with MS006 — agent-guard / SSH-wrap / etc. emit events; bridge propagates | MS006 | F01786 | non-negotiable | false | 10 |
| R03470 | Integration with MS007 — typed-mirror crates may carry NATS subject-prefix conventions for cross-repo deployments | MS007 + SDD-038 | F01787 | non-negotiable | false | 10 |
| R03471 | Integration with MS008 — selfdef-on-SAIN-01 may run a hub daemon for cross-host correlation | MS008 | F01788 | non-negotiable | false | 10 |
| R03472 | Integration with MS009 — audit cycles phase-6/-7 crate audit covers selfdef-nats | MS009 phase-6/-7 | F01789 | non-negotiable | false | 10 |
| R03473 | Operator scenario — single workstation deployment with NATS DISABLED (default) | `docs/src/ops/nats.md` § Configuration | F01790 | non-negotiable | true | 10 |
| R03474 | Operator scenario — multi-host LAN deployment with Core mode | `docs/src/ops/nats.md` § Core | F01791 | non-negotiable | true | 10 |
| R03475 | Operator scenario — multi-host deployment with intermittent connectivity + JetStream | `docs/src/ops/nats.md` § JetStream | F01792 | non-negotiable | true | 10 |
| R03476 | Operator scenario — fleet of detection daemons + hub aggregator | `docs/src/ops/nats.md` § header | F01793 | non-negotiable | true | 10 |
| R03477 | Invariant — local-bus-is-source-of-truth | `docs/src/ops/nats.md` § "What it isn't" | F01794 | non-negotiable | false | 10 |
| R03478 | Invariant — no-payload-translation (byte-equal across wire) | `docs/src/ops/nats.md` § Subject layout | F01795 | non-negotiable | false | 10 |
| R03479 | Invariant — loop-free (host_tag filter at source O(1)) | `docs/src/ops/nats.md` § Loop avoidance | F01796 | non-negotiable | false | 10 |
| R03480 | Invariant — at-least-once + UUIDv7 dedupe | `docs/src/ops/nats.md` § JetStream + § "What it isn't" | F01797 | non-negotiable | false | 10 |
| R03481 | Invariant — auth-out-of-scope (selfdef does NOT implement NATS auth) | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | F01798 | non-negotiable | false | 10 |
| R03482 | Invariant — optional-not-mandatory (default `enabled = false`) | `docs/src/ops/nats.md` § Configuration | F01799 | non-negotiable | false | 10 |
| R03483 | Cross-host correlation enabled by hub daemon subscribing to `selfdef.events.>` | `docs/src/ops/nats.md` § header + § Subject layout | F01771 | non-negotiable | false | 10 |
| R03484 | Per-host detection daemon publishes to its own subject (per-host event ownership) | `docs/src/ops/nats.md` § Subject layout | F01695 | non-negotiable | false | 10 |
| R03485 | Cross-repo binding — NATS subject schema documented; sovereign-os may subscribe externally via mTLS-protected NATS cluster (NOT direct crate import) | MS007 + SDD-038 + `docs/src/ops/nats.md` | F01787 | non-negotiable | false | 10 |
| R03486 | Cross-repo binding — sovereign-os runtime may publish runtime-trace events to a different subject prefix (e.g. `sovereign.events`) for selfdef-side ingestion via documented JSONL channel | architecture + MS007 + SDD-038 | F01787 | non-negotiable | false | 10 |
| R03487 | Bridge implementation language — Rust (selfdef-nats crate) | `crates/selfdef-nats/Cargo.toml` | M00369 | non-negotiable | false | 10 |
| R03488 | Bridge implementation library — async-nats (cited by URL grammar reference) | `docs/src/ops/nats.md` § Configuration | M00386 | non-negotiable | false | 10 |
| R03489 | Bridge does NOT implement NATS server-side features (consumer groups, mirroring, geo-replication) — leaves to NATS cluster | `docs/src/ops/nats.md` § "What it isn't" | E0158 | non-negotiable | false | 10 |
| R03490 | Bridge does NOT implement encryption-at-rest in NATS — relies on operator-deployed NATS JetStream encryption-at-rest settings | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | E0155 | non-negotiable | false | 10 |
| R03491 | Bridge does NOT implement event-level encryption — assumes mTLS or equivalent at transport layer | `docs/src/ops/nats.md` § Configuration | M00386 | non-negotiable | false | 10 |
| R03492 | Bridge does NOT translate event schemas — OCSF envelope is universal | `docs/src/ops/nats.md` § Subject layout | F01700 | non-negotiable | false | 10 |
| R03493 | Bridge does NOT mutate host_tag on outbound publishes | `docs/src/ops/nats.md` § Loop avoidance 1 | F01706 | non-negotiable | false | 10 |
| R03494 | Bridge does NOT mutate host_tag on inbound republishes | `docs/src/ops/nats.md` § Loop avoidance 2 | F01710 | non-negotiable | false | 10 |
| R03495 | Bridge survives NATS server restart — reconnect logic via async-nats library | `docs/src/ops/nats.md` § JetStream "outage stalls" | F01748 | non-negotiable | false | 10 |
| R03496 | Bridge survives daemon restart — Core mode resumes from "now"; JetStream mode resumes from last acked | `docs/src/ops/nats.md` § Core + § JetStream | F01726 + F01732 | non-negotiable | false | 10 |
| R03497 | Bridge survives network partition — Core mode loses messages; JetStream mode catches up after partition heals | `docs/src/ops/nats.md` § Core + § JetStream | F01726 + F01732 | non-negotiable | false | 10 |
| R03498 | Bridge auto-creates JetStream stream on first connect (`get_or_create_stream`) | `docs/src/ops/nats.md` § JetStream | F01740 | non-negotiable | false | 10 |
| R03499 | Bridge auto-creates durable consumer on first connect (per-host) | `docs/src/ops/nats.md` § JetStream | F01743 | non-negotiable | false | 10 |
| R03500 | Bridge respects retention config on stream creation but doesn't enforce drift afterward (operator-side responsibility) | `docs/src/ops/nats.md` § JetStream | F01746 | non-negotiable | false | 10 |
| R03501 | Operator runs `nats stream edit selfdef-events` for retention changes | `docs/src/ops/nats.md` § JetStream | F01745 | non-negotiable | true | 10 |
| R03502 | Operator runs `nats stream info selfdef-events` for stream introspection | `docs/src/ops/nats.md` § JetStream (implied tooling) | F01745 | non-negotiable | true | 10 |
| R03503 | Operator runs `nats consumer info selfdef-events selfdef-bridge-<host>` for consumer introspection | `docs/src/ops/nats.md` § JetStream (implied tooling) | F01743 | non-negotiable | true | 10 |
| R03504 | Tests — crate `selfdef-nats/tests/` includes loop-avoidance test (outbound filter) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Loop avoidance 1 | F01767 + F01705 | non-negotiable | false | 10 |
| R03505 | Tests — crate `selfdef-nats/tests/` includes loop-avoidance test (inbound filter) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Loop avoidance 2 | F01767 + F01708 | non-negotiable | false | 10 |
| R03506 | Tests — crate `selfdef-nats/tests/` includes Core mode pub-sub round-trip test | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Core | F01767 + F01723 | non-negotiable | false | 10 |
| R03507 | Tests — crate `selfdef-nats/tests/` includes JetStream durable consumer test | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § JetStream | F01767 + F01729 | non-negotiable | false | 10 |
| R03508 | Tests — crate `selfdef-nats/tests/` includes UUIDv7 dedupe test (redelivery scenario) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § JetStream redeliveries | F01767 + F01751 | non-negotiable | false | 10 |
| R03509 | Tests — crate `selfdef-nats/tests/` includes multi-server URL parsing test | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Configuration | F01767 + F01718 | non-negotiable | false | 10 |
| R03510 | Tests — crate `selfdef-nats/tests/` includes TLS URL parsing test | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Configuration | F01767 + F01719 | non-negotiable | false | 10 |
| R03511 | Tests — crate `selfdef-nats/tests/` includes subject-prefix override test (multi-tenant) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Subject layout | F01767 + F01773 | non-negotiable | false | 10 |
| R03512 | Tests — crate `selfdef-nats/tests/` includes payload byte-equality test (no translation) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Subject layout | F01767 + F01775 | non-negotiable | false | 10 |
| R03513 | Tests — crate `selfdef-nats/tests/` includes `enabled = false` no-op test (bridge skipped) | `crates/selfdef-nats/tests/` + `docs/src/ops/nats.md` § Configuration | F01767 + F01715 | non-negotiable | false | 10 |
| R03514 | Operator-facing CLI — `selfdefctl bus status` (implied; integration with selfdefctl) shows bridge state | architecture + `docs/src/ops/nats.md` § header | E0151 | non-negotiable | true | 10 |
| R03515 | Operator-facing CLI — `selfdefctl events tail` shows local bus (which includes both local AND bridge-republished remote events) | `docs/src/ops/nats.md` § Manual smoke test | F01764 | non-negotiable | true | 10 |
| R03516 | Operator-facing CLI — `selfdefctl events tail --remote` (implied) shows only bridge-republished events | architecture | F01764 | non-negotiable | true | 10 |
| R03517 | Metric — Layer-B `sovereign_os_selfdef_nats_outbound_publish_total{outcome}` (implied per MS009 audit pattern) | architecture + MS009 phase-6 80-security | E0151 | non-negotiable | true | 10 |
| R03518 | Metric — Layer-B `sovereign_os_selfdef_nats_inbound_republish_total{outcome}` (implied) | architecture | E0151 | non-negotiable | true | 10 |
| R03519 | Metric — Layer-B `sovereign_os_selfdef_nats_loop_filter_dropped_total{direction}` (implied) | architecture + `docs/src/ops/nats.md` § Loop avoidance | E0154 | non-negotiable | true | 10 |
| R03520 | Metric — Layer-B `sovereign_os_selfdef_nats_jetstream_publish_ack_latency_seconds` (implied) | architecture + `docs/src/ops/nats.md` § JetStream | F01747 | non-negotiable | true | 10 |
| R03521 | Project boundary — selfdef-nats is selfdef-scope only; sovereign-os does NOT import the crate directly | architecture + MS007 + SDD-038 | E0151 | non-negotiable | false | 10 |
| R03522 | Project boundary — cross-repo event propagation via documented NATS subject schema, NOT crate import | MS007 + SDD-038 + `docs/src/ops/nats.md` § Subject layout | F01787 | non-negotiable | false | 10 |
| R03523 | Project boundary — sovereign-os MAY subscribe to selfdef.events.> externally with mTLS for fleet-level correlation | architecture + `docs/src/ops/nats.md` § Configuration | F01788 | non-negotiable | false | 10 |
| R03524 | Project boundary — sovereign-os MAY publish to sovereign.events.> with its own bridge for fleet-level visibility into runtime traces | architecture + cross-repo pattern | R03486 | non-negotiable | false | 10 |
| R03525 | Project boundary — Oracle-Triage MS004 E0036 may carry NATS subject-prefix metadata for cross-repo event correlation | MS004 E0036 + SDD-038 | E0151 | non-negotiable | false | 10 |
| R03526 | Project boundary — selfdef-nats DOES NOT carry sovereign-os payloads (only selfdef-OCSF events) | architecture | F01700 | non-negotiable | false | 10 |
| R03527 | Project boundary — sovereign-os runtime trace re-ingest into selfdef happens via selfdef-collector-eventstream (JSONL file), NOT NATS bridge | architecture + SDD-012 Q-E | F01700 | non-negotiable | false | 10 |
| R03528 | Audit cycle integration — MS009 phase-6 crate audit covers `selfdef-nats` per charter (M00343 SDD-charter referenced) | MS009 phase-6 30-crate-audit | F01789 | non-negotiable | false | 10 |
| R03529 | Audit cycle integration — MS009 phase-7 integration audit verifies bridge end-to-end (manual smoke test transcribed) | MS009 phase-7 50-integration-audit | F01789 | non-negotiable | false | 10 |
| R03530 | Audit cycle integration — MS009 phase-6 docs audit covers `docs/src/ops/nats.md` against SDD charter style rules | MS009 phase-6 60-docs-audit | F01768 | non-negotiable | false | 10 |
| R03531 | Audit cycle integration — MS009 phase-6 security audit covers NATS-auth-out-of-scope risk + operator-deployment guidance | MS009 phase-6 80-security-audit | F01754 | non-negotiable | false | 10 |
| R03532 | Audit cycle integration — findings ledger F-2026-NNN may record NATS-side deployment misconfigurations (e.g. no mTLS) | MS009 99-findings-ledger | F01754 | non-negotiable | false | 10 |
| R03533 | Integration with MS001 daemon core — bridge sidecar task is spawned by selfdef-daemon during startup when `[bus.nats]` enabled=true | MS001 + `docs/src/ops/nats.md` § header | E0151 | non-negotiable | false | 10 |
| R03534 | Integration with MS001 daemon core — bridge subscribes to local bus via daemon's broadcast handle | MS001 + `docs/src/ops/nats.md` § header | F01690 | non-negotiable | false | 10 |
| R03535 | Integration with MS001 daemon core — bridge publishes to local bus via daemon's broadcast handle | MS001 + `docs/src/ops/nats.md` § header | F01691 | non-negotiable | false | 10 |
| R03536 | Integration with MS002 collector fabric — collectors publish to local bus; bridge sees them via subscription | MS002 + `docs/src/ops/nats.md` § header | F01783 | non-negotiable | false | 10 |
| R03537 | Integration with MS003 correlator — correlator runs rules over local bus stream (both local AND bridge-republished events) | MS003 + `docs/src/ops/nats.md` § "What it isn't" | F01784 | non-negotiable | false | 10 |
| R03538 | Integration with MS003 responder — responder triggers on correlator output regardless of event origin (local or remote-via-bridge) | MS003 + `docs/src/ops/nats.md` § "What it isn't" | F01785 | non-negotiable | false | 10 |
| R03539 | Integration with MS003 store sink — store sink dedupes by UUIDv7 (handles at-least-once redeliveries) | MS003 + `docs/src/ops/nats.md` § JetStream | F01751 | non-negotiable | false | 10 |
| R03540 | Integration with MS004 notifier integrations — notifiers fire on local bus; bridge republishes remote events that may then fire local notifiers (operator-aware) | MS004 + `docs/src/ops/nats.md` § header | E0151 | non-negotiable | false | 10 |
| R03541 | Integration with MS005 notifier engine — orchestrator handles dedup-by-correlation-id across local AND bridge events | MS005 + `docs/src/ops/nats.md` § Loop avoidance | F01711 | non-negotiable | false | 10 |
| R03542 | Integration with MS006 functional modules — all 14 modules publish events to local bus; bridge propagates | MS006 + `docs/src/ops/nats.md` § header | F01786 | non-negotiable | false | 10 |
| R03543 | Integration with MS008 SAIN-01 — bridge enables fleet-of-1 → fleet-of-N scaling without rewriting SAIN-01 deployment | MS008 + `docs/src/ops/nats.md` § header | F01788 | non-negotiable | false | 10 |
| R03544 | Integration with MS010 hardware-aware modules — module-gate events (apply / skip) propagate via bridge for fleet-wide visibility | MS010 + `docs/src/ops/nats.md` § header | F01786 | non-negotiable | false | 10 |
| R03545 | Integration with MS011 operator dashboard — dashboard MCP tab may show cross-host events via bridge subscriber endpoint | MS011 + `docs/src/ops/nats.md` § header | E0152 | non-negotiable | false | 10 |
| R03546 | Integration with MS012 perimeter coexistence — policy-strip events from agent-guard propagate via bridge for fleet-wide perimeter audit | MS012 + `docs/src/ops/nats.md` § header | F01786 | non-negotiable | false | 10 |
| R03547 | Integration with MS013 27-SDD charter — bridge has no dedicated SDD (codified in nats.md + crate); future SDD slot available if scope grows | MS013 + `docs/sdd/` ledger | E0160 | non-negotiable | false | 10 |
| R03548 | Integration with MS014 SSH-wrap — ssh-wrap policy-strip events flow into local bus via eventstream collector, then via bridge to fleet | MS014 + MS002 + `docs/src/ops/nats.md` § header | F01786 | non-negotiable | false | 10 |
| R03549 | Operator scenario — fleet-wide T1098 detection (sudoers + ssh_wrap_policy_strip) via bridge | MS014 + MS012 + `docs/src/ops/nats.md` § header | F01793 | non-negotiable | true | 10 |
| R03550 | Operator scenario — fleet-wide rollback-coordination via responder events on bridge | MS003 + `docs/src/ops/nats.md` § "What it isn't" | F01793 | non-negotiable | true | 10 |
| R03551 | Compliance scenario — single-tenant deployment uses `selfdef.events` default prefix | `docs/src/ops/nats.md` § Subject layout | F01697 | non-negotiable | true | 10 |
| R03552 | Compliance scenario — multi-tenant deployment uses per-tenant prefixes (e.g. `selfdef.tenant-a.events`, `selfdef.tenant-b.events`) | `docs/src/ops/nats.md` § Subject layout | F01773 | non-negotiable | true | 10 |
| R03553 | Compliance scenario — operator separately deploys NATS auth (mTLS / NKey / JWT) per tenant | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | F01755 | non-negotiable | true | 10 |
| R03554 | Failure mode — NATS server unreachable on startup → bridge backs off + retries (async-nats default reconnect policy) | `docs/src/ops/nats.md` § JetStream "outage stalls" + async-nats library | F01748 | non-negotiable | false | 10 |
| R03555 | Failure mode — NATS server unreachable after startup → bridge backs off + retries | async-nats library + `docs/src/ops/nats.md` § JetStream | F01748 | non-negotiable | false | 10 |
| R03556 | Failure mode — Core mode + network partition → messages lost (by design) | `docs/src/ops/nats.md` § Core | F01725 + F01726 | non-negotiable | false | 10 |
| R03557 | Failure mode — JetStream mode + network partition → daemon catches up after partition heals | `docs/src/ops/nats.md` § JetStream | F01732 | non-negotiable | false | 10 |
| R03558 | Failure mode — JetStream max_age_secs reached → old messages purged automatically by NATS server | `docs/src/ops/nats.md` § JetStream | F01737 | non-negotiable | false | 10 |
| R03559 | Failure mode — JetStream max_bytes / max_msgs reached → NATS server applies retention policy (operator decision) | `docs/src/ops/nats.md` § JetStream | F01738 + F01739 | non-negotiable | false | 10 |
| R03560 | Failure mode — bridge ack failure (NATS server crashed mid-ack) → at-least-once redelivery + UUIDv7 dedupe at store sink | `docs/src/ops/nats.md` § JetStream | F01751 | non-negotiable | false | 10 |
| R03561 | Failure mode — host_tag collision (two daemons configured with same host_tag) → loop avoidance breaks; operator-error category | `docs/src/ops/nats.md` § Loop avoidance | F01776 + F01777 | non-negotiable | false | 10 |
| R03562 | Failure mode — TOML parse error in `[bus.nats]` → bridge starts disabled + emits error log; daemon continues without bridge | `docs/src/ops/nats.md` § Configuration | F01715 | non-negotiable | false | 10 |
| R03563 | Failure mode — NATS auth rejected → bridge logs error + retries; bridge does NOT enforce auth itself | `docs/src/ops/nats.md` § "What it isn't" | F01754 | non-negotiable | false | 10 |
| R03564 | Doctrine — async-nats library is the canonical Rust NATS client | `docs/src/ops/nats.md` § Configuration "async-nats URL grammar" | M00386 | non-negotiable | false | 10 |
| R03565 | Doctrine — NATS is the recommended cross-host bus (not Kafka / RabbitMQ / Pulsar) due to subject-tree subscription semantics and low-overhead deployment | `docs/src/ops/nats.md` § header | E0151 | non-negotiable | false | 10 |
| R03566 | Doctrine — JetStream is the recommended durable mode (not Kafka topics, not RabbitMQ queues) when durability needed | `docs/src/ops/nats.md` § JetStream | E0157 | non-negotiable | false | 10 |
| R03567 | Doctrine — operator chooses Core vs JetStream per deployment characteristics (LAN stability vs need for durability) | `docs/src/ops/nats.md` § Core + § JetStream | E0156 + E0157 | non-negotiable | false | 10 |
| R03568 | Doctrine — bridge is optional infrastructure (default off; operator opt-in) | `docs/src/ops/nats.md` § Configuration | F01715 + F01799 | non-negotiable | false | 10 |
| R03569 | Doctrine — bridge does NOT replace local bus; the local bus remains the canonical source of truth | `docs/src/ops/nats.md` § "What it isn't" | F01752 + F01794 | non-negotiable | false | 10 |
| R03570 | Doctrine — bridge does NOT mutate event content (payload preserved byte-for-byte across the wire) | `docs/src/ops/nats.md` § Subject layout | F01701 + F01795 | non-negotiable | false | 10 |
| R03571 | Doctrine — bridge does NOT implement authentication; operator deploys NATS auth externally | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | F01754 + F01798 | non-negotiable | false | 10 |
| R03572 | Doctrine — bridge MUST prevent loops via host_tag filter (defense-in-depth) | `docs/src/ops/nats.md` § Loop avoidance | F01796 | non-negotiable | false | 10 |
| R03573 | Doctrine — bridge MUST handle at-least-once delivery semantics via UUIDv7 dedupe at store sink | `docs/src/ops/nats.md` § JetStream + § "What it isn't" | F01797 | non-negotiable | false | 10 |
| R03574 | Doctrine — bridge MUST survive NATS server outage (Core: messages lost; JetStream: stalls until reconnect) | `docs/src/ops/nats.md` § Core + § JetStream | R03554 + R03555 | non-negotiable | false | 10 |
| R03575 | Doctrine — bridge MUST survive daemon restart (Core: from "now"; JetStream: from last acked) | `docs/src/ops/nats.md` § Core + § JetStream | F01726 + F01732 | non-negotiable | false | 10 |
| R03576 | Doctrine — bridge MUST preserve OCSF envelope schema across the wire (no schema translation) | `docs/src/ops/nats.md` § Subject layout | F01700 | non-negotiable | false | 10 |
| R03577 | Doctrine — bridge subject space MUST be hierarchical (subject_prefix.host_tag) to enable wildcard subscriptions | `docs/src/ops/nats.md` § Subject layout | F01695 | non-negotiable | false | 10 |
| R03578 | Doctrine — operator MUST set unique host_tag per daemon to enable loop avoidance | `docs/src/ops/nats.md` § Loop avoidance | F01774 + R03561 | non-negotiable | false | 10 |
| R03579 | Doctrine — operator MUST deploy NATS cluster (single server or multi-server) before enabling `[bus.nats]` | `docs/src/ops/nats.md` § Configuration + § Manual smoke test | F01759 | non-negotiable | false | 10 |
| R03580 | Doctrine — operator MUST configure NATS auth externally (mTLS / NKey / JWT) for production deployments | `docs/src/ops/nats.md` § Configuration + § "What it isn't" | F01755 | non-negotiable | false | 10 |
| R03581 | Doctrine — operator SHOULD test bridge deployment with manual smoke test before relying on it | `docs/src/ops/nats.md` § Manual smoke test | F01762 + F01764 | non-negotiable | true | 10 |
| R03582 | Composite scenario — single-host workstation: `[bus.nats]` disabled (default); selfdef runs as standalone host-defense daemon | architecture + `docs/src/ops/nats.md` § Configuration | F01790 | non-negotiable | false | 10 |
| R03583 | Composite scenario — laptop + workstation home network: Core mode + nats-server on workstation + 2 daemons cross-correlate | architecture + `docs/src/ops/nats.md` § Core + § Manual smoke test | F01791 + F01794 | non-negotiable | true | 10 |
| R03584 | Composite scenario — small fleet (5–20 hosts) on stable LAN: Core mode + central NATS cluster (mTLS) + 1 hub daemon aggregator | architecture + `docs/src/ops/nats.md` § Core + § header | F01791 + F01793 | non-negotiable | true | 10 |
| R03585 | Composite scenario — large fleet (50+ hosts) with intermittent connectivity: JetStream mode + multi-server NATS cluster + per-host durable consumers | architecture + `docs/src/ops/nats.md` § JetStream | F01792 | non-negotiable | true | 10 |
| R03586 | Composite scenario — cross-data-center fleet: JetStream mirroring (NATS server-side feature; bridge unaware) + per-DC hub daemons | architecture + `docs/src/ops/nats.md` § JetStream + § "What it isn't" | R03489 | non-negotiable | true | 10 |
| R03587 | Operator audit verb — `selfdefctl bus status` (implied; planned per architecture) shows bridge connectivity + last-ack timestamp + lag | architecture + MS011 dashboard MCP tab | R03514 | non-negotiable | true | 10 |
| R03588 | Operator audit verb — `selfdefctl bus health` (implied) reports NATS connectivity + JetStream stream existence + consumer lag | architecture | R03514 | non-negotiable | true | 10 |
| R03589 | Operator audit verb — `nats account info` (NATS CLI; external) reports cluster-level state | NATS CLI + `docs/src/ops/nats.md` § Configuration | F01745 | non-negotiable | true | 10 |
| R03590 | Operator audit verb — `nats stream report` (NATS CLI; external) reports JetStream stream + consumer state across cluster | NATS CLI + `docs/src/ops/nats.md` § JetStream | F01745 | non-negotiable | true | 10 |
| R03591 | Composite — selfdef-nats DOES NOT implement Kafka-style "consumer groups" (NATS JetStream uses durable consumers per host instead) | `docs/src/ops/nats.md` § JetStream | F01744 | non-negotiable | false | 10 |
| R03592 | Composite — selfdef-nats DOES NOT implement message-level ordering guarantees (NATS preserves per-subject FIFO; cross-subject ordering is operator-responsibility) | `docs/src/ops/nats.md` § Subject layout + § JetStream | F01695 | non-negotiable | false | 10 |
| R03593 | Composite — selfdef-nats DOES NOT implement message-level priority (operator uses multiple subject prefixes for priority lanes if needed) | architecture + `docs/src/ops/nats.md` § Subject layout | F01773 | non-negotiable | false | 10 |
| R03594 | Composite — selfdef-nats DOES NOT implement message routing rules (subject-prefix is the only routing primitive) | `docs/src/ops/nats.md` § Subject layout | F01695 | non-negotiable | false | 10 |
| R03595 | Composite — selfdef-nats DOES NOT implement message transformation (payload byte-equal across wire) | `docs/src/ops/nats.md` § Subject layout | F01701 + F01795 | non-negotiable | false | 10 |
| R03596 | Composite — selfdef-nats DOES NOT implement RPC patterns (request-reply); selfdef daemons communicate via local API + bridge events, NOT NATS RPC | architecture + `docs/src/ops/nats.md` § header | E0151 | non-negotiable | false | 10 |
| R03597 | Composite — selfdef-nats DOES NOT implement KV-store / object-store features (NATS server features outside selfdef's scope) | `docs/src/ops/nats.md` § "What it isn't" | R03489 | non-negotiable | false | 10 |
| R03598 | Composite — selfdef-nats DOES NOT implement service discovery (operator hardcodes URL in `[bus.nats]`) | `docs/src/ops/nats.md` § Configuration | F01716 | non-negotiable | false | 10 |
| R03599 | Composite — selfdef-nats focuses ONLY on event-fan-out across hosts (single responsibility; rest delegated to NATS server + selfdef daemon) | `docs/src/ops/nats.md` § header + § "What it isn't" | E0151 + E0158 | non-negotiable | false | 10 |
| R03600 | Composite — NATS messaging backbone is the selfdef cross-host event-propagation channel; preserves local-bus-source-of-truth invariant; 2-way loop avoidance via host_tag filter at outbound + inbound; 2 modes Core (default fire-and-forget) + JetStream (durable per-host pull consumer + acks); at-least-once delivery + UUIDv7 dedupe at store sink; auth out of scope (BYO mTLS/NKey/JWT); 589-line crate `selfdef-nats` implements; operator-facing doc `docs/src/ops/nats.md` covers all contracts; integrates with MS001-MS014; cross-repo binding via documented NATS subject schema (NOT direct crate import); MS007 typed mirrors may carry subject-prefix conventions | `crates/selfdef-nats/` + `docs/src/ops/nats.md` + MS001-MS014 | E0151 + E0152 + E0153 + E0154 + E0155 + E0156 + E0157 + E0158 + E0159 + E0160 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS014: 16320 + 2400 = 18720 sub-requirements when MS015 lands

## Cross-references

- Crate root: `crates/selfdef-nats/` (Cargo.toml + src/lib.rs + tests/)
- Operator-facing doc: `docs/src/ops/nats.md`
- Config reference: `docs/src/ops/config.md` `[bus.nats]` entry
- Summary entry: `docs/src/SUMMARY.md` § NATS bridge
- Sister milestones: MS002 collector fabric (publishes to local bus; bridge subscribes) / MS003 correlator+responder+store sink (all read local bus, including bridge-republished events) / MS006 functional modules (emit events that bridge propagates) / MS008 SAIN-01 (single-workstation deployment; bridge optional) / MS012 perimeter coexistence (policy-strip events propagate via bridge) / MS014 SSH-wrap (policy-strip events flow via collector → local bus → bridge)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (sovereign-os may subscribe to selfdef.events.> externally; NOT crate import)
