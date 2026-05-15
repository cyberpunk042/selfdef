# selfdef-integration-wall

`wall(1)` session-attention channel. SDD-008 D-8.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against the venerable Unix [`wall(1)`](https://man7.org/linux/man-pages/man1/wall.1.html) broadcast. Each event spawns `/usr/bin/wall` with the rendered attention message on stdin; every logged-in TTY (where the receiver hasn't `mesg n`'d) sees the broadcast.

**No per-user targeting** — `wall(1)` does not accept a username filter; the channel is system-wide by definition. For per-user opt-in, use [`selfdef-integration-write`](../selfdef-integration-write/). The `[notifier.wall].users` knob intentionally does **not** exist (would imply behavior `wall(1)` can't deliver). See D-024 in `docs/decisions.md`.

**`severity_floor = "high"` by default** — wall is loud-by-design; bothering every TTY on routine events is wrong.

## Operator setup

See [`docs/operator/channels.md#wall`](../../docs/operator/channels.md#wall) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.wall]`.

## Crate layout

- `src/lib.rs` — `WallChannel` struct + both trait impls + severity-floor enforcement.
- `Cargo.toml` — `tokio` (subprocess), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-wall
```

Tests stub `wall(1)` with a shell-script harness that captures stdin and records invocation — no real TTY broadcast happens during `cargo test`.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) D-8.
- Decisions: [`docs/decisions.md`](../../docs/decisions.md) D-004 + D-024 (per-user transport realization).
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Sibling crate: [`selfdef-integration-write`](../selfdef-integration-write/) — per-user TTY transport.
