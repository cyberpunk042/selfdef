# selfdef-integration-write

`write(1)` per-user session-attention channel. D-024 realization.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against the Unix [`write(1)`](https://man7.org/linux/man-pages/man1/write.1.html) command. Sibling of [`selfdef-integration-wall`](../selfdef-integration-wall/) for **per-user** TTY delivery: where `wall(1)` broadcasts to every logged-in TTY, `write(1)` targets one user at a time.

For each name in the configured `users` allowlist, the channel spawns:

```
write <username>
```

and pipes the rendered attention message into stdin. Per-user spawns are sequential; a failure for one user does **not** abort delivery to the others (best-effort).

**`write(1)` exits non-zero when the target user is not logged in** — that's expected, not an error worth surfacing (operators in vim / not at a session shouldn't fail an escalation). Genuine failures (binary missing, spawn errored) still surface.

**Username validation**: each name in `users` must match `[a-zA-Z0-9._-]+`. Shell metacharacters are rejected at config-load — selfdef refuses to start with a malformed username rather than risk shell injection on the subprocess argv.

**`severity_floor = "high"` by default** — same posture as wall.

## Operator setup

See [`docs/operator/channels.md#write`](../../docs/operator/channels.md#write) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.write]`.

## Crate layout

- `src/lib.rs` — `WriteChannel` struct + both trait impls + username validator + per-user sequential spawn loop.
- `Cargo.toml` — `tokio` (subprocess), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-write
```

20 tests cover: username validation (accepts/rejects shell metacharacters), severity-floor enforcement, per-user spawn loop, the "user not logged in is OK" non-error path, multi-user delivery loop.

## See also

- Decisions: [`docs/decisions.md`](../../docs/decisions.md) D-004 (wall users misnomer) + D-024 (write as the per-user transport).
- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) D-8 (wall background; write extends).
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Sibling crate: [`selfdef-integration-wall`](../selfdef-integration-wall/) — broadcast TTY transport.
