# selfdef-integration-signal

Signal IM channel via `signal-cli`. SDD-008 D-2c.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) by spawning [`signal-cli`](https://github.com/AsamK/signal-cli) as a subprocess per event:

```
signal-cli -a <account> send -m <message> <recipient>
```

Operator-controlled — `signal-cli`'s own account state on disk (typically `~/.local/share/signal-cli/`) holds the Signal registration; selfdef holds no credentials directly.

## Operator setup

See [`docs/operator/channels.md#signal`](../../docs/operator/channels.md#signal) for the operator-facing configuration guide (`signal-cli` registration, TOML block, single-recipient v1 limit).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.signal]`.

## Crate layout

- `src/lib.rs` — `SignalCliNotifier` struct + both trait impls.
- `Cargo.toml` — `tokio` (subprocess), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-signal
```

Tests stub `signal-cli` via a small shell-script harness; no real Signal account required.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) D-2c.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
