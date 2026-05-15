# selfdef-integration-ntfy

Self-hosted ntfy push channel for selfdef. SDD-008 D-2b.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI for M4 callers) against an [ntfy](https://docs.ntfy.sh/) HTTP server. Each event becomes one HTTP POST to `<url>/<topic>` with up-to-3 attempts and ~200ms..800ms exponential backoff. Optional bearer-token auth.

## Operator setup

See [`docs/operator/channels.md#ntfy`](../../docs/operator/channels.md#ntfy) for the operator-facing configuration guide (TOML block, secret hygiene, when to use this channel vs the other 11).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.ntfy]`.

## Crate layout

- `src/lib.rs` — `NtfyNotifier` struct + both trait impls.
- `Cargo.toml` — `reqwest` (HTTPS POST), `selfdef-core` (event types), `selfdef-notifier` (legacy ABI), `selfdef-notifier-orchestrator` (`Channel` trait).

## Test locally

```sh
cargo test -p selfdef-integration-ntfy
```

Tests use `wiremock` to stand up a fake ntfy server — no network calls leave the test process.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) D-2b.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md) — Integrations layer.
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
