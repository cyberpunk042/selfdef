# selfdef-integration-slack

Slack incoming-webhook channel. SDD-008 Q-C.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against a [Slack incoming webhook URL](https://api.slack.com/messaging/webhooks). Each event becomes one HTTPS POST with `{"text": "...", "username": "...", "icon_emoji": "..."}`. The webhook URL itself is the auth secret — stored in a file at mode `0600` and read once at daemon start.

## Operator setup

See [`docs/operator/channels.md#slack`](../../docs/operator/channels.md#slack) for the operator-facing configuration guide (creating the webhook in Slack, file mode hygiene, why one webhook = one channel).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.slack]`.

## Crate layout

- `src/lib.rs` — `SlackNotifier` struct + both trait impls.
- `Cargo.toml` — `reqwest` (HTTPS POST), `serde_json` (body shape), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-slack
```

Tests use `wiremock` to stand up a fake Slack webhook receiver.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-C.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
