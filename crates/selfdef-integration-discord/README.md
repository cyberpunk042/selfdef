# selfdef-integration-discord

Discord webhook channel. SDD-008.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against a [Discord webhook URL](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks). Each event becomes one HTTPS POST with `{"content": "...", "username": "...", "avatar_url": null}`. Same secret-as-URL hygiene as Slack.

**Wire-specific caveat**: Discord caps `content` at **2000 characters**. Bodies above that are truncated with a `…[truncated]` suffix before send.

## Operator setup

See [`docs/operator/channels.md#discord`](../../docs/operator/channels.md#discord) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.discord]`.

## Crate layout

- `src/lib.rs` — `DiscordNotifier` struct + both trait impls + the 2000-char truncation helper.
- `Cargo.toml` — `reqwest`, `serde_json`, `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-discord
```

Tests cover the truncation path (>2000-char body produces a trimmed, suffix-tagged content field) and the wiremock POST shape.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md).
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
