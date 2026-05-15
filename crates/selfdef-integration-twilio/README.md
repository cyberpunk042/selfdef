# selfdef-integration-twilio

Twilio SMS channel. SDD-008 Q-D.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against [Twilio's REST API](https://www.twilio.com/docs/sms/api). Each event becomes one HTTPS POST to:

```
https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json
```

with HTTP Basic (`AccountSid` : `auth_token`) and a form-encoded body `From=<number>&To=<recipient>&Body=<text>`.

**Multi-recipient behavior**: looped sequentially; **any-success wins** — at least one delivery succeeding returns `Ok`. Failures for the other recipients are warn-logged. Bodies are soft-capped at 1500 chars to stay under Twilio's 1600-char concatenation limit.

## Operator setup

See [`docs/operator/channels.md#twilio`](../../docs/operator/channels.md#twilio) for the operator-facing configuration guide (account SID, auth token file hygiene, E.164 number format, send-only v1 limitation).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.twilio]`.

## Crate layout

- `src/lib.rs` — `TwilioNotifier` struct + both trait impls + per-recipient retry helper.
- `Cargo.toml` — `reqwest`, `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-twilio
```

Tests use `wiremock` to mock the Twilio API — body-shape, Basic-auth header, any-success-wins multi-recipient semantics are all covered.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-D.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
