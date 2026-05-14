# Integration crate template (SDD-008 D-1)

## Source of truth

- Architectural rule: [`ARCHITECTURE.md` § Integrations layer](../../ARCHITECTURE.md).
- Charter: [`docs/sdd/008-notifications-orchestration.md`](../sdd/008-notifications-orchestration.md).
- Trait crate: `crates/selfdef-notifier-orchestrator/` (SDD-008 D-2 — pending).
- Current channels still in `crates/selfdef-notifier/`; they will graduate
  into `crates/selfdef-integration-{ntfy,signal}` under D-2.

## TL;DR

Selfdef has two structurally distinct extension shapes. **Modules**
install things on the host and own service lifecycle. **Integrations**
are pure adapters that emit a typed payload to one external service.
This runbook is the contributor-facing template for adding a new
integration crate.

The rule that decides whether your work is a module or an integration:

> Can your code be deleted from the workspace without breaking the
> host? If yes → integration. If no → module.

If you find yourself writing `apt install`, `systemctl enable`,
`mkdir /etc/...`, `chown`, `setcap`, an nftables rule, or a kernel
module probe inside your new crate, **stop**: that work belongs in
`modules/<your-name>/install/apply.sh`, not in
`crates/selfdef-integration-<your-name>/`.

## Caller contract

An integration crate exposes exactly one public type implementing the
orchestrator's channel trait (SDD-008 D-2 will define the canonical
trait; until then, mirror the shape used by `NtfyNotifier` and
`SignalCliNotifier` in `crates/selfdef-notifier/src/lib.rs`):

```rust
#[async_trait::async_trait]
pub trait Channel: Send + Sync {
    fn name(&self) -> &str;
    async fn send(&self, payload: &Payload) -> Result<DeliveryReceipt, ChannelError>;
    fn supports_ack_reply(&self) -> bool { false }
    fn ack_reply_format(&self) -> Option<AckReplyHint> { None }
}
```

Required behaviours:

1. **Stateless or lightly stateful.** If you need persistent state
   beyond a session-scoped cache (e.g. last successful send
   timestamp), that state goes through the orchestrator's SQLite
   layer, not into a sidecar file your crate owns.
2. **Bounded outbound calls.** Set per-call timeouts on the
   underlying transport (`reqwest::Client::builder().timeout(...)`,
   `tokio::process::Command` with `tokio::time::timeout`). A hung
   external service must not block the orchestrator's task wheel.
3. **No host mutation.** No writes outside the orchestrator-supplied
   credentials path. No setting environment variables, no spawning
   long-lived background processes that survive the crate's
   `Drop`.
4. **Credentials from disk only.** API keys, bearer tokens,
   per-channel auth come from a config-supplied path with a mode
   check that mirrors `crates/selfdef-api/src/transport.rs::load_token`
   (refuse `mode & 0o077 != 0`). Never read credentials from
   environment variables in production code.
5. **Idempotent re-sends.** If the orchestrator retries `send()` for
   the same `Payload::id`, the integration must not double-deliver.
   For channels with native dedup (Slack/Discord interactive
   tokens), use the channel's mechanism. For channels without
   (ntfy, SMTP), embed the `Payload::id` in a header or message-id
   field so the receiving side can dedup.

## Cargo manifest template

```toml
# crates/selfdef-integration-<service>/Cargo.toml
[package]
name        = "selfdef-integration-<service>"
version     = "0.1.0"
edition     = "2021"
license     = "AGPL-3.0-or-later"
description = "<one-line description of which external service this adapts to>"
publish     = false

[lib]
name = "selfdef_integration_<service>"
path = "src/lib.rs"

[dependencies]
selfdef-core                  = { path = "../selfdef-core" }
selfdef-notifier-orchestrator = { path = "../selfdef-notifier-orchestrator" }
async-trait                   = { workspace = true }
tokio                         = { workspace = true, features = ["macros", "time"] }
thiserror                     = { workspace = true }

# choose ONE outbound transport based on the channel kind:
reqwest                       = { workspace = true, features = ["json", "rustls-tls"] }  # for HTTP-based services
# lettre                      = { workspace = true, features = ["smtp-transport", "tokio1-rustls-tls"] }  # for SMTP
# (subprocess channels use tokio::process::Command from the tokio dep above)

[dev-dependencies]
selfdef-core                  = { path = "../selfdef-core", features = ["test-helpers"] }
wiremock                      = { workspace = true }   # for HTTP channels
tempfile                      = { workspace = true }
tokio                         = { workspace = true, features = ["test-util", "macros"] }
```

What MUST be absent from the manifest:

- `selfdef-daemon` — no integration depends on the daemon
- `selfdef-config` — config injection comes through the channel
  constructor, not through reading TOML inside the integration
- `selfdef-store` — no direct DB access; the orchestrator owns
  persistence
- anything under `modules/` — modules live in a separate world

## Reference content — minimum viable integration

The minimum viable integration is one struct + one `Channel` impl
+ one constructor + one test. Skeleton:

```rust
// crates/selfdef-integration-<service>/src/lib.rs
//! <Service> outbound channel for the selfdef notifier orchestrator.
//!
//! See `docs/sdd/008-notifications-orchestration.md` for the
//! taxonomy + acknowledgement model. This crate is a pure adapter:
//! it takes a `Payload` and emits it to <service>. It owns no
//! escalation logic, no subscription filtering, no persistence —
//! those are the orchestrator's job.

use async_trait::async_trait;
use selfdef_notifier_orchestrator::{
    Channel, ChannelError, DeliveryReceipt, Payload,
};

#[derive(Clone, Debug)]
pub struct <Service>Channel {
    endpoint:  reqwest::Url,
    client:    reqwest::Client,
    api_key:   secrecy::SecretString,
}

impl <Service>Channel {
    pub fn new(
        endpoint: reqwest::Url,
        api_key:  secrecy::SecretString,
    ) -> Result<Self, ChannelError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(ChannelError::transport)?;
        Ok(Self { endpoint, client, api_key })
    }
}

#[async_trait]
impl Channel for <Service>Channel {
    fn name(&self) -> &str { "<service>" }

    async fn send(
        &self,
        payload: &Payload,
    ) -> Result<DeliveryReceipt, ChannelError> {
        let body = render_body(payload);
        let resp = self.client
            .post(self.endpoint.clone())
            .bearer_auth(self.api_key.expose_secret())
            .header("X-Selfdef-Event-Id", payload.id.as_str())
            .body(body)
            .send()
            .await
            .map_err(ChannelError::transport)?;
        if !resp.status().is_success() {
            return Err(ChannelError::remote(resp.status().as_u16(), resp.text().await.unwrap_or_default()));
        }
        Ok(DeliveryReceipt::native(resp.text().await.unwrap_or_default()))
    }
}
```

## Extension recipe — adding a new integration

1. **Confirm it's actually an integration.** Walk through the
   "Can your code be deleted without breaking the host?" test. If
   you need an `install/apply.sh`, you're writing a module.

2. **Pick the service slug.** Lowercase, ASCII, no underscores
   (use hyphens). The crate becomes
   `crates/selfdef-integration-<slug>`; the library identifier
   becomes `selfdef_integration_<slug_with_underscores>`. Match
   the slug the external service uses for itself (`ntfy`, not
   `ntfy-sh`; `signal`, not `signal-cli`; `smtp`, not `email`).

3. **Copy the manifest template** above. Trim transport deps to
   exactly one; trim feature flags to the minimum.

4. **Register the crate in the workspace.** Add the path to the
   `[workspace] members` list in the root `Cargo.toml`. Run
   `cargo metadata` locally to confirm the workspace builds.

5. **Implement the channel trait.** Keep `send()` under 100 LOC;
   anything above that probably belongs in a helper module or
   indicates the integration is doing too much.

6. **Add the per-call timeout.** Every outbound transport gets a
   timeout, no exceptions.

7. **Add credential mode-check.** If the service uses a token /
   key / password file, mirror the daemon's token-file refusal
   pattern (`mode & 0o077 != 0` → error).

8. **Add `[notifications.channels.<slug>]` section to
   `STARTER_CONFIG`** in `crates/selfdef-config` so operators see
   it commented at defaults when they `selfdefctl init config`.

9. **Add a `SECURITY.md` entry** under § API surface naming
   what the integration sends, where credentials live, and what
   the trust assumption is (e.g. "the SMTP server is trusted to
   not log message bodies").

10. **Tests** — one happy-path test using `wiremock` (HTTP) or a
    process stub (subprocess). One auth-failure test. One
    timeout test using `#[tokio::test(start_paused = true)]` +
    `tokio::time::advance` per SDD-005.

## Tests

The integration test for any new channel lands in
`crates/selfdef-integration-<slug>/tests/<slug>_channel.rs`. It
must cover:

- Happy path: `send()` succeeds → returns `DeliveryReceipt::native`.
- Auth failure: 401/403 → `ChannelError::remote(401, …)`, no panic.
- Transport timeout: external service hangs → `ChannelError::transport`
  fired within the per-call timeout, not whatever the OS default is.
- Idempotency: two `send()` calls with the same `Payload::id` are
  observable as deduplicated on the receiving side (or, for
  channels without server-side dedup, the request carries the
  `X-Selfdef-Event-Id` header / message-id field that lets a
  human dedup downstream).

Look at `crates/selfdef-notifier/tests/` (current location of
`NtfyNotifier` and `SignalCliNotifier` integration tests) for the
existing shape; the new tests inherit that pattern but live in
the per-integration crate.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Workspace fails to build with "duplicate trait impl" | The orchestrator trait is declared in two places. Only `selfdef-notifier-orchestrator` should define it; the integration crate uses it. |
| `clippy::module_inception` warns on the integration | The lib.rs is doing too much; split per-resource helpers into private submodules. |
| Tests pass locally but flake in CI on timing | A `tokio::time::sleep` slipped in without `start_paused = true`. SDD-005 forbids it; convert the test to virtual time. |
| Credentials end up in a panic message | The integration is using `Debug` on the secret type. Wrap in `secrecy::SecretString` so `Debug` redacts. |
| `cargo deny` complains about a new dep | Justify in the PR description; if the dep is correct, add it to `deny.toml` with a one-line rationale. |

## Threat model / what this doesn't fix

The taxonomy boundary prevents integration crates from *accidentally*
becoming installers. It does not by itself defend against:

- **A malicious dependency** in an integration's transport crate.
  Mitigation: `cargo-deny` enforces the workspace's advisory and
  license lists. Add new transport crates only after `cargo audit`
  clean.
- **Credential exfiltration by the external service.** Once an
  API key reaches Twilio / SendGrid / Slack, they have it. Treat
  every integration's credentials as having the trust posture of
  the external service. Document this in `SECURITY.md`'s §
  Trust assumptions when you add a new integration.
- **Integration crate becoming bloated.** Code review enforces
  the "no install scripts, no host mutation" rule; cargo doesn't
  catch it automatically. If a reviewer sees `std::fs::write`
  outside a tempdir in an integration crate, push back.

## Env overrides

Integration crates SHOULD honour the following env-var overrides
for test isolation (mirrors the test-contract.md pattern):

- `SELFDEF_INTEGRATION_<SLUG>_ENDPOINT` — override the outbound
  endpoint URL, for hitting a `wiremock` instance in tests.
- `SELFDEF_INTEGRATION_<SLUG>_TIMEOUT_MS` — override the per-call
  timeout, for forcing timeouts in tests without sleeping for the
  full default.

Production code MUST NOT read these envs; the channel constructor
takes the endpoint and timeout as typed arguments. The envs are
read only by the test harness, which then passes the values into
the constructor explicitly.
