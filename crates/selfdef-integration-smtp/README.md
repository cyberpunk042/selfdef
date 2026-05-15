# selfdef-integration-smtp

SMTP outbound (email) channel. SDD-008 D-7 Q-E.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against any operator-controlled SMTP relay. Uses [`lettre`](https://crates.io/crates/lettre) for the SMTP protocol. Each event becomes one email per `Payload` / `Event`.

**TLS profiles** (selected by `[notifier.smtp].tls`):

- `starttls` (default) — connect on the configured port (usually 587), upgrade with STARTTLS, then PLAIN auth.
- `implicit_tls` — TLS from the first byte (port 465), then PLAIN auth.
- `plain` — no TLS. **Refuses any auth-bearing send at construction time** — selfdef will not transmit credentials in cleartext.

## Operator setup

See [`docs/operator/channels.md#smtp`](../../docs/operator/channels.md#smtp) for the operator-facing configuration guide (TLS profile choice, file mode hygiene for the password, no-DKIM / no-HTML limitations).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.smtp]`.

## Crate layout

- `src/lib.rs` — `SmtpNotifier` struct + both trait impls + TLS-profile selection logic.
- `Cargo.toml` — `lettre` (SMTP), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-smtp
```

Tests use `lettre`'s `StubTransport` (in-memory) — no real SMTP relay needed. TLS-profile-rejection-on-plain-with-auth is also covered.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) D-7 Q-E.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
