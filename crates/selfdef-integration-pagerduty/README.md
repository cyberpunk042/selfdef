# selfdef-integration-pagerduty

PagerDuty Events API v2 channel. SDD-008 Q-G.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against [PagerDuty's Events API v2](https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event). Each event becomes one HTTPS POST to `https://events.pagerduty.com/v2/enqueue` (or operator-overridden `endpoint`).

**Severity collapse** (OCSF 6 → PagerDuty 4):

| OCSF | PagerDuty |
| --- | --- |
| Informational, Low | `info` |
| Medium | `warning` |
| High | `error` |
| Critical, Fatal | `critical` |

**Dedup key**:

- **Legacy chain path**: uses the OCSF event id → re-fires of the same event deduplicate on PD's side.
- **Engine path**: uses the per-rung `PayloadId` → one PD incident per rung. This is by design — SDD-008 wants unacked alerts to "page louder."

## Operator setup

See [`docs/operator/channels.md#pagerduty`](../../docs/operator/channels.md#pagerduty) for the operator-facing configuration guide (creating the Events API v2 integration, routing key hygiene, EU-endpoint override).

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.pagerduty]`.

## Crate layout

- `src/lib.rs` — `PagerDutyNotifier` struct + both trait impls + `map_severity` (OCSF → PD) + the dedup-key dual-strategy.
- `Cargo.toml` — `reqwest`, `serde_json`, `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-pagerduty
```

Tests cover: severity-map collapse (six → four), legacy-path vs engine-path dedup_key choice, routing-key secret elision in `Debug`, HTTPS-only endpoint guard.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-G.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
