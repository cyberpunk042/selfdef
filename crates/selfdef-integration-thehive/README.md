# selfdef-integration-thehive

TheHive incident-management alert channel. SDD-008 Q-G.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against [TheHive's alert API](https://docs.strangebee.com/thehive/api-docs/). Each event becomes one HTTPS POST to `<endpoint>/api/v1/alert`:

```json
{
  "type":        "selfdef",
  "source":      "<host>",
  "sourceRef":   "<event_id>",
  "title":       "<title>",
  "description": "<body>",
  "severity":    2,
  "tlp":         2,
  "tags":        ["selfdef", "selfdef:high", "kind:Detection Finding"]
}
```

**Severity collapse** (OCSF 6 → TheHive 4):

| OCSF | TheHive `severity` |
| --- | --- |
| Informational, Low | `1` (Low) |
| Medium | `2` (Medium) |
| High | `3` (High) |
| Critical, Fatal | `4` (Critical) |

**`tlp = 2` (Amber — SOC-internal)** by default — matches the operator-controlled, single-team posture selfdef typically ships into.

**HTTPS-only invariant**: rejects plain `http://` at startup.

## Operator setup

See [`docs/operator/channels.md#thehive`](../../docs/operator/channels.md#thehive) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.thehive]`.

## Crate layout

- `src/lib.rs` — `TheHiveNotifier` struct + both trait impls + `map_severity` (OCSF → 1-4) + tag composer.
- `Cargo.toml` — `reqwest`, `serde_json`, `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-thehive
```

Tests cover: severity-map collapse, tag composition, TLP default, HTTPS-only guard, alert envelope shape.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-G.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
