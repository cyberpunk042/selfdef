# selfdef-integration-loki

Grafana Loki push-API channel. SDD-008 Q-G.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against [Loki's push API](https://grafana.com/docs/loki/latest/reference/loki-http-api/#ingest-logs). Each event becomes one HTTPS POST to the configured `endpoint` (typically `/loki/api/v1/push`) with the standard Loki streams envelope:

```json
{
  "streams": [
    {
      "stream": { "service": "selfdef", "severity": "...", "host": "...", "kind": "..." },
      "values": [ ["<unix_ns>", "<title — body>"] ]
    }
  ]
}
```

**Three auth modes** (decided by which fields are set):

- **Single-tenant self-hosted**: leave `tenant_id` empty, no `auth_token_file`. No headers added.
- **Multi-tenant self-hosted**: set `tenant_id` → sent as `X-Scope-OrgID`.
- **Grafana Cloud**: set both `tenant_id` (your stack id) and `auth_token_file` → sent as `Authorization: Bearer <token>`.

**HTTPS-only invariant**: rejects plain `http://` at startup — selfdef will not ship bearer tokens over plaintext. Newlines in body get collapsed to `·` to preserve Loki's line-oriented log model.

## Operator setup

See [`docs/operator/channels.md#loki`](../../docs/operator/channels.md#loki) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.loki]`.

## Crate layout

- `src/lib.rs` — `LokiNotifier` struct + both trait impls + the three-mode auth selection + newline-collapse helper.
- `Cargo.toml` — `reqwest`, `serde_json`, `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-loki
```

Tests cover: each of the three auth modes, HTTPS-only guard rejection of `http://`, newline-to-`·` body rendering, payload envelope shape.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-G.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
