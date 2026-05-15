# selfdef-integration-opensearch

OpenSearch / Elasticsearch document-index channel. SDD-008 Q-G.

## What this crate is

Implements [`selfdef_notifier_orchestrator::Channel`] (and the legacy `Notifier` ABI) against an OpenSearch or Elasticsearch cluster. Each event becomes one HTTPS POST to `<endpoint>/<index>/_doc` with a flat JSON document:

```json
{
  "@timestamp":  "2026-05-15T12:00:00Z",
  "service":     "selfdef",
  "host":        "<source>",
  "severity":    "high",
  "kind":        "Detection Finding",
  "title":       "<rendered title>",
  "body":        "<rendered body>",
  "event_id":    "<uuid>",
  "payload_id":  "<uuid, engine path only>"
}
```

**Three auth modes** (chosen by `auth_kind`):

| `auth_kind` | Sends | Required |
|---|---|---|
| `none` | no `Authorization` header | endpoint, index |
| `basic` | `Authorization: Basic <b64(user:pass)>` | endpoint, index, username, auth_token_file |
| `apikey` | `Authorization: ApiKey <key>` (Elastic Cloud) | endpoint, index, auth_token_file |

Unknown `auth_kind` strings are **rejected at startup** so operators see the misconfig.

**HTTPS-only invariant**: rejects plain `http://` at startup. **`index` is required** when `endpoint` is set — mistyping silently misroutes documents on a real cluster, so v1 demands the operator name it explicitly.

## Operator setup

See [`docs/operator/channels.md#opensearch`](../../docs/operator/channels.md#opensearch) for the operator-facing configuration guide.

Example block: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — search for `[notifier.opensearch]`.

## Crate layout

- `src/lib.rs` — `OpenSearchNotifier` struct + both trait impls + auth-kind parser (rejects unknowns) + document builder.
- `Cargo.toml` — `reqwest`, `serde_json`, `chrono` (RFC 3339), `selfdef-core`, `selfdef-notifier`, `selfdef-notifier-orchestrator`.

## Test locally

```sh
cargo test -p selfdef-integration-opensearch
```

Tests cover: each of the three auth modes, unknown-auth_kind rejection, HTTPS-only guard, document-shape parity, missing-index rejection.

## See also

- SDD: [`docs/sdd/008-notifications-orchestration.md`](../../docs/sdd/008-notifications-orchestration.md) Q-G.
- Architecture: [`ARCHITECTURE.md`](../../ARCHITECTURE.md).
- Contributor template: [`docs/dev/integrations.md`](../../docs/dev/integrations.md).
