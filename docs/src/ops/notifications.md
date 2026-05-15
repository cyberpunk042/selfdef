# Notifications

selfdef ships **twelve notification channels** covering push, IM,
email, SMS, broadcast TTY, per-user TTY, paging, log shipping,
search index, and SOC/IR tooling. Every channel implements the
same `Channel` trait and is wired through the orchestrator's
escalation engine (SDD-008 D-5).

> **Canonical reference**: [`docs/operator/channels.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md)
> is the source of truth for per-channel TOML blocks, auth secret
> hygiene, wire-shape behavior, severity collapse tables, and
> limitations. Each `crates/selfdef-integration-<name>/README.md`
> mirrors a slice of the canonical reference for source-tree
> navigators. This mdbook page is the published landing — it
> summarises + delegates.

## At a glance

| Channel | Class | Auth secret | Network call? | Severity collapse | Ack-reply support (v1) |
|---|---|---|---|---|---|
| **ntfy**       | push          | optional bearer token         | yes (HTTP)            | none           | no (HTTP click-link) |
| **signal**     | IM            | account state on disk         | no (`signal-cli` subprocess) | none    | no (HTTP click-link) |
| **slack**      | IM            | webhook URL = secret          | yes (HTTPS)           | none           | no (HTTP click-link) |
| **discord**    | IM            | webhook URL = secret          | yes (HTTPS)           | none           | no (HTTP click-link) |
| **smtp**       | email         | username + password file      | yes (SMTP/STARTTLS)   | none           | no (HTTP click-link) |
| **twilio**     | SMS           | account SID + auth token file | yes (HTTPS Basic)     | none           | no (inbound webhook deferred) |
| **pagerduty**  | incident page | routing key file              | yes (HTTPS)           | OCSF 6 → PD 4  | no (PD UI ack deferred) |
| **loki**       | log shipping  | optional bearer token file    | yes (HTTPS, required) | none           | no (one-way push) |
| **opensearch** | search index  | basic password OR API key     | yes (HTTPS, required) | none           | no (one-way push) |
| **thehive**    | SOC / IR      | API key file                  | yes (HTTPS, required) | OCSF 6 → Hive 4 | no (Hive alert state deferred) |
| **wall**       | broadcast TTY | none (local subprocess)       | no (`wall(1)`)        | none           | no (one-way) |
| **write**      | per-user TTY  | none (local subprocess)       | no (`write(1)`)       | none           | no (one-way) |

selfdef **never writes secrets into `selfdef.toml`**. Every channel
that needs auth reads from a separate file referenced by a `*_file`
config key (mode `0600` recommended).

## Selecting active channels

```toml
[notifier]
# Ordered: first channel that succeeds wins. Channels not listed
# here are NOT used even if their [notifier.<channel>] block is
# configured. List every channel you want active.
channels = ["ntfy", "smtp", "pagerduty"]
```

A channel listed but missing required config is silently skipped at
startup with a `channel skipped — missing config` log line.

## Cross-cutting knobs

Five knobs live on `[notifier]` itself (not on a specific channel):

| Knob | Purpose | Default |
|---|---|---|
| `escalations_path` | SQLite file for the persistent escalation engine (SDD-008 D-5). When set, the daemon runs the wake-task escalation loop; events sit in the engine until acked / forgotten / max-rung. Unset = fire-and-forget M4 chain (no persistence). | unset |
| `mode` | `enforce` (default) or `audit` (engine records rows but `channel.send` is **not** called — verify wiring before going live). | `enforce` |
| `profile` | Named escalation cadence: `auto` (2 attempts, 5-min window), `aggressive` (3 attempts @ 60s/180s/600s), `patient` (4 @ 10/30/60/120min), or a custom key under `[notifier.profiles.<name>]`. | `auto` |
| `panic_floor` | Severity at or above which `audit` mode is bypassed and channels fire for real. Operator-misconfig escape hatch. | unset |
| `ack_link_base` | Base URL for the HTTP click-link ack endpoint. When set, every payload's body embeds `<base>/<uuidv7>`; operators click → daemon's `GET /notify/ack/:token` records the ack. | unset (CLI ack only) |

Per-channel subscription filters opt into filtered routing:

```toml
# Route only high+ findings to PagerDuty, everything to Loki.
[notifier.subscriptions.pagerduty]
severity_floor = "high"
event_kinds = ["security", "detection"]

[notifier.subscriptions.loki]
severity_floor = "informational"
```

Missing entry = accept every event. Both fields AND-compose.

## Operator triage

Once an escalation is in flight, four CLI verbs let the operator
intervene. All four require `[notifier].escalations_path` to be set;
they talk directly to the SQLite file (WAL mode handles concurrent
reads with the daemon).

| Verb | What it does | When to use it |
|---|---|---|
| `selfdefctl notify list` | Print pending escalations (`--limit N`, `--json`). | "What's in flight right now?" |
| `selfdefctl notify ack <event-id>` | Mark an escalation acknowledged; short-circuit further rungs. Idempotent. | You've seen the alert; stop the escalation. |
| `selfdefctl notify resend <event-id>` | Set `deadline_at = now` so the wake task fires the current rung's channels at its next poll (≤60s). Does **not** reset rung state. | Re-fire NOW without waiting for the natural ack window — testing a freshly-configured channel, or suspecting silent delivery failure. |
| `selfdefctl notify forget <event-id>` | DELETE the row entirely. Suppresses further rungs WITHOUT recording an ack — audit trail reflects "operator suppressed", not "operator saw". | False-positive cleanup. |

## Configuration quick links

For each channel: jump to the canonical operator reference for the
TOML block, secret hygiene, wire behavior, and limitations.

- **[ntfy](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#ntfy)** — self-hosted push via [ntfy.sh](https://docs.ntfy.sh/).
- **[signal](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#signal)** — Signal IM via [`signal-cli`](https://github.com/AsamK/signal-cli) subprocess.
- **[slack](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#slack)** — Slack incoming webhook.
- **[discord](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#discord)** — Discord webhook (2000-char cap with truncation).
- **[smtp](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#smtp)** — email via operator-controlled SMTP relay.
- **[twilio](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#twilio)** — Twilio SMS REST API (send-only, any-success-wins multi-recipient).
- **[pagerduty](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#pagerduty)** — PagerDuty Events API v2 (one incident per rung — unacked alerts page louder).
- **[loki](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#loki)** — Grafana Loki push-API (three auth modes: single-tenant / multi-tenant / Grafana Cloud).
- **[opensearch](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#opensearch)** — OpenSearch / Elasticsearch document index (three auth modes: none / basic / apikey; unknowns rejected at startup).
- **[thehive](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#thehive)** — TheHive alert API (TLP=Amber by default).
- **[wall](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#wall)** — broadcast `wall(1)` to every logged-in TTY.
- **[write](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md#write)** — per-user `write(1)` to an allowlist of operator accounts (D-024).

For a copy-paste-ready starter config covering all 12 channels +
the 5 cross-cutting knobs, see
[`config/selfdef.toml.example`](https://github.com/cyberpunk042/selfdef/blob/main/config/selfdef.toml.example).

## Rotating credentials

Notifier credentials are loaded **once** at daemon startup
(`SECURITY.md:75-78`). Editing the token / password / API-key file
does not take effect until the daemon restarts. This is
intentional: mid-flight rotation is a deliberate operator action,
not a side effect of editing a file.

Rotate with:

```bash
sudo -e /etc/selfdef/secrets/ntfy.token        # (or whichever channel's secret)
sudo systemctl restart selfdefd
```

The same pattern applies for every channel that reads a `*_file`
key. PagerDuty's `routing_key_file`, SMTP's `password_file`,
Twilio's `auth_token_file`, Slack/Discord webhook URL files,
TheHive `api_key_file`, Loki/OpenSearch `auth_token_file` — all
loaded-once-at-startup.

## Testing without firing real channels

```toml
[responder]
# In dry-run, the responder logs what it would do without
# actually invoking actions.
dry_run = true
allowed_actions = ["notify"]

[notifier]
mode = "audit"              # engine records rows but doesn't call channel.send
```

Either knob suppresses channel firing; combining them is belt-and-
braces. Trigger a synthetic finding via `selfdefctl events emit`
or replay a detection corpus through the daemon.

To verify a channel's wire shape without firing for real, point the
channel at a `wiremock`-style fake endpoint that captures the POST
shape for one test cycle, then revert.

## See also

- **Per-channel canonical reference** ([`docs/operator/channels.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/operator/channels.md)) — TOML blocks, secret hygiene, wire shape, limitations for each of the 12 channels.
- **Example config** ([`config/selfdef.toml.example`](https://github.com/cyberpunk042/selfdef/blob/main/config/selfdef.toml.example)) — copy-paste-ready blocks for every channel + the 5 `[notifier]` knobs.
- **Orchestration design** ([`docs/sdd/008-notifications-orchestration.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/sdd/008-notifications-orchestration.md)) — SDD-008 defines `Channel`, the escalation engine, profiles, subscriptions, and ack flows.
- **Architecture** ([`ARCHITECTURE.md`](https://github.com/cyberpunk042/selfdef/blob/main/ARCHITECTURE.md)) — where the integration layer sits relative to bus, store, correlator, responder, notifier-orchestrator.
- **Contributor template** ([`docs/dev/integrations.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/dev/integrations.md)) — adding a 13th channel.
- **Decisions log** ([`docs/decisions.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/decisions.md)) — D-NNN entries pinning operator-stated choices (D-004 / D-024 wall vs write, etc.).
