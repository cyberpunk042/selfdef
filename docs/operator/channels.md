# selfdef notification channels — operator reference

> **Audience**: operators configuring selfdef's notifier on a host.
> **Source of truth**: `crates/selfdef-config/src/lib.rs` (typed config structs with rustdoc per field) and the per-channel `crates/selfdef-integration-<name>/src/lib.rs`. This page is the consolidated operator-facing view of that surface.

selfdef ships **twelve notification channels**. Every channel implements the same `Channel` trait ([`selfdef-notifier-orchestrator`]) and is reachable via `[notifier.<channel>]` in `/etc/selfdef/selfdef.toml`. This page documents each: when to use it, exact configuration, secret hygiene, behavior on the wire, and limitations.

[`selfdef-notifier-orchestrator`]: ../../crates/selfdef-notifier-orchestrator/src/lib.rs

## At a glance

| Channel | Class | Auth secret | Network call? | Severity collapse | Ack-reply support (v1) |
|---|---|---|---|---|---|
| [`ntfy`](#ntfy)             | push          | optional bearer token         | yes (HTTP)            | none                   | no (HTTP click-link via D-4) |
| [`signal`](#signal)         | IM            | account state on disk         | no (`signal-cli` subprocess) | none                   | no (HTTP click-link) |
| [`slack`](#slack)           | IM            | webhook URL = secret          | yes (HTTPS)           | none                   | no (HTTP click-link) |
| [`discord`](#discord)       | IM            | webhook URL = secret          | yes (HTTPS)           | none                   | no (HTTP click-link) |
| [`smtp`](#smtp)             | email         | username + password file      | yes (SMTP/STARTTLS)   | none                   | no (HTTP click-link) |
| [`twilio`](#twilio)         | SMS           | account SID + auth token file | yes (HTTPS, Basic)    | none                   | no (HTTP click-link; inbound webhook deferred) |
| [`pagerduty`](#pagerduty)   | incident page | routing key file              | yes (HTTPS)           | OCSF 6 → PD 4          | no (PD UI ack deferred) |
| [`loki`](#loki)             | log shipping  | optional bearer token file    | yes (HTTPS, must)     | none                   | no (one-way push) |
| [`opensearch`](#opensearch) | search index  | basic password OR API key file | yes (HTTPS, must)    | none                   | no (one-way push) |
| [`thehive`](#thehive)       | SOC / IR      | API key file                  | yes (HTTPS, must)     | OCSF 6 → Hive 4        | no (Hive alert state deferred) |
| [`wall`](#wall)             | broadcast TTY | none (local subprocess)       | no (`wall(1)`)        | none                   | no (one-way) |
| [`write`](#write)           | per-user TTY  | none (local subprocess)       | no (`write(1)`)       | none                   | no (one-way) |

**Reading the table**:

- **"Ack-reply support"** = whether the channel itself can deliver an operator acknowledgement back to the daemon. All twelve return `false` in v1 by design — ack always flows through either the HTTP click-link (`GET /notify/ack/:token`, SDD-008 D-4 HTTP) or `selfdefctl notify {ack,resend,forget}`. Channel-native ack flows (Slack interactive buttons, PagerDuty `acknowledge` events, Twilio reply SMS, Signal JSONRPC replies) are deferred to future SDDs.
- **"Severity collapse"** = whether the upstream's severity scale is narrower than OCSF's six levels (`Informational | Low | Medium | High | Critical | Fatal`). PagerDuty and TheHive collapse; everything else passes severity through as a label.
- **"Auth secret"** lists the artifact the operator must keep at mode `0600`. **selfdef never writes secrets into `selfdef.toml`**; every channel that needs auth reads it from a separate file referenced by `*_file` config key.

## Common configuration

Every channel sits under `[notifier.<channel>]`. The daemon builds a channel **only when** that channel's `*_file` secret (if any) is readable and the channel-disabling sentinel (empty `endpoint` / empty `binary` / empty `account_sid` / etc.) is not set. **An unset channel is silently skipped** — selfdef refuses to startup-crash on a missing optional channel.

```toml
[notifier]
# Order matters: first channel that successfully delivers wins.
# Channels not listed here are NOT used even if their [notifier.<channel>]
# block is configured. List every channel you want active.
channels = ["ntfy", "smtp", "pagerduty"]
```

### Cross-cutting knobs

These five knobs live on `[notifier]` itself, not on a specific channel.

| Knob | Purpose | Default |
|---|---|---|
| `escalations_path` | SQLite file for the persistent escalation engine (SDD-008 D-5a/b/c). When set, the daemon opens this file and runs the wake-task escalation loop; events sit in the engine until acked / forgotten / max-rung. **Unset** = fire-and-forget M4 chain. | unset |
| `mode` | `enforce` (default — channels actually fire) or `audit` (engine records rows but `channel.send` is NOT called; useful for verifying wiring before going live). | `enforce` |
| `profile` | Named escalation cadence: `auto` (2 attempts, 5-min ack window), `aggressive` (3 attempts @ 60s/180s/600s), `patient` (4 attempts @ 10/30/60/120min), or any key under `[notifier.profiles.<name>]`. | `auto` |
| `panic_floor` | Severity at or above which `audit` mode is bypassed and channels fire for real. Operator misconfiguration escape hatch. | unset (no floor) |
| `ack_link_base` | Base URL for the HTTP click-link ack. When set, every outbound payload's body includes `<base>/<uuidv7>`; operators click → daemon's `GET /notify/ack/:token` records the ack. | unset (CLI ack only) |

### Per-channel subscription filters

Each channel can opt into filtered routing via `[notifier.subscriptions.<channel>]`:

```toml
# Route only high+ findings to PagerDuty, everything to Loki.
[notifier.subscriptions.pagerduty]
severity_floor = "high"
event_kinds = ["security", "detection"]

[notifier.subscriptions.loki]
severity_floor = "informational"
```

Missing entry = accept every event. Both `severity_floor` and `event_kinds` must match for the channel to fire (AND semantics).

## Operator triage

| Verb | What it does | When to use it |
|---|---|---|
| `selfdefctl notify list` | Print pending escalations (`--limit N`, `--json`). | "What's in flight right now?" |
| `selfdefctl notify ack <event-id>` | Mark an in-flight escalation acknowledged; short-circuits further rungs. Idempotent. | You've seen the alert; stop the escalation. |
| `selfdefctl notify resend <event-id>` | Pull the next wake-task action forward to "right now" by setting `deadline_at = now`. The wake task fires the current rung's channels at the next poll (≤60s). Does NOT reset rung state. | You want to re-fire NOW without waiting for the natural ack window. |
| `selfdefctl notify forget <event-id>` | DELETE the row entirely. Suppresses further rungs WITHOUT recording an ack — used when the alert was a false positive and the audit trail should reflect "operator suppressed", not "operator saw". | False-positive cleanup. |

All four require `[notifier].escalations_path` to be set. They talk directly to the SQLite file; WAL mode handles concurrent daemon reads.

---

## Channels

### ntfy

**Crate**: [`crates/selfdef-integration-ntfy`](../../crates/selfdef-integration-ntfy/) · **SDD**: SDD-008 D-2b · **PR**: #112

Self-hosted push notifications via [ntfy.sh](https://docs.ntfy.sh/). Best fit when you want phone push without an external SaaS dependency — point at your own `ntfy` server.

```toml
[notifier.ntfy]
url        = "https://ntfy.example.org"          # bare host or full URL; both work.
topic      = "selfdef-alerts"                    # any string; subscribers join on this topic.
token_file = "/etc/selfdef/secrets/ntfy.token"   # optional; mode 0600. Empty = unauthenticated.
```

**Auth**: bearer token, read once at daemon start from `token_file`. Empty / unset → unauthenticated POST (works on private servers behind a network ACL).

**Behavior**: HTTP POST to `<url>/<topic>` with up-to-3 attempts and ~200ms..800ms exponential backoff. Severity is rendered as a prefix emoji in the title.

**Limitations**: Action buttons (native ack from the ntfy app) are deferred; v1 acks via the HTTP click-link in the body.

### signal

**Crate**: [`crates/selfdef-integration-signal`](../../crates/selfdef-integration-signal/) · **SDD**: SDD-008 D-2c · **PR**: #113

Signal IM via [`signal-cli`](https://github.com/AsamK/signal-cli) — the operator-controlled CLI binary, not the Signal cloud API. Best fit when you have one operator with a phone and want notifications in the same E2EE app they already use.

```toml
[notifier.signal]
binary    = "/usr/bin/signal-cli"
account   = "+15551234567"            # the signal-cli registered number.
recipient = "+15559876543"            # who receives notifications.
```

**Auth**: none in selfdef's config — `signal-cli`'s own account state on disk (typically `~/.local/share/signal-cli/`) holds the registration. Run `signal-cli --account <number> register` interactively to set up.

**Behavior**: spawns `signal-cli -a <account> send -m <body> <recipient>` per event. No retry — operator-controlled subprocess, log on failure.

**Limitations**: Single recipient (v1). No reply-ack (would require running `signal-cli` in `--dbus` daemon mode and parsing JSONRPC replies; deferred). One subprocess per event — not high-throughput.

### slack

**Crate**: [`crates/selfdef-integration-slack`](../../crates/selfdef-integration-slack/) · **SDD**: SDD-008 Q-C · **PR**: ~#114

Slack incoming webhook. Best fit for shared on-call channels in a team Slack workspace.

```toml
[notifier.slack]
webhook_url_file = "/etc/selfdef/secrets/slack.webhook"  # mode 0600 — the URL IS the auth.
username         = "selfdef"
icon_emoji       = ":shield:"
```

**Auth**: the webhook URL itself is the secret. Store it in a file at mode `0600`; anyone who can read the file can post to the channel. selfdef will refuse to wire the channel if the file is missing or unreadable. To create the URL: Slack workspace → Apps → Incoming Webhooks → Add to Slack → bind to a channel → copy the URL → write to `webhook_url_file`.

**Behavior**: HTTPS POST to the webhook URL with `{"text": "...", "username": "...", "icon_emoji": "..."}`. Severity prefix emoji.

**Limitations**: No Slack Blocks UI (rich layout) — v1 ships plain text. No interactive components — ack via HTTP click-link. The webhook is bound to one channel at create time on slack.com; for multi-channel routing, create one webhook per channel and configure them as separate selfdef channels (Slack supports only one webhook per `[notifier.slack]` block in v1).

### discord

**Crate**: [`crates/selfdef-integration-discord`](../../crates/selfdef-integration-discord/) · **SDD**: SDD-008 · **PR**: ~#116

Discord webhook. Same shape as Slack with Discord's wire format.

```toml
[notifier.discord]
webhook_url_file = "/etc/selfdef/secrets/discord.webhook"  # mode 0600.
username         = "selfdef"
```

**Auth**: webhook URL = the secret. Same hygiene as Slack. Create via Discord server → Integrations → Webhooks → New Webhook → bind to a channel → copy URL.

**Behavior**: HTTPS POST with `{"content": "...", "username": "..."}`.

**Limitations**: Discord's `content` field is hard-capped at **2000 characters** — bodies above that get truncated with a `…[truncated]` suffix before send. No interaction components in v1 (Discord supports button-callbacks but they need a daemon-side endpoint; deferred).

### smtp

**Crate**: [`crates/selfdef-integration-smtp`](../../crates/selfdef-integration-smtp/) · **SDD**: SDD-008 D-7 Q-E · **PR**: ~#127

Email via operator-controlled SMTP relay. Best fit when you want notifications in the same inbox you already check, or when downstream tooling (ticket systems, SIEM ingest) speaks SMTP cleanly.

```toml
[notifier.smtp]
relay_host    = "smtp.example.org"
relay_port    = 587                                       # 587 STARTTLS · 465 implicit · 25 plain (testing only)
tls           = "starttls"                                # starttls | implicit_tls | plain
username      = "alerts@example.org"
password_file = "/etc/selfdef/secrets/smtp.password"      # mode 0600
from          = "selfdef-alerts@example.org"
to            = ["oncall@example.org"]
timeout_secs  = 10
```

**Auth**: PLAIN authentication. `username` in the TOML; `password_file` references the password at mode `0600`. **`tls = "plain"` refuses any auth-bearing send at construction time** — selfdef will not transmit credentials in cleartext. If you genuinely need an unauthenticated SMTP relay over plain TCP (test environments), omit `username` and `password_file`; the daemon will not attempt AUTH.

**Behavior**: connects with the selected TLS profile, authenticates if credentials are set, sends one email per event. Recipient list is RFC 5322 — multiple `to` addresses get one email with multiple recipients.

**Limitations**: No DKIM signing (the relay handles that). No HTML body — plain text. No bounce processing (operator monitors the relay's bounce mailbox out-of-band).

### twilio

**Crate**: [`crates/selfdef-integration-twilio`](../../crates/selfdef-integration-twilio/) · **SDD**: SDD-008 Q-D · **PR**: ~#120

Twilio SMS. Best fit for wake-the-on-call scenarios when the operator is reliably reachable by phone.

```toml
[notifier.twilio]
account_sid     = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"    # starts with AC, 34 chars.
auth_token_file = "/etc/selfdef/secrets/twilio.token"     # mode 0600 — the Twilio auth token.
from            = "+15551234567"                          # E.164 — Twilio-provisioned number.
to              = ["+15559876543"]                        # E.164 — one or more recipients.
timeout_secs    = 10
```

**Auth**: HTTP Basic with `account_sid` as the username and the auth token (from `auth_token_file`) as the password. The token IS the auth. Store at mode `0600`.

**Behavior**: HTTPS POST to `https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json` with form-encoded body. Multiple recipients are looped sequentially; **any-success wins** — if at least one delivery succeeds, the channel returns `Ok`. Body soft-cap at 1500 chars to stay safely under Twilio's 1600-char-per-message concatenation limit.

**Limitations**: Send-only — no inbound reply webhook for SMS-based ack (would require the daemon to expose a public HTTPS endpoint reachable from Twilio's egress IPs; deferred). Numbers MUST be E.164 format (`+<country><number>`); selfdef does not normalize.

### pagerduty

**Crate**: [`crates/selfdef-integration-pagerduty`](../../crates/selfdef-integration-pagerduty/) · **SDD**: SDD-008 Q-G · **PR**: #143

PagerDuty Events API v2. Best fit when you already pay for PagerDuty and want selfdef alerts to feed into your existing on-call rotation.

```toml
[notifier.pagerduty]
routing_key_file = "/etc/selfdef/secrets/pagerduty.key"   # mode 0600 — 32-char hex integration key.
endpoint         = ""                                     # empty = global US endpoint (events.pagerduty.com).
source           = "selfdef"                              # surfaced in PD UI; set per host for fleet visibility.
```

**Auth**: the 32-char hex routing key. Get it from PagerDuty → Services → Your Service → Integrations → Events API v2 → copy the Integration Key. Mode `0600`.

**Behavior**: HTTPS POST to `https://events.pagerduty.com/v2/enqueue` with the Events API v2 envelope. **Severity collapse**: OCSF six levels → PagerDuty four:

| OCSF | PagerDuty |
| --- | --- |
| Informational, Low | `info` |
| Medium | `warning` |
| High | `error` |
| Critical, Fatal | `critical` |

`dedup_key` is the OCSF event id (legacy chain path) or the payload id (engine path — one PD incident per rung, by design, so unacked alerts page louder). Set `endpoint` for EU-only PD instances or for mock testing.

**Limitations**: Trigger-only — `acknowledge` and `resolve` event_action flows that would close a PD incident on selfdef-side ack are deferred. The PD UI's ack stays in PD; selfdef-side ack via `selfdefctl notify ack` doesn't propagate to PD in v1.

### loki

**Crate**: [`crates/selfdef-integration-loki`](../../crates/selfdef-integration-loki/) · **SDD**: SDD-008 Q-G · **PR**: #144

Grafana Loki push-API. Best fit when you already aggregate logs in Loki and want selfdef events visible alongside everything else (Grafana dashboards, alerts that fan out from a single query layer).

```toml
[notifier.loki]
endpoint        = "https://logs-prod.grafana.net/loki/api/v1/push"  # MUST be https://.
tenant_id       = ""                                                # X-Scope-OrgID header. Empty = single-tenant.
auth_token_file = "/etc/selfdef/secrets/loki.token"                 # mode 0600 — bearer token (Grafana Cloud API key).
source          = "selfdef"                                         # `host` label in Loki.
```

**Auth modes**:
- **Self-hosted single-tenant**: leave `tenant_id` empty, no `auth_token_file`. selfdef sends no `X-Scope-OrgID` and no `Authorization`.
- **Self-hosted multi-tenant**: set `tenant_id` (sent as `X-Scope-OrgID`).
- **Grafana Cloud**: set both `tenant_id` (your stack id, e.g. `12345`) and `auth_token_file` (your API key — sent as `Authorization: Bearer <token>`).

**HTTPS-only invariant**: selfdef refuses to ship bearer tokens over plaintext; `endpoint` must be `https://`. Plain `http://` is rejected at startup.

**Behavior**: one HTTPS POST per event to `<endpoint>` with the Loki push envelope. Each event becomes one stream-entry tuple `[<unix_ns>, "<title — body>"]` with stream labels `{service, severity, host, kind}`. Newlines in body get collapsed to `·` to preserve Loki's line-oriented log model.

**Limitations**: Append-only — Loki has no native concept of ack. Use it for log retention + Grafana visualization alongside a separate "actually wakes me" channel (ntfy/Twilio/PagerDuty).

### opensearch

**Crate**: [`crates/selfdef-integration-opensearch`](../../crates/selfdef-integration-opensearch/) · **SDD**: SDD-008 Q-G · **PR**: #145

OpenSearch / Elasticsearch document index. Each event becomes one document at `<endpoint>/<index>/_doc`.

```toml
[notifier.opensearch]
endpoint        = "https://opensearch.internal:9200"
index           = "selfdef-events"
auth_kind       = "none"                                        # none | basic | apikey
username        = ""                                            # required for basic, ignored otherwise.
auth_token_file = "/etc/selfdef/secrets/opensearch.auth"        # mode 0600 — password (basic) or API key (apikey).
source          = "selfdef"
```

**Auth modes** (chosen by `auth_kind`):

| `auth_kind` | What it sends | Required fields |
|---|---|---|
| `none` | no `Authorization` header | endpoint, index |
| `basic` | `Authorization: Basic <base64(username:password)>` | endpoint, index, username, auth_token_file |
| `apikey` | `Authorization: ApiKey <key>` (Elastic Cloud format) | endpoint, index, auth_token_file |

Unknown `auth_kind` values are rejected at startup — operators see the misconfig in the daemon's first log line rather than silently falling back to `none`.

**HTTPS-only invariant**: same as Loki; `endpoint` must be `https://`.

**Behavior**: one HTTPS POST per event with a flat JSON document (`@timestamp`, `service`, `host`, `severity`, `kind`, `title`, `body`, `event_id`, `payload_id`). RFC 3339 `@timestamp`.

**Limitations**: No bulk indexing — one POST per event. Index name MUST be set when `endpoint` is set (no implicit default; mistyping the index name silently loses data on a real cluster, so v1 demands the operator name it explicitly).

### thehive

**Crate**: [`crates/selfdef-integration-thehive`](../../crates/selfdef-integration-thehive/) · **SDD**: SDD-008 Q-G · **PR**: #146

[TheHive](https://thehive-project.org/) alert-API channel. Best fit for SOC / IR workflows where selfdef events should land in your case-management tooling.

```toml
[notifier.thehive]
endpoint     = "https://hive.internal:9000"
api_key_file = "/etc/selfdef/secrets/thehive.key"   # mode 0600 — the Bearer API key.
source       = "selfdef"                            # alert `source` field.
alert_type   = "selfdef"                            # alert `type` field.
```

**Auth**: Bearer API key. Get it from TheHive → User Profile → API Key → copy. Mode `0600`.

**HTTPS-only invariant**: same as Loki/OpenSearch.

**Behavior**: one HTTPS POST per event to `<endpoint>/api/v1/alert`. **Severity collapse**: OCSF six → TheHive four:

| OCSF | TheHive (`severity`) |
| --- | --- |
| Informational, Low | `1` (Low) |
| Medium | `2` (Medium) |
| High | `3` (High) |
| Critical, Fatal | `4` (Critical) |

`tlp = 2` (Amber — SOC-internal) by default. Tags: `["selfdef", "selfdef:<severity>", "kind:<event_kind>"]`.

**Limitations**: Trigger-only — no reverse-channel for analyst-side ack to propagate back to selfdef's escalation engine (deferred). Each event creates one Alert; the analyst is responsible for promoting it to a Case.

### wall

**Crate**: [`crates/selfdef-integration-wall`](../../crates/selfdef-integration-wall/) · **SDD**: SDD-008 D-8 · **PR**: #128

[`wall(1)`](https://man7.org/linux/man-pages/man1/wall.1.html) — broadcast a one-line attention message to **every** logged-in TTY on the host. Best fit when the operator might be in a terminal that's not their primary alert surface (debugging in a vim session, ssh'd in fixing something else).

```toml
[notifier.wall]
binary         = "/usr/bin/wall"
severity_floor = "high"                  # informational | low | medium | high | critical | fatal
```

**Auth**: none — local subprocess.

**Behavior**: spawns `wall` with the attention message on stdin. Broadcasts to every TTY where the receiver hasn't `mesg n`'d. Severity emoji prefix.

**`severity_floor = "high"` by default** — wall is system-wide and bothering every TTY on Informational events is wrong. The operator can tune downward.

**Limitations**: **No per-user targeting** — `wall(1)` does not accept a username filter. For per-user opt-in, use [`write`](#write) instead. The `[notifier.wall].users` knob intentionally does **not** exist; that's a misnomer that would imply behavior `wall(1)` can't deliver. See D-024 in `docs/decisions.md`.

### write

**Crate**: [`crates/selfdef-integration-write`](../../crates/selfdef-integration-write/) · **SDD**: D-024 · **PR**: #170

[`write(1)`](https://man7.org/linux/man-pages/man1/write.1.html) — per-user TTY attention. Sibling of `wall` for operators who want session-attention only on specific accounts.

```toml
[notifier.write]
binary         = "/usr/bin/write"
severity_floor = "high"
users          = ["alice", "bob"]        # one write(1) invocation per user.
```

**Auth**: none — local subprocess.

**Behavior**: for each name in `users`, spawn `write <username>` and pipe the rendered message to stdin. Per-user spawns are sequential; failure for one user does not abort delivery to the others. `write(1)` exits non-zero when the target user is not logged in — that's expected, not an error worth surfacing (operators not at a session shouldn't fail an escalation). Genuine failures (binary missing, spawn errored) still surface.

**Username validation**: each name in `users` must match `[a-zA-Z0-9._-]+`. Shell metacharacters are rejected at config-load — selfdef will refuse to start with a malformed username rather than risk shell injection on the subprocess argv.

**`severity_floor = "high"` by default** — same posture as wall.

**Limitations**: Per-user only — broadcast-all is the [`wall`](#wall) channel. No "DM to a Linux account" concept beyond an active TTY session; if the target user isn't logged in, the message is silently dropped (by `write(1)` itself, not by selfdef).

---

## See also

- **Example configuration**: [`config/selfdef.toml.example`](../../config/selfdef.toml.example) — copy-paste-ready blocks for every channel.
- **Architecture**: [`ARCHITECTURE.md`](../../ARCHITECTURE.md) — where the integration layer sits relative to bus, store, correlator, responder, and notifier-orchestrator.
- **Orchestration design**: [`docs/sdd/008-notifications-orchestration.md`](../sdd/008-notifications-orchestration.md) — the SDD that defines `Channel`, the escalation engine, profiles, subscriptions, and ack flows.
- **Contributor template**: [`docs/dev/integrations.md`](../dev/integrations.md) — how to add a 13th channel.
- **Decisions log**: [`docs/decisions.md`](../decisions.md) — D-NNN entries that pin operator-stated choices (D-004 / D-024 wall vs write, etc.).
