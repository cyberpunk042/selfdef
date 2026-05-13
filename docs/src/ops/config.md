# Configuration

Daemon config lives at `/etc/selfdef/selfdef.toml`. The
postinst drops `config/selfdef.toml.example` there on first
install. The file is the single source of truth for daemon
behaviour — there's no environment-only override (the
`SELFDEF_CONFIG` env var only chooses the file path).

A reload is `kill -HUP $(pidof selfdefd)` (rules) or
`systemctl restart selfdefd` (everything else).

## Layout

```toml
[daemon]            # host_tag, log_level, log_format
[bus]               # in-proc broadcast capacity
[bus.nats]          # NATS bridge — see ops/nats.md
[bus.nats.jetstream]# JetStream durability
[store]             # SQLite hot path, retention
[collectors.<name>] # one block per collector
[correlator]        # rules dir, hot reload
[notifier]          # channel list — see ops/notifications.md
[notifier.<channel>]# per-channel knobs
[responder]         # dry-run, allowed actions, scripts
[api]               # HTTP API binding + auth — see ops/api.md
[api.tls]           # optional TLS / mTLS
```

## Safe defaults

Every collector defaults to `enabled = false`. The API
defaults to disabled. The responder defaults to
`dry_run = true` and `allowed_actions = ["notify"]` only.
This is deliberate — selfdef does nothing operator-visible
out of the box; opt in to each surface as you understand it.

## Module-side defaults vs daemon-side defaults

The Phase-1 audit flagged that some modules ship defaults
assuming the daemon is configured a certain way (see
[`docs/sdd/002-defaults-that-work.md`](../../sdd/002-defaults-that-work.md)
for the design proposal). Until that lands, the rule of
thumb:

- Every module that emits events into a JSONL stream
  (today: `integrity-sentinel`) requires the daemon's
  `[collectors.eventstream]` block to enable the path.
- Every module exposing metrics for `observability` to
  scrape (today: `tetragon`) requires the corresponding
  collector enabled and the daemon's `[api]` block enabled
  if the daemon-side `/metrics` endpoint is one of the
  scrape targets.

The relevant module READMEs describe their daemon-side
expectations.

## Cross-references

- [`api.md`](./api.md) — HTTP API endpoints, auth, TLS, mTLS.
- [`notifications.md`](./notifications.md) — ntfy / Signal
  setup.
- [`nats.md`](./nats.md) — multi-host bridge.
- [`ssh-wrap-install.md`](./ssh-wrap-install.md) — client-side
  ssh wrapper.

## Validating config

```bash
selfdefctl status      # exits non-zero if config can't load
selfdefd --validate    # planned — see SDD-002 follow-up
```

For now, the most reliable check is `systemctl restart selfdefd`
followed by `journalctl -u selfdefd --since='10 seconds ago'`.
A bad config logs a parse error at startup.
