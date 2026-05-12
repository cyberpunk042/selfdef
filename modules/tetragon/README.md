# tetragon

Substrate for Tetragon-based observability and enforcement on the
host. Owns Tetragon's main config, the TracingPolicy drop directory,
and the Prometheus metrics endpoint. Does **not** own any policies —
those come from policy modules like `agent-guard`. Does **not**
install the Tetragon binary — the operator does that out-of-band so
the module stays simple and uses whichever Tetragon build the host
already trusts.

## Why a separate module

Tetragon is a piece of substrate (like `bridge-l2`): everything on
top of it depends on the same config, the same event JSONL path,
and the same metrics endpoint. Letting each policy module configure
Tetragon would lead to drift between them. Instead, this module owns
the substrate and policy modules `consume = ["tetragon-tracing"]` /
`consume = ["tetragon-policies"]`.

## Prereqs

Install Tetragon ahead of time. The upstream Debian package is the
easiest path:

```bash
curl -fsSL https://github.com/cilium/tetragon/releases/latest/download/install-tetragon.sh | sudo bash
# or your distro's package manager once it ships Tetragon
```

The module's `requires` check refuses to apply if `tetragon` and
`systemctl` aren't on `PATH`.

## What it does on apply

1. Renders `/etc/tetragon/tetragon.yaml` with:
   - `export-filename` = `event_log_path` (the daemon's eventstream
     collector tails this — wire the daemon's
     `[collectors.eventstream].paths` to match).
   - `tracing-policy-dir` = `policy_dir` (where `agent-guard` etc.
     will write their YAMLs).
   - `metrics-server` = `metrics_address` (Prometheus exporter
     endpoint).
2. Creates `policy_dir` and the event-log parent dir if missing.
3. Enables the systemd unit. Restarts only when the rendered config
   actually changed bytes — re-running apply on a host already at
   the desired state is a true no-op.

The render is byte-stable: the config file lists no clocks, no
random IDs. If you see a restart on every apply, that's a bug.

## Config

```toml
event_log_path  = "/var/log/tetragon/events.json"
policy_dir      = "/etc/tetragon/tetragon.tp.d"
metrics_address = "localhost:2112"
config_path     = "/etc/tetragon/tetragon.yaml"
service_unit    = "tetragon.service"
```

`metrics_address` defaults to `localhost:2112` — flip to
`0.0.0.0:2112` only if Prometheus is on another host **and** you've
firewalled the port appropriately. Tetragon's metrics expose
syscall counts; they're not secret but they are a fingerprint of
host activity.

## What's NOT owned

- The Tetragon binary itself.
- Individual TracingPolicy YAMLs — `agent-guard` (and any future
  policy module) write those.
- The eventstream collector's *configuration* on the daemon side —
  set `[collectors.eventstream].paths = [event_log_path]` in
  `/etc/selfdef/selfdef.toml`. The module logs the configured event
  log path in its status message so the operator can verify
  alignment.

## Phase

This module ships in `phase = "pre"` so:

- Policy modules in `main` (e.g. `agent-guard`) see Tetragon
  already running when their apply.sh fires.
- `observability` in `post` finds the metrics endpoint reachable
  when it builds its Prometheus scrape config.

## Uninstall

`selfdefctl modules uninstall --confirm <hostname> --only tetragon`
stops Tetragon, removes the rendered config, and removes
`policy_dir` **only if it's empty** — never tear out a live policy
bundle. If `policy_dir` still has YAMLs, uninstall the policy
modules first (e.g. `--only agent-guard,tetragon`).
