# Operator cheatsheet — selfdef + four-watchdog set

One-page printable reference for the daily-driver commands. For the
exhaustive surface, `selfdefctl --help` + the per-subcommand `--help`.

## First-time setup

```sh
sudo apt install selfdef-daemon
selfdefctl wizard                     # 5-step setup walkthrough
selfdefctl init checklist             # 12-step first-run checklist
```

## Daily-driver

```sh
selfdefctl status                     # daemon counters
selfdefctl doctor                     # cross-cutting health check
selfdefctl trio                       # four-watchdog snapshot (4 panels)
selfdefctl trio --quiet               # single-line PS1-friendly summary
selfdefctl trio --watch 5             # human watch, clear+redraw every 5s
selfdefctl trio --json --watch 5      # JSONL stream for monitoring pipelines
selfdefctl trio-tail                  # unified live OCSF tail (Ctrl-C exits)
selfdefctl alerts                     # MS027 alerts overview (CLI parity with dashboard)
selfdefctl alerts --quiet             # single-line gate-friendly: `selfdef-alerts: OK`
selfdefctl alerts --json              # jq-friendly output (worst + per-row state)
```

## Per-watchdog drill-down

```sh
# friction-audit (MS046, hardware frame)
selfdefctl friction-audit show        # latest verdict per gate
selfdefctl friction-audit history     # ring buffer history
selfdefctl friction-audit replay      # re-run gate (operator-triggered)

# perimeter (MS047, kernel-fence)
selfdefctl perimeter show             # active policy + last 16 verdicts
selfdefctl perimeter history          # Sigkill verdict log
selfdefctl perimeter extend --signed <manifest>   # operator-signed extension
selfdefctl perimeter revoke <ext-id>  # revoke extension
selfdefctl perimeter check-overlap    # SDD-015 coexistence check
selfdefctl perimeter status           # SDD-015 coexistence status
selfdefctl perimeter audit-cycle replay  # chain integrity check

# guardian (MS044, supervisor)
selfdefctl guardian show              # state + last events
selfdefctl guardian history           # event log
selfdefctl guardian replay <event-id> # re-classify stored event
selfdefctl guardian rollback <event-id> # false-positive rollback

# scheduler (MS048, routing)
selfdefctl scheduler show             # state + last 16 decisions
selfdefctl scheduler history          # decision log
selfdefctl scheduler explain <req-id> # single-decision detail
selfdefctl scheduler replay <req-id> [--profile P]   # counterfactual replay
selfdefctl scheduler weights [--profile P]  # 7-axis weight matrix
selfdefctl scheduler force <req-id> --route R   # Ring 0 operator override
selfdefctl scheduler audit-cycle replay   # chain integrity check
```

## Modules (operator-activatable bundles)

```sh
selfdefctl modules list                       # all shipped modules
selfdefctl modules info <slug>                # single-module detail
selfdefctl modules show-requires <slug>       # daemon_requires
selfdefctl modules check <slug>               # health probe
selfdefctl modules apply --dry-run            # preview activation
sudo selfdefctl modules apply                 # apply active modules
sudo selfdefctl modules uninstall --confirm $(hostname)
```

## Module activation (edit `/etc/selfdef/modules.toml`)

```sh
sudo selfdefctl init modules            # writes starter modules.toml
sudoedit /etc/selfdef/modules.toml      # uncomment desired module blocks
sudo selfdefctl modules apply           # idempotent apply
```

## Four-watchdog set systemd enable

```sh
sudo systemctl enable --now sovereign-guard.service     # MS046 friction-audit
sudo systemctl enable --now selfdef-guardian.service    # MS044 guardian
sudo systemctl enable --now selfdef-scheduler.service   # MS048 scheduler
# MS047 perimeter: TracingPolicy auto-installed by postinst — no service to enable

sudo systemctl enable --now selfdef-doctor.timer        # hourly health check
journalctl -u selfdef-doctor.service -n 50              # last run output
```

## HTTP API (`/v1/*`, bearer-token-gated when TCP-bound)

```text
GET /status              daemon status + counters
GET /events              recent events
GET /findings            recent findings (Critical severity_id)
GET /events/stream       SSE live tail (per-token quota: 8)
GET /metrics             Prometheus exposition (selfdef-bus + four-watchdog)
GET /notify/ack/:token   one-click escalation ack

GET /v1/friction-audit{,/history}
GET /v1/perimeter{,/history}
GET /v1/guardian{,/history}
GET /v1/scheduler{,/history,/backpressure,/weights,/explain/:request_id}
GET /v1/modules{,/:name}
GET /v1/alerts                                       (MS027 server-side classifier)
GET /v1/hardware{,/capabilities,/sain01}             (MS010 hardware snapshot + derived caps + sain-01 verdict)
GET /v1/network                                      (MS011 Z-7 internet/DNS/cloudflared/tailscale/traefik)
GET /v1/storage                                      (MS011 Z-10 per-mount usage + selfdef log dirs)
GET /v1/raid                                         (MS011 Z-9 software RAID arrays from /proc/mdstat)
```

## Operator runbooks (info-hub `wiki/runbooks/`)

```text
friction-audit-{pcie,zfs,memory,immutability,signature}.md  (5)
perimeter-{tetragon-not-running,policy-load-failure,extension-create,sigkill-investigation,key-rotation,audit-log-corruption}.md  (6)
guardian-{not-running,socket-unreachable,false-positive-rollback,audit-log-corruption,console-alert-investigation}.md  (5)
scheduler-{not-running,backpressure-stuck-open,weight-matrix-rotation,audit-log-corruption,force-override-investigation}.md  (5)
ux-coherence-failures.md  (1)
```

## PS1 prompt integration

```sh
# Zsh:
PROMPT='%n@%m %~ $(selfdefctl trio --quiet 2>/dev/null) %# '

# Bash:
PS1='\u@\h \w $(selfdefctl trio --quiet 2>/dev/null) \$ '

# Tmux status-right:
set -g status-right '#(selfdefctl trio --quiet 2>/dev/null)'
```

## Shell gate (only run X if all watchdogs OK)

```sh
selfdefctl trio --quiet && sudo selfdefctl modules apply
```

## Dashboard PWA (operator-facing UI at `/dashboard/`)

The daemon serves a 6-panel single-page operator dashboard. Sections:

| Panel | Refresh interval | Backed by |
|---|---|---|
| Friction-audit (MS046) | 30 s | `GET /v1/friction-audit` |
| Perimeter (MS047) | 15 s | `GET /v1/perimeter` |
| Guardian (MS044) | 30 s | `GET /v1/guardian` |
| Scheduler (MS048) | 10 s | `GET /v1/scheduler` |
| Modules (MS006) | 60 s | `GET /v1/modules` |
| Alerts overview (MS027) | 15 s | `GET /metrics` — client-side parse of 9 alert-relevant series; surfaces chain-broken + counter alerts without needing an external Prometheus |

Open over UNIX socket (`unix://`) or TCP with `Authorization: Bearer
<token>`. PWA shell is offline-capable (service-worker cached) but
API responses are never cached — operators need the freshest data.

## Coherence harness (local dev / CI)

```sh
make coherence                        # 13-layer L1+L2+cargo gate (preferred)
bash scripts/test/coherence.sh        # same thing, direct invocation
```

CI runs the same harness on every push + PR + tag. See
`.github/workflows/ci.yml` (`coherence` job) +
`.github/workflows/release.yml` (pre-build gate).

## Cross-references

- Full operator surface: `selfdefctl --help`
- First-time setup: [`docs/dev/first-run.md`](dev/first-run.md)
- Operator health check: [`docs/dev/operator-health-check.md`](dev/operator-health-check.md)
- Module author contract: [`docs/dev/modules.md`](dev/modules.md)
- Security threat model: [`SECURITY.md`](../SECURITY.md)
- Architecture: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Changelog: [`CHANGELOG.md`](../CHANGELOG.md)
