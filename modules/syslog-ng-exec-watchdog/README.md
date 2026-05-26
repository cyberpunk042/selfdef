# syslog-ng-exec-watchdog

Boot + daily delta of the syslog-ng config's `program()`
destinations (`/etc/syslog-ng/syslog-ng.conf` +
`/etc/syslog-ng/conf.d/*`) against a learned baseline, plus an
ownership scan. Catches a program syslog-ng runs as root on a log
message. MITRE **T1546** (Event Triggered Execution).

## Why this matters

A syslog-ng `program()` destination runs a program **as root**,
fed by matching log messages — the syslog-ng sibling of rsyslog's
`omprog`:

```
destination d_evil { program("/tmp/.payload"); };   # root on log event
log { source(s_src); destination(d_evil); };
```

A rogue `program()` is root-exec-on-log-event persistence,
triggered by causing a matching log line (a failed login, a
crafted message via `logger`, etc.).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any syslog-ng-exec change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No syslog-ng config | `ok` | `no_syslog_ng` |
| No delta | `ok` | `syslog_ng_exec_intact` |
| A config / program() added, removed, or changed | `warn` | `syslog_ng_exec_changed` |
| A program under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root config | `alert` | `syslog_ng_exec_suspicious` |

## What's recorded

- `file:<conf>:<sha12>` — hash of each syslog-ng config.
- `own:<conf>:<owner:mode>` — owner + mode.
- `program:<conf>:<prog>` — each `program()` destination's
  program (first token).

## Cadence

`OnBootSec=45min` + `OnCalendar=*-*-* 09:50:00` — extends the
staggered ladder after crypttab (09:45). A rogue `program()`
fires on the next matching log message, so the boot catch
confirms the config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a matching log message is
  the trigger that runs the program as root.
- **T1059.004** — the `program()` is command execution.
- **T1562.001** (adjacent) — the same config controls logging.

## Operator workflow

```bash
journalctl -t selfdef-syslog-ng-exec -n 1 --no-pager
journalctl -t selfdef-syslog-ng-exec-detail --since "1 day ago"

# Inventory program() destinations
grep -rnE 'program[[:space:]]*\(' /etc/syslog-ng/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/syslog-ng/conf.d/<file>.conf
sudo systemctl restart syslog-ng
sudo rm /var/lib/selfdef/syslog-ng-exec-baseline.tsv
sudo systemctl start selfdef-syslog-ng-exec.service
```

## Caveats

- **program() is rare in default configs** — most syslog-ng
  destinations are file/network. A new one fires `warn`, and the
  tmp/relative-program + injection + ownership tiers are the
  high-confidence alert. Re-baseline a vetted integration.
- **rsyslog hosts** → `no_syslog_ng` no-op; rsyslog-exec-watchdog
  covers the rsyslog side.
- **Daily+boot cadence** misses an inject-log-revert within the
  window; an audit-rules watch on `/etc/syslog-ng` writes is the
  real-time complement.

## Coexistence

- **rsyslog-exec-watchdog**: the rsyslog `omprog`/`^program` exec
  surface; this is the syslog-ng `program()` equivalent. Both
  log-daemon exec surfaces (a host runs one or the other).
- **logrotate / cron / apt-hooks watchdogs**: the root-exec-on-
  event family — this adds the syslog-ng log-message trigger.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the syslog-ng configs; this adds the program()-semantic view.
