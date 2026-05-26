# rsyslog-exec-watchdog

Boot + daily delta of the rsyslog config's program-exec actions
(`/etc/rsyslog.conf` + `/etc/rsyslog.d/*`) against a learned
baseline, plus an ownership scan. Catches a program rsyslog runs
as root on a log message. MITRE **T1546** (Event Triggered
Execution).

## Why this matters

rsyslog can run a program **as root** when a log message matches:

```
# legacy shell-exec action
*.*  ^/tmp/.payload;RSYSLOG_TraditionalFileFormat

# modern omprog output module
action(type="omprog" binary="/tmp/.payload --arg")
```

A rogue exec action is root-exec-on-log-event persistence: the
attacker triggers it simply by causing a matching log line (a
failed login, a crafted message via `logger`, etc.). It hides in
log-pipeline config.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any rsyslog-exec change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No rsyslog config | `ok` | `no_rsyslog` |
| No delta | `ok` | `rsyslog_exec_intact` |
| A config / exec action added, removed, or changed | `warn` | `rsyslog_exec_changed` |
| An exec program under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root config | `alert` | `rsyslog_exec_suspicious` |

## What's recorded

- `file:<conf>:<sha12>` — hash of each rsyslog config.
- `own:<conf>:<owner:mode>` — owner + mode.
- `exec:<conf>:<prog>` — each exec action's program (first
  token), from the legacy `^program` action and the modern
  `omprog binary="..."`.

## Cadence

`OnBootSec=41min` + `OnCalendar=*-*-* 09:30:00` — extends the
staggered ladder after apt-hooks (09:25). A rogue action fires on
the next matching log message, so the boot catch confirms the
config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — a matching log message is
  the trigger that runs the program as root.
- **T1059.004** — the exec action is command execution.
- **T1562.001** (adjacent) — the same config controls logging, so
  an attacker may also use it to suppress evidence.

## Operator workflow

```bash
journalctl -t selfdef-rsyslog-exec -n 1 --no-pager
journalctl -t selfdef-rsyslog-exec-detail --since "1 day ago"

# Inventory exec actions
grep -rnE 'omprog|binary=|[[:space:]]\^' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/rsyslog.d/<file>.conf
sudo systemctl restart rsyslog
sudo rm /var/lib/selfdef/rsyslog-exec-baseline.tsv
sudo systemctl start selfdef-rsyslog-exec.service
```

## Caveats

- **Exec actions are rare in default configs** — most rsyslog.d
  files are filters + file/forward outputs. A new omprog/`^`
  action fires `warn`, and the tmp/relative-program + injection +
  ownership tiers are the high-confidence alert. Re-baseline a
  legit one (e.g. an alerting integration).
- **syslog-ng** uses a different config (`program()` destination);
  not covered here (a future sibling) — this targets rsyslog.
- **Daily+boot cadence** misses an inject-log-revert within the
  window; an audit-rules watch on `/etc/rsyslog.d` writes is the
  real-time complement.

## Coexistence

- **logrotate / cron / udev / apt-hooks watchdogs**: the root-
  exec-on-event family — this adds the log-message trigger
  surface.
- **logfile-integrity-watchdog**: log CONTENT integrity; this is
  the log-PIPELINE exec surface. Complementary log-subsystem
  views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the rsyslog configs; this adds the exec-action semantic view.
