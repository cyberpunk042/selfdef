# incron-watchdog

Boot + daily delta of the incron tables against a learned baseline,
plus an ownership + command scan. Catches a command incron runs on
an inotify file event. MITRE **T1546**.

## Why this matters

`incron` is **cron-for-inotify**. Each table line:

```
<path>  <event_mask>  <command>
```

runs the command (as the table's owner — **root** for the system
and root tables) when the named inotify event fires on the watched
path. Tables live in:

- `/etc/incron.d/*` — system tables
- `/var/spool/incron/*` — per-user tables (root's is
  `/var/spool/incron/root`)

A planted line watching a commonly-touched file (e.g. `/etc/passwd`,
a log file, a spool directory) with a malicious command is
**file-event-triggered code execution / persistence** — and the
attacker can fire it on demand simply by touching the watched path.

This is the **inotify-event exec** surface — distinct from
**cron-job-watchdog**/**anacrontab-watchdog** (time), the
login/network/power/boot watchdogs, and **at-jobs-watchdog**
(one-shot time).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any incron table change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No incron tables present | `ok` | `no_incron` |
| No delta | `ok` | `incron_intact` |
| A table / line added / changed / removed | `warn` | `incron_changed` |
| A table world-writable/non-root, OR a command program under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern | `alert` | `incron_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each table.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `line:<path>:<watch>:<cmd>` — each incron entry's watched path +
  command.

## Cadence

`OnBootSec=82min` + `OnCalendar=*-*-* 13:20:00` — extends the
staggered ladder after kernel-usermodehelper (13:10). A planted
incron line fires the next time the watched inotify event occurs
(triggerable on demand), so the daily catch bounds dwell time; the
boot catch confirms the table set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — an inotify file event on the
  watched path triggers the command.
- **T1059** — the command is arbitrary code run by incrond.

## Operator workflow

```bash
journalctl -t selfdef-incron -n 1 --no-pager
journalctl -t selfdef-incron-detail --since "1 day ago"

# Inventory
cat /etc/incron.d/* /var/spool/incron/* 2>/dev/null
incrontab -l 2>/dev/null          # current user's table

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/incron.d/<file>
sudo rm /var/lib/selfdef/incron-baseline.tsv
sudo systemctl start selfdef-incron.service
```

## Caveats

- **incron is rarely installed by default** → `no_incron` no-op on
  most hosts. Its presence (or any table line) is worth a `warn`
  review; a tmp-exec / injection / writable / non-root tier is the
  high-confidence alert.
- **Legit incron uses exist** (auto-reload a service on config
  change, process an upload spool); a new line with a standard
  absolute command fires `warn` (re-baseline).
- **`/var/spool/incron/<user>` for non-root users** runs as that
  user — still worth tracking (lateral persistence), and the file is
  baselined; the root/system tables are the highest-impact.
- **Daily+boot cadence** misses a drop-touch-revert inside the
  window; an audit-rules watch on the incron dirs' writes is the
  real-time complement.

## Coexistence

- **cron-job-watchdog / anacrontab-watchdog / at-jobs-watchdog**:
  time-triggered exec; this is the inotify-event-triggered one —
  together they cover the scheduler/event exec surface.
- **dhclient/dhcpcd/network-dispatcher, acpi/systemd-power, fail2ban
  watchdogs**: other event-triggered root-exec surfaces; this adds
  the filesystem-event one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  tables; this adds the command-scan view.
