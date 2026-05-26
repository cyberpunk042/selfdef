# autofs-watchdog

Boot + daily delta of the autofs master maps against a learned
baseline, plus an ownership + program-map scan. Catches a map that
autofs runs as root when a mountpoint is accessed. MITRE **T1546**.

## Why this matters

`autofs` runs a **`program:` map** (or any **executable map file**)
**as root** to generate mount entries when the corresponding autofs
mountpoint is accessed. Master maps:

- `/etc/auto.master`
- `/etc/auto.master.d/*.autofs`

Each line is `<mountpoint> <map> [options]`, where `<map>` may be:

- `program:/path/to/script` — autofs **execs** the script (program
  map) to produce entries.
- `/path/to/mapfile` — a map file; **if it is executable**, autofs
  treats it as a program map and runs it too.
- `yp:` / `ldap:` / `file:` / `nis:` — network/file maps (no local
  exec).

A planted `program:` map — or a writable executable map file — is
**mount-access-triggered root code execution**, fired on demand by
anyone who can `stat`/`cd` the mountpoint. This is the
**mount-access exec** trigger class, distinct from cron/incron/at
(time/file-event), the login/network/power/boot watchdogs, and
snmpd/mail (query/mail).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any autofs map change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No autofs master map present | `ok` | `no_autofs` |
| No delta | `ok` | `autofs_intact` |
| A master map / entry added / changed / removed | `warn` | `autofs_changed` |
| A master map world-writable/non-root, a `program:`/map path under `/tmp` `/var/tmp` `/dev/shm` `/home`, or an executable map file that is itself world-writable/non-root | `alert` | `autofs_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each master map.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `map:<path>:<mountpoint>:<map>` — each master-map entry.

## Cadence

`OnBootSec=85min` + `OnCalendar=*-*-* 13:45:00` — extends the
staggered ladder after snmpd-exec (13:35). A planted program map
fires the next time the mountpoint is accessed, so the daily catch
bounds dwell time; the boot catch confirms the master map after a
restart.

## MITRE coverage

- **T1546** Event Triggered Execution — accessing the autofs
  mountpoint triggers the program map.
- **T1059** — the program map is arbitrary code run by autofs as
  root.

## Operator workflow

```bash
journalctl -t selfdef-autofs -n 1 --no-pager
journalctl -t selfdef-autofs-detail --since "1 day ago"

# Inventory the maps; find program maps + executable map files
cat /etc/auto.master /etc/auto.master.d/*.autofs 2>/dev/null
grep -rnE 'program:' /etc/auto.master /etc/auto.master.d/ 2>/dev/null
awk '$1!~/^#/ && $2 ~ /^\//{print $2}' /etc/auto.master 2>/dev/null | xargs -r ls -la 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/auto.master
sudo rm /var/lib/selfdef/autofs-baseline.tsv
sudo systemctl start selfdef-autofs.service
```

## Caveats

- **Legit program maps exist** (`/etc/auto.net`, `program:` helpers
  shipped by autofs); a new entry with a standard absolute path
  fires `warn` (re-baseline). The writable program-map / writable
  map path / writable-or-non-root executable-map tiers are the
  high-confidence alert.
- **This watches the master maps**, and checks the ownership +
  exec-bit of any directly-referenced map file; it does not recurse
  into the contents of every indirect map (those `key location`
  entries are a deeper surface — pair with integrity-sentinel on the
  map files).
- **autofs is uncommon on single-host servers** (more common with
  NFS-home / LDAP-automount fleets) → `no_autofs` no-op where unused.
- **Daily+boot cadence** misses a drop-access-revert inside the
  window; an audit-rules watch on `/etc/auto.master*` writes is the
  real-time complement.

## Coexistence

- **cron / incron / at / snmpd / postfix / aliases watchdogs**: the
  other event-trigger exec classes (time, file-event, query, mail);
  this is the mount-access one — together they cover the
  trigger-driven root-exec taxonomy.
- **fstab-watchdog / mount-options-watchdog**: static mount config;
  this is the automount program-map exec surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  master + map files; this adds the program-map semantic view.
