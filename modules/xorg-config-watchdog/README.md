# xorg-config-watchdog

Boot + daily delta of the X server config against a learned
baseline, plus an ownership + `ModulePath`/`Load` scan. Catches a
config that loads attacker code into the root X server. MITRE
**T1574** / **T1547**.

## Why this matters

On non-rootless setups the **X server runs as root** and loads
modules (`.so`) according to directives in `/etc/X11/xorg.conf` and
`/etc/X11/xorg.conf.d/*.conf`:

- `Section "Files"` → `ModulePath "<dir[,dir...]>"` — where the
  server searches for driver/extension modules.
- `Section "Module"` → `Load "<modulename>"` — a module to load.

A planted config that points `ModulePath` at a **writable/attacker
location** makes the root X server load attacker `.so` code at the
next server start (graphical login / display-manager restart) — a
root-context code-load surface that the session/login watchdogs do
not see.

This is distinct from **xsession-watchdog** (user-context session
scripts) and **display-manager-hooks-watchdog** (DM root login
scripts); this is the **X-server module-load** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any X server config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No X server config present | `ok` | `no_xorg_config` |
| No delta | `ok` | `xorg_config_intact` |
| A config / directive added / changed / removed | `warn` | `xorg_config_changed` |
| A `.conf` world-writable/non-root, OR a `ModulePath` under `/tmp` `/var/tmp` `/dev/shm` `/home` or a relative `ModulePath` | `alert` | `xorg_config_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `modpath:<path>:<dir>` — each `ModulePath` entry (comma-split).
- `load:<path>:<module>` — each `Load` entry.

## Cadence

`OnBootSec=70min` + `OnCalendar=*-*-* 12:05:00` — extends the
staggered ladder after csh-config (12:00). A planted ModulePath/Load
takes effect at the next X server start, so the boot catch confirms
the config set after a restart and the daily catch bounds dwell
time.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable `ModulePath` makes
  the root X server load attacker modules.
- **T1547** Boot or Logon Autostart Execution — the modules load at
  X server start (graphical login).

## Operator workflow

```bash
journalctl -t selfdef-xorg-config -n 1 --no-pager
journalctl -t selfdef-xorg-config-detail --since "1 day ago"

# Inventory ModulePath / Load directives
grep -rinE '^\s*(ModulePath|Load)\b' /etc/X11/xorg.conf /etc/X11/xorg.conf.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/X11/xorg.conf.d/<file>.conf
sudo rm /var/lib/selfdef/xorg-config-baseline.tsv
sudo systemctl start selfdef-xorg-config.service
```

## Caveats

- **Standard ModulePath values** (`/usr/lib/xorg/modules`, …) and
  normal `Load` of named modules (`glx`, `dri2`) are not flagged. A
  new config still fires `warn` (re-baseline). The
  writable/relative-ModulePath / writable / non-root tiers are the
  high-confidence alert.
- **Rootless Xorg / Wayland** hosts don't run the X server as root
  (or at all); the surface is reduced, but the config files (when
  present) are still watched for change.
- **Headless servers** usually have no X config →
  `no_xorg_config` no-op.
- **Daily+boot cadence** misses a drop-restart-revert inside the
  window; an audit-rules watch on `/etc/X11` writes is the real-time
  complement.

## Coexistence

- **xsession-watchdog / display-manager-hooks-watchdog /
  xdg-autostart-watchdog**: the graphical-login script surfaces;
  this is the X-server module-load surface — together they cover the
  graphical stack's exec/load vectors.
- **ld-so-conf-watchdog / ld-preload-watchdog**: dynamic-linker
  search/preload; this is the X-server-specific module search path.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  configs; this adds the ModulePath/Load semantic view.
