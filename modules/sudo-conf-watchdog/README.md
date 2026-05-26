# sudo-conf-watchdog

Boot + daily delta of `/etc/sudo.conf` against a learned baseline,
plus an ownership + `Plugin`/`Path` scan. Catches a config that
loads attacker code into setuid-root sudo. MITRE **T1574**.

## Why this matters

`sudo` is **setuid-root**, and it loads its policy and I/O-logging
plugins (`.so`) according to `/etc/sudo.conf`:

```
Plugin sudoers_policy sudoers.so
Plugin sudoers_io     sudoers.so
Path   plugin_dir     /usr/libexec/sudo
```

- a `Plugin <symbol> <path>` line names a `.so` to load (relative
  names resolve under `Path plugin_dir`),
- a `Path plugin_dir <dir>` line sets where relative plugins load
  from.

A planted `Plugin policy /tmp/evil.so` — or a `Path plugin_dir`
pointing at a **writable** dir so a relative plugin name resolves
there — loads attacker code into **setuid-root sudo on every sudo
invocation**. On an admin host that is constant, immediate
privilege escalation + persistence.

This is distinct from the **sudoers watchdogs**
(`sudoers-defaults-watchdog`, `sudoers-integrity-watchdog`), which
watch the *rule content* of `/etc/sudoers` and `/etc/sudoers.d`.
This module watches the sudo **plugin-load** surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any sudo.conf change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/sudo.conf` present | `ok` | `no_sudo_conf` |
| No delta | `ok` | `sudo_conf_intact` |
| A directive / file added / changed / removed | `warn` | `sudo_conf_changed` |
| File world-writable/non-root, OR a `Plugin` `.so` / `plugin_dir` under `/tmp` `/var/tmp` `/dev/shm` `/home`, OR a relative-with-slash `Plugin` path | `alert` | `sudo_conf_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of `/etc/sudo.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `plugin:<path>:<name>:<so>` — each `Plugin` line.
- `pathdir:<path>:<name>:<dir>` — each `Path` line.

## Cadence

`OnBootSec=71min` + `OnCalendar=*-*-* 12:10:00` — extends the
staggered ladder after xorg-config (12:05). A planted
Plugin/plugin_dir takes effect on the next sudo invocation, so the
daily catch bounds dwell time; the boot catch confirms the config
after a restart.

## MITRE coverage

- **T1574** Hijack Execution Flow — a writable plugin path loads
  attacker code into setuid-root sudo.
- **T1548.003** Abuse Elevation Control Mechanism: Sudo — the
  plugin runs with sudo's elevated authority.

## Operator workflow

```bash
journalctl -t selfdef-sudo-conf -n 1 --no-pager
journalctl -t selfdef-sudo-conf-detail --since "1 day ago"

# Inspect + show resolved plugins
cat /etc/sudo.conf 2>/dev/null
sudo -V 2>/dev/null | grep -iE 'plugin|policy'   # what sudo actually loaded

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/sudo.conf
sudo rm /var/lib/selfdef/sudo-conf-baseline.tsv
sudo systemctl start selfdef-sudo-conf.service
```

## Caveats

- **Most hosts have no `/etc/sudo.conf`** (sudo uses compiled-in
  defaults) → `no_sudo_conf` no-op. Its *appearance* is itself worth
  a `warn` review; a `Plugin`/`plugin_dir` pointing into a writable
  dir is the high-confidence alert.
- **Legit `Plugin sudoers.so`** (relative, resolved from the
  standard plugin_dir) and a standard absolute `plugin_dir`
  (`/usr/libexec/sudo`, `/usr/lib/sudo`) are not flagged.
- **`Path` directives other than `plugin_dir`** (askpass, noexec,
  sesh) are tracked for delta but not alerted; review them on a
  `warn`.
- **Daily+boot cadence** misses a drop-sudo-revert inside the
  window; an audit-rules watch on `/etc/sudo.conf` writes is the
  real-time complement.

## Coexistence

- **sudoers-defaults-watchdog / sudoers-integrity-watchdog /
  sudo-tune**: the `/etc/sudoers` rule-content surface; this is the
  sudo plugin-load surface.
- **ld-preload-watchdog / ld-so-conf-watchdog**: dynamic-linker
  hijack; this is the sudo-specific plugin search.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  `/etc/sudo.conf`; this adds the Plugin/Path semantic view.
