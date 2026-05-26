# modules-load-watchdog

Boot + daily delta of the kernel-module auto-load config
(`/etc/modules-load.d/*.conf` + `/etc/modules` + runtime/local
dirs) against a learned baseline, plus an ownership scan.
Catches a module forced to load at boot. MITRE **T1547.006**
(Kernel Modules and Extensions).

## Why this matters

`systemd-modules-load.service` (and the legacy `/etc/modules`,
read by the kmod init path) force-load the kernel modules listed
in these files **at boot**. An attacker who adds a module name
here makes a malicious out-of-tree module — or a known-vulnerable
in-tree one used for privilege escalation — load on every boot:

```
echo 'evil_lkm' > /etc/modules-load.d/zz.conf
echo 'dccp'     >> /etc/modules          # re-enable a CVE-prone module
```

This is the auto-load **source** — the companion to
`kernel-module-watchdog` (which sees what is LOADED) and
`modprobe-config-watchdog` (which sees `install`/`alias`
directives).

## Watched

| Path | Watched | Why |
|---|---|---|
| `/etc/modules-load.d/*.conf` | **yes** | admin auto-load |
| `/etc/modules` | **yes** | legacy Debian auto-load list |
| `/run/modules-load.d/*.conf` | **yes** | runtime |
| `/usr/local/lib/modules-load.d/*.conf` | **yes** | local |
| `/usr/lib/modules-load.d` | **no** | package-managed |

No-ops cleanly if none exist (`event:no_modules_load`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any modules-load change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No auto-load config | `ok` | `no_modules_load` |
| No delta | `ok` | `modules_load_intact` |
| A module-to-load added/removed, or a file changed | `warn` | `modules_load_changed` |
| A config file world-writable or non-root-owned | `alert` | `modules_load_writable_config` |

A new module-to-load is `warn` (surfaced for review — packages
do add these; there is no safe allowlist of "good" module names
to alert against). The `alert` tier is reserved for a config
file an attacker can rewrite (world-writable / non-root), which
lets them force-load anything.

## What's recorded

- `file:<path>:<sha12>` — hash of each config file.
- `own:<path>:<owner:mode>` — owner + mode.
- `load:<modname>:<src>` — each module scheduled to auto-load.

## Cadence

`OnBootSec=26min` + `OnCalendar=*-*-* 08:15:00` — extends the
staggered ladder after dbus-service (08:10). The listed modules
load at the start of the next boot, so the boot catch confirms
the config after a restart.

## MITRE coverage

- **T1547.006** Boot or Logon Autostart Execution: Kernel
  Modules and Extensions — PRIMARY; auto-loading a module at
  boot.
- **T1601** Modify System Image (adjacent) — forcing a
  vulnerable/malicious module into the running kernel.

## Operator workflow

```bash
journalctl -t selfdef-modules-load -n 1 --no-pager
journalctl -t selfdef-modules-load-detail --since "1 day ago"

# Inventory
grep -rvE '^\s*#|^\s*$' /etc/modules-load.d/ /etc/modules 2>/dev/null

# Investigate a changed module-to-load
modinfo <modname>          # what is it? out-of-tree? signed?
# Remove the entry, then re-baseline:
sudo $EDITOR /etc/modules-load.d/<file>.conf
sudo rm /var/lib/selfdef/modules-load-baseline.tsv
sudo systemctl start selfdef-modules-load.service
```

## Caveats

- **Package installs add auto-load entries** (e.g. a driver
  package). A new entry fires `warn` (re-baseline). There is no
  reliable allowlist of benign module names, so this is a
  change-surfacing watchdog by design; the `kernel-module-watchdog`
  + `modinfo` are the follow-up to judge a specific module.
- **Daily+boot cadence** misses an add-reboot-revert within the
  window; an audit-rules watch on `/etc/modules-load.d` +
  `/etc/modules` writes is the real-time complement.

## Coexistence

- **kernel-module-watchdog**: watches LOADED modules
  (`/proc/modules`) — the runtime result; this watches the
  auto-load SOURCE. Together: what loaded + what is configured to
  load.
- **modprobe-config-watchdog**: `install`/`alias`/`blacklist`
  directives (how a module loads / what runs on load); this is
  the explicit auto-load LIST. Complementary modprobe-side views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the config files; this adds the per-module + ownership semantic
  view.
