# udev-rules-watchdog

Boot + daily delta of the admin/runtime udev rule directories
(`/etc/udev/rules.d` + `/run/udev/rules.d`) against a learned
baseline. Catches a `.rules` file that executes code AS ROOT on
device events. MITRE **T1546** (Event Triggered Execution).

## Why this matters

`udevd` runs as root and evaluates `*.rules` files on every
device event — boot coldplug AND hotplug. A rule with an exec
directive runs its target as root when a matching event fires:

```
# /etc/udev/rules.d/99-evil.rules
ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/.payload"
```

```
# fires on EVERY boot via an always-present device:
KERNEL=="null", RUN+="/dev/shm/persist.sh"
```

The exec directives are `RUN`/`RUN+=`, `PROGRAM`, and
`IMPORT{program}`. A rule that matches a device always present
at boot (or any USB insert) is a **persistence + privilege**
vector that survives reboot and runs before most monitoring is
up — the udev equivalent of a cron `@reboot` or a systemd unit,
but easier to overlook.

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/etc/udev/rules.d` | **yes** | admin rules; the attacker-writable persistence path |
| `/run/udev/rules.d` | **yes** | volatile runtime rules |
| `/usr/lib/udev/rules.d` | **no** | package-managed; legitimately full of `RUN+=`. integrity-sentinel / aide-bridge cover package-owned content. |

Watching only the admin/runtime dirs keeps the exec-directive
signal high: a new `RUN+=` in `/etc/udev/rules.d` is rare and
notable, whereas `/usr/lib` is full of them by design.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any udev-rules change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `udev_rules_intact` |
| A rule file hash changed / a non-exec rule added or removed | `warn` | `udev_rules_changed` |
| A NEW exec directive (`RUN`/`PROGRAM`/`IMPORT{program}`) appears | `alert` | `udev_rules_new_exec` |
| An exec target under /tmp /var/tmp /dev/shm /home, world-writable, or bare/relative | `alert` | `udev_rules_suspicious_exec` (the payload signature) |

## What's recorded

- `file:<rule>:<sha12>` — hash of each `.rules` file (catches a
  comment-only or match-condition edit the exec parse misses).
- `exec:<rule>:<target>` — the program path of each
  `RUN`/`PROGRAM`/`IMPORT{program}` directive (the code-exec
  surface). The first whitespace-delimited token is recorded
  (args stripped).

A new exec directive is alert-grade even with a normal-looking
target, because adding root code-exec on a device event is
inherently high-signal in the admin rule dir. A target under
`/tmp`/`/home`/`/dev/shm`, a world-writable file, or a bare
relative path escalates to the payload-signature event.

## Cadence

`OnBootSec=11min` + `OnCalendar=*-*-* 07:00:00` — extends the
staggered ladder after nsswitch (06:55). The boot catch matters
here: udev rules fire at coldplug, so the boot scan confirms the
rule set on its first post-reboot opportunity.

## MITRE coverage

- **T1546** Event Triggered Execution — PRIMARY; a udev rule is
  an event trigger (device add/change) that runs an attacker
  command as root.
- **T1059** Command and Scripting Interpreter — the `RUN+=` /
  `PROGRAM` target is arbitrary command execution.
- **T1037** Boot or Logon Initialization Scripts — a rule
  matching an always-present device runs at every boot.
- **T1200** Hardware Additions — a rule keyed on `ACTION=="add"`
  for USB executes on attacker-inserted hardware (pairs with
  usbguard / pci-device-watchdog).

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-udev-rules -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-udev-rules-detail --since "1 day ago"

# Manual inventory of admin/runtime exec directives
grep -rEn 'RUN[+]?=|PROGRAM|IMPORT\{program\}' /etc/udev/rules.d /run/udev/rules.d 2>/dev/null

# Investigate a suspicious_exec alert
# - Is the target under /tmp /home /dev/shm, world-writable, or
#   a bare path? → almost certainly a payload.
ls -l <target>; file <target>; head -20 <target>
# Remove the rule + payload, reload udev, re-baseline:
sudo rm /etc/udev/rules.d/99-evil.rules
sudo udevadm control --reload-rules
sudo rm /var/lib/selfdef/udev-rules-baseline.tsv
sudo systemctl start selfdef-udev-rules.service

# Re-baseline after a legit admin rule (you added device
# automation): re-run the service once after writing the rule.
sudo rm /var/lib/selfdef/udev-rules-baseline.tsv
sudo systemctl start selfdef-udev-rules.service
```

## Caveats

- **Legit admin rules use RUN too** (custom device automation,
  power management). A new admin `RUN+=` fires `alert`
  (`new_exec`) — by design, so the operator sees every added
  root-exec-on-event; re-baseline once the rule is vetted. The
  `suspicious_exec` tier (writable/tmp/home/bare target) is the
  high-confidence one.
- **Daily+boot cadence** misses an inject-trigger-revert within
  the window; an audit-rules watch on `/etc/udev/rules.d` writes
  is the real-time complement.
- **`udevadm control --reload-rules`** is needed for a rule to
  take effect on already-running udevd; the boot scan covers the
  reboot path, this module watches the FILES (the persistence
  artifact), not the loaded ruleset.
- **The exec target's content** is caught by aide-bridge /
  integrity-sentinel; this catches the udev RULE that invokes
  it. Both are needed.

## Coexistence

- **systemd-unit-watchdog / cron-job-watchdog**: the other
  persistence-mechanism watchdogs — systemd units (services),
  cron (`@reboot`/scheduled), and udev (device-event) are the
  three classic root-persistence surfaces; this closes the udev
  one.
- **usbguard / pci-device-watchdog**: the hardware-addition
  family — a udev rule keyed on `ACTION=="add"` is the EXEC that
  fires when those modules see a new device; together they cover
  detection (new device) + the rule that weaponizes it.
- **audit-rules**: the real-time complement — watching writes to
  `/etc/udev/rules.d` catches the inject within the daily window
  this module's snapshot misses.
- **aide-bridge / integrity-sentinel**: content integrity on the
  exec targets; this is the udev-rule semantic view.
