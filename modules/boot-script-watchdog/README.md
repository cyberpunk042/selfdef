# boot-script-watchdog

Boot + daily delta of the SysV/rc boot-script surfaces against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches an appended payload or a new init script that runs as
root at boot. MITRE **T1037.004** (rc.local) / **T1037** (init
scripts).

## Why this matters

`/etc/rc.local` and `/etc/init.d/*` run **as root at boot** —
even on pure-systemd hosts, via `systemd-rc-local-generator`
(rc.local) and `systemd-sysv-generator` (init.d). They are a
legacy boot-exec surface that is easy to overlook next to native
systemd units:

```
echo '/tmp/.p &' >> /etc/rc.local                  # runs at boot
cp /tmp/evil /etc/init.d/cups-helper; chmod +x ...  # + an rc?.d link
ln -s ../init.d/cups-helper /etc/rc5.d/S99cups-helper
```

This is the legacy-boot member of the persistence family,
alongside cron, systemd-unit, udev, shell-init, modprobe, and
network-dispatcher.

## Watched

| Target | What |
|---|---|
| `/etc/rc.local`, `/etc/rc.d/rc.local` | boot-time root script (T1037.004) |
| `/etc/init.d/*` | SysV init scripts |
| `/etc/rc{0..6}.d/*`, `/etc/rcS.d/*` | runlevel symlinks (enable/disable + link target) |

If none of these exist, the module no-ops cleanly
(`event:no_boot_scripts`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any boot-script change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No boot scripts present | `ok` | `no_boot_scripts` |
| No delta | `ok` | `boot_script_intact` |
| A script / symlink added, changed, or removed | `warn` | `boot_script_changed` |
| A script world-writable or non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `boot_script_suspicious` |

## What's recorded

- `file:<script>:<sha12>` — hash of rc.local + each init.d
  script.
- `own:<script>:<owner:mode>` — owner + mode. A boot script
  **world-writable** or **not owned by root** is hijackable into
  root execution — flagged hard.
- `susp:<script>:<pattern>` — a high-risk exec pattern
  (`curl|sh`, `/dev/tcp`, `nc -e`, `bash -i`, `base64 -d`, …);
  comment-only lines stripped first.
- `link:<rcd-link>:<target>` — each runlevel symlink's target,
  so an enable/disable or a symlink to a rogue script surfaces.

## Cadence

`OnBootSec=16min` + `OnCalendar=*-*-* 07:25:00` — extends the
staggered ladder after network-dispatcher (07:20). These scripts
run at boot, so the boot scan catches a boot-persistence edit on
its first opportunity.

## MITRE coverage

- **T1037.004** Boot or Logon Initialization Scripts: RC Scripts
  — PRIMARY for `/etc/rc.local`.
- **T1037** Boot or Logon Initialization Scripts — init.d /
  runlevel scripts run at boot.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the injected payload is shell execution.
- **T1543** Create or Modify System Process (adjacent) — a
  world-writable/non-root boot script is a privilege handle.

## Operator workflow

```bash
journalctl -t selfdef-boot-script -n 1 --no-pager
journalctl -t selfdef-boot-script-detail --since "1 day ago"

# Manual inventory
cat /etc/rc.local 2>/dev/null
ls -la /etc/init.d/ /etc/rc[0-6].d/ /etc/rcS.d/ 2>/dev/null

# Investigate a suspicious alert
# - world-writable / non-root script, or a curl|sh / reverse shell?
ls -l <script>; head -40 <script>
sudo rm <script>          # or remove the appended line from rc.local
sudo rm /var/lib/selfdef/boot-script-baseline.tsv
sudo systemctl start selfdef-boot-script.service

# Re-baseline after a legit init script (a package added one):
sudo rm /var/lib/selfdef/boot-script-baseline.tsv
sudo systemctl start selfdef-boot-script.service
```

## Caveats

- **Packages add init.d scripts + rc?.d symlinks** (legacy
  daemons). A new root-owned script with no suspicious pattern
  fires `warn` (re-baseline). The `suspicious` tier (writable /
  non-root / injection pattern) is the high-confidence one.
- **Daily+boot cadence** misses an inject-reboot-revert within
  the window; an audit-rules watch on `/etc/rc.local` +
  `/etc/init.d` writes is the real-time complement.
- **Pure-systemd hosts** may have no rc.local / init.d at all →
  `no_boot_scripts` no-op. The module is still worth enabling: it
  catches an attacker who CREATES rc.local to gain a generator-
  backed boot hook on an otherwise unit-only host.

## Coexistence

- **systemd-unit-watchdog**: watches NATIVE systemd units
  (ExecStart, enable state); this watches the LEGACY rc.local /
  init.d surface that systemd generators still execute. Together
  they cover both the modern and legacy boot-exec paths.
- **cron-job / udev-rules / shell-init / modprobe-config /
  network-dispatcher watchdogs**: the persistence-mechanism
  family — this adds the legacy-boot (T1037.004) surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the scripts; this adds the ownership + injection-pattern +
  symlink-target semantic view.
