# inittab-watchdog

Boot + daily delta of the SysV init config (`/etc/inittab` +
`/etc/init/*.conf` upstart jobs) against a learned baseline, plus
an ownership + process scan. Catches a self-respawning boot
process. MITRE **T1037** (Boot or Logon Initialization Scripts).

## Why this matters

On SysV/upstart init, an `/etc/inittab` line runs a process as
root at boot and — with the `respawn` action — restarts it
whenever it exits:

```
id:runlevels:action:process
x1:5:respawn:/tmp/.payload        # root at boot, auto-restarts
```

That is self-healing boot persistence: kill the payload and init
brings it back. The exec actions are `respawn`, `once`, `wait`,
`boot`, `bootwait`, `sysinit`, `powerwait`, `powerfail`
(`initdefault`, `ctrlaltdel`, `off` carry no payload). Upstart
`/etc/init/*.conf` jobs `exec` a command similarly.

No-ops on systemd hosts (no `/etc/inittab`); matters on the
legacy/embedded systems selfdef also targets.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any inittab change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No inittab/upstart | `ok` | `no_inittab` |
| No delta | `ok` | `inittab_intact` |
| An entry / file added, removed, or changed | `warn` | `inittab_changed` |
| An exec process under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root inittab | `alert` | `inittab_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of inittab / upstart conf.
- `own:<path>:<owner:mode>` — owner + mode.
- `inittab:<id>:<action>:<prog>` — each exec entry's process
  (first token); only payload-bearing actions are recorded.

## Cadence

`OnBootSec=43min` + `OnCalendar=*-*-* 09:40:00` — extends the
staggered ladder after dnf-plugins (09:35). A respawn line runs +
re-spawns at the next boot on a SysV/upstart host, so the boot
catch confirms the config after a restart.

## MITRE coverage

- **T1037** Boot or Logon Initialization Scripts — inittab/upstart
  run the process at boot, as root.
- **T1059.004** — the process is command execution.
- **T1543** (adjacent) — `respawn` makes it a self-restarting
  service-like persistence.

## Operator workflow

```bash
journalctl -t selfdef-inittab -n 1 --no-pager
journalctl -t selfdef-inittab-detail --since "1 day ago"

# Inventory (SysV/upstart hosts)
grep -vE '^\s*#|^\s*$' /etc/inittab 2>/dev/null
ls /etc/init/*.conf 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/inittab          # remove the rogue respawn line
sudo telinit q                     # reload inittab
sudo rm /var/lib/selfdef/inittab-baseline.tsv
sudo systemctl start selfdef-inittab.service
```

## Caveats

- **systemd hosts have no /etc/inittab** → `no_inittab` no-op; the
  module is legacy/embedded coverage and catches an attacker who
  CREATES one on a host with a SysV-compat init.
- **Standard inittab entries** (getty respawns, initdefault) are
  baselined; a new entry or changed process fires `warn`, and the
  tmp/relative-process + injection + ownership tiers are the alert.
- **Daily+boot cadence** misses an inject-reboot-revert within the
  window; an audit-rules watch on `/etc/inittab` writes is the
  real-time complement.

## Coexistence

- **boot-script-watchdog**: rc.local / init.d / rc?.d (SysV
  service scripts); this covers `/etc/inittab` itself (the init
  process table) + upstart jobs. Both legacy-boot surfaces.
- **systemd-unit / systemd-generator watchdogs**: the modern
  init; this is the SysV/upstart init. Complementary init-system
  views.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  inittab; this adds the per-entry process semantic view.
