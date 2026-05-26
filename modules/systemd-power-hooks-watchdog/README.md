# systemd-power-hooks-watchdog

Boot + daily delta of the systemd power-event exec dirs
(`system-sleep` + `system-shutdown`) against a learned baseline,
plus an ownership + suspicious-pattern scan. Catches a script that
runs as root on suspend/resume or at power-off. MITRE **T1546**.

## Why this matters

systemd runs **every executable** in these dirs **as root** on a
power-state transition:

- `system-sleep/*` — invoked with `pre`/`post` plus the verb
  (`suspend`, `hibernate`, `hybrid-sleep`, `suspend-then-hibernate`)
  around every sleep cycle.
- `system-shutdown/*` — invoked at `halt` / `poweroff` / `reboot` /
  `kexec`, as one of the last things that runs before power-off.

searched under `/usr/lib/systemd`, `/lib/systemd`, and
`/etc/systemd`. The key property: **suspend/resume fires
automatically** — laptop lid close, idle timer, `systemctl suspend`
— so a dropped sleep hook self-triggers with no operator action,
giving quiet recurring root execution. A shutdown hook runs at the
last moment before the box powers off (useful for anti-forensics or
a "dead man" payload).

This is distinct from **systemd-generator-watchdog** (unit
generators run at every daemon-reload) and **systemd-unit-watchdog**
(the unit files themselves).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any power-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No power-hook dirs present | `ok` | `no_power_hooks` |
| No delta | `ok` | `power_hooks_intact` |
| A script added / changed / removed | `warn` | `power_hooks_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `power_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

Symlinked dirs (`/lib/systemd` → `/usr/lib/systemd`) are
de-duplicated by resolved real path so each file is recorded once.

## Cadence

`OnBootSec=51min` + `OnCalendar=*-*-* 10:20:00` — extends the
staggered ladder after initramfs-hooks (10:15). A dropped sleep hook
self-triggers on the next suspend/resume and a shutdown hook runs at
the next power-off, so the daily catch bounds dwell time; the boot
catch confirms the hook set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the power-state transition
  is the trigger, and suspend/resume is automatic/recurring.
- **T1059.004** — the hook is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-systemd-power-hooks -n 1 --no-pager
journalctl -t selfdef-systemd-power-hooks-detail --since "1 day ago"

# Inventory
ls -la /usr/lib/systemd/system-sleep/ /etc/systemd/system-sleep/ \
       /usr/lib/systemd/system-shutdown/ /etc/systemd/system-shutdown/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <script>
sudo rm /var/lib/selfdef/systemd-power-hooks-baseline.tsv
sudo systemctl start selfdef-systemd-power-hooks.service
```

## Caveats

- **Packages ship legitimate hooks** (e.g. `nvidia` and `mariadb`
  ship `system-sleep` scripts; `grub`/`systemd` ship
  `system-shutdown` helpers); a new root-owned hook with no
  suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Headless servers** that never suspend still execute
  `system-shutdown` hooks at reboot; the dirs are usually empty →
  `no_power_hooks` no-op until something populates them.
- **Daily+boot cadence** misses a drop-suspend-revert inside the
  window; an audit-rules watch on the dirs' writes is the real-time
  complement.

## Coexistence

- **systemd-generator-watchdog / systemd-unit-watchdog**: unit
  generators and unit files; this is the power-event exec-dir
  surface — a different systemd execution path.
- **acpi / logind handler config**: this watches the scripts those
  events run, not the event-binding config.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
