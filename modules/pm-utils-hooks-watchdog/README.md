# pm-utils-hooks-watchdog

Boot + daily delta of the `pm-utils` power-event hook dirs against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches a script that runs as root on suspend/resume or AC/battery
transition under the pm-utils mechanism. MITRE **T1546**.

## Why this matters

`pm-action` and `pm-powersave` run every script in these dirs **as
root**:

- `/etc/pm/sleep.d/*` — around suspend / hibernate / thaw / resume
- `/etc/pm/power.d/*` — on AC ↔ battery transition
- `/etc/pm/config.d/*` — pm-utils config fragments

A dropped script self-triggers on routine power activity — lid
close, AC plug/unplug, idle suspend — with no operator action,
giving quiet recurring root execution.

`pm-utils` is a **third, independent power-event mechanism**
alongside systemd-logind and acpid. On hosts that still run pm-utils
(older Debian/derivatives, some XFCE/LXDE setups), this surface is
invisible to:

- **systemd-power-hooks-watchdog** — systemd `system-sleep` /
  `system-shutdown`,
- **acpi-hooks-watchdog** — acpid `events`/`actions`.

Together the three watchdogs cover all three power-event exec paths.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any pm-utils hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No pm-utils hooks present | `ok` | `no_pm_utils_hooks` |
| No delta | `ok` | `pm_utils_intact` |
| A script added / changed / removed | `warn` | `pm_utils_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `pm_utils_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=60min` + `OnCalendar=*-*-* 11:05:00` — extends the
staggered ladder after tmpfiles (11:00). A dropped hook
self-triggers on the next suspend/resume or AC/battery transition,
so the daily catch bounds dwell time; the boot catch confirms the
hook set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the power-state transition
  is the trigger; suspend/resume and AC events recur automatically.
- **T1059.004** — the hook is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-pm-utils -n 1 --no-pager
journalctl -t selfdef-pm-utils-detail --since "1 day ago"

# Inventory
ls -la /etc/pm/sleep.d/ /etc/pm/power.d/ /etc/pm/config.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/pm/sleep.d/<script>
sudo rm /var/lib/selfdef/pm-utils-hooks-baseline.tsv
sudo systemctl start selfdef-pm-utils.service
```

## Caveats

- **Packages ship legitimate hooks** (`sleep.d/00powersave`,
  `99video`, laptop-mode-tools); a new root-owned script with no
  suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **/usr/lib/pm-utils/{sleep,power}.d is not watched** — it is
  package-managed (integrity-sentinel / aide-bridge territory); this
  module watches the admin `/etc/pm` dirs an attacker would write to.
- **Pure-systemd hosts** have no `/etc/pm` → `no_pm_utils_hooks`
  no-op; their power-event exec is covered by
  systemd-power-hooks-watchdog (and acpid by acpi-hooks-watchdog).
- **Daily+boot cadence** misses a drop-suspend-revert inside the
  window; an audit-rules watch on the `/etc/pm` dirs' writes is the
  real-time complement.

## Coexistence

- **systemd-power-hooks-watchdog / acpi-hooks-watchdog**: the other
  two power-event exec mechanisms; this is the pm-utils one. The
  three together cover the full power-event root-exec surface.
- **xsession / display-manager / shell-init hooks**: login-time
  exec; this is power-event exec.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
