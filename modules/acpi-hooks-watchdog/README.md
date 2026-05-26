# acpi-hooks-watchdog

Boot + daily delta of the acpid event-binding + action-script
surface against a learned baseline, plus an ownership +
suspicious-pattern scan. Catches a script (or event binding) that
runs as root on an ACPI hardware event. MITRE **T1546**.

## Why this matters

`acpid` runs the bound action **as root** on each ACPI hardware
event — power button, lid open/close, AC adapter plug/unplug,
thermal trip:

- `/etc/acpi/events/*` — event bindings of the form
  `event=<regex>` + `action=<command>`. A new binding whose
  `action=` points at attacker code is exec persistence.
- `/etc/acpi/actions/*` — the action scripts those bindings invoke.
- `/etc/acpi/*.sh` — top-level handlers (`handler.sh`,
  `powerbtn.sh`, `lid.sh`, …).

A dropped action script — or a new event binding — self-triggers on
routine hardware activity (someone presses the power button,
unplugs the laptop) with no operator action, giving root execution.

`acpid` is a **separate daemon from systemd-logind**, so this is
distinct from **systemd-power-hooks-watchdog** (which watches
systemd's `system-sleep`/`system-shutdown` dirs). On hosts running
both, the two cover different code paths to root-on-power-event.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any acpi-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No acpid hooks present | `ok` | `no_acpi_hooks` |
| No delta | `ok` | `acpi_hooks_intact` |
| A file added / changed / removed | `warn` | `acpi_hooks_changed` |
| A file world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `acpi_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=55min` + `OnCalendar=*-*-* 10:40:00` — extends the
staggered ladder after resolvconf-hooks (10:35). A dropped acpid
action/binding self-triggers on the next ACPI event, so the daily
catch bounds dwell time; the boot catch confirms the hook set after
a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — the ACPI hardware event is
  the trigger.
- **T1059.004** — the action is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-acpi-hooks -n 1 --no-pager
journalctl -t selfdef-acpi-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/acpi/events/ /etc/acpi/actions/ 2>/dev/null
for f in /etc/acpi/handler.sh /etc/acpi/powerbtn.sh; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done
grep -rH '^action=' /etc/acpi/events/ 2>/dev/null   # what each event runs

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <file>
sudo rm /var/lib/selfdef/acpi-hooks-baseline.tsv
sudo systemctl start selfdef-acpi-hooks.service
```

## Caveats

- **Distro packages ship legitimate hooks** (`powerbtn`,
  `lid.sh`, `handler.sh`); a new root-owned file with no suspicious
  pattern fires `warn` (re-baseline). The writable/non-root/injection
  tiers are the high-confidence alert.
- **Hosts without acpid** (pure systemd power handling) have no
  `/etc/acpi` hooks → `no_acpi_hooks` no-op; their power-event exec
  is covered by systemd-power-hooks-watchdog.
- **Event bindings vs scripts:** an `action=` line pointing at an
  external script is flagged as a content change in the binding
  file; the target script (if under a watched dir) is also tracked.
  A target outside the watched dirs is visible only as the changed
  binding — investigate the `action=` path.
- **Daily+boot cadence** misses a drop-trigger-revert inside the
  window; an audit-rules watch on `/etc/acpi` writes is the
  real-time complement.

## Coexistence

- **systemd-power-hooks-watchdog**: systemd system-sleep/
  system-shutdown; this is the acpid daemon's event/action surface —
  a different code path to root-on-power-event.
- **xsession / xdg-autostart / display-manager hooks**: login-time
  exec; this is hardware-event exec.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
