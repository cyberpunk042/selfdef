# xdg-autostart-watchdog

Boot + daily delta of the XDG desktop autostart entries
(`/etc/xdg/autostart/*.desktop` + root's `~/.config/autostart` +
local) against a learned baseline, plus an ownership + Exec scan.
Catches a `.desktop` entry that runs on graphical login. MITRE
**T1547.013** (XDG Autostart Entries).

## Why this matters

Every `.desktop` file in an autostart dir with an `Exec=` line is
launched by the desktop session on each graphical login. A
dropped or tampered entry is GUI-login persistence:

```ini
# /etc/xdg/autostart/evil.desktop
[Desktop Entry]
Type=Application
Exec=/tmp/.payload
X-GNOME-Autostart-enabled=true
```

This is the desktop login member of the persistence family
(alongside shell-init for shell login and motd-scripts for
SSH/console login). It no-ops on headless servers and matters on
workstation deployments.

## Watched directories

| Directory | Watched | Why |
|---|---|---|
| `/etc/xdg/autostart/*.desktop` | **yes** | system autostart |
| `/usr/local/share/applications/autostart/*.desktop` | **yes** | local |
| `/root/.config/autostart/*.desktop` | **yes** | root's per-user autostart |

No-ops cleanly if none exist (`event:no_autostart_dirs`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any autostart change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No autostart dirs present | `ok` | `no_autostart_dirs` |
| No delta | `ok` | `xdg_autostart_intact` |
| A `.desktop` added / changed / removed | `warn` | `xdg_autostart_changed` |
| An Exec target under /tmp /home /dev/shm, world-writable, or a relative-with-slash path; a fetch-pipe-shell payload; or a world-writable/non-root `.desktop` | `alert` | `xdg_autostart_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.desktop`.
- `own:<path>:<owner:mode>` — owner + mode.
- `exec:<file>:<prog>` — the `Exec=` program (first token;
  `%`-field-codes and bare PATH commands are not flagged — only
  suspicious targets/payloads/ownership are).

## Cadence

`OnBootSec=30min` + `OnCalendar=*-*-* 08:35:00` — extends the
staggered ladder after ssh-client-config (08:30). An entry fires
on the next graphical login, so the boot catch confirms the set
after a restart.

## MITRE coverage

- **T1547.013** Boot or Logon Autostart Execution: XDG Autostart
  Entries — PRIMARY.
- **T1059.004** — the `Exec=` is command execution.
- **T1546** Event Triggered Execution (adjacent) — graphical
  login is the trigger.

## Operator workflow

```bash
journalctl -t selfdef-xdg-autostart -n 1 --no-pager
journalctl -t selfdef-xdg-autostart-detail --since "1 day ago"

# Inventory
grep -rHE '^(Exec|Name)=' /etc/xdg/autostart/ /root/.config/autostart/ 2>/dev/null

# Investigate a suspicious alert
cat <file>            # Exec under /tmp? world-writable .desktop?
sudo rm <file>
sudo rm /var/lib/selfdef/xdg-autostart-baseline.tsv
sudo systemctl start selfdef-xdg-autostart.service
```

## Caveats

- **Desktop environments populate `/etc/xdg/autostart`** with many
  legit entries; a new root-owned entry with a normal Exec fires
  `warn` (re-baseline). The `suspicious` tier (tmp/writable target,
  payload, non-root/world-writable file) is the high-confidence
  one.
- **Headless servers** have no autostart dirs → `no_autostart_dirs`
  no-op. The module is workstation-deployment coverage and catches
  an attacker who creates one.
- **Daily+boot cadence** misses an inject-login-revert within the
  window; an audit-rules watch on the autostart dirs' writes is
  the real-time complement.

## Coexistence

- **shell-init-watchdog / motd-scripts-watchdog**: shell-login and
  SSH/console-login exec surfaces; this adds the graphical-login
  (XDG autostart) surface. The three login-time persistence
  vectors.
- **systemd-unit-watchdog**: a systemd `--user` unit is the other
  per-user autostart path; this covers the XDG `.desktop` path.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the `.desktop` files; this adds the Exec + ownership semantic
  view.
