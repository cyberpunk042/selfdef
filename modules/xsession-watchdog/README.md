# xsession-watchdog

Boot + daily delta of the X11 session-init scripts against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches a script that runs on graphical login. MITRE **T1037** /
**T1546**.

## Why this matters

These run on every graphical login, **during session startup**,
as the logging-in user (root for a root login):

- `/etc/X11/Xsession.d/*` — the Debian X session pipeline
- `/etc/X11/xinit/xinitrc.d/*` — xinit/startx
- `/etc/X11/xinit/{xinitrc,Xclients}`, `/etc/X11/Xsession`
- `~/.xsession`, `~/.Xsession`, `~/.xprofile`, `~/.xinitrc` (root)

A dropped or tampered script is GUI-login exec persistence. This
is distinct from `xdg-autostart-watchdog`: Xsession.d runs *during
session startup* (sourced by the display manager / startx), while
XDG autostart `.desktop` entries are launched *after* the session
is up.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any xsession change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No X session scripts | `ok` | `no_xsession` |
| No delta | `ok` | `xsession_intact` |
| A script added / changed / removed | `warn` | `xsession_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `xsession_suspicious` |

## What's recorded

- `file:<script>:<sha12>` — hash of each script.
- `own:<script>:<owner:mode>` — owner + mode.
- `susp:<script>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, tmp/dev-shm execution, …);
  comment-only lines stripped first.

## Cadence

`OnBootSec=46min` + `OnCalendar=*-*-* 09:55:00` — extends the
staggered ladder after syslog-ng-exec (09:50). A rogue script
fires on the next graphical login, so the boot catch confirms the
set after a restart.

## MITRE coverage

- **T1037** Boot or Logon Initialization Scripts — runs at
  graphical logon.
- **T1546** Event Triggered Execution — graphical login is the
  trigger.
- **T1059.004** — the script/pattern is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-xsession -n 1 --no-pager
journalctl -t selfdef-xsession-detail --since "1 day ago"

# Inventory
ls -la /etc/X11/Xsession.d/ /etc/X11/xinit/xinitrc.d/ 2>/dev/null
for f in /root/.xsession /root/.xprofile /root/.xinitrc; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <script>
sudo rm /var/lib/selfdef/xsession-baseline.tsv
sudo systemctl start selfdef-xsession.service
```

## Caveats

- **Desktop packages populate Xsession.d / xinitrc.d**; a new
  root-owned script with no suspicious pattern fires `warn`
  (re-baseline). The writable/non-root/injection tiers are the
  high-confidence alert.
- **Headless servers** have no X session scripts → `no_xsession`
  no-op; workstation-deployment coverage.
- **Daily+boot cadence** misses an inject-login-revert within the
  window; an audit-rules watch on the X session dirs' writes is
  the real-time complement.

## Coexistence

- **xdg-autostart-watchdog**: post-startup `.desktop` autostart;
  this is the session-STARTUP script surface. Both graphical-login
  exec vectors.
- **shell-init-watchdog / motd-scripts-watchdog**: shell-login and
  SSH/console-login exec; this completes the login-time
  persistence set with the X-session-startup surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the scripts; this adds the ownership + injection-pattern view.
