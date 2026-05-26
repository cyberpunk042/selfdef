# display-manager-hooks-watchdog

Boot + daily delta of the display-manager **root-context**
login-hook scripts against a learned baseline, plus an ownership +
suspicious-pattern scan. Catches a script the display manager runs
as root around every graphical login. MITRE **T1037** / **T1546**.

## Why this matters

The display manager runs these scripts **as root** around every
graphical login — a more privileged surface than the user's own X
session:

- **gdm** — `/etc/gdm3/{Init,PreSession,PostSession,PostLogin}/*`
  (Debian/Ubuntu) and the `/etc/gdm/*` equivalents (RHEL/Fedora):
  - `Init/*` runs before the greeter,
  - `PreSession/*` runs before the user session starts,
  - `PostLogin/*` runs after authentication,
  - `PostSession/*` runs at logout.
  All as **root**.
- **sddm** — `/usr/share/sddm/scripts/Xsetup` (before greeter) and
  `Xstop` (after session), plus `/etc/sddm/scripts/*`. Run as root.

A dropped or tampered script here is **root-context** GUI-login
exec persistence. This is distinct from:

- **xsession-watchdog** — the **user-context** X session pipeline
  (`/etc/X11/Xsession.d/*`, run as the logging-in user).
- **xdg-autostart-watchdog** — post-startup user `.desktop`
  autostart.

This watchdog covers the privileged **DM-side** scripts those two
do not see.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any DM-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No display-manager hooks present | `ok` | `no_dm_hooks` |
| No delta | `ok` | `dm_hooks_intact` |
| A script added / changed / removed | `warn` | `dm_hooks_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `dm_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

`gdm3` → `gdm` symlinked dirs are de-duplicated by resolved real
path.

## Cadence

`OnBootSec=52min` + `OnCalendar=*-*-* 10:25:00` — extends the
staggered ladder after systemd-power-hooks (10:20). A dropped DM
hook fires on the next graphical login; the boot catch confirms the
set after a restart and the daily catch bounds dwell time on a
long-running session host.

## MITRE coverage

- **T1037** Boot or Logon Initialization Scripts — runs at
  graphical logon, as root.
- **T1546** Event Triggered Execution — graphical login is the
  trigger.
- **T1059.004** — the script is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-dm-hooks -n 1 --no-pager
journalctl -t selfdef-dm-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/gdm3/Init/ /etc/gdm3/PreSession/ /etc/gdm3/PostLogin/ \
       /usr/share/sddm/scripts/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <script>
sudo rm /var/lib/selfdef/display-manager-hooks-baseline.tsv
sudo systemctl start selfdef-dm-hooks.service
```

## Caveats

- **gdm ships a `Default` script** in `Init`/`PreSession`/
  `PostSession` (sets up XKB, AccessX, etc.); a new root-owned
  script with no suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Headless servers** and hosts with no display manager have no
  hook dirs → `no_dm_hooks` no-op; workstation-deployment coverage.
- **lightdm** binds its `greeter-setup-script` /
  `session-setup-script` via config keys rather than a drop-dir, so
  it is covered by config-watching rather than this dir scan; a
  future `lightdm.conf` watcher is the complement.
- **Daily+boot cadence** misses an inject-login-revert inside the
  window; an audit-rules watch on the DM hook dirs' writes is the
  real-time complement.

## Coexistence

- **xsession-watchdog**: user-context X session pipeline;
  **xdg-autostart-watchdog**: user `.desktop` autostart. This is the
  privileged DM-side login surface those two omit — together the
  three cover the graphical-login exec triangle (DM-root / X-session
  / autostart).
- **shell-init-watchdog / motd-scripts-watchdog**: console/SSH login
  exec; this completes login-time persistence with the
  graphical-DM-root surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
