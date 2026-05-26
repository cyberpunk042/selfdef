# motd-scripts-watchdog

Boot + daily delta of the dynamic MOTD script dir
(`/etc/update-motd.d/*`) against a learned baseline, plus an
ownership + suspicious-pattern scan. Catches a script that runs
as root on every login. MITRE **T1546** / **T1037**.

## Why this matters

`pam_motd` runs the executable scripts in `/etc/update-motd.d/`
**as root** on every interactive login (SSH + console) to build
the dynamic message-of-the-day. A script added or tampered here
is reliable root-exec persistence that fires on each login — and
it is easy to overlook because it looks like cosmetic banner
config:

```
cp /tmp/p /etc/update-motd.d/99-evil
chmod +x /etc/update-motd.d/99-evil
# → runs as root on the next login
```

This is the login-time member of the persistence family
(alongside shell-init), but it runs as **root** regardless of
who logs in.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any motd-script change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No update-motd.d dir | `ok` | `no_motd_dir` |
| No delta | `ok` | `motd_scripts_intact` |
| A script added / changed / removed | `warn` | `motd_scripts_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `motd_scripts_suspicious` |

## What's recorded

- `file:<script>:<sha12>` — hash of each motd script.
- `own:<script>:<owner:mode>` — owner + mode. A world-writable
  or non-root script in update-motd.d is hijackable into
  root-on-login exec — flagged hard.
- `susp:<script>:<pattern>` — a high-risk exec pattern
  (`curl|sh`, `/dev/tcp`, `bash -i`, `base64 -d`, tmp/home
  execution, …); comment-only lines stripped first.

## Cadence

`OnBootSec=24min` + `OnCalendar=*-*-* 08:05:00` — extends the
staggered ladder after polkit-rules (08:00). A motd script fires
on the next interactive login, so the boot catch confirms the
set after a restart.

## MITRE coverage

- **T1546** Event Triggered Execution — login is the trigger
  that runs the motd script as root.
- **T1037** Boot or Logon Initialization Scripts — runs at
  logon, as root.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the script/pattern is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-motd-scripts -n 1 --no-pager
journalctl -t selfdef-motd-scripts-detail --since "1 day ago"

# Inventory (package scripts: 00-header, 10-help-text, …)
ls -la /etc/update-motd.d/

# Investigate a suspicious alert
ls -l <script>; head -40 <script>
sudo rm <script>          # or restore the package version
sudo rm /var/lib/selfdef/motd-scripts-baseline.tsv
sudo systemctl start selfdef-motd-scripts.service

# Re-baseline after a legit motd change (e.g. motd-doctrine wrote
# its presence banner): re-run the service once.
```

## Caveats

- **Package scripts populate this dir** (Ubuntu ships
  `00-header`, `10-help-text`, `50-motd-news`, …); a new
  root-owned script with no suspicious pattern fires `warn`
  (re-baseline). The `suspicious` tier (writable / non-root /
  injection pattern) is the high-confidence one.
- **`50-motd-news`** legitimately fetches remote content over
  HTTPS via the news service — its body is package-shipped and
  baselined; a hash CHANGE to it is `warn` (review), and the
  pattern scan does not match its (non-shell-injection) fetch.
- **Daily+boot cadence** misses an inject-login-revert within the
  window; an audit-rules watch on `/etc/update-motd.d` writes is
  the real-time complement.

## Coexistence

- **motd-doctrine**: WRITES the selfdef presence banner into
  this dir (prevention/presence); this DETECTS rogue/tampered
  scripts. The doctrine banner is baselined here and a tamper to
  it surfaces. Presence + detection pair.
- **shell-init-watchdog**: the per-user login-script surface
  (profile/bashrc, runs as the user); update-motd.d runs as
  ROOT regardless of who logs in. Both login-time exec surfaces.
- **boot-script / cron / udev / systemd-unit / network-dispatcher
  watchdogs**: the persistence-mechanism family — this adds the
  motd login-banner root-exec surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the scripts; this adds the ownership + injection-pattern
  semantic view.
