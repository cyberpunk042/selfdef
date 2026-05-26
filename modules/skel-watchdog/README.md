# skel-watchdog

Boot + daily recursive delta of `/etc/skel` against a learned
baseline, plus an ownership + suspicious-pattern scan. Catches a
file planted in the new-account template that would backdoor every
future user. MITRE **T1546.004** / **T1136**.

## Why this matters

`/etc/skel` is the skeleton tree copied verbatim into every **new**
user's home directory at account creation (`useradd -m`, `adduser`).
Anything dropped here is inherited by every future account and runs
the first time that user logs in or opens a shell:

- `.bashrc`, `.bash_profile`, `.profile`, `.bash_login`, `.bash_logout`
- `.zshrc`, `.zprofile`, `.zlogin`
- `.config/autostart/*.desktop`, `.xprofile`, `.xsession`
- anything else an attacker chooses to seed

A tampered or added skel file is **future-account exec persistence**:
the payload lies dormant until the next account is created, then
fires on that user's first login — long after the intrusion. This is
distinct from:

- **shell-init-watchdog** — watches *existing* root/global rc that
  runs now.
- **xdg-autostart-watchdog** — watches the *live* session's
  `.desktop` autostart.

This watches the **template for accounts that don't exist yet**.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any skel change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/skel` (or empty) | `ok` | `no_skel` |
| No delta | `ok` | `skel_intact` |
| A file added / changed / removed | `warn` | `skel_changed` |
| A file world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `skel_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each regular file under `/etc/skel`
  (recursive — catches `.config/autostart/*.desktop` etc.).
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, tmp/dev-shm execution, …);
  comment-only lines stripped first.

## Cadence

`OnBootSec=47min` + `OnCalendar=*-*-* 10:00:00` — extends the
staggered ladder after xsession-watchdog (09:55). A planted skel
file only fires when a new account is created, so the daily catch
is the right cadence; the boot catch confirms the template set
after a restart.

## MITRE coverage

- **T1546.004** Event Triggered Execution: Unix Shell Configuration
  Modification — the seeded dotfile is shell-init persistence.
- **T1136** Create Account — skel is the template every newly
  created local account inherits.
- **T1059.004** — the file/pattern is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-skel -n 1 --no-pager
journalctl -t selfdef-skel-detail --since "1 day ago"

# Inventory
find /etc/skel -type f -exec ls -la {} +
for f in /etc/skel/.bashrc /etc/skel/.profile /etc/skel/.bash_profile; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/skel/<file>
sudo rm /var/lib/selfdef/skel-baseline.tsv
sudo systemctl start selfdef-skel.service
```

## Caveats

- **Distro/desktop packages populate `/etc/skel`** (a fresh GNOME
  install seeds `.config/`); a new root-owned file with no
  suspicious pattern fires `warn` (re-baseline). The
  writable/non-root/injection tiers are the high-confidence alert.
- **Minimal/container images** often have an empty or absent
  `/etc/skel` → `no_skel` no-op.
- **Daily+boot cadence** misses a seed-create-account-revert inside
  the window; an audit-rules watch on `/etc/skel` writes is the
  real-time complement.

## Coexistence

- **shell-init-watchdog**: existing root/global login rc; this is
  the future-account template surface. Both shell-init exec vectors.
- **xdg-autostart-watchdog / xsession-watchdog**: live-session
  autostart and X-session-startup scripts; this is the seed-for-new-
  accounts surface that those inherit.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  skel tree; this adds the ownership + injection-pattern view.
