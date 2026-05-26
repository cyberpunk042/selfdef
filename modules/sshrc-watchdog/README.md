# sshrc-watchdog

Boot + daily delta of the SSH login rc scripts against a learned
baseline, plus an ownership + suspicious-pattern scan. Catches a
script `sshd` runs on every SSH login. MITRE **T1546** / **T1037**.

## Why this matters

`sshd` runs these **as the logging-in user** on every SSH session:

- `/etc/ssh/sshrc` — run for any user that has **no** `~/.ssh/rc`
- `~/.ssh/rc` — run *instead of* `/etc/ssh/sshrc` when present
  (root's `~/.ssh/rc` is watched here; per-user rc files are the
  home-dir surface)

`sshrc` runs **before** the user's shell rc, on **every** SSH login.
A planted `/etc/ssh/sshrc` is therefore exec-on-every-SSH-login
persistence affecting every account that lacks its own `~/.ssh/rc` —
a quiet, high-reach foothold that survives shell-rc cleanups.

This is distinct from the other SSH/login watchdogs:

- **sshd-config-watchdog** — `sshd_config` (daemon policy),
- **ssh-authkeys-watchdog** — `authorized_keys` (who may log in),
- **ssh-client-config-watchdog** — `ssh_config` (outbound client),
- **shell-init-watchdog** — bash/profile rc (shell startup).

`sshrc` is the **sshd-invoked per-login rc** none of those cover.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any sshrc change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No sshrc present | `ok` | `no_sshrc` |
| No delta | `ok` | `sshrc_intact` |
| An rc added / changed / removed | `warn` | `sshrc_changed` |
| An rc world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `sshrc_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each rc.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=61min` + `OnCalendar=*-*-* 11:10:00` — extends the
staggered ladder after pm-utils (11:05). A planted sshrc fires on
the next SSH login, so the boot catch confirms the rc set after a
restart and the daily catch bounds dwell time on a rarely-rebooted
host.

## MITRE coverage

- **T1546** Event Triggered Execution — the SSH login is the
  trigger.
- **T1037** Boot or Logon Initialization Scripts — sshrc is a
  logon-time init script.
- **T1059.004** — the rc is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-sshrc -n 1 --no-pager
journalctl -t selfdef-sshrc-detail --since "1 day ago"

# Inspect
for f in /etc/ssh/sshrc /root/.ssh/rc; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/ssh/sshrc
sudo rm /var/lib/selfdef/sshrc-baseline.tsv
sudo systemctl start selfdef-sshrc.service
```

## Caveats

- **`sshrc` is usually absent** on a default install → `no_sshrc`
  no-op until something creates it. Its mere appearance is worth a
  `warn` review; the writable/non-root/injection tiers are the
  high-confidence alert.
- **A legitimate `/etc/ssh/sshrc`** exists on some hardened hosts
  (e.g. to set up an X11 cookie or log the session); re-baseline
  after a deliberate edit.
- **Per-user `~/.ssh/rc`** (non-root) is the home-dir surface — this
  module watches the system `/etc/ssh/sshrc` and root's rc; a
  full per-user sweep is a home-dir-walk complement.
- **Daily+boot cadence** misses a drop-login-revert inside the
  window; an audit-rules watch on `/etc/ssh/sshrc` writes is the
  real-time complement.

## Coexistence

- **sshd-config / ssh-authkeys / ssh-hostkey / ssh-moduli /
  ssh-client-config watchdogs**: the SSH daemon-policy, key, and
  client surfaces; this is the per-login rc exec surface that
  completes the SSH set.
- **shell-init-watchdog / motd-scripts-watchdog**: shell-rc and
  MOTD login-time exec; this adds the sshd-invoked rc.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  rc; this adds the ownership + injection-pattern view.
