# csh-config-watchdog

Boot + daily delta of the csh/tcsh global init files against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches a snippet sourced into every csh/tcsh session. MITRE
**T1546**.

## Why this matters

`csh` and `tcsh` source these global init files:

- `/etc/csh.cshrc` — on **every** invocation (interactive or
  script)
- `/etc/csh.login` — at login
- `/etc/csh.logout` — at logout

A planted snippet runs in every csh/tcsh session — the same
interactive-shell persistence idea as a poisoned `.bashrc`. csh/tcsh
is less common on Linux than bash, but is the default interactive
shell on several BSD-derived environments and is still installed on
many hosts; `/etc/csh.cshrc` running on *every* invocation makes it
a high-reach foothold where present.

This **completes the global interactive-shell-init quartet**:

- **shell-init-watchdog** — bash/zsh global rc
- **bash-completion-watchdog** — bash completion drop-ins
- **fish-config-watchdog** — fish global config
- **csh-config-watchdog** — csh/tcsh global init (this module)

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any csh init change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No csh init files present | `ok` | `no_csh_config` |
| No delta | `ok` | `csh_config_intact` |
| An init file added / changed / removed | `warn` | `csh_config_changed` |
| An init file world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `csh_config_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each init file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval ...`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=69min` + `OnCalendar=*-*-* 12:00:00` — extends the
staggered ladder after hosts-allow (11:50). A planted snippet runs
in the next csh/tcsh session, so the boot catch confirms the set
after a restart and the daily catch bounds dwell time on a
long-running host.

## MITRE coverage

- **T1546** Event Triggered Execution — starting a csh/tcsh shell is
  the trigger.
- **T1059** — the snippet is csh-shell code sourced into the
  session.

## Operator workflow

```bash
journalctl -t selfdef-csh-config -n 1 --no-pager
journalctl -t selfdef-csh-config-detail --since "1 day ago"

# Inspect
for f in /etc/csh.cshrc /etc/csh.login /etc/csh.logout; do
  [ -f "$f" ] && echo "== $f ==" && cat "$f"; done

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/csh.cshrc
sudo rm /var/lib/selfdef/csh-config-baseline.tsv
sudo systemctl start selfdef-csh-config.service
```

## Caveats

- **csh/tcsh may not be installed** → `no_csh_config` no-op. The
  files' appearance on a bash-only host is itself worth a `warn`
  review.
- **Legit `/etc/csh.cshrc`** ships with the tcsh package; re-baseline
  after a deliberate edit.
- **Per-user `~/.cshrc` / `~/.tcshrc` / `~/.login`** are the home-dir
  surface — this module watches the system files; a per-user sweep is
  the home-dir-walk complement.
- **Daily+boot cadence** misses a drop-shell-revert inside the
  window; an audit-rules watch on the csh init files' writes is the
  real-time complement.

## Coexistence

- **shell-init-watchdog / bash-completion-watchdog /
  fish-config-watchdog**: the bash/zsh, bash-completion, and fish
  surfaces; this is the csh/tcsh one — together the four cover the
  global interactive-shell startup exec set across all four common
  shells.
- **sshrc / motd-scripts / xsession watchdogs**: other login-time
  exec surfaces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  init files; this adds the ownership + injection-pattern view.
