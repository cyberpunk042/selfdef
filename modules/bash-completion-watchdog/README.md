# bash-completion-watchdog

Boot + daily delta of the bash-completion drop-in dir against a
learned baseline, plus an ownership + suspicious-pattern scan.
Catches a file that gets sourced into every interactive bash shell.
MITRE **T1546**.

## Why this matters

The `bash-completion` package **sources** every file in
`/etc/bash_completion.d/*` into interactive bash shells — eagerly on
older versions, lazily on first `<Tab>` completion on newer ones. A
planted file there runs **arbitrary code in the context of every
interactive bash session**, for every user — a foothold that
survives cleanups of the obvious rc files and is rarely inspected.

This is distinct from **shell-init-watchdog**, which covers
`/etc/profile`, `/etc/bash.bashrc`, `/etc/profile.d/*`, and the zsh
global rc files. The bash-completion drop-in dir is a separate
code-execution surface those do not watch.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any bash-completion change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/bash_completion.d` present | `ok` | `no_bash_completion` |
| No delta | `ok` | `bash_completion_intact` |
| A file added / changed / removed | `warn` | `bash_completion_changed` |
| A file world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `bash_completion_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each drop-in.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=66min` + `OnCalendar=*-*-* 11:40:00` — extends the
staggered ladder after fail2ban-action (11:30). A planted completion
file runs in the next interactive bash session, so the boot catch
confirms the set after a restart and the daily catch bounds dwell
time on a long-running host.

## MITRE coverage

- **T1546** Event Triggered Execution — opening an interactive bash
  shell (or triggering completion) is the trigger.
- **T1059.004** — the drop-in is shell code sourced into the
  session.

## Operator workflow

```bash
journalctl -t selfdef-bash-completion -n 1 --no-pager
journalctl -t selfdef-bash-completion-detail --since "1 day ago"

# Inventory
ls -la /etc/bash_completion.d/ 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/bash_completion.d/<file>
sudo rm /var/lib/selfdef/bash-completion-baseline.tsv
sudo systemctl start selfdef-bash-completion.service
```

## Caveats

- **Many packages ship legitimate completions** here (git, docker,
  kubectl, etc.); a new root-owned completion with no suspicious
  pattern fires `warn` (re-baseline). The writable/non-root/injection
  tiers are the high-confidence alert.
- **/usr/share/bash-completion/completions/ is not watched** — it is
  package-managed and loaded lazily by completion name
  (integrity-sentinel / aide-bridge territory); this module watches
  the admin-droppable `/etc/bash_completion.d` that is sourced
  eagerly.
- **Completions are sourced, not executed** — a non-executable file
  is still dangerous here (the danger is the source, not the +x
  bit), so this module hashes/scans content regardless of mode.
- **Daily+boot cadence** misses a drop-shell-revert inside the
  window; an audit-rules watch on `/etc/bash_completion.d` writes is
  the real-time complement.

## Coexistence

- **shell-init-watchdog**: /etc/profile, bashrc, profile.d, zsh
  global rc; this is the bash-completion drop-in surface — together
  they cover the global interactive-shell startup exec set.
- **motd-scripts / sshrc / xsession watchdogs**: other login-time
  exec surfaces; this is the per-interactive-shell one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  drop-ins; this adds the ownership + injection-pattern view.
