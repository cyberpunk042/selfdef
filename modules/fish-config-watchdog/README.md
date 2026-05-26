# fish-config-watchdog

Boot + daily delta of the fish shell global config against a learned
baseline, plus an ownership + suspicious-pattern scan. Catches a
snippet sourced into every interactive fish session. MITRE
**T1546**.

## Why this matters

`fish` sources these at the start of each interactive (and login)
fish session, and auto-loads functions by name on demand:

- `/etc/fish/config.fish` — global startup config
- `/etc/fish/conf.d/*.fish` — sourced at startup (sorted by name)
- `/etc/fish/functions/*.fish` — auto-loaded by function name

A planted snippet runs **in the context of every fish session** —
the same interactive-shell persistence idea as a poisoned
`.bashrc`, but for the growing fish user base, and in a dir set the
bash/zsh watchdogs don't look at.

This **completes the interactive-shell-init set**:

- **shell-init-watchdog** — bash/zsh global rc
  (`/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/*`)
- **bash-completion-watchdog** — bash completion drop-ins
- **fish-config-watchdog** — fish global config (this module)

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any fish config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No `/etc/fish` config present | `ok` | `no_fish_config` |
| No delta | `ok` | `fish_config_intact` |
| A snippet added / changed / removed | `warn` | `fish_config_changed` |
| A snippet world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `fish_config_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each snippet.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval (...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=67min` + `OnCalendar=*-*-* 11:45:00` — extends the
staggered ladder after bash-completion (11:40). A planted snippet
runs in the next interactive fish session, so the boot catch
confirms the set after a restart and the daily catch bounds dwell
time on a long-running host.

## MITRE coverage

- **T1546** Event Triggered Execution — starting an interactive fish
  shell is the trigger.
- **T1059** — the snippet is fish-shell code sourced into the
  session.

## Operator workflow

```bash
journalctl -t selfdef-fish-config -n 1 --no-pager
journalctl -t selfdef-fish-config-detail --since "1 day ago"

# Inventory
ls -la /etc/fish/conf.d/ /etc/fish/functions/ 2>/dev/null
[ -f /etc/fish/config.fish ] && cat /etc/fish/config.fish

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/fish/conf.d/<file>.fish
sudo rm /var/lib/selfdef/fish-config-baseline.tsv
sudo systemctl start selfdef-fish-config.service
```

## Caveats

- **Packages ship legitimate `conf.d` snippets** (fzf, virtualfish,
  prompt themes); a new root-owned snippet with no suspicious
  pattern fires `warn` (re-baseline). The writable/non-root/injection
  tiers are the high-confidence alert.
- **/usr/share/fish/ is not watched** — it is package-managed
  (integrity-sentinel / aide-bridge territory); this module watches
  the admin-droppable `/etc/fish` config.
- **`eval` matching is fish-aware** — fish uses `eval (cmd)` (parens)
  rather than bash's `eval $(...)`, so the pattern matches both
  forms; `set -gx` and ordinary functions are not flagged.
- **Daily+boot cadence** misses a drop-shell-revert inside the
  window; an audit-rules watch on `/etc/fish` writes is the
  real-time complement.

## Coexistence

- **shell-init-watchdog / bash-completion-watchdog**: bash/zsh rc and
  bash completion; this is the fish surface — together the three
  cover the global interactive-shell startup exec set across the
  three popular shells.
- **sshrc / motd-scripts / xsession watchdogs**: other login-time
  exec surfaces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  snippets; this adds the ownership + injection-pattern view.
