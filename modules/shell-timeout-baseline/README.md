# shell-timeout-baseline

Auto-logs-out idle interactive shells via a read-only
`TMOUT` set in `/etc/profile.d`. Defends against an
unattended operator session — a left-open terminal, an
SSH session the operator walked away from, a detached
tmux/screen — being taken over at the keyboard or
hijacked. CIS 5.4.x.

## Why this matters

An authenticated root/operator shell left idle is a
standing invitation:
- A physical attacker sits down at the unlocked
  workstation / console and inherits the live root shell.
- An attacker who gets brief access to a shared jump host
  finds an operator's idle SSH session still authenticated.
- A forgotten `screen`/`tmux` session persists an
  authenticated context indefinitely.

`TMOUT` is the bash/ksh built-in that exits the shell
after N seconds of inactivity. Setting it system-wide +
`readonly` means idle shells self-terminate, shrinking the
unattended-session window.

## Profiles

| Profile | TMOUT | Idle logout after |
|---|---|---|
| `standard` (default) | 900 | 15 minutes |
| `strict` | 300 | 5 minutes |

## File

`/etc/profile.d/50-selfdef-tmout.sh` — sourced by every
interactive login shell. Sets `TMOUT` + `readonly TMOUT`
so a casual `unset TMOUT` in the session fails.

The guard only arms for INTERACTIVE shells (`case "$-" in
*i*`) and only bash/ksh (`BASH_VERSION`/`KSH_VERSION`), so
it never breaks non-interactive scripts, cron, or
`ssh host command` invocations (which aren't interactive
and shouldn't time out mid-run).

## MITRE coverage

- **T1078** Valid Accounts — PRIMARY; an idle authenticated
  session IS a valid-account foothold an attacker inherits.
- **T1563** Remote Service Session Hijacking — narrows the
  window for hijacking an idle SSH/screen session.
- **T1078.003** Local Accounts — physical takeover of an
  unlocked console shell.

## Operator workflow

```bash
# Verify the file
cat /etc/profile.d/50-selfdef-tmout.sh

# Take effect in the current shell (or just re-login)
exec bash -l
echo "$TMOUT"        # expect 900 (standard) or 300 (strict)

# An idle shell now exits after the timeout with
# "timed out waiting for input: auto-logout"

# Switch to strict (5 min) on high-sensitivity hosts
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/shell-timeout-baseline.toml
sudo selfdefctl modules apply shell-timeout-baseline
```

## Caveats

- **Deterrent, not a jail**: `readonly TMOUT` blocks
  casual unset, but a determined operator can launch a
  fresh non-login shell (`bash --norc`) or a long-running
  foreground process (which resets the idle timer). This
  is a CIS control + deterrent, not an unbypassable
  confinement. For hard enforcement, pair with screen-lock
  (GUI) + physical security.
- **Long-running interactive commands** (a `less` on a
  huge file, an interactive debugger) count as activity OR
  reset TMOUT when they exit — TMOUT measures shell-prompt
  idle, not total session time, so it won't kill an
  actively-used session mid-task.
- **Takes effect on NEXT login shell** — existing sessions
  keep their current TMOUT (or none) until re-login.
- **Operators who run `watch`/monitoring in a terminal**
  intentionally leave it idle-at-prompt; they exempt that
  host or use a dedicated tmux with the module not applied.
- **zsh** uses `TMOUT` too but reads it differently;
  primarily targets bash/ksh (the server norm).

## Coexistence

- **ssh-hardening**: complementary — ssh-hardening can set
  `ClientAliveInterval`/`ClientAliveCountMax` (server
  drops idle SSH at the protocol layer); TMOUT drops at
  the shell layer. Defense-in-depth — TMOUT also covers
  local console + screen/tmux that SSH-keepalive doesn't.
- **umask-baseline + login-defs-baseline**: same
  /etc/profile.d + login.defs account-environment family.
- **pam-faillock**: complementary — faillock defends the
  login; this defends the post-login idle window.
