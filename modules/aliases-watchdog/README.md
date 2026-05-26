# aliases-watchdog

Boot + daily delta of the mail aliases database against a learned
baseline, plus an ownership + pipe/include scan. Catches a mail
alias that pipes to a command on delivery. MITRE **T1546.004**.

## Why this matters

An alias of the form:

```
name: |command
```

makes the MTA **run that command** — as the default delivery user
(often `nobody`/`mail`, sometimes root, depending on MTA config) —
whenever mail is delivered to the alias. This is the classic Unix
mail-alias exec vector (the historic `decode:` alias RCE). A target
of the form:

```
name: :include:/path/to/file
```

reads recipients (and thus further pipe/file targets) from another
file.

A planted pipe alias — or one pointing at `/tmp`, or a `:include:`
of a writable file — is **mail-triggered code execution /
persistence**, and the attacker can trigger it on demand simply by
sending mail to the alias. Files watched: `/etc/aliases`,
`/etc/mail/aliases`, `/etc/postfix/aliases`.

This is distinct from **postfix-exec-watchdog** (master.cf/main.cf
service + command config); this is the **alias-recipient pipe**
surface.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any aliases change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No aliases file present | `ok` | `no_aliases` |
| No delta | `ok` | `aliases_intact` |
| A file / pipe / include added / changed / removed | `warn` | `aliases_changed` |
| A file world-writable/non-root, a pipe command under `/tmp` `/var/tmp` `/dev/shm` `/home` or with an injection pattern, or a `:include:` of a file under those locations | `alert` | `aliases_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each aliases file.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `pipe:<path>:<command>` — a `|command` alias target.
- `include:<path>:<inc>` — a `:include:` target file.

## Cadence

`OnBootSec=78min` + `OnCalendar=*-*-* 12:45:00` — extends the
staggered ladder after postfix-exec (12:40). A planted pipe alias
fires the next time mail reaches it, so the daily catch bounds dwell
time; the boot catch confirms the alias set after a restart.

## MITRE coverage

- **T1546.004** Event Triggered Execution (Unix Shell / mail-alias)
  — mail to the alias triggers the pipe command.
- **T1059** — the pipe command is arbitrary code run by the MTA.

## Operator workflow

```bash
journalctl -t selfdef-aliases -n 1 --no-pager
journalctl -t selfdef-aliases-detail --since "1 day ago"

# Inventory pipe + include aliases
grep -nE '\|' /etc/aliases /etc/mail/aliases /etc/postfix/aliases 2>/dev/null
grep -nE ':include:' /etc/aliases 2>/dev/null

# Investigate a suspicious alert, then re-baseline (remember to run newaliases):
sudo $EDITOR /etc/aliases && sudo newaliases
sudo rm /var/lib/selfdef/aliases-baseline.tsv
sudo systemctl start selfdef-aliases.service
```

## Caveats

- **A few legit pipe aliases exist** (mailman/majordomo list
  delivery, `vacation`, ticketing systems) with standard absolute
  command paths; a new pipe alias still fires `warn` (re-baseline).
  The tmp-exec / injection / writable / `:include:`-writable tiers
  are the high-confidence alert.
- **This watches the source aliases text, not the compiled
  `aliases.db`.** A change made directly to the `.db` (without
  editing the source) would not show here; pair with an
  integrity-sentinel watch on `aliases.db`.
- **`~/.forward`** files are the per-user equivalent (also support
  `|command`) — a home-dir surface not covered here; a per-user
  `.forward` sweep is the complement.
- **Daily+boot cadence** misses a drop-mail-revert inside the
  window; an audit-rules watch on the aliases files' writes is the
  real-time complement.

## Coexistence

- **postfix-exec-watchdog**: master.cf/main.cf service + command
  config; this is the alias-recipient pipe surface.
- **mta-loopback-detect**: MTA listening posture; this is the
  alias-exec posture.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  aliases files (and the compiled `.db`); this adds the pipe/include
  semantic view.
