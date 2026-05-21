# sudo-tune

sudo defaults tightening + full I/O session recording. Drops
`/etc/sudoers.d/50-selfdef-tune` after `visudo -cf` validation
(refuse-to-brick guard — a syntactically-bad sudoers locks the
operator out of sudo, so the file MUST validate before commit).

## Profiles

| Profile | Timestamp timeout | Lecture | Extras |
|---|---|---|---|
| `audit-trail` (default) | 5 min, per-tty | once-per-user | log_year + iolog + pwfeedback off + use_pty |
| `paranoid` | 2 min, per-tty | every-invocation | + secure_path reset + env_reset + custom lecture file |

Both profiles share:
- `log_year` — multi-month forensic timelines need the year
- `logfile=/var/log/sudo.log`
- `iolog_dir=/var/log/sudo-io` + `log_input` + `log_output`
- `timestamp_type=tty` — sudo in one terminal doesn't unlock
  another terminal (mitigates T1548.003 sudo-cache abuse)
- `!pwfeedback` — no asterisks (password-length leak)
- `use_pty` — force-allocate a PTY for every sudo'd command
  (sudo's recommended hardening since 2020)

## Replay forensic sessions

```bash
# List recorded sessions
sudoreplay -l

# Replay a specific session at original speed
sudoreplay <session-id>

# Faster replay (10x)
sudoreplay -s 10 <session-id>

# Just the command that was run
sudo grep "^.*COMMAND=" /var/log/sudo.log | tail -20
```

## MITRE coverage

- **T1548.003** Abuse Elevation Control Mechanism: Sudo and Sudo
  Caching — `timestamp_type=tty` + tighter `timestamp_timeout`
  block the cross-terminal sudo-cache abuse vector.
- **T1078** Valid Accounts — full I/O session recording surfaces
  WHAT a valid-credentialed actor did (not just that they ran
  sudo).
- **T1059** Command and Scripting Interpreter — every sudo'd
  shell invocation is recorded, including arguments + command
  history.

## NOPASSWD interaction

`Defaults !authenticate` is intentionally NOT set here — we
require password. Operator's existing NOPASSWD rules (`%wheel
ALL=(ALL) NOPASSWD: ALL` etc.) at higher-numbered sudoers files
(`/etc/sudoers.d/99-operator-nopasswd`) still apply per sudo's
"last matching rule wins" parse.

## Refuse-to-brick guard

`apply.sh` validates the rendered profile via `visudo -cf` BEFORE
installing. If the file would break sudo (syntax error /
ambiguous Defaults override), apply.sh refuses to commit. This
is the same pattern as usbguard's `acknowledge_modules_disabled`
flag — an irreversible operator-lockout has explicit safety
gates.

## Disk cost

`iolog_dir=/var/log/sudo-io` records every keystroke + terminal
output. For an active operator workstation, expect ~10-100 MB/day.
Operator can prune via:

```bash
sudo find /var/log/sudo-io -mtime +30 -type f -delete
```

A future `sudo-iolog-rotate` module would automate this on a
weekly timer.

## Operator-extension

`/etc/sudoers.d/60-operator-tune` (lex-order LATER → overrides
our defaults) is the operator-pull extension hook. Selfdef NEVER
touches operator-prefixed files.

## Why visudo -cf MATTERS

```bash
# DON'T: install a sudoers fragment without validation
sudo cp my-sudoers.conf /etc/sudoers.d/    # broken syntax = LOCKED OUT

# DO: validate first
sudo visudo -cf my-sudoers.conf            # exit 0 ⇒ safe to install
```

selfdef's apply.sh follows the DO pattern; uninstall.sh also
re-validates the remaining sudoers tree after removal.
