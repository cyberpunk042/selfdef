# cron-baseline

Restrict cron + at scheduling access via `/etc/cron.allow` +
`/etc/at.allow`. Default Linux distros leave both files ABSENT,
which means EVERY user can run `crontab -e` to install their own
scheduled persistence. This module locks cron access to operator-
named users.

## Why this matters (T1053.003)

`crontab -e` is the canonical Linux user-persistence primitive
for attackers who land an unprivileged shell:
- No root needed
- Survives logout + reboot
- audit-rules paranoid profile catches the WRITE to
  /var/spool/cron/crontabs/<user>, BUT only AFTER the entry is
  already installed and the next-tick exec is about to fire
- With `/etc/cron.allow` enforced, the attacker's `crontab -e`
  exits with EPERM BEFORE the file is created

The detection→prevention shift is the value: detection modules
(audit-rules, aide-bridge) flag the persistence attempt;
cron-baseline blocks it at the source.

## Profiles

| Profile | /etc/cron.allow contents | Use |
|---|---|---|
| `root-only` (default) | `root` only | Hosts where operator-scheduling goes via systemd-timer (selfdef's own modules do this); cron is for the OS only |
| `operator-list` | `root` + `operator_users` config field | Hosts where named operators legitimately use `crontab -e` |

Both profiles also write EMPTY `/etc/cron.deny` + `/etc/at.deny`.
The cron + at daemons consult `.allow` if it exists, else
`.deny`. Writing both eliminates a distro-specific surprise where
operator's `crontab` mysteriously fails.

## Files installed

| Path | Mode | Owner | Content |
|---|---|---|---|
| `/etc/cron.allow` | 0640 | root:crontab (or root:root) | User list, one per line |
| `/etc/at.allow` | 0640 | root:crontab | Same user list |
| `/etc/cron.deny` | 0640 | root:root | Empty |
| `/etc/at.deny` | 0640 | root:root | Empty |

Mode 0640 because cron's group is read-required on some distros
(Debian's `crontab` binary is setgid `crontab`; the group must
be able to read `/etc/cron.allow`). 0600 breaks Debian.

## Operator workflow

```bash
# Verify the restriction is active
cat /etc/cron.allow

# Test as a non-root non-listed user
sudo -u nobody crontab -e
# Expected:  "You (nobody) are not allowed to use this program (crontab)"

# To allow a new operator user
sudo selfdefctl modules apply cron-baseline  # if config edited

# To do it manually (operator-pull bypass; selfdef next apply
# will revert unless config edited):
sudo bash -c 'echo "alice" >> /etc/cron.allow'

# Alternative scheduling: systemd-timer
# (selfdef's own modules — aide-bridge, rkhunter-cron, lynis-cron,
# clamav-cron — all use systemd-timer instead of cron)
sudo systemctl list-timers
```

## MITRE coverage

- **T1053.003** Scheduled Task/Job: Cron — primary; blocks
  per-user crontab install for non-root non-listed users.
- **T1053.001** Scheduled Task/Job: at — same restriction
  applies to at(1).

## What this does NOT block

- **Root's crontab** — root can still install entries
  (intentional — selfdef itself + OS packages may schedule via
  /etc/cron.d/, which is root-owned).
- **System-wide /etc/cron.d/ + /etc/cron.{daily,hourly,weekly,
  monthly}/** — these are root-owned + drop-files
  there require root. NOT user-spoofable.
- **systemd-timer** — orthogonal scheduling system. systemd-timer
  units are root-owned + immune to user-cron access controls.

To detect tampering of root cron / cron.d / cron.* dirs, pair
this module with:
- `audit-rules` paranoid profile (watches /etc/cron.d /var/spool/
  cron /etc/crontab)
- `aide-bridge` (diff baseline includes /etc)

## Caveats

- **Operator's existing per-user crontabs**: existing crontabs at
  /var/spool/cron/crontabs/<user> KEEP RUNNING after this module
  applies — the .allow only gates NEW installations via
  `crontab -e`. To remove a stale per-user crontab:
  ```bash
  sudo crontab -u <username> -r
  ```
- **systemd-cron substitution**: some distros (Arch) ship
  systemd-cron, where /var/spool/cron contents are translated
  to per-user systemd units. cron.allow is still consulted.
- **No coverage for anacron**: anacron runs as root from
  /etc/anacrontab. Different access model.
