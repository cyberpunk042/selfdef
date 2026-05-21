# pam-faillock

Configures [pam_faillock](https://github.com/linux-pam/linux-pam)
account lockout policy. After N failed auth attempts within M
seconds, the account is locked for L seconds. Defends the
**local-auth** layer (sudo, su, login, passwd) against
T1110 Brute Force.

## Profiles

| Profile | Threshold | Window | Lockout | Use |
|---|---|---|---|---|
| `lenient` (default) | 10 fails | 15 min | 15 min | Operator workstation; survives typo storms |
| `strict` | 5 fails | 10 min | 30 min | High-assurance hosts; mostly key-only ssh |

Both profiles share:
- `even_deny_root` — root account is subject to lockout too
  (an attacker can't bypass by targeting root)
- `root_unlock_time = 60` — root unlocks faster than user
  accounts; preserves emergency recovery
- `silent + no_log_info` — quiet PAM TTY output (selfdef-
  collector-journald + audit-rules already capture the events)
- `dir = /var/lib/faillock` — per-user lockout state

## PAM stack wiring

`faillock.conf` is CONSUMED by `pam_faillock.so` invoked from the
PAM stack (`/etc/pam.d/*`). Most modern distros wire it by
default:

| Distro | Default | Operator step if missing |
|---|---|---|
| Fedora 35+ / RHEL 9+ | wired via authselect | `sudo authselect select sssd with-faillock` |
| Debian 12+ / Ubuntu 22.04+ | wired via pam-auth-update | `sudo pam-auth-update --enable faillock-tally` |
| Older / custom | not wired | hand-edit `/etc/pam.d/common-auth` (Debian) or `system-auth` (RHEL) — add `auth required pam_faillock.so preauth` + `auth [default=die] pam_faillock.so authfail` + `account required pam_faillock.so` |

apply.sh DETECTS whether `pam_faillock.so` appears in any
`/etc/pam.d/*` file + LOGS a NOTICE if not. The config installs
either way; it's just dormant until the PAM stack invokes it.

## MITRE coverage

- **T1110** Brute Force — primary; throws off online
  brute-force at the lockout threshold.
- **T1110.001** Brute Force: Password Guessing — local auth
  guesses (sudo, su) blocked.
- **T1078** Valid Accounts — compromised account can't be
  silently brute-forced past the lockout.

## Operator recovery

Account locked? Unlock via:

```bash
sudo faillock --user <username> --reset
```

Check current lock state:

```bash
sudo faillock --user <username>
# Or list ALL users:
sudo faillock
```

The lockout state persists in `/var/lib/faillock/<username>`.
Uninstalling this module does NOT clear that state (operator
may want the audit trail).

## Coexistence with ssh-hardening + sudo-tune

| Module | Layer | What it blocks |
|---|---|---|
| `ssh-hardening` | Network (sshd) | Network-side brute force at the SSH protocol layer |
| `pam-faillock` | Local-auth (PAM) | Local-side brute force at the PAM layer (sudo, su, login, passwd) |
| `sudo-tune` | Sudo cache | Cross-terminal sudo-cache abuse |

All three work together: ssh-hardening blocks network brute force
BEFORE PAM sees it; pam-faillock catches what gets through (or
local brute force from a compromised user); sudo-tune narrows the
post-auth elevation window.

## Why even_deny_root

Conventional wisdom says "never lock root — preserve recovery."
The selfdef stance: with `root_unlock_time=60`, root unlocks in
60s anyway. The trade-off is:
- Attacker brute-forcing root: tries 5/10 attempts → root locked
  for 60s → resumes → locked again → in steady state, attacker
  gets ~1 attempt per minute per IP. Effectively rate-limited.
- Operator who genuinely forgot root password: 60-second wait,
  or use single-user mode from console for hard recovery.
