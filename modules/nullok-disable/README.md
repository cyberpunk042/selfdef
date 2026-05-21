# nullok-disable

Removes `nullok` (and `nullok_secure`) from `pam_unix.so`
directives in `/etc/pam.d/*`. Blocks the empty-password login
path that some legacy distro defaults permitted for accounts
with no password set.

## Why this matters

The `nullok` PAM option means: "if the user has an empty password
in /etc/shadow, allow login without a password prompt." Multiple
attack patterns exploit this:

- **T1078 Valid Accounts: Default Accounts** — an installer that
  created an unprivileged service account with no password (some
  legacy distro defaults) becomes login-able via any path that
  honors nullok.
- **Operator misconfiguration** — `usermod -p '' someuser` (or
  `passwd -d`) on an account with the intent of "disabling
  password auth" SHOULD set an `!`-locked field. If it doesn't,
  the empty-field becomes a nullok-permitted password.
- **Compromised /etc/shadow edit** — attacker with root briefly
  blanks a target account's password field; nullok permits the
  empty pw login on that account thereafter.

Removing `nullok` shifts the failure mode: empty-password
accounts CANNOT log in at all, regardless of how they got into
that state. Operators who legitimately want password-less auth
use SSH keys + PasswordAuthentication=no instead.

## Profiles

| Profile | Behavior |
|---|---|
| `audit` (default) | Scan + LOG findings; do NOT modify files. Safe baseline collection. |
| `enforce` | Scan + sed-remove `nullok` + `nullok_secure`. Backs up each affected file to `.selfdef-nullok-backup`. |

The audit-first pattern is intentional — operator runs apply
once in audit mode to see WHICH /etc/pam.d/* files have nullok,
inspect them, then flip to enforce.

## What this does NOT block

- **Empty-password CONSOLE login via `login(1)`** when console
  login is configured with `nullok` removed: login still
  PROMPTS for the password but rejects empty input. Effectively
  the same protection.
- **Password-less SSH via authorized_keys** — entirely separate
  mechanism; not affected.
- **Operator who manually re-adds nullok** post-apply — apply
  reverts on next run; check flags as drift.

## MITRE coverage

- **T1078** Valid Accounts — primary; blocks the empty-password
  edge case of valid-but-unset accounts.
- **T1556** Modify Authentication Process — narrows the PAM
  authentication surface; one fewer trust assumption.

## Operator workflow

```bash
# Audit-only first
echo 'profile = "audit"' | sudo tee /etc/selfdef/modules/nullok-disable.toml
sudo selfdefctl modules apply nullok-disable
sudo journalctl -t selfdef-modules | grep nullok

# Inspect each finding (operator may want to keep some)
sudo grep -rn 'nullok' /etc/pam.d/

# Flip to enforce
echo 'profile = "enforce"' | sudo tee /etc/selfdef/modules/nullok-disable.toml
sudo selfdefctl modules apply nullok-disable

# Verify
sudo grep -rn 'nullok' /etc/pam.d/  # expect empty output
ls /etc/pam.d/*.selfdef-nullok-backup  # backup files for restore
```

## Caveats

- **Some distros' default common-auth has nullok intentionally**
  — Ubuntu's "shadow installation" default ships
  `auth [success=1 default=ignore] pam_unix.so nullok` so a
  freshly-installed user (before passwd) can still log in
  during first-boot. After first-boot the nullok is harmless
  (no empty passwords remain) but selfdef removes it
  defensively anyway.
- **chpasswd / changeable accounts**: if an operator workflow
  ZEROES passwords as a re-onboard step (rare), this module
  breaks that flow. Recommendation: use `passwd -l <user>` +
  `passwd -e <user>` to expire instead of zeroing.
- **PAM stack composition**: `nullok` may be set on a different
  module than pam_unix.so on some distros (pam_securetty,
  pam_chauthtok). This module only targets pam_unix.so + 
  pam_unix2.so. Operator extends via a 60-operator drop-in if
  needed.

## Coexistence

- **pam-pwquality**: enforces complexity at password SET time.
  pam-pwquality + nullok-disable together: weak passwords
  blocked at set + empty passwords blocked at use.
- **pam-faillock**: catches brute-force at USE time.
- **ssh-hardening**: PasswordAuthentication=no removes the SSH
  side of this attack surface entirely; nullok-disable remains
  relevant for local console + su + sudo paths.
