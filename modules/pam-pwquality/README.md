# pam-pwquality

Configures pam_pwquality to enforce password complexity at SET
time. Pairs with pam-faillock (lockout after fails at USE time)
to address T1110.001 (Password Guessing) at both ends of the
password-attack pipeline.

## Two-stage password attack defense

| Attack stage | Defender | Mechanism |
|---|---|---|
| 1. Operator sets a new password | `pam-pwquality` | pam_pwquality blocks weak passwords at `passwd` time |
| 2. Attacker tries the password | `pam-faillock` | pam_faillock locks the account after N failed attempts |

Without #1, even pam-faillock can't defend against a guessable
password (the attacker succeeds on attempt 1, never trips the
lockout). pam-pwquality forces the operator to PICK a password
that the brute-force tier can't easily hit.

## Profiles

| Profile | minlen | char classes | diff from old | enforce_for_root | dictionary |
|---|---|---|---|---|---|
| `standard` (default) | 12 | 3-of-4 required | 4 chars | no (recovery-friendly) | no |
| `strict` | 16 | 4-of-4 required | 6 chars | yes | yes (needs cracklib-dicts) |

Both share:
- `retry = 3` (3 attempts per `passwd` invocation)
- `reject_username = true` (block "operator" or "operator2024" if
  username is "operator")
- `gecoscheck = true` (block password matching the user's GECOS
  field — full name from /etc/passwd)

## PAM stack wiring

Same DETECT-AND-NOTICE pattern as pam-faillock. The config is
INSTALLED unconditionally; the PAM stack must include
`pam_pwquality.so` for it to take effect:

| Distro | Default | Operator step if missing |
|---|---|---|
| Debian/Ubuntu | wired via libpam-pwquality | `sudo pam-auth-update --enable pwquality` |
| Fedora/RHEL | wired via authselect | `sudo authselect select sssd with-pwquality` |
| Older / custom | not wired | hand-edit `/etc/pam.d/common-password` (Debian) or `system-auth` (RHEL) — add `password requisite pam_pwquality.so retry=3` |

apply.sh detects PAM wiring + logs a NOTICE with the distro-
specific operator step if not wired.

## Existing passwords are unaffected

pam_pwquality only runs at SET time (`passwd`, useradd, etc.).
Existing user passwords keep working regardless of their
strength. Operator forces a re-evaluation via:

```bash
# Force operator to change password at next login
sudo chage -d 0 <username>
```

## MITRE coverage

- **T1110.001** Brute Force: Password Guessing — direct
  prevention. A 12-char 3-class password is ~10^21 entropy =
  not crackable by typical attacker.
- **T1078** Valid Accounts — narrows the pool of guessable
  accounts.

## Coexistence with the auth-defense triad

| Module | When |
|---|---|
| `pam-pwquality` | At password SET time (passwd) |
| `pam-faillock` | At password USE time (login/sudo) |
| `ssh-hardening` | At SSH protocol time (PasswordAuth=no usually preempts password auth entirely) |
| `fail2ban-bridge` | At IP-firewall time |

ssh-hardening's `PasswordAuthentication=no` is the strongest
defense (no online password attack possible). pam-pwquality is
a defense-in-depth backstop for any path that DOES allow password
auth (sudo, su, local console login).

## Operator workflow

```bash
# Test a password against the policy (without setting it)
echo "mypassword123" | pwscore
# Output:  Password quality check: Bad password
#          (or score 0-100 if it passes)

# Set a new password as operator
passwd
# pam_pwquality validates as you type the new password.

# View live pwquality config (composed across all conf.d)
cat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null
```

## Caveats

- **enforce_for_root=false (standard profile)** — root can set
  weak passwords. Intentional recovery primitive: if pwquality
  has a config bug, root can still set a recovery password.
  Strict profile flips this.
- **Dictionary words** (strict profile) require cracklib-dicts
  package. Without it, the dictionary check silently skips.
- **gecoscheck** rejects passwords containing the user's full
  name. If GECOS isn't set, no-op.
- **NIST SP 800-63B v3 deprecates complexity rules** in favor of
  length + breach-database lookup. pam_pwquality doesn't have
  built-in breach lookup; operator who wants haveibeenpwned-
  style check uses `passwdqc` or a custom PAM module.
