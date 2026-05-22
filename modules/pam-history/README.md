# pam-history

Configures `pam_pwhistory` to require N distinct
passwords before reuse. Completes the PAM password-
attack-defense triad:

| Stage | Module | Mechanism |
|---|---|---|
| **1. Operator picks a new password** | `pam-pwquality` | reject weak passwords at `passwd` time (complexity + dictionary) |
| **2. Operator picks a previously-used password** | `pam-history` (THIS) | reject if in last N |
| **3. Attacker tries the password** | `pam-faillock` | lock the account after N failed attempts |

Without #2, an operator forced to rotate every 90 days
just toggles between two passwords forever — defeating
the entire rotation premise. pam_pwhistory makes
rotation mean something.

## Why this matters

NIST SP 800-63B v3 (2020) deprecates mandatory password
rotation IN FAVOR OF length + breach-DB lookup +
2FA. But many compliance regimes (PCI DSS, HIPAA, SOX,
DISA-STIG) still mandate password history.

For operators in those regimes, this module is
mandatory. For operators outside them, it's still
valuable defense-in-depth: even with mandatory
rotation, password history prevents the "rotate +
revert" anti-pattern.

## Profiles

| Profile | remember | retry | enforce_for_root |
|---|---|---|---|
| `standard` (default) | 5 | 3 | no (recovery-friendly) |
| `strict` | 24 | 3 | yes (PCI DSS / SOX / STIG) |

`standard` blocks the 5 most recent passwords (≈1
year if operator rotates quarterly). `strict` blocks
the 24 most recent (2 years if monthly rotation).

`retry = 3` matches pam-pwquality + pam-faillock for
consistent operator UX across the triad.

## File

`/etc/security/pwhistory.conf` rendered per-profile
with selfdef header marker.

Backup of operator's pre-selfdef pwhistory.conf is
saved to `/var/lib/selfdef/pam-history-distro-
default.bak` on first apply. Uninstall restores it.

## PAM stack wiring (DETECT-AND-NOTICE)

Same pattern as pam-pwquality + pam-faillock: the
config file is always installed; the PAM stack must
include `pam_pwhistory.so` for it to take effect.

| Distro | Default | Operator step if missing |
|---|---|---|
| Debian/Ubuntu | not auto-wired | `sudo pam-auth-update --enable pwhistory` (after `apt install libpam-modules`) |
| Fedora/RHEL | wired via authselect | `sudo authselect select sssd with-pwhistory` |
| Older / custom | not wired | hand-edit `/etc/pam.d/common-password` (Debian) or `system-auth` (RHEL) — add `password requisite pam_pwhistory.so` |

apply.sh + check.sh DETECT the wiring + log a NOTICE
with the distro-specific operator step if not wired.
selfdef does NOT auto-edit /etc/pam.d/* to avoid
operator-lockout from a botched password change.

## MITRE coverage

- **T1110.001** Brute Force: Password Guessing —
  narrowly; complements pam-pwquality (complexity
  side) + pam-faillock (lockout side) for the
  password-recurrence vector.
- **T1078** Valid Accounts — narrows the
  re-acquisition window for an attacker who learned
  an old password (operator can't rotate-and-revert
  to the leaked one).

## Operator workflow

```bash
# Verify config is in place
cat /etc/security/pwhistory.conf

# Verify wiring (DETECT side)
grep -E 'pam_pwhistory' /etc/pam.d/common-password \
                       /etc/pam.d/system-auth \
                       /etc/pam.d/password-auth 2>/dev/null

# Wire on Debian/Ubuntu if missing
sudo apt install libpam-modules     # if absent
sudo pam-auth-update --enable pwhistory

# Wire on Fedora/RHEL
sudo authselect select sssd with-pwhistory

# Verify enforcement (as a non-root user)
passwd
# Set a new password.
# Try again with the SAME password → "Password has been already used"

# Switch to strict
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/pam-history.toml
sudo selfdefctl modules apply pam-history
```

## Caveats

- **Existing passwords are not retroactively
  remembered**. The history accumulates only from the
  first post-apply `passwd` invocation. Operators
  starting with strict profile will be able to use any
  of their CURRENT passwords until they've rotated
  through 24 different ones (which takes time).
- **enforce_for_root=no (standard)** lets root reuse
  passwords. Intentional recovery primitive — paired
  with the same logic in pam-pwquality. Strict flips it.
- **NIST guidance**: SP 800-63B v3 (2020) DEPRECATES
  password history in favor of length + breach-DB
  lookup. For NIST-aligned environments, this module
  is unnecessary. PCI DSS / SOX / STIG still mandate
  it — apply for compliance.
- **PAM wiring requires operator action**. Same
  posture as pam-pwquality + pam-faillock to prevent
  operator-lockout from a botched pam-auth-update run.
- **pwhistory.conf was introduced in pam_pwhistory ~1.5**
  (~2020). Older distros (RHEL 7) use module arguments
  on the pam_pwhistory.so line itself; this module's
  conf file is ignored on those.

## Coexistence

- **pam-pwquality**: complementary — pwquality
  rejects weak NEW passwords; pwhistory rejects
  REUSED passwords. Same pam-stack invocation order
  (pwquality first, then pwhistory).
- **pam-faillock**: complementary — faillock locks
  the account on failed-login bursts; pwhistory
  defeats the rotate-and-revert anti-pattern. Together
  the three modules cover SET + REUSE + USE password
  defenses.
- **ssh-hardening**: usually `PasswordAuthentication=no`
  preempts most password attack surfaces; pam-history
  is defense-in-depth for sudo/su/local-console paths
  that still allow password auth.
- **nullok-disable**: complementary — nullok-disable
  blocks empty passwords entirely (a degenerate case
  of weak/reused).
