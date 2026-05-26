# login-defs-baseline

Sets password-aging + strong-hash defaults in
`/etc/login.defs.d/` (with a `/etc/login.defs` fallback
for older distros). Governs how NEW accounts age and how
all passwords are hashed. CIS 5.5.x. Completes the
account-policy layer alongside the
pam-pwquality / pam-history / pam-faillock triad.

## Why this matters

`/etc/login.defs` is consulted by `useradd`, `passwd`,
`chage`, and `login(1)` to decide:
- **How long a password is valid** (PASS_MAX_DAYS).
- **How soon it can be changed again** (PASS_MIN_DAYS —
  prevents rotate-through-history-instantly abuse).
- **How passwords are HASHED** (ENCRYPT_METHOD +
  SHA_CRYPT rounds).

A weak default here undermines every other password
control: a fast hash (MD5, DES) means even a strong
password falls to offline cracking once `/etc/shadow`
leaks. This module guarantees a slow, modern hash
(yescrypt or SHA512 with 65536 rounds) + sane aging.

## Profiles

| Profile | MAX_DAYS | MIN_DAYS | WARN_AGE | hash |
|---|---|---|---|---|
| `standard` (default) | 365 | 1 | 14 | YESCRYPT (SHA512 fallback) |
| `strict` | 90 | 7 | 14 | SHA512, 65536 rounds (PCI DSS / STIG) |

`standard` follows NIST SP 800-63B v3 (which deprecates
aggressive forced rotation) — aging exists but is
generous; the real win is the strong hash. `strict` meets
PCI DSS 90-day rotation + names SHA512 explicitly for
compliance regimes.

## File

`/etc/login.defs.d/50-selfdef-login-defs.conf` rendered
per-profile with selfdef header marker. On distros that
don't read `login.defs.d` (older Debian, RHEL 7), a
marker-fenced block is ALSO appended to
`/etc/login.defs` (idempotent — replaced on re-apply).

## Settings

| Key | standard | strict | Effect |
|---|---|---|---|
| `PASS_MAX_DAYS` | 365 | 90 | Force password change after N days |
| `PASS_MIN_DAYS` | 1 | 7 | Min days between changes (anti-rotate-abuse) |
| `PASS_WARN_AGE` | 14 | 14 | Warn N days before expiry |
| `ENCRYPT_METHOD` | YESCRYPT | SHA512 | Password hash algorithm |
| `SHA_CRYPT_MIN/MAX_ROUNDS` | 65536 | 65536 | SHA512 cost (when used) |

## MITRE coverage

- **T1110.002** Brute Force: Password Cracking — PRIMARY;
  a slow modern hash (yescrypt / SHA512-65536) makes
  offline cracking of a leaked /etc/shadow infeasible.
- **T1110.001** Password Guessing — aging narrows the
  window a guessed password stays valid.
- **T1078** Valid Accounts — bounded password lifetime
  limits how long stolen creds work.

## Existing accounts

login.defs governs NEW account creation + the NEXT
password change. Existing accounts keep their current
aging until the operator forces a re-evaluation:

```bash
# Apply the new max-age to an existing user
sudo chage --maxdays 90 --warndays 14 <user>

# Force change at next login
sudo chage -d 0 <user>

# Re-hash: the hash upgrades automatically at next
# `passwd` (the new ENCRYPT_METHOD is used then).
```

## Operator workflow

```bash
# View effective settings
grep -E 'PASS_|ENCRYPT_METHOD|SHA_CRYPT' \
    /etc/login.defs /etc/login.defs.d/*.conf 2>/dev/null

# Verify a user's aging
sudo chage -l <user>

# Switch to strict (PCI DSS 90-day)
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/login-defs-baseline.toml
sudo selfdefctl modules apply login-defs-baseline
```

## Caveats

- **yescrypt availability**: yescrypt needs libxcrypt +
  a recent shadow-utils (Debian 11+, Fedora 35+). On
  older systems ENCRYPT_METHOD=YESCRYPT is ignored and
  the system falls back to SHA512 anyway — harmless. Use
  the strict profile (explicit SHA512) on older hosts.
- **NIST vs compliance tension**: NIST 800-63B v3 says
  DON'T force rotation; PCI DSS still requires 90 days.
  standard profile leans NIST (365-day = barely-aging);
  strict leans compliance.
- **Existing weak hashes persist** until the next
  password change. Operator forces re-hash via
  `chage -d 0`.
- **umask-baseline owns the UMASK key** in a separate
  login.defs.d file — no conflict (different filenames).

## Coexistence

- **pam-pwquality + pam-history + pam-faillock**:
  complementary — those govern complexity / reuse /
  lockout at PAM time; this governs aging + hash at the
  login.defs layer. Together they're the full account-
  password-policy stack.
- **umask-baseline**: complementary — shares
  /etc/login.defs.d/ but owns the UMASK key in its own
  file (50-selfdef-umask.conf vs this module's
  50-selfdef-login-defs.conf).
- **account-watchdog**: complementary — detects NEW
  accounts; this governs how those accounts' passwords
  age + hash.
- **service-account-lock**: complementary — locks
  service-account shells; this sets the aging policy
  human accounts inherit.
