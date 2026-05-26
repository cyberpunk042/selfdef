# pam-config-watchdog

Daily + boot delta of the PAM configuration — the
`/etc/pam.d/*` auth-stack lines plus the on-disk
`pam_*.so` module set hashes — against a learned baseline.
A NEW pam line or a CHANGED/added PAM module is the MITRE
**T1556.003** pluggable-authentication-module backdoor
signature.

## Why this matters

PAM is the gate every login passes through (SSH, sudo, su,
login, display managers). Two backdoor variants:

1. **Config injection**: add a line to `/etc/pam.d/sshd`
   like `auth sufficient pam_permit.so` (accept everyone)
   or a malicious `auth sufficient pam_backdoor.so` that
   accepts a magic password — instant auth bypass for
   every SSH login, no password needed.
2. **Module replacement**: replace `pam_unix.so` with a
   trojaned build that logs every password to a file OR
   accepts a hardcoded backdoor password. The config looks
   untouched; only the module binary's hash changed.

This module catches BOTH: it normalizes + diffs the
pam.d config lines (type+control+module, args dropped to
avoid tuning churn) AND hashes every `pam_*.so` in the
standard security lib dirs.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any added/changed line or module → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| Line/module removed | `warn` | `pam_config_removed` |
| Line added OR module added/hash-changed | `alert` | `pam_config_changed` |

## What's recorded

- `pamline:<file>:<type control module>` — every active
  rule in `/etc/pam.d/*` (comments + `@include` dropped;
  module ARGS dropped so `pam_unix.so rounds=...` tuning
  doesn't churn, but a new module / control change shows).
- `pammod:<path>:<sha256-12>` — every `pam_*.so` in
  `/lib*/security`, `/usr/lib*/security`, multiarch dirs.

## Cadence

`OnBootSec=7min` + `OnUnitActiveSec=4h` + jitter — a PAM
backdoor is high-impact auth-bypass persistence; boot
catch confirms the auth stack after restart.

## MITRE coverage

- **T1556.003** Modify Authentication Process: Pluggable
  Authentication Modules — PRIMARY; exact technique.
- **T1556** Modify Authentication Process — the class.
- **T1554** Compromise Host Software Binary — a trojaned
  pam_unix.so is a compromised system binary.
- **T1078** Valid Accounts — the backdoor grants
  authenticated access.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-pam-config -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-pam-config-detail --since "1 day ago"

# Manual inventory
grep -rvE '^\s*(#|$|@include)' /etc/pam.d/ | sort
ls -l /lib/*/security/pam_*.so /usr/lib/*/security/pam_*.so 2>/dev/null

# Investigate an alert
# - A new "sufficient pam_*.so" line in an auth stack is
#   highly suspicious (it's an OR-bypass).
sudo grep -n 'sufficient' /etc/pam.d/*
# - A changed pam_unix.so hash → compare against the package:
dpkg --verify libpam-modules 2>/dev/null || rpm -V pam 2>/dev/null

# Re-baseline after a legit change (pam-auth-update, package upgrade)
sudo rm /var/lib/selfdef/pam-config-baseline.tsv
sudo systemctl start selfdef-pam-config.service
```

## Caveats

- **`pam-auth-update` / `authselect`** (the legit tools
  selfdef's own pam-* modules tell operators to run) change
  pam.d → legitimate adds; re-baseline after running them.
- **Package upgrades** re-write pam_*.so (new hash) →
  re-baseline after an upgrade wave; cross-check the new
  hash against the package (`dpkg --verify` / `rpm -V`).
- **4h cadence** misses a backdoor added-then-removed
  within the window; auditd watching /etc/pam.d +
  /lib*/security writes (audit-rules) is the real-time
  complement.
- **Module-args dropped** in the line normalization — an
  attack that ONLY changes args (rare) is caught by the
  module-hash side if it swapped the .so, or by
  integrity-sentinel if the pam.d file content is watched.

## Coexistence

- **pam-pwquality + pam-history + pam-faillock +
  nullok-disable**: those CONFIGURE the PAM stack; this
  WATCHES it for backdoor tampering. The config modules'
  legit changes are the baseline this monitors.
- **audit-rules**: real-time write watch on /etc/pam.d +
  the security lib dir; this is the periodic parsed-delta
  backstop.
- **integrity-sentinel + aide-bridge**: file-content
  integrity; this is the PAM-semantic (line-level +
  module-hash) specialization.
- **ssh-authkeys / sudoers / account watchdogs**: sibling
  auth-persistence detectors — PAM backdoor is the
  auth-stack member of that family.
