# sudoers-integrity-watchdog

Daily + boot delta of the sudo grant set (`/etc/sudoers` +
`/etc/sudoers.d/*` parsed rules) against a learned
baseline. A NEW sudo rule — especially a `NOPASSWD` or
blanket `ALL=(ALL) ALL` grant — is privilege-escalation
persistence (T1548.003) that `account-watchdog`'s group-
membership view does NOT catch.

## Why this matters

`account-watchdog` catches a user being ADDED to the
`sudo`/`wheel` group. But sudo can be granted a second way
that bypasses group membership entirely: a rule file in
`/etc/sudoers.d/`. An attacker drops:

```
echo 'www-data ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz-backdoor
```

Now `www-data` has passwordless root — and it's NOT in any
sudo group, so a group-membership audit misses it. This
module parses the actual sudo RULES + diffs them, catching
the dropped grant.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any ADDED rule → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| Rule removed (only) | `warn` | `sudo_grant_removed` |
| Non-dangerous rule added | `warn` | `sudo_grant_added` |
| `NOPASSWD` or `ALL=(ALL[:ALL]) ALL` rule added | `alert` | `dangerous_sudo_grant_added` |

## What's parsed

Rule lines (containing `=`, excluding comments/blank/
`Defaults`) from `/etc/sudoers` + every file in
`/etc/sudoers.d/`, whitespace-normalized so cosmetic
spacing changes don't create false deltas. `Defaults`
lines are intentionally excluded — those are tunables
owned by `sudo-tune`, not grants.

## Baseline file

`/var/lib/selfdef/sudoers-integrity-baseline.tsv` (mode
0600). Re-baseline after a legitimate sudo change:
```bash
sudo rm /var/lib/selfdef/sudoers-integrity-baseline.tsv
sudo systemctl start selfdef-sudoers-integrity.service
```
Preserved across uninstall (forensic).

## Cadence

`OnBootSec=6min` + `OnUnitActiveSec=2h` + jitter — tight
because NOPASSWD injection is instant root persistence;
boot catch confirms the grant set after every restart.

## MITRE coverage

- **T1548.003** Abuse Elevation Control Mechanism: Sudo and
  Sudo Caching — PRIMARY; a new sudo grant is the exact
  artifact.
- **T1098** Account Manipulation — granting sudo is
  account manipulation via the rule path.
- **T1078** Valid Accounts — the granted account becomes a
  privileged foothold.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-sudoers-integrity -n 1 --no-pager

# Per-rule detail
journalctl -t selfdef-sudoers-integrity-detail --since "1 day ago"

# Manual inventory (validate syntax + list)
sudo visudo -c
sudo grep -rvE '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/ | grep =

# Investigate an alert
sudo cat /etc/sudoers.d/<suspicious>
# If illegitimate, remove it:
sudo rm /etc/sudoers.d/<suspicious>
sudo visudo -c          # re-validate

# Re-baseline after a legit change
sudo rm /var/lib/selfdef/sudoers-integrity-baseline.tsv
sudo systemctl start selfdef-sudoers-integrity.service
```

## Caveats

- **Config-management churn**: tools (Ansible/Puppet) that
  template sudoers.d files produce legit adds → re-baseline
  after a config push, or exclude managed files (future
  allowlist).
- **#includedir / @includedir** in /etc/sudoers can pull in
  other dirs — this module scans the standard
  /etc/sudoers.d; non-standard include dirs would need
  SELFDEF_ override (future).
- **2h cadence** misses an add-then-remove within the
  window; auditd (audit-rules paranoid watches
  /etc/sudoers + sudoers.d writes) is the real-time
  complement.

## Coexistence

- **account-watchdog**: complementary — account-watchdog
  catches sudo-GROUP membership adds; this catches sudo-
  RULE-file grants (the bypass path). Run both for full
  privilege-grant coverage.
- **sudo-tune**: complementary — sudo-tune owns the
  `Defaults` (timestamp_timeout, iolog, lecture); this
  watches the GRANT rules. No overlap (Defaults excluded
  here).
- **audit-rules**: real-time write watch on sudoers; this
  is the periodic parsed-rule delta backstop.
- **pam-faillock + login-defs-baseline**: complementary
  account-policy layer.
