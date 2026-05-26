# account-watchdog

Daily delta of the host's account surface against a
learned baseline: every `/etc/passwd` entry, the uid=0
set, and the sudo/wheel/admin privilege roster. A NEW
account — especially a NEW uid=0 or a NEW sudo member —
is the canonical T1136 persistence + T1078 privilege
indicator.

## Why this matters

After compromise, attackers establish durable access by
touching the account surface:
- `useradd -ou 0 -g 0 backdoor` — a second uid=0 account
  that's root without being named root.
- `usermod -aG sudo www-data` — granting a service
  account sudo.
- Adding a normal-looking user (`gituser`, `backup-svc`)
  that's actually the attacker's.
- Editing `/etc/passwd` offline (mounted disk) then
  booting.

All of these change `/etc/passwd` or group membership.
Baselining the account surface + diffing daily catches
the change mechanically, and escalates severity when the
new account is privileged.

Complements `acct-baseline` (which audits account-change
EVENTS in real time via auditd) — this is the periodic
state-delta backstop that catches what the live audit
missed or what was edited offline.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on any ADDED account → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| New non-privileged user | `warn` | `new_account` |
| New uid=0 OR new sudo/wheel/admin member | `alert` | `new_privileged_account` |

## What's recorded

| Class | Identity |
|---|---|
| `user` | `name:uid:gid:shell` (gecos/home/password fields excluded — they churn) |
| `uid0` | every account with uid 0 |
| `sudo` | members of sudo/wheel/admin (both group-roster AND primary-gid members) |

## Baseline file

`/var/lib/selfdef/accounts-baseline.tsv` (mode 0600).
First scan creates it; re-baseline after legitimate
account changes:
```bash
sudo rm /var/lib/selfdef/accounts-baseline.tsv
sudo systemctl start selfdef-accounts.service
```
Preserved across uninstall (forensic).

## Cadence

`OnBootSec=5min` + `OnCalendar=*-*-* 05:50:00` + jitter.
Boot catch confirms the account-set after every restart
(catches the offline-edit-then-boot attack); daily 05:50
extends the staggered ladder right after cron-jobs (05:45).

## MITRE coverage

- **T1136.001** Create Account: Local Account — PRIMARY;
  a new /etc/passwd entry is the exact artifact.
- **T1078.003** Valid Accounts: Local Accounts — a new
  uid=0 or sudo member is privileged-account persistence.
- **T1098** Account Manipulation — adding a user to the
  sudo group is account-manipulation.
- **T1548.003** Abuse Elevation Control: Sudo — new sudo
  roster member.

## Operator workflow

```bash
# Last scan summary
journalctl -t selfdef-accounts -n 1 --no-pager

# Per-account detail (added/removed)
journalctl -t selfdef-accounts-detail --since "1 day ago"

# Manual inventory
awk -F: '($3==0){print "uid0: "$1}' /etc/passwd
getent group sudo wheel admin
awk -F: '{print $1":"$3":"$7}' /etc/passwd

# Investigate an alert
id <new-account>
sudo grep <new-account> /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d/*

# Re-baseline after a legitimate account addition
sudo rm /var/lib/selfdef/accounts-baseline.tsv
sudo systemctl start selfdef-accounts.service
```

## Caveats

- **Package installs create service accounts** (e.g.
  `_apt`, `systemd-coredump`, `nginx`) → fires
  `new_account` legitimately. Operator confirms + re-
  baselines after a package wave.
- **LDAP / SSSD / cloud-init users** that appear via NSS
  but not /etc/passwd are NOT covered — this module reads
  the local files only. A future enhancement could walk
  `getent passwd` (which includes NSS sources).
- **Daily + boot cadence**: an account added + removed
  within a day between scans is caught at boot if a
  reboot intervenes; otherwise the acct-baseline live
  audit event covers that window.
- **/etc/shadow content is NOT hashed** — only the
  account roster (passwd/group) is. Password-hash
  changes are out of scope (pam-history covers reuse;
  this covers existence).

## Coexistence

- **acct-baseline**: complementary — acct-baseline emits
  real-time auditd events on account changes; this is the
  periodic state-delta backstop catching offline edits +
  rotated-out audit events.
- **cron-job-watchdog + suid-sgid-watchdog + listening-
  ports-watchdog**: sibling delta-detection modules —
  the four canonical persistence surfaces (accounts /
  scheduled tasks / setuid binaries / network listeners).
- **pam-pwquality + pam-history + pam-faillock**:
  complementary — those govern password strength/reuse/
  lockout for the accounts; this watches for new accounts
  appearing.
- **service-account-lock**: complementary — that locks
  service accounts' shells; this detects new ones added.
