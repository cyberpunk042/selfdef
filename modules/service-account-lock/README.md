# service-account-lock

Walks `/etc/passwd` and locks service accounts (UID < 1000)
that have interactive shells. Most distros leave several daemon
accounts with `/bin/sh` or `/bin/bash` for historical reasons
— `games`, `gnats`, `news`, `mail`, `list`, `irc` are common
offenders on Debian-derived hosts.

## Why this matters

Service accounts with interactive shells are the canonical
"forgotten default accounts" attack surface:

- An attacker who finds a CVE in any daemon RUNNING AS those
  service accounts gets a shell at their UID. With shell=
  /usr/sbin/nologin, the immediate shell-spawn fails.
- Some installer scripts use `su - <serviceuser>` to test
  startup; with the service account locked, that test fails
  loudly — operator notices the deviation from baseline.
- Operator workflow auditing becomes simpler: any sudo or su
  attempt FROM root TO a locked service account is a high-
  signal anomaly (no legitimate operator workflow does this).

T1078.001 + T1078.003 (Valid Accounts: Default + Local) are both
mitigated.

## Profiles

| Profile | Behavior |
|---|---|
| `audit` (default) | Walk /etc/passwd + report findings to journal; do NOT modify. Safe baseline. |
| `enforce` | Record original shell to `/etc/selfdef/service-accounts-original.txt` + `chsh -s /usr/sbin/nologin` + `passwd -l` for every match. |

The audit-first pattern is intentional: operator runs apply
once in audit mode to see WHICH accounts have interactive
shells, inspect them (some may legitimately need shells for
local-tool invocation), then flip to enforce.

## Selection criteria

An account is selected for locking IF ALL of:
- UID < 1000 (system/service account threshold; convention
  shared by Debian/Ubuntu/RHEL/Fedora)
- UID not in `reserved_uids` (default: 0, 1, 2, 3 = root,
  daemon, bin, sys — operator-tunable)
- Shell ∉ {/usr/sbin/nologin, /sbin/nologin, /usr/bin/nologin,
  /bin/false, /usr/bin/false, ""} (i.e. shell looks interactive)

## MITRE coverage

- **T1078.001** Valid Accounts: Default Accounts — primary;
  blocks login via forgotten distro-default service accounts.
- **T1078.003** Valid Accounts: Local Accounts — narrows the
  attacker's pool of usable local accounts.
- **T1136.001** Create Account: Local Account — defender side:
  cleaner /etc/passwd makes operator-noticed any new account
  creation that adds an interactive shell to a UID<1000 entry.

## Cross-distro support

| Distro | Service accounts with interactive shells (typical) |
|---|---|
| Debian/Ubuntu | games, gnats, mail, list, irc, news, sync (intentional for `sync && halt`) |
| RHEL/Fedora | none by default (RHEL convention: all daemon accounts ship /sbin/nologin) |
| Arch | minimal; most services ship nologin |
| openSUSE | mixed; some user-package daemons ship /bin/bash |

audit mode reports zero findings on a clean RHEL host (expected
no-op). On Debian, audit typically reports 3-7 findings on
first install.

## Operator workflow

```bash
# Step 1: audit-only first.
sudo selfdefctl modules apply service-account-lock
sudo journalctl -t selfdef-modules | grep FOUND

# Step 2: inspect each finding manually. Confirm the account is
# REALLY not needed for interactive use.
getent passwd games        # uid=5  shell=/bin/sh

# Step 3: flip to enforce.
sudo sed -i 's/profile = "audit"/profile = "enforce"/' \
    /etc/selfdef/modules/service-account-lock.toml
sudo selfdefctl modules apply service-account-lock

# Step 4: verify.
getent passwd games        # now shell=/usr/sbin/nologin
cat /etc/selfdef/service-accounts-original.txt  # restoration log

# To restore a specific account:
sudo chsh -s /bin/sh games
sudo passwd -u games

# To re-lock after restore:
sudo selfdefctl modules apply service-account-lock
```

## Caveats

- **PAM restrictions on chsh** — Debian's `chsh` reads
  /etc/shells; if /usr/sbin/nologin isn't listed there, chsh
  refuses. apply.sh logs WARN on failure; operator adds
  /usr/sbin/nologin to /etc/shells or sets `--shell` directly.
- **sync(8) is intentional** — Debian's `sync` user with
  shell=/bin/sync exists so operator on console can `login sync`
  to safely flush+poweroff. Enforce mode locks this; restore
  via the operator workflow above if needed.
- **passwd -l can break some service-account daemons** that
  read /etc/shadow for their own auth (rare; most use socket
  activation). The shell=nologin alone suffices for the attack
  surface; operator can skip passwd -l by editing apply.sh.
- **NIS/LDAP/sssd-backed accounts** are NOT touched (only
  /etc/passwd is walked). Network-account systems have their
  own /etc/nsswitch.conf-mediated lock procedures.

## Coexistence

- **nullok-disable**: removes empty-password login path; even
  if a service account had empty password historically + nullok
  is set, both this module's chsh-to-nologin AND nullok-disable's
  PAM tightening block the login.
- **pam-faillock**: locks accounts after N failed auths; this
  module preemptively makes those accounts un-loginable in the
  first place.
- **sudo-tune**: per-tty sudo timestamp + iolog session
  recording. Combined: even if a service account gets unlocked
  legitimately, every action via sudo is iolog'd.
