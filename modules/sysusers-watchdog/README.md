# sysusers-watchdog

Boot + daily delta of the `systemd-sysusers` declarations against a
learned baseline, plus an ownership + semantic scan. Catches a
backdoor account or group that is recreated automatically at boot.
MITRE **T1136** / **T1098**.

## Why this matters

`systemd-sysusers` creates the declared users and groups **at boot**
(and on package install) from:

- `/etc/sysusers.d/*.conf` — admin declarations
- `/run/sysusers.d/*.conf` — runtime declarations

Line format (whitespace-separated):

```
#Type Name   ID         GECOS        Home     Shell
u     svc    999        "Service"    /var/svc /usr/sbin/nologin
g     svc    998
m     svc    docker                              (add svc to group docker)
r     -      500-600                             (reserve an id range)
```

The danger is **idempotent recreation**: a planted declaration
recreates its account/group every time `systemd-sysusers` runs — so
even if a defender deletes the rogue account, it **comes back at the
next boot**. A `u` entry with **UID 0** is a second root; an `m`
entry adding a user to a **privileged group** (`sudo`, `wheel`,
`docker`, `disk`, `shadow`, …) is silent privilege escalation.

This is distinct from **account-watchdog**, which watches the live
`/etc/passwd` / `/etc/shadow` / `/etc/group` state. This watchdog
watches the **declarations that regenerate** that state.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any sysusers declaration change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No sysusers.d declarations present | `ok` | `no_sysusers` |
| No delta | `ok` | `sysusers_intact` |
| An entry added / changed / removed | `warn` | `sysusers_changed` |
| A `.conf` world-writable/non-root, OR a `u` entry with UID 0, OR an `m` membership into a privileged group | `alert` | `sysusers_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each `.conf`.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `ent:<path>:<type>:<name>:<id>` — each declaration entry (the
  `id`/group field is parsed from column 3, which precedes the
  quotable GECOS field, so it is robust).

## Cadence

`OnBootSec=58min` + `OnCalendar=*-*-* 10:55:00` — extends the
staggered ladder after binfmt (10:50). A planted declaration
recreates its account at the next `systemd-sysusers` run, so the
daily catch bounds dwell time; the boot catch confirms the
declaration set after a restart.

## MITRE coverage

- **T1136** Create Account — declarative account creation at boot.
- **T1098** Account Manipulation — `m` entries grant group
  membership (privilege).
- **T1078** Valid Accounts — a UID-0 declaration mints a
  root-equivalent login.

## Operator workflow

```bash
journalctl -t selfdef-sysusers -n 1 --no-pager
journalctl -t selfdef-sysusers-detail --since "1 day ago"

# Inventory the declarations and what they would create
cat /etc/sysusers.d/*.conf /run/sysusers.d/*.conf 2>/dev/null
systemd-sysusers --dry-run 2>/dev/null    # show pending actions

# Cross-check against the live account state (account-watchdog domain)
getent passwd | awk -F: '$3==0{print "UID0:",$1}'

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/sysusers.d/<file>.conf
sudo rm /var/lib/selfdef/sysusers-baseline.tsv
sudo systemctl start selfdef-sysusers.service
```

## Caveats

- **Packages ship legitimate declarations** (most daemons declare
  their service account via sysusers.d now); a new root-owned `u`
  entry with a non-zero UID and `nologin` shell fires `warn`
  (re-baseline). The UID-0 / privileged-membership /
  world-writable / non-root tiers are the high-confidence alert.
- **/usr/lib/sysusers.d is not watched** — it is package-managed
  (integrity-sentinel / aide-bridge territory); this module watches
  the admin/runtime `/etc` + `/run` dirs an attacker would write to.
- **Shell field not parsed:** a quoted GECOS with spaces makes the
  6th (shell) column unreliable to extract positionally, so this
  module flags on UID/membership/ownership rather than shell. Cross-
  check a suspicious account's shell via `systemd-sysusers --dry-run`
  or `getent passwd`.
- **Daily+boot cadence** misses a declare-boot-undeclare inside the
  window; an audit-rules watch on the sysusers.d dirs' writes is the
  real-time complement.

## Coexistence

- **account-watchdog / group-integrity-watchdog**: live passwd /
  group state; this is the declarative source that regenerates it.
- **nullok-disable / service-account-lock / login-defs-baseline**:
  account-hardening posture; this catches the boot-time creation of
  a new account that would bypass it.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  `.conf` files; this adds the semantic (UID-0 / priv-group) view.
