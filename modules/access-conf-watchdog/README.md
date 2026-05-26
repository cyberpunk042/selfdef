# access-conf-watchdog

Boot + daily delta of the pam_access login-access-control rules
(`/etc/security/access.conf` + `access.d/*`) against a learned
baseline. Catches a broad permit rule or a removed deny rule
that changes who may log in. MITRE **T1556** (Modify
Authentication Process) / **T1098** (Account Manipulation).

## Why this matters

When `pam_access.so` is in the PAM stack (account phase, common
in hardened configs), `/etc/security/access.conf` decides **who
may log in from where**. Rules are first-match:

```
permission : users/groups : origins
-  : ALL EXCEPT root (wheel) : ALL        # lock down
+  : eviluser : ALL                        # ← attacker grant
```

An attacker who appends a broad **permit** rule grants
themselves login access from anywhere; one who **removes a deny
rule** weakens the lockdown. Both are quiet access persistence
that the PAM stack hash (pam-config-watchdog) does not see — the
stack still references `pam_access.so`; only the RULE DATA
changed.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any access.conf change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No access.conf | `ok` | `no_access_conf` |
| No delta | `ok` | `access_conf_intact` |
| Any rule added / removed / changed | `warn` | `access_conf_changed` |
| A `+` (permit) rule whose origin is `ALL`/broad | `alert` | `access_conf_broad_permit` (the backdoor-access signature) |

## What's recorded

- `file:<path>:<sha12>` — hash of access.conf + each access.d
  drop-in.
- `rule:<perm>:<users>:<origins>` — each normalized rule
  (`perm` = `+`/`-`; whitespace collapsed).

A `+` permit-from-`ALL` rule is alert-grade: granting login from
anywhere to a user/group is the canonical access backdoor in
this file.

## Cadence

`OnBootSec=18min` + `OnCalendar=*-*-* 07:35:00` — extends the
staggered ladder after hosts-file (07:30). A permit rule takes
effect on the next login, so the boot catch confirms the
login-access rules after a restart.

## MITRE coverage

- **T1556** Modify Authentication Process — altering who PAM
  permits to authenticate/log in.
- **T1098** Account Manipulation — granting an account login
  access via access.conf rather than group membership (which
  account-watchdog / group-integrity-watchdog cover).
- **T1562.001** Impair Defenses (adjacent) — removing a deny
  rule weakens an access lockdown.

## Operator workflow

```bash
journalctl -t selfdef-access-conf -n 1 --no-pager
journalctl -t selfdef-access-conf-detail --since "1 day ago"

# Is pam_access even active? (rules are inert without it)
grep -rn pam_access /etc/pam.d/

# Current rules
grep -vE '^\s*#|^\s*$' /etc/security/access.conf

# Investigate a broad_permit alert, then re-baseline:
sudo $EDITOR /etc/security/access.conf      # remove the rogue '+' rule
sudo rm /var/lib/selfdef/access-conf-baseline.tsv
sudo systemctl start selfdef-access-conf.service
```

## Caveats

- **Rules are inert unless `pam_access.so` is in the stack.**
  The module still baselines them — an attacker who ADDS both
  pam_access to the stack (caught by pam-config-watchdog) and a
  permit rule here is caught by the pair.
- **access.conf semantics are first-match + support EXCEPT /
  group / origin syntax** the module does not fully evaluate; it
  records rules verbatim (delta) + flags the unambiguous
  permit-from-ALL case. Every change is surfaced (`warn`) for
  operator review regardless.
- **Daily+boot cadence** misses an inject-login-revert within the
  window; an audit-rules watch on `/etc/security/access.conf`
  writes is the real-time complement.

## Coexistence

- **pam-config-watchdog**: watches the PAM STACK (whether
  pam_access is invoked + module hashes); this watches the RULE
  DATA pam_access reads. Together: is the gate wired, and what
  does the gate allow.
- **login-defs-baseline**: UID ranges / password aging in
  login.defs — a different login-policy file; complementary.
- **account-watchdog / group-integrity-watchdog**: who EXISTS +
  group membership; this is who may LOG IN. Orthogonal access
  controls.
- **sshd-config-watchdog**: AllowUsers/DenyUsers at the sshd
  layer; access.conf is the PAM-layer equivalent that also
  covers console/other PAM services. Both layers worth watching.
