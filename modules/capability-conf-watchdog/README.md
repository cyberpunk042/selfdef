# capability-conf-watchdog

Boot + daily delta of the pam_cap capability-grant config
(`/etc/security/capability.conf`) against a learned baseline.
Catches a Linux capability granted to a user for privilege
escalation. MITRE **T1548** (Abuse Elevation Control Mechanism).

## Why this matters

When `pam_cap.so` is in the PAM stack, the lines in
`/etc/security/capability.conf` grant Linux capabilities to users
at login. Format: `<cap-list> <user>`:

```
cap_net_raw,cap_net_admin   netadmin     # legit, scoped
cap_setuid,cap_sys_admin    eviluser     # ← privesc grant
all                         backdoor     # full caps = root
```

A high-power capability granted to an ordinary user is privilege
escalation **without setuid or sudo**: `cap_setuid` → become any
uid; `cap_dac_override` → bypass all file permissions;
`cap_sys_admin`/`cap_sys_module` → effectively root;
`cap_sys_ptrace` → inject into root processes; `all` → root. This
is the per-USER login-cap surface — distinct from file/binary caps.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any capability.conf change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No capability.conf | `ok` | `no_capability_conf` |
| No delta | `ok` | `capability_conf_intact` |
| Any grant added / removed / changed | `warn` | `capability_conf_changed` |
| A NEWLY-ADDED grant containing a dangerous capability | `alert` | `capability_conf_dangerous_grant` |

Dangerous caps: `cap_setuid`, `cap_setgid`, `cap_sys_admin`,
`cap_sys_module`, `cap_dac_override`, `cap_dac_read_search`,
`cap_sys_ptrace`, `cap_fowner`, `cap_mknod`, `cap_sys_rawio`,
`cap_chown`, `cap_setfcap`, and `all`. The alert is delta-based —
a pre-existing dangerous grant is flagged once at baseline for
vetting, then not re-alerted.

## What's recorded

- `cap:<user>:<caplist>` — each capability grant (cap-list +
  user).
- `file:<path>:<sha12>` — hash of capability.conf.

## Cadence

`OnBootSec=31min` + `OnCalendar=*-*-* 08:40:00` — extends the
staggered ladder after xdg-autostart (08:35). A grant takes
effect on the next login, so the boot catch confirms the set
after a restart.

## MITRE coverage

- **T1548** Abuse Elevation Control Mechanism — granting
  privileged capabilities to a user is an elevation-control
  abuse.
- **T1098** Account Manipulation (adjacent) — capability grants
  are an account-power change.
- **T1078.003** Valid Accounts: Local Accounts — a cap-empowered
  ordinary account behaves like a privileged one.

## Operator workflow

```bash
journalctl -t selfdef-capability-conf -n 1 --no-pager
journalctl -t selfdef-capability-conf-detail --since "1 day ago"

# Is pam_cap even active? (grants are inert without it)
grep -rn pam_cap /etc/pam.d/

# Current grants
grep -vE '^\s*#|^\s*$' /etc/security/capability.conf

# Investigate a dangerous_grant alert, then re-baseline:
sudo $EDITOR /etc/security/capability.conf   # remove the rogue grant
sudo rm /var/lib/selfdef/capability-conf-baseline.tsv
sudo systemctl start selfdef-capability-conf.service
```

## Caveats

- **Grants are inert unless `pam_cap.so` is in the stack.** The
  module still baselines them — an attacker who adds both pam_cap
  to the stack (caught by pam-config-watchdog) and a grant here
  is caught by the pair.
- **Legit scoped grants exist** (e.g. `cap_net_raw` to a network
  tool's service account); the alert targets the
  privesc-grade caps. Other changes are `warn` (review).
- **Daily+boot cadence** misses an inject-login-revert within the
  window; an audit-rules watch on `/etc/security/capability.conf`
  writes is the real-time complement.

## Coexistence

- **file-capabilities-watchdog**: watches setcap xattrs on
  BINARIES (file caps); this watches per-USER login caps via
  pam_cap. Complementary capability surfaces.
- **pam-config-watchdog**: watches whether `pam_cap` is wired
  into the stack; this watches the grant DATA it reads.
- **access-conf / limits-conf / sudoers-defaults watchdogs**: the
  other `/etc/security` + sudo privilege surfaces; this adds the
  capability-grant one.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the file; this adds the per-grant + dangerous-cap semantic view.
