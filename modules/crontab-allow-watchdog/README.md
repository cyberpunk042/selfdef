# crontab-allow-watchdog

Daily + boot delta of the who-may-schedule roster —
`/etc/cron.allow`, `/etc/cron.deny`, `/etc/at.allow`,
`/etc/at.deny` — against a learned baseline. Catches an
attacker granting themselves scheduling capability, which
`cron-job-watchdog` (the jobs) and `cron-baseline` (the
policy) don't surface.

## Why this matters

These four files decide WHO may use cron/at:
- If `cron.allow` exists, ONLY users listed in it may use
  cron (deny-by-default — the `cron-baseline` hardened
  posture).
- Otherwise `cron.deny` lists who may NOT.

An attacker who has compromised a low-privilege service
account, and finds the host is deny-by-default, can't
schedule persistence — until they add their account to
`cron.allow`. That single-line edit is a CAPABILITY GRANT:
it doesn't create a job yet (so `cron-job-watchdog` stays
quiet), but it unlocks the ability to. Equivalently,
removing their account from `cron.deny` grants the same
capability.

This module watches the roster + escalates specifically on
a capability grant (added to `*.allow` or removed from
`*.deny`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any roster change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| A roster file changed (non-grant direction) | `warn` | `schedule_roster_changed` |
| User added to cron.allow/at.allow OR removed from cron.deny/at.deny | `alert` | `schedule_capability_granted` |

## Cadence

`OnBootSec=8min` + `OnCalendar=*-*-* 06:30:00` — extends
the staggered ladder after timestomp (06:20) +
kernel-cmdline (06:25); boot catch confirms the roster.

## MITRE coverage

- **T1053.003** Scheduled Task/Job: Cron — PRIMARY; the
  capability-grant precursor to cron persistence.
- **T1098** Account Manipulation — granting a scheduling
  capability is a form of account manipulation.
- **T1548** Abuse Elevation Control Mechanism — narrowly;
  cron jobs run as the listed user.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-crontab-allow -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-crontab-allow-detail --since "1 day ago"

# Manual inventory
for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    echo "== $f =="; cat "$f" 2>/dev/null
done

# Re-baseline after a legit roster change
sudo rm /var/lib/selfdef/crontab-allow-baseline.tsv
sudo systemctl start selfdef-crontab-allow.service
```

## Caveats

- **Legit operator changes** (adding a new sysadmin to
  cron.allow) fire once, then re-baseline absorbs them.
- **No cron.allow + no cron.deny** = cron open to all
  (the distro default on some systems); `cron-baseline`
  is the module that ESTABLISHES the deny-by-default
  posture this watchdog then monitors. Pair them.
- **Daily+boot cadence** misses a grant-schedule-revoke
  within the window; audit-rules watching these four
  files is the real-time complement.

## Coexistence

- **cron-baseline + at-disable**: those SET the policy
  (deny-by-default cron / mask atd); this DETECTS roster
  drift. Establish + monitor pair.
- **cron-job-watchdog**: complementary — that watches the
  JOBS (what's scheduled); this watches the CAPABILITY
  (who may schedule). The grant precedes the job.
- **account-watchdog + sudoers-integrity-watchdog**:
  sibling capability-grant detectors (account creation /
  sudo grant / schedule grant).
- **audit-rules**: real-time write watch on the four
  roster files; this is the periodic delta backstop.
