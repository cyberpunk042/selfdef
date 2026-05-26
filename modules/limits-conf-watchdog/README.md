# limits-conf-watchdog

Boot + daily delta of the `pam_limits` resource-limit config
(`/etc/security/limits.conf` + `limits.d/*`) against a learned
baseline. Catches a re-enabled core dump (hardening revert) and
limit drift. MITRE **T1005** (Data from Local System) /
**T1562.001** (Impair Defenses).

## Why this matters

`pam_limits` applies these limits at login. The
security-relevant case: an attacker who re-enables core dumps —

```
* hard core unlimited
```

reverts the `coredump-suid-restrict` protection and re-opens
**memory-secret harvesting**: a setuid binary's core dump
routinely contains the credentials, keys, and decrypted secrets
it was handling. Loosening `nproc` / `nofile` / `maxlogins`
enables fork-bomb / fd-exhaustion / multi-session abuse.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any limits change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No limits.conf | `ok` | `no_limits_conf` |
| No delta | `ok` | `limits_conf_intact` |
| Any limit / file added, removed, or changed | `warn` | `limits_conf_changed` |
| A NEWLY-ADDED `core` limit with a non-zero value | `alert` | `limits_conf_core_reenabled` (the hardening-revert signature) |

A pre-existing non-zero `core` value is flagged once at baseline
for vetting, then does not re-alert (delta-based, like
access-conf-watchdog) — only a newly-added core re-enable
alerts.

## What's recorded

- `limit:<domain>:<type>:<item>:<value>` — each parsed limit
  line (`domain` = `*`/user/`@group`; `type` = hard/soft/-;
  `item` = core/nproc/nofile/…).
- `file:<path>:<sha12>` — hash of limits.conf + each limits.d
  drop-in.

## Cadence

`OnBootSec=22min` + `OnCalendar=*-*-* 07:55:00` — extends the
staggered ladder after systemd-generator (07:50). A limit change
takes effect on the next login, so the boot catch confirms the
config after a restart.

## MITRE coverage

- **T1005** Data from Local System — re-enabling core dumps to
  harvest secrets from a crashed (setuid) process's memory.
- **T1562.001** Impair Defenses — reverting the
  coredump-suid-restrict hardening.
- **T1499**-adjacent — loosening `nproc`/`nofile` enables
  resource-exhaustion DoS.

## Operator workflow

```bash
journalctl -t selfdef-limits-conf -n 1 --no-pager
journalctl -t selfdef-limits-conf-detail --since "1 day ago"

# Current limits
grep -rvE '^\s*#|^\s*$' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null

# Investigate a core_reenabled alert
# - Who added `core unlimited`? It undoes secret protection.
ulimit -c                              # effective core limit
# Remove the line, then re-baseline:
sudo $EDITOR /etc/security/limits.d/<file>.conf
sudo rm /var/lib/selfdef/limits-conf-baseline.tsv
sudo systemctl start selfdef-limits-conf.service
```

## Caveats

- **Dev/debug hosts** may legitimately set a non-zero `core`
  limit; the alert is delta-based (only a NEW core re-enable
  fires), and baseline flags any pre-existing one once for
  vetting. Re-baseline to accept.
- **Other limits** (nproc/nofile/maxlogins) are tracked as
  `warn` on change — surfaced for review without a dedicated
  alert tier (their abuse is DoS, lower-confidence than the
  core-dump secret-harvest signature).
- **Daily+boot cadence** misses an inject-login-revert within
  the window; an audit-rules watch on `/etc/security/limits*`
  writes is the real-time complement.

## Coexistence

- **coredump-suid-restrict**: SETS the `core 0` hard limit +
  `fs.suid_dumpable=0` (prevention); this DETECTS tampering that
  reverts it. Prevention + detection pair.
- **coredump-pattern-watchdog / coredumpd-redirect**: the
  kernel core_pattern side (where dumps go); this is the
  per-login ulimit side (whether they happen at all).
- **access-conf-watchdog**: the other `/etc/security/*` file
  (login access); together they cover the pam_access + pam_limits
  security configs.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the limits files; this adds the parsed-limit + core-reenable
  semantic view.
