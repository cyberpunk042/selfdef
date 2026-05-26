# anacrontab-watchdog

Boot + daily delta of `/etc/anacrontab` against a learned
baseline, plus an ownership + command scan. Catches a rogue
anacron job that runs as root. MITRE **T1053.003** (Scheduled
Task/Job: Cron — anacron variant).

## Why this matters

anacron is the catch-up scheduler that runs jobs missed while the
host was powered off; its job commands run **as root**. Job line
format:

```
period  delay  job-identifier  command...
1       5      cron.daily      run-parts /etc/cron.daily
7       25     evil            /tmp/.payload          # root, on catch-up
```

A rogue job line (or a tampered command on an existing one) is
root-exec persistence that `cron-job-watchdog` — which covers
crontab / cron.d / `cron.{daily,weekly,monthly}` — does **not**
see, because `/etc/anacrontab` is a separate file.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any anacrontab change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No anacrontab | `ok` | `no_anacrontab` |
| No delta | `ok` | `anacrontab_intact` |
| A job / env / file change | `warn` | `anacrontab_changed` |
| A job command under /tmp /home /dev/shm, world-writable, or bare/relative; an injection pattern; or a world-writable/non-root anacrontab | `alert` | `anacrontab_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of anacrontab.
- `own:<path>:<owner:mode>` — owner + mode.
- `job:<job-id>:<cmd0>` — each job's command (first token; bare
  commands like `run-parts`/`nice` are benign, a tmp/relative
  path is the signature).
- `env:<key>:<value>` — env assignments (PATH, RANDOM_DELAY, …).
- `susp:<file>:<pattern>` — an injection pattern in the file.

## Cadence

`OnBootSec=39min` + `OnCalendar=*-*-* 09:20:00` — extends the
staggered ladder after logrotate (09:15). A rogue job runs on the
next anacron catch-up, so the boot catch confirms anacrontab after
a restart.

## MITRE coverage

- **T1053.003** Scheduled Task/Job: Cron — anacron is the
  catch-up cron variant; a job is root-scheduled execution.
- **T1059.004** — the job command is shell execution.

## Operator workflow

```bash
journalctl -t selfdef-anacrontab -n 1 --no-pager
journalctl -t selfdef-anacrontab-detail --since "1 day ago"

# Current jobs
grep -vE '^\s*#|^\s*$|=' /etc/anacrontab 2>/dev/null

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR /etc/anacrontab      # remove the rogue job line
sudo rm /var/lib/selfdef/anacrontab-baseline.tsv
sudo systemctl start selfdef-anacrontab.service
```

## Caveats

- **Standard anacrontab has 3 jobs** (cron.daily/weekly/monthly
  via run-parts); a new job or changed command fires `warn`, and
  the tmp/relative-command + injection + ownership tiers are the
  high-confidence alert. Re-baseline after a legit change.
- **Some distros drive anacron via systemd timers** instead of
  /etc/anacrontab; this watches the file when present
  (`no_anacrontab` no-op otherwise).
- **Daily+boot cadence** misses an inject-run-revert within the
  window; an audit-rules watch on `/etc/anacrontab` writes is the
  real-time complement.

## Coexistence

- **cron-job-watchdog**: crontab / cron.d / cron.{daily,weekly,
  monthly} dirs; this adds the `/etc/anacrontab` catch-up
  scheduler that those don't read. Complementary cron-family
  views.
- **at-jobs-watchdog**: the one-shot `at` scheduler; cron + at +
  anacron are the three scheduler-persistence surfaces.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  anacrontab; this adds the per-job command + injection view.
