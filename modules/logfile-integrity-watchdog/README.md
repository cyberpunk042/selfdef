# logfile-integrity-watchdog

Detects log-tampering by tracking the monotonic growth +
inode stability of critical logs (wtmp, btmp, lastlog,
auth.log, secure, audit.log, journal, syslog, messages). A
log that SHRANK while keeping the SAME inode is the
in-place-truncation signature of an attacker erasing their
tracks.

## Why this matters

Indicator removal (MITRE T1070) is a near-universal
post-compromise step: after logging in + acting, the
attacker wipes the evidence. The classic moves:
- `: > /var/log/wtmp` — erase the login record (no more
  `last` showing their session).
- `truncate -s 0 /var/log/auth.log` — erase the SSH auth
  trail.
- `sed -i '/evil/d' /var/log/secure` — surgically remove
  their lines (shrinks the file in place).

Append-only logs only ever GROW between rotations. The one
thing that should NEVER happen is the file getting SMALLER
while keeping the same inode. logrotate changes the inode
(rename + recreate) — that's benign and distinguishable.
Same-inode shrink has no legitimate cause.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 on any same-inode shrink or missing log → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| All logs grew or rotated cleanly | `ok` | `logs_intact` |
| A tracked log went missing (deleted) | `warn` | `log_missing` |
| Same-inode size shrink (in-place truncation) | `alert` | `log_truncation_detected` |

## How it distinguishes tamper from rotation

State file records `path  inode  size` per log. On each
scan:
- **Same inode, size ≥ last** → append (benign growth).
- **Same inode, size < last** → **IN-PLACE TRUNCATION**
  (ALERT — the tamper signature).
- **Different inode** → rotation/recreation (logrotate
  renames + makes a fresh file). Counted as `rotated`, not
  alerted, and the state re-baselines.
- **Path gone** → deleted (`warn`).

## Watched logs

`/var/log/{wtmp,btmp,lastlog,auth.log,secure,syslog,
messages}`, `/var/log/audit/audit.log`, and
`/var/log/journal` (aggregate dir size). Only those that
exist are tracked.

## Cadence

`OnBootSec=6min` + `OnUnitActiveSec=30min` + jitter — a
tighter 30-min cadence (vs the daily forensic scans)
because truncation is a fast action right after the
attacker's activity; catching it quickly keeps the
surrounding events still in the notifier pipeline.

## MITRE coverage

- **T1070.002** Indicator Removal: Clear Linux or Mac
  System Logs — PRIMARY; wtmp/auth.log/secure truncation.
- **T1070.006** Indicator Removal: Timestomp — inode
  change tracking catches recreation-based tamper.
- **T1070.003** Indicator Removal: Clear Command History
  — sibling technique (shell history); this covers the
  system-log half.
- **T1485** Data Destruction — log wipe is targeted
  destruction.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-logfile-integrity -n 1 --no-pager

# Detail (which log + old->new size)
journalctl -t selfdef-logfile-integrity-detail --since "1 day ago"

# Investigate a truncation alert
sudo stat /var/log/wtmp
last -f /var/log/wtmp | head        # is the login history suspiciously short?
# Cross-check with the persisted state
sudo cat /var/lib/selfdef/logfile-integrity-state.tsv
```

## Caveats

- **logrotate is benign** — it changes the inode, which
  this module recognizes as rotation (not tamper) and
  re-baselines. No false positive from normal rotation.
- **journal vacuum** (`journalctl --vacuum-size`)
  legitimately shrinks `/var/log/journal` → may fire
  `log_truncation_detected` for the journal dir. Operator
  who runs manual vacuums treats journal-dir shrink as
  expected; the per-log detail distinguishes it from
  wtmp/auth.log tamper.
- **30-min cadence** misses a wipe-then-restore within the
  window; the real defense pairing is shipping logs OFF
  the host (the notifier engine's Loki/OpenSearch
  integrations) so an on-host wipe doesn't erase the
  shipped copy.
- **The state file itself** could be tampered if the
  attacker has root + knows about it. Stored 0600; pair
  with auditd watching /var/lib/selfdef + off-host log
  shipping for tamper-evidence.

## Coexistence

- **auditd (audit-rules + auditd-immutable)**: complementary
  — auditd-immutable makes the audit log append-only at the
  kernel layer; this watches the broader log set for
  truncation. The notifier engine ships both off-host.
- **aide-bridge + integrity-sentinel**: complementary file-
  integrity (content hash); this is size/inode-monotonicity
  specialized for append-only logs.
- **account-watchdog + cron-job-watchdog**: complementary —
  an attacker who truncates wtmp to hide a login may also
  have added an account/cron job those modules catch.
- **journald-collector / notifier**: the durable answer is
  off-host log shipping; this module catches the on-host
  tamper attempt.
