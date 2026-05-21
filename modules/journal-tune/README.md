# journal-tune

systemd-journald tuning for selfdef's high-volume tagged events.
Default journald settings DROP events under burst load — a silent
visibility gap that breaks the detection pipeline.

## Why this matters

The selfdef detection modules emit structured events tagged
`selfdef-aide`, `selfdef-aide-detail`, `selfdef-rkhunter`,
`selfdef-rkhunter-detail`, `selfdef-lynis`, `selfdef-time-skew`.
Default journald:
- Rate-limits at 10000 messages per 30 seconds **per service**.
  aide-bridge's selfdef-aide-detail tag can blow past that during
  a large diff.
- Caps LineMax at 48 KiB — truncates rich JSON payloads with long
  `sample[]` arrays.
- Uses up to 10% of /var (often = 50+ GB on a developer host
  with a big /var) for retention; operator-readable space
  pressure.
- Forwards everything to syslog (duplicates if rsyslog is also
  running).

This module tunes those defaults to selfdef's actual workload.

## Profiles

| Profile | Persistent journal | Ratelimit | LineMax | MaxLevelStore | Use |
|---|---|---|---|---|---|
| `standard` (default) | 500 MiB, 30-day retention, SystemKeepFree=1G | 30000/30s | 256K | info | Hosts running daily-cadence detection modules |
| `paranoid` | 4 GiB, 90-day retention, SystemKeepFree=2G | DISABLED | 512K | debug | Hosts running audit-rules `paranoid` OR verbose AI tools |

Both profiles:
- `Storage=persistent` (force /var/log/journal/ — survives reboot)
- `Compress=yes` (zstd)
- `ForwardToSyslog=no` (selfdef-collector-journald reads directly)
- `ForwardToWall=no` (no console interruption)
- 30-/90-day MaxRetentionSec

## File

Drop-in at `/etc/systemd/journald.conf.d/50-selfdef.conf`. systemd-
journald composes this with `/etc/systemd/journald.conf` (OS
default) + any later-named drop-ins from operator (`60-…`,
`99-…`).

## Operator-extension

Operator-tuned overrides drop at `/etc/systemd/journald.conf.d/
60-operator.conf` (lex-order after ours → overrides). selfdef
NEVER touches operator-prefixed files.

Common operator extension patterns:
- Forward to remote syslog: `ForwardToSyslog=yes`
- Tighter MaxLevelStore for a memory-constrained host
- ReadKMsg=no (don't ingest kernel ring buffer)

## Coexistence with auditd-tune

| Module | Tunes | Path |
|---|---|---|
| `auditd-tune` | auditd daemon (Linux audit subsystem) | /etc/audit/auditd.conf |
| `journal-tune` | systemd-journald | /etc/systemd/journald.conf.d/50-selfdef.conf |

They cover different log subsystems. auditd writes
`/var/log/audit/audit.log` (kernel + audit-rules); journald
writes `/var/log/journal/*.journal` (systemd units + tagged
`logger(1)` events from selfdef detection modules).

selfdef-collector-auditd tails the auditd log; selfdef-collector-
journald reads the journal. Both pipelines feed the selfdef-bus.

## Operator workflow

```bash
# Check current disk usage vs configured SystemMaxUse
sudo journalctl --disk-usage

# Force-rotate the journal (drops oldest entries to free space)
sudo journalctl --rotate
sudo journalctl --vacuum-size=500M

# Verify the live drop-in is in effect
systemd-analyze cat-config systemd/journald.conf | tail -30
```

## When to switch to paranoid

The standard profile is sized for ~5-10 selfdef detection events
per minute + normal system logging. Indicators you need paranoid:

1. `journalctl --disk-usage` shows MaxRetentionSec hit before
   SystemMaxUse — you're losing old events to time-based pruning,
   not space pressure (acceptable but tune-able).
2. `journalctl -t selfdef-aide-detail` shows truncated diff
   output — bump LineMax (which paranoid does).
3. `journalctl -k --boot=0` shows `[!]` after entries — rate-
   limit dropped messages.
4. You enabled audit-rules `paranoid` (universal exec + ptrace
   audit) → matching journal-tune `paranoid` is required.
