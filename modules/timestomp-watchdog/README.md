# timestomp-watchdog

Scans system binary + config directories for timestamp-
manipulation anomalies — future-dated mtimes, epoch-zero
(1970) timestamps, and mtime-newer-than-ctime
impossibilities. Attackers timestomp planted or modified
files to blend into their surroundings or break time-based
forensic triage. MITRE **T1070.006 Indicator Removal:
Timestomp**.

## Why this matters

After modifying or planting a binary, an attacker runs
`touch -r /bin/ls /tmp/.evil` (copy a neighbor's timestamp)
or `touch -t 202001010000 /usr/bin/backdoor` to make their
file look old + untouched. This defeats the "what changed
recently?" forensic question. But timestomping leaves
tells:

| Anomaly | Why it's suspicious |
|---|---|
| **FUTURE** mtime (after now+1day) | A file can't legitimately be modified in the future — a careless timestomp overshoot or clock-tamper. |
| **EPOCH** mtime (before 2001) | A system binary dated 1970/1999 on a distro that didn't exist then — the lazy `touch -t 197001010000`. |
| **MTIME > CTIME** (by >1 day) | `ctime` (inode-change time) updates on ANY metadata change and CANNOT be set by `touch`. `touch` sets mtime but bumps ctime to now — so mtime far in the future of ctime means mtime was pushed forward while ctime records the real recent tamper. |

The MTIME>CTIME check is the strong one — it catches the
timestomp even when the attacker picked a plausible-looking
date, because they can't forge ctime.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 on any anomaly → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No anomalies | `ok` | `no_timestamp_anomaly` |
| 1–3 anomalies (non-core dirs) | `warn` | `timestamp_anomaly` |
| 4+ anomalies OR any in /bin /sbin /usr/bin /usr/sbin | `alert` | `timestomp_anomaly` |

## Scan scope

`/bin /sbin /usr/bin /usr/sbin /usr/local/bin
/usr/local/sbin /etc` by default (override
`SELFDEF_TIMESTOMP_ROOTS`); container-storage + virtual-fs
pruned.

## Cadence

`*-*-* 06:20:00 ±15m` daily, `Nice=15` + idle I/O. A
stateless anomaly scan (no baseline needed — the anomalies
are absolute, not relative), so it just runs daily.

## MITRE coverage

- **T1070.006** Indicator Removal: Timestomp — PRIMARY;
  the exact technique.
- **T1070** Indicator Removal — the class.
- **T1036** Masquerading — a timestomped file masquerades
  as old/untouched.
- **T1554** Compromise Host Software Binary — a planted
  binary is often timestomped to hide it.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-timestomp -n 1 --no-pager

# Per-file detail (anomaly class + path + mtime)
journalctl -t selfdef-timestomp-detail --since "1 day ago"

# Investigate a flagged file
stat /path/to/file        # compare Modify vs Change times
# A Modify time far from Change time = timestomp tell.
# Cross-check against the package's expected timestamp:
dpkg -V $(dpkg -S /path/to/file | cut -d: -f1) 2>/dev/null
rpm -qf /path/to/file && rpm -V $(rpm -qf /path/to/file) 2>/dev/null

# Manual sweep
find /usr/bin -type f -newermt "$(date -d tomorrow +%F)" 2>/dev/null  # future-dated
```

## Caveats

- **Build-from-source / tarball extraction** with
  `--preserve-timestamps` can legitimately produce old
  mtimes on locally-installed binaries → warn-tier in
  non-core dirs. Core bin dirs (package-managed) shouldn't
  have these.
- **Clock-skew / NTP correction** during a build can
  briefly create future mtimes; the 1-day tolerance
  absorbs normal skew. A file dated weeks ahead is real.
- **MTIME>CTIME** is normal in the SMALL (a file edited
  then chmod'd has ctime > mtime); this module only flags
  mtime MORE than a day AHEAD of ctime (the touch-forward
  case), not the normal edit-then-meta-change ordering.
- **Stateless** — no baseline, so no re-baseline needed,
  but also no "this file CHANGED" detection (that's aide-
  bridge / integrity-sentinel). This catches absolute
  timestamp impossibilities.

## Coexistence

- **aide-bridge + integrity-sentinel**: complementary —
  those detect file CONTENT changes; this detects
  timestamp ANOMALIES (which an attacker uses to hide a
  content change from time-based triage). aide hashes
  content so a timestomp can't fool it; this catches the
  timestomp attempt itself.
- **logfile-integrity-watchdog**: sibling T1070 detector
  (log truncation vs timestamp manipulation).
- **suid-sgid / file-capabilities watchdogs**: a planted
  setuid binary is often timestomped — these catch the
  privilege artifact, this catches the time-hiding.
- **kernel-module / hidden-process / ld-preload
  watchdogs**: the rootkit-detection family; timestomp is
  a common companion to rootkit file-planting.
