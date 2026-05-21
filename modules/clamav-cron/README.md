# clamav-cron

systemd-timer-driven daily [ClamAV](https://www.clamav.net/)
virus signature scan. Emits structured JSON tagged `selfdef-clamav`
(+ full per-line detail tagged `selfdef-clamav-detail`) to the
journal.

## How it differs from rkhunter-cron + aide-bridge

| Module | Detection model | Catches |
|---|---|---|
| `aide-bridge` | File diff vs operator-built baseline | Any tamper to monitored paths |
| `rkhunter-cron` | Signature match against **rootkit** DB | Known rootkits (kernel + LD_PRELOAD + LKM) |
| `clamav-cron` | Signature match against **virus/trojan/PUA** DB | Windows malware on shared dirs, Linux trojans, malicious docs, EICAR test files |
| `host-sentinel` kmod-watch | Real-time Tetragon kprobe | Kernel-module load events |

The four overlap intentionally — different DB universes, different
threat assumptions. ClamAV's DB is the largest (millions of
signatures including Windows malware) and is most useful on hosts
that:
- Share files with Windows operators (T1080 Taint Shared Content
  vector)
- Serve uploaded user content (CMSes, NAS, mail attachments)
- Run dev tools that pull packages from random sources

## Profiles

| Profile | Scan paths | Runtime |
|---|---|---|
| `home` (default) | /home + /tmp + /var/tmp + /srv | 1-10 min |
| `full` | home + /opt + /usr/local + /var/www | 30-180 min |

Both profiles share `--cross-fs=no` (don't traverse mount
points; protects /proc /sys /dev /run from spurious "infected"
matches) + `--max-filesize=100M --max-scansize=1000M` (skip huge
files that aren't typical malware vectors).

## Event severity ladder

| Severity | clamscan rc | Meaning |
|---|---|---|
| `ok` | 0 | No virus found |
| `alert` | 1 | One or more files match a signature |
| `high` | 2 | clamscan internal error (DB missing, permission) |

## Event schema

```json
{
  "tag": "selfdef-clamav",
  "severity": "alert",
  "event": "infected_files",
  "profile": "home",
  "clamscan_rc": 1,
  "infected": 2,
  "scanned": 18432,
  "freshclam_rc": 0,
  "sample": "/home/operator/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND|/tmp/foo.exe: Trojan.GenericKD FOUND|"
}
```

A companion `selfdef-clamav-detail` tag carries the full clamscan
output (16 KiB max) for operator triage.

## Signature DB freshness

The wrapper calls `freshclam --quiet` BEFORE clamscan. If
freshclam fails (offline, network issue), the scan still runs
against the last-known DB. check.sh warns if the DB is more than
7 days old.

## Timer schedule

Daily at 02:30 + 30min jitter. Offset window across all 5
detection modules:

| Cadence | Module | Window |
|---|---|---|
| 02:30 | clamav-cron | virus signatures |
| 03:30 | aide-bridge | file diff |
| 04:30 | rkhunter-cron | rootkit signatures |
| 05:30 (Sun only) | lynis-cron | compliance audit |
| 5 min continuous | time-skew-watchdog | clock drift |

The staggered window keeps the early-morning I/O budget
controlled. Each module's service unit is `Nice=15-18
IOSchedulingClass=idle` so they stay out of the operator's way.

## MITRE coverage

- **T1204** User Execution — operator-clicked malicious file
  caught at next scan.
- **T1080** Taint Shared Content — malware planted in shared dir
  caught.
- **T1027** Obfuscated Files or Information — many obfuscation
  patterns have ClamAV signatures.
- **T1027.002** Software Packing — packed binaries with known-bad
  unpacker signatures matched.
- **T1059.002** AppleScript — ClamAV's DB includes macOS
  AppleScript trojans (operator on a multi-OS shared dir).

## Operator workflow

```bash
# Inspect last scan event
sudo journalctl -t selfdef-clamav -n 1

# Inspect full clamscan output for a recent scan
sudo journalctl -t selfdef-clamav-detail --since '4 hours ago'

# Manually force-refresh signatures (e.g. fresh-install host)
sudo freshclam

# Quarantine an infected file (clamscan can do this in one shot)
sudo clamscan --infected --move=/var/quarantine/selfdef <path>

# Force a re-scan now
sudo systemctl start selfdef-clamav-scan.service
sudo journalctl -t selfdef-clamav -n 1
```

## Why daily cadence on alt-port-of-rkhunter

Both clamav + rkhunter are signature-match against periodically-
updated DBs. Daily cadence catches:
- Operator-introduced malware (downloaded files) within 24h
- Newly-published signatures matching files that were already on
  disk

Faster cadence (hourly) generates notifier-fatigue on a typical
workstation; weekly cadence (like lynis-cron) leaves a wider
window between malware-on-disk and detection.

## Caveats

- **False positives on dev tools**: pentesting tools (metasploit,
  social-engineer-toolkit), security research samples, EICAR test
  files all match. Operator adds path-exclusions via
  `/etc/clamav/clamav.conf` (operator-owned; selfdef doesn't
  touch it).
- **Signature DB size**: ~300 MB after first freshclam. Disk cost
  worth noting on small-disk hosts.
- **CPU cost**: full profile on a 1 TB /home takes 60+ min single-
  threaded. Nice=18 + IOSchedulingClass=idle stays out of the
  way but still consumes CPU cycles.
