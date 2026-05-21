# rkhunter-cron

systemd-timer-driven daily [rkhunter](https://rkhunter.sourceforge.net/)
known-rootkit-signature scan. Emits structured JSON tagged
`selfdef-rkhunter` (+ full per-line detail tagged
`selfdef-rkhunter-detail`) to the journal.

**Complements** `aide-bridge`: AIDE detects FILESYSTEM DIFFS
against an operator-built baseline; rkhunter detects KNOWN-
SIGNATURE rootkits + suspicious files matching curated patterns
(Suckit, Adore, BeastKit, etc.). They cover different threat models:

| Tool | Detection model | Catches |
|---|---|---|
| aide-bridge | Diff vs operator-built baseline | Any tamper to monitored paths (including unknown rootkits) |
| rkhunter-cron | Signature-match against curated DB | Known rootkits even on a host with no prior baseline |
| host-sentinel kmod-watch | Tetragon kprobe on `do_init_module` | Real-time module-load attempts |
| audit-rules base | auditd watch on /lib/modules | Real-time module-load syscalls |

The four overlap and cross-corroborate — different layers, different
threat assumptions, same intent.

## Profiles

| Profile | Diff handling |
|---|---|
| `report` (default) | Findings logged to journal as `selfdef-rkhunter` events; systemd unit exits 0 always |
| `enforce` | Any finding → exit 1 → `systemctl status` shows failed → operator-alertable |

Switch to enforce AFTER tuning `/etc/rkhunter.conf.local` to
allow-list legitimate operator-installed tools that trip
false positives.

## Event severity ladder

| Severity | rkhunter rc | Meaning |
|---|---|---|
| `ok` | 0 | No warnings, no errors |
| `warn` | 1 | Warnings (likely allow-list candidates) |
| `alert` | 2 | Errors (config / exec problems OR strong findings) |
| `alert` | other | Runtime issue (DB outdated, file-properties drift) |

## Event schema

```json
{
  "tag": "selfdef-rkhunter",
  "severity": "warn",
  "event": "warnings_found",
  "profile": "report",
  "rkhunter_rc": 1,
  "warning_count": 3,
  "sample": "Warning: The file '/usr/bin/whoami' has the immutable-bit set.|Warning: Hidden directory found: /tmp/.X11-unix|"
}
```

A companion `selfdef-rkhunter-detail` tag carries up to 16 KiB of
the raw output line-by-line so operators can `journalctl -t
selfdef-rkhunter-detail` for full triage.

## MITRE coverage

- **T1014** Rootkit — primary; rkhunter's DB matches Linux
  rootkit signatures (kernel-module + LD_PRELOAD + LKM types).
- **T1083** File and Directory Discovery — flags suspicious
  hidden files + dirs.
- **T1547.006** Boot/Logon Autostart: Kernel Modules — flags
  unsigned / unknown modules loaded.

## Timer schedule

Daily at 04:30 + 15min jitter. Offset from aide-bridge (03:30) so
both detection scans don't trample the operator's I/O budget at
the same time. Service unit is `Nice=15 IOSchedulingClass=idle`
so it stays out of the operator's way.

## Operator workflow

When rkhunter flags a legitimate operator-installed file as
suspicious:

```bash
# Inspect the finding.
sudo journalctl -t selfdef-rkhunter-detail | head -50

# Update the signature DB (catches false-positive resolutions
# upstream).
sudo rkhunter --update

# Re-baseline file properties (legitimate package update).
sudo rkhunter --propupd

# Add a specific allow-list line to /etc/rkhunter.conf.local.
echo 'ALLOWHIDDENFILE="/operator/path"' | sudo tee -a /etc/rkhunter.conf.local
```

## Why both aide-bridge AND rkhunter-cron?

Defense-in-depth + different threat models. AIDE catches an
**unknown** rootkit that touched any of the watched paths.
rkhunter catches a **known** rootkit even if AIDE's baseline
was poisoned (e.g. attacker compromised the host BEFORE first
aide --init). Together they bracket the threat surface.
