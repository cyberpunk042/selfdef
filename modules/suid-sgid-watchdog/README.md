# suid-sgid-watchdog

Daily inventory of every setuid/setgid executable on the
host, diffed against a learned baseline. Emits structured
events for `added`, `removed`, `perm_changed`,
`hash_changed`. Catches attacker-installed SUID backdoors
and accidental `chmod u+s` slips.

## Why this matters

A new setuid-root binary on a host is one of the loudest
signals a defender has of compromise. Attacker workflow:

1. Land as unprivileged user (web-app RCE, SSH brute,
   stolen creds).
2. Drop a payload binary owned by root with mode 4755.
3. Re-execute the payload later from ANY user → root.

This is the persistence + privilege-escalation primitive
behind a huge fraction of post-exploit toolchains. The
detection is mechanical: every setuid binary that wasn't
there before deserves an immediate operator look.

Same logic applies for setgid (sometimes used for
package-staff group escalation or dev-tool sudo-bypass).

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on added or perm_changed (removed is operator-cleanup, never alerts) → systemd unit failed → journald-collector surfaces |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline write) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| 1–3 added/perm_changed | `warn` | `suid_drift` |
| 4+ added/perm_changed | `alert` | `bulk_delta` (likely bulk-install attack) |
| Only hash_changed | `warn` | `suid_hash_drift` (binary replaced — patched OR backdoored) |

## Baseline file

`/var/lib/selfdef/suid-sgid-baseline.tsv` (mode 0600).
Format: `path<TAB>mode<TAB>uid<TAB>gid<TAB>sha256` per line.

- First scan creates it.
- Subsequent scans diff against it.
- **Not auto-rotated** — operator-driven rotation. To
  accept the current state as the new baseline:
  ```bash
  sudo rm /var/lib/selfdef/suid-sgid-baseline.tsv
  sudo systemctl start selfdef-suid-sgid.service
  ```
- Preserved across uninstall (forensic evidence).

## Scan scope

Default roots: `/usr /bin /sbin /opt /var`.
Excludes container-storage paths + virtual filesystems
(same pattern as unowned-files-watchdog).

Override via `SELFDEF_SUIDSGID_ROOTS` env in
`systemctl edit`.

## Cadence

`*-*-* 05:15:00 ±10m` daily. Fits the staggered ladder:

| Time | Module |
|---|---|
| 02:30 | aide-bridge |
| 03:30 | clamav-cron |
| 04:30 | rkhunter-cron |
| 05:00 | world-writable-watchdog |
| **05:15** | **suid-sgid-watchdog** |
| Sun 05:30 | lynis-cron |
| Sun 06:00 | unowned-files-watchdog |

## MITRE coverage

- **T1548.001** Abuse Elevation Control Mechanism: Setuid
  and Setgid — primary; this is the technique the
  scan-and-delta is designed to detect.
- **T1546** Event Triggered Execution — narrower; setuid
  binaries are an event-triggered exec primitive.
- **T1059** Command and Scripting Interpreter — perm-
  changed shell interpreters (chmod u+s on /bin/bash) get
  caught in the perm_change class.
- **T1574.005** Hijack Execution Flow: Executable
  Installer File Permissions Weakness — paired with
  world-writable-watchdog for the writeable-installer
  half; this module catches the executable-installer
  half (suid bit on installer).

## Operator workflow

```bash
# Last scan summary
journalctl -t selfdef-suid-sgid -n 1 --no-pager

# Per-finding detail (added/removed/perm/hash lines)
journalctl -t selfdef-suid-sgid-detail --since "1 day ago"

# Re-baseline (after legitimate operator-installed package
# that added a new setuid binary)
sudo rm /var/lib/selfdef/suid-sgid-baseline.tsv
sudo systemctl start selfdef-suid-sgid.service
journalctl -t selfdef-suid-sgid -n 1   # expect baseline_initial

# Manual inventory query
sudo find /usr /bin /sbin -xdev -type f -perm /6000 -ls 2>/dev/null

# Investigate one finding
file /opt/some-bin
sha256sum /opt/some-bin
rpm -qf /opt/some-bin   # OR dpkg -S /opt/some-bin
stat /opt/some-bin
```

## Caveats

- **Package upgrade** that updates a setuid binary's hash
  will fire a `suid_hash_drift` event. This is correct
  behavior — operator confirms via `apt log` / `dnf log`
  that the upgrade is legitimate, then re-baselines.
- **Custom-built setuid wrappers** (sudo replacement,
  policy-elevation tools) require re-baseline after install.
  Add the install step to operator runbook.
- **Container-internal setuid binaries**: excluded by path
  prune list (containers manage their own setuid surface
  inside the image; host has no visibility into
  container-internal state).
- **NFS root**: `-xdev` blocks descent into NFS-mounted
  trees. Operator with critical setuid binaries on NFS
  must add the mount root explicitly to
  SELFDEF_SUIDSGID_ROOTS (not recommended without
  performance review).
- **Daily cadence** means a malicious setuid binary added
  AND used within the same day before the next scan WILL
  be caught at next scan but not in real time. Pair with
  tetragon for inotify-based file-write detection on
  critical paths if real-time is required.

## Coexistence

- **world-writable-watchdog**: complementary detection;
  permission drift in two different bit classes
  (writable vs setuid).
- **unowned-files-watchdog**: complementary; ownership
  vs permission. Both run on the staggered I/O budget.
- **aide-bridge**: more general (catches ANY drift on
  watched paths); this module's specificity is the
  baseline + delta + severity-class structure that
  surfaces suid-specific events directly.
- **tetragon**: for real-time file-write detection on
  critical paths, tetragon's inotify hook catches the
  setuid binary as it's written. This module's daily
  delta is the catch-anyway backstop.
- **kernel-lockdown**: limits some setuid escalation
  paths via `kernel.unprivileged_bpf_disabled` etc; this
  module catches the on-disk-artifact side.
