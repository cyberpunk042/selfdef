# file-capabilities-watchdog

Daily + boot delta of file capabilities (`getcap -r`)
against a learned baseline. File capabilities are the
modern, fine-grained replacement for the setuid bit — and
the `suid-sgid-watchdog` scan does NOT see them, because
capabilities live in a separate `security.capability`
xattr, not in the mode bits. This module covers that
blind spot.

## Why this matters

Linux capabilities split root's power into ~40 distinct
privileges. A file capability grants a binary specific
powers without the setuid bit:

| Capability on a binary | What it grants |
|---|---|
| `cap_setuid+ep` | become any uid → **root-equivalent backdoor** |
| `cap_dac_override+ep` | bypass ALL file permission checks |
| `cap_dac_read_search+ep` | read any file (e.g. /etc/shadow) |
| `cap_sys_admin+ep` | the "new root" — mount, namespaces, etc. |
| `cap_sys_ptrace+ep` | attach to any process (credential theft) |
| `cap_sys_module+ep` | load kernel modules (rootkit) |
| `cap_net_raw+ep` | craft raw packets (spoofing, sniffing) |

An attacker who runs `setcap cap_setuid+ep /tmp/.x`
creates a root backdoor that:
- Has NO setuid bit → invisible to `find -perm /6000`
  and to suid-sgid-watchdog.
- Looks like an ordinary executable to `ls -l`.

The only way to see it is to read the capability xattr —
which is exactly what this module baselines + diffs.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any ADDED capability → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| 1–2 added (ordinary caps) | `warn` | `capability_added` |
| 3+ added | `alert` | `mass_capability_added` |
| Any added binary with a dangerous cap (setuid/setgid/dac_override/dac_read_search/sys_admin/sys_ptrace/sys_module) | `alert` | `dangerous_capability_added` |

## Baseline file

`/var/lib/selfdef/file-capabilities-baseline.tsv` (mode
0600), `path capabilities` per line. Re-baseline after a
legitimate setcap (e.g. installing `ping` which gets
cap_net_raw, or a custom tool):
```bash
sudo rm /var/lib/selfdef/file-capabilities-baseline.tsv
sudo systemctl start selfdef-file-caps.service
```
Preserved across uninstall (forensic).

## Scan scope

Default roots `/usr /bin /sbin /opt /var`, container-storage
+ virtual-fs pruned (same pattern as suid-sgid-watchdog).
Override via `SELFDEF_FILECAPS_ROOTS`.

## Cadence

`*-*-* 05:20:00 ±10m` daily — right after suid-sgid (05:15)
since file-capabilities + setuid-bit are the matched pair
of on-disk privilege-escalation artifact classes.

## MITRE coverage

- **T1548** Abuse Elevation Control Mechanism — PRIMARY;
  file capabilities are a non-setuid elevation primitive.
- **T1098** Account Manipulation — granting cap_setuid is
  effectively granting root.
- **T1546** Event Triggered Execution — a cap-bearing
  binary is a privilege-escalation primitive.
- **T1574** Hijack Execution Flow — cap_dac_override on a
  binary enables overwriting other binaries.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-file-caps -n 1 --no-pager

# Per-binary detail (added/removed)
journalctl -t selfdef-file-caps-detail --since "1 day ago"

# Manual inventory
getcap -r /usr /bin /sbin 2>/dev/null

# Investigate a dangerous-cap alert
getcap /path/to/binary
ls -l /path/to/binary          # note: NO setuid bit visible
rpm -qf /path/to/binary || dpkg -S /path/to/binary

# Remove an illegitimate capability
sudo setcap -r /path/to/binary

# Re-baseline after a legit install
sudo rm /var/lib/selfdef/file-capabilities-baseline.tsv
sudo systemctl start selfdef-file-caps.service
```

## Caveats

- **getcap must be installed** (libcap2-bin / libcap).
  check.sh + scanner require it.
- **Legit caps exist**: `ping` (cap_net_raw),
  `/usr/bin/newgidmap`/`newuidmap` (cap_setgid/setuid for
  rootless containers), some browsers. These appear in the
  baseline; only DELTAS alert.
- **Package upgrades** that re-setcap a binary fire
  `capability_added` (often same cap, re-applied) →
  operator re-baselines after an upgrade wave.
- **Daily cadence** misses a setcap-then-remove within the
  window; tetragon's security_file_open / capset eBPF is
  the real-time complement.

## Coexistence

- **suid-sgid-watchdog**: the matched sibling — setuid-bit
  vs file-capability are the two on-disk privilege-
  escalation artifact classes. Run BOTH; neither sees the
  other's surface.
- **kernel-module / cron / account / listening-ports /
  mount-options / dns-resolver watchdogs**: the broader
  delta-detection family on the staggered ladder.
- **kernel-yama-baseline**: complementary — yama blocks
  ptrace at runtime; this detects a binary GRANTED
  cap_sys_ptrace on disk.
- **tetragon**: real-time capset/setcap eBPF is the
  sub-second complement to this daily delta.
