# mount-options-watchdog

Daily + boot verification that security-relevant mount
points carry their expected `nosuid` / `nodev` / `noexec`
hardening flags. Detects drift — a remount or fstab edit
that silently dropped a flag, whether by an attacker or a
careless operator.

## Why this matters

Mount-option hardening is a cheap, high-value control:

| Flag | Blocks |
|---|---|
| `nosuid` | setuid/setgid bit honored → blocks privilege escalation via a planted setuid binary on that fs |
| `nodev` | device-node interpretation → blocks a planted `/tmp/sda` raw-disk access trick |
| `noexec` | execution of binaries → blocks running a dropped payload from `/tmp`, `/dev/shm`, etc. |

`tmpfs-baseline` SETS these on `/tmp` + `/var/tmp`. But:
- An attacker who gains root can `mount -o remount,exec
  /tmp` to re-enable execution for their payload.
- A careless operator edits `/etc/fstab` and drops
  `noexec` to "fix" a package that needed to run from
  /tmp.
- A new mount (`/home`, `/var/log`, `/boot`) may never
  have had the flags.

This module checks the LIVE mount options daily + at boot
and flags any expected-but-missing hardening flag.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if any expected flag is missing |

## Checked mounts + expected flags

| Mount | Expected flags |
|---|---|
| `/tmp` | nosuid nodev noexec |
| `/var/tmp` | nosuid nodev noexec |
| `/dev/shm` | nosuid nodev noexec |
| `/home` | nosuid nodev (NOT noexec — operators run scripts from home) |
| `/var/log` | nosuid nodev noexec |
| `/boot` | nosuid nodev noexec |

## Separate-mount awareness

A mount option can only be enforced if the path is its
OWN filesystem. If `/var/log` is just a directory on the
root filesystem (not a separate mount), the flag CAN'T
apply — the module reports that as `not_separate_mount`
(informational), NOT as drift. Only paths that ARE
separate mounts are drift-checked. This avoids false
positives on hosts with a single-partition layout (where
making these separate mounts is a different, fstab-level
project).

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| All separate mounts carry expected flags | `ok` | `all_flags_present` |
| 1–2 missing flags | `warn` | `missing_flags` |
| 3+ missing flags | `alert` | `broad_missing_flags` (broad remount-weaken) |

## MITRE coverage

- **T1059** Command and Scripting Interpreter — `noexec`
  on /tmp blocks dropped-script execution; drift detection
  catches its removal.
- **T1548.001** Abuse Elevation Control: Setuid/Setgid —
  `nosuid` drift on a writable fs re-opens the planted-
  setuid path.
- **T1546** Event Triggered Execution — payload-in-/tmp
  execution.
- **T1564** Hide Artifacts — `nodev` drift enables device-
  node tricks.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-mount-options -n 1 --no-pager

# Per-mount missing-flag detail
journalctl -t selfdef-mount-options-detail --since "1 day ago"

# Manual check
findmnt /tmp /var/tmp /dev/shm /home /var/log /boot

# Remediate a live drift (re-add noexec to /tmp)
sudo mount -o remount,noexec,nosuid,nodev /tmp
# And fix /etc/fstab so it survives reboot, OR re-apply
# tmpfs-baseline which owns /tmp + /var/tmp.
```

## Caveats

- **Single-partition hosts**: most of these paths aren't
  separate mounts → reported as info, not drift. Making
  them separate mounts is an fstab/partitioning project
  (out of scope for a detection module).
- **/home with noexec breaks operator workflows** —
  deliberately NOT in /home's expected set. Operators who
  want noexec /home add it to fstab themselves.
- **Container hosts**: overlay/bind mounts have their own
  option semantics; the module checks what findmnt
  reports for the host paths.
- **Detection only** — remediation is `mount -o remount`
  + fstab edit (or re-apply tmpfs-baseline for /tmp +
  /var/tmp). Config-side ownership stays with
  tmpfs-baseline to avoid two modules writing fstab.

## Coexistence

- **tmpfs-baseline**: the config-side companion — it SETS
  noexec/nosuid/nodev on /tmp + /var/tmp; this module
  DETECTS drift across a broader mount set. Detect+enforce
  pair.
- **suid-sgid-watchdog + world-writable-watchdog**:
  complementary — those find dangerous FILES; this finds
  dangerous MOUNT semantics that would let those files
  execute / escalate.
- **listening-ports / cron / account / kernel-module
  watchdogs**: sibling detection family on the staggered
  ladder.
