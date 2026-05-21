# unowned-files-watchdog

Weekly scan for files whose uid or gid does not resolve to
a current `/etc/passwd` or `/etc/group` entry. Emits
structured events tagged `selfdef-unowned-files` (summary)
and `selfdef-unowned-files-detail` (per-path).

## Why this matters

Orphaned-ownership files are a classic forensic indicator
and a real persistence vector:

- **Attacker created a user**, dropped a payload owned by
  that user, then deleted the user account thinking the
  files would go too. The files remain on disk with a
  numeric uid that no longer maps. `find -nouser` lights
  them up immediately.
- **Package install gone wrong** — a service package was
  uninstalled but left state files behind. Less malicious
  but still operator-visibility-worthy (drift detection).
- **NFS-mounted home re-export with mismatched uid maps**
  — the same file shows different ownership across hosts.
  False-positive class; operator filters via PRUNE_PATHS.
- **Tar/zip extraction with `--numeric-owner`** from a
  foreign system — files get uids that don't exist locally.

The whole class is "files that nobody can rationally own."
On a clean operator-managed host the count should be 0.
Anything > 0 is operator-investigate-worthy.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 (timer ok). Operator-pull via `journalctl -t selfdef-unowned-files`. |
| `enforce` | exit 1 on findings → systemd marks unit failed → journald-collector + selfdef-notifier-engine surface as severity=warn event |

## Severity ladder

| Unowned count | Severity | Event |
|---|---|---|
| 0 | `ok` | `no_unowned` |
| 1–50 | `warn` | `unowned_found` |
| 51+ | `alert` | `bulk_unowned` (typical of a bulk user-deletion forensic event) |

## Scan scope

Default roots: `/etc /home /opt /root /srv /usr /var`.
Override with `SELFDEF_UNOWNED_ROOTS` (space-separated).

Excluded by default (high false-positive paths):

| Path | Why |
|---|---|
| `/var/lib/docker/overlay2` | Containers use anonymous in-image uids; not host-meaningful |
| `/var/lib/containerd` | Same |
| `/var/lib/containers/storage` | podman storage; same |
| `/var/lib/lxd/storage-pools` | LXD storage |
| `/var/lib/snapd/snaps` | snap squashfs uids vary |
| `/var/cache/apt/archives` | downloaded packages |

`/proc /sys /dev /run` are implicitly excluded via `-xdev`
(don't cross filesystem boundaries from the scan-root).

## Cadence

Sun 06:00 + ±15min jitter, `Persistent=true`. Slot
rationale fits the existing staggered cadence:

| Time | Module |
|---|---|
| 02:30 | aide-bridge |
| 03:30 | clamav-cron |
| 04:30 | rkhunter-cron |
| Sun 05:30 | lynis-cron |
| **Sun 06:00** | **unowned-files-watchdog** |

Weekly is sufficient because unowned-file creation is a
rare-and-significant event; daily would be wasted I/O.

## MITRE coverage

- **T1070.004** Indicator Removal: File Deletion — direct
  detector for the half of this technique where the
  attacker deleted the USER but the FILES remained.
- **T1136** Create Account — when paired with
  `acct-baseline`'s account-creation audit, the catch is
  bidirectional: creation logged at `acct-baseline`,
  cleanup-gap caught at `unowned-files-watchdog`.
- **T1078** Valid Accounts — files indicating a former
  account that has been deleted to cover tracks.
- **T1083** File and Directory Discovery — defender side;
  operator-visibility into unusual file ownership patterns.

## Operator workflow

```bash
# Inspect last scan event
journalctl -t selfdef-unowned-files -n 1 --no-pager

# Drill down to per-path detail
journalctl -t selfdef-unowned-files-detail --since "1 week ago"

# Force an on-demand scan (test or post-incident)
sudo systemctl start selfdef-unowned-files.service
sudo systemctl status selfdef-unowned-files.service

# Override scan roots (e.g. include /mnt)
sudo systemctl edit selfdef-unowned-files.service
# Add:
#   [Service]
#   Environment=SELFDEF_UNOWNED_ROOTS=/etc /home /opt /root /srv /usr /var /mnt
sudo systemctl daemon-reload

# Investigate a finding
sudo find /home -nouser -o -nogroup -ls 2>/dev/null | head

# Adopt unowned files (operator decision — assign to
# nobody:nogroup OR root:root depending on policy)
sudo find /opt -nouser -exec chown nobody {} \;
```

## Caveats

- **NFS with uid-shift remapping** generates false positives
  for any file whose source-uid is not provisioned locally.
  Operator either excludes the mount path via
  SELFDEF_UNOWNED_ROOTS OR fixes the uid mapping.
- **Container hosts**: files inside container storage are
  excluded by default (PRUNE_PATHS). If the operator runs
  rootless podman with --userns=keep-id, uids may collide
  with host accounts — review case-by-case.
- **Backup mount points** that include foreign-uid restores
  should be excluded.
- **Weekly cadence** means a malicious actor who creates +
  deletes within 6 days WILL be caught at the next scan,
  but the operator-notify isn't real-time. Pair with
  `acct-baseline` for live account-creation events.

## Coexistence

- **acct-baseline**: complementary — acct-baseline catches
  the account-CREATE event in real time; this module catches
  the account-DELETE-leaves-files cleanup gap on the weekly
  cycle.
- **aide-bridge**: complementary — aide detects file
  CONTENT/PERMISSION drift; this module detects ownership-
  resolution failures. Both run at staggered cadences and
  emit through the same journald event-stream contract.
- **integrity-sentinel**: complementary; integrity-sentinel
  hashes operator-defined critical paths, while this module
  walks ownership space.
- **proc-hidepid**: orthogonal — runtime-process visibility,
  not on-disk file ownership.
