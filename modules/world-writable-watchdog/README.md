# world-writable-watchdog

Daily scan for files (and non-sticky-bit directories) with
the world-writable bit (`0002`) set, OUTSIDE the safe-by-
default whitelist. Catches accidental `chmod 777`, malware
drop-and-make-writable, package post-install permission
slips, operator-script mistakes.

## Why this matters

World-writable files are an upgrade path for any
unprivileged-attacker:

- **Persistence**: attacker who lands as `nobody` /
  `_apt` / `systemd-resolve` can WRITE to a world-writable
  file owned by root, then wait for root to read/exec it.
- **Privilege escalation via write-then-wait**: attacker
  writes to a world-writable log script that root executes
  at next cron tick.
- **Drift indicator**: `chmod -R 777 /opt/myapp` "to make
  it work" is one of the most-frequent operator mistakes;
  detecting it is half of remediating it.

The kernel offers no way to disallow `chmod 0002` at the
syscall layer for non-suid files (would break too much).
Detection-after-the-fact is the right tool.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0; operator-pull via journalctl |
| `enforce` | exit 1 on findings → systemd unit failed → journald-collector + selfdef-notifier-engine surface |

## Severity ladder

| Count | Severity | Event |
|---|---|---|
| 0 | `ok` | `no_findings` |
| 1–25 | `warn` | `world_writable_found` |
| 26+ | `alert` | `bulk_world_writable` (recursive chmod 777 incident) |

## Scan logic

Two find passes per scan-root, both with `-xdev` (do not
cross filesystem boundaries):

1. `find <root> -type f -perm -0002 -print` — any
   world-writable file.
2. `find <root> -type d -perm -0002 ! -perm -1000 -print`
   — world-writable directory WITHOUT the sticky bit.
   Sticky-bit dirs (`/tmp`, `/var/tmp`) are intentional
   shared scratch and are also pruned at the path level.

Default scan roots: `/etc /home /opt /root /srv /usr /var`.
Override via `SELFDEF_WORLDWRITE_ROOTS` (space-separated)
through `systemctl edit`.

## Prune (safe-by-design) paths

| Path | Why |
|---|---|
| `/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock` | sticky-bit shared scratch — intentional |
| `/var/lib/docker/overlay2` | container overlay state |
| `/var/lib/containerd` | containerd state |
| `/var/lib/containers/storage` | podman storage |
| `/var/lib/lxd/storage-pools` | LXD storage |
| `/var/lib/snapd/snaps` | snap squashfs (in-image perms vary) |
| `/proc`, `/sys` | virtual fs |

## Cadence

`*-*-* 05:00:00 ±15m` daily. Extends the staggered ladder:

| Time | Module |
|---|---|
| 02:30 | aide-bridge |
| 03:30 | clamav-cron |
| 04:30 | rkhunter-cron |
| **05:00** | **world-writable-watchdog** |
| Sun 05:30 | lynis-cron |
| Sun 06:00 | unowned-files-watchdog |

## MITRE coverage

- **T1222** File and Directory Permissions Modification —
  primary; detects the WORLD-WRITABLE half of permission
  drift (paired with operator-side umask-baseline for
  prevent-side).
- **T1574.010** Hijack Execution Flow: Services File
  Permissions Weakness — world-writable systemd unit files
  are the exact bug class CVEs in this technique exploit;
  the scan surfaces them.
- **T1083** File and Directory Discovery — defender-side;
  operator visibility into unusual permission patterns.
- **T1078** Valid Accounts — escalation via writing to
  a root-owned-but-world-writable script.

## Operator workflow

```bash
# View last scan summary
journalctl -t selfdef-world-writable -n 1 --no-pager

# Per-path detail
journalctl -t selfdef-world-writable-detail --since "1 day ago"

# On-demand scan
sudo systemctl start selfdef-world-writable.service
sudo systemctl status selfdef-world-writable.service

# Manual investigation of one root
sudo find /opt -xdev -type f -perm -0002 -ls 2>/dev/null

# Remediate a finding (operator decision; chmod o-w is the
# safe default for non-sticky-bit files)
sudo chmod o-w /opt/some-app/world-writable-script.sh

# Add a path to operator-side excludes (e.g. an app that
# truly needs world-writable scratch outside /tmp)
sudo systemctl edit selfdef-world-writable.service
# Add:
#   [Service]
#   Environment=SELFDEF_WORLDWRITE_ROOTS=/etc /home /opt /root /srv /usr /var
#   # And edit the script's PRUNE_PATHS via operator-prefixed override
sudo systemctl daemon-reload
```

## Caveats

- **`/proc/sys/*` and other procfs entries** have unusual
  permissions; excluded via `/proc` prune.
- **Snap squashfs** in-image perms aren't really world-
  writable (immutable squashfs) but show as such; pruned.
- **Container overlay snapshots** can contain any in-image
  perms; pruned (container-internal hardening is the
  container image's responsibility, not the host scan).
- **NFS mounts** with foreign permissions: operator may
  exclude via SELFDEF_WORLDWRITE_ROOTS or accept the noise.
- **Daily cadence** means an attacker writing-then-using
  within hours WILL be caught next day; for real-time,
  pair with tetragon for inotify-based file-write events
  on critical paths.

## Coexistence

- **umask-baseline**: complementary — umask-baseline is
  the prevent-side (operator creates files with safe perms
  by default); world-writable-watchdog is the detect-side
  for when the prevention is bypassed.
- **unowned-files-watchdog**: complementary detection;
  different attack indicator class (ownership vs
  permission). Both run on the staggered I/O budget.
- **aide-bridge**: more general (catches ANY file
  change); this module is narrower (specific bit class)
  and runs more often (daily vs aide's chosen cadence).
- **integrity-sentinel**: hashes operator-named critical
  paths; this module walks the broader tree for perm
  patterns.
