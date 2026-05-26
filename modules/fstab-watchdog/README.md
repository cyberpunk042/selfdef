# fstab-watchdog

Boot + daily **entry-level** delta of `/etc/fstab` (+
`/etc/fstab.d/*`) against a learned baseline. Catches a mount
entry an attacker uses to shadow system files, mount an
attacker-controlled image, or re-enable setuid. MITRE
**T1564.005** (Hide Artifacts: VSS / bind-mount) / **T1036**
(Masquerading) / **T1211**-adjacent.

## Why this matters

`mount-options-watchdog` verifies the `nosuid`/`nodev`/`noexec`
**flags** on a fixed set of known mounts; it does not see an
attacker-ADDED entry. The fstab entries themselves are a
tampering surface:

```
/tmp/.img   /usr/lib   ext4  loop            # mount an attacker image over /usr/lib
/tmp/evil   /usr/bin   none  bind            # shadow system binaries
/dev/sdb1   /mnt/x     ext4  defaults,suid   # setuid honored on removable media
```

A **bind-mount over a sensitive system path** lets an attacker
overlay trusted files (a trojaned `/usr/bin`, a fake `/etc`); a
**loop device under `/tmp`/`/home`** is an attacker-controlled
filesystem image; an **explicit `suid`** on a normally-hardened
mount is a privesc handle.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any fstab change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No fstab | `ok` | `no_fstab` |
| No delta | `ok` | `fstab_intact` |
| Any entry added / removed / changed | `warn` | `fstab_changed` |
| A bind-mount over a sensitive path; a loop/file device under /tmp /home /dev/shm; or an explicit `suid` option | `alert` | `fstab_suspicious_mount` |

The alert is delta-based — a pre-existing suspicious entry is
flagged once at baseline for vetting, then not re-alerted.

## What's recorded

- `file:<path>:<sha12>` — hash of fstab.
- `mount:<mountpoint>:<dev>|<fstype>|<opts>` — each parsed entry
  (device, filesystem type, options).

Sensitive shadow targets: `/etc`, `/bin`, `/sbin`, `/usr/bin`,
`/usr/sbin`, `/usr/local/{bin,sbin}`, `/lib*`, `/usr/lib`,
`/boot`, `/root` (+ subpaths).

## Cadence

`OnBootSec=36min` + `OnCalendar=*-*-* 09:05:00` — extends the
staggered ladder after sysctl-hardening (09:00). A new mount
entry takes effect at the next boot / `mount -a`, so the boot
catch confirms fstab after a restart.

## MITRE coverage

- **T1564.005** Hide Artifacts (bind-mount overlay) — shadowing
  a path with a bind mount.
- **T1036** Masquerading — overlaying trusted binaries/configs.
- **T1068** Exploitation for Privilege Escalation (adjacent) —
  setuid on a removable/attacker filesystem.

## Operator workflow

```bash
journalctl -t selfdef-fstab -n 1 --no-pager
journalctl -t selfdef-fstab-detail --since "1 day ago"

# Inventory + live mounts
grep -vE '^\s*#|^\s*$' /etc/fstab
findmnt --real

# Investigate a suspicious_mount alert
# - bind over /usr/bin? loop image in /tmp? suid on removable?
findmnt <mountpoint>
sudo umount <mountpoint>          # if an active shadow mount
sudo $EDITOR /etc/fstab           # remove the rogue entry
sudo rm /var/lib/selfdef/fstab-baseline.tsv
sudo systemctl start selfdef-fstab.service
```

## Caveats

- **Legit bind-mounts + loop mounts exist** (containers, chroots,
  squashfs); a new one fires `warn`, and the shadow/loop-in-tmp/
  suid sub-signatures are the high-confidence alert. Re-baseline
  after vetting.
- **fstab is the PERSISTED config** — an attacker may `mount`
  directly without persisting (caught by a runtime `findmnt`
  diff, not this); this catches the reboot-surviving entry.
- **Daily+boot cadence** misses an add-mount-revert within the
  window; an audit-rules watch on `/etc/fstab` writes is the
  real-time complement.

## Coexistence

- **mount-options-watchdog**: verifies nosuid/nodev/noexec FLAGS
  on known mounts; this watches the fstab ENTRIES for added/
  shadow/suid tampering. Flag-presence + entry-content views.
- **nfs-mount-watchdog**: network-mount hardening flags; this
  covers the local fstab entry surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on
  fstab; this adds the per-entry shadow/loop/suid semantic view.
