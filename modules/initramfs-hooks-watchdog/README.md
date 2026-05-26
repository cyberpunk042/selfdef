# initramfs-hooks-watchdog

Boot + daily delta of the initramfs-tools hook + boot-script dirs
against a learned baseline, plus an ownership + suspicious-pattern
scan. Catches a script that gets baked into the initramfs and runs
as root in early boot, before any disk-resident defense. MITRE
**T1542** / **T1546**.

## Why this matters

initramfs-tools exposes two root-exec surfaces:

- **build time** — `/etc/initramfs-tools/hooks/*` run as root
  during `update-initramfs` and copy arbitrary files **into** the
  image. A rogue hook can implant a binary/script into every future
  initramfs.
- **boot time** — `/etc/initramfs-tools/scripts/<stage>/*` are
  **baked into the initramfs** and run as root in early userspace
  **before `pivot_root`** — earlier than the real root filesystem,
  earlier than systemd, earlier than any selfdef daemon. Stages:
  `init-top`, `init-premount`, `init-bottom`, `local-top`,
  `local-premount`, `local-bottom`, `nfs-top`, `nfs-premount`,
  `nfs-bottom`, `panic`.
- plus `/etc/initramfs/post-update.d/*` (run after an image update).

Code that runs pre-pivot can unlock disks, patch the root fs before
it is mounted, or hide itself — classic bootkit territory. This is
distinct from **kernel-install-hooks-watchdog** (build-time package
*transaction* hooks): these scripts execute **inside the initramfs
at boot**.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any initramfs-hook change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan | `ok` | `baseline_initial` |
| No initramfs-tools dirs present | `ok` | `no_initramfs_hooks` |
| No delta | `ok` | `initramfs_hooks_intact` |
| A script added / changed / removed | `warn` | `initramfs_hooks_changed` |
| A script world-writable / non-root-owned, OR containing a suspicious command-injection pattern | `alert` | `initramfs_hooks_suspicious` |

## What's recorded

- `file:<path>:<sha12>` — hash of each script.
- `own:<path>:<owner:mode>` — owner + mode (symlinks dereferenced
  with `stat -L`).
- `susp:<path>:<pattern>` — a high-risk exec pattern (`curl|sh`,
  `/dev/tcp`, `bash -i`, `base64 -d`, `python -c`, `perl -e`,
  `eval $(...)`, tmp/shm/home execution, …); comment-only lines
  stripped first.

## Cadence

`OnBootSec=50min` + `OnCalendar=*-*-* 10:15:00` — extends the
staggered ladder after kernel-hooks (10:10). An injected initramfs
script only takes effect on the next `update-initramfs` and runs at
the following boot, so the daily catch bounds dwell time; the boot
catch confirms the script set after a restart.

## MITRE coverage

- **T1542** Pre-OS Boot — boot scripts run before `pivot_root`;
  build hooks implant into the image.
- **T1546** Event Triggered Execution — image rebuild / boot is the
  trigger.
- **T1059.004** — the script is shell execution run as root.

## Operator workflow

```bash
journalctl -t selfdef-initramfs-hooks -n 1 --no-pager
journalctl -t selfdef-initramfs-hooks-detail --since "1 day ago"

# Inventory
ls -la /etc/initramfs-tools/hooks/ \
       /etc/initramfs-tools/scripts/init-bottom/ \
       /etc/initramfs-tools/scripts/local-top/ 2>/dev/null

# Inspect what is actually inside the current image:
lsinitramfs /boot/initrd.img-"$(uname -r)" | grep -E 'scripts/|hooks/'

# Investigate a suspicious alert, then re-baseline:
sudo $EDITOR <script>
sudo update-initramfs -u   # rebuild after a legitimate edit
sudo rm /var/lib/selfdef/initramfs-hooks-baseline.tsv
sudo systemctl start selfdef-initramfs-hooks.service
```

## Caveats

- **Distro packages populate these dirs** (cryptsetup, lvm2, mdadm,
  plymouth, resume, zfs); a new root-owned script with no suspicious
  pattern fires `warn` (re-baseline). The writable/non-root/injection
  tiers are the high-confidence alert.
- **dracut hosts** (RHEL/Fedora/Arch) and **no-initramfs** systems
  have no `/etc/initramfs-tools` → `no_initramfs_hooks` no-op. The
  dracut module surface (`/usr/lib/dracut/modules.d`,
  `/etc/dracut.conf.d`) is a separate (future) surface.
- **This watches the source dirs, not the built image.** A delta
  here precedes the next `update-initramfs`; pairing with
  `lsinitramfs` content verification of `/boot/initrd.img-*` closes
  the gap where the image and the source dirs diverge.

## Coexistence

- **kernel-install-hooks-watchdog**: build-time kernel package
  transaction hooks; this is the initramfs build-hook + baked-in
  boot-script surface those rebuilds produce.
- **kernel-cmdline-watchdog / grub-cfg watchers**: bootloader/cmdline
  surface; this is the initrd payload surface.
- **aide-bridge / integrity-sentinel**: byte-level integrity on the
  scripts; this adds the ownership + injection-pattern view.
