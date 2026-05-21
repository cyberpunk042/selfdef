# usb-storage-mass-disable

Blocks `usb_storage` (and `uas`, `vfat`, `cdrom`) kernel modules
via `/etc/modprobe.d/`. When a USB mass-storage device is
inserted, the kernel calls modprobe to auto-load the driver;
this module's install-override + blacklist make modprobe a no-op.
Result: nothing mounts, even with operator-physical-access to
the USB port.

## How this differs from usbguard

| Module | Layer | Bypass |
|---|---|---|
| `usbguard` | Userspace policy daemon (USB device authorization) | Can be stopped + unloaded by an attacker who lands root |
| `usb-storage-mass-disable` | Kernel module load layer | Kernel will not load the driver; even root can't make modprobe work (rm -f the drop-in + re-modprobe still loads, but the modprobe.d check still runs) |

The two are complementary:
- usbguard handles **selective** USB authorization (HID is OK,
  random vendor-id mass-storage is NOT)
- usb-storage-mass-disable handles **categorical** mass-storage
  block (no USB mass-storage AT ALL, regardless of vendor)

Operators on hosts where ANY USB mass-storage attach is
suspicious (servers, hardened workstations) ship this module +
usbguard together. Operators on workstations who legitimately
plug USB drives (operator-owned backup drives) skip this module
+ rely on usbguard's authorization for per-device control.

## Profiles

| Profile | usb_storage load behavior |
|---|---|
| `blocked` (default) | `install usb_storage /bin/true` — load attempts succeed-without-loading; no driver registers; insertions invisible to kernel |
| `audited` | install-override pipes through `logger -t selfdef-usb-storage` THEN loads normally — baseline visibility into how often usb_storage loads |

The audited profile is a baseline-collection tier: operator runs
it for 1-2 weeks, sees zero legit usb_storage loads in the
journal, then flips to blocked.

## Modules covered

| Module | Purpose |
|---|---|
| `usb_storage` | Standard USB mass-storage (most USB drives) |
| `uas` | USB Attached SCSI (modern fast-mode, e.g. USB3 SSD enclosures) |
| `vfat` | FAT filesystem (most thumbdrives ship FAT32; blocking the FS module is defense-in-depth) |
| `cdrom` | USB-attached optical drives |

vfat blocking has a caveat: EFI System Partitions are FAT-formatted.
Operator who legitimately needs to mount /boot/efi (most don't post-
install; the OS auto-mounts it via fstab BEFORE this module's
modprobe.d takes effect) overrides via
`/etc/modprobe.d/60-operator-fs.conf`.

## MITRE coverage

- **T1052.001** Exfiltration over Physical Medium: Exfiltration
  over USB — direct prevention. Attacker plugging in their
  thumbdrive gets nothing.
- **T1091** Replication Through Removable Media — drive-by USB
  malware (BadUSB, autorun-attempting USB drives) can't mount
  + can't execute.
- **T1200** Hardware Additions — categorical mass-storage block
  is a strong defense against an attacker physically near the
  host inserting a malicious USB drive.

## Coexistence

- **usbguard**: per-device authorization (allow trusted, deny
  others). Stack: usbguard's allow-list catches operator-owned
  devices; usb-storage-mass-disable catches everything
  categorically. Operator who plugs in a trusted device but
  doesn't want mass-storage gets HID/etc working via usbguard
  while mass-storage stays kernel-blocked.
- **audit-rules** + `host-sentinel` kmod-watch: log every
  attempted kernel-module-load including failed ones. Operator
  sees attempted usb_storage loads (= USB drive was plugged in,
  modprobe was called, the call no-op'd) in the journal.
- **kernel-lockdown** strict mode (`kernel.modules_disabled=1`):
  even stronger — NO new module loads at all. usb-storage-mass-
  disable still adds value because it's effective BEFORE
  kernel-lockdown strict flips (which requires post-boot
  baseline + operator acknowledgement); ships defense from
  day-one.

## Operator workflow

```bash
# Verify modprobe sees the override
modprobe --show-depends usb_storage
# Expected: "install /bin/true"  (blocked profile)
# OR:       "install /bin/sh -c '...logger...'"  (audited profile)

# Verify usb_storage is NOT loaded
lsmod | grep usb_storage  # expected: empty output

# Test by inserting a USB drive + checking dmesg
# (Will show "usb 1-1: new high-speed USB device" but NO
# "usb-storage: device found" / "scsi host: usb-storage"
# follow-up lines under blocked profile)
sudo dmesg -T | tail -20
```

## Caveats

- **Initramfs may have its own modprobe rules** — for kernel-
  cmdline `root=...` on a USB stick (rare on workstations,
  more common on netboot kiosk hosts), the initramfs's
  modprobe.d may need a corresponding entry. update-initramfs
  on Debian + dracut on RHEL automatically pick up
  /etc/modprobe.d when rebuilding.
- **Operator legitimately needs USB drives**: skip this module;
  use usbguard's per-device allow-list instead.
- **EFI System Partition**: blocked by vfat blacklist. fstab
  mount at boot happens BEFORE modprobe.d, so existing /boot/
  efi mount survives. New mounts (operator manually `mount /dev/
  sda1 /mnt/usb`) fail.
