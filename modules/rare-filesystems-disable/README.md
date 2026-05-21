# rare-filesystems-disable

Renders `/etc/modprobe.d/selfdef-rare-filesystems-
blacklist.conf` defeating modprobe of legacy + obscure
filesystem kernel modules. Reduces kernel attack surface
and defeats the USB-with-exotic-fs auto-mount-as-root
attack class.

## Why this matters

Linux ships kernel modules for many filesystems no
modern operator workstation or server actually needs:

- **cramfs, freevxfs, jffs2** — embedded/legacy fs.
  Kernel parser CVEs occasionally drop (CVE-2020-27194
  type confusion in jffs2; cramfs had multiple in
  2018-2020).
- **hfs, hfsplus** — Apple. Linux on a server has no
  reason to mount HFS. Mostly useful as an attack
  primitive: drop a malformed HFS image on a USB stick,
  hand to an operator, host's auto-mount triggers
  module load → kernel parser CVE.
- **udf** — DVD/Blu-ray. No modern server use.
- **ksmbd** — in-kernel SMB server, added 5.15. Many
  CVEs in 2022-2024 (CVE-2023-32257 RCE,
  CVE-2024-26845 type confusion). Operators usually
  run samba (userspace) instead.

Each of these is dead kernel code on most hosts. Block
the module load and the entire CVE class becomes
unreachable.

The `install <m> /bin/true` pattern is the canonical
modprobe defeat — even explicit `modprobe <m>` returns
success but loads nothing (same pattern used by
bluetooth-disable + usb-storage-mass-disable).

## Profiles

| Profile | Modules blocked |
|---|---|
| `baseline` (default) | cramfs, freevxfs, jffs2, hfs, hfsplus, udf, ksmbd |
| `strict` | baseline + squashfs, nfsd, gfs2 (operator must confirm no snap-package + no NFS server + no cluster fs use) |

`squashfs` is excluded from `baseline` because snap
packages depend on it; blocking would break every snap.
Operator using only deb/rpm packages can switch to
strict.

## File

`/etc/modprobe.d/selfdef-rare-filesystems-blacklist.conf`
rendered with header marker for uninstall ownership
check.

## Reboot behavior

modprobe.d takes effect on the NEXT load attempt. If a
blacklisted module is already loaded (rare but
possible), it stays loaded until `rmmod` or reboot.
apply.sh + check.sh both detect and log already-loaded
modules.

## MITRE coverage

- **T1068** Exploitation for Privilege Escalation —
  primary; kernel-parser-CVE-on-mounted-image class.
- **T1190** Exploit Public-Facing Application — ksmbd
  CVEs in particular (ksmbd is a network-facing
  service when started).
- **T1052.001** Exfiltration Over Physical Medium —
  defender-side; blocking hfsplus/udf reduces auto-
  mount on plugged-in media.
- **T1091** Replication Through Removable Media —
  defender-side; same as 1052.001.
- **T1014** Rootkit — secondary; ksmbd RCE has been
  used as a rootkit-install vector.

## Operator workflow

```bash
# Inspect the blacklist
cat /etc/modprobe.d/selfdef-rare-filesystems-blacklist.conf

# Verify a module is currently UNloadable
sudo modprobe cramfs        # exit 0 silently (install /bin/true) but lsmod shows nothing
lsmod | grep cramfs         # empty

# If a module is currently loaded (rare), check via:
lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|hfsplus|udf|ksmbd'

# To unload right now:
sudo rmmod ksmbd   # may need iptables-style force if active

# Switch to strict (operator-attestation that no snap + no NFS server)
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/rare-filesystems-disable.toml
sudo selfdefctl modules apply rare-filesystems-disable
```

## Caveats

- **squashfs is required by snap** — if operator uses
  any snap package, do NOT switch to `strict`.
- **nfsd is required by Linux kernel NFS server**.
  Operator running `exportfs` skips strict.
- **gfs2 is required by Red Hat Cluster Suite** —
  cluster-host operators skip strict.
- **Reboot may be required** if a target module was
  already loaded (rare with this set since none auto-
  load on modern distros).
- **Container hosts**: modprobe.d is host-scope.
  Containers cannot load kernel modules anyway; the
  blacklist on the host is the only meaningful layer.

## Coexistence

- **usb-storage-mass-disable**: complementary —
  usb-storage-mass-disable blocks USB block-storage
  driver entirely; this module blocks the FILESYSTEM
  drivers above it. Defense-in-depth pair.
- **bluetooth-disable**: same pattern (modprobe.d
  blacklist + install /bin/true); orthogonal scope
  (Bluetooth vs filesystem modules).
- **kernel-lockdown**: orthogonal; locks down kernel
  features post-load, doesn't block load.
- **integrity-sentinel + aide-bridge**: complementary —
  monitor / detect on-disk changes; this module
  prevents the attack from getting kernel exec at all.
- **secure-boot-status**: complementary trust-chain;
  blocked modules wouldn't be signature-checked
  anyway.
