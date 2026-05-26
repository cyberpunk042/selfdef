# nfs-mount-watchdog

Verifies every network filesystem mount (nfs/nfs4/cifs/
smb3/fuse.sshfs/ceph/gluster/afs) carries `nosuid` +
`nodev`. A network mount WITHOUT `nosuid` lets whoever
controls the export (or a MITM on an unencrypted link)
plant a setuid-root binary that the client honors → any
local user runs it → instant local root. CIS 2.x.

## Why this matters

A network filesystem is, by definition, content the local
host does not control. The export server's admin — or an
attacker who compromised it, or a man-in-the-middle on an
unencrypted NFSv3 link — chooses what files exist there.
If the client mounts it without `nosuid`:

```
# on the (attacker-controlled) NFS server:
cp /bin/bash /export/share/rootshell
chmod 4755 /export/share/rootshell   # setuid root
# on the victim client (mounted without nosuid):
/mnt/share/rootshell -p              # → root shell
```

`nosuid` makes the client ignore setuid/setgid bits on the
mounted fs (defusing this). `nodev` blocks device-node
interpretation from the export. Both are mandatory on any
network mount.

This module is distinct from `mount-options-watchdog`
(which checks LOCAL critical mounts like /tmp); this
focuses on NETWORK mounts, where the threat model — an
untrusted remote controlling the content — is qualitatively
worse.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if any network mount lacks nosuid → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No network mounts, or all carry nosuid+nodev | `ok` | `network_mounts_hardened` / `no_network_mounts` |
| A network mount missing nodev (has nosuid) | `warn` | `network_mount_missing_nodev` |
| A network mount missing nosuid | `alert` | `network_mount_missing_nosuid` (the root vector) |

## Network fs types checked

`nfs`, `nfs4`, `cifs`, `smb3`, `smbfs`, `fuse.sshfs`,
`ceph`, `glusterfs`, `afs`.

## Cadence

`OnBootSec=6min` + `OnUnitActiveSec=6h` + jitter — network
mounts come and go (autofs, operator `mount`), so a 6h
cadence catches a freshly-mounted unhardened share; boot
catch confirms fstab-persistent ones.

## MITRE coverage

- **T1080** Taint Shared Content — PRIMARY; a setuid binary
  on a shared export is tainted content that escalates on
  the client.
- **T1548.001** Abuse Elevation Control: Setuid/Setgid —
  the missing-nosuid mount is what makes the export's
  setuid bit dangerous.
- **T1210** Exploitation of Remote Services — narrowly; the
  NFS trust relationship is the exploited service.
- **T1080** also covers the watering-hole-via-share pattern.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-nfs-mount -n 1 --no-pager

# Per-mount detail
journalctl -t selfdef-nfs-mount-detail --since "1 day ago"

# Manual check
findmnt -t nfs,nfs4,cifs,smb3 -o TARGET,SOURCE,OPTIONS

# Remediate — remount with nosuid,nodev (and fix fstab)
sudo mount -o remount,nosuid,nodev /mnt/share
# In /etc/fstab, add nosuid,nodev to the options column:
#   server:/export  /mnt/share  nfs4  rw,nosuid,nodev,...  0 0
# autofs: add to the map entry options.
```

## Caveats

- **Some legitimate NFS workflows need suid** (rare —
  shared /opt with setuid tools across trusted hosts). If
  the export is genuinely trusted + admin-controlled, the
  operator accepts the alert or scopes that mount out. The
  default assumption (untrusted remote) is the safe one.
- **Detection only** — remediation is `mount -o remount` +
  fstab/autofs-map edit (which selfdef doesn't auto-edit;
  network-mount config is too site-specific).
- **NFSv3 over an unencrypted link** is MITM-able
  regardless; nosuid defuses the setuid-escalation half,
  but operators should also use NFSv4 + krb5p or a VPN
  (vpn-bridge) for confidentiality.
- **findmnt required** (util-linux; universally present).

## Coexistence

- **mount-options-watchdog**: the local-mount sibling —
  that checks /tmp, /var/tmp, /home etc.; this checks
  NETWORK mounts (worse threat model). Run both.
- **suid-sgid-watchdog + file-capabilities-watchdog**:
  complementary — those find suid artifacts on LOCAL fs;
  nosuid on the network mount is what stops a REMOTE suid
  artifact from mattering.
- **vpn-bridge**: complementary — for confidentiality of
  the NFS link itself (this module addresses the
  setuid-escalation surface, not link encryption).
- **rpcbind-disable**: related — on a host that is NOT an
  NFS client, rpcbind-disable removes the portmapper
  entirely; this module is for hosts that DO mount NFS.
