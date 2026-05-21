# rare-network-protocols-disable

Modprobe.d blacklist for rare network-protocol kernel
modules (DCCP, SCTP, RDS, TIPC at baseline; legacy
protocols at strict). Parallels `rare-filesystems-
disable` for the network side. Per CIS Benchmark 3.4.

## Why this matters

The Linux kernel ships parsers for many network
protocols nearly nobody uses on a general-purpose host.
Each parser is kernel-mode code accessible from the
network — when a CVE drops, anyone whose host happens
to have the module loaded is vulnerable, even if they
never knowingly used the protocol.

Real CVEs in these protocols:

| Protocol | CVE | Effect |
|---|---|---|
| DCCP | CVE-2017-6074 | Use-after-free → local PE |
| SCTP | CVE-2019-20812 | Memory corruption in chunk processing |
| RDS | CVE-2010-3904 | Priv-esc via RDS_PAGE_REMAINDER |
| TIPC | CVE-2021-43267 | Heap overflow in MSG_CRYPTO type |

Most hosts don't use any of these. Blocking the modules
eliminates the CVE classes regardless of which one
drops next.

## Profiles

| Profile | Modules blocked |
|---|---|
| `baseline` (default) | dccp, sctp, rds, tipc |
| `strict` | baseline + atm, can, appletalk, decnet, ipx, netrom, ax25, rose, x25 (DISA-STIG legacy) |

## File

`/etc/modprobe.d/selfdef-rare-network-protocols-
blacklist.conf` rendered with selfdef header marker for
uninstall ownership check.

## When NOT to use

- Telco / carrier-grade Linux running SIGTRAN (M3UA, M2PA)
  needs `sctp`. Skip this module.
- Oracle stack hosts using RDS sockets need `rds`. Skip.
- Some embedded / industrial Linux deployments use TIPC
  or CAN. Skip or use baseline-only.
- Ham-radio operators using AX.25 / NetROM / ROSE skip
  strict.

## MITRE coverage

- **T1068** Exploitation for Privilege Escalation —
  primary; kernel-protocol-parser CVE class.
- **T1190** Exploit Public-Facing Application — these
  are network-reachable protocol stacks (SCTP/TIPC
  especially can listen on the wire).
- **T1014** Rootkit — secondary; protocol-CVE chain has
  been used as a rootkit-install path.
- **T1499** Endpoint Denial of Service — narrowly;
  malformed packets to a rare protocol parser have
  caused kernel panics historically.

## Operator workflow

```bash
# Inspect the blacklist
cat /etc/modprobe.d/selfdef-rare-network-protocols-blacklist.conf

# Verify a module is currently UNloadable
sudo modprobe dccp           # silent exit 0; lsmod shows nothing
lsmod | grep -E 'dccp|sctp|rds|tipc'

# If a module was already loaded before this module installed:
sudo rmmod dccp

# Switch to strict (operator attestation that no
# legacy-protocol use)
sudo sed -i 's/^profile.*/profile = "strict"/' \
    /etc/selfdef/modules/rare-network-protocols-disable.toml
sudo selfdefctl modules apply rare-network-protocols-disable
```

## Caveats

- **Reboot recommended** if any target module is
  currently loaded (rare on modern distros since none
  of these auto-load).
- **rsyslog with imuxsock or imptcp** does NOT use any
  of these protocols. Safe.
- **kubernetes / Calico / Cilium** do NOT depend on
  these. Safe.
- **wireguard / openvpn / strongswan** do NOT use them.
  Safe.

## Coexistence

- **rare-filesystems-disable**: complementary —
  filesystem-side parallel; same pattern.
- **bluetooth-disable + usb-storage-mass-disable**:
  same modprobe.d pattern; orthogonal scopes
  (Bluetooth radio / USB block / network protocols /
  filesystem parsers). Defense-in-depth set.
- **sysctl-network-baseline + dns-shield + loopback-
  only-dns + fail2ban-bridge**: network-side hardening
  layered stack; this module is the kernel-module
  layer below the sysctl + DNS + IP-filtering layers.
- **kernel-lockdown + kernel-yama-baseline**:
  orthogonal kernel-feature restrictions, not module-
  load blocking.
