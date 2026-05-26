# rsh-telnet-disable

Masks the legacy cleartext-protocol daemons if any are
present: telnet, rsh/rlogin/rexec, tftp, finger. These
transmit credentials and/or data in cleartext and have
no defensible place on a 2026 host. CIS 2.2.x.

## Why this matters

These protocols predate ubiquitous encryption and send
everything — including passwords — in plaintext on the
wire:

| Service | Port | Problem |
|---|---|---|
| `telnet` | 23 | Password + session in cleartext; LAN sniffer captures the login |
| `rsh` / `rlogin` | 514 / 513 | `.rhosts` trust + cleartext; trivially spoofable source-IP auth |
| `rexec` | 512 | Cleartext remote command execution |
| `tftp` | 69 (UDP) | No auth at all; arbitrary file read/write; classic config-exfil + boot-tamper vector |
| `finger` | 79 | User-enumeration info leak (who's logged in, home dirs, .plan) |

If any of these is installed AND running, it's almost
certainly a misconfiguration or a forgotten dependency.
The replacement for all of them is SSH/SCP/SFTP
(`ssh-hardening` module governs that).

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask every present legacy unit |
| `stop` | stop + disable only |

apply.sh probes for unit existence — on the common
modern host where none are installed, it's a clean
no-op (logs "the common, healthy case").

## Units covered

telnet.socket/telnetd.service/telnet.service,
rsh/rlogin/rexec .socket + .service,
tftp.socket/tftp.service/atftpd.service,
finger.socket/finger.service.

## MITRE coverage

- **T1040** Network Sniffing — PRIMARY; cleartext
  telnet/rsh passwords are the textbook sniff target.
- **T1110** Brute Force — cleartext protocols offer no
  rate-limiting or modern auth; trivially brute-forced.
- **T1078** Valid Accounts — rsh `.rhosts` source-IP
  trust is spoofable → unauthenticated account access.
- **T1071** Application Layer Protocol — tftp is a
  common malware config-pull + exfil channel.
- **T1087** Account Discovery — finger enumerates users.

## Operator workflow

```bash
# Confirm none are listening
ss -lntu | grep -E ':(23|512|513|514|69|79) '   # expect: empty

# Inspect what (if anything) was acted on
sudo selfdefctl modules check rsh-telnet-disable

# The correct replacement for ALL of these:
#   telnet  → ssh
#   rcp     → scp
#   rsh     → ssh <host> <command>
#   tftp    → scp / sftp
#   finger  → (don't; it's an info leak)
```

## Caveats

- **Network-boot infrastructure** sometimes uses tftp
  for PXE. A PXE/TFTP boot server legitimately needs
  tftp — skip this module on those, or scope tftp out.
- **Ancient embedded gear** occasionally still speaks
  telnet/rsh; isolate it on a segmented VLAN rather
  than running the daemon on a general host.
- **No-op is the expected result** on modern hosts —
  these packages aren't installed by default since the
  mid-2010s.

## Coexistence

- **ssh-hardening**: the positive counterpart — ssh is
  the encrypted replacement for every protocol this
  module disables.
- **avahi-disable + rpcbind-disable + nscd-disable +
  services-disable-printing + bluetooth-disable +
  apport-disable**: same service-mask family; this
  module covers the cleartext-legacy slice.
- **fail2ban-bridge**: with telnet/rsh masked, there's
  no cleartext login surface left for brute-force —
  fail2ban focuses on ssh.
- **audit-rules**: complementary — if a legacy daemon
  somehow runs, auditd's exec watch flags it.
