# mta-loopback-detect

Detection module verifying that any listening SMTP-family
port (25 smtp, 465 smtps, 587 submission) binds ONLY to
loopback — not `0.0.0.0` / `::` / a routable address. A
mail transfer agent reachable from the network is an
open-relay + spam-cannon + CVE attack surface; most hosts
only need local mail delivery on `127.0.0.1`.

## Why this matters

Linux distros ship an MTA (postfix on Debian/Ubuntu,
postfix/sendmail on RHEL) so that local services can send
mail — cron job output, `logwatch` reports, `mdadm` RAID
alerts, `smartd` disk warnings. That mail only needs to
flow to `127.0.0.1:25`.

If the MTA instead binds `0.0.0.0:25` (network-reachable),
the host becomes:
- **An open relay** (if misconfigured) — spammers route
  millions of messages through it; the host's IP lands on
  every blocklist.
- **A network attack surface** — SMTP-protocol-parsing
  CVEs (exim has had remote-root CVEs: CVE-2019-10149,
  CVE-2019-15846, CVE-2020-28017 family) become remotely
  exploitable.
- **A spam-backscatter source** — bounces to forged
  senders.

The default postfix `inet_interfaces` is often
`all` on server installs. This module catches the
exposure. (Remediation — `inet_interfaces = loopback-only`
— is operator config since MTA config syntax varies; this
module is detection.)

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log findings; exit 0 |
| `enforce` | exit 1 if any SMTP port binds a non-loopback address |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| No SMTP listener OR all loopback-only | `ok` | `no_smtp_or_loopback_only` |
| SMTP bound to a specific routable address | `warn` | `smtp_routable_bind` (intentional mail server — confirm) |
| SMTP bound to `0.0.0.0` / `::` wildcard | `alert` | `smtp_wildcard_bind` (open to the whole network) |

## Cadence

`OnBootSec=5min` + `OnUnitActiveSec=6h` + jitter. An MTA
can be reconfigured to expose port 25 any time (operator
edit, `dpkg-reconfigure postfix`); 6h bounds detection
latency.

## MITRE coverage

- **T1190** Exploit Public-Facing Application — PRIMARY; a
  network-exposed MTA is a public-facing app with a long
  RCE-CVE history (exim especially).
- **T1071.003** Application Layer Protocol: Mail Protocols
  — exposed SMTP is a C2 / exfil channel.
- **T1048** Exfiltration Over Alternative Protocol — an
  open relay is an exfil path.
- **T1046** Network Service Scanning — defender-side; the
  module is the host's self-scan of its own SMTP exposure.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-mta-loopback -n 1 --no-pager

# Manual check
ss -lntp 'sport = :25'
ss -lntp 'sport = :465 or sport = :587'

# Remediate postfix (the common case) — bind loopback only
sudo postconf -e 'inet_interfaces = loopback-only'
sudo systemctl restart postfix
# Verify
ss -lntp 'sport = :25'   # expect 127.0.0.1:25 + [::1]:25 only

# Remediate exim
sudo sed -i 's/^local_interfaces.*/local_interfaces = <; 127.0.0.1 ; ::1/' \
    /etc/exim4/exim4.conf.localmacros   # path varies
```

## Caveats

- **Intentional mail servers** (a real SMTP gateway,
  Mailcow, mail-in-a-box) legitimately bind the network →
  fire `smtp_routable_bind` (warn) or `smtp_wildcard_bind`
  (alert). Operator confirms + sets the module to report,
  OR scopes the expected port out. This module assumes the
  COMMON case (host needs local mail only).
- **submission (587) + smtps (465)** behind TLS + auth are
  legitimate for a mail server; still flagged for operator
  awareness.
- **Detection only** — does not edit MTA config (postfix
  vs exim vs sendmail syntaxes differ too much for safe
  auto-edit). Remediation is the documented operator step.
- **ss must be installed** (iproute2).

## Coexistence

- **listening-ports-watchdog**: complementary — that
  catches ANY new listener; this is SMTP-specific with
  loopback-vs-exposed classification + remediation
  guidance.
- **fail2ban-bridge**: if an MTA IS intentionally exposed,
  fail2ban's postfix/sasl jails defend it; this module
  flags the exposure so the operator makes that an
  informed choice.
- **sysctl-network-baseline + rpcbind-disable + avahi-
  disable**: network-surface-reduction family; this adds
  the SMTP slice.
- **ssh-hardening**: same philosophy (bind/expose only
  what's needed) applied to the SSH surface.
