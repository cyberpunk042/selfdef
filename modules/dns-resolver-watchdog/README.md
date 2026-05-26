# dns-resolver-watchdog

Daily + boot delta of the active DNS resolver configuration
(`/etc/resolv.conf` nameservers + search domains,
systemd-resolved upstreams, `/etc/hosts` override count)
against a learned baseline. A CHANGED nameserver is the
DNS-hijack signature.

## Why this matters

Name resolution is the trust root for almost everything a
host does: package downloads (`apt`/`dnf` repo hostnames),
TLS endpoint identity, NTP servers, C2-vs-legit
distinction. An attacker who repoints DNS to a resolver
they control can:
- MITM package downloads → serve trojaned `.deb`/`.rpm`.
- Redirect `update.example.com` to a malicious mirror.
- Defeat some TLS validation paths (fake OCSP/CRL
  responders).
- Redirect telemetry / exfil to attacker infrastructure
  while looking "normal."

The hijack is often a one-line change: rewrite
`/etc/resolv.conf`, push a malicious DNS via a rogue DHCP
lease, or reconfigure systemd-resolved. Baselining the
resolver set + diffing it catches the change — and
escalates to ALERT specifically when a NAMESERVER (not
just a search domain) changes.

## Profiles

| Profile | Effect |
|---|---|
| `report` (default) | log delta; exit 0 |
| `enforce` | exit 1 on any resolver-config change → systemd unit failed → notifier engine |

## Severity ladder

| Condition | Severity | Event |
|---|---|---|
| First scan (baseline) | `ok` | `baseline_initial` |
| No delta | `ok` | `no_delta` |
| search-domain or /etc/hosts override-count change | `warn` | `resolver_config_changed` |
| nameserver added/changed (resolv.conf or resolved upstream) | `alert` | `nameserver_changed` (hijack signature) |

## What's recorded

| Class | Source |
|---|---|
| `nameserver:<ip>` | `/etc/resolv.conf` nameserver lines |
| `search:<domain>` | `/etc/resolv.conf` search domains |
| `resolved:<ip>` | `resolvectl dns` upstreams (the stub 127.0.0.53 hides the real servers; resolvectl reveals them) |
| `hosts_overrides:<count>` | non-comment `/etc/hosts` line count (sudden jump = mass hosts-based redirect) |

## Baseline file

`/var/lib/selfdef/dns-resolver-baseline.tsv` (mode 0600).
Re-baseline after a legitimate DNS change (new corporate
resolver, ISP change):
```bash
sudo rm /var/lib/selfdef/dns-resolver-baseline.tsv
sudo systemctl start selfdef-dns-resolver.service
```
Preserved across uninstall (forensic).

## Cadence

`OnBootSec=5min` + `OnUnitActiveSec=6h` + jitter. DNS can
be hijacked any time (resolv.conf rewrite, rogue DHCP
lease, resolved reconfigure); boot catch confirms the
config after every restart / DHCP renew.

## MITRE coverage

- **T1584.002** Compromise Infrastructure: DNS Server —
  the attacker-controlled resolver is compromised infra;
  this detects the host being pointed at it.
- **T1565.001** Stored Data Manipulation — rewriting
  resolv.conf is stored-config manipulation.
- **T1557** Adversary-in-the-Middle — DNS redirect is a
  classic MITM setup step.
- **T1071.004** Application Layer Protocol: DNS — a
  changed resolver may be a DNS-tunneling C2 endpoint.

## Operator workflow

```bash
# Last scan
journalctl -t selfdef-dns-resolver -n 1 --no-pager

# Per-change detail
journalctl -t selfdef-dns-resolver-detail --since "1 day ago"

# Manual inventory
cat /etc/resolv.conf
resolvectl dns 2>/dev/null
grep -cvE '^\s*(#|$)' /etc/hosts

# Investigate an alert
# - Is the new nameserver expected (corporate/ISP change)?
# - Was resolv.conf rewritten? (check mtime, audit-rules)
sudo stat /etc/resolv.conf

# Re-baseline after a legit change
sudo rm /var/lib/selfdef/dns-resolver-baseline.tsv
sudo systemctl start selfdef-dns-resolver.service
```

## Caveats

- **DHCP churn**: hosts on DHCP with rotating ISP
  resolvers will see legitimate nameserver changes →
  `nameserver_changed` alerts. On such hosts, either
  pin static DNS (better security anyway) OR re-baseline
  after each lease change OR accept the warn-tier noise.
- **systemd-resolved stub**: resolv.conf often points to
  127.0.0.53 (the stub). The module reads BOTH the stub
  entry AND the real upstreams via `resolvectl dns` so a
  hijack of the actual upstream is caught even behind the
  stub.
- **VPN connect/disconnect** changes DNS legitimately →
  expected churn on road-warrior laptops. Static-DNS
  servers are the clean case.
- **Detection only** — does not lock resolv.conf. Operator
  can `chattr +i /etc/resolv.conf` (with systemd-resolved
  disabled) for prevention; this module detects either way.

## Coexistence

- **dns-shield + loopback-only-dns**: complementary — those
  HARDEN the DNS path (DoT, local resolver); this DETECTS
  hijack of whatever resolver is configured.
- **account / cron / listening-ports / kernel-module /
  mount-options watchdogs**: sibling config-integrity +
  persistence-surface delta family on the staggered ladder.
- **audit-rules**: complementary — auditd can watch
  /etc/resolv.conf writes in real time; this is the
  periodic state-delta backstop (catches resolved-upstream
  changes that don't touch resolv.conf).
- **package-trust-baseline**: complementary — DNS hijack
  is one way to MITM package downloads; package-trust
  (signed-by) defends the package-signature layer
  independently.
