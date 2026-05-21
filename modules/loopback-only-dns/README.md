# loopback-only-dns

systemd-resolved hardening — restricts the DNS stub listener to
loopback only + disables link-local resolution + sets sane TLS
defaults. Pairs with `dns-shield` (the sinkhole layer on
/etc/hosts) at a different point in the DNS resolution path.

## Why this matters

A host with systemd-resolved listening on a non-loopback IP can
be abused as a:
- **T1498.002** Reflection Amplification (DDoS): attacker spoofs
  victim source IP → resolver sends large response to victim
- **T1018** Remote System Discovery: attacker queries the
  resolver to enumerate operator's internal DNS view
- **DNS rebinding** facilitator if zone authoritative records
  are reachable through it

Default systemd-resolved on Debian/Ubuntu binds to 127.0.0.53
(loopback), but operator-installed dnsmasq + an unconfigured
unbound + a misconfigured drop-in CAN expose port 53 broadly.
This module's drop-in pins systemd-resolved's behavior
explicitly.

## Profiles

| Profile | DNSStubListener | LLMNR | mDNS | DNSSEC | DoT |
|---|---|---|---|---|---|
| `loopback` (default) | yes (127.0.0.53) | no | no | allow-downgrade | opportunistic |
| `disabled-listener` | no | no | no | allow-downgrade | opportunistic |

Both profiles share:
- `LLMNR=no` + `MulticastDNS=no` — these are link-local
  resolution protocols an attacker on the same L2 can spoof
  (Responder.py + similar tools)
- `DNSSEC=allow-downgrade` — operator-tunable to `yes` (strict)
  via 60-operator-dnssec.conf drop-in
- `DNSOverTLS=opportunistic` — uses DoT when upstream supports it;
  operator-tunable to `yes` (strict) via 60-operator drop-in
- `FallbackDNS=` (empty) — refuses silent fallback to
  Google/Cloudflare; forces operator to set Upstream DNS via
  the OS-shipped /etc/systemd/resolved.conf OR a 60-operator
  drop-in

## When to use `disabled-listener`

If the operator runs their own local resolver (unbound,
pi-hole, dnsmasq) on 127.0.0.1:53, systemd-resolved's stub
listener is unnecessary AND will collide on port 53. The
disabled-listener profile turns systemd-resolved's stub off
entirely while keeping it as the NSS resolver backend.

## MITRE coverage

- **T1498.002** Network Denial of Service: Reflection
  Amplification — direct prevention (no off-host listener =
  no reflection source)
- **T1018** Remote System Discovery — defender side: attackers
  scanning your network's port 53 see no service on this host
- **T1557** Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning —
  LLMNR=no + MulticastDNS=no remove the link-local resolution
  attack surface

## Coexistence

- **dns-shield**: writes sinkhole entries to /etc/hosts. NSS
  consults /etc/hosts BEFORE the resolver, so dns-shield's
  blocks fire FIRST regardless of which resolver runs.
- **bridge-l2**: declares nftables rules in a separate table;
  doesn't touch port 53.
- **fail2ban-bridge**: doesn't ban DNS clients (sshd jail
  scope only).

## Operator-extension

`/etc/systemd/resolved.conf.d/60-operator-upstream.conf` —
operator's Upstream DNS choice (Cloudflare, Quad9, NextDNS,
self-hosted). Numbered LATER → overrides selfdef's defaults.
selfdef NEVER touches operator-prefixed files.

Example:
```ini
[Resolve]
DNS=1.1.1.1 1.0.0.1
DNSOverTLS=yes
DNSSEC=yes
```

## Operator workflow

```bash
# Verify live state
resolvectl status

# Verify no off-loopback port 53 listener
sudo ss -lntu | grep ':53 '
# Expected:  only 127.0.0.53 or 127.0.0.1 entries

# Test DNS resolution
resolvectl query example.com

# Force-refresh stale cache
sudo resolvectl flush-caches
```

## Caveats

- **Container hosts** (Docker / podman) often need 127.0.0.1:53
  reachable from containers. Use the docker `--dns` flag or
  systemd-resolved's bridge-network forwarding (`Domains=~docker`).
- **Some VPN clients** (OpenVPN, wireguard with split-tunnel)
  expect to write to /etc/resolv.conf directly. systemd-
  resolved manages that file; operator-side VPN configs may
  need `dhcp-option DNS` or `update-resolv-conf` hooks.
- **mDNS=no** disables Bonjour / Avahi discovery for printer +
  AirPlay devices. Operator on a network with Apple-ecosystem
  devices may want mDNS=yes via a 60-operator drop-in.
