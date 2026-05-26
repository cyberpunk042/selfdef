# avahi-disable

Masks `avahi-daemon` (mDNS / DNS-SD / zeroconf) on hosts
that don't need service auto-discovery. Removes a LAN
information-leak surface and a recurring CVE class.

## Why this matters

Avahi implements mDNS (multicast DNS, `.local` names) +
DNS-SD (service discovery). When running it:

- **Broadcasts the hostname + every advertised service**
  on UDP 5353 to the entire LAN segment — a free
  reconnaissance gift. An attacker passively sniffing
  the LAN learns the host's name, OS hints, and which
  services (SSH, HTTP, printer, file-share) it offers.
- **Has a recurring CVE history**:
  - CVE-2021-3468 — infinite-loop DoS via crafted event.
  - CVE-2021-3502 — DoS via empty TXT record.
  - CVE-2023-1981 — DBus-triggered assertion crash.
  - Multiple earlier mDNS reflection / amplification
    issues.
- **mDNS is a reflection-amplification vector** — UDP
  5353 responders can be abused in DDoS reflection.

Most servers + IPS hosts have static hostnames + known
service endpoints. They never need zeroconf. Masking
avahi removes the leak + the CVE surface.

## Profiles

| Profile | Effect |
|---|---|
| `mask` (default) | stop + disable + mask avahi-daemon.service + avahi-daemon.socket. Defeats package re-install auto-enable + socket-activation. |
| `stop` | stop + disable only; operator-pull restartable. |

apply.sh probes for unit existence first — no-op on
hosts without avahi installed.

## When NOT to use

- **Desktop / laptop on a home LAN** using `.local`
  names to reach printers, Chromecast, AirPlay, network
  shares — avahi is the discovery mechanism.
- **CUPS auto-discovery of network printers** depends
  on avahi (though `services-disable-printing` already
  handles the print side).
- **Home Assistant / IoT hubs** discovering devices via
  mDNS.

For those, skip this module or use the `stop` profile +
re-enable when needed.

## MITRE coverage

- **T1046** Network Service Scanning — defender-side;
  with avahi off, the host no longer answers mDNS
  discovery probes, shrinking what an attacker enumerates.
- **T1590** Gather Victim Network Information — primary;
  avahi's broadcasts ARE the victim-network-info the
  attacker would otherwise harvest passively.
- **T1499** Endpoint Denial of Service — the avahi CVE
  DoS chain (CVE-2021-3468 etc.) is removed.
- **T1498** Network Denial of Service — mDNS reflection-
  amplification vector removed.

## Operator workflow

```bash
# Verify avahi is silent
systemctl status avahi-daemon 2>/dev/null | grep -E 'Loaded:|Active:'
ss -lnu | grep ':5353 '          # expect: empty

# Confirm the host no longer answers mDNS (from another host)
# avahi-resolve -n thishost.local   → should fail

# Re-enable for one-shot discovery (operator-pull)
sudo systemctl unmask avahi-daemon avahi-daemon.socket
sudo systemctl enable --now avahi-daemon
```

## Caveats

- **`.local` name resolution stops** for this host (both
  advertising AND, depending on nsswitch, resolving).
  Hosts that reach peers by `.local` need nss-mdns +
  avahi; this module breaks that.
- **Package upgrade may re-enable** without mask profile.
- **systemd-resolved also does mDNS** (separate
  implementation) — if the operator relies on
  resolved's mDNS, this module (which only touches
  avahi) won't disable it; configure
  `MulticastDNS=no` in resolved.conf separately.

## Coexistence

- **nscd-disable + services-disable-printing +
  bluetooth-disable + apport-disable**: same service-
  mask family; orthogonal scopes. avahi + printing
  often go together (operator who masks printing
  usually masks avahi too).
- **dns-shield + loopback-only-dns**: complementary
  DNS-layer hardening; avahi is the mDNS/zeroconf side.
- **sysctl-network-baseline**: complementary IP-layer
  hardening.
- **fail2ban-bridge**: orthogonal — avahi-off means
  one fewer network-facing daemon for fail2ban to
  worry about.
