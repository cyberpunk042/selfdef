# nftables-baseline

Default-deny inet host firewall via nftables. Drops
inbound traffic by default; allows established/related +
loopback + ICMP + an operator-declared port set with SSH
**always** included. The foundational host-firewall layer
— and built so it can never lock the operator out.

## Why this matters

A host without a default-deny firewall accepts a
connection to every listening port from anywhere the
network can reach. Every service a package quietly starts
(a debug HTTP server, a clustering port, a forgotten
daemon) is exposed. Default-deny inverts that: nothing is
reachable unless explicitly allowed.

selfdef ships this as `nftables` (the modern Linux
firewall, replacing iptables) in a dedicated `inet`
table — `selfdef_filter` — so it composes with any other
nftables tables the operator runs without clobbering them.

## Profiles

| Profile | Inbound | Outbound |
|---|---|---|
| `baseline` (default) | drop; allow established/related + lo + ICMP + SSH (+operator `allow_tcp`/`allow_udp`) | accept |
| `web` | baseline + 80/443 inbound | accept |
| `locked` | baseline | **drop**; allow only established/related + lo + ICMP + DNS(53) + NTP(123) + HTTPS(443) egress. Requires `acknowledge_egress=true` |

Operator-declared extra ports go in the profile TOML:
```toml
profile = "baseline"
allow_tcp = "2222,8443"
allow_udp = "51820"          # e.g. wireguard
```

## Anti-lockout (refuse-to-brick)

The #1 firewall hazard is locking yourself out of SSH.
This module enforces a hard invariant:

1. **SSH is always in the allow set** — `detect_ssh_ports`
   parses `sshd_config` `Port` lines + always includes 22,
   so even a non-standard SSH port is allowed.
2. **Parse-check before apply** — the rendered ruleset is
   validated with `nft -c -f` before anything goes live;
   a malformed ruleset is refused.
3. **SSH-accept verification** — apply.sh greps the
   rendered ruleset for an SSH accept and ABORTS if it's
   somehow absent.
4. **Backup** — the current live ruleset is saved to
   `/var/lib/selfdef/nftables-ruleset.bak` before the
   first apply.

This is the 13th refuse-to-brick gate in the module
ecosystem.

## File

`/etc/nftables.d/selfdef-baseline.nft` rendered with a
selfdef header marker. Loaded live via `nft -f`. The table
is `inet selfdef_filter` (dual IPv4+IPv6).

## MITRE coverage

- **T1190** Exploit Public-Facing Application — default-
  deny shrinks the reachable-service surface to the
  explicitly-allowed set.
- **T1133** External Remote Services — only declared
  remote-access ports (SSH) are reachable.
- **T1046** Network Service Scanning — an external scan
  sees only the allowed ports; everything else is dropped
  silently.
- **T1048** Exfiltration Over Alternative Protocol — the
  `locked` profile's egress default-drop blocks
  unauthorized outbound channels.
- **T1571** Non-Standard Port — a backdoor on an
  unexpected port can't receive inbound connections under
  default-deny.

## Operator workflow

```bash
# Inspect the loaded ruleset
sudo nft list table inet selfdef_filter

# Watch the drop counter (recon / attack volume)
sudo nft list chain inet selfdef_filter input | grep counter

# Allow an extra inbound port
sudo sed -i 's/^allow_tcp.*/allow_tcp = "8080"/' \
    /etc/selfdef/modules/nftables-baseline.toml
sudo selfdefctl modules apply nftables-baseline

# Egress lockdown (CONFIRM it won't break your workflows)
sudo tee /etc/selfdef/modules/nftables-baseline.toml <<EOF
profile = "locked"
acknowledge_egress = true
EOF
sudo selfdefctl modules apply nftables-baseline

# Emergency: flush our table (restores reachability)
sudo nft delete table inet selfdef_filter
```

## Persistence across reboot

The ruleset file lives in `/etc/nftables.d/`. For it to
load at boot, the host's `nftables.service` must `include`
that directory (Debian's default `/etc/nftables.conf`
often does; RHEL varies). apply.sh loads it LIVE
immediately; check.sh verifies it's loaded. If your distro
doesn't auto-include `/etc/nftables.d/`, add to
`/etc/nftables.conf`:
```
include "/etc/nftables.d/*.nft"
```
and `systemctl enable nftables`.

## Caveats

- **Boot-load wiring is distro-specific** — apply.sh
  guarantees the LIVE load; persistent boot-load needs the
  include line above on some distros (documented, not
  auto-edited, to avoid clobbering operator nftables.conf).
- **Docker/Podman manage their own nftables tables** — this
  module's dedicated `selfdef_filter` table coexists, but
  container port-publish rules live in separate tables
  (`ip nat`, docker's chains). On a container host, verify
  published ports still work after apply.
- **`locked` egress-drop breaks** apt/dnf (unless the
  mirror is HTTPS), telemetry, non-443/53/123 outbound.
  Gated by acknowledge_egress.
- **firewalld hosts**: if firewalld is active it owns
  nftables; running both is confusing. Pick one — disable
  firewalld OR don't use this module there.

## Coexistence

- **fail2ban-bridge**: complementary — fail2ban adds
  dynamic per-IP bans (its own table/set); this is the
  static default-deny baseline beneath it.
- **listening-ports-watchdog + mta-loopback-detect**:
  complementary — those DETECT exposed listeners; this
  DROPS inbound to undeclared ports regardless.
- **sysctl-network-baseline**: complementary IP-layer
  sysctl hardening (rp_filter, syncookies) beneath the
  firewall rules.
- **vpn-bridge / wireguard**: declare the VPN UDP port in
  `allow_udp` so the tunnel can establish.
