# sysctl-network-baseline

Default-deny sysctl baseline for `net.ipv4.*` + `net.ipv6.*`.
Renders `/etc/sysctl.d/50-selfdef-network-baseline.conf` +
applies live. Tightens the kernel's network stack against
well-known LAN/WAN attack classes that distro defaults
historically leave permissive (ICMP redirects, source-route,
SYN-flood, martian-source acceptance).

## Why this matters

Every Linux host inherits a sysctl tree that the distro
ships with defaults sized for compatibility, not security.
Examples of distro defaults that are NOT secure-by-default
in 2026:

| sysctl | Distro default | Risk |
|---|---|---|
| `net.ipv4.conf.all.accept_redirects` | 1 on some distros | Attacker on LAN sends ICMP-redirect → operator-host honors → traffic to gateway X re-routes through attacker-controlled box Y. |
| `net.ipv4.conf.all.accept_source_route` | 0 modern; 1 historic | Attacker-supplied "use this route" hint in IP options → routes around firewall. |
| `net.ipv4.icmp_echo_ignore_broadcasts` | 1 modern | If 0: smurf-attack amplification (broadcast ICMP echo → all LAN hosts reply to spoofed source). |
| `net.ipv4.tcp_syncookies` | 1 modern | If 0: SYN-flood fills conntrack table → service unavailable. |
| `net.ipv4.conf.all.log_martians` | 0 | No visibility on spoofed-source packet arrival. |
| `net.ipv6.conf.all.accept_ra` | 1 default | LAN-adjacent attacker advertises rogue IPv6 router → operator-host self-configures via attacker prefix. |

This module ships a curated baseline (mirroring CIS +
DISA-STIG guidance), the router profile for intentional
gateway hosts, and a paranoid profile for silent-host
deployments.

## Profiles

| Profile | net.ipv4 | net.ipv6 | ip_forward | ICMP echo |
|---|---|---|---|---|
| `baseline` (default) | source-route 0, redirects 0, syncookies 1, rp_filter strict, log_martians on, broadcast-echo ignore | accept_ra 0, autoconf 0, redirects 0, source-route 0 | distro default | reply (default) |
| `router` | baseline + send_redirects 1, conntrack TIME_WAIT 30s | accept_ra 0, autoconf 0 | 1 (forwards) | reply |
| `paranoid` | baseline + icmp_echo_ignore_all 1 (silent host) | disable_ipv6 1 globally | distro default | IGNORE — host invisible to ping/traceroute |

## Files installed

| Path | Purpose |
|---|---|
| `/etc/sysctl.d/50-selfdef-network-baseline.conf` | Rendered per-profile drop-in; loaded by `sysctl --system` at boot + by apply.sh live |
| `/etc/selfdef/modules/sysctl-network-baseline.toml` | Profile selector (operator-editable to switch profile) |

Header marker on rendered drop-in for uninstall ownership
check.

## Live apply + container safety

apply.sh writes the drop-in THEN walks every `key = value`
in it and calls `sysctl -w` per key. Failures on individual
keys are SOFT (logged as WARN) because containers + restricted
network namespaces commonly lack the `net.ipv6.*` or
`net.netfilter.*` keys; the module logs the count and moves on.

The final `sysctl --load=$DROPIN` consolidates the load and
matches what would happen at reboot.

## MITRE coverage

- **T1557.002** Adversary-in-the-Middle: ARP Cache Poisoning
  & ICMP Redirect — `accept_redirects=0` + `rp_filter=1`
  defeat the redirect-based half of this technique.
- **T1499** Endpoint Denial of Service — `tcp_syncookies=1`
  + `icmp_echo_ignore_broadcasts=1` directly defeat the two
  oldest DoS amplifications (SYN flood, smurf).
- **T1590** Gather Victim Network Information — `log_martians=1`
  gives the defender visibility into reconnaissance probes;
  paranoid `icmp_echo_ignore_all=1` denies the basic
  ping-sweep enumeration.
- **T1542.005** Pre-OS Boot: TFTP Boot — narrowly mitigated
  via `accept_source_route=0` (TFTP-boot relays via
  source-routed packets fail).

## Operator workflow

```bash
# Inspect rendered drop-in
cat /etc/sysctl.d/50-selfdef-network-baseline.conf

# Verify live values
sysctl net.ipv4.conf.all.accept_redirects \
       net.ipv4.tcp_syncookies \
       net.ipv4.conf.all.rp_filter

# Switch to router profile (on intentional gateway hosts)
sudo selfdefctl modules switch-profile sysctl-network-baseline router
sudo selfdefctl modules apply sysctl-network-baseline

# Operator override — add operator-prefixed drop-in that
# comes AFTER selfdef's (lex-order higher prefix wins):
sudo tee /etc/sysctl.d/60-operator-overrides.conf <<EOF
net.ipv4.conf.all.log_martians = 0   # I'm too noisy with this
EOF
sudo sysctl --system
```

## Caveats

- **`rp_filter=1` (strict mode)** breaks asymmetric routing
  scenarios (multi-homed hosts where reply route differs
  from receive interface). Operator on these topologies
  uses `rp_filter=2` (loose mode) via operator-prefixed
  drop-in.
- **`accept_ra=0`** breaks IPv6 SLAAC auto-config. Operator
  on dynamic-prefix ISPs (residential, mobile) must either
  set static IPv6 OR use dhcpv6 OR switch this baseline OFF.
  Server deployments typically have static IPv6 anyway.
- **paranoid `icmp_echo_ignore_all=1`** breaks ping and
  traceroute. Monitoring systems that ICMP-probe will
  flag the host DOWN. Use only after coordinating with
  monitoring team.
- **Container hosts**: many keys live in the host network
  namespace and are not settable from inside containers.
  Soft-fail behavior in apply.sh handles this. Host
  itself should apply this module; containers inherit
  what they're given.

## Coexistence

- **kernel-lockdown**: orthogonal — handles non-network
  kernel hardening (kptr_restrict, dmesg_restrict,
  perf_event_paranoid). Both apply together.
- **dns-shield + loopback-only-dns**: complementary —
  application-layer DNS hardening; this module handles
  the IP-layer below.
- **fail2ban-bridge**: complementary — fail2ban defends
  against application-protocol brute-force; this module
  defends against IP/ICMP-layer attacks one level lower.
- **vpn-bridge + polarproxy + bridge-l2**: hosts intentionally
  routing use the `router` profile to permit `ip_forward=1`.
