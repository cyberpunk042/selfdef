# vpn-bridge

WireGuard overlay between two or more hosts that **both sit behind
their own NAT** (the classic "OPNsense at home + OPNsense at the
office, neither has a public IP" case). The headline scenario this
module exists for: you want to reach a private LAN — say, an AI
machine — from a router that's behind a carrier-NAT too.

## Why this exists / what's hard

Vanilla WireGuard expects one peer to be reachable on a known
`Endpoint = ip:port`. When **both** ends are behind NAT and neither
can port-forward, you can't peer them directly without help. The
common workarounds:

| Approach | Reliability | Setup cost | Notes |
| --- | --- | --- | --- |
| Public relay (this module's profile) | Excellent | ~$3/mo VPS or any host with a public IP | Both ends WireGuard to the relay. Relay forwards. Works through any NAT type. |
| STUN-assisted hole punching | Good on cone NATs, fails on symmetric | Low | Out-of-band signalling needed. Not shipped in v0.1.0. |
| Tailscale / Headscale | Excellent (DERP fallback) | Requires Tailscale auth or self-hosted Headscale | Not shipped in v0.1.0. |

For v0.1.0 we ship only **`relay-via-server`** because it's the
profile that just works for the headline scenario, with no SaaS or
out-of-band signalling. The other approaches can land as additional
profiles once the relay one is proven.

## Scope of this module

Owns:

1. **Service state**: `wg-quick@<interface>` is enabled and started.
2. **nftables forwarding** between the wg interface and the LAN
   bridge / NIC (so traffic can actually move between the overlay
   and the local network — disabled by default; opt-in per host).
3. **`keygen.sh` helper** (not auto-run) that generates a private +
   public key pair into `/etc/wireguard/` with `0600` perms.

Does **not** own:

- **`/etc/wireguard/<interface>.conf`**. The operator writes that.
  The wg-quick format is the standard; rendering it from bash with a
  `[[peers]]` array of unknown length is hostile. The README shows
  exactly what to put in it for both the relay and endpoint roles.
- **WireGuard package install.** `requires.package = "wireguard-tools"`
  fails closed if the package isn't present.
- **Key distribution.** You generate keys, you copy the public ones to
  the operators of the other peers, via whatever channel you trust.

## Topology — `relay-via-server`

```
  ┌──────────────┐                ┌─────────────────┐                ┌──────────────┐
  │ Endpoint A   │                │ Relay (public)  │                │ Endpoint B   │
  │ 10.99.0.2/24 │ ────wg/udp───► │ 10.99.0.1/24    │ ◄───wg/udp──── │ 10.99.0.3/24 │
  │  behind NAT  │                │  public IP      │                │  behind NAT  │
  └──────────────┘                │  ip-forwarding  │                └──────────────┘
                                  │  enabled        │
                                  └─────────────────┘
```

The relay has a publicly reachable WireGuard `Endpoint`; both
endpoints connect to it and use `PersistentKeepalive = 25` to keep
the NAT pinhole open on their side.

## Config

```toml
[modules.vpn-bridge]
profile        = "relay-via-server"
role           = "endpoint"          # endpoint | relay
interface      = "wg0"
listen_port    = 51820

# Set `forward_to_lan` to a LAN-side iface name to enable
# bidirectional routing between the overlay and the local LAN. Empty
# = wg interface is reachable from the host only.
forward_to_lan = ""
```

The wg-quick config itself lives at `/etc/wireguard/<interface>.conf`
and is owned by the operator. For the relay-via-server topology:

**`/etc/wireguard/wg0.conf` on Endpoint A** (10.99.0.2):

```ini
[Interface]
PrivateKey = <A's privkey>
Address    = 10.99.0.2/24
ListenPort = 51820

[Peer]
# The relay.
PublicKey            = <relay's pubkey>
Endpoint             = relay.example.com:51820
AllowedIPs           = 10.99.0.0/24      # whole overlay through the relay
PersistentKeepalive  = 25
```

**`/etc/wireguard/wg0.conf` on the relay** (10.99.0.1):

```ini
[Interface]
PrivateKey = <relay's privkey>
Address    = 10.99.0.1/24
ListenPort = 51820
PostUp     = sysctl -w net.ipv4.ip_forward=1
PostDown   = sysctl -w net.ipv4.ip_forward=0

[Peer]
# Endpoint A
PublicKey  = <A's pubkey>
AllowedIPs = 10.99.0.2/32

[Peer]
# Endpoint B
PublicKey  = <B's pubkey>
AllowedIPs = 10.99.0.3/32
```

**Endpoint B is symmetric to A**, with its own keys and address.

## First-time setup

```bash
# On each host:
sudo /usr/share/selfdef/modules/vpn-bridge/install/keygen.sh wg0
# → writes /etc/wireguard/wg0.privkey (0600) + wg0.pubkey

# Edit /etc/wireguard/wg0.conf per the templates above.
# Then:
sudo selfdefctl modules apply vpn-bridge
```

`apply.sh` enables and starts the service, brings the interface up,
and applies the optional nftables forward rules.

## Reaching a remote LAN (e.g. your AI machine)

If your AI machine lives at `192.168.50.42` on Endpoint B's LAN, on
Endpoint A you can route to it by:

1. Add `192.168.50.0/24` to the relay's peer-B `AllowedIPs`.
2. Add `192.168.50.0/24` to Endpoint A's peer-relay `AllowedIPs`.
3. Set `forward_to_lan = "ens0"` (or whichever iface) on Endpoint B
   to let the kernel forward overlay traffic onto its LAN.

The module renders the nftables FORWARD rules; the wg-quick config
itself is still the operator's.

## Idempotency

Same contract as every module — re-running is a no-op,
`SELFDEF_DRY_RUN=1` prints intended actions only, the script emits
a structured-status JSON line at the end.

## Uninstall

`uninstall.sh` stops and disables `wg-quick@<interface>`, removes the
nftables forward table. It does **not** delete `/etc/wireguard/`
config or keys — operator responsibility.

## Caveats

- **Trust model**: the relay sees all traffic between endpoints. Use
  it like you'd use any VPN hub: TLS the things you care about,
  consider the relay's operator part of your trust boundary.
- **Bandwidth**: relay-via-server doubles the traffic on the relay's
  link. For a personal-scale overlay this is fine; for high-rate
  flows consider hole-punching once that profile ships.
- **OPNsense** runs WireGuard via the `os-wireguard` plugin or
  built-in 24.x kernel WireGuard. This module assumes a Linux host
  with `wg-quick` from `wireguard-tools`. OPNsense end-hosts are
  configured via the GUI/CLI directly — but the topology + the
  relay's own `wg0.conf` are still what's documented above.
