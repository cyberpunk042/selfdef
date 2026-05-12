# vpn-bridge

Remote-network connectivity for hosts that **sit behind their own
NAT** (the classic "OPNsense at home + OPNsense at the office, neither
has a public IP, I want to reach my AI machine on the other LAN"
case). The module ships **three profiles**, each with a different
trust + paradigm tradeoff, plus a documented extension hook so future
overlay tech can slot in without forking.

## Decision matrix

| Profile | Paradigm | Trust boundary | Setup cost | Best for |
| --- | --- | --- | --- | --- |
| `relay-via-server` | P2P overlay via your own WireGuard relay | You / the relay's operator | Stand up a $3/mo VPS (or any host with a public IP) | Maximum control, no SaaS dependency, full L3 reachability |
| `tailscale` | P2P overlay via Tailscale's DERP/hole-punching | Tailscale (or your self-hosted Headscale) | Sign up (or run Headscale), drop an auth key on disk | Easy mode. Works through any NAT in minutes, including symmetric. Best when "it just works" matters |
| `cloudflare-tunnel` | **Outbound L7 publishing** (not an overlay!) | Cloudflare | Create a tunnel in Zero Trust, paste the token | "I want to reach the AI machine's web UI from anywhere, behind Cloudflare Access" — single-direction service publishing |

The three are **not interchangeable**. The first two give you bidirectional
L3 reachability (ping, SSH, NFS, arbitrary IP traffic). `cloudflare-tunnel`
only publishes specific services to a Cloudflare-fronted hostname — you
can't ping across it.

It's normal to run more than one of these. A common shape:

- `relay-via-server` (or `tailscale`) for full overlay reachability between
  your hosts and OPNsense routers.
- `cloudflare-tunnel` to expose the AI machine's web UI to a non-VPN'd
  device (your phone, a guest, etc.) with Cloudflare Access in front.

A single `vpn-bridge` instance can only run one profile, but the
module is declared `instanced = true` so you can run two instances on
the same host — one per profile — by giving each its own
`#instance` suffix in `/etc/selfdef/modules.toml`:

```toml
[modules."vpn-bridge#overlay"]
config = "/etc/selfdef/modules/vpn-bridge.overlay.toml"   # profile = "relay-via-server" (or "tailscale")
[modules."vpn-bridge#publish"]
config = "/etc/selfdef/modules/vpn-bridge.publish.toml"   # profile = "cloudflare-tunnel"
```

Each instance gets its own config file, its own structured-status
line, and (where applicable) its own service unit. Instances run in
alphabetical order under `selfdefctl modules apply`.

## Profiles

### `relay-via-server` — operator-run public WireGuard relay

```
  ┌──────────────┐                ┌─────────────────┐                ┌──────────────┐
  │ Endpoint A   │ ────wg/udp───► │ Relay (public)  │ ◄───wg/udp──── │ Endpoint B   │
  │  behind NAT  │   (keepalive)  │  public IP      │  (keepalive)   │  behind NAT  │
  └──────────────┘                │  ip-forwarding  │                └──────────────┘
                                  └─────────────────┘
```

Pure WireGuard. You generate keys, write the `wg-quick` config
yourself; the module owns the service state and (optionally) the
forwarding nftables rule between the wg interface and a LAN-side
interface.

**Config:**

```toml
[modules.vpn-bridge]
profile        = "relay-via-server"
role           = "endpoint"          # endpoint | relay
interface      = "wg0"
listen_port    = 51820
forward_to_lan = ""                  # e.g. "br0" or "eno1" to expose LAN
```

The wg-quick config itself (which is **operator-owned**) for a typical
relay-and-two-endpoints topology:

**`/etc/wireguard/wg0.conf` on each endpoint:**

```ini
[Interface]
PrivateKey = <endpoint's privkey>
Address    = 10.99.0.2/24    # 10.99.0.3 on the other endpoint
ListenPort = 51820

[Peer]
PublicKey            = <relay's pubkey>
Endpoint             = relay.example.com:51820
AllowedIPs           = 10.99.0.0/24
PersistentKeepalive  = 25
```

**`/etc/wireguard/wg0.conf` on the relay:**

```ini
[Interface]
PrivateKey = <relay's privkey>
Address    = 10.99.0.1/24
ListenPort = 51820
PostUp     = sysctl -w net.ipv4.ip_forward=1
PostDown   = sysctl -w net.ipv4.ip_forward=0

[Peer]
PublicKey  = <A's pubkey>
AllowedIPs = 10.99.0.2/32

[Peer]
PublicKey  = <B's pubkey>
AllowedIPs = 10.99.0.3/32
```

**Reaching a remote LAN** (e.g. AI machine at `192.168.50.42` on
Endpoint B's LAN): add `192.168.50.0/24` to the relay's peer-B
`AllowedIPs` *and* to Endpoint A's peer-relay `AllowedIPs`; on
Endpoint B set `forward_to_lan = "<lan-iface>"` so the kernel
forwards overlay traffic onto the LAN.

**One-time keygen:**
```bash
sudo /usr/share/selfdef/modules/vpn-bridge/install/keygen.sh wg0
```

### `tailscale` — defer NAT traversal to Tailscale / Headscale

```
  Endpoint A ────► tailscaled ────► Tailscale control plane (or your Headscale)
  Endpoint B ────► tailscaled ─────────────┘ + DERP relays for fallback
```

Tailscale handles hole-punching, DERP relay fallback, key
distribution, and ACLs. You install the package, drop an auth key,
the module runs `tailscale up` with your parameters.

**Config:**

```toml
[modules.vpn-bridge]
profile          = "tailscale"
auth_key_path    = "/etc/tailscale/auth.key"   # 0600, operator-managed
control_url      = ""                          # empty = Tailscale-hosted; set = self-hosted Headscale URL
hostname         = ""                          # default: system hostname
advertise_routes = ""                          # comma-sep CIDRs (subnet router)
accept_routes    = "false"                     # accept routes advertised by other nodes
tags             = ""                          # comma-sep ACL tags
```

The module runs `tailscale up --reset --auth-key=file:<path>` plus
whatever optional flags you set. Re-applies are safe — `tailscale up`
is itself idempotent.

**Trust note**: in hosted mode, Tailscale's control plane sees node
identities, routes, and ACL decisions (but not packet payloads — those
are WireGuard-encrypted end-to-end). Run Headscale yourself if that
trust boundary bothers you.

### `cloudflare-tunnel` — outbound L7 tunnel for service publishing

```
                        ┌──────────────────────┐
  Host with             │ Cloudflare edge      │  ◄────────  Your phone / guest /
  cloudflared ────►     │   (Access policy)    │             non-VPN'd device
  (outbound only)       └──────────────────────┘             (HTTPS to your hostname)
```

`cloudflared` makes an outbound persistent connection to Cloudflare's
edge; service requests for the configured hostname are routed back
through the tunnel to local addresses (HTTP origins, SSH, raw TCP).
Pair with Cloudflare Access for SSO / device-posture / IP allow-list
auth in front of internal services.

**Config (token mode, simplest):**

```toml
[modules.vpn-bridge]
profile           = "cloudflare-tunnel"
tunnel_token_path = "/etc/cloudflared/token"     # 0600, paste the token from Zero Trust → Tunnels
```

**Config (config-file mode, more flexible):**

```toml
[modules.vpn-bridge]
profile          = "cloudflare-tunnel"
tunnel_id        = "<uuid from cloudflared tunnel create>"
credentials_path = "/etc/cloudflared/<uuid>.json"
config_path      = "/etc/cloudflared/config.yml"
```

The module runs `cloudflared service install`; the unit it writes
auto-starts on boot. The actual tunnel routing (which hostname →
which local service) is owned by your Cloudflare dashboard or your
`config.yml`, not by selfdef.

**This is not a substitute for `relay-via-server` or `tailscale`.**
It cannot move arbitrary IP traffic between hosts. Use it for
exposing services *outward*, with Cloudflare in front for auth.

## Scope of this module

Owns:

1. The systemd service state for the chosen profile (`wg-quick@<iface>`,
   `tailscaled`, or `cloudflared`).
2. The optional bridging nftables rule between the wg interface and a
   LAN iface (relay-via-server only).
3. `keygen.sh` one-time helper for WireGuard keypairs.

Does **not** own:

- The package install (`wireguard-tools`, `tailscale`, `cloudflared` —
  each profile's preflight fails closed if its binary is missing).
- The wg-quick config file, the Tailscale auth key, or the Cloudflare
  tunnel credentials — all operator-managed at `0600`.
- Cross-profile coexistence on the same host (one active profile at a
  time per module instance — multi-instance support is future work).

## Extending — adding a new profile

The module is intentionally extensible. To add e.g. a `nebula`
or `zerotier` profile:

1. Create `install/profiles/<name>.sh`. Define three functions:
   `profile_apply`, `profile_check`, `profile_uninstall`. Each should
   end with one `emit_status` call. Use `die "<reason>"` to fail
   closed.
2. Create `profiles/<name>.toml` with the default config values your
   profile needs.
3. Add `<name>` to `[profiles].available` in `module.toml`. Update
   the manifest's `provides` if your profile offers a new capability
   (e.g. a profile that does both publishing and overlay would
   declare both `overlay-network` and `published-tunnel`).
4. Add a section to this README's [Decision matrix](#decision-matrix)
   explaining when to pick it.
5. Add smoke tests in `crates/selfdef-cli/tests/module_vpn_bridge_<name>.rs`.

The dispatcher in `install/{apply,check,uninstall}.sh` will pick up
the new profile automatically — there is no central registry to
update.

## Idempotency

Same contract as every module — re-applying is a no-op,
`SELFDEF_DRY_RUN=1` prints intended actions only, every action ends
with a structured-status JSON line.

## Uninstall

`uninstall.sh` cleanly tears down whichever profile is active. It
**does not** delete operator-owned data: WireGuard keys + wg.conf,
Tailscale auth keys, Cloudflare tunnel credentials, or the underlying
packages all survive.

## OPNsense integration

selfdef owns Linux host state directly. OPNsense state is **operator-
driven** via OPNsense's own UI / API:

- For `relay-via-server`: configure WireGuard on OPNsense via the
  `os-wireguard` plugin (Settings → WireGuard → Local) using the
  same key + peer values you'd put in `wg-quick` on a Linux host.
- For `tailscale`: enable the FreeBSD tailscale plugin on OPNsense
  (`os-tailscale`). Auth key handling is identical.
- For `cloudflare-tunnel`: not currently supported on OPNsense via
  the GUI; run cloudflared on a Linux host on the same LAN if you
  need the publishing pattern.

In all cases the *topology* (who is the relay, what's the overlay
subnet, what CIDRs each side advertises) is the same on OPNsense as
on Linux; only the install mechanism differs.

## Caveats

- **Trust models differ across profiles.** Read the per-profile
  section before picking.
- **Bandwidth**: `relay-via-server` doubles traffic on the relay's
  link. For personal scale this is fine. `tailscale` falls back to
  DERP relays only when direct hole-punching fails — most flows go
  point-to-point.
- **OPNsense**'s built-in WireGuard (24.x kernel WG) is the
  preferred path; `os-wireguard` plugin works on older versions.
