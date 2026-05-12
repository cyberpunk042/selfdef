# polarproxy

Transparent [PolarProxy](https://www.netresec.com/?page=PolarProxy)
deployment: TLS termination and re-encryption, with cleartext flows
emitted as PCAP-over-IP on tcp/4430 for downstream IDS / capture
tools (most commonly Suricata or Wireshark / tshark).

## Threat / use case

You want to inspect *what's actually inside* the TLS flows crossing
this host — JA3 fingerprints + SNI aren't enough; you need the
plaintext for content rules. PolarProxy acts as a man-in-the-middle
with a CA you've installed on endpoints; this module wires it into
the network path and exposes the decrypted feed.

## Scope of this module

Owns:

1. **systemd unit**: `polarproxy.service` that runs the PolarProxy
   binary with the configured listener / TLS / log paths.
2. **nftables redirect** (host-tls-mitm only): TCP/443 from the local
   host → 10443 (or whatever `listen_port` you set).
3. **Pointer file** `/etc/selfdef/modules/polarproxy.toml` exposing
   `pcap_over_ip_port` so downstream consumers (a future
   `selfdef-collector-pcap` or a Suricata AF_PACKET feed via the
   `polarproxytls` dummy interface) can pick it up.

Does **not** own:

- Installation of the PolarProxy binary. It's a `.NET` binary
  released by Netresec; obtain it per their licence terms and put it
  on `$PATH` as `PolarProxy`. The module's `requires` will fail
  closed if it's not present.
- CA generation and endpoint trust distribution. That's an operator
  responsibility — wrong place to automate it.
- The `polarproxytls` dummy interface for the `bridge-tap` profile.
  Created on-demand by the service unit when needed; documented
  below.

## Profiles

| Profile           | What it does | Depends on |
| ----------------- | ------------ | ---------- |
| `host-tls-mitm`   | Adds nftables NAT redirect from this host's TCP/443 to the local PolarProxy listener. Cleartext exposed on tcp/4430. | — |
| `bridge-tap`      | Runs PolarProxy as an inline tap on the L2 bridge; cleartext fed into a dummy `polarproxytls` netdev so Suricata can read it via AF_PACKET. | `bridge-l2` (checked at apply time) |

## Config

```toml
[modules.polarproxy]
profile           = "host-tls-mitm"
listen_port       = 10443                        # local PolarProxy TLS listener
pcap_over_ip_port = 4430                         # cleartext PCAP-over-IP
cert_http_port    = 10080                        # CA cert exposure (set 0 to disable)
log_dir           = "/var/log/polarproxy"
ca_pfx_path       = "/etc/polarproxy/ca.pfx"     # PFX bundle PolarProxy signs with
ca_pfx_password   = ""                           # leave empty → read from env
```

## Idempotency & dry-run

`SELFDEF_DRY_RUN=1` short-circuits every state change. Re-running on a
host already at the target state emits `"status":"skipped"`. Switching
profiles (host-tls-mitm ↔ bridge-tap) cleanly removes the previous
profile's nftables rule before adding the new one's.

## Uninstall

`uninstall.sh` removes the nftables redirect (if any) and stops +
disables `polarproxy.service`. It does **not** delete the PolarProxy
binary, captured PCAPs, or the CA bundle.

## Caveats

- TLS interception is operator-visible and policy-bearing. Don't
  enable this without explicit user / device consent and a documented
  data-handling policy.
- PolarProxy 1.x and 2.x have slightly different CLI flags; this
  module currently targets 1.x defaults. Override the systemd unit's
  `ExecStart` in `/etc/systemd/system/polarproxy.service.d/override.conf`
  if you're on 2.x.
- Per-host `host-tls-mitm` only redirects *this host's* outbound
  TCP/443 — it doesn't intercept traffic transiting a bridge. For
  the latter, use `bridge-tap`.
