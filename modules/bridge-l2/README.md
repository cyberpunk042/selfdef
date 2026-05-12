# bridge-l2

Transparent Layer-2 bridge with an nftables policy chain that other
inline modules (`suricata`, `polarproxy`) hook into. This is the
**foundation** module: it owns `br0` (or whatever you call your
bridge) and the FORWARD policy on it.

## What it does

1. Creates a Linux bridge interface (default name `br0`).
2. Adds the configured member interfaces to the bridge and brings them
   up with no IP address (the bridge is L3-invisible from the data
   path).
3. Installs an nftables ruleset that:
   - Owns the FORWARD chain on `br0` and either passes or drops by
     policy (depending on profile).
   - Drops INPUT on the management interface if one is configured —
     management plane is outbound-only.
   - Exposes an empty `selfdef_bridge_forward_hook` chain that the
     `suricata`, `polarproxy`, and any future inline modules add jumps
     into. The owning module does **not** know about its consumers.
4. Persists everything via systemd-networkd or an idempotent boot-time
   script (selectable in the profile).

## Profiles

| Profile         | Members                                  | FORWARD policy |
| --------------- | ---------------------------------------- | --------------- |
| `passthrough`   | configurable in host config              | `accept` — pure transparent bridge, no filtering yet. Use this as a baseline before stacking IDS/IPS on top. |
| `opnsense-edge` | two NICs (WAN-facing + LAN-facing)       | `accept` — same policy, but assumes a downstream OPNsense is the actual firewall; the bridge is purely an inspection vantage. |

Profiles set defaults; the operator overrides member NICs and bridge
name in `/etc/selfdef/host.toml`.

## Config

```toml
[modules.bridge-l2]
profile         = "opnsense-edge"
bridge_name     = "br0"
members         = ["eno1", "eno2"]
management_iface = "wlan0"            # optional; INPUT-drop applied if set
forward_policy  = "accept"            # accept | drop
persist         = "systemd-networkd"  # systemd-networkd | boot-script | none
```

See [`docs/src/modules.md`](../../docs/src/modules.md#config-layering)
for the full layering precedence rules.

## Idempotency

`install/apply.sh` is safe to re-run. On a host already at the target
state it makes zero changes and exits 0 with
`{"module":"bridge-l2","status":"skipped","message":"already at target state"}`.

## Dry-run

`SELFDEF_DRY_RUN=1` causes every state-changing step to print what it
*would* do and exit without touching the system. Use this on a target
host before committing to the real apply.

## Caveats

- Running this on a host whose only network access is via the
  to-be-bridged NICs will sever your connection. Either run it from
  the management interface or from console.
- The first apply does **not** schedule a "revert if no operator
  check-in within N minutes" safety. That's planned for the same
  module's v0.2.0.
