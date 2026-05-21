# SDD-039 — Bridge-L2 module — layer-2 transparent bridge — MS024

> Status: **draft** — Stage-2 architectural spec for the shipped
> `bridge-l2` module under `modules/bridge-l2/`. The module provisions
> a Linux bridge interface + nftables FORWARD chain that inline
> network modules (Suricata, polarproxy) hook into.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS024 (catalog
> `backlog/milestones/MS024-bridge-l2-module-layer-2-transparent-bridge.md`)
> Companions: SDD-040 (MS023 polarproxy — inline consumer),
> packaging/test/L2-bridge-l2.bats (11 tests)

## Problem

Inline network defense (IDS rules, TLS inspection, deep packet
inspection) requires the network stack to route through a controlled
chokepoint. A transparent L2 bridge gives this:
- the bridge interface is invisible to layer-3 endpoints (no IP
  reassignment needed)
- both ingress and egress traffic traverses the bridge
- nftables on the bridge's FORWARD chain becomes the policy
  enforcement point

Without a shared bridge substrate, each inline module would have to
own its own bridge config + risk colliding with siblings. This module
owns the bridge + the FORWARD chain skeleton; sibling modules add
jumps into their own chains via the `forward-policy` contract.

## Operator directive — verbatim (sacrosanct)

> "Make sure your order of execution make sense too. Some things
>  depend on others, all that intelligence must be there too."

Translation for MS024: bridge-l2 ships in phase=pre alongside
tetragon so inline IDS modules (phase=main) find both the bridge
+ the eBPF substrate already up.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/bridge-l2/module.toml` | provides=[l2-bridge, forward-policy], requires=[ip, nft, systemctl, CONFIG_BRIDGE, CONFIG_NF_TABLES] |
| Apply | `modules/bridge-l2/install/apply.sh` | Provisions Linux bridge + writes `/etc/nftables.d/selfdef-bridge.conf` |
| Check | `modules/bridge-l2/install/check.sh` | Read-only verifier |
| Uninstall | `modules/bridge-l2/install/uninstall.sh` | Idempotent tear-down |
| Helper lib | `modules/bridge-l2/install/lib.sh` | TOML readers |
| L2 tests | `packaging/test/L2-bridge-l2.bats` | 11 tests |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Provided contracts

| Contract | What downstream modules get |
|---|---|
| `l2-bridge` | The bridge interface name (default `br0`) every inline module can attach to (Suricata AF_PACKET, NFQUEUE attachment) |
| `forward-policy` | The nftables FORWARD chain owned by this module; siblings add jumps into their own chains rather than rewriting the policy |

### Deliverable 2 — Configuration knobs

| Key | Default | Purpose |
|---|---|---|
| `bridge_name` | `"br0"` | Bridge interface name |
| `forward_policy` | `"accept"` | Default FORWARD verdict; tighten to `"drop"` once siblings have populated their jumps |
| `management_iface` | `""` | If set, excluded from bridge enslavement (operator's SSH lifeline) |
| `members` | `[]` | List of physical interfaces to enslave to the bridge |

### Deliverable 3 — nftables ruleset shape

`/etc/nftables.d/selfdef-bridge.conf` declares a `table bridge selfdef`
with a `forward` chain hooking `forward` priority 0. Sibling modules
add to this table via their own ruleset files.

### Deliverable 4 — Required binaries + kernel features

`ip` (iproute2), `nft` (nftables CLI), `systemctl` (for nftables
service reload) — all on the manifest's `requires` list.

`CONFIG_BRIDGE=y` + `CONFIG_NF_TABLES=y` kernel features required.
On Debian 13 / Ubuntu 24 both ship enabled.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Manifest provides l2-bridge + forward-policy contracts | L2 bats test 2 |
| All 3 binaries on requires list | L2 bats test 3 |
| Both kernel features on requires list | L2 bats test 4 |
| 4 install scripts shipped | L2 bats test 5 |
| apply.sh DRY_RUN aware + reads 4 config keys | L2 bats tests 7-9 |
| Writes /etc/nftables.d/selfdef-bridge.conf | L2 bats test 10 |
| Handles unknown profile cleanly (dry-run) | L2 bats test 11 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with phase=pre + binary + kernel-feature requires
2. ✅ install/apply.sh with bridge provisioning + nftables ruleset
3. ✅ install/check.sh + uninstall.sh + lib.sh
4. ✅ L2 bats coverage (11 tests)

## Authorization for Stage-3+ work

This SDD authorizes:
- `forward_policy = "drop"` tightening once siblings populate jumps
- VLAN-aware bridge (currently flat L2)
- Multi-bridge composition for tenant separation
- Inline `forward-policy` jump audit gate (L1) verifying every
  sibling that consumes `forward-policy` actually adds a jump

— End of SDD-039 / MS024 Stage-2.
