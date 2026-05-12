# Modules roadmap

Companion to [`modules.md`](./modules.md). Tracks which modules are
absorbed, in progress, or planned. Each module gets its own
implementation PR; this page is the running ledger.

Statuses:

- **shipping** — manifest in `modules/<slug>/`, install scripts work,
  passes `selfdefctl modules check` on a clean host.
- **absorbing** — manifest landed, but install logic still being
  imported (often from [`root-ghostproxy`](https://github.com/cyberpunk042/root-ghostproxy)).
- **designing** — collecting requirements; no manifest yet.
- **planned** — known target; nothing started.

## Current state

| Module        | Category      | Status     | Source                 | Notes |
| ------------- | ------------- | ---------- | ---------------------- | ----- |
| `detect-host` | detection     | shipping   | this repo              | Wraps the existing daemon, collectors, correlator, responder, notifier, store, api. Example manifest, no install scripts (the `.deb` is the install). |
| `suricata`    | network       | shipping   | root-ghostproxy + existing `selfdef-collector-suricata` | Inline IDS — NFQUEUE (`host-ids`, fail-OPEN via `bypass`) or AF_PACKET copy-mode (`opnsense-bridge`, read-only). Depends on `bridge-l2`'s `forward_hook` chain for NFQUEUE attachment. Does **not** own `suricata.yaml`. |
| `polarproxy`  | network       | shipping   | root-ghostproxy        | TLS termination → PCAP-over-IP on tcp/4430. Two profiles: `host-tls-mitm` (NAT-redirects host's TCP/443 to a local PolarProxy listener) and `bridge-tap` (runtime-checked soft dependency on `bridge-l2`). Manages the systemd unit + nftables redirect; does **not** own the PolarProxy binary or the CA. |
| `bridge-l2`   | network       | shipping   | root-ghostproxy        | Transparent L2 bridge (`br0`) + nftables FORWARD policy + management-wifi INPUT-drop. Foundation for the inline modules. Two profiles: `passthrough`, `opnsense-edge`. Install/check/uninstall scripts pass dry-run smoke tests. |
| `vpn-bridge`  | network       | designing  | new                    | OPNsense-to-OPNsense (or host-to-host) WireGuard mesh that survives double-NAT. Either STUN-assisted hole-punching or a relay fallback; both ends behind their own NAT is the headline scenario. |
| `integrity-sentinel` | hardening | planned | root-ghostproxy + new | SHA256 baseline verification for policy artifacts (rules, configs, module manifests themselves). Fail-closed on drift. |

## Out of scope

- **AI-agent safety envelope** (Claude Code / opencode hooks) stays in
  root-ghostproxy. Not a self-defense concern at the host level.
- **Management wifi nftables specifics** stay coupled to `bridge-l2`'s
  install rather than being a standalone module — it's not useful
  without the bridge.

## Ordering

The cleanest absorption order is:

1. `bridge-l2` — every other network module depends on it.
2. `suricata` — biggest user value; we already have the collector half.
3. `polarproxy` — small, mostly install logic.
4. `vpn-bridge` — design + implementation in one go; no prior code to absorb.

Each is one PR. The contract is fixed; modules don't reopen it.
