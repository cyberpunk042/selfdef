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
| `vpn-bridge`  | network       | shipping (v0.2.0) | new             | Three profiles for the double-NAT case: **`relay-via-server`** (your own public WireGuard relay), **`tailscale`** (Tailscale-hosted or self-hosted Headscale), **`cloudflare-tunnel`** (outbound L7 service publishing — different paradigm, not an overlay). Per-profile script files under `install/profiles/<name>.sh` with a documented extension hook for future transports. Decision matrix in the module's README. v0.3.0 may add a STUN hole-punch profile if there's demand beyond what tailscale already solves. |
| `integrity-sentinel` | hardening | planned | root-ghostproxy + new | SHA256 baseline verification for policy artifacts (rules, configs, module manifests themselves). Fail-closed on drift. |

## Out of scope

- **AI-agent safety envelope** (Claude Code / opencode hooks) stays in
  root-ghostproxy. Not a self-defense concern at the host level.
- **Management wifi nftables specifics** stay coupled to `bridge-l2`'s
  install rather than being a standalone module — it's not useful
  without the bridge.

## Ordering

The cleanest absorption order was:

1. `bridge-l2` — every other network module depends on it. ✅ shipped.
2. `suricata` — biggest user value; we already had the collector half. ✅ shipped.
3. `polarproxy` — small, mostly install logic. ✅ shipped.
4. `vpn-bridge` — design + implementation in one go; no prior code to absorb. ✅ shipped (v0.1.0, relay-via-server only).

The four network modules are all in the catalog. Remaining work:

- `vpn-bridge` v0.3.0 (optional): STUN-assisted hole-punching profile. Lower priority now that `tailscale` covers most NAT-traversal cases via DERP fallback.
- Multi-instance host-config syntax (`[modules."vpn-bridge#tunnel"]`) so a single host can run e.g. `relay-via-server` for overlay reachability and `cloudflare-tunnel` for service publishing simultaneously. The lifecycle runner already validates and refuses the `#` form with a clear error pointing at this work; the parser change is the next PR.
- `integrity-sentinel`: still `planned`. SHA256 baseline verification for policy artifacts (rules, configs, module manifests).
- `selfdefctl modules uninstall`: destructive op, deferred until after the operator-confirmation UX is wired (probably alongside `panic mode`'s confirm pattern).

## Lifecycle surface

`selfdefctl modules` now covers both inspection and execution:

| Subcommand | Mutates? | What it does |
| --- | --- | --- |
| `list` | no | Print the catalog (every `module.toml` on disk). |
| `info <slug>` | no | Full manifest for one module. |
| `apply` | yes (each script) | Run every active module's `install/apply.sh` in dependency order. Aggregates structured-status. `--dry-run` propagates `SELFDEF_DRY_RUN=1`. `--only` / `--except` filter the active set. Exit 1 if any module ends `failed`. |
| `check` | no | Run every active module's `install/check.sh` and aggregate. |
| `status` | no | Alias of `check`. |

Active modules are declared in `/etc/selfdef/modules.toml`:

```toml
[modules.detect-host]
[modules.bridge-l2]
[modules.suricata]
[modules.vpn-bridge]
# config = "/etc/selfdef/modules/vpn-bridge.toml"   # default if omitted
```

Per-module config files default to `/etc/selfdef/modules/<slug>.toml` and are exposed to the install scripts via `SELFDEF_<SLUG>_CONFIG`. Each script ends with one JSON line `{"module":"<slug>","status":"ok|skipped|failed","message":"..."}` which the runner aggregates. Defence-in-depth: a script that emits `ok` but exits non-zero is treated as failed; a script that emits status under the wrong slug is rejected outright.

Each remaining item is one PR. The contract is fixed; modules don't reopen it.
