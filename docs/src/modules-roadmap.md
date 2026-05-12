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
| `integrity-sentinel` | hardening | shipping (v0.1.0) | new | SHA256 baseline of operator-defined policy paths (rules, configs, module manifests, install scripts), with `strict` (fail-closed) and `warn-only` profiles. Baseline format is plain `sha256sum -c`-compatible, so the file is verifiable out-of-band without `selfdefctl`. The paths-to-track file is operator-owned at `/etc/selfdef/integrity-sentinel/paths.txt`. |

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

Every module the roadmap originally named is now in the catalog. Remaining work:

- `vpn-bridge` v0.3.0 (optional): STUN-assisted hole-punching profile. Lower priority now that `tailscale` covers most NAT-traversal cases via DERP fallback.
- `selfdefctl modules uninstall`: destructive op, deferred until after the operator-confirmation UX is wired (probably alongside `panic mode`'s confirm pattern).
- Notifier wiring for `integrity-sentinel` drift: today the module's structured-status surfaces drift to `selfdefctl modules check`; emitting an OCSF event onto the daemon's bus so the existing notifier chain (ntfy / Signal) fires is a separate cross-crate PR.

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
# Single-instance (the normal case):
[modules.detect-host]
[modules.bridge-l2]
[modules.suricata]

# Multi-instance: declare a module twice under different `#instance`
# suffixes. Only allowed for modules that opt in via
# `instanced = true` in their manifest (e.g. `vpn-bridge`).
[modules."vpn-bridge#overlay"]
config = "/etc/selfdef/modules/vpn-bridge.overlay.toml"
[modules."vpn-bridge#publish"]
config = "/etc/selfdef/modules/vpn-bridge.publish.toml"
```

Per-module config files default to `/etc/selfdef/modules/<slug>.toml` for single-instance, or `/etc/selfdef/modules/<slug>.<instance>.toml` when an instance is set. Both forms are exposed to the install scripts via `SELFDEF_<SLUG>_CONFIG`. Each script ends with one JSON line `{"module":"<slug>","status":"ok|skipped|failed","message":"..."}` which the runner aggregates. Defence-in-depth: a script that emits `ok` but exits non-zero is treated as failed; a script that emits status under the wrong slug is rejected outright.

Dependency / conflict declarations in manifests are **slug-level** — depending on `bridge-l2` is satisfied by any active instance. Within one slug, instances run alphabetically.

### Apply phases

A manifest can declare `phase = "pre" | "main" | "post"` (default `"main"`). The runner applies all `pre` modules first, then all `main`, then all `post`. Within each phase, the existing `depends_on` topo sort applies and ties break alphabetically.

`integrity-sentinel` ships in `pre`: a drift detection in `strict` mode halts the apply before any `main`-phase module mutates host state.

Cross-phase dependencies are validated: a module can depend on another module in the same phase or an earlier phase, but **not** a later phase (that would force the resolver to run a later phase first). The resolver rejects this with a clear error.

Each remaining item is one PR. The contract is fixed; modules don't reopen it.
