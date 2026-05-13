# Modules

> Status: **design** (M-modules milestone, contract pass). The contract
> is settled enough to build against. The list of modules currently
> shipping is in [`modules-roadmap.md`](./modules-roadmap.md).

selfdef is a *library of modules* that downstream consumers (other
selfdef hosts, OPNsense appliances, sister projects like
[root-ghostproxy](https://github.com/cyberpunk042/root-ghostproxy))
compose à la carte. A module is a self-contained capability — IDS,
TLS inspection, L2 bridge, host detection daemon, VPN bridge —
discoverable, version-pinned, with a typed config schema and a defined
install hook.

This page is the contract every module must conform to. New modules are
not free-form scripts; they fit this shape so the selector,
configuration layering, and install pipeline can treat them uniformly.

---

## Layout

Every module lives at `modules/<slug>/` in this repository. The slug is
lowercase, dash-separated, globally unique. Directory contents:

```
modules/<slug>/
├── module.toml              # manifest (required)
├── README.md                # human docs (required)
├── config/
│   └── defaults.toml        # config defaults (optional)
├── profiles/
│   ├── <profile-1>.toml     # named preset bundles (optional)
│   └── <profile-2>.toml
├── templates/               # config templates to render (optional)
└── install/
    ├── apply.sh             # idempotent install entry-point
    ├── check.sh             # verifier; exit 0 = OK
    └── uninstall.sh         # rollback
```

Nothing other than `module.toml` and `README.md` is mandatory. A module
that ships pure Rust code in the workspace (e.g. `detect-host`) can omit
`install/` entirely — the install of the underlying `.deb` is the
install of the module.

---

## `module.toml` manifest

```toml
# Identity
name        = "suricata"            # slug — must match directory name
version     = "0.1.0"               # semver, independent from selfdef itself
summary     = "Inline IDS via Suricata"
category    = "network"             # detection | network | hardening | observability

# Dependency graph
depends_on  = ["bridge-l2"]         # other modules required before install
conflicts   = ["suricata-host"]     # mutually exclusive modules

# Capability flags this module provides / consumes. Used for soft
# coupling: a module can declare `consumes = ["pcap-source"]` and any
# enabled module that `provides = ["pcap-source"]` satisfies it.
provides    = ["ids", "eve-json"]
consumes    = []

# System prerequisites (kernel features, binaries, packages). Install
# aborts if not met.
requires    = [
    { kind = "kernel-feature", value = "NETFILTER_XT_MATCH_NFQUEUE" },
    { kind = "binary",         value = "nft" },
    { kind = "package",        value = "suricata" },
]

# How this module gets onto a host.
[install]
kind = "script"                     # script | debian-package | rust-binary
apply = "install/apply.sh"
check = "install/check.sh"
uninstall = "install/uninstall.sh"

# Profiles — named preset bundles the operator can pick.
[profiles]
default = "host-ids"
available = ["host-ids", "opnsense-bridge", "afpacket-copy"]
```

---

## Config layering

Every module has a config namespace. The final config seen by the
module at runtime is the result of layering, in order from lowest to
highest precedence:

1. **Module defaults** — `modules/<slug>/config/defaults.toml`
2. **Profile preset** — `modules/<slug>/profiles/<profile>.toml`,
   selected via the `profile` field in host config (falls back to the
   manifest's `profiles.default` if unset).
3. **Host config** — the `[modules.<slug>]` table in
   `/etc/selfdef/host.toml`.
4. **Environment variables** — `SELFDEF__<SLUG>__<KEY>=value`. Double
   underscores separate dotted keys. Highest precedence so operators
   can override anything without editing a file.

Each layer is a partial; missing keys inherit from the layer below.
This is the same layering rule for every module. Module authors do
not implement their own merging.

The merged config is passed to `install/apply.sh` as a single rendered
TOML on stdin, and committed to `/etc/selfdef/modules/<slug>.toml` for
introspection.

---

## Host config

`/etc/selfdef/host.toml` is the selector. It chooses which modules are
enabled, which profile each runs under, and the per-module overrides:

```toml
# Modules enabled on this host. Order is irrelevant — the resolver
# orders by `depends_on`.
enabled = ["detect-host", "suricata", "vpn-bridge"]

# Per-module config overrides + profile selection.
[modules.suricata]
profile = "opnsense-bridge"
eve_json_path = "/var/log/suricata/eve.json"

[modules.vpn-bridge]
profile = "opnsense-mesh"
peer_endpoint = "203.0.113.10:51820"
```

If a module is in `enabled` but its `depends_on` is not, `selfdefctl
modules apply` fails closed with a clear error. The same applies to
`conflicts` and to unmet `requires`.

### Uninstalling

`selfdefctl modules uninstall` walks active modules in the **inverse**
of apply order — dependents come down before the modules they
depended on, and phases unwind `post → main → pre`. It's destructive
and therefore requires `--confirm <hostname>` matching this host
(same pattern as `selfdefctl panic`); `--dry-run` previews without
the confirm gate. Modules that didn't declare an `install.uninstall`
script are reported as `skipped` rather than failing the run.

---

## Install hooks

`install/apply.sh` is the single source of truth for getting a module
onto a host. Required properties:

- **Idempotent.** Re-running on a host already at the target state
  must be a no-op (or, at worst, re-render config files).
- **Atomic.** Either every change lands or none of them does. On
  failure, the script unwinds whatever partial state it created.
- **`--dry-run` aware.** `SELFDEF_DRY_RUN=1` in the environment must
  cause the script to print intended changes without making them.
- **`--check` aware.** A separate `install/check.sh` returns exit 0
  if the module is correctly installed and configured, non-zero
  otherwise. Used by `selfdefctl modules status`.
- **Speaks structured status.** On completion, emits one JSON line on
  stdout: `{"module": "<slug>", "status": "ok|skipped|failed", "message": "..."}`.
  The selector picks that up and writes it into the audit log.

For modules whose install **is** a Rust crate (e.g. `detect-host`), the
manifest's `install.kind = "rust-binary"` short-circuits the scripts —
the install is just "the `selfdef-daemon` package is present".

---

## Versioning and updates

Each module has its own semver, decoupled from selfdef-daemon's
version. The `selfdefctl modules update` flow (future PR) checks
against the published catalog and proposes a diff. Modules can advance
independently; a host running `suricata 0.3.0` and `vpn-bridge 0.1.5`
is normal.

The catalog itself is `modules/MANIFEST.toml`, generated by
`xtask modules manifest`, which lists every module + its current
version + its content hash.

---

## What stays out of a module

- **Long-lived background daemons that are part of the core detection
  pipeline** (correlator, store, NATS bridge, API server) are *not*
  modules. They're the substrate. Modules feed events into them.
- **AI-agent policy (Claude Code / opencode hooks)** stays in
  `root-ghostproxy`. selfdef's threat model is host self-defense; an
  IDE-policy envelope is a different concern.

---

## What's there today

See [`modules-roadmap.md`](./modules-roadmap.md) for the current
status of each module. Every module the original roadmap named now
ships as a manifested catalog entry: `detect-host`, `bridge-l2`,
`suricata`, `polarproxy`, `vpn-bridge`, `integrity-sentinel`,
`tetragon`, `agent-guard`, `observability`. The roadmap doc is
the canonical inventory.
