# detect-host

The selfdef host self-defense daemon, packaged as a module.

This module **is** the substrate that every other module feeds into.
When a host enables `detect-host`, the install layer ensures
`selfdef-daemon` (collectors + correlator + responder + notifier +
store + api) is present and running.

## What it provides

- `event-bus` — in-process tokio broadcast bus used by all collectors.
- `finding-store` — SQLite hot store at `/var/lib/selfdef/state.sqlite`.
- `sigma-correlator` — loads rules from `/etc/selfdef/rules/`.

Other modules that want to publish events declare
`consumes = ["event-bus"]` in their manifest. Other modules that
read findings (e.g. a future remote dashboard) declare
`consumes = ["finding-store"]`.

## Install

`install.kind = "debian-package"` — installing the module means installing
the `selfdef-daemon` Debian package, built by `cargo deb -p
selfdef-daemon`. No imperative install scripts.

## Config

Configuration is **not yet** under the module-layer overlay (see
[modules.md § Config layering](../../docs/src/modules.md#config-layering));
it still lives in `/etc/selfdef/selfdef.toml`. Folding it in is M-modules
phase 2.

## Why this module exists as a manifest

Even though it ships no install scripts, it carries the manifest so
that:

1. `selfdefctl modules list` shows it alongside the others.
2. Other modules can `depends_on = ["detect-host"]` to express that
   they have nothing to publish events *to* without it.
3. Future module-aware health checks (`selfdefctl modules status`)
   treat the daemon and the optional modules through the same lens.
