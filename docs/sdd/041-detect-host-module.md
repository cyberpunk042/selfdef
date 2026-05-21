# SDD-041 — Detect-host module — the daemon as a first-class module — MS025

> Status: **draft** — Stage-2 architectural spec for the shipped
> `detect-host` module under `modules/detect-host/`. This module is
> the **canonical reference** for the `install.kind = "debian-package"`
> contract documented in `docs/dev/modules.md` — it has NO install
> scripts; the install IS the install of the `selfdef-daemon` Debian
> package.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS025 (catalog
> `backlog/milestones/MS025-detect-host-module-host-class-detection.md`)
> Companions: packaging/test/L2-detect-host.bats (9 tests),
> docs/dev/modules.md § debian-package kind

## Problem

The selfdef daemon (the daemon binary that runs all the
collectors / correlator / responder / signing layers documented in
SDD-001 + SDD-003) IS a first-class module from the module-system's
perspective:
- it provides contracts (event-bus, finding-store, sigma-correlator)
  other modules consume
- it has a versioned manifest
- it's lifecycle-managed by `selfdefctl modules apply` /
  `selfdefctl modules check` like any other module

But its install is fundamentally **the Debian package install**, not
a shell script that renders config + reloads a service. So this module
ships as the canonical reference implementation of the `install.kind
= "debian-package"` contract — proving that contract works end-to-end.

## Operator directive — verbatim (sacrosanct)

> "respect the projects" + "the project is intelligent. the
>  intelligence comes from USING the project"

Translation for MS025: detect-host doesn't reinvent the daemon's
install pipeline — it documents that pipeline AS a module-system
participant. The cataloging exists so operators see the daemon in
`selfdefctl modules list` alongside the other 13 modules.

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/detect-host/module.toml` | install.kind="debian-package", package="selfdef-daemon" |
| Operator pointer | `modules/detect-host/README.md` | Operator-facing pointer to selfdef-daemon docs |
| (no install/ dir) | — | The debian-package install kind ships no shell scripts |
| L2 tests | `packaging/test/L2-detect-host.bats` | 9 tests including "NO install/ dir" assertion |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Debian-package install kind contract

```toml
[install]
kind = "debian-package"
package = "selfdef-daemon"
```

This tells `selfdefctl modules apply` to delegate the actual install
to `apt-get install selfdef-daemon` (or refuse if the package is not
in the apt repos the operator has configured). No shell scripts to
run — the postinst from the .deb does the work.

### Deliverable 2 — Provided contracts

| Contract | What downstream modules get |
|---|---|
| `event-bus` | The selfdef bus — anywhere a module wants to publish events with `consumes = ["event-bus"]` |
| `finding-store` | The hot-store (selfdef-store) holding correlated findings |
| `sigma-correlator` | The Sigma-rule correlator that turns events → findings |

These contracts are what every other module assumes is available when
they declare consumes on them.

### Deliverable 3 — Required binary

`systemctl` — needed by `selfdefctl modules check detect-host` to
ascertain the daemon's systemd state.

### Deliverable 4 — Cross-reference: selfdef-daemon crate

The Debian package is built from `crates/selfdef-daemon/`. The L2
bats suite cross-checks that the crate exists in the workspace
(otherwise the manifest would point at a phantom package).

### Deliverable 5 — Operator-facing surface

| Verb | Effect |
|---|---|
| `selfdefctl modules list` | Shows `detect-host` alongside the 13 other modules |
| `selfdefctl modules info detect-host` | Shows the manifest's provides + consumes + the daemon's runtime status |
| `selfdefctl modules check detect-host` | Verifies the selfdef-daemon Debian package is installed AND `selfdefd.service` is active |
| `selfdefctl modules apply` (with `[modules.detect-host]` active) | Delegates to `apt-get install selfdef-daemon` |
| `selfdefctl modules uninstall detect-host` | (Future) — currently the operator removes via `apt purge selfdef-daemon` |

## Production-readiness gates

| Gate | Verification |
|---|---|
| install.kind = debian-package (not script) | L2 bats test 2 |
| install.package = selfdef-daemon | L2 bats test 3 |
| Provides 3 contracts | L2 bats test 4 |
| Requires systemctl binary | L2 bats test 5 |
| README.md ships | L2 bats test 6 |
| NO install/ dir (debian-package kind has no scripts) | L2 bats test 7 |
| Referenced selfdef-daemon crate exists | L2 bats test 8 |
| docs/dev/modules.md exists (the contract this module exemplifies) | L2 bats test 9 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest declaring install.kind = "debian-package" +
   package = "selfdef-daemon" + 3 provides contracts
2. ✅ README.md operator pointer
3. ✅ L2 bats coverage (9 tests including the "NO install/ dir"
   negative-existence assertion that locks the kind = debian-package
   contract)

## Authorization for Stage-3+ work

This SDD authorizes:

- `selfdefctl modules uninstall detect-host` Stage-3 implementation
  (currently the operator uses `apt purge`)
- A debian-package-kind L3 nspawn boot-replay test that installs
  selfdef-daemon from a local apt repo + verifies the module
  becomes visible in `selfdefctl modules list`
- Other daemons that ship as `kind = "debian-package"` modules
  (e.g. an MS018-related `tailscale` module for the `tailscale`
  profile) following this same pattern

— End of SDD-041 / MS025 Stage-2.
