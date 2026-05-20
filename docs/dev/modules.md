# `modules/` contract — operator-activatable modules

selfdef's `modules/` directory holds operator-activatable bundles that
sit on top of the daemon. Each module is a self-contained directory
with a manifest (`module.toml`), installer scripts under `install/`,
and bundled assets under `assets/`. Operators select which modules to
activate via `/etc/selfdef/modules.toml`; `selfdefctl modules apply`
walks the dependency graph and runs each active module's installer in
the right order.

This document is the authoritative contract for module authors. Every
module ships with a `README.md` that explains the module's *operator-
facing* surface; this doc explains the *contract* every module must
honor regardless of what it does.

## `module.toml` schema

Each module has a `module.toml` at the root of its directory.

```toml
name        = "<module-name>"        # required; matches dir name
version     = "0.1.0"                # SemVer; bumped on schema-affecting change
summary     = "<one-line description>"
category    = "detection" | "hardening" | "deception" | "response" | "observability" | ...

# Dependency graph (computed by `selfdefctl modules apply` to determine
# install order).
depends_on  = ["<other-module-name>", ...]    # ordered before this module
conflicts   = ["<other-module-name>", ...]    # mutually exclusive
provides    = ["<symbol>", ...]               # capabilities this module offers
consumes    = ["<symbol>", ...]               # capabilities this module needs
                                              # (resolved against `provides`)

# Host requirements — checked by `selfdefctl modules check` before apply.
requires    = [
    { kind = "binary",         value = "<binary-name>" },     # e.g. systemctl, podman
    { kind = "kernel-feature", value = "CONFIG_<NAME>" },     # in /proc/config.gz
    { kind = "service",        value = "<unit-name>.service" },
    { kind = "package",        value = "<deb-package-name>" },
]

[install]
kind = "script" | "debian-package"
```

## `[install]` kinds

### `kind = "script"` (most modules)

The default + most common. The module ships an `install/` directory:

```
modules/<name>/install/
    apply.sh        # required — idempotent installer; drops files, enables units, reloads
    check.sh        # required — side-effect-free verifier; exit 0 = healthy
    uninstall.sh    # required — reverses apply.sh (manifest-walked per SDD-006 v2)
    lib.sh          # optional — module-local helpers (sourced by the other 3)
```

Contract:

- All three scripts MUST be idempotent. `apply.sh` re-runs are no-ops
  when the desired state is already in place (use file diffs + service
  reload triggers).
- All three scripts MUST honor `SELFDEF_DRY_RUN=1` (preview without
  side effects).
- All three scripts MUST source `module-lib.sh` from the v2 helper
  library (`/usr/share/selfdef/lib/module-lib.sh` at runtime; mirror
  at `packaging/lib/module-lib.sh` in the source tree). The v2 helpers
  provide `run`, `log`, `emit_status`, `module_record_file`,
  `module_clear_manifest`, `toml_get`, and friends.
- `apply.sh` MUST record every file it creates via `module_record_file`.
  `uninstall.sh` walks the recorded manifest (NOT a hand-curated path
  list) to ensure no drift between what `apply` writes and what
  `uninstall` removes. F-2027-024 finding catalogues this as the
  drift-risk every module must address.
- `check.sh` MUST be side-effect-free. Operators run it as a periodic
  health probe; mutating in `check` would defeat the purpose.

Bats coverage convention: every `kind = "script"` module ships at
least one bats test under `modules/<name>/install/tests/` exercising
the apply → check → uninstall round-trip with mocked external binaries.

### `kind = "debian-package"` (one module today: `detect-host`)

A module whose install IS the install of a Debian package. The daemon
itself (`selfdef-daemon`) is the canonical example; the `detect-host`
module declares `kind = "debian-package"` because it's the operator's
trigger for activating the daemon as a module (the daemon is installed
via apt; the module just declares "host has the daemon active").

For `kind = "debian-package"` modules:

- The `install/` directory MAY be omitted entirely (the daemon's
  apt-installed maintainer scripts handle the lifecycle).
- The module's `README.md` MUST explain which Debian package provides
  the runtime + how operators install it.
- `selfdefctl modules check <name>` for a `kind = "debian-package"`
  module verifies the named package is installed via `dpkg -s` and
  the named systemd unit is active (configured via the module's
  `requires` block).

Operators who try to `apply` a `kind = "debian-package"` module on a
host that doesn't have the package get a clear error pointing at the
install path (apt repo URL or .deb release).

## Activation flow

```text
/etc/selfdef/modules.toml          ← operator chooses which modules to activate
  ↓ selfdefctl modules apply
walk depends_on graph (topological sort)
  ↓ for each active module:
  selfdefctl modules check <name>  ← verify requires
  ↓ if check ok:
  apply.sh                          ← install
  module_record_file *              ← manifest tracks every file
  ↓ on every commit / reboot / cron:
  check.sh                          ← side-effect-free probe
  ↓ on operator-driven removal:
  uninstall.sh                      ← reverse apply via manifest walk
```

The "kind = script vs debian-package" branch is at the `apply.sh` step:
script modules run their `apply.sh`; debian-package modules verify the
.deb is installed + active.

## Module catalog (as of 2026-05-20)

The following modules ship in the v0.1 catalog. See each module's
`README.md` for operator-facing detail.

| Module | Kind | Category | Purpose |
|---|---|---|---|
| `agent-guard` | script | hardening | container-internal Tetragon TracingPolicies |
| `bitnet-gpu-inference` | script | observability | 1-bit/ternary model inference on GPU |
| `bridge-l2` | script | hardening | layer-2 transparent bridge |
| `detect-host` | debian-package | detection | the selfdef daemon itself |
| `hardware-tune-cache` | script | observability | SDD-018 hardware-tune cache |
| `integrity-sentinel` | script | hardening | F-2027-024 cross-cutting integrity |
| `observability` | script | observability | Prometheus + Grafana + alerts |
| `polarproxy` | script | observability | TLS inspection |
| `slm-cpu-loop` | script | observability | small language model CPU loop |
| `suricata` | script | detection | Suricata IDS collector |
| `tensor-parallel-inference` | script | observability | tensor parallel inference |
| `tetragon` | script | hardening | Cilium Tetragon eBPF substrate |
| `vpn-bridge` | script | hardening | VPN bridge multi-instance |
| `wasm-aot-cache` | script | observability | WASM AOT compile cache |

## Authoring a new module

1. Create `modules/<name>/` with `module.toml` + `README.md` +
   (for `kind = "script"`) `install/{apply,check,uninstall,lib}.sh`.
2. Wire `module-lib.sh` source line at the top of each shell script:
   `source "${LIB_DIR}/lib.sh"` (the module's local lib.sh sources the
   v2 helpers).
3. Add bats tests under `modules/<name>/install/tests/`.
4. Add a row to the catalog table above.
5. Update `config/modules.toml.example` with the module's commented-out
   entry so operators can uncomment to activate.
6. If the module emits Prometheus metrics, declare
   `provides = ["metrics-endpoint"]` so `observability` picks it up.

## Cross-references

- [`docs/dev/module-helpers.md`](module-helpers.md) — the v2 helper
  library API surface (`run`, `log`, `module_record_file`, etc).
- [`docs/dev/test-contract.md`](test-contract.md) — the bats coverage
  contract every module must honor.
- Per-module `README.md` for operator-facing detail.
- `packaging/lib/module-lib.sh` — the v2 helper library source.
