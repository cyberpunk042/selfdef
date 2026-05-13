# SDD-002 — Defaults that work out of the box

> Status: draft
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-004, F-2026-018, F-2026-020

## Problem

A clean Debian install of selfdef with the three new modules
(`tetragon`, `integrity-sentinel`, `observability`) and the
existing detect-host substrate currently does **nothing
operator-visible** without manual config. The package's
postinst (`packaging/debian/postinst:34-40`) drops the example
config at `/etc/selfdef/selfdef.toml`, and the example config
defaults *every* collector to `enabled = false`, the API to
`enabled = false`, and ships every module-emission path
commented out.

The two failure modes are symmetric:

- **Module side**: `modules/integrity-sentinel/profiles/strict.toml`
  ships `event_stream_path` commented out
  (`F-2026-018`). Even a perfect daemon-side config wouldn't
  see drift events because the module doesn't emit them.
- **Daemon side**: `selfdef-config EventstreamConfig::default`
  ships `paths = []`; `ApiConfig::default` ships
  `enabled = false`, `tcp_addr = ""`
  (`F-2026-004`). Even a perfect module-side config wouldn't
  reach a notifier because the daemon doesn't ingest the
  path or expose the metrics endpoint.

Plus the cross-cutting "**there's no bundled template for the
two ends to align**" finding (`F-2026-020`).

The audit's integration document (`docs/review/40-integration-audit.md`)
walked four flows that *should* work out of the box and found
that none of them do without operator-side bridging the
documentation doesn't surface in a single place.

## Goals

1. An operator who installs the .deb, activates the three new
   modules in `/etc/selfdef/modules.toml`, and starts
   `selfdefd.service` gets, with no further editing:
   - drift events from `integrity-sentinel` flowing to the
     notifier chain,
   - Tetragon events flowing through the daemon's bus to the
     store,
   - the `/metrics` endpoint scrapeable by Prometheus over a
     UNIX socket (zero-config local) or a documented TCP
     setup.
2. The operator can deviate from any default via the same
   config file without breaking discoverability.
3. The relationship between module-side defaults and
   daemon-side defaults is captured in **one place** — a
   bundled `selfdef.toml` template paired with the three
   modules' default profile files — rather than in prose
   spread across multiple READMEs.
4. The "safe by default" property of the daemon (no API on a
   public port, no destructive actions enabled, no secrets
   leaked) is preserved.

## Non-goals

- Removing the dry-run default on the responder. `dry_run =
  true` is the right safe default and stays.
- Auto-installing Tetragon. The `tetragon` module still
  refuses to apply if the `tetragon` binary isn't on PATH.
  The operator owns the install.
- Auto-installing Prometheus or Grafana. The `observability`
  module still configures, not installs.
- Schema bump.
- A new config file format. Everything stays in TOML where it
  already is.
- Solving multi-host out of the box. NATS bridge stays
  opt-in.

## Glossary

- **postinst defaults** — what's true on a fresh install
  immediately after `apt install selfdef-daemon` finishes.
- **profile-shipped defaults** — what's true after the
  operator activates a module in `modules.toml` but hasn't
  edited any per-module config.
- **bridging the two ends** — making sure the daemon's
  `selfdef.toml` defaults align with the modules' profile
  defaults so they cooperate without operator intervention.

## Current state

### Daemon defaults

`crates/selfdef-config/src/lib.rs` reports the following
defaults (paraphrased):

- `[bus]` — backend `inproc`, capacity 4096.
- `[store]` — `hot_path = /var/lib/selfdef/state.sqlite`,
  `hot_retention_days = 30` (dead knob per F-2026-016, but
  exposed).
- `[collectors.*].enabled = false` for every collector
  (auditd, journald, tetragon, suricata, canary, eventstream,
  ebpf).
- `[collectors.eventstream].paths = []`.
- `[collectors.tetragon].input_path =
  /var/log/tetragon/events.json`.
- `[correlator] rules_dir = /etc/selfdef/rules`,
  `hot_reload = true`.
- `[notifier] channels = ["ntfy"]`, both channel configs
  empty.
- `[responder] dry_run = true`, `allowed_actions = ["notify"]`.
- `[api] enabled = false`, `unix_socket = /run/selfdef.sock`,
  `tcp_addr = ""`.

The postinst drops this config at
`/etc/selfdef/selfdef.toml` and does **not** start the
service.

### Module-side defaults

- `tetragon` (`modules/tetragon/profiles/default.toml`):
  `event_log_path = /var/log/tetragon/events.json`,
  `policy_dir = /etc/tetragon/tetragon.tp.d`,
  `metrics_address = localhost:2112`.
- `integrity-sentinel` (`modules/integrity-sentinel/profiles/strict.toml`):
  `paths_file`, `baseline_path`, `on_missing`. The
  `event_stream_path = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"`
  is **commented out** so emission is off by default.
- `observability` (`modules/observability/profiles/bundled.toml`):
  `scrape_targets = "localhost:2112, localhost:8443"` —
  expects Tetragon's metrics on 2112 and selfdef's `/metrics`
  on 8443.

### The mismatches

| Where the value lives | Daemon expects | Modules ship | Result |
| --- | --- | --- | --- |
| eventstream path | `paths = []` | integrity-sentinel writes `…/integrity-sentinel.jsonl` (when uncommented) | nothing tails the file |
| API bind | `tcp_addr = ""`, `enabled = false` | observability scrapes `localhost:8443` | scrape target unreachable |
| Tetragon ingest | `[collectors.tetragon].enabled = false` | tetragon module writes events.json | events stranded on disk |
| Drift emission | (n/a) | `event_stream_path` commented out | no emission ever happens |

## Design alternatives considered

### Alternative A — Daemon defaults flip to "ready for the modules"

Change `selfdef-config` defaults so that:
- `[collectors.tetragon].enabled = true`,
  `[collectors.eventstream].enabled = true`.
- `[collectors.eventstream].paths` includes the
  `integrity-sentinel` JSONL path by default.
- `[api].enabled = true`, `tcp_addr = "127.0.0.1:8443"`.

**Pros**

- Modules just work after install + activation.
- One place to change (Rust defaults), one place to read
  (the example config).

**Cons**

- Breaks the "safe by default" property: collectors run
  whether or not the modules that need them are active.
  Resource cost on hosts that aren't using the AI-machine
  track.
- Couples daemon defaults to module assumptions. If a
  future module wants to write a JSONL to a different
  path, the daemon defaults need to learn about it too.
  Tight coupling.
- Surprises operators who installed the .deb before the
  modules existed.

### Alternative B — Postinst writes a richer selfdef.toml

Keep the Rust-level defaults conservative ("everything off"),
but ship a fuller `selfdef.toml.example` and have the
postinst (`packaging/debian/postinst`) drop *that* at
`/etc/selfdef/selfdef.toml` only on first install. The
example would have the AI-machine track enablement
**commented in** so a `selfdefctl modules apply` of the three
modules just works.

**Pros**

- Rust defaults stay defensive.
- The "out of the box" experience is documented in one file
  the operator already opens.
- Postinst already drops the example; the change is to its
  content, not its behaviour.

**Cons**

- Two sources of truth: Rust defaults (conservative) and
  postinst-shipped config (operator-friendly). If they
  drift, a `selfdefd` started without a config behaves
  differently from `selfdefd` started with the
  postinst-shipped config.
- Operators who delete `/etc/selfdef/selfdef.toml` to
  "start fresh" get the conservative behaviour without
  warning.

### Alternative C — Module-side dependency declarations

Have each module's manifest declare *what daemon-side knobs
it needs*. `selfdefctl modules apply` would then check the
daemon config and either warn or auto-bridge.

For example, `tetragon`'s manifest could carry:
```toml
[daemon_requires]
collectors.tetragon.enabled = true
collectors.tetragon.input_path = "/var/log/tetragon/events.json"
```

`integrity-sentinel`'s manifest could carry (when emission is
enabled):
```toml
[daemon_requires]
collectors.eventstream.enabled = true
collectors.eventstream.paths = ["${event_stream_path}"]
```

`selfdefctl modules apply` either (a) refuses to apply unless
the daemon side already matches, or (b) prints a one-line
diff "you need this in selfdef.toml" plus the snippet.

**Pros**

- Each module declares its own requirements; daemon defaults
  stay conservative.
- The bridge is documented in code, not prose.
- Operators get a precise "add this snippet" message.
- Future modules don't require any daemon-side change.

**Cons**

- New manifest field. Schema, validation, tests.
- Doesn't *auto-fix* selfdef.toml — the operator still has
  to copy-paste. Less magic than A.
- The auto-fix variant (selfdefctl writes to selfdef.toml)
  would require a TOML editor that preserves comments — not
  in the current code.

### Alternative D — Bundled profile sets (recommended)

Ship a small set of named **bundled profiles** for the
typical deployments:

- `bundle/host-baseline.toml` — detect-host alone.
- `bundle/ai-machine.toml` — tetragon + agent-guard +
  observability + integrity-sentinel.
- `bundle/network-edge.toml` — bridge-l2 + suricata +
  polarproxy.

Each bundle is a single TOML file that, when used via
`selfdefctl modules apply --bundle ai-machine`, sets up:

- The host's `modules.toml` (writing the right `[modules.X]`
  blocks).
- A drop-in `/etc/selfdef/selfdef.toml.d/<bundle>.conf`
  with the daemon-side enablements that bundle needs.

The Rust defaults stay defensive. Operators who want to opt
in pick a bundle. The relationship between module-side
defaults and daemon-side defaults is captured once per
bundle.

**Pros**

- Operators with a named workload (an AI machine, a network
  edge box, a baseline detector) get a single command to
  enable the whole thing.
- Daemon defaults stay safe.
- New bundles compose without churning existing ones.
- Drop-in directory pattern is operator-familiar (matches
  systemd's drop-in conventions).
- A `selfdefctl modules show-bundle ai-machine` reveals
  exactly what would be written.

**Cons**

- Largest implementation surface of the four.
- Introduces a new lifecycle verb (`apply --bundle ...`) and
  a new config-merge surface (drop-in directory).
- Three pieces of state to keep in sync: the bundle file,
  the per-module profiles it activates, the daemon-side
  drop-in it writes.

## Recommended design

A composition of **Alternative B + Alternative C**.

- Take from B: ship a richer `selfdef.toml.example` whose
  commented-out blocks for the AI-machine track are obvious
  and uncomment-able with copy-paste.
- Take from C: add a `[daemon_requires]` section to each
  module's `module.toml`. Run a validator at
  `selfdefctl modules apply` time. The validator does **not
  edit** `selfdef.toml`; it diff-prints the missing
  daemon-side snippet and refuses to proceed unless either
  (a) the daemon config matches, or (b) the operator passes
  `--ignore-daemon-requires` (with a logged warning).

Why this composition rather than D:

- The Rust defaults stay conservative (B preserves "safe by
  default").
- The bridge between module defaults and daemon defaults is
  declarative (C, the manifest field) and shipped per module.
- No new lifecycle verb. `selfdefctl modules apply` already
  exists; the validator is one new code path.
- No new config-merge surface. The operator still edits
  `selfdef.toml` directly; the validator just tells them
  *exactly* what to add.
- The bundle concept can land later as syntactic sugar over
  the same mechanism, without touching the daemon defaults
  again.

## Detailed design

### D-1 — `[daemon_requires]` in `module.toml`

Add a new optional section to module manifests. Schema:

```toml
[daemon_requires]
# Each entry: a key-path under `selfdef.toml` and the
# expected value. Values are scalars or arrays of scalars.
# Variable substitution is supported via `${<config-key>}`
# referencing the same module's host config.

"collectors.tetragon.enabled" = true
"collectors.tetragon.input_path" = "${event_log_path}"

# Multi-valued (arrays of strings) — interpreted as
# set-inclusion: the daemon's actual array must contain every
# element here. Other entries in the daemon's array are fine.
"collectors.eventstream.paths" = ["${event_stream_path}"]
```

Two helper extensions to `selfdef-cli/src/modules.rs`:

- `ModuleManifest` deserialization grows an optional
  `daemon_requires: BTreeMap<String, DaemonRequirement>`.
- A new pre-apply check, `check_daemon_requires`, reads
  `/etc/selfdef/selfdef.toml` and the active module's host
  config, expands `${...}` references, and either passes,
  produces a snippet-diff, or refuses to apply.

The validator runs **before** any apply.sh fires. Apply
order:
1. Resolve catalog + host config (already done).
2. Topo sort by phase + deps (already done).
3. **NEW**: for every active module, call
   `check_daemon_requires`. Aggregate any failures.
4. If failures and not `--ignore-daemon-requires`: print a
   single diff-style block, exit 2.
5. Otherwise: continue as today.

### D-2 — Snippet rendering

When the validator finds a missing key it produces a
copy-pasteable TOML block. Example output:

```
selfdefctl: module `tetragon` requires daemon-side config not present
in /etc/selfdef/selfdef.toml. Add the following block and re-run apply:

  [collectors.tetragon]
  enabled    = true
  input_path = "/var/log/tetragon/events.json"
  read_from  = "end"

selfdefctl: module `integrity-sentinel` requires daemon-side config not present:

  [collectors.eventstream]
  enabled = true
  paths   = ["/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"]

Re-run with --ignore-daemon-requires to skip this check.
```

The snippet is built from the manifest's `[daemon_requires]`
section. Comments / context come from a per-key template
table held in `selfdef-cli`. (No new YAML / JSON; the
template is a small Rust constant.)

### D-3 — Profile defaults that emit by default

The Phase-1 audit flagged the
`integrity-sentinel/profiles/strict.toml`
`event_stream_path` commenting (F-2026-018) as a defaults
problem. Decision: **uncomment it** in `strict.toml` and in
`warn-only.toml`. Default value:

```toml
event_stream_path = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"
```

The default makes emission live, and the new
`[daemon_requires]` check will surface to the operator that
the daemon needs the matching `[collectors.eventstream]`
block. Without operator action the apply refuses cleanly
rather than silently producing inert state.

### D-4 — `selfdef.toml.example` polish

Three changes to `config/selfdef.toml.example`:

- The `[collectors.tetragon]` block grows a comment pointing
  at the `tetragon` module README and naming the inverse
  failure mode (don't use `[collectors.eventstream]` for
  Tetragon).
- The `[collectors.eventstream]` block grows an example of
  the integrity-sentinel JSONL path commented in, with a
  reference to the relevant module.
- The `[api]` block gains a "to make `observability` work
  out of the box" comment block showing how to enable the
  TCP transport, bind to localhost, and point Prometheus at
  a bearer token.

No changes to Rust-level defaults; the example file alone
covers operator discovery.

### D-5 — `selfdefctl modules show-requires`

New read-only subcommand:

```
selfdefctl modules show-requires [--module <slug>] [--all]
```

Without args, lists every active module's `[daemon_requires]`
section in the same snippet form. With `--module <slug>`
just that one. With `--all` even inactive modules in the
catalog.

This lets an operator preview the daemon-side burden of a
module *before* activating it. Falls out of D-1 / D-2
naturally.

## Test plan (implementation PR must satisfy)

1. Unit tests in `selfdef-cli/src/modules.rs`:
   - Manifest with `[daemon_requires]` deserializes.
   - `${...}` substitution resolves against the host config.
   - `check_daemon_requires` returns a structured diff when
     a required key is absent, when a scalar value is wrong,
     when an array doesn't contain the expected element.
   - `check_daemon_requires` passes silently when everything
     matches.
2. Integration test `tests/cli_modules_apply_daemon_requires.rs`:
   - Hermetic fixture with a stub catalog declaring
     `[daemon_requires]`, an empty `selfdef.toml`, and an
     active module.
   - Verify `selfdefctl modules apply` exits 2 with the
     expected diff.
   - Verify `--ignore-daemon-requires` allows apply to
     proceed and logs a warning.
3. Integration test for the integrity-sentinel flow:
   - With `event_stream_path` uncommented (the new default),
     a daemon configured with the matching collector path
     receives drift events on the bus.
   - With the daemon config NOT matched,
     `selfdefctl modules apply` refuses, printing the right
     snippet.
4. `selfdefctl modules show-requires` subcommand test.

## Rollout / migration

- The `[daemon_requires]` field is opt-in per manifest. Old
  modules without the field skip the new check entirely.
- The integrity-sentinel profile change (D-3) is a default
  change. Existing deployments that *deliberately* had
  emission off and used the default profile see a check
  failure on next apply, telling them to either uncomment
  the daemon-side config or set
  `event_stream_path = ""` in their host config to opt out.
  Migration note in CHANGELOG.
- `selfdef.toml.example` is touched only on first install
  (the postinst checks for an existing
  `/etc/selfdef/selfdef.toml` before copying). Existing
  hosts are unaffected.
- No daemon-binary changes are required for D-1..D-5; this
  is entirely a `selfdef-cli` + manifests + docs change.

## Risks

- **R-1 — apply now refuses where it used to succeed.**
  Mitigated by the `--ignore-daemon-requires` flag and the
  CHANGELOG migration note. The strict default is intentional
  (loud over silent).
- **R-2 — substitution syntax (`${...}`) is yet another
  mini-DSL.** Mitigated by keeping it deliberately small:
  only same-module config keys, no nested expressions, no
  string concatenation. Documented in `docs/sdd/000-charter.md`
  as a constraint.
- **R-3 — Operators who don't read the snippet output.**
  Mitigated by exit code 2 + a single block of output, not
  scrolling logs. Future enhancement: a `--write-snippets <dir>`
  flag that drops the snippets as `/etc/selfdef/selfdef.toml.d/`
  drop-in files for operator review.

## Open questions

- **Q-A** — Drop-in support in `selfdef-config`. The
  conservative answer is "no, the snippet goes in
  `/etc/selfdef/selfdef.toml`". A future drop-in directory
  (matching systemd's pattern) would let
  `--write-snippets` mode produce non-clobbering files.
  Worth a separate SDD if it gains traction.
- **Q-B** — Does `[daemon_requires]` need to support
  *removal* (`enabled = false` precludes other defaults)?
  Not for v1.
- **Q-C** — `selfdefctl modules apply --auto-fix` that
  rewrites `selfdef.toml` directly. Tempting but requires a
  comment-preserving TOML editor. Out of scope.
- **Q-D** — Should the validator run on every `selfdefctl
  modules check` too? Default yes — `check` is read-only and
  it's strictly better to surface daemon-config drift before
  apply.

## Appendix — why not bundles (Alternative D)

Bundles (a `bundle/ai-machine.toml` that activates three
modules and writes a `selfdef.toml.d/` drop-in) are the
"easiest UX" answer but introduce three new state shapes
(bundle files, drop-in directory, the contract between
them) for a problem the manifest-level `[daemon_requires]`
solves with one new state shape (the manifest field) plus
operator discipline. We can ship bundles later as syntactic
sugar over the manifest-level contract without revising it.
