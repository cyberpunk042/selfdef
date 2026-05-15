# SDD-003 — vpn-bridge multi-instance honesty

> Status: implemented
> Owner: audit team
> Last updated: 2026-05-13
> Closes findings: F-2026-005

## Implementation status

Shipped in the SDD-003 implementation PR.

- **D-1 — ProfileSpec details**: `ProfileSpec` in
  `crates/selfdef-cli/src/modules.rs` gained a `details:
  BTreeMap<String, ProfileDetails>` field with optional
  `instanced` per profile, plus a `ProfileSpec::profile_instanced`
  helper that falls back to the module-level default.
- **D-2 — Resolver gate**: `resolve_active` now reads each
  instance's per-module config (parsing just the `profile = ...`
  line), looks up the profile's `instanced` capability, and
  refuses any `slug#instance` host-config key when the profile
  is declared `instanced = false`. Falls back to the manifest's
  default profile if the per-instance config can't be parsed.
- **D-3 — Dispatcher env**: `run_one` passes
  `SELFDEF_INSTANCE_ID=<inst>` into the spawned bash process
  whenever `active.instance.is_some()`. Absent for the legacy
  single-instance shape.
- **D-4 — Profile scripts**: `relay-via-server.sh` derives
  per-instance defaults from `${SELFDEF_INSTANCE_ID}`
  (`selfdef-<inst>` iface, `selfdef_vpn_bridge_<inst>` nftables
  table, `/etc/nftables.d/selfdef-vpn-bridge-<inst>.conf` state
  file). Legacy single-instance defaults are unchanged when the
  env var is absent. `tailscale.sh` and `cloudflare-tunnel.sh`
  `die` defence-in-depth at the top of `profile_apply` /
  `profile_uninstall` when `SELFDEF_INSTANCE_ID` is set.
- **D-5 — Manifest + docs**: `modules/vpn-bridge/module.toml`
  carries `[profiles.details.relay-via-server] instanced = true`,
  `[profiles.details.tailscale] instanced = false`, and
  `[profiles.details.cloudflare-tunnel] instanced = false`. The
  README's pre-SDD-003 caveat block is rewritten into a
  "Multi-instance support" section with the capability table,
  per-instance naming convention, and migration notes.

Tests:
- Unit (`crates/selfdef-cli/src/modules.rs`):
  `profile_instanced_falls_back_to_module_default_when_unset`,
  `profile_instanced_per_profile_override_wins`,
  `resolver_rejects_instance_for_singleton_profile`,
  `resolver_accepts_instance_for_multi_instance_profile`,
  `resolver_falls_back_to_default_profile_when_config_missing`.
- Integration
  (`crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs`):
  `relay_apply_with_instance_id_uses_per_instance_iface`,
  `relay_apply_without_instance_id_keeps_legacy_wg0_defaults`,
  `tailscale_apply_refuses_when_instance_id_is_set`,
  `cloudflare_apply_refuses_when_instance_id_is_set`,
  `cli_resolver_refuses_singleton_profile_with_instance_suffix`.

## Problem

`modules/vpn-bridge/module.toml` declares `instanced = true`,
which signals to `selfdefctl modules apply` that the host can
activate multiple instances under different
`[modules."vpn-bridge#<instance>"]` blocks. The resolver
honours this: it accepts the suffix syntax, assigns each
instance its own per-module config path under
`/etc/selfdef/modules/vpn-bridge.<instance>.toml`, and runs
each instance's apply.sh in turn.

The three shipped profile scripts (`relay-via-server.sh`,
`tailscale.sh`, `cloudflare-tunnel.sh`) **do not honour the
instance suffix**. They write to instance-shared paths:

- `relay-via-server.sh:26-28` —
  `wg_conf = /etc/wireguard/selfdef0.conf` (via
  `${iface}` defaulting to `selfdef0` — operator can override
  per instance, but defaults collide) and
  `nft_path = /etc/nftables.d/selfdef-vpn-bridge.conf`
  (no per-instance variant).
- `tailscale.sh:42` — operates on the singleton
  `tailscaled.service`. Tailscale is fundamentally one
  daemon per host (kernel TUN device, `/var/lib/tailscale`
  state). Two tailscale instances on one host is not a
  thing.
- `cloudflare-tunnel.sh:55-65` — `cloudflared service install`
  writes a singleton `/etc/systemd/system/cloudflared.service`.
  Two cloudflared instances need custom per-instance unit
  files, which the profile script doesn't generate.

The manifest's `instanced = true` is a **lie** by surface.
Two `vpn-bridge#a` + `vpn-bridge#b` applications:

- with relay-via-server: silently overwrite the same WG
  config and the same nftables file. Whichever instance ran
  last wins; the other is partially-applied state on disk
  with no daemon awareness.
- with tailscale: silently re-apply the same singleton
  service. Symmetric — they don't conflict but they also
  don't multi-instance anything.
- with cloudflare-tunnel: the second `cloudflared service
  install` clobbers the first.

The audit's M-008 (Phase 1, ledger row F-2026-005) flagged
this as a blocker because the manifest promises a feature
the implementation silently corrupts state to deliver.

## Goals

1. The manifest's multi-instance contract reflects what the
   profiles actually support. Operators reading the manifest
   know what's safe to declare.
2. Profiles that can be multi-instance (`relay-via-server`)
   parameterise every state path by instance id.
3. Profiles that cannot be multi-instance (`tailscale`,
   `cloudflare-tunnel`) refuse cleanly when an instance
   suffix is passed.
4. `selfdefctl modules apply` produces a clear error before
   running any apply.sh when the operator's multi-instance
   intent doesn't match the profile's capability.
5. The fix lands without breaking single-instance deployments
   (the common case today).

## Non-goals

- A general per-profile manifest feature beyond what
  vpn-bridge needs. If `cloudflare-tunnel` instances are
  later made multi-instance via per-instance systemd unit
  generation, that's a future SDD.
- Renaming the module or splitting it into three modules
  (`vpn-bridge-relay`, `vpn-bridge-tailscale`,
  `vpn-bridge-cloudflare`). That refactor has merit but is
  much larger scope than closing F-2026-005.
- Migrating existing single-instance deployments. They keep
  working with no operator action.

## Glossary

- **instance id** — the suffix after `#` in a host-config
  key. `[modules."vpn-bridge#publish"]` → instance id
  `publish`. Single-instance modules have instance id
  `None`.
- **per-profile multi-instance** — the property that one
  *profile* of one *module* supports running multiple
  instances simultaneously. Distinct from module-level
  `instanced`.
- **state path** — any filesystem path or service-manager
  resource (systemd unit, nftables table) the apply script
  reads or writes.

## Current state

### vpn-bridge manifest

`modules/vpn-bridge/module.toml`:

```toml
instanced = true
```

Plus `[profiles].available = ["relay-via-server", "tailscale",
"cloudflare-tunnel"]`. No declaration of which profiles
support multi-instance.

### Resolver behaviour

`crates/selfdef-cli/src/modules.rs:404-435` (the
`resolve_active` function) honours `instanced` and:

- Accepts `slug#instance` host-config keys.
- Constructs a per-instance config path (`vpn-bridge.<inst>.toml`).
- Refuses to mix flat (`[modules.vpn-bridge]`) and instanced
  (`[modules."vpn-bridge#a"]`) keys for the same slug.
- Iterates each instance in turn calling its apply.sh.

The resolver does **not** know which profile each instance
will resolve to; that's read inside apply.sh from the
per-instance config file.

### Per-instance config passing

`crates/selfdef-cli/src/modules.rs:737-739`:

```rust
let mut cmd = Command::new("bash");
cmd.arg(&script)
    .env(env_var_for_config(&active.slug), &active.config_path)
    ...
```

The script gets `SELFDEF_VPN_BRIDGE_CONFIG` pointing at the
per-instance config file. **No instance-id env var is
passed.** The script can recover the instance id by parsing
the config filename (`vpn-bridge.<inst>.toml`) but doesn't
today.

### Profile script paths (relay-via-server)

`modules/vpn-bridge/install/profiles/relay-via-server.sh`:

- `iface = ${SELFDEF_VPN_BRIDGE_WG_IFACE:-selfdef0}`
- `wg_conf = /etc/wireguard/${iface}.conf`
- `nft_path = ${SELFDEF_VPN_BRIDGE_NFT_PATH:-/etc/nftables.d/selfdef-vpn-bridge.conf}`
- service: `wg-quick@${iface}.service`

If operator-defaulted, every instance uses `iface = selfdef0`
and `nft_path = /etc/nftables.d/selfdef-vpn-bridge.conf`. Two
instances collide on both.

### Profile script paths (tailscale)

`modules/vpn-bridge/install/profiles/tailscale.sh`:

- service: `tailscaled.service` (hard-coded).
- state: `/var/lib/tailscale` (managed by the
  tailscaled binary, not the script — but it's a singleton).

No instance parameterisation is possible without running a
second tailscaled binary in a different state dir. Out of
scope for this module.

### Profile script paths (cloudflare-tunnel)

`modules/vpn-bridge/install/profiles/cloudflare-tunnel.sh`:

- service: `cloudflared.service` (installed by `cloudflared
  service install`).
- state: `/etc/cloudflared/`.

Same as tailscale — the upstream's service-install command
writes singleton paths. Multi-instance is possible but
non-trivial (custom unit per instance + per-instance
state dir).

## Design alternatives considered

### Alternative A — Demote `instanced` to `false`

Change `modules/vpn-bridge/module.toml` from
`instanced = true` to `instanced = false`. The resolver
rejects any `vpn-bridge#<instance>` host-config key with
"module not declared `instanced = true`". Document the
limitation in the README.

**Pros**

- One-line manifest change.
- The manifest stops lying.
- Existing single-instance deployments unaffected.

**Cons**

- Operators who *were* using the multi-instance syntax (even
  if it was silently broken) now get a hard refusal. Need a
  migration note.
- Forecloses on per-profile multi-instance entirely. The
  relay-via-server profile, which *could* be made
  multi-instance cleanly, would no longer be allowed to.

### Alternative B — Per-profile `[profiles.<name>] instanced` field

Extend the manifest schema:

```toml
[profiles]
default = "relay-via-server"
available = ["relay-via-server", "tailscale", "cloudflare-tunnel"]

[profiles.relay-via-server]
instanced = true

[profiles.tailscale]
instanced = false

[profiles.cloudflare-tunnel]
instanced = false
```

`module.toml` top-level `instanced = true` becomes
"at least one profile is instance-capable". The resolver
checks that **the instance's chosen profile** is instance-capable.
Per-profile defaults table is also a place to colocate
profile metadata.

The dispatcher (`install/apply.sh`) passes an instance id env
var (`SELFDEF_INSTANCE_ID`) to the profile script. Profiles
that are `instanced = true` use it to parameterise state
paths. Profiles that are `instanced = false` refuse to run
when it's set (in addition to the resolver's pre-check, as
defence-in-depth).

**Pros**

- Honest contract per profile.
- Future modules with mixed-instance profiles get the same
  facility.
- Single-instance deployments keep working without change.
- Multi-instance with relay-via-server becomes a real
  feature, not a nominal one.

**Cons**

- Manifest schema change. `selfdef-cli`'s `ModuleManifest`
  struct grows a nested optional map.
- The validator + resolver both need updates.
- Three changes land together: manifest schema, dispatcher
  env var, profile-script parameterisation.

### Alternative C — Resolver gates on profile, dispatcher stays the same

Same per-profile capability as B, but instead of an
`SELFDEF_INSTANCE_ID` env var, the dispatcher continues to
pass only `SELFDEF_VPN_BRIDGE_CONFIG`. Profile scripts that
need an instance id derive it from the config filename
(`basename "${SELFDEF_VPN_BRIDGE_CONFIG}" | sed 's/^vpn-bridge\.//;s/\.toml$//'`)
or, more brittly, from the operator passing it explicitly in
the config file:

```toml
# /etc/selfdef/modules/vpn-bridge.publish.toml
profile = "relay-via-server"
instance_id = "publish"
```

**Pros**

- No new env-var contract between the CLI dispatcher and
  scripts. Smaller surface change.

**Cons**

- Asks the operator to keep filename + content in sync.
- Filename parsing in bash is fragile.
- Future modules' profile scripts can't rely on a stable
  env-var convention.

### Alternative D — Split into three modules

`modules/vpn-bridge-relay`, `modules/vpn-bridge-tailscale`,
`modules/vpn-bridge-cloudflare`. Each is its own catalog
entry. Multi-instance is then "activate
`vpn-bridge-relay#publish` and `vpn-bridge-relay#tunnel`" —
the catalog stays `instanced = true` only for the relay
variant; the other two declare `instanced = false`.

**Pros**

- Cleanest separation of concerns. No per-profile manifest
  field needed.
- Catalog entries map 1:1 to upstream tool families
  (wireguard / tailscale / cloudflared).
- Each module's README focuses on one workload.

**Cons**

- Three modules to maintain instead of one.
- Migration: existing hosts have
  `[modules.vpn-bridge]` configs that wouldn't match the
  new module names. Backward-compat shim or rename
  documentation.
- The shared lib.sh, profile detection logic, and config
  layout would be duplicated across three modules — exactly
  the kind of duplication F-2026-081 (the SDD-debt finding
  on shared module helpers) wants to *reduce*.
- Larger scope than the blocker requires.

## Recommended design

**Alternative B**. Per-profile `instanced` capability in the
manifest, with a `SELFDEF_INSTANCE_ID` env var passed by the
CLI dispatcher when an instance suffix is present.

Why:

- Closes F-2026-005 with a real fix (the relay-via-server
  multi-instance feature works) rather than a demotion.
- Lays groundwork for future modules with mixed-profile
  capabilities (e.g. a `mailserver` module where `imap` is
  instanceable but `mta` is not).
- Avoids the larger split-into-three refactor (D) which
  trades one debt for another.

D remains available as future work — once the `selfdef-cli`
shared module library (F-2026-081) lands, splitting becomes
cheaper because the shared code lives in one place.

## Detailed design

### D-1 — Manifest schema extension

`crates/selfdef-cli/src/modules.rs ModuleManifest` grows an
optional field:

```rust
pub(crate) struct ProfileSpec {
    #[serde(default)]
    pub(crate) default: Option<String>,
    #[serde(default)]
    pub(crate) available: Vec<String>,
    /// Per-profile metadata. Each key is a profile name from
    /// `available`. Profiles not listed here inherit
    /// module-level defaults.
    #[serde(default)]
    pub(crate) details: BTreeMap<String, ProfileDetails>,
}

pub(crate) struct ProfileDetails {
    /// Whether this profile supports multi-instance. If
    /// unset, falls back to the module-level `instanced`.
    /// If the module-level says `instanced = true` but this
    /// is `false`, this profile refuses instance suffixes.
    #[serde(default)]
    pub(crate) instanced: Option<bool>,
}
```

TOML shape (in `module.toml`):

```toml
[profiles]
default = "relay-via-server"
available = ["relay-via-server", "tailscale", "cloudflare-tunnel"]

[profiles.details.relay-via-server]
instanced = true

[profiles.details.tailscale]
instanced = false

[profiles.details.cloudflare-tunnel]
instanced = false
```

Module-level `instanced = true` stays; it now means "at least
one profile is instance-capable". Defaults (no
`details.<profile>` entry) fall back to the module-level
value, so existing manifests continue to work.

### D-2 — Resolver check

`resolve_active` (`crates/selfdef-cli/src/modules.rs:369-562`)
gains a post-resolve validation: for every active module
with an instance suffix, read the per-instance config to
discover the chosen profile, look up the profile's
`instanced` capability, and refuse if it's false.

Wire shape:

```rust
for instance in &active_instances {
    if instance.instance_id.is_some() {
        let profile = read_profile(&instance.config_path)?;
        let profile_instanced = manifest.profile_instanced(&profile);
        if !profile_instanced {
            bail!(
                "module `{}` profile `{}` does not support multi-instance \
                 (host key `{}#{}` cannot be applied)",
                instance.slug, profile, instance.slug,
                instance.instance_id.as_deref().unwrap()
            );
        }
    }
}
```

The check fires *before* any apply.sh is spawned, so the
operator sees a clean refusal rather than partial apply
state.

### D-3 — `SELFDEF_INSTANCE_ID` env var

`crates/selfdef-cli/src/modules.rs:737-739` (the script
invocation site) grows one line:

```rust
if let Some(inst) = &active.instance {
    cmd.env("SELFDEF_INSTANCE_ID", inst);
}
```

Profile scripts read it. Existing single-instance deployments
don't see it (the env var is absent for `instance = None`),
so no behaviour change for them.

### D-4 — Profile script parameterisation

`modules/vpn-bridge/install/profiles/relay-via-server.sh`:
state paths become instance-aware. Naming convention:

| Resource | Without instance | With instance |
| --- | --- | --- |
| WG interface | `selfdef0` | `selfdef-${INST}` |
| WG conf | `/etc/wireguard/selfdef0.conf` | `/etc/wireguard/selfdef-${INST}.conf` |
| nftables file | `/etc/nftables.d/selfdef-vpn-bridge.conf` | `/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf` |
| systemd unit | `wg-quick@selfdef0.service` | `wg-quick@selfdef-${INST}.service` |

The `iface` variable's default becomes
`selfdef-${SELFDEF_INSTANCE_ID:-0}` (so the single-instance
case stays `selfdef0`; multi-instance gets unique names).

Symmetric updates in `check.sh` / `uninstall.sh` for the
relay-via-server profile.

`tailscale.sh` and `cloudflare-tunnel.sh` get a defence-in-
depth guard at the top:

```bash
if [[ -n "${SELFDEF_INSTANCE_ID:-}" ]]; then
    die "profile '<name>' does not support multi-instance \
         (set instanced=false in module.toml profiles.details)"
fi
```

This is redundant with D-2's resolver check but provides a
second line of defense if a future change accidentally
bypasses the resolver.

### D-5 — Documentation

- `modules/vpn-bridge/README.md` — new section
  "Multi-instance support" listing per-profile capability
  and the naming convention from D-4.
- `modules/vpn-bridge/profiles/relay-via-server.toml` —
  comment block referencing the env var and the naming
  convention.
- A migration note in CHANGELOG for any hosts that *were*
  using multi-instance with the relay-via-server profile and
  default `iface` — they need to re-name to
  `selfdef-${inst}` and re-apply. (In practice, since
  multi-instance was silently broken before this SDD, the
  population affected by this migration is likely zero.)

## Test plan (implementation PR must satisfy)

1. Unit tests in `selfdef-cli/src/modules.rs`:
   - `ModuleManifest` with `[profiles.details.<name>].instanced`
     deserializes.
   - A profile not in `details` inherits the module-level
     `instanced`.
   - `profile_instanced("nonexistent")` returns the
     module-level value (a missing profile name is the
     operator's bug, but the validator surfaces it elsewhere).
2. Integration test in `tests/cli_modules_apply.rs`:
   - Fixture activates `vpn-bridge#a` with `profile =
     "tailscale"` (declared `instanced = false`).
   - `selfdefctl modules apply --dry-run` exits non-zero
     before invoking apply.sh, with the documented error
     string.
3. Integration test in `tests/module_vpn_bridge.rs`:
   - Relay-via-server profile gets `SELFDEF_INSTANCE_ID=publish`
     and writes to `selfdef-publish` paths.
   - Without an instance id, writes to `selfdef0` (unchanged
     from today).
4. Manifest test: `vpn-bridge`'s `module.toml` after the SDD
   lands has `[profiles.details.relay-via-server].instanced
   = true` and the other two profiles `= false`.

## Rollout / migration

- Single-instance `[modules.vpn-bridge]` deployments: no
  change. `SELFDEF_INSTANCE_ID` is unset; profile scripts
  behave as today.
- Multi-instance hosts running relay-via-server: assumed
  near-empty population (the feature was nominal). For any
  affected operators, the migration note in CHANGELOG and
  README documents the new path naming.
- Multi-instance hosts running tailscale or cloudflare-tunnel:
  the apply now refuses cleanly. Operators move to a single
  instance per profile.

No daemon-binary changes. Entirely a `selfdef-cli` + manifest
+ shell-script change.

## Risks

- **R-1 — operators who deliberately worked around the
  multi-instance corruption** by setting `iface` manually
  per-instance lose their workaround (the iface env var
  defaults change). Mitigated by keeping the env var
  override (`SELFDEF_VPN_BRIDGE_WG_IFACE`) as the operator
  escape hatch.
- **R-2 — the per-profile `instanced` manifest extension is
  vpn-bridge-specific in practice for now.** Future modules
  might never use it. Mitigated by keeping it optional and
  invisible to single-profile modules.
- **R-3 — defensive `die` in tailscale/cloudflare profile
  scripts is dead code in the normal apply path** (the
  resolver catches the same case earlier). Defence-in-depth
  justification: it's two lines, it costs nothing, it catches
  resolver bugs.

## Open questions

- **Q-A** — Should the per-profile metadata table support
  more fields than `instanced`? **Answered (D-014, 2026-05-15)** —
  out of scope for SDD-003; the schema in D-1 is already
  extensible, add fields when a concrete need arises.
  _Original framing for history_: Yes plausibly (e.g.
  per-profile `phase` overrides, per-profile `requires`).
  Out of scope for SDD-003; the schema in D-1 is extensible.
- **Q-B** — Should the resolver error message include the
  suggested fix ("declare instanced=true in
  profiles.details.<profile>")? **Answered (D-015, 2026-05-15)** —
  yes; operator-ergonomics improvement, tracked as an
  implementation-PR follow-up. _Original framing for
  history_: Probably yes — operator
  ergonomics. Implementation detail.
- **Q-C** — Naming convention for the WG interface
  (`selfdef-${INST}`). **Answered (D-005, 2026-05-15)**: `apply.sh`
  refuses cleanly with an explicit operator-facing error when the
  instance id exceeds **7** characters (`selfdef-` prefix is 8 chars;
  Linux IFNAMSIZ is 15; max INST = 15 − 8 = 7). _Original framing for
  history_: Linux interface names are limited to
  15 characters; `selfdef-${INST}` accommodates instance
  ids up to 8 chars (_note: this was an off-by-one in the original
  framing — the math gives 7, not 8_). Document the limit in the README. If
  an operator picks a longer instance id, the apply.sh
  should refuse cleanly. **Worth adding to D-4** — track in
  implementation PR.

## Appendix — interaction with SDD-002

SDD-002 introduces `[daemon_requires]` in `module.toml`.
vpn-bridge profiles do not currently require any daemon-side
config (the daemon doesn't ingest vpn-bridge state). If a
future profile needs daemon-side state (e.g. a relay
heartbeat collector), it would declare `[daemon_requires]`
under that profile via the same per-profile-details table
sketched in D-1. The schema is forward-compatible.

## Follow-up findings (F-2027-045)

Phase 2 raised two `nice` findings against this SDD's surface;
both are closed in tree. Listed here so future SDD readers can
trace the lineage without bouncing through the ledger.

- **F-2027-001** — the original SDD-003 refusal message
  (`module 'vpn-bridge' profile '<x>' does not support
  multi-instance`) was prose-only. Phase 2 nice-cluster PR
  (#57) replaced it with a copy-pasteable
  `[profiles.details.<profile>]\ninstanced = true\n` TOML
  stanza embedded directly in the diagnostic.
- **F-2027-025** — `_relay_inst_defaults` in
  `modules/vpn-bridge/install/profiles/relay-via-server.sh`
  interpolated `$SELFDEF_INSTANCE_ID` into nftables table
  names without the `safe_name` validator that lives in
  `install/lib.sh`. Phase 2 module-cleanup PR (#64) added a
  `safe_name "$INST" || die …` guard. Operator-controlled
  string today, so this was defense-in-depth.
