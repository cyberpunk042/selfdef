# MS018 — VPN-bridge multi-instance

> Parent: `backlog/milestones/INDEX.md` row MS018.
> Source: `docs/sdd/003-vpn-bridge-multi-instance.md` (647 lines; status=implemented; owner=audit team; last updated 2026-05-13; closes F-2026-005; ships D-1..D-5 + 5 unit tests + 5 integration tests + 2 phase-2 follow-ups F-2027-001 + F-2027-025) + `modules/vpn-bridge/` (module.toml + README.md + install/ + config/ + profiles/ + templates/) + `crates/selfdef-cli/src/modules.rs` ProfileSpec + ProfileDetails + resolve_active + run_one. All entries below extract verbatim. No invention.

## Epics (E0181–E0190)

| Epic ID | Phrase | Source |
|---|---|---|
| E0181 | SDD-003 mission — "vpn-bridge multi-instance honesty"; status=implemented; closes F-2026-005 (M-008 Phase 1 ledger row blocker: "manifest promises a feature the implementation silently corrupts state to deliver") | SDD-003 § header + § Problem |
| E0182 | Problem statement — `module.toml` declared `instanced=true` but 3 profile scripts (relay-via-server / tailscale / cloudflare-tunnel) wrote to instance-shared paths; manifest's `instanced=true` was a "lie by surface"; two `vpn-bridge#a` + `vpn-bridge#b` applications silently overwrite WG config + nftables file (last instance wins; partially-applied state with no daemon awareness) | SDD-003 § Problem |
| E0183 | 5 Goals — (1) manifest's multi-instance contract reflects what profiles actually support; (2) profiles that CAN be multi-instance (relay-via-server) parameterise every state path by instance id; (3) profiles that CANNOT (tailscale / cloudflare-tunnel) refuse cleanly when instance suffix passed; (4) selfdefctl modules apply produces clear error BEFORE running any apply.sh when intent doesn't match capability; (5) fix lands without breaking single-instance deployments | SDD-003 § Goals |
| E0184 | 4 Design alternatives considered — A (Demote `instanced=false`: one-line change, forecloses on relay-via-server multi-instance); B (Per-profile [profiles.details.<name>].instanced field; manifest schema + SELFDEF_INSTANCE_ID env var + profile script parameterisation); C (Resolver gates on profile, dispatcher unchanged; brittle filename parsing); D (Split into three modules: cleanest separation but largest scope; duplicates shared lib.sh); RECOMMENDED = B | SDD-003 § Design alternatives + § Recommended design |
| E0185 | D-1 — Manifest schema extension `ProfileSpec` grows `details: BTreeMap<String, ProfileDetails>` with optional `instanced` per profile + `ProfileSpec::profile_instanced` helper falling back to module-level default; TOML shape `[profiles.details.<name>].instanced = bool` | SDD-003 § D-1 |
| E0186 | D-2 — Resolver check `resolve_active` reads each instance's per-module config (parsing `profile = ...` line) + looks up profile's `instanced` capability + refuses any `slug#instance` host-config key when profile declared `instanced=false`; falls back to manifest default profile if per-instance config can't be parsed; check fires BEFORE any apply.sh spawn | SDD-003 § D-2 |
| E0187 | D-3 — `SELFDEF_INSTANCE_ID` env var; `run_one` passes `SELFDEF_INSTANCE_ID=<inst>` into spawned bash process whenever `active.instance.is_some()`; absent for legacy single-instance shape | SDD-003 § D-3 |
| E0188 | D-4 — Profile script parameterisation; relay-via-server derives per-instance defaults from `${SELFDEF_INSTANCE_ID}` (selfdef-<inst> iface / selfdef_vpn_bridge_<inst> nftables table / /etc/nftables.d/selfdef-vpn-bridge-<inst>.conf state file); legacy single-instance defaults unchanged when env var absent; tailscale.sh + cloudflare-tunnel.sh `die` defence-in-depth at top of profile_apply/profile_uninstall when SELFDEF_INSTANCE_ID is set; per Q-C IFNAMSIZ limit `selfdef-${INST}` max INST = 7 chars (8-char prefix + 15-char Linux IFNAMSIZ = 7) | SDD-003 § D-4 + Q-C |
| E0189 | D-5 — Documentation; `modules/vpn-bridge/module.toml` carries [profiles.details.relay-via-server].instanced=true + [profiles.details.tailscale].instanced=false + [profiles.details.cloudflare-tunnel].instanced=false; README "Multi-instance support" section with capability table + per-instance naming convention + migration notes; profiles/relay-via-server.toml comment references env var + naming convention; CHANGELOG migration note (population affected ~zero since multi-instance was silently broken before) | SDD-003 § D-5 |
| E0190 | Test plan + Phase-2 follow-ups — 5 unit tests in selfdef-cli/src/modules.rs (profile_instanced_falls_back_to_module_default_when_unset / profile_instanced_per_profile_override_wins / resolver_rejects_instance_for_singleton_profile / resolver_accepts_instance_for_multi_instance_profile / resolver_falls_back_to_default_profile_when_config_missing); 5 integration tests in module_vpn_bridge_multi_instance.rs (relay_apply_with_instance_id_uses_per_instance_iface / relay_apply_without_instance_id_keeps_legacy_wg0_defaults / tailscale_apply_refuses_when_instance_id_is_set / cloudflare_apply_refuses_when_instance_id_is_set / cli_resolver_refuses_singleton_profile_with_instance_suffix); 2 phase-2 follow-ups F-2027-001 (operator-ergonomics: prose-only refusal message replaced with copy-pasteable TOML stanza; PR #57) + F-2027-025 (safe_name validator on $SELFDEF_INSTANCE_ID in nftables table names; PR #64; defense-in-depth) | SDD-003 § Test plan + § "Follow-up findings (F-2027-045)" |

## Modules (M00447–M00472)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00447 | F-2026-005 finding — multi-instance manifest claim corrupted by silent state overwrite | SDD-003 § header + § Problem | E0181 |
| M00448 | Affected profile relay-via-server — `/etc/wireguard/selfdef0.conf` + `/etc/nftables.d/selfdef-vpn-bridge.conf` instance-shared paths | SDD-003 § Problem | E0182 |
| M00449 | Affected profile tailscale — singleton `tailscaled.service` (kernel TUN device + `/var/lib/tailscale` state; "Tailscale is fundamentally one daemon per host") | SDD-003 § Problem | E0182 |
| M00450 | Affected profile cloudflare-tunnel — singleton `/etc/systemd/system/cloudflared.service` ("cloudflared service install" clobbers; "Two cloudflared instances need custom per-instance unit files") | SDD-003 § Problem | E0182 |
| M00451 | Recommendation B — per-profile [profiles.details.<name>].instanced field | SDD-003 § Recommended design | E0184 |
| M00452 | Rejected Alternative A — demote `instanced=false` (forecloses on relay-via-server multi-instance) | SDD-003 § Alternative A | E0184 |
| M00453 | Rejected Alternative C — resolver gates on profile, dispatcher unchanged (brittle filename parsing) | SDD-003 § Alternative C | E0184 |
| M00454 | Rejected Alternative D — split into three modules (cleanest but largest scope; duplicates shared lib.sh) | SDD-003 § Alternative D | E0184 |
| M00455 | D-1 Rust schema — `ProfileSpec { default: Option<String>, available: Vec<String>, details: BTreeMap<String, ProfileDetails> }` | SDD-003 § D-1 | E0185 |
| M00456 | D-1 Rust schema — `ProfileDetails { instanced: Option<bool> }` | SDD-003 § D-1 | E0185 |
| M00457 | D-1 TOML shape — `[profiles.details.<name>] instanced = bool` | SDD-003 § D-1 | E0185 |
| M00458 | D-1 module-level `instanced=true` semantics — "at least one profile is instance-capable" | SDD-003 § D-1 | E0185 |
| M00459 | D-2 resolver check — reads per-instance config, parses profile, looks up profile_instanced, refuses if false | SDD-003 § D-2 | E0186 |
| M00460 | D-2 resolver error message — `module '<slug>' profile '<profile>' does not support multi-instance (host key '<slug>#<inst>' cannot be applied)` | SDD-003 § D-2 | E0186 |
| M00461 | D-3 env-var contract — `SELFDEF_INSTANCE_ID=<inst>` passed into bash by `run_one` when `active.instance.is_some()`; absent otherwise | SDD-003 § D-3 | E0187 |
| M00462 | D-4 naming convention — selfdef-${INST} iface + /etc/wireguard/selfdef-${INST}.conf + /etc/nftables.d/selfdef-vpn-bridge-${INST}.conf + wg-quick@selfdef-${INST}.service | SDD-003 § D-4 naming table | E0188 |
| M00463 | D-4 single-instance defaults — selfdef0 / /etc/wireguard/selfdef0.conf / /etc/nftables.d/selfdef-vpn-bridge.conf / wg-quick@selfdef0.service (unchanged) | SDD-003 § D-4 naming table | E0188 |
| M00464 | D-4 defense-in-depth — `tailscale.sh` + `cloudflare-tunnel.sh` `die` at top of `profile_apply`/`profile_uninstall` when `SELFDEF_INSTANCE_ID` set | SDD-003 § D-4 | E0188 |
| M00465 | D-4 Q-C IFNAMSIZ enforcement — apply.sh refuses cleanly when instance id exceeds 7 chars (selfdef- prefix 8 + Linux IFNAMSIZ 15 = max INST 7) | SDD-003 § Q-C answer | E0188 |
| M00466 | D-5 manifest content — `[profiles.details.relay-via-server].instanced=true` | SDD-003 § D-5 | E0189 |
| M00467 | D-5 manifest content — `[profiles.details.tailscale].instanced=false` | SDD-003 § D-5 | E0189 |
| M00468 | D-5 manifest content — `[profiles.details.cloudflare-tunnel].instanced=false` | SDD-003 § D-5 | E0189 |
| M00469 | D-5 README — "Multi-instance support" section with capability table + per-instance naming convention + migration notes | SDD-003 § D-5 | E0189 |
| M00470 | Test plan — 5 unit tests in `crates/selfdef-cli/src/modules.rs` | SDD-003 § Test plan + § Implementation status | E0190 |
| M00471 | Test plan — 5 integration tests in `crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs` | SDD-003 § Implementation status | E0190 |
| M00472 | Phase-2 follow-ups F-2027-001 (operator-ergonomics: refusal message TOML stanza; PR #57) + F-2027-025 (safe_name validator on $SELFDEF_INSTANCE_ID; PR #64; defense-in-depth) | SDD-003 § "Follow-up findings (F-2027-045)" | E0190 |

## Features (F02041–F02160)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F02041 | SDD-003 status = implemented | SDD-003 § header | E0181 | composite | false |
| F02042 | SDD-003 owner = audit team | SDD-003 § header | E0181 | composite | false |
| F02043 | SDD-003 last updated = 2026-05-13 | SDD-003 § header | E0181 | composite | false |
| F02044 | SDD-003 closes findings = F-2026-005 | SDD-003 § header | E0181 | composite | false |
| F02045 | SDD-003 closes M-008 (Phase 1 ledger blocker) | SDD-003 § Problem | E0181 | composite | false |
| F02046 | F-2026-005 — manifest promises feature implementation silently corrupts state to deliver | SDD-003 § Problem | M00447 | composite | false |
| F02047 | `modules/vpn-bridge/module.toml` declared `instanced=true` | SDD-003 § Current state | E0182 | composite | false |
| F02048 | Resolver honoured manifest instanced=true — accepts suffix syntax; assigns per-instance config path under `/etc/selfdef/modules/vpn-bridge.<instance>.toml`; runs each instance's apply.sh in turn | SDD-003 § Current state Resolver behaviour | E0182 | composite | false |
| F02049 | 3 shipped profile scripts did NOT honour instance suffix — they wrote to instance-shared paths | SDD-003 § Problem | E0182 | composite | false |
| F02050 | relay-via-server collision — `wg_conf=/etc/wireguard/selfdef0.conf` + `nft_path=/etc/nftables.d/selfdef-vpn-bridge.conf` (no per-instance variant) | SDD-003 § Problem | M00448 | composite | false |
| F02051 | tailscale collision — singleton `tailscaled.service`; kernel TUN device; `/var/lib/tailscale` state | SDD-003 § Problem | M00449 | composite | false |
| F02052 | tailscale rationale — "Tailscale is fundamentally one daemon per host. Two tailscale instances on one host is not a thing." | SDD-003 § Problem | M00449 | composite | false |
| F02053 | cloudflare-tunnel collision — `cloudflared service install` writes singleton `/etc/systemd/system/cloudflared.service` | SDD-003 § Problem | M00450 | composite | false |
| F02054 | cloudflare-tunnel multi-instance — "Two cloudflared instances need custom per-instance unit files, which the profile script doesn't generate." | SDD-003 § Problem | M00450 | composite | false |
| F02055 | Manifest's `instanced = true` was "a lie by surface" | SDD-003 § Problem | E0182 | composite | false |
| F02056 | Two vpn-bridge#a + vpn-bridge#b applications — relay-via-server silently overwrites same WG config + nftables file | SDD-003 § Problem | E0182 | composite | false |
| F02057 | Two vpn-bridge#a + vpn-bridge#b applications — last-write-wins; partially-applied state on disk with no daemon awareness | SDD-003 § Problem | E0182 | composite | false |
| F02058 | Two vpn-bridge#a + vpn-bridge#b applications — tailscale silently re-applies same singleton service (symmetric; don't conflict but don't multi-instance anything) | SDD-003 § Problem | E0182 | composite | false |
| F02059 | Two vpn-bridge#a + vpn-bridge#b applications — cloudflare-tunnel second install clobbers first | SDD-003 § Problem | E0182 | composite | false |
| F02060 | Goal 1 — manifest's multi-instance contract reflects what profiles actually support | SDD-003 § Goals 1 | E0183 | composite | false |
| F02061 | Goal 2 — multi-instance-capable profiles parameterise every state path by instance id | SDD-003 § Goals 2 | E0183 | composite | false |
| F02062 | Goal 3 — non-multi-instance profiles refuse cleanly when instance suffix passed | SDD-003 § Goals 3 | E0183 | composite | false |
| F02063 | Goal 4 — `selfdefctl modules apply` clear error BEFORE any apply.sh when intent doesn't match capability | SDD-003 § Goals 4 | E0183 | composite | false |
| F02064 | Goal 5 — fix lands without breaking single-instance deployments (the common case today) | SDD-003 § Goals 5 | E0183 | composite | false |
| F02065 | Non-goal — general per-profile manifest feature beyond what vpn-bridge needs | SDD-003 § Non-goals | E0184 | composite | false |
| F02066 | Non-goal — renaming module / splitting into three (vpn-bridge-relay, vpn-bridge-tailscale, vpn-bridge-cloudflare); refactor has merit but much larger scope | SDD-003 § Non-goals | M00454 | composite | false |
| F02067 | Non-goal — migrating existing single-instance deployments; they keep working with no operator action | SDD-003 § Non-goals | E0184 | composite | false |
| F02068 | Glossary — instance id (suffix after # in host-config key) | SDD-003 § Glossary | E0182 | composite | false |
| F02069 | Glossary — per-profile multi-instance (property that one profile of one module supports running multiple instances simultaneously; distinct from module-level `instanced`) | SDD-003 § Glossary | E0185 | composite | false |
| F02070 | Glossary — state path (any filesystem path or service-manager resource the apply script reads or writes) | SDD-003 § Glossary | E0182 | composite | false |
| F02071 | Alternative A — Demote `instanced=false`; one-line manifest change; manifest stops lying; existing single-instance unaffected | SDD-003 § Alternative A | M00452 | composite | false |
| F02072 | Alternative A con — operators using multi-instance syntax (even if silently broken) now get a hard refusal; need migration note | SDD-003 § Alternative A | M00452 | composite | false |
| F02073 | Alternative A con — forecloses on per-profile multi-instance entirely; relay-via-server which COULD be cleanly multi-instance no longer allowed | SDD-003 § Alternative A | M00452 | composite | false |
| F02074 | Alternative B (recommended) — per-profile [profiles.<name>] instanced field | SDD-003 § Alternative B + § Recommended design | M00451 | composite | true |
| F02075 | Alternative B pro — honest contract per profile | SDD-003 § Alternative B | M00451 | composite | false |
| F02076 | Alternative B pro — future modules with mixed-instance profiles get same facility | SDD-003 § Alternative B | M00451 | composite | false |
| F02077 | Alternative B pro — single-instance deployments keep working without change | SDD-003 § Alternative B | M00451 | composite | false |
| F02078 | Alternative B pro — multi-instance with relay-via-server becomes real feature, not nominal | SDD-003 § Alternative B | M00451 | composite | false |
| F02079 | Alternative B con — manifest schema change; selfdef-cli's ModuleManifest struct grows nested optional map | SDD-003 § Alternative B | M00451 | composite | false |
| F02080 | Alternative B con — validator + resolver both need updates | SDD-003 § Alternative B | M00451 | composite | false |
| F02081 | Alternative B con — three changes land together (manifest schema / dispatcher env var / profile-script parameterisation) | SDD-003 § Alternative B | M00451 | composite | false |
| F02082 | Alternative C — same per-profile capability as B, but profile scripts derive instance id from config filename | SDD-003 § Alternative C | M00453 | composite | false |
| F02083 | Alternative C con — operator must keep filename + content in sync | SDD-003 § Alternative C | M00453 | composite | false |
| F02084 | Alternative C con — filename parsing in bash is fragile | SDD-003 § Alternative C | M00453 | composite | false |
| F02085 | Alternative C con — future modules' profile scripts can't rely on stable env-var convention | SDD-003 § Alternative C | M00453 | composite | false |
| F02086 | Alternative D — split into vpn-bridge-relay / vpn-bridge-tailscale / vpn-bridge-cloudflare | SDD-003 § Alternative D | M00454 | composite | false |
| F02087 | Alternative D pro — cleanest separation of concerns; no per-profile manifest field needed | SDD-003 § Alternative D | M00454 | composite | false |
| F02088 | Alternative D pro — catalog entries map 1:1 to upstream tool families (wireguard / tailscale / cloudflared) | SDD-003 § Alternative D | M00454 | composite | false |
| F02089 | Alternative D pro — each module's README focuses on one workload | SDD-003 § Alternative D | M00454 | composite | false |
| F02090 | Alternative D con — three modules to maintain instead of one | SDD-003 § Alternative D | M00454 | composite | false |
| F02091 | Alternative D con — migration: existing hosts have `[modules.vpn-bridge]` configs that wouldn't match new module names | SDD-003 § Alternative D | M00454 | composite | false |
| F02092 | Alternative D con — shared lib.sh + profile detection logic + config layout duplicated across three modules (exactly what F-2026-081 wants to reduce) | SDD-003 § Alternative D | M00454 | composite | false |
| F02093 | Alternative D con — larger scope than blocker requires | SDD-003 § Alternative D | M00454 | composite | false |
| F02094 | Recommended — Alternative B | SDD-003 § Recommended design | M00451 | composite | false |
| F02095 | Recommendation rationale — closes F-2026-005 with real fix; relay-via-server multi-instance works | SDD-003 § Recommended design | E0184 | composite | false |
| F02096 | Recommendation rationale — lays groundwork for future modules with mixed-profile capabilities (e.g. mailserver where imap is instanceable but mta is not) | SDD-003 § Recommended design | E0184 | composite | false |
| F02097 | Recommendation rationale — avoids the larger split-into-three refactor (D) which trades one debt for another | SDD-003 § Recommended design | E0184 | composite | false |
| F02098 | D remains available as future work once selfdef-cli shared module library (F-2026-081) lands | SDD-003 § Recommended design | M00454 | composite | false |
| F02099 | D-1 Rust struct — `pub(crate) struct ProfileSpec` | SDD-003 § D-1 | M00455 | composite | false |
| F02100 | D-1 Rust field — `details: BTreeMap<String, ProfileDetails>` | SDD-003 § D-1 | M00455 | composite | false |
| F02101 | D-1 Rust struct — `pub(crate) struct ProfileDetails` | SDD-003 § D-1 | M00456 | composite | false |
| F02102 | D-1 Rust field — `instanced: Option<bool>` | SDD-003 § D-1 | M00456 | composite | false |
| F02103 | D-1 helper — `ProfileSpec::profile_instanced(&self, profile_name) -> bool` (falls back to module-level default) | SDD-003 § D-1 + § Implementation status | M00455 | composite | false |
| F02104 | D-1 TOML — `[profiles.details.<name>] instanced = bool` | SDD-003 § D-1 | M00457 | composite | true |
| F02105 | D-1 semantics — Module-level `instanced=true` stays; now means "at least one profile is instance-capable" | SDD-003 § D-1 | M00458 | composite | false |
| F02106 | D-1 backward-compat — defaults (no details.<profile> entry) fall back to module-level value; existing manifests continue to work | SDD-003 § D-1 | M00458 | composite | false |
| F02107 | D-2 resolver gate — fires BEFORE any apply.sh spawn | SDD-003 § D-2 | M00459 | composite | false |
| F02108 | D-2 — for every active module with instance suffix, read per-instance config to discover chosen profile + look up profile's instanced + refuse if false | SDD-003 § D-2 | M00459 | composite | false |
| F02109 | D-2 — falls back to manifest default profile if per-instance config can't be parsed | SDD-003 § Implementation status | M00459 | composite | false |
| F02110 | D-2 error format — "module '<slug>' profile '<profile>' does not support multi-instance (host key '<slug>#<inst>' cannot be applied)" | SDD-003 § D-2 | M00460 | composite | false |
| F02111 | D-3 — `run_one` adds `cmd.env("SELFDEF_INSTANCE_ID", inst)` when `active.instance.is_some()` | SDD-003 § D-3 + § Implementation status | M00461 | composite | false |
| F02112 | D-3 — env var absent for `instance = None` (legacy single-instance shape) | SDD-003 § D-3 | M00461 | composite | false |
| F02113 | D-4 — relay-via-server.sh derives per-instance defaults from `${SELFDEF_INSTANCE_ID}` | SDD-003 § D-4 | M00462 | composite | false |
| F02114 | D-4 — WG interface `selfdef-${INST}` (vs `selfdef0` legacy) | SDD-003 § D-4 naming table | M00462 | composite | true |
| F02115 | D-4 — WG conf `/etc/wireguard/selfdef-${INST}.conf` (vs `/etc/wireguard/selfdef0.conf` legacy) | SDD-003 § D-4 naming table | M00462 | composite | true |
| F02116 | D-4 — nftables file `/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf` (vs `/etc/nftables.d/selfdef-vpn-bridge.conf` legacy) | SDD-003 § D-4 naming table | M00462 | composite | true |
| F02117 | D-4 — systemd unit `wg-quick@selfdef-${INST}.service` (vs `wg-quick@selfdef0.service` legacy) | SDD-003 § D-4 naming table | M00462 | composite | true |
| F02118 | D-4 — nftables table `selfdef_vpn_bridge_<inst>` | SDD-003 § Implementation status D-4 | M00462 | composite | true |
| F02119 | D-4 single-instance default behavior — `iface` defaults to `selfdef-${SELFDEF_INSTANCE_ID:-0}` so single-instance stays `selfdef0` | SDD-003 § D-4 | M00463 | composite | false |
| F02120 | D-4 symmetric updates in check.sh / uninstall.sh for relay-via-server | SDD-003 § D-4 | M00462 | composite | false |
| F02121 | D-4 defense-in-depth — tailscale.sh `die` at top of profile_apply when SELFDEF_INSTANCE_ID set | SDD-003 § D-4 + § Implementation status | M00464 | composite | false |
| F02122 | D-4 defense-in-depth — cloudflare-tunnel.sh `die` at top of profile_apply when SELFDEF_INSTANCE_ID set | SDD-003 § D-4 + § Implementation status | M00464 | composite | false |
| F02123 | D-4 defense-in-depth — tailscale.sh `die` at top of profile_uninstall when SELFDEF_INSTANCE_ID set | SDD-003 § Implementation status D-4 | M00464 | composite | false |
| F02124 | D-4 defense-in-depth — cloudflare-tunnel.sh `die` at top of profile_uninstall when SELFDEF_INSTANCE_ID set | SDD-003 § Implementation status D-4 | M00464 | composite | false |
| F02125 | D-4 defense-in-depth — redundant with D-2 but catches resolver bugs | SDD-003 § D-4 | M00464 | composite | false |
| F02126 | Q-C IFNAMSIZ — Linux interface names limited to 15 characters | SDD-003 § Q-C answer | M00465 | composite | false |
| F02127 | Q-C math — `selfdef-` prefix is 8 chars; max INST = 15-8 = 7 | SDD-003 § Q-C answer | M00465 | composite | false |
| F02128 | Q-C enforcement — apply.sh refuses cleanly with explicit operator-facing error when INST > 7 chars | SDD-003 § Q-C answer | M00465 | composite | false |
| F02129 | D-5 manifest — `[profiles.details.relay-via-server].instanced = true` | SDD-003 § D-5 | M00466 | composite | true |
| F02130 | D-5 manifest — `[profiles.details.tailscale].instanced = false` | SDD-003 § D-5 | M00467 | composite | true |
| F02131 | D-5 manifest — `[profiles.details.cloudflare-tunnel].instanced = false` | SDD-003 § D-5 | M00468 | composite | true |
| F02132 | D-5 README — "Multi-instance support" section (capability table + per-instance naming convention + migration notes) | SDD-003 § D-5 | M00469 | composite | false |
| F02133 | D-5 profile config — `modules/vpn-bridge/profiles/relay-via-server.toml` comment block references env var + naming convention | SDD-003 § D-5 | M00469 | composite | false |
| F02134 | D-5 CHANGELOG migration note — population affected likely zero (multi-instance was silently broken before) | SDD-003 § D-5 | M00469 | composite | false |
| F02135 | Unit test — `profile_instanced_falls_back_to_module_default_when_unset` | SDD-003 § Implementation status Tests | M00470 | composite | true |
| F02136 | Unit test — `profile_instanced_per_profile_override_wins` | SDD-003 § Implementation status Tests | M00470 | composite | true |
| F02137 | Unit test — `resolver_rejects_instance_for_singleton_profile` | SDD-003 § Implementation status Tests | M00470 | composite | true |
| F02138 | Unit test — `resolver_accepts_instance_for_multi_instance_profile` | SDD-003 § Implementation status Tests | M00470 | composite | true |
| F02139 | Unit test — `resolver_falls_back_to_default_profile_when_config_missing` | SDD-003 § Implementation status Tests | M00470 | composite | true |
| F02140 | Integration test file — `crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs` | SDD-003 § Implementation status Tests | M00471 | composite | false |
| F02141 | Integration test — `relay_apply_with_instance_id_uses_per_instance_iface` | SDD-003 § Implementation status Tests | M00471 | composite | true |
| F02142 | Integration test — `relay_apply_without_instance_id_keeps_legacy_wg0_defaults` | SDD-003 § Implementation status Tests | M00471 | composite | true |
| F02143 | Integration test — `tailscale_apply_refuses_when_instance_id_is_set` | SDD-003 § Implementation status Tests | M00471 | composite | true |
| F02144 | Integration test — `cloudflare_apply_refuses_when_instance_id_is_set` | SDD-003 § Implementation status Tests | M00471 | composite | true |
| F02145 | Integration test — `cli_resolver_refuses_singleton_profile_with_instance_suffix` | SDD-003 § Implementation status Tests | M00471 | composite | true |
| F02146 | Rollout — single-instance `[modules.vpn-bridge]` deployments: no change | SDD-003 § Rollout / migration | E0189 | composite | false |
| F02147 | Rollout — multi-instance hosts running relay-via-server: assumed near-empty population | SDD-003 § Rollout / migration | E0189 | composite | false |
| F02148 | Rollout — multi-instance hosts running tailscale or cloudflare-tunnel: apply now refuses cleanly | SDD-003 § Rollout / migration | E0189 | composite | false |
| F02149 | Rollout — no daemon-binary changes (entirely selfdef-cli + manifest + shell-script change) | SDD-003 § Rollout / migration | E0189 | composite | false |
| F02150 | Risk R-1 — operators who worked around multi-instance corruption (manual iface) lose workaround; mitigated by keeping `SELFDEF_VPN_BRIDGE_WG_IFACE` operator escape hatch | SDD-003 § Risks R-1 | E0188 | composite | false |
| F02151 | Risk R-2 — per-profile `instanced` manifest extension is vpn-bridge-specific in practice for now; mitigated by keeping optional + invisible to single-profile modules | SDD-003 § Risks R-2 | E0185 | composite | false |
| F02152 | Risk R-3 — defensive `die` in tailscale/cloudflare profile scripts is dead code in normal apply path; defense-in-depth justification (two lines, costs nothing, catches resolver bugs) | SDD-003 § Risks R-3 | M00464 | composite | false |
| F02153 | Q-A — per-profile metadata table extensibility (Answered D-014: out of scope for SDD-003; schema in D-1 is already extensible) | SDD-003 § Q-A answer | E0185 | composite | false |
| F02154 | Q-B — resolver error message includes suggested fix (Answered D-015: yes; operator-ergonomics; tracked as implementation-PR follow-up F-2027-001) | SDD-003 § Q-B answer + § Follow-up findings | M00472 | composite | false |
| F02155 | Appendix — interaction with SDD-002 (forward-compatible schema; future profile needing daemon-side state would declare [daemon_requires] under per-profile-details table) | SDD-003 § Appendix | E0185 | composite | false |
| F02156 | Phase-2 follow-up F-2027-001 — operator-ergonomics; refusal message TOML stanza; PR #57 | SDD-003 § Follow-up findings | M00472 | composite | false |
| F02157 | Phase-2 follow-up F-2027-025 — _relay_inst_defaults safe_name validator on $SELFDEF_INSTANCE_ID; PR #64; defense-in-depth | SDD-003 § Follow-up findings | M00472 | composite | false |
| F02158 | F-2027-025 background — operator-controlled string today; safe_name is defense-in-depth | SDD-003 § Follow-up findings | M00472 | composite | false |
| F02159 | F-2027-001 — copy-pasteable `[profiles.details.<profile>]\ninstanced = true\n` TOML stanza embedded directly in diagnostic | SDD-003 § Follow-up findings | M00472 | composite | false |
| F02160 | Composite — SDD-003 ships per-profile instanced capability (D-1..D-5 + 5 unit tests + 5 integration tests + 2 phase-2 follow-ups); F-2026-005 closed; relay-via-server multi-instance is real feature; tailscale + cloudflare-tunnel refuse cleanly; single-instance deployments unaffected | SDD-003 entire | E0181 + E0182 + E0183 + E0184 + E0185 + E0186 + E0187 + E0188 + E0189 + E0190 | composite | false |

## Requirements (R04081–R04320)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R04081 | SDD-003 status = implemented | SDD-003 § header | F02041 | non-negotiable | false | 10 |
| R04082 | SDD-003 closes finding F-2026-005 | SDD-003 § header | F02044 | non-negotiable | false | 10 |
| R04083 | F-2026-005 was M-008 Phase 1 ledger blocker | SDD-003 § Problem | F02045 | non-negotiable | false | 10 |
| R04084 | Manifest's `instanced=true` was "a lie by surface" before SDD-003 | SDD-003 § Problem | F02055 | non-negotiable | false | 10 |
| R04085 | relay-via-server `wg_conf=/etc/wireguard/selfdef0.conf` was instance-shared | SDD-003 § Problem | M00448 | non-negotiable | false | 10 |
| R04086 | relay-via-server `nft_path=/etc/nftables.d/selfdef-vpn-bridge.conf` had no per-instance variant | SDD-003 § Problem | M00448 | non-negotiable | false | 10 |
| R04087 | tailscale operates on singleton `tailscaled.service` | SDD-003 § Problem | M00449 | non-negotiable | false | 10 |
| R04088 | "Tailscale is fundamentally one daemon per host" | SDD-003 § Problem | F02052 | non-negotiable | false | 10 |
| R04089 | cloudflared service install writes singleton `/etc/systemd/system/cloudflared.service` | SDD-003 § Problem | M00450 | non-negotiable | false | 10 |
| R04090 | Two vpn-bridge#a + vpn-bridge#b with relay-via-server silently overwrite same WG config + nftables file | SDD-003 § Problem | F02056 | non-negotiable | false | 10 |
| R04091 | Two vpn-bridge#a + vpn-bridge#b — whichever instance ran last wins | SDD-003 § Problem | F02057 | non-negotiable | false | 10 |
| R04092 | Two vpn-bridge#a + vpn-bridge#b — other is partially-applied state on disk with no daemon awareness | SDD-003 § Problem | F02057 | non-negotiable | false | 10 |
| R04093 | Goal 1 — manifest's multi-instance contract reflects what profiles actually support | SDD-003 § Goals 1 | F02060 | non-negotiable | false | 10 |
| R04094 | Goal 2 — multi-instance-capable profiles parameterise every state path by instance id | SDD-003 § Goals 2 | F02061 | non-negotiable | false | 10 |
| R04095 | Goal 3 — non-multi-instance profiles refuse cleanly when instance suffix passed | SDD-003 § Goals 3 | F02062 | non-negotiable | false | 10 |
| R04096 | Goal 4 — `selfdefctl modules apply` clear error BEFORE any apply.sh when intent doesn't match capability | SDD-003 § Goals 4 | F02063 | non-negotiable | false | 10 |
| R04097 | Goal 5 — fix without breaking single-instance deployments | SDD-003 § Goals 5 | F02064 | non-negotiable | false | 10 |
| R04098 | Non-goal — general per-profile manifest feature beyond what vpn-bridge needs | SDD-003 § Non-goals | F02065 | non-negotiable | false | 10 |
| R04099 | Non-goal — renaming module / splitting into three modules | SDD-003 § Non-goals | F02066 | non-negotiable | false | 10 |
| R04100 | Non-goal — migrating existing single-instance deployments | SDD-003 § Non-goals | F02067 | non-negotiable | false | 10 |
| R04101 | Glossary — instance id = suffix after # in host-config key | SDD-003 § Glossary | F02068 | non-negotiable | false | 10 |
| R04102 | Glossary — single-instance modules have instance id = None | SDD-003 § Glossary | F02068 | non-negotiable | false | 10 |
| R04103 | Glossary — per-profile multi-instance is distinct from module-level `instanced` | SDD-003 § Glossary | F02069 | non-negotiable | false | 10 |
| R04104 | Glossary — state path = any filesystem path or service-manager resource the apply script reads or writes | SDD-003 § Glossary | F02070 | non-negotiable | false | 10 |
| R04105 | Alternative A demote `instanced=false` — rejected | SDD-003 § Recommended design | F02074 | non-negotiable | false | 10 |
| R04106 | Alternative B (recommended) — per-profile `[profiles.details.<name>].instanced` field | SDD-003 § Recommended design | F02074 | non-negotiable | false | 10 |
| R04107 | Alternative B pro — honest contract per profile | SDD-003 § Alternative B | F02075 | non-negotiable | false | 10 |
| R04108 | Alternative B pro — future modules with mixed-instance profiles get same facility | SDD-003 § Alternative B | F02076 | non-negotiable | false | 10 |
| R04109 | Alternative B pro — single-instance deployments keep working without change | SDD-003 § Alternative B | F02077 | non-negotiable | false | 10 |
| R04110 | Alternative B pro — multi-instance with relay-via-server becomes real feature, not nominal | SDD-003 § Alternative B | F02078 | non-negotiable | false | 10 |
| R04111 | Alternative C resolver-only — rejected (brittle filename parsing) | SDD-003 § Alternative C | F02082 | non-negotiable | false | 10 |
| R04112 | Alternative D split-into-three-modules — rejected (larger scope; duplicates shared lib.sh) | SDD-003 § Alternative D | F02086 | non-negotiable | false | 10 |
| R04113 | Recommendation rationale — closes F-2026-005 with real fix (relay-via-server multi-instance works) | SDD-003 § Recommended design | F02095 | non-negotiable | false | 10 |
| R04114 | Recommendation rationale — lays groundwork for future modules with mixed-profile capabilities | SDD-003 § Recommended design | F02096 | non-negotiable | false | 10 |
| R04115 | Recommendation rationale — avoids the larger split-into-three refactor (D) which trades one debt for another | SDD-003 § Recommended design | F02097 | non-negotiable | false | 10 |
| R04116 | Alternative D remains available as future work once selfdef-cli shared module library (F-2026-081) lands | SDD-003 § Recommended design | F02098 | non-negotiable | false | 10 |
| R04117 | D-1 — `ProfileSpec` gains `details: BTreeMap<String, ProfileDetails>` field | SDD-003 § D-1 + § Implementation status | F02100 | non-negotiable | false | 10 |
| R04118 | D-1 — `ProfileDetails { instanced: Option<bool> }` | SDD-003 § D-1 | F02102 | non-negotiable | false | 10 |
| R04119 | D-1 — `ProfileSpec::profile_instanced` helper falls back to module-level default | SDD-003 § Implementation status D-1 | F02103 | non-negotiable | false | 10 |
| R04120 | D-1 TOML shape — `[profiles.details.<name>] instanced = bool` | SDD-003 § D-1 | F02104 | non-negotiable | true | 10 |
| R04121 | D-1 — Module-level `instanced=true` now means "at least one profile is instance-capable" | SDD-003 § D-1 | F02105 | non-negotiable | false | 10 |
| R04122 | D-1 — Defaults (no details.<profile> entry) fall back to module-level value | SDD-003 § D-1 | F02106 | non-negotiable | false | 10 |
| R04123 | D-1 — Existing manifests continue to work | SDD-003 § D-1 | F02106 | non-negotiable | false | 10 |
| R04124 | D-2 — `resolve_active` reads each instance's per-module config | SDD-003 § D-2 + § Implementation status | F02108 | non-negotiable | false | 10 |
| R04125 | D-2 — Parses `profile = ...` line | SDD-003 § Implementation status D-2 | M00459 | non-negotiable | false | 10 |
| R04126 | D-2 — Looks up profile's `instanced` capability | SDD-003 § D-2 | M00459 | non-negotiable | false | 10 |
| R04127 | D-2 — Refuses any `slug#instance` host-config key when profile declared `instanced=false` | SDD-003 § Implementation status D-2 | M00459 | non-negotiable | false | 10 |
| R04128 | D-2 — Falls back to manifest default profile if per-instance config can't be parsed | SDD-003 § Implementation status D-2 | F02109 | non-negotiable | false | 10 |
| R04129 | D-2 — Check fires BEFORE any apply.sh is spawned | SDD-003 § D-2 | F02107 | non-negotiable | false | 10 |
| R04130 | D-2 error format — `module '<slug>' profile '<profile>' does not support multi-instance (host key '<slug>#<inst>' cannot be applied)` | SDD-003 § D-2 | F02110 | non-negotiable | false | 10 |
| R04131 | D-3 — `run_one` passes `SELFDEF_INSTANCE_ID=<inst>` into spawned bash process | SDD-003 § D-3 + § Implementation status | F02111 | non-negotiable | false | 10 |
| R04132 | D-3 — env var passed whenever `active.instance.is_some()` | SDD-003 § Implementation status D-3 | F02111 | non-negotiable | false | 10 |
| R04133 | D-3 — env var absent for legacy single-instance shape (`active.instance.is_none()`) | SDD-003 § D-3 | F02112 | non-negotiable | false | 10 |
| R04134 | D-4 — `relay-via-server.sh` derives per-instance defaults from `${SELFDEF_INSTANCE_ID}` | SDD-003 § D-4 + § Implementation status | F02113 | non-negotiable | false | 10 |
| R04135 | D-4 — `selfdef-<inst>` interface naming | SDD-003 § D-4 naming table | F02114 | non-negotiable | true | 10 |
| R04136 | D-4 — `/etc/wireguard/selfdef-<inst>.conf` WG conf | SDD-003 § D-4 naming table | F02115 | non-negotiable | true | 10 |
| R04137 | D-4 — `/etc/nftables.d/selfdef-vpn-bridge-<inst>.conf` nftables file | SDD-003 § D-4 naming table | F02116 | non-negotiable | true | 10 |
| R04138 | D-4 — `wg-quick@selfdef-<inst>.service` systemd unit | SDD-003 § D-4 naming table | F02117 | non-negotiable | true | 10 |
| R04139 | D-4 — `selfdef_vpn_bridge_<inst>` nftables table name | SDD-003 § Implementation status D-4 | F02118 | non-negotiable | true | 10 |
| R04140 | D-4 — `iface` default `selfdef-${SELFDEF_INSTANCE_ID:-0}` (single-instance stays `selfdef0`; multi-instance gets unique names) | SDD-003 § D-4 | F02119 | non-negotiable | false | 10 |
| R04141 | D-4 — Single-instance defaults unchanged when env var absent | SDD-003 § Implementation status D-4 | M00463 | non-negotiable | false | 10 |
| R04142 | D-4 — Symmetric updates in check.sh / uninstall.sh for relay-via-server | SDD-003 § D-4 | F02120 | non-negotiable | false | 10 |
| R04143 | D-4 — tailscale.sh `die` at top of `profile_apply` when `SELFDEF_INSTANCE_ID` set | SDD-003 § Implementation status D-4 | F02121 | non-negotiable | false | 10 |
| R04144 | D-4 — cloudflare-tunnel.sh `die` at top of `profile_apply` when `SELFDEF_INSTANCE_ID` set | SDD-003 § Implementation status D-4 | F02122 | non-negotiable | false | 10 |
| R04145 | D-4 — tailscale.sh `die` at top of `profile_uninstall` when `SELFDEF_INSTANCE_ID` set | SDD-003 § Implementation status D-4 | F02123 | non-negotiable | false | 10 |
| R04146 | D-4 — cloudflare-tunnel.sh `die` at top of `profile_uninstall` when `SELFDEF_INSTANCE_ID` set | SDD-003 § Implementation status D-4 | F02124 | non-negotiable | false | 10 |
| R04147 | D-4 defense-in-depth — redundant with D-2 resolver check but catches resolver bugs | SDD-003 § D-4 + § Risks R-3 | F02125 | non-negotiable | false | 10 |
| R04148 | Q-C — Linux interface names limited to 15 characters | SDD-003 § Q-C answer | F02126 | non-negotiable | false | 10 |
| R04149 | Q-C math — `selfdef-` prefix is 8 chars; max INST = 15-8 = 7 | SDD-003 § Q-C answer | F02127 | non-negotiable | false | 10 |
| R04150 | Q-C enforcement — apply.sh refuses cleanly with explicit operator-facing error when INST > 7 chars | SDD-003 § Q-C answer | F02128 | non-negotiable | false | 10 |
| R04151 | D-5 manifest — `[profiles.details.relay-via-server].instanced = true` in `modules/vpn-bridge/module.toml` | SDD-003 § D-5 + § Implementation status | F02129 | non-negotiable | true | 10 |
| R04152 | D-5 manifest — `[profiles.details.tailscale].instanced = false` in `modules/vpn-bridge/module.toml` | SDD-003 § D-5 + § Implementation status | F02130 | non-negotiable | true | 10 |
| R04153 | D-5 manifest — `[profiles.details.cloudflare-tunnel].instanced = false` in `modules/vpn-bridge/module.toml` | SDD-003 § D-5 + § Implementation status | F02131 | non-negotiable | true | 10 |
| R04154 | D-5 README — "Multi-instance support" section with capability table | SDD-003 § D-5 + § Implementation status | F02132 | non-negotiable | false | 10 |
| R04155 | D-5 README — per-instance naming convention documented | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04156 | D-5 README — migration notes documented | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04157 | D-5 profile config — `modules/vpn-bridge/profiles/relay-via-server.toml` comment references env var + naming convention | SDD-003 § D-5 | F02133 | non-negotiable | false | 10 |
| R04158 | D-5 CHANGELOG — migration note for hosts using multi-instance with relay-via-server + default `iface` (need to re-name + re-apply) | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04159 | D-5 migration — population affected by migration likely zero (multi-instance was silently broken before this SDD) | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04160 | Unit test — `profile_instanced_falls_back_to_module_default_when_unset` | SDD-003 § Implementation status Tests | F02135 | non-negotiable | true | 10 |
| R04161 | Unit test — `profile_instanced_per_profile_override_wins` | SDD-003 § Implementation status Tests | F02136 | non-negotiable | true | 10 |
| R04162 | Unit test — `resolver_rejects_instance_for_singleton_profile` | SDD-003 § Implementation status Tests | F02137 | non-negotiable | true | 10 |
| R04163 | Unit test — `resolver_accepts_instance_for_multi_instance_profile` | SDD-003 § Implementation status Tests | F02138 | non-negotiable | true | 10 |
| R04164 | Unit test — `resolver_falls_back_to_default_profile_when_config_missing` | SDD-003 § Implementation status Tests | F02139 | non-negotiable | true | 10 |
| R04165 | Integration test file — `crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs` | SDD-003 § Implementation status Tests | F02140 | non-negotiable | false | 10 |
| R04166 | Integration test — `relay_apply_with_instance_id_uses_per_instance_iface` | SDD-003 § Implementation status Tests | F02141 | non-negotiable | true | 10 |
| R04167 | Integration test — `relay_apply_without_instance_id_keeps_legacy_wg0_defaults` | SDD-003 § Implementation status Tests | F02142 | non-negotiable | true | 10 |
| R04168 | Integration test — `tailscale_apply_refuses_when_instance_id_is_set` | SDD-003 § Implementation status Tests | F02143 | non-negotiable | true | 10 |
| R04169 | Integration test — `cloudflare_apply_refuses_when_instance_id_is_set` | SDD-003 § Implementation status Tests | F02144 | non-negotiable | true | 10 |
| R04170 | Integration test — `cli_resolver_refuses_singleton_profile_with_instance_suffix` | SDD-003 § Implementation status Tests | F02145 | non-negotiable | true | 10 |
| R04171 | Test plan — `ModuleManifest` with `[profiles.details.<name>].instanced` deserializes | SDD-003 § Test plan 1 | M00470 | non-negotiable | false | 10 |
| R04172 | Test plan — profile not in `details` inherits module-level `instanced` | SDD-003 § Test plan 1 | M00470 | non-negotiable | false | 10 |
| R04173 | Test plan — `profile_instanced("nonexistent")` returns module-level value | SDD-003 § Test plan 1 | M00470 | non-negotiable | false | 10 |
| R04174 | Test plan — `selfdefctl modules apply --dry-run` exits non-zero on tailscale+instance suffix before invoking apply.sh | SDD-003 § Test plan 2 | M00471 | non-negotiable | false | 10 |
| R04175 | Test plan — relay-via-server with `SELFDEF_INSTANCE_ID=publish` writes to `selfdef-publish` paths | SDD-003 § Test plan 3 | M00471 | non-negotiable | false | 10 |
| R04176 | Test plan — Without instance id, writes to `selfdef0` (unchanged from today) | SDD-003 § Test plan 3 | M00471 | non-negotiable | false | 10 |
| R04177 | Test plan — Manifest test verifies `[profiles.details.*].instanced` values match Goal-1 contract | SDD-003 § Test plan 4 | M00471 | non-negotiable | false | 10 |
| R04178 | Rollout — single-instance deployments unchanged; SELFDEF_INSTANCE_ID unset; profile scripts behave as today | SDD-003 § Rollout / migration | F02146 | non-negotiable | false | 10 |
| R04179 | Rollout — multi-instance hosts running relay-via-server: assumed near-empty population (feature was nominal); migration note in CHANGELOG + README | SDD-003 § Rollout / migration | F02147 | non-negotiable | false | 10 |
| R04180 | Rollout — multi-instance hosts running tailscale or cloudflare-tunnel: apply now refuses cleanly; operators move to single instance per profile | SDD-003 § Rollout / migration | F02148 | non-negotiable | false | 10 |
| R04181 | Rollout — no daemon-binary changes (entirely selfdef-cli + manifest + shell-script change) | SDD-003 § Rollout / migration | F02149 | non-negotiable | false | 10 |
| R04182 | Risk R-1 — operators who deliberately worked around the multi-instance corruption (manual iface) lose their workaround | SDD-003 § Risks R-1 | F02150 | non-negotiable | false | 10 |
| R04183 | Risk R-1 mitigation — `SELFDEF_VPN_BRIDGE_WG_IFACE` override env var remains as operator escape hatch | SDD-003 § Risks R-1 | F02150 | non-negotiable | false | 10 |
| R04184 | Risk R-2 — per-profile `instanced` manifest extension is vpn-bridge-specific in practice for now | SDD-003 § Risks R-2 | F02151 | non-negotiable | false | 10 |
| R04185 | Risk R-2 mitigation — kept optional + invisible to single-profile modules | SDD-003 § Risks R-2 | F02151 | non-negotiable | false | 10 |
| R04186 | Risk R-3 — defensive `die` in tailscale/cloudflare profile scripts is dead code in normal apply path | SDD-003 § Risks R-3 | F02152 | non-negotiable | false | 10 |
| R04187 | Risk R-3 justification — two lines, costs nothing, catches resolver bugs | SDD-003 § Risks R-3 | F02152 | non-negotiable | false | 10 |
| R04188 | Q-A — per-profile metadata table extensibility, Answered (D-014, 2026-05-15) — out of scope for SDD-003; schema in D-1 is already extensible | SDD-003 § Open questions Q-A answer | F02153 | non-negotiable | false | 10 |
| R04189 | Q-B — resolver error message includes suggested fix, Answered (D-015, 2026-05-15) — yes; tracked as implementation-PR follow-up | SDD-003 § Open questions Q-B answer | F02154 | non-negotiable | false | 10 |
| R04190 | Q-C IFNAMSIZ — Answered (D-005, 2026-05-15): apply.sh refuses cleanly when INST > 7 chars | SDD-003 § Q-C answer | F02128 | non-negotiable | false | 10 |
| R04191 | Appendix — interaction with SDD-002 forward-compatible (future profile needing daemon-side state declares `[daemon_requires]` under per-profile-details table) | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04192 | Phase-2 follow-up F-2027-001 — original refusal message was prose-only | SDD-003 § Follow-up findings | F02156 | non-negotiable | false | 10 |
| R04193 | Phase-2 follow-up F-2027-001 — Phase 2 PR #57 replaced with copy-pasteable `[profiles.details.<profile>]\ninstanced = true\n` TOML stanza embedded in diagnostic | SDD-003 § Follow-up findings | F02159 | non-negotiable | false | 10 |
| R04194 | Phase-2 follow-up F-2027-025 — `_relay_inst_defaults` in `modules/vpn-bridge/install/profiles/relay-via-server.sh` interpolated $SELFDEF_INSTANCE_ID into nftables table names without safe_name validator | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04195 | Phase-2 follow-up F-2027-025 — Phase 2 PR #64 added `safe_name "$INST" || die …` guard | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04196 | Phase-2 follow-up F-2027-025 background — operator-controlled string today; safe_name is defense-in-depth | SDD-003 § Follow-up findings | F02158 | non-negotiable | false | 10 |
| R04197 | safe_name validator lives in `install/lib.sh` (shared module-script library) | SDD-003 § Follow-up findings | M00472 | non-negotiable | false | 10 |
| R04198 | Closes F-2027-045 phase-2 nice-cluster (F-2027-001 + F-2027-025 closed in tree) | SDD-003 § Follow-up findings | M00472 | non-negotiable | false | 10 |
| R04199 | Integration with MS001 daemon core — selfdefctl modules apply lifecycle hosts vpn-bridge install | MS001 + SDD-003 | E0181 | non-negotiable | false | 10 |
| R04200 | Integration with MS006 — vpn-bridge is one of 14 functional modules | MS006 + `modules/vpn-bridge/module.toml` | M00451 | non-negotiable | false | 10 |
| R04201 | Integration with MS009 audit cycles — phase-6/40-module-audit covers vpn-bridge multi-instance contract | MS009 phase-6 40-module-audit | E0181 | non-negotiable | false | 10 |
| R04202 | Integration with MS010 hardware-aware modules — vpn-bridge does NOT require special hardware; manifest [requires_hardware] empty | MS010 + `modules/vpn-bridge/module.toml` | M00455 | non-negotiable | false | 10 |
| R04203 | Integration with MS012 perimeter coexistence — vpn-bridge does NOT author Tetragon TracingPolicies; nftables-only | MS012 + `modules/vpn-bridge/install/profiles/` | M00448 | non-negotiable | false | 10 |
| R04204 | Integration with MS013 27-SDD charter — SDD-003 is one of the foundational 10 SDDs (000-009) per MS013 R03012 | MS013 + SDD-003 | E0181 | non-negotiable | false | 10 |
| R04205 | Integration with MS016 eBPF + Tetragon — vpn-bridge events flow into selfdef-collector-eventstream via OCSF logs | MS016 + `modules/vpn-bridge/` | E0181 | non-negotiable | false | 10 |
| R04206 | Project boundary — vpn-bridge multi-instance is selfdef-scope only; sovereign-os MAY consume events via NATS bridge MS015 with mTLS | architecture + MS015 + MS007 + SDD-038 | E0181 | non-negotiable | false | 10 |
| R04207 | Module manifest schema — `[profiles]` block grows `details: BTreeMap<String, ProfileDetails>` field | SDD-003 § D-1 | M00455 | non-negotiable | false | 10 |
| R04208 | Module manifest schema — `[profiles.details.<profile-name>]` table per profile in `available` | SDD-003 § D-1 | M00457 | non-negotiable | false | 10 |
| R04209 | Module manifest schema — `[profiles.details.<name>].instanced` is Option<bool> | SDD-003 § D-1 | F02102 | non-negotiable | false | 10 |
| R04210 | Module manifest schema — Module-level `instanced=true` means "at least one profile is instance-capable" | SDD-003 § D-1 | F02105 | non-negotiable | false | 10 |
| R04211 | Module manifest schema — Profiles not listed in details inherit module-level `instanced` | SDD-003 § D-1 | F02106 | non-negotiable | false | 10 |
| R04212 | Resolver check — fires post-resolve before any apply.sh spawn | SDD-003 § D-2 | F02107 | non-negotiable | false | 10 |
| R04213 | Resolver check — iterates active instances with `instance_id.is_some()` | SDD-003 § D-2 | M00459 | non-negotiable | false | 10 |
| R04214 | Resolver check — for each instance with suffix, reads per-instance config to discover chosen profile | SDD-003 § D-2 | M00459 | non-negotiable | false | 10 |
| R04215 | Resolver check — uses `manifest.profile_instanced(&profile)` helper | SDD-003 § D-2 | F02103 | non-negotiable | false | 10 |
| R04216 | Resolver check — bails with error format `module '<slug>' profile '<profile>' does not support multi-instance (host key '<slug>#<inst>' cannot be applied)` | SDD-003 § D-2 | F02110 | non-negotiable | false | 10 |
| R04217 | Resolver check — operator sees clean refusal rather than partial apply state | SDD-003 § D-2 | F02107 | non-negotiable | false | 10 |
| R04218 | Env-var contract — `SELFDEF_INSTANCE_ID=<inst>` passed by `run_one` when `active.instance.is_some()` | SDD-003 § D-3 + § Implementation status | F02111 | non-negotiable | false | 10 |
| R04219 | Env-var contract — single-instance deployments don't see SELFDEF_INSTANCE_ID (instance=None) | SDD-003 § D-3 | F02112 | non-negotiable | false | 10 |
| R04220 | Env-var contract — no behaviour change for legacy single-instance deployments | SDD-003 § D-3 | F02112 | non-negotiable | false | 10 |
| R04221 | Profile script — `relay-via-server.sh` `iface` default becomes `selfdef-${SELFDEF_INSTANCE_ID:-0}` | SDD-003 § D-4 | F02119 | non-negotiable | false | 10 |
| R04222 | Profile script — single-instance case stays `selfdef0`; multi-instance gets unique names | SDD-003 § D-4 | F02119 | non-negotiable | false | 10 |
| R04223 | Profile script — `tailscale.sh` `die` at top of `profile_apply` when SELFDEF_INSTANCE_ID set | SDD-003 § D-4 + § Implementation status | F02121 | non-negotiable | false | 10 |
| R04224 | Profile script — `tailscale.sh` `die` at top of `profile_uninstall` when SELFDEF_INSTANCE_ID set | SDD-003 § Implementation status D-4 | F02123 | non-negotiable | false | 10 |
| R04225 | Profile script — `cloudflare-tunnel.sh` `die` at top of `profile_apply` when SELFDEF_INSTANCE_ID set | SDD-003 § D-4 + § Implementation status | F02122 | non-negotiable | false | 10 |
| R04226 | Profile script — `cloudflare-tunnel.sh` `die` at top of `profile_uninstall` when SELFDEF_INSTANCE_ID set | SDD-003 § Implementation status D-4 | F02124 | non-negotiable | false | 10 |
| R04227 | Profile script — defense-in-depth `die` message: "profile '<name>' does not support multi-instance (set instanced=false in module.toml profiles.details)" | SDD-003 § D-4 | F02121 + F02122 | non-negotiable | false | 10 |
| R04228 | Per-instance state path — WG interface `selfdef-${INST}` | SDD-003 § D-4 | F02114 | non-negotiable | true | 10 |
| R04229 | Per-instance state path — WG conf `/etc/wireguard/selfdef-${INST}.conf` | SDD-003 § D-4 | F02115 | non-negotiable | true | 10 |
| R04230 | Per-instance state path — nftables file `/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf` | SDD-003 § D-4 | F02116 | non-negotiable | true | 10 |
| R04231 | Per-instance state path — systemd unit `wg-quick@selfdef-${INST}.service` | SDD-003 § D-4 | F02117 | non-negotiable | true | 10 |
| R04232 | Per-instance state path — nftables table name `selfdef_vpn_bridge_<inst>` | SDD-003 § Implementation status D-4 | F02118 | non-negotiable | true | 10 |
| R04233 | Per-instance state path — INST length limited to 7 characters | SDD-003 § Q-C answer | F02127 | non-negotiable | false | 10 |
| R04234 | Per-instance state path — apply.sh refuses cleanly with explicit operator-facing error when INST > 7 chars | SDD-003 § Q-C answer | F02128 | non-negotiable | false | 10 |
| R04235 | Per-instance state path — defense-in-depth via safe_name validator (F-2027-025) on $INST for nftables table names | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04236 | Single-instance default — selfdef0 / /etc/wireguard/selfdef0.conf / /etc/nftables.d/selfdef-vpn-bridge.conf / wg-quick@selfdef0.service | SDD-003 § D-4 naming table | M00463 | non-negotiable | false | 10 |
| R04237 | Single-instance default — unchanged from pre-SDD-003 behavior | SDD-003 § D-4 | M00463 | non-negotiable | false | 10 |
| R04238 | Manifest content — `[profiles.details.relay-via-server].instanced = true` | SDD-003 § Implementation status D-5 | F02129 | non-negotiable | true | 10 |
| R04239 | Manifest content — `[profiles.details.tailscale].instanced = false` | SDD-003 § Implementation status D-5 | F02130 | non-negotiable | true | 10 |
| R04240 | Manifest content — `[profiles.details.cloudflare-tunnel].instanced = false` | SDD-003 § Implementation status D-5 | F02131 | non-negotiable | true | 10 |
| R04241 | README content — "Multi-instance support" section | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04242 | README content — capability table per profile | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04243 | README content — per-instance naming convention | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04244 | README content — migration notes | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04245 | profiles/relay-via-server.toml — comment block references env var | SDD-003 § D-5 | F02133 | non-negotiable | false | 10 |
| R04246 | profiles/relay-via-server.toml — comment block references naming convention | SDD-003 § D-5 | F02133 | non-negotiable | false | 10 |
| R04247 | CHANGELOG — migration note for any hosts using multi-instance with relay-via-server default `iface` | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04248 | CHANGELOG — migration step is re-name to `selfdef-${inst}` + re-apply | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04249 | CHANGELOG — population affected by migration likely zero | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04250 | Module manifest test — `vpn-bridge`'s `module.toml` after SDD lands has `[profiles.details.relay-via-server].instanced = true` | SDD-003 § Test plan 4 | F02129 | non-negotiable | false | 10 |
| R04251 | Module manifest test — `vpn-bridge`'s `module.toml` after SDD lands has `[profiles.details.tailscale].instanced = false` | SDD-003 § Test plan 4 | F02130 | non-negotiable | false | 10 |
| R04252 | Module manifest test — `vpn-bridge`'s `module.toml` after SDD lands has `[profiles.details.cloudflare-tunnel].instanced = false` | SDD-003 § Test plan 4 | F02131 | non-negotiable | false | 10 |
| R04253 | Doctrine — manifest contract honesty (manifest declares what implementation actually delivers) | SDD-003 § Goals 1 | F02060 | non-negotiable | false | 10 |
| R04254 | Doctrine — per-profile capability is the canonical way to express mixed-instance modules | SDD-003 § Recommended design | F02074 | non-negotiable | false | 10 |
| R04255 | Doctrine — single-instance default unchanged means existing operators don't have to migrate | SDD-003 § Goals 5 + § Rollout | F02064 | non-negotiable | false | 10 |
| R04256 | Doctrine — defense-in-depth (resolver check + profile script die) catches resolver bugs | SDD-003 § D-4 + § Risks R-3 | F02125 | non-negotiable | false | 10 |
| R04257 | Doctrine — manifest schema extensions remain optional + invisible to single-profile modules | SDD-003 § Risks R-2 | F02151 | non-negotiable | false | 10 |
| R04258 | Doctrine — operator escape hatches preserved (SELFDEF_VPN_BRIDGE_WG_IFACE) so workarounds don't break | SDD-003 § Risks R-1 | F02150 | non-negotiable | false | 10 |
| R04259 | Doctrine — resolver refuses BEFORE apply.sh spawn so operator sees clean error not partial apply state | SDD-003 § D-2 | F02107 | non-negotiable | false | 10 |
| R04260 | Doctrine — per-profile capability is forward-compatible with future fields (per-profile phase / per-profile requires) per Q-A | SDD-003 § Open questions Q-A answer | F02153 | non-negotiable | false | 10 |
| R04261 | Doctrine — Alternative D (split into three modules) remains future-available once shared module lib (F-2026-081) reduces duplication cost | SDD-003 § Recommended design | F02098 | non-negotiable | false | 10 |
| R04262 | Doctrine — operator-ergonomics matters (F-2027-001 refusal-message TOML stanza is a Phase-2 nice-cluster fix) | SDD-003 § Follow-up findings | F02159 | non-negotiable | false | 10 |
| R04263 | Doctrine — operator-controlled inputs validated with safe_name from shared lib (F-2027-025 defense-in-depth pattern) | SDD-003 § Follow-up findings | F02158 | non-negotiable | false | 10 |
| R04264 | Module manifest field — `instanced=true` at module level (vpn-bridge already declared) | `modules/vpn-bridge/module.toml` + SDD-003 § Current state | E0182 | non-negotiable | false | 10 |
| R04265 | Module manifest field — `[profiles].available = ["relay-via-server", "tailscale", "cloudflare-tunnel"]` | SDD-003 § Current state vpn-bridge manifest | E0182 | non-negotiable | false | 10 |
| R04266 | Resolver behavior — `crates/selfdef-cli/src/modules.rs:404-435` `resolve_active` function | SDD-003 § Current state Resolver behaviour | F02048 | non-negotiable | false | 10 |
| R04267 | Resolver behavior — accepts `slug#instance` host-config keys (when `instanced=true`) | SDD-003 § Current state Resolver behaviour | F02048 | non-negotiable | false | 10 |
| R04268 | Resolver behavior — constructs per-instance config path (`vpn-bridge.<inst>.toml`) | SDD-003 § Current state Resolver behaviour | F02048 | non-negotiable | false | 10 |
| R04269 | Resolver behavior — refuses to mix flat (`[modules.vpn-bridge]`) and instanced (`[modules."vpn-bridge#a"]`) keys for same slug | SDD-003 § Current state Resolver behaviour | F02048 | non-negotiable | false | 10 |
| R04270 | Resolver behavior — iterates each instance in turn calling its apply.sh | SDD-003 § Current state Resolver behaviour | F02048 | non-negotiable | false | 10 |
| R04271 | Per-instance config passing — `crates/selfdef-cli/src/modules.rs:737-739` script invocation | SDD-003 § Current state Per-instance config passing | F02111 | non-negotiable | false | 10 |
| R04272 | Per-instance config passing — script gets `SELFDEF_VPN_BRIDGE_CONFIG` pointing at per-instance config file | SDD-003 § Current state Per-instance config passing | E0187 | non-negotiable | false | 10 |
| R04273 | Per-instance config passing — script can recover instance id by parsing config filename (vpn-bridge.<inst>.toml) | SDD-003 § Current state Per-instance config passing | F02082 | non-negotiable | false | 10 |
| R04274 | Cross-repo binding — vpn-bridge profiles do not currently require any daemon-side config | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04275 | Cross-repo binding — daemon does not ingest vpn-bridge state | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04276 | Cross-repo binding — future profile needing daemon-side state would declare `[daemon_requires]` under same per-profile-details table | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04277 | Cross-repo binding — schema is forward-compatible (per Appendix's interaction with SDD-002) | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04278 | Project boundary — vpn-bridge multi-instance capability is selfdef-scope; sovereign-os does NOT author vpn-bridge profiles | architecture + MS012 | E0181 | non-negotiable | false | 10 |
| R04279 | Project boundary — sovereign-os MAY observe vpn-bridge events via NATS bridge MS015 with mTLS | MS015 + MS007 + SDD-038 | R04206 | non-negotiable | false | 10 |
| R04280 | Project boundary — cross-repo binding via MS007 typed-mirror crates (NOT direct selfdef-cli import) | MS007 + SDD-038 | R04206 | non-negotiable | false | 10 |
| R04281 | F-2027-001 follow-up — error message includes copy-pasteable TOML stanza | SDD-003 § Follow-up findings | F02159 | non-negotiable | false | 10 |
| R04282 | F-2027-001 follow-up — example stanza `[profiles.details.<profile>]\ninstanced = true\n` | SDD-003 § Follow-up findings | F02159 | non-negotiable | false | 10 |
| R04283 | F-2027-001 follow-up — embedded directly in diagnostic | SDD-003 § Follow-up findings | F02159 | non-negotiable | false | 10 |
| R04284 | F-2027-001 closed in tree via PR #57 | SDD-003 § Follow-up findings | F02156 | non-negotiable | false | 10 |
| R04285 | F-2027-025 follow-up — _relay_inst_defaults function interpolated $SELFDEF_INSTANCE_ID into nftables table names | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04286 | F-2027-025 follow-up — without `safe_name` validator from `install/lib.sh` | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04287 | F-2027-025 follow-up — Phase 2 PR #64 added `safe_name "$INST" || die …` guard | SDD-003 § Follow-up findings | F02157 | non-negotiable | false | 10 |
| R04288 | F-2027-025 background — operator-controlled string today | SDD-003 § Follow-up findings | F02158 | non-negotiable | false | 10 |
| R04289 | F-2027-025 background — safe_name is defense-in-depth | SDD-003 § Follow-up findings | F02158 | non-negotiable | false | 10 |
| R04290 | F-2027-045 phase-2 nice-cluster closed (F-2027-001 + F-2027-025 closed in tree) | SDD-003 § Follow-up findings | M00472 | non-negotiable | false | 10 |
| R04291 | Phase-2 nice-cluster — pattern for operator-ergonomics + defense-in-depth follow-ups against shipping SDDs | SDD-003 § Follow-up findings | M00472 | non-negotiable | false | 10 |
| R04292 | Future SDD — splitting vpn-bridge into three modules (vpn-bridge-relay / -tailscale / -cloudflare) | SDD-003 § Non-goals + § Recommended design | M00454 | non-negotiable | false | 10 |
| R04293 | Future SDD — per-profile-details extensibility (per-profile `phase` overrides, per-profile `requires`) per Q-A | SDD-003 § Open questions Q-A answer | F02153 | non-negotiable | false | 10 |
| R04294 | Future SDD — cloudflare-tunnel multi-instance via per-instance systemd unit generation | SDD-003 § Non-goals | E0184 | non-negotiable | false | 10 |
| R04295 | Audit-cycle integration — MS009 phase-6 40-module-audit covers vpn-bridge multi-instance contract | MS009 phase-6 40-module-audit + SDD-003 | E0181 | non-negotiable | false | 10 |
| R04296 | Audit-cycle integration — MS009 phase-7 50-integration-audit covers vpn-bridge multi-instance end-to-end | MS009 phase-7 50-integration-audit + SDD-003 | E0181 | non-negotiable | false | 10 |
| R04297 | Audit-cycle integration — phase-6 60-docs-audit covers SDD-003 against charter style rules (MS013) | MS009 phase-6 60-docs-audit + MS013 | E0181 | non-negotiable | false | 10 |
| R04298 | Audit-cycle integration — phase-6 70-tests-audit covers 5 unit tests + 5 integration tests | MS009 phase-6 70-tests-audit | M00470 + M00471 | non-negotiable | false | 10 |
| R04299 | Audit-cycle integration — phase-6 80-security-audit covers safe_name defense-in-depth on operator-controlled $INST | MS009 phase-6 80-security-audit + F-2027-025 | F02158 | non-negotiable | false | 10 |
| R04300 | Audit-cycle integration — findings ledger F-2026-NNN records vpn-bridge multi-instance manifest contract violations | MS009 99-findings-ledger | F02046 | non-negotiable | false | 10 |
| R04301 | Module bundle convention — modules with multiple profiles MAY declare per-profile instanced via `[profiles.details.<name>].instanced` | SDD-003 § D-1 | M00457 | non-negotiable | false | 10 |
| R04302 | Module bundle convention — single-profile modules don't need [profiles.details] table (module-level instanced suffices) | SDD-003 § D-1 | F02151 | non-negotiable | false | 10 |
| R04303 | Module bundle convention — module-level `instanced=true` is preserved across SDD-003 (semantics shifted from "all profiles" to "at least one profile") | SDD-003 § D-1 | F02105 | non-negotiable | false | 10 |
| R04304 | Module bundle convention — resolver verifies declared profile capability before apply.sh runs | SDD-003 § D-2 | F02107 | non-negotiable | false | 10 |
| R04305 | Module bundle convention — dispatcher passes `SELFDEF_INSTANCE_ID` env var when instance suffix present | SDD-003 § D-3 | F02111 | non-negotiable | false | 10 |
| R04306 | Module bundle convention — profile scripts read `SELFDEF_INSTANCE_ID` to parameterise state paths | SDD-003 § D-4 | F02113 | non-negotiable | false | 10 |
| R04307 | Module bundle convention — non-multi-instance profiles `die` if `SELFDEF_INSTANCE_ID` is set (defense-in-depth) | SDD-003 § D-4 + § Risks R-3 | F02125 | non-negotiable | false | 10 |
| R04308 | Module bundle convention — manifest content declares per-profile instanced explicitly | SDD-003 § D-5 | F02129 + F02130 + F02131 | non-negotiable | false | 10 |
| R04309 | Module bundle convention — README documents multi-instance support including capability table + naming convention + migration notes | SDD-003 § D-5 | F02132 | non-negotiable | false | 10 |
| R04310 | Module bundle convention — profile config files comment-reference env var + naming convention | SDD-003 § D-5 | F02133 | non-negotiable | false | 10 |
| R04311 | Module bundle convention — CHANGELOG carries migration notes for any breaking changes (even if affected population is near-zero) | SDD-003 § D-5 | F02134 | non-negotiable | false | 10 |
| R04312 | Module bundle convention — unit tests cover manifest deserialization + helper fallback + resolver gate | SDD-003 § Test plan | M00470 | non-negotiable | false | 10 |
| R04313 | Module bundle convention — integration tests cover apply with + without instance id; refusal cases for non-multi-instance profiles | SDD-003 § Test plan + § Implementation status | M00471 | non-negotiable | false | 10 |
| R04314 | Module bundle convention — Phase-2 follow-ups address operator-ergonomics + defense-in-depth (F-2027-001 + F-2027-025 pattern) | SDD-003 § Follow-up findings | M00472 | non-negotiable | false | 10 |
| R04315 | Module bundle convention — manifest schema is forward-compatible (Appendix's interaction with SDD-002) | SDD-003 § Appendix | F02155 | non-negotiable | false | 10 |
| R04316 | Module bundle convention — Alternative B per-profile capability is the canonical pattern for future mixed-instance modules | SDD-003 § Recommended design | F02074 | non-negotiable | false | 10 |
| R04317 | Module bundle convention — Alternative D (split into multiple modules) is preferred ONLY when shared lib reduces duplication cost first | SDD-003 § Recommended design | F02098 | non-negotiable | false | 10 |
| R04318 | Composite — SDD-003 ships D-1..D-5 + 5 unit tests + 5 integration tests + 2 phase-2 follow-ups (F-2027-001 + F-2027-025); F-2026-005 closed; relay-via-server multi-instance is real feature; tailscale + cloudflare-tunnel refuse cleanly; single-instance deployments unaffected; per-profile-details manifest schema is canonical pattern for future mixed-instance modules; Q-C IFNAMSIZ limit 7 chars enforced; safe_name validator on $INST; manifest schema is forward-compatible | SDD-003 entire | F02160 | non-negotiable | false | 10 |
| R04319 | Composite — vpn-bridge multi-instance closes M-008 phase-1 ledger blocker by making manifest contract honest (per-profile capability + resolver gate + dispatcher env var + profile script parameterisation + defense-in-depth `die` + documentation + tests + 2 phase-2 follow-ups); manifest's `instanced=true` no longer "a lie by surface" | SDD-003 § Problem + entire | F02160 | non-negotiable | false | 10 |
| R04320 | Composite — MS018 covers SDD-003 implementation + tests + phase-2 follow-ups; integrates with MS001 daemon core / MS006 14 functional modules / MS009 audit cycles / MS013 27-SDD charter / MS015 NATS messaging / MS016 eBPF + Tetragon; project boundary preserved (selfdef-scope; cross-repo binding via NATS + MS007 typed mirrors only) | INDEX.md MS018 + SDD-003 + MS001-MS017 | E0181 + E0182 + E0183 + E0184 + E0185 + E0186 + E0187 + E0188 + E0189 + E0190 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS017: 23520 + 2400 = 25920 sub-requirements when MS018 lands

## Cross-references

- SDD source: `docs/sdd/003-vpn-bridge-multi-instance.md` (647 lines; status=implemented; closes F-2026-005)
- Module root: `modules/vpn-bridge/` (module.toml + README.md + install/{apply,check,uninstall,lib,profiles/{relay-via-server,tailscale,cloudflare-tunnel}.sh} + config/ + profiles/ + templates/)
- Implementation crate: `crates/selfdef-cli/src/modules.rs` (ProfileSpec + ProfileDetails + resolve_active + run_one)
- Integration test: `crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs` (5 tests)
- Phase-2 follow-ups: F-2027-001 (PR #57; refusal-message TOML stanza) + F-2027-025 (PR #64; safe_name validator); both closed in tree per F-2027-045
- Sister milestones: MS006 14 functional modules (vpn-bridge is one) / MS013 27-SDD charter (SDD-003 is foundational 000-009 layer) / MS021 shared module-script lib (F-2026-081 reduces duplication cost for future Alternative D splits)
- Forward-compat: SDD-002 `[daemon_requires]` extends `[profiles.details.<name>]` table (per SDD-003 Appendix)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (sovereign-os reads vpn-bridge events via NATS subscription with mTLS; NOT crate import)
