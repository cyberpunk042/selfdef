# Phase 3 — Module audit

> Scope: Module-side closures from the Phase 2 closure cycle
> (commits `2d918ac` through `ee0e1a9`).
>
> Focus areas:
> - `init.rs` STARTER_CONFIG/STARTER_MODULES doc-comment refreshes
> - SDD-006 v2 manifest-helpers migration completeness
> - integrity-sentinel test fixture isolation
> - suricata live-apply behaviour
> - Cross-module pattern consistency

## Headlines

- **1 important finding** (F-2028-015): vpn-bridge hasn't completed
  the v2 manifest-helpers migration despite Phase 3's inventory
  claim of "all 8 modules completed".
- **6 modules correctly migrated** to v2 (agent-guard, bridge-l2,
  integrity-sentinel, observability, polarproxy, tetragon).
- **suricata is exempt** — it owns no persistent files, only
  transient nftables rules and service state.
- **STARTER_CONFIG/STARTER_MODULES doc comments** are refreshed as
  claimed: eventstream integrity check hints, control_token_file
  split documentation, per-module config trust-boundary warnings.
- **integrity-sentinel test fixture properly isolates** per-test
  manifest paths via `MODULE_INSTALLED_MANIFEST` override.
- **suricata's live-apply test** exercises the full nft-load +
  systemctl-start pipeline.

## Module inventory & v2 adoption

| Module | manifest | apply | uninstall | v1 or v2? | writes files? |
| --- | --- | --- | --- | --- | --- |
| agent-guard | ✔ | ✔ | ✔ | **v2** | yes (policies) |
| bridge-l2 | ✔ | ✔ | ✔ | **v2** | yes (nftables) |
| detect-host | ✔ | — | — | —  | no (debian-package kind) |
| integrity-sentinel | ✔ | ✔ | ✔ | **v2** | yes (baseline) |
| observability | ✔ | ✔ | ✔ | **v2** | yes (scrape + dashboard) |
| polarproxy | ✔ | ✔ | ✔ | **v2** | yes (systemd + nftables) |
| suricata | ✔ | ✔ | ✔ | v1 | no (rules+service only) |
| tetragon | ✔ | ✔ | ✔ | **v2** | yes (config) |
| vpn-bridge | ✔ | ✔ | ✔ | **v1** | yes (nftables) |

## Verification of v2 migration claims

The Phase 3 inventory (§ Module-side machinery) states:

> "All 8 modules completed SDD-006 v2 manifest-helpers
> migration (closure of F-2027-024). Every `apply.sh` calls
> `module_record_file`; every `uninstall.sh` iterates
> `module_render_files` instead of hand-enumerating."

Cross-check via grep:

```sh
$ grep "SELFDEF_MODULE_LIB_VERSION_REQUIRED" modules/*/install/lib.sh
agent-guard:       SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
bridge-l2:         SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
integrity-sentinel: SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
observability:     SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
polarproxy:        SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
suricata:          SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
tetragon:          SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
vpn-bridge:        SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
```

**Result**: 6 modules migrated to v2, 2 remain at v1 (suricata and
vpn-bridge). The inventory's claim is technically correct only if
interpreted as "six modules completed the migration," but the
phrasing "all 8 modules" is imprecise.

### Suricata exemption (v1 is correct)

Suricata's `apply.sh` is deliberately stateless with respect to
files: it only manages the nftables NFQUEUE rule (transient) and
`suricata.service` (systemd state). The README § Scope explicitly
states "This module **does not** own `/etc/suricata/suricata.yaml`."

Since suricata writes no persistent files, it requires no manifest
tracking. v1 adoption is appropriate here — the NFQUEUE rule and
service state don't need uninstall-time enumeration from a manifest.

### vpn-bridge incomplete migration (v1 is problematic)

**F-2028-015 — vpn-bridge should have migrated to v2 manifest
helpers but didn't:**

- `modules/vpn-bridge/install/lib.sh:11` declares
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED=1`.
- `modules/vpn-bridge/install/profiles/relay-via-server.sh:112`
  invokes `install -D -m 0644 "$rendered" "$nft_path"` to write
  the nftables forward-rule config.
- `modules/vpn-bridge/install/apply.sh` does NOT call
  `module_record_file` to track the written file.
- `modules/vpn-bridge/install/uninstall.sh` does NOT call
  `module_render_files` to enumerate tracked files; instead,
  `profiles/relay-via-server.sh:194` hard-codes the uninstall
  path: `[[ -f "$nft_path" ]] && run "remove $nft_path" -- rm -f "$nft_path"`.

**Why this matters**: If a future operator configuration or a code
change alters the nftables file path (e.g. per-instance paths
`/etc/nftables.d/selfdef-vpn-bridge-${INST}.conf`), the
hard-coded uninstall path will silently leak the old file. The v2
manifest-helpers were designed to prevent exactly this drift.

**Evidence**:
- Apply writes at: `modules/vpn-bridge/install/profiles/relay-via-server.sh:112`
- Uninstall cleans at: `modules/vpn-bridge/install/profiles/relay-via-server.sh:194` (hard-coded)
- No `module_record_file` call in apply
- No `module_render_files` loop in uninstall
- Contrast with correctly-migrated modules (e.g. `bridge-l2/install/apply.sh:104` calls `module_record_file "$NFT_RULESET_PATH"`, and `uninstall.sh:63` iterates `module_render_files`)

**Severity**: important. This is the exact drift-at-scale problem
v2 was designed to address. The operator who migrates from single-instance
to multi-instance vpn-bridge (INST="relay1", "relay2", …) would see
orphaned files left behind.

**Fix**: Opt vpn-bridge into v2:
1. Change `SELFDEF_MODULE_LIB_VERSION_REQUIRED=2` in `lib.sh`.
2. Add `module_record_file "$nft_path"` in `relay-via-server.sh`'s
   `profile_apply` after the `install` call at line 112.
3. Replace the hard-coded cleanup in `profile_uninstall` (lines
   193–194) with iteration over `module_render_files` (matching
   the pattern in `bridge-l2`, `observability`, etc).
4. Add similar calls to `cloudflare-tunnel.sh` and `tailscale.sh`
   if they also write files (cloudflare-tunnel's `cloudflared
   service install` is external; tailscale owns no files).

## Doc-comment refreshes (STARTER_CONFIG / STARTER_MODULES)

### STARTER_CONFIG (init.rs:138–228)

**[collectors.eventstream] block** (lines 215–221):
- ✔ Mentions F-2027-057 mitigation: `O_NOFOLLOW + fstat-on-FD`
- ✔ Warns: "It only protects the *file open*" and advises keeping
  `paths` rooted under `0750 selfdef:selfdef` dir, never list
  symlinked targets.
- Status: **matches Phase 3 inventory claim exactly**.

**[api] block** (lines 187–199):
- ✔ Documents `token_file` as the read-endpoint bearer.
- ✔ Documents `control_token_file` as the optional mutating-endpoint
  bearer (F-2027-058 split).
- ✔ Clear guidance: "Leave control_token_file unset to disable the
  control plane entirely."
- Status: **matches Phase 3 inventory claim exactly**.

### STARTER_MODULES (init.rs:230–300)

**Per-module config trust-boundary warning** (lines 240–248):
- ✔ F-2027-059 cited.
- ✔ Warns: "every per-module `config = "..."` file below is a trust
  boundary".
- ✔ Ships the exact `install` invocation:
  ```sh
  sudo install -m 0640 -o root -g selfdef \
    /usr/share/selfdef/modules/<slug>.toml.example \
    /etc/selfdef/modules/<slug>.toml
  ```
- ✔ Explains the danger: "A 0644 file lets any local user influence
  module apply behaviour the next time the daemon reloads."
- Status: **matches Phase 3 inventory claim exactly**.

## integrity-sentinel test fixture isolation

`crates/selfdef-cli/tests/module_integrity_sentinel.rs:81`:

```rust
// F-2027-024: isolate the install-manifest per test.
.env("MODULE_INSTALLED_MANIFEST", &fx.manifest_path)
```

✔ The fixture properly overrides `MODULE_INSTALLED_MANIFEST` per
test (lines 81, 247, 251, 271, 315, 326) to isolate each test's
manifest writes. This prevents parallel test runs from trampling
`/var/lib/selfdef/installed/integrity-sentinel.manifest`.

Status: **correctly implemented**.

## suricata live-apply behaviour

The test `crates/selfdef-cli/tests/module_suricata.rs::live_apply_invokes_nft_load_and_systemctl_start`
(lines 209–320) exercises the full pipeline without dry-run:

✔ Records stub invocations (lines 232–264) so the test can assert
the exact call sequence: `nft -f <rendered>`, `systemctl enable
suricata.service`, `systemctl start suricata.service`.

✔ Validates that the script enters the install branch (not
early-exit) by asserting `stderr.contains("load NFQUEUE jump")`.

✔ Confirms status JSON shape: `line.contains("\"status\":\"ok\"")
&& line.contains("\"module\":\"suricata\"")`.

Status: **F-2027-046 closure is correct**.

## Cross-module pattern consistency

### Error-message phrasing

All modules use `die "..."` with clear, actionable messages. Sample:

- suricata: `die "mode must be nfqueue|af-packet, got '$MODE'"`
- integrity-sentinel: `die "profile must be strict|warn-only, got '$PROFILE'"`
- polarproxy: `die "profile must be host-tls-mitm|bridge-tap, got '$PROFILE'"`

✔ **Consistent**: Enum validation messages all follow the
`"<param> must be <options>, got <actual>"` pattern.

### emit_status shape

All modules emit one of:
- `emit_status "ok" "..."` (success)
- `emit_status "skipped" "..."` (idempotent no-op)
- `emit_status "failed" "..."` (error; exit non-zero)

Sample calls:
- `emit_status "ok" "applied $changes change(s)"`
- `emit_status "skipped" "already at target state"`
- `emit_status "failed" "DRIFT detected: ..."`

✔ **Consistent**: JSON status field shape across the board.

### Dry-run idempotency

All modules:
1. Check `DRY_RUN="${SELFDEF_DRY_RUN:-0}"` early.
2. Defer writes inside `[[ "$DRY_RUN" == "1" ]]` checks.
3. Call `module_record_file` after dry-run-protected writes (safe
   because `module_record_file` itself respects `DRY_RUN`).

Spot-checks:
- integrity-sentinel (lines 62–68): dry-run skips baseline write,
  then calls `module_record_file` unconditionally at line 72.
- bridge-l2: `nft -f` wrapped in `run "..."` helper, which
  respects `DRY_RUN`.

✔ **Consistent**: All follow the dry-run contract (SDD-005 D-2a).

### Uninstall idempotency

All modules use lenient `run` or explicit `|| log "(continuing)"`:
- Prevents a single step failure from blocking the rest of cleanup.

Example (suricata `uninstall.sh:27`):
```bash
"$@" || log "(continuing past failure)"
```

✔ **Consistent**: All six modules with uninstall scripts follow
the best-effort pattern.

## Triage

| id | severity | surface | summary | next phase |
| --- | --- | --- | --- | --- |
| F-2028-015 | **important** | vpn-bridge manifest-helpers | vpn-bridge still declares v1 and hand-codes uninstall paths for nftables files, despite writing persistent files that should be tracked via v2 helpers. Drift risk on multi-instance path changes. | implement (batch with other v2 migrations) |

## Status

- **14 findings raised** across two explorers (recent-PRs and crate).
  **Now 15** with this module audit.
- **1 new important finding** (F-2028-015).
- **0 blockers**, **1 important**, **9 nice** (from prior
  explorers, F-2028-001..013).
- Remaining explorers: integration, docs, tests, security.
