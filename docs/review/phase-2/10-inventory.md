# Phase 2 inventory — what's been added since Phase 1

Hand-counted from `git log` covering the 18 PRs post-Phase-1
closeout (PRs #37 → #54). Used by the seven Phase 2 explorers
as the starting point for "what's the new surface I'm auditing?"

## New crate

- **`selfdef-signing`** (PR #45) — wraps `minisign-verify`
  (zero-deps). Exposes `Verifier::load`,
  `Verifier::verify_detached_file`, typed `SigningError`. Used
  by the correlator's opt-in rule-signing path and the
  `selfdefctl keys verify` debug verb.

## Modified crates

### selfdef-cli

New modules:
- `doctor.rs` (PR #50) — `CheckStatus` / `CheckResult` types,
  per-category check functions, human + JSON renderers.
- `init.rs` (PR #51) — `write_starter_config` /
  `write_starter_modules` / `print_checklist`. Embedded
  `STARTER_CONFIG` / `STARTER_MODULES` / `CHECKLIST` templates.
- `follow.rs` (PR #54) — raw HTTP/1.1 over `tokio::net::UnixStream`
  + chunked-encoding + SSE parser.

New subcommands (all in `main.rs`):
- `doctor [--json]`
- `init {config, modules, checklist}`
- `events follow [--unix-socket] [--alerts-only] [-n LIMIT]`
- `keys verify <target> [--public-key]`
- `api rotate-token [--token-file] [--bytes] [--pid] [--print]`
- `rbac check [--probe] [--as SUBJECT] [--namespace] [--warn-only]`

### selfdef-correlator

- `Correlator::with_verifier(v)` builder.
- `Engine::load_dir_verified(dir, v)` — verify each rule's
  `.minisig` before compiling.
- `SigmaError::Signature { path, source }` typed failure.
- Two new dev-deps: `selfdef-signing` for the verifier type,
  `minisign` for test-fixture key generation.

### selfdef-api

- `LoadedTokens` now lives behind `Arc<RwLock<Option<LoadedTokens>>>`.
- New `TokenReloader` struct with `reload()` method.
- `ApiServer::token_reloader()` accessor.
- `bearer_auth` middleware reads tokens through the shared
  RwLock (microsecond hold).
- Re-export added in `lib.rs`.

### selfdef-collector-eventstream

- New `IntegrityCheck { enabled, allowed_owners }` struct.
- `EventstreamCollector::with_integrity_check(c)` builder.
- `EventstreamError::IntegrityRefused` typed variant.
- `check_path_integrity()` helper reads file mode + owner UID
  via `MetadataExt`.
- `unsafe_geteuid()` reads `/proc/self/status` (workspace lint
  forbids `unsafe`).

### selfdef-config

- New `SecurityConfig` block: `require_signed_rules: bool`,
  `signing_public_key_file: Option<PathBuf>`.
- `EventstreamConfig` gains `integrity_check: bool` +
  `allowed_owners: Vec<u32>`.

### selfdef-daemon

- `wait_for_shutdown_or_reload` gains SIGUSR2 arm that calls
  `TokenReloader::reload()`.
- Correlator chain conditionally adds the verifier when
  `[security].require_signed_rules = true`. Refuses to start
  when the flag is on but the key path is missing.
- `IntegrityCheck` built from config + cloned per spawned
  collector instance.

## Module-side machinery

- **Shared lib v2** (`packaging/lib/module-lib.sh`, PR #47):
  - `SELFDEF_MODULE_LIB_VERSION` bumped 1 → 2.
  - New helpers: `module_record_file`, `module_render_files`,
    `module_clear_manifest`, `selfdef_manifest_path`.
  - Per-module manifest at
    `${MODULE_INSTALLED_MANIFEST:-/var/lib/selfdef/installed/<MODULE>.manifest}`.

- **agent-guard** (PR #47):
  - `install/lib.sh` requires v2.
  - `install/apply.sh` calls `module_record_file` for every
    rendered policy.
  - `install/uninstall.sh` iterates `module_render_files` with
    a legacy-enum fallback for pre-v2 installs.

- **tetragon** (PR #46):
  - `profiles/default.toml` gains `require_signed_policies =
    false` (default).
  - `install/apply.sh` shells out to `selfdefctl keys verify`
    for every `*.yml`/`*.yaml` in `policy_dir` when the knob
    is true. Dry-run logs intent, never enforces.
  - `install/check.sh` reports unsigned-policy count as
    `failed`.

- **vpn-bridge** (SDD-003 / earlier in this session):
  - Per-profile `instanced` capability declared in
    `module.toml` (`[profiles.details.<name>].instanced =
    true|false`).
  - `tailscale` + `cloudflare-tunnel` `die` defence-in-depth
    when `SELFDEF_INSTANCE_ID` is set.
  - `relay-via-server` parameterises iface / nft table /
    state file on `${SELFDEF_INSTANCE_ID}`.

## Configuration surface

New `selfdef.toml` blocks:

- `[security]` — `require_signed_rules`, `signing_public_key_file`.
- `[collectors.eventstream]` extended with `integrity_check`,
  `allowed_owners`.

New module-side knobs:

- `modules/tetragon/profiles/default.toml`:
  `require_signed_policies`.

## Documentation surface

New under `docs/dev/`:
- `first-run.md` (PR #51) — `init` runbook.
- `operator-health-check.md` (PR #50) — `doctor` runbook.
- `signing.md` (PR #45) — rule + TracingPolicy signing.
- `rbac-posture.md` (PR #49) — k8s RBAC posture check.
- `module-helpers.md` (SDD-006 + PR #47) — shared lib API.
- `test-contract.md` (PR #41 / SDD-005) — test categorisation.

Repo-root:
- `README.md` (PR #52) — comprehensive refresh.
- `ARCHITECTURE.md` (PR #53) — comprehensive refresh.
- `SECURITY.md` — rewritten via SDD-004 (PR #42), four
  known-gap entries flipped from "tracked" to "shipped" across
  PRs #43, #44, #45, #46, #49.
- `CHANGELOG.md` — every PR adds a section.

SDDs (all `implemented`):
- 001 AI-machine end-to-end
- 002 daemon_requires
- 003 vpn-bridge multi-instance
- 004 security threat-model
- 005 test contract
- 006 shared module-script library

## Test surface (post-Phase-1 additions)

- `crates/selfdef-cli/tests/`:
  - `cli_modules_shared_lib.rs` — shared-lib smoke + version
    mismatch
  - `cli_modules_daemon_requires.rs` — SDD-002 enforcement
  - `cli_api_rotate_token.rs` — 4 tests (PR #44)
  - `cli_modules_shared_lib.rs` — 3 tests
  - `module_tetragon_signing.rs` — 6 tests (PR #46)
  - `module_vpn_bridge_multi_instance.rs` — 5 tests (SDD-003)
  - `cli_rbac_check.rs` — 7 tests (PR #49)
  - `cli_doctor.rs` — 6 tests (PR #50)
  - `cli_init.rs` — 7 tests (PR #51)
  - `cli_events_follow.rs` — 4 tests (PR #54)
  - Plus dry-run-noop tests added to every per-module test
    file (PR #48).
- `crates/selfdef-signing/src/lib.rs` `#[cfg(test)] mod tests`
  — 9 tests (PR #45)
- `crates/selfdef-correlator/tests/signed_rules.rs` — 6 tests
  (PR #45)
- `crates/selfdef-correlator/tests/hot_reload.rs` — 2 tests
  (SDD-005)
- `crates/selfdef-store/tests/concurrent.rs` — 3 tests
- `crates/selfdef-nats/tests/integration.rs` — 2 tests
  (`#[ignore]`-gated)
- `crates/selfdef-collector-tetragon/tests/translation.rs` —
  10 tests
- `crates/selfdef-daemon/tests/m_ai_machine.rs` — SDD-001
  pipeline test

## Numbers

- 18 PRs merged post-Phase-1.
- 1 new crate.
- 6 new operator-facing CLI subcommands.
- 6 new operator runbooks under `docs/dev/`.
- ~80 new tests across the workspace.
- ~7000 lines added net per `git diff --stat`.
