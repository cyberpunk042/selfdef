# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — `selfdefctl doctor` (cross-cutting operator health check)

A single verb that verifies the cross-cutting policy state every post-audit security feature depends on. Synthesizes everything the recent follow-up PRs added (rule signing, API token rotation, eventstream integrity, RBAC posture) into one go-to "is this deployment healthy?" command. Complementary to `selfdefctl modules check` — the two don't subsume each other.

#### Categories

- **`signing`** — when `[security].require_signed_rules = true`, verifies the public key loads + every rule in `[correlator].rules_dir` has a sibling `.minisig` that validates.
- **`api`** — when `[api].enabled = true`, verifies the token file exists, is mode 0600, and is non-empty.
- **`eventstream`** — when `[collectors.eventstream].integrity_check = true`, verifies every configured path passes the same checks the collector will run at startup (not world-writable, owned by daemon-allowed UID).
- **`rbac`** — reads agent-guard's host config; when `scope = "pod-label"`, emits a `warn:` pointing at `selfdefctl rbac check --probe` for the actual cluster RBAC verification.

#### Output

- Human report by default (`## <category>` headings + `[status] check-name: detail` lines + summary count).
- `--json` flag emits JSON-lines (one object per check) for CI / monitoring integration.
- Exit `0` if no `FAIL`, `1` otherwise. `warn` and `skip` never trigger non-zero.

#### Operator integration

- Post-deploy smoke check: `selfdefctl doctor`.
- Periodic via systemd timer: see `docs/dev/operator-health-check.md` for the unit + timer files.
- CI: `selfdefctl doctor --json | jq -e '. | select(.status == "FAIL")'`.

#### Tests

`crates/selfdef-cli/tests/cli_doctor.rs` ships 6 integration tests covering: all-opt-ins-off → all `skip`; API token `0644` flagged as `FAIL`; API token `0600` reported as `ok`; signing enabled without key path flagged as `FAIL`; eventstream world-writable path flagged as `FAIL`; `--json` emits one object per check covering every expected category.

`cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — k8s RBAC posture check (SDD-004 F-2026-025 follow-up)

Closes the SDD-004 F-2026-025 known-gap follow-up as **shipped**.
Adds `selfdefctl rbac check` — a verb that verifies whether the
cluster's RBAC posture matches `agent-guard`'s `scope = "pod-label"`
assumption (only documented narrow subjects should be able to
PATCH pod labels).

With this PR, **every tracked deferred follow-up from the
Phase-1 audit, SDD-004, and SDD-006 is closed**.

- **`selfdefctl rbac check`** — new CLI verb.
  - Reads agent-guard's module config (default
    `/etc/selfdef/modules/agent-guard.toml`, override via
    `--module-config`).
  - If `scope != "pod-label"`, reports the check as
    not-applicable and exits 0.
  - Otherwise, prints the recommended posture + the exact
    `kubectl auth can-i patch pods --subresource=labels --as=<subj>`
    commands the operator should run.
  - With `--probe`, shells out to those commands for the
    built-in subjects (`system:authenticated`,
    `system:unauthenticated`) plus any operator-supplied
    `--as <subject>`. Reports each as `ok:` or `WARN:` and
    exits non-zero if any subject is overly permissive.
    `--warn-only` suppresses the exit code.
  - `--namespace <ns>` scopes the probe to one namespace.
- **`docs/dev/rbac-posture.md`** — operator runbook covering
  when the check applies, the recommended posture, read-only
  vs probe modes, and the documented caveats (the check is
  spot-checking on a fixed subject set, not a cluster-wide
  enumeration).
- **`SECURITY.md`** — F-2026-025 known-gap entry flips from
  "desirable but not designed" to "shipped".

#### Tests

`crates/selfdef-cli/tests/cli_rbac_check.rs` ships 7
integration tests using a stubbed `kubectl` on PATH (mapping
`--as=<subject>` to the `yes`/`no` exit-code contract). Covers:

- not-applicable when `scope = "container"`
- read-only mode prints the recommended posture
- clean posture (every probed subject CANNOT patch labels)
  exits 0
- overly-permissive subject exits non-zero with a clear WARN
  line
- `--warn-only` suppresses the exit code
- operator-supplied `--as` subjects get probed too
- `--namespace` propagates into the printed commands

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — dry-run-noop tests across every module (closes F-2026-030 fully)

Closes F-2026-030 fully (was "reference closed" — adopted only in `vpn-bridge` from PR #41). Every other module-test file now carries a companion `dry_run_apply_must_be_a_noop_on_disk` test using the shared `snapshot_tree` + `assert_tree_unchanged` helpers from `tests/common/mod.rs`.

The dry-run-negative contract: when `SELFDEF_DRY_RUN=1`, the module's `apply.sh` produces zero on-disk delta. A regression making dry-run write the rendered output, the unit file, the nftables ruleset, the baseline, the scrape config, or any other side-effect file is now caught by the test suite.

- `module_agent_guard.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the policy_dir + manifest path.
- `module_bridge_l2.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the config-holding tempdir.
- `module_integrity_sentinel.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the scratch root + spot-checks the baseline file is absent.
- `module_observability.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the bundled-profile scrape/dashboard dirs.
- `module_polarproxy.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the scratch root + spot-checks the systemd unit / nftables ruleset are absent.
- `module_suricata.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the nfqueue-mode fixture.
- `module_tetragon.rs::dry_run_apply_must_be_a_noop_on_disk` — snapshots the tetragon.yaml + policy_dir scope.

#### Tests

7 new tests added, each ~25 lines, follow the same pattern. `cargo test --workspace`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — shared-lib v2: manifest helpers (SDD-006 F-2026-050 follow-up)

Closes the SDD-006 F-2026-050 follow-up as **shipped**. Bumps
the shared module-script library to v2 and adds three new
helpers that let `apply.sh` record every rendered file into a
per-module manifest; `uninstall.sh` enumerates the manifest
instead of hand-listing expected paths.

- **`packaging/lib/module-lib.sh`**: `SELFDEF_MODULE_LIB_VERSION`
  bumped from `1` to `2`. New helpers:
  - `module_record_file <path>` — append `<path>` to the
    per-module manifest. Idempotent (dedups via `grep -Fxq`),
    dry-run aware.
  - `module_render_files` — print every recorded path (one per
    line). Returns empty for pre-v2 installs / pre-first-apply.
  - `module_clear_manifest` — remove the manifest. Dry-run
    aware.
  - `selfdef_manifest_path` — internal helper exposing the
    manifest path (default `/var/lib/selfdef/installed/<MODULE>.manifest`,
    override via `MODULE_INSTALLED_MANIFEST`).
- **`modules/agent-guard/install/lib.sh`** bumps
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED` from `1` to `2` — agent-guard
  now hard-requires v2 of the shared lib. Older selfdef installs
  hit the existing version-mismatch refusal (exit 99 with a
  structured error).
- **`modules/agent-guard/install/apply.sh`** calls
  `module_record_file "$dst"` for every rendered policy YAML.
  Records both first-write and re-apply cases (idempotent).
- **`modules/agent-guard/install/uninstall.sh`** iterates
  `module_render_files` and removes each path, then
  `module_clear_manifest` wipes the record. A legacy-enum
  fallback handles pre-v2 installs (where the manifest is
  empty) so the first post-upgrade uninstall still cleans up
  the rendered policies.
- **`docs/dev/module-helpers.md`**: new "v2 changes" section +
  per-helper documentation following the same shape as the v1
  helpers.

#### Backwards compatibility

- The shared lib's version-mismatch contract from SDD-006 still
  fires: a v1 selfdef install with v2 modules exits 99 at source
  time with a clear stderr message. The 7 modules that
  required v1 (every module other than agent-guard) keep working
  unchanged — they don't ask for v2 features.
- agent-guard installations that upgrade across this PR
  silently work: apply.sh starts recording, uninstall.sh's
  legacy fallback handles the gap. A second apply post-upgrade
  fully populates the manifest.

#### Tests

- **3 new agent-guard integration tests** in
  `crates/selfdef-cli/tests/module_agent_guard.rs`:
  - `manifest_records_every_rendered_policy` — the manifest's
    contents match every `.yaml` file in `policy_dir`
    post-apply.
  - `manifest_deduplicates_across_reapply` — byte-stable
    across two consecutive apply runs.
  - `uninstall_with_no_manifest_falls_back_to_legacy_enum` —
    migration path: a missing manifest still cleans up via
    the hand-enumerated fallback.
- The existing 19 agent-guard tests continue to pass — every
  apply / check / pod-label / scope / gpu test verified
  byte-stably under the new manifest-recording path.
- **`cli_modules_shared_lib.rs`**: `module_requesting_newer_lib_version_is_refused`
  updated to expect `"have 2"` in the version-mismatch
  diagnostic.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

#### Test isolation note

The shared-lib helpers write to
`/var/lib/selfdef/installed/<MODULE>.manifest` by default.
The agent-guard integration test fixture now sets
`MODULE_INSTALLED_MANIFEST` to a tempdir path per test so the
test suite is hermetic and never touches the host's
`/var/lib/selfdef/installed/`.

### Added — TracingPolicy signing (SDD-004 F-2026-024 follow-up)

Closes the SDD-004 F-2026-024 known-gap follow-up as **shipped**.
Re-uses the rule-signing infrastructure (PR before this one) to
gate Tetragon TracingPolicies in
`/etc/tetragon/tetragon.tp.d/`. The `tetragon` module's
`apply.sh` and `check.sh` shell out to `selfdefctl keys verify`
on every policy file before tetragon (re)starts.

- **Tetragon module config**: new `require_signed_policies: bool`
  (default `false`) in `modules/tetragon/profiles/default.toml`.
  Operators turn it on per-host once they've signed every policy
  in `policy_dir`.
- **apply.sh enforcement**: when `require_signed_policies = true`,
  apply.sh iterates every `*.yml`/`*.yaml` in `policy_dir` and
  runs `selfdefctl keys verify` on each. Failures emit a
  structured `failed` status and exit non-zero **before**
  invoking `systemctl restart tetragon` — the running tetragon
  stays up with whatever policies were already loaded.
- **check.sh report**: when `require_signed_policies = true`,
  check.sh reports the unsigned-policy count as a `failed`
  structured status with detail
  `"<N> of <M> policy file(s) in <dir> failed signature verification"`.
  Non-fatal to the running tetragon — the check is purely a
  state report.
- **Dry-run** logs "DRY-RUN: would verify ..." for each policy
  but never enforces — preserving the dry-run-is-a-no-op
  contract (SDD-005 D-2a).
- **`docs/dev/signing.md`**: new "TracingPolicy signing"
  section walks operators through enabling the gate, apply +
  check behaviour, and the agent-guard render-time caveat
  (rendered policies are not pre-signed; operators turn on the
  gate where they don't run agent-guard, or trust agent-guard's
  output via package signatures + integrity-sentinel
  baselining).

#### Tests

`crates/selfdef-cli/tests/module_tetragon_signing.rs` ships 6
integration tests covering:
- apply passes when signing disabled (sanity: existing workflow
  unchanged)
- apply passes when every policy is signed
- apply refuses with a clear `failed` status when one policy
  is unsigned
- dry-run logs verification intent but never fails
- check passes when signing disabled even with unsigned
  policies
- check fails when signing is enabled and an unsigned policy
  exists

The fixture uses a stubbed `selfdefctl` on PATH that mimics
`keys verify`'s exit-code contract (0 if a sibling `.minisig`
exists, 1 otherwise) — the real verifier path is covered
end-to-end by `selfdef-signing`'s own unit suite + the
correlator's `signed_rules.rs` integration suite.

#### What this closes

- **F-2026-024 follow-up** in `docs/review/99-findings-ledger.md`
  flips from "partial close" to "shipped"; the SECURITY.md
  known-gap entry flips accordingly.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — detection-rule signing (closes original "Rule signing" Known gap)

Closes the original SECURITY.md "Rule signing not yet enforced"
Known gap as **opt-in shipped**, and ships the verifier
infrastructure that the SDD-004 F-2026-024 follow-up will reuse
for Tetragon TracingPolicies.

The daemon can now refuse to load detection rules that aren't
accompanied by a valid detached minisign signature. Signing
happens offline on the operator's signing machine (with the
standalone `minisign` CLI); the daemon is verify-only.

- **New crate `selfdef-signing`** wraps `minisign-verify`
  (zero-deps, audited). Exposes `Verifier::load(pub_key)` and
  `Verifier::verify_detached_file(<target>)` — looks for
  `<target>.minisig` and verifies under the loaded key.
- **`selfdef-correlator`**: `Correlator::with_verifier(v)`
  builder + `Engine::load_dir_verified(dir, v)` rule loader.
  `SigmaError::Signature { path, source }` is the new typed
  failure mode; the existing "keep prior ruleset on failure"
  semantics mean an unsigned drop never affects the running
  rule set.
- **`selfdef-config`**: new `[security]` block with
  `require_signed_rules: bool` (default `false`) +
  `signing_public_key_file: Option<PathBuf>`. The daemon
  refuses to start when `require_signed_rules = true` but the
  key path is missing or unreadable — failing loudly beats
  silently running unsigned-trusted.
- **`selfdefd`**: when `[security].require_signed_rules` is on,
  the daemon loads the public key at startup and chains the
  verifier onto the Correlator. Logged at `INFO` as
  "correlator: rule-signing verification enabled".
- **`selfdefctl keys verify <target>`**: new debug CLI verb.
  Loads `[security].signing_public_key_file` (or `--public-key`)
  and verifies the target's `.minisig` sidecar. Useful when an
  operator is investigating signing without involving the
  daemon.
- **`docs/dev/signing.md`**: new operator runbook —
  key generation, signing workflow, deployment, manual
  verification, rotation, threat-model caveats.

#### Behavioural notes

- Default is `require_signed_rules = false`. Every existing
  deployment behaves identically; rule signing is strictly
  opt-in.
- A SIGHUP rule reload picks up new signatures + new rules
  but reuses the verifier loaded at startup; rotating the
  public-key path itself requires a daemon restart.
- Verification happens at rule-load time. A previously-loaded
  malicious rule already in memory continues to fire until
  the daemon restarts — `integrity-sentinel` watching the
  rules directory remains the right mitigation for
  in-memory tampering.

#### Tests

- **`selfdef-signing` unit** (9 tests): public-key parsing
  from raw base64 + minisign `.pub` format, malformed-key
  rejection, signed/unsigned/wrong-key/tampered/malformed-sig
  paths, the `signature_path_for` helper.
- **`selfdef-correlator` integration**
  (`tests/signed_rules.rs`, 6 tests): full `load_rules` path
  with a configured verifier — positive accept, unsigned
  reject, tampered reject, wrong-key reject,
  no-verifier-no-signature sanity, prior-ruleset-preserved on
  signature failure.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — API token hot-rotation (SDD-004 F-2026-023 follow-up)

Closes the SDD-004 F-2026-023 known-gap follow-up as **shipped**.
Operators can now rotate the API bearer token without restarting
the daemon — in-flight scrapes continue against the new token
once the daemon picks it up.

- **`selfdefctl api rotate-token`** — new CLI verb.
  - Generates a fresh 32-byte high-entropy token (read from
    `/dev/urandom`, base64-url-safe encoded — no padding, no
    pulled dep).
  - Writes atomically to the configured `[api].token_file`:
    tempfile → `write_all` → `fsync` → `rename` → `chmod 0600`.
    Survives a crash mid-rotation; the previous token stays
    valid.
  - `--token-file <path>` overrides the config target (useful
    when rotating the control token).
  - `--bytes <N>` (default 32) sets the entropy length;
    validates `1..=256`.
  - `--pid <pid>` or `--pid auto` signals the daemon. `auto`
    runs `systemctl show -p MainPID --value
    selfdefd.service` and parses the pid; omit `--pid` and the
    operator signals the daemon themselves
    (`systemctl kill --signal=SIGUSR2 selfdefd`).
  - `--print` echoes the new token to stdout (default: only the
    on-disk path is logged).
- **Daemon SIGUSR2 handler** — `selfdef-daemon/src/main.rs`'s
  `wait_for_shutdown_or_reload` gains a SIGUSR2 arm that calls
  the new `TokenReloader::reload`. SIGHUP (rules) and SIGUSR2
  (api tokens) stay structurally identical.
- **`selfdef-api::TokenReloader`** — the bearer-token
  middleware now reads tokens through an
  `Arc<RwLock<Option<LoadedTokens>>>` shared with the daemon's
  signal handler. `TokenReloader::reload()` re-reads
  `token_file` / `control_token_file` from disk and swaps the
  inner value under the write lock; reload errors (empty
  file, IO failure) keep the previously-loaded tokens in
  place. New `pub` exports: `TokenReloader`.

#### Behavioural notes

- The middleware now holds a read lock for the duration of the
  byte-compare (microseconds). Read contention is bounded by
  scrape concurrency.
- The previously-loaded tokens persist on reload failure — the
  daemon stays up; existing valid tokens keep working. Operators
  see a structured `warn!` line.
- Pre-follow-up callers that constructed `Arc<LoadedTokens>` —
  none in the public API — would now go through
  `ApiServer::token_reloader()` instead. The function signature
  for `ApiServer::new` is unchanged.

#### Tests

- **Unit** (`selfdef-api`): 4 tests in
  `transport::token_reload_tests` covering atomic swap,
  prior-tokens-preserved-on-empty-file, prior-tokens-preserved-on-io-error,
  and the `is_loaded` accessor.
- **CLI integration**
  (`crates/selfdef-cli/tests/cli_api_rotate_token.rs`): 4
  tests covering url-safe + 0600 output, `--token-file`
  override, `--bytes` validation, and two rotations producing
  different tokens.
- **`base64_urlsafe` self-tests** (in main.rs): RFC 4648 §5
  positive vectors + a property-style char-set check.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Added — eventstream parse-time integrity check (SDD-004 F-2026-026 follow-up)

Closes the SDD-004 F-2026-026 follow-up known gap as
**opt-in shipped**. The daemon's `[collectors.eventstream]`
config gains two new fields:

- `integrity_check: bool` (default `false`). When `true`, the
  collector refuses to tail any path that is world-writable
  (`mode & 0o002 != 0`) or owned by a UID outside
  `{daemon-effective-uid, root} ∪ allowed_owners`. Mismatches
  return an `IntegrityRefused` error and the daemon logs a
  structured warning; other configured paths continue tailing.
- `allowed_owners: Vec<u32>`. Additional numeric UIDs accepted
  as a writer when `integrity_check = true`. Empty list = only
  the daemon-effective-uid and root are accepted. Operators
  with a deliberate operator-owned emitter (e.g. the user's
  own `~/.local/share/selfdef/ssh-wrap.jsonl`) add their UID
  here.

Default is `false` so operator-owned emitters keep working
unchanged. The hardening checklist in `SECURITY.md` recommends
turning it on once `/var/lib/selfdef/eventstream/` is
`0750 selfdef:selfdef`.

#### What this changes for operators

- `config/selfdef.toml.example` documents the two new knobs
  under `[collectors.eventstream]` with the
  ssh-wrap-emitter-on-uid-1000 example.
- `SECURITY.md` known-gap entry for eventstream JSONL
  injection updates from "tracked under SDD-004 follow-up" to
  "opt-in shipped; turn on via `integrity_check = true`".

#### Tests

- Unit (`crates/selfdef-collector-eventstream/src/lib.rs`):
  - `integrity_check_rejects_world_writable_file`
  - `integrity_check_accepts_daemon_or_root_owned_file`
  - `integrity_check_accepts_explicit_allowed_owner`
  - The pre-existing `tails_event_file_and_republishes` test
    continues to pass, confirming the default-disabled path
    is unchanged.

`cargo test --workspace`, `cargo clippy --workspace --tests
-- -D warnings`, and `cargo fmt --all -- --check` are clean.

### Documentation — security threat-model rewrite (SDD-004 implementation)

Closes Phase-1 audit findings F-2026-023, F-2026-024, F-2026-025,
F-2026-026. SDD-004 status flips from `draft` to `implemented`.
With this PR, **every Phase-1 SDD has shipped its implementation
PR** and every important / blocker finding the audit raised is
now closed or has a tracked follow-up.

`SECURITY.md` is rewritten in place; `docs/src/security.md` is
now a symlink to `../../SECURITY.md` (was a duplicated copy)
to eliminate the drift surface.

- **Assets table**: three new rows. `/metrics` endpoint, Tetragon
  TracingPolicy directory (`/etc/tetragon/tetragon.tp.d/`), and
  eventstream JSONL paths. Total: 10 rows.
- **Adversaries table**: new class 6 *Cluster-tenant attacker* —
  has Pod-label `PATCH` rights on the k8s cluster.
- **Trust assumptions**: cluster control plane added as a
  trusted entity for k8s deployments.
- **Mitigations**: two new layers added — *API surface* (UNIX
  vs TCP transports, bearer-token model, `/metrics` read-cap
  parity, uptime side channel) and *Policy surface*
  (TracingPolicy directory ownership, agent-guard pod-label
  scope dependency on cluster RBAC, eventstream JSONL trust
  boundary).
- **Known gaps**: extended with three new follow-up entries —
  TracingPolicy signing (F-2026-024 follow-up), metrics-token
  rotation (F-2026-023 follow-up), k8s label-RBAC posture
  (F-2026-025 follow-up). Eventstream JSONL integrity
  (F-2026-026 follow-up) was already enumerated by PR #36 and
  stays.
- **Hardening checklist**: short copy-paste-able sidebar at the
  end of the Mitigations section enumerating the recommended
  posture for an AI-machine deployment.

The rewrite is documentation-only — no code, no defaults change.
Operators reading `SECURITY.md` see new asset rows + a new
adversary class + new mitigation guidance. Recommended action
for AI-machine deployments is the new Hardening checklist
sidebar.

### Added — test contract + 6 test-gap closures (SDD-005 implementation)

Closes SDD-debt finding F-2026-082 and the six implementation
findings F-2026-030 through F-2026-036. SDD-005 status flips from
`draft` to `implemented`. The six Test-N PRs the SDD breaks the
work into collapse into a single PR per the "big chunks" steer.

- **D-5 — Test-contract runbook**: `docs/dev/test-contract.md`
  is the new contributor-facing doc — four test categories
  (translation, pipeline, module-script, seam) with explicit
  contracts, plus the three shared patterns (P-1 dry-run-noop,
  P-2 Prometheus parser, P-3 real-broker NATS).
- **Test-1 (D-2a) — Dry-run negative**:
  `crates/selfdef-cli/tests/common/mod.rs` gains `snapshot_tree`
  + `assert_tree_unchanged`. The reference adoption is
  `module_vpn_bridge.rs::endpoint_dry_run_must_be_a_noop_on_disk`
  — staging a relay-via-server fixture, running apply with
  `SELFDEF_DRY_RUN=1`, snapshotting before/after, and asserting
  byte equality. The fingerprint is length+first-32-bytes (hand
  rolled) so we don't take a hash-crate dep. Closes F-2026-030
  for the reference module; the other module test files migrate
  when next touched.
- **Test-2 (D-2b) — Prometheus parser + read-cap gate**:
  `m12_api.rs` gains a `mod prom` exposition parser
  (Sample(name, labels, value) tuples, dedup-key check, strict
  comment shapes). New tests
  `metrics_exposition_passes_format_strict_parse` and
  `metrics_allows_read_capability` close F-2026-031 and
  F-2026-032. The pre-existing substring assertions on the
  /metrics body are kept alongside as a regression net.
- **Test-3 (D-2c) — Real-broker NATS round-trip**:
  `crates/selfdef-nats/tests/integration.rs` spawns a real
  `nats-server` on a free port (discovered via `which`) and runs
  the bridge against it. `core_bridge_round_trips_event_between_two_hosts`
  asserts the wire format end-to-end; `jetstream_bridge_creates_stream_and_durable_consumer`
  asserts the JetStream startup contract. Both are
  `#[ignore]`-gated — CI without the binary stays green; the
  runbook documents `cargo test -p selfdef-nats -- --include-ignored`
  for local runs (and CI installing `nats-server`).
  Closes F-2026-035.
- **Test-4 — Correlator hot-reload**:
  `crates/selfdef-correlator/tests/hot_reload.rs`.
  `correlator_swaps_rules_atomically_under_live_traffic` runs a
  driver task firing 5ms-cadence events while the test swaps
  rule A→B mid-flight and verifies findings match exactly one
  rule title (no half-state).
  `correlator_load_rules_keeps_prior_set_on_parse_failure`
  asserts the non-destructive failure path. Closes F-2026-033.
- **Test-5 — Store concurrency + crash-recovery**:
  `crates/selfdef-store/tests/concurrent.rs`.
  `concurrent_inserts_do_not_lose_rows` hammers the store from
  8 tasks × 200 inserts under a multi-thread runtime;
  `crash_recovery_surfaces_every_committed_insert` opens, inserts
  50, drops, reopens, asserts all 50 are durable;
  `concurrent_inserts_then_reopen_preserves_count` composes
  both. Closes F-2026-034.
- **Test-6 — Tetragon collector isolation**:
  `crates/selfdef-collector-tetragon/tests/translation.rs`.
  10 tests covering every `process_exec` / `process_kprobe`
  (file_open, socket, unknown function) / `process_exit` /
  unknown-top-level branch + 3 tolerance branches (empty line,
  malformed JSON, missing-fields). A new
  `pub fn TetragonCollector::translate_line(&str) -> Option<Event>`
  gives the external test surface; `process_line` now wraps it
  (translate-then-publish). Closes F-2026-036.

### Behavioural notes

The translation-only `translate_line` API on `TetragonCollector`
is additive — existing callers go through `process_line` and
`run()` unchanged. The `mod prom` parser is contained in the
m12_api integration test file; if a future test outside that
file needs it, extract to a workspace test-only crate.

### Tests

The six new test files run as part of `cargo test --workspace`.
NATS integration is gated; the runbook documents the
`--include-ignored` invocation. Full workspace `cargo test`,
`cargo clippy --workspace --tests -- -D warnings`, and
`cargo fmt --all -- --check` are clean.

### Added — shared module-script library (SDD-006 implementation)

Closes SDD-debt finding F-2026-081; partial close on F-2026-051.
SDD-006 status flips from `draft` to `implemented`. Phase A + B + C
of the SDD's rollout plan land together in one PR per the
"big chunks" steer: the shared library, the dispatcher
plumbing, **and** the byte-stable migration of all eight modules.

- **D-1 — Shared library**: `packaging/lib/module-lib.sh` ships
  the five core helpers (`log`, `emit_status`, `die`, `run`,
  `toml_get`) plus version pin (`SELFDEF_MODULE_LIB_VERSION=1`).
  Helpers are byte-identical to the per-module copies (except
  `log()`, which the shared version parameterises on
  `${MODULE}` instead of a hard-coded slug literal). The library
  refuses to source when
  `SELFDEF_MODULE_LIB_VERSION_REQUIRED` exceeds what it ships
  (exits 99 with a clear stderr message).
- **D-2 — Dispatcher plumbing**: `run_one` in
  `crates/selfdef-cli/src/modules.rs` exports
  `SELFDEF_MODULE_LIB` via a new `resolve_module_lib_path()`
  with three-tier precedence (env override → workspace
  `packaging/lib/module-lib.sh` → installed
  `/usr/share/selfdef/lib/module-lib.sh`).
- **D-3 — Per-module migration**: eight modules migrated in one
  go: `agent-guard`, `tetragon`, `observability`,
  `integrity-sentinel`, `vpn-bridge`, `bridge-l2`, `polarproxy`,
  `suricata`. The five with an existing `install/lib.sh` had
  their helper block replaced by a `source` of the shared lib;
  the three with inlined helpers (`bridge-l2`, `polarproxy`,
  `suricata`) gained a `lib.sh` of their own and source it from
  apply / check / uninstall. The lib.sh files use a
  `${BASH_SOURCE[0]%/*}` parameter-expansion fallback to the
  workspace path so integration tests + ad-hoc invocations work
  without `SELFDEF_MODULE_LIB` set, and the resolver never
  shells out to `dirname` (some tests run the scripts under a
  stripped `$PATH`). `bridge-l2`'s, `polarproxy`'s, and
  `suricata`'s uninstall scripts override `log()` and `run()`
  after sourcing to preserve the pre-SDD-006 `[<slug>:uninstall]`
  log prefix and lenient continue-past-failure behaviour.
- **D-4 — Helpers doc**: `docs/dev/module-helpers.md` is the new
  authoritative reference — every exported helper, the caller
  contract, the versioning policy, and how to add module-specific
  helpers / shared-helper overrides.
- **D-5 — Packaging**: `crates/selfdef-daemon/Cargo.toml`'s
  `[package.metadata.deb]` assets list installs the shared lib
  at `/usr/share/selfdef/lib/module-lib.sh` mode `0644`.

#### Behavioural notes

The migration is **byte-stable** for every shipped module's apply
/ check / uninstall flow. The only externally visible change is
the `log()` prefix: pre-SDD-006, each module hard-coded
`[<slug>]` in its own `log()` definition; the shared lib uses
`[${MODULE}]`, which produces the identical string at runtime.
Operator log captures should diff cleanly. The `[<slug>:uninstall]`
prefix that bridge-l2 / polarproxy / suricata's uninstall scripts
emitted pre-SDD-006 is preserved by per-script `log()` overrides
after sourcing.

#### Tests

- Unit (`crates/selfdef-cli/src/modules.rs`):
  `resolve_module_lib_path_finds_workspace_by_default`. The
  env-override branch is exercised by integration only because
  the workspace lint forbids in-process `std::env::set_var`
  (the lint is correct: env mutation isn't thread-safe).
- Integration
  (`crates/selfdef-cli/tests/cli_modules_shared_lib.rs`):
  `dispatcher_exports_module_lib_env_var` asserts selfdefctl
  exports the env var; `module_sourcing_shared_lib_at_v1_succeeds`
  is a smoke test of the full source-and-call flow;
  `module_requesting_newer_lib_version_is_refused` checks the
  version-pin diagnostic.
- All 13 per-module integration test files
  (`module_*.rs`) continue to pass byte-stably — proof the
  migration didn't change apply / check / uninstall behaviour.

#### Deferred / partial

- **F-2026-050** (agent-guard's hand-enumerated policy list in
  `uninstall.sh`) is **deferred** to a follow-up. The SDD reserved
  a `module_render_files` helper for this; v1's library surface
  is intentionally minimal.
- **F-2026-051** (`render_pod_scope` awk fragility) is **partial
  close**: the v1 library doesn't ship YAML-aware editing
  helpers. A future v2 of the library could ship `yq`/python
  helpers and close it fully.

### Added — vpn-bridge multi-instance honesty (SDD-003 implementation)
Closes Phase-1 audit blocker F-2026-005. SDD-003 status flips
from `draft` to `implemented`. With this PR, all six Phase-1
blockers from the architect/PM sweep are closed.

The vpn-bridge manifest's `instanced = true` is now honest about
which profiles can actually run side-by-side, and the resolver +
profile scripts enforce that boundary.

- **`selfdef-cli` D-1**: `ProfileSpec` (in
  `crates/selfdef-cli/src/modules.rs`) gains an optional
  per-profile `[profiles.details.<name>]` block with an
  `instanced: Option<bool>` field. Profiles not listed there
  inherit the module-level `instanced` value.
  `ProfileSpec::profile_instanced(profile, module_default)`
  is the single accessor.
- **`selfdef-cli` D-2**: `resolve_active` reads each instance's
  per-module config (parsing just the `profile = ...` line),
  looks up the profile's `instanced` capability, and refuses
  any `slug#instance` host-config key whose profile is declared
  `instanced = false`. Refusal happens before any apply.sh fires.
- **`selfdef-cli` D-3**: `run_one` now passes
  `SELFDEF_INSTANCE_ID=<inst>` into the spawned bash process
  whenever the active module has an instance suffix. Absent for
  the legacy single-instance shape — scripts that don't need it
  can ignore it.
- **`modules/vpn-bridge` D-4**: `relay-via-server.sh` derives
  per-instance defaults from `${SELFDEF_INSTANCE_ID}`:
  interface defaults to `selfdef-<inst>` (was `wg0`), nftables
  table to `selfdef_vpn_bridge_<inst>` (was `selfdef_vpn_bridge`),
  nftables state file to
  `/etc/nftables.d/selfdef-vpn-bridge-<inst>.conf` (was
  `/etc/nftables.d/selfdef-vpn-bridge.conf`). The forward-rule
  template now substitutes `@@NFT_TABLE@@`. Override
  environment variables (`SELFDEF_VPN_BRIDGE_NFT_TABLE`,
  `SELFDEF_VPN_BRIDGE_NFT_PATH`) take precedence as before.
  `tailscale.sh` and `cloudflare-tunnel.sh` `die`
  defence-in-depth at the top of `profile_apply` /
  `profile_uninstall` when `SELFDEF_INSTANCE_ID` is set — the
  resolver should already have refused the apply, but the
  scripts guard against bypass.
- **`modules/vpn-bridge` D-5**: `module.toml` declares
  `[profiles.details.relay-via-server] instanced = true`,
  `[profiles.details.tailscale] instanced = false`,
  `[profiles.details.cloudflare-tunnel] instanced = false`. The
  README's pre-SDD-003 "Multi-instance caveat" block is
  rewritten into a "Multi-instance support" section with the
  capability table, per-instance naming convention
  (`selfdef-<inst>` iface and friends), and migration notes for
  pre-SDD-003 deployments.

#### Backwards compatibility

Single-instance `[modules.vpn-bridge]` deployments are
**byte-stable**: when `SELFDEF_INSTANCE_ID` is unset, the
relay-via-server defaults remain `wg0` / `selfdef_vpn_bridge`
/ `/etc/nftables.d/selfdef-vpn-bridge.conf`. No migration is
needed for the common shape.

If you were running multiple instances of `tailscale` or
`cloudflare-tunnel` (which silently corrupted state pre-SDD-003),
the resolver will now refuse the `#suffix` host keys with a
clear message. Pick one to keep, drop the `#suffix`, and
re-apply.

If you were running multiple instances of `relay-via-server`,
each instance's apply will now install per-instance state files
alongside any legacy `selfdef_vpn_bridge` table you had — see
the vpn-bridge README's "Migrating from pre-SDD-003" section for
the cleanup steps.

#### Tests

- Unit (`crates/selfdef-cli/src/modules.rs`):
  `profile_instanced_falls_back_to_module_default_when_unset`,
  `profile_instanced_per_profile_override_wins`,
  `resolver_rejects_instance_for_singleton_profile`,
  `resolver_accepts_instance_for_multi_instance_profile`,
  `resolver_falls_back_to_default_profile_when_config_missing`.
- Integration
  (`crates/selfdef-cli/tests/module_vpn_bridge_multi_instance.rs`):
  the relay profile uses per-instance iface when
  `SELFDEF_INSTANCE_ID` is set and stays on `wg0` when it isn't;
  the singleton profiles refuse to apply when the env var leaks
  through; the CLI resolver refuses `vpn-bridge#extra` for the
  tailscale profile before invoking apply.sh.

### Added — defaults that work out of the box (SDD-002 implementation)
Closes Phase-1 audit blockers F-2026-004 / F-2026-018 / F-2026-020.
SDD-002 status flips from `draft` to `implemented`.

The bridge between module defaults and daemon defaults is now a
**manifest-level contract**. Every active module's
`[daemon_requires]` is validated against
`/etc/selfdef/selfdef.toml` before any apply.sh fires; mismatch
prints a copy-pasteable TOML snippet (with `${...}` substitutions
expanded against the per-module config) and exits 2, unless the
operator passes `--ignore-daemon-requires`.

- **`selfdef-cli` D-1**: `ModuleManifest` gains an optional
  `daemon_requires: BTreeMap<String, DaemonRequirement>`. The
  untagged `DaemonRequirement` enum supports bool / int / string /
  array-of-string values. Array entries are interpreted as
  set-inclusion (the daemon's actual array must contain every
  element listed in the manifest).
- **`selfdef-cli` D-2**: `check_daemon_requires` runs in
  `run_lifecycle` for `Apply` and `Check` actions (uninstall
  skips — tearing a module down doesn't care). Substitution
  rule is intentionally minimal: only `${<flat-key>}` referencing
  a same-module top-level scalar. The snippet renderer groups
  unmet requirements by module with `# ── <module> ──` headers.
- **D-3**: `modules/integrity-sentinel/profiles/strict.toml` and
  `profiles/warn-only.toml` now ship with `event_stream_path`
  live by default (default
  `/var/lib/selfdef/eventstream/integrity-sentinel.jsonl`). Set
  the key to `""` to opt out. The module's `[daemon_requires]`
  ensures the daemon's `[collectors.eventstream].paths` includes
  this file before apply proceeds.
- **D-4**: `config/selfdef.toml.example` gained operator-discovery
  comments under `[collectors.tetragon]` (explicitly contrasting
  it with `[collectors.eventstream]`) and under
  `[collectors.eventstream]` (showing the integrity-sentinel
  emission path as a commented example).
- **D-5**: new `selfdefctl modules show-requires` subcommand
  prints every active module's expanded `[daemon_requires]` as a
  copy-pasteable snippet. Read-only; never touches the daemon
  config.
- **Manifests**: `tetragon` and `integrity-sentinel` now declare
  their daemon-side knobs. Other modules can adopt the field
  incrementally — manifests without the section skip the check.
- **Operator-facing CLI surface**: `selfdefctl modules apply` and
  `selfdefctl modules check` gain a `--ignore-daemon-requires`
  flag; new `selfdefctl modules show-requires` subcommand.
- 4 new integration tests in
  `tests/cli_modules_daemon_requires.rs`: apply refuses on unmet,
  apply succeeds on satisfied, `--ignore-daemon-requires`
  bypasses, `show-requires` prints the expanded snippet.

Operator-visible effect: a fresh `.deb` install with
`integrity-sentinel`, `tetragon`, and `agent-guard` active in
`/etc/selfdef/modules.toml` now refuses to silently proceed on a
mismatched `selfdef.toml`. The operator sees exactly what to
add. Once added, every promise the modules' READMEs make about
the daemon picking up their output holds end-to-end.

### Added — AI-machine track is end-to-end (SDD-001 implementation)
Closes the four Phase-1 audit blockers that surrounded the
AI-machine track: F-2026-001, F-2026-002, F-2026-003,
F-2026-006. SDD-001's status flips from `draft` to
`implemented`.

- `selfdef-collector-tetragon` now attaches a stable
  `raw.tetragon.{policy_name,policy_namespace,action,function_name}`
  subobject to every `process_kprobe` Event it builds.
  Severity stays Informational at the collector layer
  per the SDD's "collectors are dumb translators"
  invariant — meaning lives in the correlator. Closes
  **F-2026-001**.
- New sigma rule
  `rules/sigma/hardening/agent_guard_violation.yml`
  matches `raw.tetragon.policy_name|startswith
  "selfdef-agent-"` AND `raw.tetragon.action|in [Sigkill,
  Override, NotifyKiller]`, promotes to `level: high`.
  Audit-mode `Post` actions deliberately do **not** trip
  this rule. Six-case `.tests.yaml` corpus covers Sigkill,
  Override, NotifyKiller, audit-mode-Post-negative,
  non-agent-guard-negative, non-tetragon-source-negative.
  Closes **F-2026-002**.
- `modules/tetragon/README.md` now names
  `[collectors.tetragon]` as the correct daemon-side
  ingest path with a paste-ready snippet, and the
  "What's NOT owned" section explicitly calls out the
  `[collectors.eventstream]` collector as the wrong
  choice. Closes **F-2026-003**.
- New daemon integration test
  `crates/selfdef-daemon/tests/m_ai_machine.rs` exercises
  the full pipeline (Tetragon JSON → collector → bus →
  correlator → findings store) and asserts the negative
  case (audit-mode `Post` does NOT promote). Closes
  **F-2026-006**.

Operator-visible effect: with the `tetragon` collector
enabled in the daemon config and `agent-guard` running in
`enforce` (or a per-policy `*_action = "sigkill"`
override), a real policy violation now surfaces as a
high-severity Detection Finding through the existing
notifier chain (ntfy / Signal). The kernel-side action
worked all along; this PR plumbs the operator alert side.

### Changed — Phase 1 audit follow-ups (one bigger PR)
Seven small fixes batched together. Each closes (or partially
closes) a Phase-1 ledger row.

- **F-2026-054** — `selfdef-daemon::build_notifier_chain` now
  warns at startup when `[notifier.ntfy]` or `[notifier.signal]`
  carries non-default config but the channel name isn't in the
  active `[notifier].channels` list. The channel was silently
  inert before; now the operator sees it on every restart.
- **F-2026-059** — extracted `check_confirm_hostname` +
  `ConfirmRefusal` helper in `selfdef-cli/src/main.rs`. Both
  `panic` and `modules uninstall` now share the
  hostname-confirmation gate; the duplicated bodies are gone.
  Output text is preserved (test suite asserts the same
  refusal strings).
- **F-2026-060** — new `crates/selfdef-cli/tests/common/mod.rs`
  carrying the `workspace_root` / `module_dir(slug)` /
  `write_file` / `write_executable` / `last_stdout_line` /
  `prepended_path` helpers that nine `module_*.rs` test files
  duplicated. Per-test migration is incremental — adopting the
  common module in each test file is a follow-up.
- **F-2026-061** — `m12_api.rs metrics_endpoint_returns_prometheus_exposition`
  now exact-matches the `Content-Type` against
  `text/plain; version=0.0.4; charset=utf-8`, asserts each
  `# TYPE` line is present **exactly once** (catches accidental
  duplicates), and validates every body line follows the
  Prometheus exposition shape. Substring matching is gone.
- **F-2026-062** — `module_agent_guard.rs` gains a byte-stable
  reapply test that exercises every rendered policy (with
  egress allowlist + GPU allowlist set so the substitution
  paths are exercised). Bridge-l2 / suricata / polarproxy /
  vpn-bridge still need theirs (follow-up).
- **F-2026-065 + F-2026-066** — SECURITY.md (and its mirror
  `docs/src/security.md`) gain two Known-gaps entries: the
  eventstream-JSONL injection primitive via
  `selfdefctl events emit`, and the `selfdef_uptime_seconds`
  side channel that lets a `/metrics` scraper time
  credential-file edits to a daemon restart. Both name the
  recommended mitigation.

Verified: `cargo build --workspace`, `cargo test -p
selfdef-cli -p selfdef-api`, `cargo fmt --all -- --check`,
`cargo clippy -p selfdef-cli -p selfdef-daemon -p selfdef-api
--tests` all clean.

### Docs — Phase 1 audit nice-cluster cleanup
- `modules/vpn-bridge/README.md` — new "Multi-instance
  caveat" block at the top calling out F-2026-005 / SDD-003
  and warning operators not to declare two
  `[modules."vpn-bridge#..."]` blocks against the same
  profile until SDD-003 ships. Closes **F-2026-058**.
- `modules/observability/README.md` — new "Tetragon
  metric-name pin" section documenting the upstream-version
  assumption (the dashboard panels target Tetragon v1.x's
  metric naming). Documents **F-2026-052** as a partial
  close; the `tetragon` module's `requires` block doesn't
  pin a version range yet.
- `docs/review/99-findings-ledger.md` — back-references the
  nice-cluster PR. Also marks **F-2026-056** and
  **F-2026-057** as closed by doc-sweep PR #30 (the
  README's Module catalog table and the CHANGELOG's
  "Honest correction" entry, respectively — they were
  shipped but not back-referenced at the time).

### Changed — Phase 1 audit dead-knob cleanup
- `selfdef-store/src/sqlite.rs` no longer carries its own
  `const SCHEMA_VERSION: u32 = 1` — it now imports
  `selfdef_core::SCHEMA_VERSION`. Drift risk eliminated; a
  future schema bump in `selfdef-core` propagates to the
  store's migration check automatically. Closes
  **F-2026-017** (audit ledger).
- `selfdef-config::BusConfig::backend` and
  `selfdef-config::CorrelatorConfig::{window_secs,threshold}`
  rustdoc-marked **vestigial**: the daemon doesn't branch on
  any of the three. The fields stay in the struct so existing
  operator configs keep parsing (serde `#[serde(default)]`
  was already on the struct). Removed from
  `config/selfdef.toml.example` so new operators don't copy
  them in. Closes **F-2026-015** + **F-2026-053**.
- No daemon behaviour change. No public-API removal.
- Findings ledger updated with closure references.

### Docs — Phase 1 audit doc-sweep
- `README.md` no longer claims "Milestone 1 — Scaffolding only".
  Adds a module catalog table and an AI-machine track milestone.
- `ARCHITECTURE.md` updated to show the `/metrics` endpoint and a
  Modules-layer overview.
- `docs/src/modules.md` corrects the stale "only `detect-host`
  ships" claim.
- `modules/observability/README.md`: `scrape_targets` documented
  default reconciled (Tetragon + selfdef-daemon, not Tetragon
  alone). Dashboard panel list extended to cover the three new
  selfdef-daemon panels. New "Scraping the daemon" section
  walks the bearer-token scrape config Prometheus needs against
  the daemon's `/metrics` TCP transport.
- `modules/observability/install/apply.sh` fallback default for
  `scrape_targets` now matches the shipped profile defaults.
- mdbook `SUMMARY.md` surfaces the previously-orphan
  `api.md`, `ebpf.md`, `nats.md`, `ssh-wrap-install.md`. Those
  files moved from `docs/` into `docs/src/{ops,dev}/` so the
  mdbook tree owns them.
- Five `# TODO` stub pages (`dev/build`, `dev/collector`,
  `ops/install`, `ops/config`, `ops/notifications`,
  `detect/rules`, `detect/testing`) replaced with real, tight
  content.
- Closes Phase 1 audit findings F-2026-012 / -013 / -019 /
  -021 / -022 / -027 / -028 / -029. Findings ledger is updated
  with cross-references.

### Honest correction — AI-machine track operator promise
The CHANGELOG entries for PRs #21, #22, #24 described an
operator-facing benefit (drift fires the notifier chain;
agent-guard kills surface as alerts; GPU device access surfaces)
that the Phase 1 audit (`docs/review/40-integration-audit.md`)
showed is not plumbed end-to-end today. The kernel-side action
works (Tetragon Sigkill terminates); the path from Tetragon
event to operator alert breaks at two seams: the
selfdef-collector-tetragon hardcodes `Informational`, and no
sigma rule promotes Tetragon agent-guard events to findings.
The fix is designed in `docs/sdd/001-ai-machine-end-to-end.md`
(closes F-2026-001 / -002 / -003 / -006). Until that
implementation lands, treat the agent-guard "you'll get a
notifier ping on a violation" claim as **planned, not
shipped**.

### Added — `agent-guard` v0.3.0: pod-label scope for Kubernetes
- New `scope` config key in `agent-guard.toml` selects how the
  shipped policies decide "what counts as inside an agent
  container":
  - `container` (default, unchanged from v0.2.0) — `matchNamespaces:
    Pid NotIn [host_ns]`. Works on every container runtime.
  - `pod-label` — `matchPodSelector: matchLabels.<key>=<value>`.
    Kubernetes-only; narrower because only pods carrying the
    operator-defined label fire the policy.
- Two new keys back the pod-label scope: `pod_label_key` and
  `pod_label_value` (defaults `selfdef.io/agent` / `true`). Both
  are required when `scope = "pod-label"`; apply.sh refuses
  without them with a clear error.
- `lib.sh` gains `render_pod_scope()` which rewrites every
  rendered policy's `matchNamespaces` block to `matchPodSelector`.
  It runs *after* the policy-specific post-render hooks so the
  gpu-device-guard's `matchNamespaces`-anchored awk stays valid.
- 5 new integration tests cover: pod-selector splicing across all
  five policies, the default `container` scope leaving
  `matchNamespaces` intact, `pod-label` without required keys
  refused, invalid scope value refused, and the gpu-device-guard's
  `matchBinaries` block surviving the pod-scope swap when the
  allowlist is set.
- README documents the new scope table + the sample k8s Pod
  manifest with `selfdef.io/agent: "true"`.
- Module bumps to `0.3.0`. Roadmap drops the pod-label follow-up
  from the remaining-work list.

### Added — `agent-guard` v0.2.0: GPU device guard
- New `gpu-device-guard` TracingPolicy ships in the `agent-guard`
  bundle. Watches `security_file_open` against GPU device nodes
  (`/dev/nvidia`, `/dev/nvidiactl`, `/dev/nvidia-uvm*`,
  `/dev/nvidia-modeset` by default) from inside containers
  (`matchNamespaces: Pid NotIn [host_ns]`). A `matchBinaries: NotIn`
  selector filters out the operator's allowlist of permitted
  in-container binary paths; anything else opening a tracked device
  trips the policy.
- New host-config keys: `gpu_device_enabled` (default true),
  `gpu_device_action` (audit/enforce defaults via the existing
  per-policy resolver), `gpu_device_paths` (CSV of device-path
  prefixes — empty = ship default NVIDIA set; populate to add AMD
  ROCm `/dev/kfd`, Intel Habana `/dev/accel`, etc.), and
  `gpu_device_allowlist` (CSV of in-container binary paths
  permitted to open those devices — empty = match every binary).
- Apply / check / uninstall all extended to handle the fifth policy.
  `lib.sh` gains `render_gpu_policy()` that rewrites the device
  prefix block and the binary allowlist (or drops the
  `matchBinaries` selector entirely when the allowlist is empty,
  inverting the semantic from "allowlist" to "match every in-container
  binary").
- Module bumps to `0.2.0`. README + roadmap updated; the GPU
  follow-up is removed from the remaining-work list.
- 4 new integration tests:
  - default render keeps NVIDIA prefixes and drops `matchBinaries`
    with an empty allowlist
  - non-empty allowlist keeps `matchBinaries` and splices values
  - operator-supplied `gpu_device_paths` fully replace the shipped
    NVIDIA defaults
  - `gpu_device_enabled = false` removes any stale render

### Added — selfdef-daemon `/metrics` endpoint (Prometheus exposition)
- New `GET /metrics` route on the existing API surface (UNIX socket
  + TCP), rendering Prometheus exposition format
  (`text/plain; version=0.0.4`). Operators point Prometheus at the
  same address that already serves `/status` and `/events`. The
  observability module's default `scrape_targets` now includes
  `localhost:8443` alongside Tetragon's `localhost:2112`.
- Counters: `selfdef_events_total`, `selfdef_events_by_class_total{class_uid}`,
  `selfdef_findings_total`, `selfdef_findings_by_severity_total{severity_id}`,
  `selfdef_ingest_lag_events_total`. Gauges: `selfdef_uptime_seconds`,
  `selfdef_store_events`, `selfdef_build_info{version,schema,host_tag}`.
  Label cardinality is bounded — high-cardinality fields (host_tag,
  source string) are kept out of per-series labels so a busy host
  doesn't blow up Prometheus's TSDB.
- A `selfdef-api::Metrics` Arc is shared between the API state
  (which serves the endpoint) and a new ingest task the daemon
  spawns (`run_metrics_ingest`) that subscribes to the bus and
  bumps counters per event. Lag from a slow subscriber is surfaced
  as `selfdef_ingest_lag_events_total` rather than swallowed.
- 5 unit tests (`record_event`, findings-bucket gating, exposition
  format validity, label escaping, lag accumulation) plus 3
  integration tests (Content-Type + headers, in-process counter
  ingest end-to-end via the spawned task, store gauge alignment).
- Observability module: dashboard JSON gains three new panels —
  "selfdef events / second by class", "selfdef findings / second
  by severity", "selfdef hot-store size". Default `scrape_targets`
  now picks up both Tetragon and the daemon.

### Added — AI-machine track: `tetragon` + `agent-guard` + `observability` modules
- New `tetragon` module (v0.1.0, hardening, `phase = "pre"`):
  substrate for everything Tetragon-based. Renders
  `/etc/tetragon/tetragon.yaml` byte-stably from the host config,
  owns the TracingPolicy drop directory, exposes the built-in
  Prometheus metrics endpoint, points Tetragon's event JSONL at a
  path the daemon's `eventstream` collector can tail. Refuses to
  apply if `tetragon` / `systemctl` aren't on `PATH`. Restarts the
  service only when the rendered config actually changes bytes —
  re-running apply on a converged host is a true no-op. Provides
  `tetragon-tracing` / `tetragon-policies` / `metrics-endpoint`.
- New `agent-guard` module (v0.1.0, hardening, `depends_on =
  ["tetragon"]`): four TracingPolicies tuned for AI agents running
  in Docker / Podman / containerd containers:
  - `etc-write-guard` — `security_file_open` with write intent
    under `/etc/`.
  - `container-shell-guard` — `execve` of `bash` / `sh` / `dash`
    / `zsh` / `ash`.
  - `egress-guard` — `tcp_connect` to non-allowlisted destinations
    (CSV CIDR allowlist via `egress_allowlist`).
  - `securemessage-guard` — forward-looking stub for a SecureMessage
    endpoint; auto-downgrades to `Post` action whenever the
    endpoint is unset so the placeholder never SIGKILLs anything.
  Two profiles: `audit` (Post-only, the bring-up default) and
  `enforce` (Sigkill). Per-policy `*_action = default | post |
  sigkill` overrides let operators ramp up policies individually.
  Container scope uses Tetragon's `matchNamespaces` to skip the
  host PID namespace — works on every container runtime without
  needing k8s labels.
- New `observability` module (v0.1.0, observability, `phase =
  "post"`, `depends_on = ["tetragon"]`): Prometheus scrape config
  + Grafana dashboard JSON for the selfdef stack. Two profiles:
  `bundled` (drops files under `/etc/prometheus/conf.d/` and
  `/var/lib/grafana/dashboards/selfdef/`, reloads Prometheus) and
  `external` (renders into a staging dir for the operator to sync
  out). Dashboard: four panels — Tetragon events/sec, kills by
  policy, process-cache utilization, BPF map errors.
- 23 new hermetic dry-run smoke tests cover the three modules:
  byte-stable config rendering + idempotent reapply (tetragon),
  per-policy action resolution + egress allowlist splicing +
  SecureMessage stub behaviour + check drift detection +
  uninstall cleanup (agent-guard), bundled vs external rendering +
  scrape target splicing + dashboard JSON validity + idempotent
  reapply + empty-target refusal (observability).
- Roadmap (`docs/src/modules-roadmap.md`) gains rows for the three
  new modules and the "AI-machine track" callout in remaining
  work, with pod-label / GPU device-guard variants + a
  selfdef-daemon `/metrics` endpoint flagged as follow-ups.

### Added — `selfdefctl events emit` + `integrity-sentinel` notifier wiring
- New `selfdefctl events emit` subcommand appends a single OCSF
  Event line to a JSONL stream the daemon's existing `eventstream`
  collector tails. Modules and helper scripts can now surface
  findings onto the bus without hand-rolling the envelope in bash:
  the Rust side builds a real `selfdef_core::Event`, so taxonomy,
  schema version, derived `type_uid`, and metadata are guaranteed
  correct. Args: `--class-uid`, `--activity-id` (default 1),
  `--severity` (informational|low|medium|high|critical|fatal),
  `--source`, `--message`, `--host-tag` (defaults to
  $HOSTNAME / /etc/hostname), `--out <path>` (required).
- `integrity-sentinel` v0.1.1: when `event_stream_path` is set in
  the module's host config, drift now emits a Detection Finding
  (OCSF class 2004) to that JSONL stream. The daemon picks it up,
  the responder routes Findings-category events through the
  notifier chain, and ntfy / Signal fires. Severity defaults to
  `high` for `strict` and `low` for `warn-only`; both are
  overridable via `event_severity_strict` / `event_severity_warn`.
  Leave `event_stream_path` unset to suppress emission — the
  structured-status surface is unaffected. Best-effort: a
  `selfdefctl` not on PATH or a failed emit logs a warning and
  never fails the apply / check run.
- 5 new unit tests for `selfdefctl events emit` (round-trips
  through `Event`, atomic append doesn't clobber prior lines,
  unknown severity / empty source rejected, parent dir is created
  on demand) plus 1 integration test that exercises
  `integrity-sentinel`'s apply path with `event_stream_path` set
  and asserts the resulting JSONL line parses back into a valid
  Findings-category Event.
- Roadmap docs (`docs/src/modules-roadmap.md`) updated to remove
  both shipped items (`modules uninstall`, integrity-sentinel
  notifier wiring) from the remaining-work list and to include the
  `uninstall` row in the lifecycle table.

### Added — `selfdefctl modules uninstall`
- New subcommand drives each active module's `uninstall.sh` in the
  inverse of apply order: dependents come down before the modules
  they depended on, and phases unwind `post → main → pre`.
- Destructive by design — non-dry-run runs require
  `--confirm <hostname>` matching this host (mirrors the `panic`
  subcommand's confirmation pattern). Mismatched or absent
  `--confirm` exits 2 with a clear message.
- `--dry-run` previews the run without `--confirm`, propagating
  `SELFDEF_DRY_RUN=1` so module scripts can short-circuit.
- Standard `--only` / `--except` filters apply, accepting either a
  bare slug or a `slug#instance` form.
- Modules whose manifest never declared an uninstall script (or use
  `kind = "debian-package"`) are reported as `skipped: no uninstall
  script declared` so a host-wide uninstall still produces a useful
  aggregate.
- Refactored the internal lifecycle runner around a small
  `LifecyclePolicy` (reverse order + tolerate-missing-script) to
  share the apply / check / uninstall machinery without forking.
- 3 new unit tests (reverse apply order, reverse phase order,
  missing-script detection) and 6 integration tests in
  `tests/cli_modules_uninstall.rs` cover ordering, the skipped path,
  both confirmation refusals, the matching-confirm happy path, and
  `--only` filtering.

### Added — JetStream durability for the NATS bridge
- New `[bus.nats.jetstream]` config block. When `enabled = true`, the
  bridge:
  - Ensures a JetStream stream (`stream_name`, default
    `selfdef-events`) capturing `<subject_prefix>.>` with operator-
    tunable retention (`max_age_secs` / `max_bytes` / `max_msgs`).
  - Creates a per-host durable pull consumer named
    `<durable_consumer_prefix>-<host_tag>` so each daemon tracks its
    own ack progress and a restart resumes mid-stream.
  - Publishes locally-originated events via `js.publish(...).await`
    and waits for the server ack — outages stall publishes rather
    than silently dropping them.
  - Acks each inbound message after republishing it onto the local
    bus (or recognizing it as a self-echo).
- Same loop-avoidance machinery as Core mode (host_tag check on both
  sides). At-least-once redeliveries are safe because each event
  carries a UUIDv7 and the store sink dedupes by id.
- Public API additions in `selfdef-nats`:
  - `JetStreamConfig` struct + nested in `NatsConfig`.
  - `durable_consumer_name(prefix, host_tag)` helper that sanitizes
    host_tags to the JetStream durable-name grammar (alphanumeric +
    `-` + `_`).
- 3 new unit tests: `durable_consumer_name` builds the expected
  string, sanitizes disallowed chars, and the `JetStreamConfig`
  defaults are conservative (disabled, 7-day retention, unlimited
  size).
- async-nats `jetstream` feature added to the workspace dep flags.
- Docs: `docs/nats.md` gains a "Modes: Core vs JetStream" section
  with a runnable config snippet, retention semantics, and explicit
  notes on at-least-once delivery + the dedupe contract. Example
  config gains the `[bus.nats.jetstream]` block.

### Added — Dashboard control surface
- The bundled PWA in `dashboard/` gains a **Control** panel that wires
  up the M13/M14 write endpoints:
  - **Reload rules** — `POST /rules/reload`. Shows the resulting
    `rules_loaded` count.
  - **Panic** — `POST /panic`. Confirmation requires typing the host
    tag (matches `selfdefctl panic --confirm`) and clicking through a
    second browser-level confirm dialog.
  - **Run action** — `POST /actions/{name}/run`. The action dropdown
    is populated from `GET /actions`. Leaving the event-id field
    blank runs the action against the most-recent finding.
- New `post()` helper in `dashboard/app.js` that parses the JSON body
  from both 2xx and error responses so the dashboard can surface what
  actually went wrong (`{"error": "..."}`).
- Result indicator (`#control-result`) renders ok / error states with
  green / red coloring and the API's own status text.
- Service worker now bypasses every non-`GET` request — control verbs
  pass straight through, no chance of an offline-cached fallback
  swallowing a panic dispatch. `/actions` is also added to the
  always-network list so the action list stays fresh.
- Docs: `docs/api.md`'s Dashboard section describes the new control
  surface and how the read-vs-control token gate is reflected in the
  UI.

### Added — M15 (NATS bridge for multi-host correlation)
- New crate `selfdef-nats` — pumps events between selfdef daemons over
  NATS Core. The local in-proc broadcast stays the source of truth for
  every in-process subscriber (collectors, correlator, responder,
  store sink, API SSE stream); the bridge is a sidecar task with two
  loops:
  - **outbound**: subscribes to the local bus and publishes locally-
    originated events to `<subject_prefix>.<host_tag>`.
  - **inbound**: subscribes to `<subject_prefix>.>` and republishes
    received events onto the local bus, dropping any whose
    `host_tag` matches ours (self-echo loop guard).
- Loop avoidance is two-layered on purpose: outbound filters by
  `event.host_tag == local`, inbound drops the mirror. The host_tag
  check is O(1) and doesn't need the deduper dance UUIDv7 enables.
- `[bus.nats]` config block: `enabled`, `url`, `subject_prefix`.
  Default prefix `selfdef.events`. Disabled by default. Multiple NATS
  servers are comma-separated per the async-nats URL grammar; TLS via
  the `tls://` scheme.
- Daemon wires the bridge as another supervised task next to the API
  and the store sink. SIGTERM/SIGINT cancel propagates through; the
  bridge tears down both child tasks before exiting.
- async-nats 0.48 (latest as of this PR). Picked deliberately over the
  0.37 baseline because that pull also yanked the unmaintained
  `rustls-pemfile` + old `rustls-webpki` transitive deps that fell out
  of `cargo deny check advisories`.
- Unit tests for the bridge cover the subject layout
  (`outbound_subject` / `inbound_subject`), subject sanitization
  (host_tags with `.`, `*`, `>`, whitespace), the local-origin check,
  and JSON round-trip on the wire format.
- Docs: new `docs/nats.md` describes the topology, subject layout,
  loop avoidance, and a one-liner smoke test against `nats-server`.
- Documented non-goals: this is NATS Core only (no JetStream
  durability yet); no built-in auth (operators bring NATS mTLS / NKey
  / JWT as needed).

### Added — M14 (per-token capabilities for the API)
- `[api].control_token_file` — a second, optional bearer token. Read
  endpoints accept either the existing `token_file` or
  `control_token_file`; control endpoints (`/rules/reload`, `/panic`,
  `/actions/{name}/run`) require the control token specifically.
- New `selfdef_api::Capability` (`Read` | `Full`) request extension
  set by the auth layer based on which token matched (or
  unconditionally `Full` for UNIX-socket clients). Control handlers
  pull a `RequireControl` extractor that returns `403 Forbidden` for
  `Read` requests and `401 Unauthorized` for unauthenticated.
- New `selfdef_api::with_full_capability` / `with_capability` helpers.
  Tests use them to stamp a capability onto the request without going
  through bearer auth. The UNIX-socket transport uses `with_capability(_, Full)`
  internally — same primitive, no special cases.
- 6 new integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: read-only token on read endpoints (200), read-only token on
  `/actions` discovery (200), read-only token on each control verb
  (403), and the anonymous control-verb path (401). 19 cases total.
- Docs: `docs/api.md` gains a fleshed-out auth-boundary section with
  token mint + rotate recipes. Example config gains the new
  `control_token_file` field with annotated semantics. README adds the
  M14 checkbox.

### Added — M13 (control-plane verbs + TLS/mTLS for the API)
- **Control-plane endpoints** in `selfdef-api` (write side):
  - `POST /rules/reload` — re-reads the rules directory, returns
    `{rules_loaded: N}`. Returns `503` when the daemon hasn't wired a
    correlator handle (e.g. correlator disabled in config).
  - `POST /panic` — body `{confirm, message?}`. Validates `confirm`
    against the daemon's `host_tag` (same safety belt as
    `selfdefctl panic`) and direct-fires the panic action set.
  - `POST /actions/{name}/run` — body `{event}` *or* `{event_id}`.
    Runs a single named action against the supplied / stored event
    via the responder's new `dispatch_single` method. Bypasses the
    allowlist on purpose — the auth boundary is the API token / UNIX
    socket permissions.
  - `GET /actions` — discovery: returns registered action names in
    order so dashboards / scripts can enumerate them.
- **Audit trail.** Every control verb publishes a synthetic event on
  the bus (`source = "selfdef.api"`, class `INCIDENT_FINDING`,
  severity `Informational`) with the action, status, and details. The
  store sink writes it to disk so `selfdefctl events tail` shows who
  poked the daemon.
- **`Responder` gains** `dispatch_single(name, event)` and
  `action_names()`. The bus-driven responder and the API now share
  one `Arc<Responder>` via clone rather than each having its own —
  same action set, one allowlist, one dry-run flag.
- **`ApiState` gains** an optional `ControlHandles` block (correlator,
  responder, publisher). Builder methods (`with_correlator`,
  `with_responder`, `with_publisher`) keep tests able to construct a
  read-only state with no control handles, in which case control
  endpoints return `503 Service Unavailable`.
- **TLS / mTLS for the TCP transport.** New `[api.tls]` block:
  `cert_path`, `key_path`, `client_ca`. With cert+key only: vanilla TLS
  (bearer token still authenticates). Add `client_ca` → mTLS (client
  certificate required and verified). Uses `tokio-rustls` 0.26 with the
  ring provider; the TLS-wrapped accept loop drives hyper directly,
  matching the existing UDS pattern. No CA bundle for client verification
  shipped — operators bring their own.
- New integration tests in `crates/selfdef-api/tests/m12_api.rs`
  covering: `/actions` discovery, `/rules/reload` 503 when correlator
  missing, `/panic` hostname mismatch returns 400, `/panic` happy path,
  `/actions/{name}/run` dry-run, unknown action 404, missing
  body 400. 13 cases total, up from 6.
- Docs: `docs/api.md` extended with the control-endpoint table, the
  auth-boundary note, and a TLS / mTLS section with a self-signed
  recipe. Example config gains `[api.tls]`.

### Added — Milestone 12 (Mobile dashboard / read-only HTTP API)
- New crate `selfdef-api`: axum-based read-only HTTP API. Endpoints:
  - `GET /status` — host_tag, schema_version, crate_version,
    event_count, uptime_secs.
  - `GET /events?n=N` — last N events from the hot store (default 50,
    capped at 1,000).
  - `GET /findings?n=N` — last N events with `category_uid = 2`.
  - `GET /events/stream` — Server-Sent Events live tail. Subscribes a
    fresh bus subscriber per client and forwards each event as a `data:`
    frame; lagged subscribers get a single `event: lagged` frame and
    resume; clients disconnect → forwarder exits on next send.
- Two transports, either or both at once via `[api]` config:
  - **UNIX socket** (default `/run/selfdef.sock`, mode `0660`). Trusted
    via filesystem permissions; no token. Driven via a custom hyper-util
    accept loop because axum 0.7's `axum::serve` is TCP-only.
  - **TCP** (off by default). Requires `Authorization: Bearer <token>`
    matching the contents of `token_file`. CORS is permissive on the
    response side; operators are expected to bind localhost and put a
    reverse proxy in front for TLS termination.
- Vanilla-JS PWA in `dashboard/`: single-file `app.js`, no bundler, no
  `node_modules`. Renders findings + events lists, polls `/status`
  every 5s, and exposes a "live stream" toggle that opens an
  `EventSource` against `/events/stream`. Service-worker shell-caches
  the static assets but never the API responses themselves. Manifest
  JSON makes it installable on iOS/Android.
- Daemon wiring: when `[api] enabled = true`, a new task spins up the
  API alongside the collectors / correlator / responder. Store and bus
  moved behind `Arc` so the API and the existing sink share ownership
  cleanly. New `build_api_config` helper translates the
  string-shaped `[api]` TOML into the typed `selfdef_api::ApiConfig` —
  a malformed `tcp_addr` logs a warning and disables the TCP transport
  rather than crashing the daemon.
- Integration test `crates/selfdef-api/tests/m12_api.rs` exercises the
  router via `tower::ServiceExt::oneshot`: status returns the host tag
  and counters; `/findings` filters by `category_uid = 2`;
  `/events?n=N` honors the page param; an unknown route 404s; the
  event JSON round-trips back to `selfdef_core::Event` envelopes.
- Documentation: new `docs/api.md` covers the transports, endpoints,
  and dashboard wiring; example config gains a documented `[api]`
  section.

### Added — M10 polish (eBPF: argv capture, LSM file_open, do_unlinkat kprobe)
- **argv capture** in the `execve_enter` tracepoint program. Walks the
  userspace `argv` pointer array with `bpf_probe_read_user` plus
  `bpf_probe_read_user_str_bytes`, bounded at 16 entries and 256 bytes
  total. Sets `argv_truncated` when the buffer fills or the entry cap
  is reached without seeing the NULL terminator. The OCSF
  `process.cmdline` now reflects the captured argv (joined by spaces);
  the `raw` payload carries the structured `argv` array and the
  `argv_truncated` flag for rule matching.
- **LSM `file_open` BPF program**. Observe-only (always returns 0, never
  vetoes). Reports pid/uid/comm/flags. Path capture is deferred until
  the project gains generated `vmlinux.rs` bindings — the ring-buffer
  schema already has `path` and `path_len` fields so the path can be
  layered on without touching userspace.
- **`do_unlinkat` kprobe BPF program**. Reports pid/uid/comm. Same
  path-deferral rationale as the LSM hook.
- New userspace API `selfdef_collector_ebpf::EbpfProbes` carries the
  three opt-in flags (`execve`, `lsm_file_open`, `kprobe_unlinkat`)
  from config into the collector. `EbpfCollector::with_probes()`
  selects what to attach; the existing `EbpfCollector::new()` keeps
  the conservative default (execve only).
- Each probe attach is independent and **fail-soft**: missing program
  in the `.bpf.o`, missing kernel BTF, missing `CONFIG_BPF_LSM=y`, or
  a kprobe that points at an inlined symbol all log a warning and
  leave the other probes running. The daemon never aborts on a
  partial attach.
- Daemon wires the three `[collectors.ebpf]` `enable_*` config bits
  into `EbpfProbes`. Example config + `docs/ebpf.md` updated to drop
  the "reserved" / "not yet implemented" notes and describe the
  current capabilities and limitations.
- Unit-test coverage extended in `selfdef-collector-ebpf`:
  `argv_truncated` propagates into the OCSF `raw` payload;
  `FileOpenEvent` and `UnlinkEvent` round-trip into properly classed
  `FILE_SYSTEM_ACTIVITY` events; `EbpfProbes::default()` matches the
  conservative shipping config.

### Added — Milestone 11 (Forensics + Velociraptor integration)
- New responder action `forensics_bundle`: on Critical findings, writes an
  evidence bundle to `forensics_dir/<event-uuid>/` containing the
  triggering event JSON, host metadata (`uname`, `/etc/os-release`,
  `/proc/version`, `/proc/cmdline`, `uptime`, `mounts`, `modules`,
  `passwd`, `group`), network state (`/proc/net/tcp`, `/proc/net/udp`,
  `ss -tnap`), kernel ring buffer tail (`dmesg`, bounded to 2,000
  lines), recent journal (`journalctl -n 2000`), and a per-pid
  snapshot of `/proc/<pid>/{cmdline,environ,status,maps,stat,io}` plus
  `exe_link`, `cwd_link`, and `fd/` listing when the event carries an
  actor pid. A `manifest.txt` records what was captured and what was
  skipped (with the underlying error). Best-effort throughout — missing
  files or unreadable subprocesses don't abort the bundle.
- New responder action `velociraptor_escalate`: invokes a configured
  Velociraptor binary with operator-defined argv. The placeholders
  `{event_id}` and `{host_tag}` are substituted before invocation, so
  the same selfdef config can drive client-side artifact collection,
  server-side hunt creation, or any other Velociraptor workflow. Empty
  args = action runs cleanly with no side effects (useful when the
  action is allowlisted but a particular host has no Velociraptor
  deployment).
- New `[responder]` config fields: `forensics_dir`,
  `velociraptor_binary`, `velociraptor_args`. Defaults are conservative
  — `forensics_dir` lives under `/var/lib/selfdef/forensics`, the
  Velociraptor binary path is set but `velociraptor_args` is empty so
  the action is opt-in even after being added to `allowed_actions`.
- `selfdefctl forensics list` — lists bundle directories in
  `forensics_dir` with per-bundle size.
- `selfdefctl forensics collect <event-id>` — manually triggers a
  forensics bundle for any event already in the hot store. Useful for
  retroactively building evidence on an event that was caught before
  `forensics_bundle` was added to the allowlist.
- Example `config/selfdef.toml.example` extended with both new fields
  and two ready-to-use Velociraptor argv templates (client collect,
  server hunt).
- Integration test `crates/selfdef-daemon/tests/m11_forensics.rs`:
  - **bus → responder → disk**: a synthetic Critical finding published
    onto the bus produces a `forensics_dir/<uuid>/` directory with
    `event.json` (round-trips back to the same event id) and a
    `manifest.txt` that records the `proc/* SKIP` line for the pidless
    event.
  - **dry-run safety**: dry-run on `forensics_bundle` doesn't create
    the target directory.
  - **velociraptor placeholders**: dry-run rendering of
    `velociraptor_escalate` substitutes `{event_id}` and `{host_tag}`
    in every arg.
- Toolchain pin moved from 1.83 to 1.88 to match the edition 2024
  requirement and current dependency MSRVs (notably `time` and the
  `icu_*` chain). The workspace `unsafe_code` lint moved from `forbid`
  to `deny` with a documented carve-out so `selfdef-ebpf-common` can
  still implement `bytemuck::Pod` for ring-buffer record types. The
  ssh-wrap binary added `#![cfg_attr(test, allow(unsafe_code))]` to
  accommodate the Rust 2024 unsafe-`set_var` for its test-only env
  setup.

### Added — Milestone 10 (Custom eBPF programs via aya)
- New crate `selfdef-ebpf-common`: shared `#[repr(C)]` POD types between
  kernel-space BPF programs and the userspace loader. Ships
  `ProcessExecEvent`, `FileOpenEvent`, `UnlinkEvent` with an
  `EventKind` discriminator byte for ring-buffer record dispatch.
  `userspace` feature exposes `bytemuck::Pod` impls and decode helpers
  (`comm_str`, `argv_strings`); `ebpf` feature is `no_std`-compatible
  for the BPF target.
- New crate `selfdef-collector-ebpf`: userspace loader built on aya
  0.13. Loads a precompiled BPF object via `aya::Ebpf::load_file`,
  attaches the `execve_enter` tracepoint to `syscalls/sys_enter_execve`,
  takes ownership of the `EVENTS` ring buffer, wraps it in
  `tokio::io::unix::AsyncFd`, and drains records into OCSF events
  published on the bus.
- **Graceful degradation**: if the BPF object isn't installed at the
  configured `program_path`, the collector logs a warning at startup
  and runs idle. Daemon stays up; other collectors keep working. Same
  daemon binary can ship to hosts with and without eBPF support — config
  drives the difference.
- Kernel-space crate at `bpf/selfdef-bpf/` (intentionally **outside the
  main workspace** with its own `[workspace]` block so
  `cargo build --workspace` never tries to compile it). Ships one
  tracepoint program: `execve_enter`. Captures pid/tgid/ppid/uid/gid/comm
  and emits to a 256 KB ring buffer.
- Build orchestration via `xtask`:
  - `cargo xtask build-bpf [--release]` — compile with nightly
    toolchain, `-Z build-std=core`, target `bpfel-unknown-none`.
  - `cargo xtask install-bpf [<dest>]` — build release + install to
    `/usr/lib/selfdef/selfdef.bpf.o` (or custom path).
- Systemd drop-in `packaging/systemd/selfdefd.service.d/ebpf.conf`:
  grants `CAP_BPF` + `CAP_PERFMON` ambient (no full root needed on
  Linux >= 5.8), raises `LimitMEMLOCK=infinity` for older kernels that
  still account BPF map pages there. Default install keeps the
  capability-light ambient set; you opt-in by installing the drop-in.
- New `[collectors.ebpf]` config section with `enabled`,
  `program_path`, `enable_execve`, `enable_lsm_open` (reserved),
  `enable_kprobe_unlink` (reserved). Daemon wires the collector as a
  task with the same shutdown semantics as the other collectors.
- Documentation `docs/ebpf.md` covering prerequisites (`bpf-linker`,
  nightly toolchain, rust-src), kernel requirements (BTF, ring buffer
  support), capabilities drop-in, troubleshooting, and a clear ledger
  of what's actually shipped versus reserved-for-future-work.
- Integration test `crates/selfdef-daemon/tests/m10_ebpf.rs`:
  - **graceful degradation**: collector runs idle when no BPF object
    exists; shutdown is clean.
  - **event conversion**: `ProcessExecEvent` → OCSF `Event` round-trips
    through the bus into SQLite with correct class/activity/process
    fields. Three synthetic execs (`ls`, `curl`, `sshd`) are decoded,
    published, and asserted. Loading a real BPF program needs CAP_BPF
    + a real kernel + the BPF toolchain — out of scope for `cargo test`
    but documented for manual smoke tests.

### Honest deferrals
- **argv capture from the execve tracepoint.** Reading the user-pointer
  array requires bounded looped `bpf_probe_read_user` calls. The
  infrastructure (buffer in `ProcessExecEvent`, `argv_truncated` flag,
  decode helper, OCSF mapping) is in place; the BPF-side capture lands
  in a follow-up.
- **LSM `file_open` program.** Type reserved in `EventKind::FileOpen`,
  userspace decode path implemented, kernel-side program not yet
  shipped. Requires `CONFIG_BPF_LSM=y` and `bpf` in `CONFIG_LSM`.
- **`kprobe:do_unlinkat` program.** Type reserved as
  `EventKind::Unlink`, userspace decode implemented, kernel-side
  program not yet shipped.
- Stale M1 stub crates (`selfdef-ebpf-types`, `selfdef-ebpf-progs`)
  removed in favor of the M10 layout.

### Added — Milestone 9 (Client-side SSH wrapper)
- New binary crate `selfdef-ssh-wrap` (`selfdef-ssh-wrap`): a drop-in
  replacement for `ssh` that enforces per-host policy and emits OCSF
  events for every session. Designed for fast cold-start (no async
  runtime, no heavy deps).
- argv classifier (`crates/selfdef-ssh-wrap/src/argv.rs`) that
  distinguishes flags, value-taking options (`-o`, `-i`, `-p`, ...),
  attached-value options (`-pPORT`), `--` markers, and positional
  arguments. Extracts the target spec and supports filtering of
  policy-denied flags.
- Policy file (`~/.config/selfdef/ssh-wrap.toml`, override via
  `$SELFDEF_SSH_POLICY`):
  - `[defaults]` with secure baseline: no agent fwd, no X11, no port
    forwarding, `StrictHostKeyChecking=accept-new`,
    `ExitOnForwardFailure=true`, conservative timeouts.
  - `[hosts."<pattern>"]` per-host overrides. Patterns support exact
    match, `*.suffix`, `prefix*`. No regex.
  - Resolved policy is rendered as `-o key=value` ssh args prepended to
    the user's invocation; user-supplied flags conflicting with policy
    are stripped.
- Event emission (`crates/selfdef-ssh-wrap/src/events.rs`): writes OCSF
  events to `~/.local/share/selfdef/ssh-wrap.jsonl` (override via
  `$SELFDEF_SSH_EVENT_LOG`). Three event kinds:
  - **session start** — `SSH_ACTIVITY` / Open, with target, host, port,
    user, and `first_seen` flag (computed via `ssh-keygen -F`).
  - **policy strip** — `DETECTION_FINDING` / Low, lists the args removed
    from the user's invocation.
  - **session end** — `SSH_ACTIVITY` / Close, with duration and exit
    code; status_id reflects success/failure.
- New collector `selfdef-collector-eventstream`: tails a JSONL file of
  pre-formed selfdef events and republishes onto the bus. Used by the
  ssh wrapper and any other producer. Each event must already be a
  well-formed `Event`; malformed lines are logged and skipped.
- `[collectors.eventstream]` config section with `enabled`, `paths`,
  `read_from`.
- Daemon wires N independent eventstream collector tasks (one per path).
- New rule `rules/sigma/defense_evasion/ssh_wrap_policy_strip.yml` +
  tests: catches the wrapper's policy-strip findings as Medium-severity.
  Maps to `attack.defense_evasion`.
- Example policy file `packaging/ssh-wrap-policy.toml.example` with
  annotated defaults and per-host examples.
- Install guide `docs/ssh-wrap-install.md`: PATH-shadowing pattern,
  daemon wiring, caveats (host-key change detection delegated to ssh
  itself, in-session forwarding invisible to the wrapper).
- Integration test `crates/selfdef-daemon/tests/m9_ssh_wrap.rs`
  exercises the JSONL-to-bus-to-SQLite path with three event kinds.

### Added — Milestone 8 (Honeytokens + responder actions)
- New collector `selfdef-collector-canary`: inotify-based watcher that
  emits a `DETECTION_FINDING` with `Severity::Critical` and ATT&CK tag
  `T1552.001` whenever any configured path is read, opened, modified,
  has attributes changed, is deleted, or is moved. Watches are installed
  once at startup; recreating a watched file requires a daemon restart
  (documented limitation).
- Responder rewritten around an [`Action`] trait. Five built-in actions:
  - `notify` — sends through the existing `Notifier` chain.
  - `snapshot_proc` — writes `/proc/<pid>/{cmdline,environ,status,maps,stat,io}`
    plus `exe_link` and `cwd_link` symlink targets to
    `snapshot_dir/<event-uuid>/`. Best-effort: per-file read errors are
    swallowed.
  - `kill_pid` — runs `kill -TERM <pid>`. Pid extracted from
    `event.actor.process.pid` or `event.process.pid`.
  - `lockdown_egress` — invokes a configurable shell script with
    `activate`. Default path `/usr/local/sbin/selfdef-lockdown.sh`. Operator
    owns the nftables logic.
  - `revoke_session` — invokes a configurable script with the user's
    name. Default path `/usr/local/sbin/selfdef-revoke-session.sh`.
- All actions support `dry_run=true` and produce structured `ActionOutcome`
  values (`Success` / `DryRun` / `Skipped`). Failing actions log a warning
  without stopping siblings.
- Responder allowlist: each action's `name()` must appear in
  `responder.allowed_actions` to fire. Default config ships only `notify`
  enabled.
- `selfdefctl panic --confirm <hostname>` is now real:
  - Validates hostname match (prevents accidental fire on the wrong box).
  - Builds a synthetic Critical Finding with `source = "selfdef.panic"`.
  - Dispatches via `Responder::fire` with a 2-action set: `notify` +
    `lockdown_egress`.
  - Respects `responder.dry_run` from config.
- New rule `rules/sigma/credential_access/canary_access.yml` documents
  the canary path in the rule set (and surfaces in ATT&CK coverage).
- New config sections:
  - `[collectors.canary]` with `enabled` and `paths`.
  - `[responder]` extended with `snapshot_dir`, `lockdown_script`,
    `revoke_session_script`.
- Example operator script `packaging/scripts/selfdef-lockdown.sh`
  (annotated nftables-based egress lockdown with lifeline allowlist via
  `$SELFDEF_LIFELINES` env var).
- Integration test `crates/selfdef-daemon/tests/m8_honeytokens.rs`
  exercises the full path: real inotify, real bus, real responder, all
  five actions in dry-run mode. Verifies the canary finding lands in
  SQLite with the expected ATT&CK tag.

### Added — Milestone 7 (Detection-as-code CI)
- Per-rule test files: every rule may have a sibling `<rule>.tests.yaml`
  declaring partial input events and an `expected_findings` count. The
  test runner builds full events from minimal specs, runs each test
  against a single-rule engine, asserts firing counts.
- New crate APIs:
  - `selfdef_correlator::Engine::with_rules(Vec<CompiledRule>)`
    constructor for test isolation.
  - `selfdef_correlator::sigma::AttackCoverage` and
    `Engine::attack_coverage()` — walks loaded rules, returns techniques,
    tactics, and per-tactic rule counts.
  - `selfdef_correlator::lint` module: `lint_rule`, `lint_rules`, `Issue`,
    `Severity`. Checks for missing metadata (description, attack tags,
    technique tag, falsepositives, author), undefined selections in
    conditions, count-by fields that don't look like known event paths,
    duplicate rule IDs across files.
- `Engine::load_dir` now skips `*.tests.yaml` and `*.tests.yml` files
  during rule discovery (those are fixtures, not rules).
- 7 per-rule test files covering the 7 starter rules with 25+ test cases
  total — positive matches, negative matches, logsource gating,
  aggregation thresholds.
- New integration test `crates/selfdef-correlator/tests/rule_tests.rs`
  with three test functions:
  - `every_rule_with_tests_passes` — discovers and runs all per-rule
    fixtures, fails the build on any mismatch.
  - `rule_set_passes_lint` — fails on lint errors, surfaces warnings.
  - `attack_coverage_report` — prints the coverage matrix; fails if zero
    techniques covered.
- `selfdefctl rules lint` — runs lint with exit code 1 on errors.
- `selfdefctl rules coverage` — prints the ATT&CK coverage matrix.
- Adversary emulation directory at `tests/adversary/` with documented
  layout and `T1110.001-password-guessing/` as the first technique
  (atomic.yaml in ART format + expected.yaml contract). Full ART runner
  integration deferred to a future milestone (needs a VM/container
  sandbox to be safe in CI).

### Added — Milestone 6 (Collector fan-out)
- `selfdef-collector-journald`: real implementation. Two input modes
  selected by config (`mode = "journalctl"` or `"file"`):
  - **subprocess** spawns `journalctl --output=json --follow --no-pager`,
    optionally with `-u <unit>` filters from `collectors.journald.units`.
  - **file** tails a JSON-lines file (for tests / external pipelines).
  Maps `sshd` to `SSH_ACTIVITY`, `sudo` to `AUTHENTICATION`,
  `systemd-logind` to `AUTHORIZE_SESSION`; everything else generic.
  Priority → severity mapping (`PRIORITY=3` → High, `=4` → Medium, etc.).
- `selfdef-collector-tetragon`: real implementation. Tails Tetragon JSON
  output. Recognizes `process_exec` (→ `PROCESS_ACTIVITY`/Launch),
  `process_kprobe` with `security_file_open`-style functions
  (→ `FILE_SYSTEM_ACTIVITY`/Open with `file.path` extracted from kprobe
  args), `process_exit` (→ Terminate). Other event kinds preserve their
  raw payload.
- `selfdef-collector-suricata`: real implementation. Tails Suricata EVE
  JSON. **Alerts become `DETECTION_FINDING` directly** — Suricata is itself
  detection, so its alerts go straight to the responder. Suricata severity
  inverted to OCSF (1→High, 2→Medium, 3→Low). DNS/HTTP/TLS/flow records
  emit as informational network-class events that Sigma rules can match.
- `selfdef-config`: new `[collectors.journald]`, `[collectors.tetragon]`,
  `[collectors.suricata]` sections with typed config.
- `selfdef-daemon`: wires all three new collectors. Each enabled via its
  `enabled` flag in config; each runs as its own task with shared
  `CancellationToken` for graceful shutdown.
- New rules:
  - `rules/sigma/discovery/sshd_publickey_accepted.yml` — uses the journald
    collector; informational baseline for SSH key logins.
  - `rules/sigma/execution/webshell_pattern.yml` — uses the tetragon
    collector; detects shells spawned from nginx/apache/php-fpm parents.
- New replay corpora:
  - `tests/replay/journald/sshd_login.jsonl`
  - `tests/replay/tetragon/sensitive_file.jsonl`
  - `tests/replay/suricata/scan_alert.jsonl`
- Integration test `crates/selfdef-daemon/tests/m6_collectors.rs`:
  - journald file-mode emits classified events
  - tetragon replay emits typed events with the right class_uid
  - suricata alert lands in SQLite as a DETECTION_FINDING

### Deferred to a polish milestone
- Multi-line auditd record grouping (SYSCALL + PATH + EXECVE + EOE). The
  current M3 parser handles each line standalone, which covers the
  user-auth records selfdef cares most about today. Multi-line grouping
  is real parser work that deserves its own milestone.

### Added — Milestone 5 (Sigma engine + hot reload)
- `selfdef-correlator::sigma`: Sigma-subset rule engine. Parses YAML rules
  with metadata (`id`, `title`, `description`, `level`, `tags`, `references`,
  `falsepositives`, `author`, `date`), `logsource`, named `selection_*`
  blocks, optional `timeframe`, and `condition` strings of the form
  `<sel>` or `<sel> | count() by <field> > <N>`.
- Field matchers: equality, `|contains`, `|startswith`, `|endswith`, `|re`
  (regex). List of values within a field = OR. Dot-notation for nested
  fields (`src_endpoint.ip`, `actor.user.name`).
- `Aggregator` for time-windowed counting; clears window on fire to
  prevent re-firing on the same burst.
- ATT&CK overlay: `attack.t1234[.567]` tags → technique IDs;
  `attack.<tactic>` tags → tactic enum; both flow into the emitted finding's
  `attack` array.
- `Correlator` now loads rules from a directory; `load_rules()` is
  idempotent and atomically swaps the engine on success (failure preserves
  the previous ruleset). Backed by `Arc<RwLock<Arc<Engine>>>` so reads
  don't block reloads.
- `selfdef-daemon`: SIGHUP triggers `correlator.load_rules()`. `selfdefd`
  keeps running across reloads; `systemctl reload selfdefd` works (the unit
  already had `ExecReload=/bin/kill -HUP $MAINPID`).
- 5 initial rules in `rules/sigma/`:
  - `credential_access/ssh_bruteforce.yml` — replaces the M4 hardcoded rule.
  - `credential_access/sensitive_file_access.yml` — `/etc/shadow`, `/root/.ssh/`,
    etc. (logsource: tetragon; waits for the tetragon collector).
  - `privilege_escalation/sudo_failure.yml` — failed sudo PAM auth.
  - `persistence/sudoers_tamper.yml` — writes to `/etc/sudoers*`.
  - `persistence/setuid_binary.yml` — new files with setuid/setgid bits.
- Replay corpus: `tests/replay/auditd/ssh_bruteforce.jsonl` (4 events) +
  `ssh_bruteforce.expected.yaml` (expected firings).
- `selfdefctl` implements `rules list`, `rules validate <path>`,
  `rules test --corpus <jsonl>`.
- New integration test `crates/selfdef-daemon/tests/m5_sigma.rs`:
  - engine loads N rules from a directory
  - engine ignores non-YAML files
  - replay corpus produces the expected firing count
  - hot reload picks up new rules in-place
- M4 test updated to use the YAML rule via a tempdir rules directory
  instead of the now-removed `Correlator::new(window, threshold)` API.
- New workspace deps: `serde_yml` (maintained fork of `serde_yaml`), `regex`.

### Added — Milestone 4 (Alert path)
- `selfdef-notifier`: `Notifier` trait, `NtfyNotifier` (HTTP POST to a
  self-hosted ntfy server with optional bearer token, 3-attempt backoff),
  `SignalCliNotifier` (subprocess to `signal-cli`), `NotifierChain` that
  tries channels in order. Severity → ntfy priority mapping. Title/body
  rendering helpers `render_title`/`render_body`. Tags include ATT&CK
  technique IDs.
- `selfdef-correlator`: subscribes to the bus, processes events through a
  built-in `SshBruteforceRule` (≥ N failed auths from the same source IP
  within W seconds → emit a Detection Finding). Configurable window and
  threshold. Loop guard: Findings-class events are never reprocessed.
- `selfdef-responder`: subscribes to the bus, watches for Findings-class
  events, executes the `notify` action through the configured notifier
  chain. Allowlist enforcement (`allowed_actions`) and `dry_run` mode.
- `selfdef-core`: added `ClassUid::SECURITY_FINDING` (2001),
  `DETECTION_FINDING` (2004), `INCIDENT_FINDING` (2005) constants.
- `selfdef-config`: added `[correlator]`, `[notifier]` (with `[notifier.ntfy]`,
  `[notifier.signal]` subsections), and `[responder]` config sections.
- `selfdef-store`: `recent_findings(limit)` helper for the CLI alerts view.
- `selfdef-daemon`: M4 wiring — correlator + responder spawned alongside
  the store sink, each as an independent bus subscriber.
- `selfdef-cli`: `events alerts -n N [--json]` subcommand for tailing
  findings.
- Integration test `crates/selfdef-daemon/tests/m4_alert.rs` proves the
  full path: 3 failed-auth lines → wiremock-mocked ntfy server receives
  exactly one POST with `Priority: 5`.
- Workspace lints: dropped `unwrap_used`, `expect_used`, `panic` from the
  default warn set — too noisy in test code; `clippy::pedantic` still
  catches real issues.

### Added — Milestone 3 (First spine)
- `selfdef-config`: Figment-based layered config loader (defaults → TOML →
  `SELFDEF_*` env vars). Typed `Config`, `DaemonConfig`, `BusConfig`,
  `StoreConfig`, `CollectorsConfig`, `AuditdConfig`.
- `selfdef-bus`: in-proc broadcast bus over `tokio::sync::broadcast`.
  `Bus`, `Publisher` (Clone), `Subscriber`, `BusError`. Tests for
  publish/subscribe ordering, fan-out, and lagged subscriber detection.
- `selfdef-store`: `SqliteStore` with WAL mode, `synchronous=NORMAL`,
  hand-rolled migrations driven by `user_version`. Async API via
  `spawn_blocking`. Operations: `open`, `insert`, `count`, `recent`, `get`.
  Migration `0001_initial.sql` defines the indexed `events` table.
- `selfdef-collector-auditd`: line parser for `USER_AUTH`, `USER_LOGIN`,
  `USER_ACCT` (mapped to `ClassUid::AUTHENTICATION` with correct
  `status_id`, ATT&CK technique tagging on failure). Unknown record types
  emitted as generic events with raw payload preserved. File tailer with
  `ReadFrom::{Start, End}` modes and graceful shutdown via `CancellationToken`.
- `selfdef-daemon`: real entry point — loads config, opens store, builds bus,
  spawns the auditd collector + a store sink task, waits for SIGTERM/SIGINT,
  drains the bus, reports counts on exit.
- `selfdef-cli`: `status` (event count + store path), `events tail [-n N] [--json]`
  reading the SQLite store directly.
- Integration test `crates/selfdef-daemon/tests/m3_pipeline.rs` proves the
  end-to-end loop: 4 canned audit lines → collector → bus → sink → SQLite,
  with assertions on classification, severity, and ATT&CK tagging.

### Added — Milestone 2 (Event envelope)
- `selfdef-core` restructured into focused modules: `envelope`, `category`,
  `activity`, `severity`, `status`, `attack`, `metadata`, `observable/*`,
  `error`, `prelude`.
- OCSF-aligned `Event` envelope with: `schema`, `id` (UUIDv7), `time_dt`
  (RFC3339), `category_uid`, `class_uid`, `activity_id`, `type_uid`,
  `severity_id`, `status_id`, `host_tag`, `source`, `message`, `metadata`,
  `raw`, plus optional typed observables.
- Typed observables: `Actor`, `User`, `Process`, `Session`, `File`,
  `FileType`, `Hash`, `HashAlgorithm`, `Endpoint`, `NetworkConnection`,
  `Direction`.
- MITRE ATT&CK overlay: `Tactic` enum with stable `TA*` IDs,
  `TechniqueRef` with convenience constructors.
- `Metadata` block with `Product`, `logged_time_dt`, `sequence`, `profiles`.
- Builder methods on `Event` (`with_status`, `with_actor`, ...).
- `Event::validate()` invariant check.
- 6 inline unit tests + insta snapshot tests for 4 canonical event shapes
  + proptest properties for round-trip, type_uid, category, validation.
- `SCHEMA_VERSION` bumped from 0 (placeholder) to 1 (first real schema).
- Daemon logs schema version on startup; `selfdefctl version` displays it.

### Added — Milestone 1 (Foundation)
- Cargo workspace with 13 crates.
- Pinned Rust toolchain, lint policy, `cargo-deny` config.
- Hardened systemd unit, AppArmor profile, Debian packaging metadata.
- CI workflow skeleton (fmt, clippy, test, deny, audit, build).
- Documentation skeleton (mdbook), architecture and security threat model.
- Example configuration.
