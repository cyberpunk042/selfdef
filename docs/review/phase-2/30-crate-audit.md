# Phase 2 — Crate audit

> Scope (per the Phase 2 charter): the new `selfdef-signing`
> crate, plus the extended surfaces on `selfdef-cli`,
> `selfdef-api`, `selfdef-correlator`, and
> `selfdef-collector-eventstream`. Per-area ids prefix `C2-` and
> roll up to the ledger as `F-2027-NNN`.
>
> What this audit doesn't re-litigate: Phase 1's per-crate
> findings (every `F-2026-NNN` crate finding closed during the
> previous cycle — `bus.backend` C-001, the correlator window
> dead-knobs C-002, the store retention sweeper C-003, etc.). If
> a Phase 1 fix is broken, that's a new `F-2027-NNN` with a
> back-reference.

## Headlines

- **No blockers and no important findings**. The four extended
  crates are wired cleanly into the daemon's startup path. The
  new `selfdef-signing` crate is small and self-contained.
  Errors propagate through a typed enum; `unsafe_code` is
  `forbid`-ed; deps are tight (one production dep —
  `minisign-verify`).
- **11 nice findings** clustered around three themes:
  - **API surface hygiene** — public symbols that have no
    external callers, or that look like they should
    (`SIGNATURE_SUFFIX`, `signature_path_for`,
    `with_full_capability`).
  - **Doc-string drift** — crate `//!` headers that don't
    advertise the surfaces shipped post-Phase-1 (correlator's
    `reload_verifier`, signing's helper functions).
  - **Observability** — operator-visible state that the daemon
    knows but doesn't log (the path the rule-signing verifier
    was loaded from, the env var that lets `doctor` use a
    staged agent-guard.toml).
- The recent-PRs explorer's findings (F-2027-001 through
  F-2027-010) are closed except F-2027-010 (SDD-debt).

## Per-crate notes

### selfdef-signing

The new verify-only crate. Five public surfaces:
`SIGNATURE_SUFFIX`, `SigningError`, `Verifier`,
`signature_path_for`, plus `Verifier::{load, source,
verify_detached_file}`. Test surface is solid (9 unit tests
covering valid / missing / tampered / wrong-key / malformed
sig + the path-helper), and there are integration tests in
`selfdef-correlator/tests/signed_rules.rs` and
`selfdef-cli/tests/cli_keys_verify_dir.rs`.

Observations:

- `SIGNATURE_SUFFIX` (`src/lib.rs:45`) and `signature_path_for`
  (`src/lib.rs:152`) are `pub` but `grep -rn` across the
  workspace finds zero external callers — every site that needs
  a sibling `.minisig` either goes through
  `Verifier::verify_detached_file` (which internally calls
  `signature_path_for`) or builds the string by hand
  (`tests/cli_keys_verify_dir.rs:41-43`,
  `tests/module_tetragon_signing.rs:163`). Either deprecate
  them or surface them in the crate `//!` header so the next
  contributor reaches for the helper instead of `target.push(".minisig")`.
  **(C2-001)**
- `SigningError::Io` (`src/lib.rs:50`) uses `#[from]
  std::io::Error`, so any io failure (reading the pubkey,
  reading the target file, reading the sig file) is wrapped
  without context. The sibling variants `BadPublicKey { path,
  reason }` and `BadSignature { path, reason }` carry the path
  the error happened against — `Io` is the only branch that
  loses it. Consider variant-per-site:
  `Io { path: PathBuf, source: io::Error }`. **(C2-002)**
- The crate `//!` header (`src/lib.rs:1-32`) walks the operator
  through `minisign -G` / `-S` and the daemon-side load path
  but doesn't mention `signature_path_for` or
  `SIGNATURE_SUFFIX`. If they're public helpers, document them
  in the header's "Usage shape" block; if they're internal,
  flip them to `pub(crate)`. **(C2-003)**

### selfdef-cli

Binary-only crate. Post-Phase-1 surface is the three new modules
(`init.rs`, `doctor.rs`, `follow.rs`, `emit.rs`) plus the
extended `main.rs` with `events follow`, `keys verify`,
`keys verify-dir`, `api rotate-token`, `rbac check`, `init`, and
`doctor` verbs. Dispatch in `main.rs::main` is a flat match arm
over `Command` — every variant routes to one function, no orphan
branches.

Observations:

- The starter-config path constants are split across two files
  with no cross-reference: `init.rs::OUTPUT_DEFAULTS` knows
  `/etc/selfdef/selfdef.toml` and `/etc/selfdef/modules.toml`;
  `modules.rs:31-32` redefines `DEFAULT_HOST_CONFIG`
  (`/etc/selfdef/modules.toml`) and `DEFAULT_PER_MODULE_DIR`
  (`/etc/selfdef/modules/`). The two views of "where modules
  live" need to agree — drift here means `init` writes to one
  path and `modules apply` looks at another. **(C2-004)**
- `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG`
  (`crates/selfdef-cli/src/doctor.rs:354`) is the test-only env
  var that lets the doctor integration tests stage a fake
  `agent-guard.toml` without writing to `/etc/`. The var is
  documented only in a source-comment immediately above its
  read site; it doesn't appear in `docs/dev/operator-health-check.md`
  or in the doctor verb's `--help`. Operators who hit a doctor
  bug and want to reproduce it with a staged config have no
  way to discover it. Either move the doc to
  `docs/dev/operator-health-check.md` under a "Testing /
  reproducing" section, or rename it with a `_TEST_` infix and
  document the convention once across the CLI crate. **(C2-005)**
- `crates/selfdef-cli/Cargo.toml:38-44` carries `minisign =
  "0.9"` as a dev-dep (F-2027-006 follow-up integration tests)
  *and* `selfdef-signing = { workspace = true }` (which itself
  has `minisign = "0.9"` as a dev-dep). The duplication is
  inert at the workspace level (Cargo resolves both to the same
  version) but worth a one-line note explaining the choice so
  the next contributor doesn't try to "consolidate". **(C2-006)**

### selfdef-api

Post-Phase-1 surface: SSE handler (`handlers::events_stream`),
`TokenReloader` exported from `transport.rs`, the `Metrics`
ingest task (`metrics.rs::run_ingest` re-exported as
`run_metrics_ingest`).

Observations:

- `selfdef_api::with_full_capability` (`src/lib.rs:53`) is a
  `pub fn` documented as "Test-only convenience" — but the
  `pub` makes it a stable API surface that downstream crates
  (in tree: 0; out of tree: any future contributor) could call.
  In a misuse, wrapping the router with `with_full_capability`
  before binding it to a TCP transport would bypass the
  bearer-token check. The daemon's actual wiring uses
  `with_capability(router, Capability::Full)` on UNIX and the
  bearer-token middleware on TCP — `with_full_capability`
  itself is only ever called from `selfdef-api/tests/m12_api.rs`.
  Either gate it on `#[cfg(any(test, feature = "test-helpers"))]`
  + put it behind a feature flag, or rename it
  `_test_with_full_capability` and document the underscore as
  "do not use in production". **(C2-007)**
- `metrics::run_ingest` (re-exported as `run_metrics_ingest`),
  `Metrics::record_event`, `Metrics::record_ingest_lag`, and
  `Metrics::render` have no `///` doc comments
  (`crates/selfdef-api/src/metrics.rs` — every method). They're
  short and arguably self-describing, but the daemon's wire-up
  comment (`crates/selfdef-daemon/src/main.rs:167-172`) calls
  out the gating contract ("only spawn the ingest task when the
  API is enabled, otherwise the counters are dead weight") —
  that contract belongs on the `run_ingest` signature, not buried
  in the daemon. **(C2-008)**
- `ApiServer::run` returns `Err(ServerError::NoTransport)`
  when neither UNIX socket nor TCP is configured
  (`crates/selfdef-api/src/transport.rs::run`), but the same
  error fires when the API is enabled with both transports
  intentionally disabled (rare but valid for a dry-run config).
  Operator-facing message could distinguish the two paths:
  "api is enabled but neither `[api.unix]` nor `[api.tcp]` has
  a path/bind set — set one or disable the api". **(C2-009)**

### selfdef-correlator

Post-Phase-1 surface: `Arc<RwLock<Option<Verifier>>>` field,
`with_verifier`, `reload_verifier`, `has_verifier`,
`ReloadVerifierError` (shipped in PR #58, F-2027-005 closeout).

Observations:

- The crate `//!` header (`src/lib.rs:1-7`) still reads
  "M5: the hardcoded `SshBruteforceRule` is gone. The engine
  loads YAML rules from a directory and supports atomic hot
  reload (SIGHUP from the daemon)." Post-PR-#58, the daemon
  also supports verifier hot-rotation via SIGUSR2 — the crate
  header should advertise both signals, plus the
  `reload_verifier` / `has_verifier` surface, since they're the
  external contract callers (daemon, future plug-ins) rely on.
  **(C2-010)**
- `Correlator::load_rules` (`src/lib.rs:121-138`) logs the
  rule_count after a successful load (via the daemon's caller
  at `crates/selfdef-daemon/src/main.rs:109-112`), but doesn't
  log the key path the rules were verified against when a
  verifier is configured. After a SIGUSR2 verifier reload, the
  operator's eye-balling sequence is "did the verifier
  actually change?" — and there's no log line that proves it
  did. Pair the existing `info!(rules = n, "rules reloaded")`
  with `info!(verifier_key = %v.source().display())` when the
  verifier branch was taken. **(C2-011)**
- There's no public getter for the currently-loaded verifier
  source path. Tests, `selfdefctl doctor`, and ops dashboards
  all want to answer "which `policy.pub` is the daemon
  trusting right now?". Add
  `Correlator::verifier_source(&self) -> Option<PathBuf>` that
  read-locks and clones `Verifier::source()` when present.
  Mirrors `has_verifier()`. **(C2-012)**

### selfdef-collector-eventstream

No new observations beyond F-2027-003 (closed by PR #56 —
`read_euid` returns `Option<u32>` and the caller falls back
strict-safe). The crate's surface is small (one config struct,
one collector, one integrity check) and well-tested. Worth
calling out that:

- `IntegrityCheck::allowed_owners`
  (`crates/selfdef-collector-eventstream/src/lib.rs:64`) is
  exposed via `[collectors.eventstream].allowed_owners` in the
  daemon config (confirmed:
  `crates/selfdef-config/src/lib.rs:340`). The agent's
  reflexive "code-only" worry doesn't apply — the operator can
  tune it. No finding.

## Triage

Every observation is **nice**. Most are documentation or
API-surface hygiene; one (C2-007) is a defensive rename that's
worth doing before someone outside the test suite calls
`with_full_capability` and silently disables auth on a
production router.

Closing-PR candidates (cluster, ship one PR):

- **selfdef-signing API surface** — C2-001 + C2-002 + C2-003.
  One PR re-scopes `SIGNATURE_SUFFIX` / `signature_path_for`
  (either `pub(crate)` or `//!`-documented), adds path context
  to `SigningError::Io`, and updates the crate header.
- **selfdef-correlator observability** — C2-010 + C2-011 +
  C2-012. One PR refreshes the crate header for the post-PR-#58
  surface, logs the verifier source path on rule loads, and
  exposes `verifier_source()` for tooling.
- **selfdef-api / selfdef-cli ergonomics** — C2-004 through
  C2-009. Five small fixes that don't cluster cleanly; can ship
  one-per-PR or in one bundle.

All 11 entries land in the Phase 2 findings ledger as
F-2027-011 through F-2027-021 with `nice` severity and
"implement" next-phase.
