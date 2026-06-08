# Test contract

This page is the **mdbook-published entry point** for the test-contract
documentation. The canonical, living version lives at
[`docs/dev/test-contract.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/dev/test-contract.md)
in the source tree; this page surfaces it here so contributors can find
it from the book.

## What the contract covers

selfdef's test surface is organized into **four categories**:

1. **Translation** — the smallest unit: a function that turns one
   external thing (a Tetragon JSON line, a sigma rule's `condition`
   string, a TOML manifest) into a typed in-process value. Hermetic;
   no I/O.
2. **Pipeline** — daemon-internal multi-crate composition: collector
   publishes → bus → correlator → store / notifier. Asserts end-to-end
   flow under realistic configuration.
3. **Module-script** — `bash` against an install module's `apply.sh` /
   `check.sh` / `uninstall.sh` with `SELFDEF_DRY_RUN=1` and stubbed
   binaries. Asserts the structured-status contract + the
   `module_record_file` side-effect ledger.
4. **Seam** — a place where data crosses a crate / module / process
   boundary. Real-broker NATS, real-Tetragon event ingestion via the
   collector, real `wg-quick` / `nft` invocations with mocked binaries.

Each category has explicit contracts a test author must satisfy; the
canonical doc enumerates them with concrete examples.

## Shared patterns

- **Snapshot tree + assert-unchanged** for dry-run-negative checks
  (`crates/selfdef-cli/tests/common/mod.rs`).
- **Strict Prometheus exposition parser** for `/metrics` tests
  (`crates/selfdef-api/tests/m12_api.rs::prom`).
- **EngineHarness** for daemon-engine pipeline tests
  (`crates/selfdef-daemon/tests/m_notify_engine.rs`).

## Cross-repo contract gates

selfdef is the producer in a 3-repo seam: the **sovereign-os** cockpit
consumes selfdef's `/metrics` series + scheduler decisions, and the
**devops-solutions-information-hub** hosts the operator runbooks that
selfdef's alerts link to. Several `scripts/test/L1-*.sh` gates enforce
those contracts, but they **skip** unless the sister repo is reachable —
so they need an env var pointing at a checkout:

| Gate | Needs | Env var | Checks |
|---|---|---|---|
| `L1-prometheus-alerts.sh` (Gate 3b) | info-hub | `INFOHUB_RUNBOOKS` | every alert `runbook_url` target file exists |
| `L1-info-hub-doc-references.sh` | info-hub | `SELFDEF_INFO_HUB_REPO` | every `…/information-hub/blob/…` doc reference resolves |
| `L1-cross-repo-alert-runbook-binding.sh` | sovereign-os | `SOVEREIGN_OS_REPO` | MS048 runbook ↔ sovereign-os scheduler-alert symmetry + anchors |
| `L1-mirror-schema-version-coherence.sh` | sovereign-os | `SOVEREIGN_OS_REPO` | the mirror schema version sovereign-os consumers accept matches what selfdef emits |

CI's `coherence` job checks both sister repos out (read-only, no token —
they're public-ish) and sets all three env vars, so these gates run on
every push. A sister checkout that fails is `continue-on-error`, so the
gate degrades to its skip path rather than breaking CI. To run them
locally, clone the sisters adjacent and:

```bash
SOVEREIGN_OS_REPO=../sovereign-os \
SELFDEF_INFO_HUB_REPO=../devops-solutions-information-hub \
INFOHUB_RUNBOOKS=../devops-solutions-information-hub/wiki/runbooks \
  bash scripts/test/coherence.sh
```

The mirror direction (sovereign-os asserting selfdef emits what its cockpit
panels reference) lives in sovereign-os's own `cross-repo-lint` CI job,
which checks selfdef out as a sibling and runs its `$SELFDEF_REPO_ROOT`
gates symmetrically.

## How the contract stays fresh

Per [D-018 in the decisions log](https://github.com/cyberpunk042/selfdef/blob/main/docs/decisions.md):
every Phase-N closure-cycle audit re-asks "do these categories still
match the codebase?" Contract drift surfaces as audit findings.

## Source of truth

The canonical doc — with full per-category contract text, every shared
pattern's runbook, and the `--include-ignored` + `nats-server 2.10+`
runbook for the real-broker seam tests — is at
[`docs/dev/test-contract.md`](https://github.com/cyberpunk042/selfdef/blob/main/docs/dev/test-contract.md).

Design rationale: [SDD-005](https://github.com/cyberpunk042/selfdef/blob/main/docs/sdd/005-test-contract.md).
