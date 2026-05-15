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
