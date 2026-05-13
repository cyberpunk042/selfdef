# Test contract (SDD-005)

This document is the contributor-facing runbook for SDD-005. It
describes what "integration-tested" means in this codebase, the
four test categories, and the three shared patterns the audit
asked us to standardise. Treat it as a checklist when adding a
new feature; treat the SDD itself
(`docs/sdd/005-test-contract.md`) as the design rationale.

## TL;DR

For a new feature PR, ship tests in **at least one** of the four
categories listed below. New event sources (collectors, modules
that emit events to the daemon) ship tests in **at least one
pipeline test plus one seam test** by default; pure passive
modules can skip seam tests.

## Categories

### Category 1 — Translation tests

**Where**: `#[cfg(test)] mod tests` inside the source crate, or
`crates/<name>/tests/translation.rs` for a dedicated file.

**What**: Asserts the crate correctly translates its input format
(Tetragon JSON, Suricata EVE, journald, auditd, sigma rule YAML,
TOML manifest) into the corresponding in-tree type
(`selfdef_core::Event`, `CompiledRule`, `ModuleManifest`).

**Contract**: every translation branch has

- at least one positive test (input shape → expected fields), and
- at least one tolerance test (input shape that's malformed in a
  documented way → no panic, logged warning, soft-skip).

**Examples in tree**:
- `crates/selfdef-collector-tetragon/tests/translation.rs`
  (SDD-005 Test-6) — kprobe / process_exec / process_exit
  positive coverage + a tolerance case for missing fields.
- `crates/selfdef-correlator/src/sigma.rs` — `mod tests` for
  rule compilation positive + negative.

### Category 2 — Pipeline tests

**Where**: `crates/selfdef-daemon/tests/`.

**What**: Spins up a minimal in-process pipeline (`bus + collector
+ correlator + responder + store`) and asserts a full flow:
event in → expected effect at the end (a finding in the store,
a NotifyAction fired, an API response).

**Contract**: every operator-visible "promise" the daemon makes
must be exercised by at least one pipeline test that would fail
if the promise regressed. "Promise" = anything in the README,
ARCHITECTURE.md, a module's README, or a SECURITY.md known-gap
entry.

**Examples in tree**:
- `crates/selfdef-daemon/tests/m_ai_machine.rs` (SDD-001) —
  Tetragon JSON → collector → correlator → store, asserts the
  agent-guard finding lands with severity High.
- `crates/selfdef-daemon/tests/m4_correlator_finding.rs` —
  bus → correlator → finding shape.

### Category 3 — Module-script tests

**Where**: `crates/selfdef-cli/tests/module_<slug>.rs`.

**What**: Spawns `bash` on a module's `install/*.sh` against a
hermetic tempdir. Stubs every host binary the script touches via
a PATH-prefix tempdir.

**Contract**: for each shipped script, both the
**dry-run-negative** (SELFDEF_DRY_RUN=1 produces zero on-disk
delta) and the **live-positive** (SELFDEF_DRY_RUN=0 produces
the documented effect) paths are asserted. The dry-run-negative
side has a shared helper —
`crates/selfdef-cli/tests/common::dry_run_must_be_a_noop`
(SDD-005 D-2a / Test-1) — that snapshots paths + content
hashes before and after, and asserts byte equality.

**Examples in tree**:
- `crates/selfdef-cli/tests/module_vpn_bridge.rs` — relay
  apply succeeds in dry-run + check fails on missing config.
- `crates/selfdef-cli/tests/module_agent_guard.rs` — full
  apply / check / reapply / uninstall coverage.

### Category 4 — Seam tests

**Where**: `crates/selfdef-daemon/tests/seam_*.rs` (when the seam
crosses a process boundary that's still in-tree) or alongside
the pipeline tests.

**What**: Asserts two-side behaviour at a seam — the writer side
produces what the reader side parses, including failure modes.

**Contract**: every seam called out in
`docs/review/40-integration-audit.md` Flows 1–6 has at least
one seam test. New seams (new in-tree publishers or consumers)
ship one with their introducing PR.

**Examples in tree**:
- `crates/selfdef-daemon/tests/m_integrity_sentinel_drift.rs`
  — module writes the eventstream JSONL, daemon reads, finding
  lands in store with the expected severity.
- `crates/selfdef-daemon/tests/m_metrics_endpoint.rs` —
  metrics ingester subscribes to the bus and surfaces the
  rendered Prometheus exposition through the API.

The four categories overlap deliberately. A pipeline test may
also exercise translation; a seam test often uses a
module-script test as one of its inputs. The contract is about
**at-least-one-of** coverage, not exclusive categorisation.

## Three shared patterns

### Pattern P-1 — Dry-run must be a no-op

A module script's `SELFDEF_DRY_RUN=1` mode promises **zero
on-disk side effects**. The shared helper
`dry_run_must_be_a_noop` in
`crates/selfdef-cli/tests/common/mod.rs`:

1. Snapshots the tempdir's tree (sorted relative paths + sha256
   of file contents) **before** the apply.
2. Runs the apply with `SELFDEF_DRY_RUN=1`.
3. Snapshots **after**.
4. Asserts equality with a per-file diff in the failure
   message.

Use it whenever a module-script test exercises a live-positive
path. Pair the existing positive test with a one-liner negative
that runs the same fixture under dry-run.

```rust
mod common;
use common::{dry_run_must_be_a_noop, module_dir, write_executable, ...};

#[test]
fn vpn_bridge_apply_is_a_noop_in_dry_run() {
    dry_run_must_be_a_noop(|tempdir| {
        // Stage fixtures + run apply.sh with DRY_RUN=1 inside the
        // tempdir. The helper does the snapshotting.
    });
}
```

### Pattern P-2 — Prometheus exposition parser

For `/metrics` tests, **don't substring-match**. Use the parser
fixture from
`crates/selfdef-api/tests/m12_api.rs::prom`:

- Verifies `Content-Type` is exactly
  `text/plain; version=0.0.4; charset=utf-8`.
- Parses the body into `(name, labels, value)` tuples.
- Asserts presence of expected `(name, labels)` pairs.
- Asserts absence of duplicate `(name, labels)` keys
  (Prometheus invariant).
- Asserts every line is either blank, a `# HELP/TYPE` comment,
  or a sample line with the right shape.

The parser is small (~80 lines) and hand-rolled so we don't
take a new dep. If you find yourself adding a fourth `/metrics`
test, extract the parser to its own module.

### Pattern P-3 — Real-broker NATS fixture

For NATS integration tests, **don't fake the broker** — the
fakes don't catch JetStream durability bugs. Pattern:

- The test discovers `nats-server` via `which nats-server`.
- If absent, `#[ignore]` — CI without the binary stays green.
- If present, spawn it on a free port, wait for the bind line
  on stderr, run the bridge against it, assert the durable
  delivery promise.
- Tear down on test exit (kill + tempdir cleanup).

`crates/selfdef-nats/tests/integration.rs` (SDD-005 Test-3)
is the canonical example.

To run locally with the broker:

```sh
apt install nats-server                            # debian-derived, v2.10+
# OR
brew install nats-server                           # macOS
# OR
# binary from https://nats.io/download/

cargo test -p selfdef-nats -- --include-ignored    # runs the gated tests
```

`nats-server` 2.10+ is required for the JetStream tests (`KeyValue` /
durable consumer flags this fixture uses). Older Debian repos ship
2.9.x; download the latest from the nats.io release page if `apt`
gives you an older version.

CI installs `nats-server` so the gate doesn't permanently hide the
test. F-2027-002 follow-up: the daemon's `[bus.nats]` JetStream
support tracks 2.10+ semantics; running the fixture against an older
broker silently skips the JetStream test and surfaces only the core
pub/sub one.

## What not to test

- **Coverage %.** Not a contract. The contract is about *what*
  is tested, not *how much*.
- **External services beyond their wire format.** The NATS
  integration test asserts the bridge's promises; it doesn't
  re-test that nats-server itself works.
- **System-state preconditions.** Hermetic tempdirs only. If
  your test reads `/etc/selfdef/`, it'll behave differently on
  a contributor's laptop vs. CI.
- **Time.** Use `tokio::time::pause()` and explicit advances
  rather than `sleep`-and-poll. The few existing
  `tokio::time::sleep` calls in tests are bugs waiting to
  flake — convert when you touch them.

## Keeping the contract honest

Every Phase-N audit (yearly cadence) re-asks "do these
categories still match the codebase?" The current audit at
`docs/review/` is Phase 1; future Phases re-run the seven
explorers against an updated inventory and surface contract
drift as findings. If a new pattern emerges (e.g.
property-testing fixtures land workspace-wide), document it
here.
