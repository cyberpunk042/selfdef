# Inventory — ground truth, no commentary

> Snapshot of what exists in the repo at `HEAD` (PR #25 merged).
> This document does not raise findings. It exists so every later
> audit doc can reference shared coordinates without re-counting.
> If a number in this file looks wrong to a future reader, that's
> itself a finding for the ledger.

## Workspace shape

- **Top-level documentation**: `README.md`, `ARCHITECTURE.md`,
  `SECURITY.md`, `CHANGELOG.md`, `LICENSE`.
- **Cargo workspace**: `Cargo.toml`, `rust-toolchain.toml`.
- **Supply chain / CI**: `deny.toml`, `supply-chain/`, `.github/workflows/`.
- **Out-of-tree assets**: `ansible/`, `dashboard/`, `packaging/`,
  `selfdef-ebpf/`, `tests/replay/`, `xtask/`, `bpf/`.

## Crates (20)

Categorised by their stated role in `ARCHITECTURE.md` /
crate-level rustdoc:

### Foundation
- `selfdef-core` — Event envelope, OCSF taxonomy, severity, metadata.
- `selfdef-bus` — In-process broadcast bus + publisher/subscriber.
- `selfdef-config` — `selfdef.toml` parser, defaults, validation.
- `selfdef-store` — SQLite hot store.
- `selfdef-correlator` — Sigma rule engine.
- `selfdef-responder` — Action set + dispatch.
- `selfdef-notifier` — ntfy / Signal / chain notifiers.
- `selfdef-nats` — Core + JetStream bridge between hosts.
- `selfdef-ebpf-common` — Shared types between user-space and BPF.

### Collectors (input side, all named `selfdef-collector-*`)
- `selfdef-collector-auditd`
- `selfdef-collector-canary`
- `selfdef-collector-ebpf`
- `selfdef-collector-eventstream`
- `selfdef-collector-journald`
- `selfdef-collector-suricata`
- `selfdef-collector-tetragon`

### Application binaries
- `selfdef-daemon` — main long-running process; wires every
  collector + correlator + responder + API + NATS bridge.
- `selfdef-api` — HTTP/HTTPS read API + `/metrics`.
- `selfdef-cli` — `selfdefctl` admin CLI.
- `selfdef-ssh-wrap` — drop-in `ssh` wrapper that emits events.

## Integration test surface (per crate, counts of `tests/*.rs`)

| Crate | Integration test files |
| --- | --- |
| `selfdef-api` | 1 |
| `selfdef-bus` | 0 |
| `selfdef-cli` | 12 |
| `selfdef-collector-auditd` | 0 |
| `selfdef-collector-canary` | 0 |
| `selfdef-collector-ebpf` | 0 |
| `selfdef-collector-eventstream` | 0 |
| `selfdef-collector-journald` | 0 |
| `selfdef-collector-suricata` | 0 |
| `selfdef-collector-tetragon` | 0 |
| `selfdef-config` | 0 |
| `selfdef-core` | 2 |
| `selfdef-correlator` | 1 |
| `selfdef-daemon` | 8 |
| `selfdef-ebpf-common` | 0 |
| `selfdef-nats` | 0 |
| `selfdef-notifier` | 0 |
| `selfdef-responder` | 0 |
| `selfdef-ssh-wrap` | 0 |
| `selfdef-store` | 0 |

Unit tests under `src/` are not counted here — only the
`tests/` directory of each crate. Most crates rely on
`#[cfg(test)] mod tests` for coverage; the absence of `tests/`
files is not by itself a finding.

## Modules (9)

`modules/<slug>/` layout: each one has at minimum a `module.toml`
manifest. File counts:

| Module | File count | Category | Phase |
| --- | --- | --- | --- |
| `detect-host` | 2 | detection | (default `main`) |
| `bridge-l2` | 9 | network | (default `main`) |
| `suricata` | 9 | network | (default `main`) |
| `polarproxy` | 10 | network | (default `main`) |
| `vpn-bridge` | 15 | network | (default `main`) |
| `integrity-sentinel` | 9 | hardening | `pre` |
| `tetragon` | 7 | hardening | `pre` |
| `agent-guard` | 13 | hardening | `main` |
| `observability` | 10 | observability | `post` |

`detect-host` is the daemon-as-module entry — it's `kind =
"debian-package"`, no install scripts; everything else is `kind
= "script"`.

## Detection rules

| Source | File count | Notes |
| --- | --- | --- |
| `rules/sigma/` | 38 | organised by ATT&CK tactic subdirs |
| `rules/tetragon/` | 1 | observe-only template; no enforce-mode policy in this tree |
| `rules/yara/` | 0 | directory exists, no rules |

## CI workflows

`.github/workflows/`:
- `audit.yml` — supply-chain (cargo-deny, cargo-audit).
- `ci.yml` — build, test, clippy, fmt, two-channel `test
  (ubuntu-latest)` + `test (ubuntu-24.04)`.
- `release.yml` — release packaging.

## Docs (mdbook)

`docs/src/` layout:
- `SUMMARY.md`
- `intro.md`
- `architecture.md`
- `security.md`
- `modules.md`
- `modules-roadmap.md`
- `detect/` (sub-section)
- `dev/` (sub-section)
- `ops/` (sub-section)

This `review/` directory is **not** yet referenced from
`SUMMARY.md`. Whether to add it is itself a deferred decision —
see `99-findings-ledger.md`.

## Recent PR history (relevant to the audit window)

PRs #19–#25 on the long-running branch:

| PR | Title (shortened) | Status |
| --- | --- | --- |
| #19 | manifest `phase` field (pre/main/post) | merged |
| #20 | `selfdefctl modules uninstall` | merged |
| #21 | `events emit` + integrity-sentinel notifier wiring | merged |
| #22 | AI-machine track — tetragon + agent-guard + observability | merged |
| #23 | selfdef-api `GET /metrics` (Prometheus exposition) | merged |
| #24 | agent-guard GPU device guard (v0.2.0) | merged |
| #25 | agent-guard pod-label scope (v0.3.0) | merged |

Pre-#19 history isn't part of the retrospective scope, but `git
log` shows the earlier module batch (#11–#18) followed the same
cadence.

## How to cite this inventory

Other audit docs reference items here by their canonical names:

- Crates: `crates/selfdef-<name>`
- Modules: `modules/<slug>`
- Rule directories: `rules/<engine>`
- PRs: `#NN`
- Test files: `<crate>/tests/<file>.rs`
