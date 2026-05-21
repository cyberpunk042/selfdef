# SDD-042 — Integrity-sentinel module — SHA256 baseline + drift — MS026

> Status: **draft** — Stage-2 architectural spec for the shipped
> `integrity-sentinel` module under `modules/integrity-sentinel/`.
> The module provides SHA256 baseline verification for policy
> artifacts and fails closed on drift.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS026 (catalog
> `backlog/milestones/MS026-integrity-sentinel-module.md`)
> Companions: packaging/test/L2-integrity-sentinel.bats (16 tests),
> SDD-037 (MS030 tensor-parallel — composes with integrity-sentinel
> for `.toml` partition-config monitoring)

## Problem

Policy artifacts (Tetragon TracingPolicies, Sigma correlator rules,
module config TOMLs) live on disk and can drift between operator
inspection points. Drift comes from:
- legitimate operator edits (no signal)
- module re-applies (legitimate, should produce byte-identical
  on no-op apply)
- malicious tampering or storage corruption (signal)

A SHA256 baseline maintained against an operator-curated path list
gives detection of any drift class, with strict (fail-closed) vs
warn-only (alert without blocking) policies operator-configurable.

## Operator directive — verbatim (sacrosanct)

> "DO NOT MINIMIZE WHAT I SAY, SAID OR ASKED FOR... avx-plus-plus
>  base reason being. DO NOT STOP AT DEFINING/REGISTERING THE
>  REQUIREMENT and doing the scaffolds, we expect the full
>  production progressively through the workflow."

Translation for MS026: drift detection must SHIP + the strict /
warn-only profile choice must be operator-controlled + the baseline
+ current state must be operator-inspectable (diff output, not just
"drift detected").

## Module inventory (shipped)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/integrity-sentinel/module.toml` | provides=[baseline-attestation], profiles=[strict, warn-only] |
| Apply | `modules/integrity-sentinel/install/apply.sh` | Computes baseline → writes baseline_path |
| Check | `modules/integrity-sentinel/install/check.sh` | Re-computes current state → diffs against baseline → fails (strict) or warns (warn-only) |
| Uninstall | `modules/integrity-sentinel/install/uninstall.sh` | Removes baseline file |
| Helper lib | `modules/integrity-sentinel/install/lib.sh` | sha256 + diff helpers |
| Default path list | `modules/integrity-sentinel/paths.txt.default` | Operator-curated default monitored paths |
| L2 tests | `packaging/test/L2-integrity-sentinel.bats` | 16 tests including dry-run smoke + malformed-profile rejection |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Two-profile contract

| Profile | check.sh behavior on drift |
|---|---|
| `strict` | Emits `failed` status + exits non-zero (selfdefctl modules check shows the module as failing) |
| `warn-only` | Emits `ok` status with `(warn-only: not blocking)` annotation + exits zero |

Operator-overridable per host via `/etc/selfdef/modules/integrity-sentinel.toml`.

### Deliverable 2 — Required binaries

`sha256sum` (coreutils) + `diff` (coreutils) — both on the manifest's
requires list. `apply.sh` fails fast with a clear error message if
either is missing.

### Deliverable 3 — Configuration knobs

| Key | Default | Purpose |
|---|---|---|
| `profile` | `"strict"` | strict / warn-only |
| `paths_file` | (unset, required) | Path to newline-separated list of monitored files |
| `baseline_path` | (unset, required) | Path where baseline SHA256 file lives |
| `on_missing` | `"create"` | What to do when baseline doesn't exist yet: `create` (compute now) or `fail` (refuse, force operator-curated baseline) |

### Deliverable 4 — Drift-output legibility

When drift is detected, check.sh emits the diff output (not just a
status), so operators see exactly which paths changed. Sample
`status="failed"` JSON includes `summary="DRIFT detected: +N
new/changed lines, -M missing/changed lines vs baseline"` for
operator-level signal + the per-line diff for forensics.

### Deliverable 5 — Composition with MS030 + MS017

The `paths.txt.default` shipped with the module includes:
- `/etc/selfdef/tensor-parallel/` (MS030 partition configs)
- `/etc/tetragon/tetragon.tp.d/` (MS016 + MS017 TracingPolicies)
- `/etc/selfdef/modules.toml` (the module-activation manifest itself)

So drift on any compute-stack or policy-layer artifact triggers a
strict-mode failure.

## Production-readiness gates

| Gate | Verification |
|---|---|
| Provides baseline-attestation contract | L2 bats test 3 |
| Requires sha256sum + diff | L2 bats test 4 |
| Both profiles supported | L2 bats test 5 |
| 4 install scripts + lib + paths.txt.default | L2 bats tests 6, 7 |
| apply.sh DRY_RUN aware + fail-fast on missing binaries | L2 bats tests 9, 10 |
| Reads 4 config keys | L2 bats test 11 |
| check.sh always DRY_RUN=0 (read-only) | L2 bats test 12 |
| Differentiates strict (fail) vs warn-only (pass) on drift | L2 bats test 13 |
| Dry-run smoke + idempotency | L2 bats tests 14, 15 |
| Rejects malformed profile | L2 bats test 16 |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest with [strict, warn-only] profiles + sha256sum + diff
   requires
2. ✅ install/apply.sh with 4 config keys + fail-fast checks
3. ✅ install/check.sh with strict↔warn-only differentiation
4. ✅ install/uninstall.sh removing the baseline file
5. ✅ install/lib.sh helpers
6. ✅ paths.txt.default with selfdef-side monitored paths
7. ✅ L2 bats coverage (16 tests including dry-run + malformed-profile)

## Authorization for Stage-3+ work

This SDD authorizes:

- Cron-based periodic drift check via a sister systemd timer
  (`selfdef-integrity-sentinel.timer`) similar to MS027's
  selfdef-doctor.timer pattern
- Drift event emission onto the selfdef bus — currently surfaces
  via `selfdefctl modules check`; could also push to OCSF events
  with `class_uid = INCIDENT_FINDING`
- Per-directory baselines (currently one baseline file covers all
  paths — could split for finer-grained ownership)
- Cryptographic signing of the baseline itself (currently it's a
  plain SHA256 manifest; signing-chain composition with MS003 would
  add integrity to the integrity manifest)

— End of SDD-042 / MS026 Stage-2.
