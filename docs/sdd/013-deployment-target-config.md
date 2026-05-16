# SDD-013 — `[deployment.target]` config + path resolution

> Status: **review** — first Stage-2 PR (per SDD-012 Q-H ordering)
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-16
> Closes findings: SDD-012 Q-G (non-SAIN-01 deployment posture)
> Derived from: SDD-012 (integration design); SDD-002 (defaults-that-work; existing config plumbing)

## Problem

SDD-012 Q-G proposed gating all SAIN-01-specific behavior behind a
`[deployment.target]` config field defaulting to `"generic"`. This SDD
specifies the implementation: where the field lives, how it's read,
how downstream selfdef code paths fork on it, and what regression-
prevention tests cover the non-SAIN-01 deployment.

The goal: a single config switch turns SAIN-01 integration on or off
**without forking code paths**. Every existing non-SAIN-01 selfdef
deployment must work identically (no regression).

## Required coverage

### 1. Schema addition to `selfdef.toml`

Add to `crates/selfdef-config/src/lib.rs` (or wherever the deserialize
struct lives):

```toml
# /etc/selfdef/selfdef.toml — schema addition
[deployment]
target = "generic"      # default; or "sain01"
```

Field is **optional with default = `"generic"`**. Existing config files
parse unchanged.

### 2. Type + validation

```rust
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentTarget {
    Generic,
    Sain01,
}

impl Default for DeploymentTarget {
    fn default() -> Self {
        Self::Generic
    }
}
```

Reject unknown values at parse time — fail-loud per IaC bar.

### 3. Path resolution helper

```rust
pub fn state_dir(target: DeploymentTarget) -> &'static Path {
    match target {
        DeploymentTarget::Generic => Path::new("/var/lib/selfdef"),
        DeploymentTarget::Sain01  => Path::new("/mnt/vault/context"),
    }
}

pub fn audit_log_path(target: DeploymentTarget) -> PathBuf {
    state_dir(target).join("selfdef-audit.jsonl")
}

pub fn escalations_path(target: DeploymentTarget) -> PathBuf {
    state_dir(target).join("selfdef-escalations.sqlite")
}
```

Used by `selfdef-daemon`, `selfdef-notifier`, and `selfdefctl` so a
single source of truth per target governs all path decisions.

### 4. `selfdefctl init config --target=sain01`

Extend `selfdefctl init config` with a `--target` flag:

```sh
sudo selfdefctl init config                     # generic (current behavior)
sudo selfdefctl init config --target=generic    # explicit
sudo selfdefctl init config --target=sain01     # SAIN-01 path layout
```

When `--target=sain01`, the generated `selfdef.toml`:

- Includes `[deployment] target = "sain01"`
- Updates `[notifier.escalations_path]` to `/mnt/vault/context/selfdef-escalations.sqlite`
- Updates `[audit.path]` to `/mnt/vault/context/selfdef-audit.jsonl`
- (Other paths resolved at daemon-start via `state_dir()`)

### 5. Daemon startup behavior

On startup, `selfdef-daemon` logs the active target:

```
INFO selfdefd: deployment.target = sain01
INFO selfdefd: state_dir = /mnt/vault/context
INFO selfdefd: audit_log = /mnt/vault/context/selfdef-audit.jsonl
INFO selfdefd: escalations = /mnt/vault/context/selfdef-escalations.sqlite
```

Operator can grep this line in `journalctl -u selfdefd` to confirm the
posture.

### 6. Schema validation

Existing `selfdefctl init checklist` and `selfdefctl doctor` verify
the target value parses + the resolved paths exist (or are creatable
with proper permissions). New checks:

- `doctor`: warn if `target = "sain01"` but `/mnt/vault/` doesn't exist
- `doctor`: warn if `target = "generic"` but `/mnt/vault/context/`
  exists with selfdef files (likely operator forgot to update target)

## Regression-prevention tests

Per the operator's "do this clean and right and professional" bar +
SDD-012 Q-G: every existing non-SAIN-01 deployment must work
identically.

New tests in `crates/selfdef-config/tests/`:

```rust
#[test]
fn target_defaults_to_generic_when_absent() {
    let cfg: Config = toml::from_str("").unwrap();
    assert_eq!(cfg.deployment.target, DeploymentTarget::Generic);
}

#[test]
fn target_parses_generic() { /* ... */ }

#[test]
fn target_parses_sain01() { /* ... */ }

#[test]
fn target_rejects_unknown_value() {
    let r: Result<Config, _> = toml::from_str(r#"
        [deployment]
        target = "bogus"
    "#);
    assert!(r.is_err());
}

#[test]
fn generic_target_uses_var_lib_selfdef() {
    assert_eq!(state_dir(DeploymentTarget::Generic), Path::new("/var/lib/selfdef"));
}

#[test]
fn sain01_target_uses_mnt_vault_context() {
    assert_eq!(state_dir(DeploymentTarget::Sain01), Path::new("/mnt/vault/context"));
}
```

Plus integration tests via the existing test harness (`tests/it/`) that
exercise daemon startup with each target value and verify paths.

## Goals

1. **Single source of truth** for target-conditional behavior across daemon + CLI + notifier (only `state_dir()` and friends know about paths).
2. **Zero regression** for existing `generic` deployments — default behavior unchanged when field is absent or explicitly `"generic"`.
3. **Fail-loud** on unknown values (no silent fallback).
4. **Operator-visible** posture (startup log line).
5. **`doctor`-friendly** — sanity checks warn on likely-misconfigured deployments.

## Non-goals (this SDD)

- Does NOT implement the `shared-audit-summary` notifier channel (SDD-014).
- Does NOT implement perimeter coexistence (SDD-015).
- Does NOT implement `oracle-triage` channel (SDD-016).
- Does NOT alter any existing notifier channel behavior on `generic` deployments.
- Does NOT auto-migrate state across path changes (operator manually moves files when changing target post-deployment; the daemon refuses to start if old path exists alongside new path to prevent state-fork).

## Open sub-questions

- **Q13-A** — Should `selfdefctl init config --target=sain01` auto-create `/mnt/vault/context/` if missing? Recommend: **NO** — fail with a clear error directing operator to run `zfs-datasets-create.sh` first. Avoids hiding the SAIN-01 dependency.
- **Q13-B** — Should `target = "sain01"` warn at startup if Tetragon isn't active? Recommend: **NO** — Tetragon dependency is implicit in the systemd `Requires=tetragon.service` (already shipped on SAIN-01 via sovereign-os profile); selfdef's doctor catches this separately.
- **Q13-C** — Should the daemon refuse to start when target mismatches state-dir contents (e.g., target=generic but /mnt/vault/context/selfdef-escalations.sqlite exists)? Recommend: **YES, refuse with clear error** — operator-explicit migration is safer than silent state fork.

## Way forward

1. **This PR** — config schema + path resolver + CLI flag + tests. **No notifier-channel changes; no perimeter changes.**
2. **SDD-014 PR** — `shared-audit-summary` notifier channel (per Q-C).
3. **SDD-015 PR** — Tetragon perimeter coexistence runtime + `selfdefctl perimeter check-overlap` (per Q-A).
4. **SDD-016 PR** — `oracle-triage` notifier channel (per Q-D).

Each Stage-2 PR landed independently per SDD-012 Q-H ordering.

## Cross-references

- SDD-012 (integration design; Q-G resolution is this SDD's mandate)
- SDD-010 (scoping stub; Q-G open question)
- SDD-002 (defaults-that-work; existing config plumbing pattern)
- SDD-005 (test contract; the regression tests follow its discipline)
- sovereign-os `profiles/sain-01.yaml` (`hardware.storage.datasets` declares `tank/context` with `sync=always` — the target path on SAIN-01)
- sovereign-os `scripts/hooks/during-install/zfs-datasets-create.sh` (creates `/mnt/vault/context` mountpoint before selfdef daemon starts)
