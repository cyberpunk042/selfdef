# SDD-015 — Tetragon perimeter coexistence (Stage-2 PR 3/4)

> Status: **review** — third Stage-2 SDD per SDD-012 Q-H ordering
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-16
> Closes findings: SDD-012 Q-A (Tetragon policy authoring authority)
> Derived from: SDD-012 (integration design); SDD-013 ([deployment.target]); SDD-014 (shared-audit-summary channel); SDD-001 (ai-machine-end-to-end); SDD-004 (security threat model)

## Problem

SDD-012 Q-A resolved: **coexist as separate policies, single authoring authority per origin**.

- sovereign-os ships `sovereign-kernel-fence.yaml` (4-binary `sys_execve` allowlist + SIGKILL) at `/etc/tetragon/tracing-policies/`
- selfdef's `agent-guard` module ships its own TracingPolicies at the same directory
- Tetragon loads both; daemon-side merging is permissive allowlist + intersect deny

The risk: **two policies disagreeing without operator awareness**. If `sovereign-kernel-fence` allows `python3` for sys_execve but `agent-guard` denies it inside a container, the effective behavior is conditional on which policy fires first and on Tetragon's merge semantics. Operator deserves to know.

This SDD specifies:
1. The boundary contract between the two policy authors
2. `selfdefctl perimeter check-overlap` — runtime detector for cross-policy contradictions
3. `selfdefctl perimeter diff` — operator-readable diff between expected and loaded policies
4. selfdef-side configuration that makes the coexistence explicit + auditable

## Required coverage

### 1. Boundary contract — non-overlapping scopes

**sovereign-os** `sovereign-kernel-fence.yaml`:
- Scope: container-runtime processes (`podman`, `vllm`, `nvidia-smi`, `python3`) executing `sys_execve` from inside Rootless Podman containers
- Authority: sovereign-os Stage-2+ team (effectively the operator)
- Lives at: `/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml`
- Modified by: `sovereign-osctl perimeter reload` (re-installs from sovereign-os repo)

**selfdef** `agent-guard-*.yaml`:
- Scope: container-INTERNAL processes scoped via `matchPIDs` + pod-label selectors; targets Docker/Podman/containerd container-internal syscalls
- Authority: selfdef team (effectively the operator via selfdef config)
- Lives at: `/etc/tetragon/tracing-policies/agent-guard-*.yaml`
- Modified by: `selfdefctl modules apply` (or future `selfdefctl perimeter apply`)

The boundary: **sovereign-kernel-fence governs the OUTER container interface (which binaries can be invoked AT ALL); agent-guard governs the INNER container behavior (what those binaries can do INSIDE)**.

In Tetragon's hook-firing model:
- `sovereign-kernel-fence` fires its `sys_execve` kprobe with `matchPIDs: NotIn [1]` (not init) and `matchBinaries: NotIn` allowlist — SIGKILL non-allowlisted execves at the host level
- `agent-guard` fires its kprobes scoped via `matchNamespaces: [container]` + label selectors — independent action surface

**Non-overlap invariant**: no `agent-guard` policy should ever assert on `sys_execve` host-wide. If it does, `selfdefctl perimeter check-overlap` flags it as a violation.

### 2. `selfdefctl perimeter check-overlap`

```sh
sudo selfdefctl perimeter check-overlap
```

Output (success):
```
sovereign-kernel-fence.yaml         host-scoped sys_execve allowlist
agent-guard-etc-write.yaml          container-scoped (matchNamespaces=container) sys_openat
agent-guard-shell-exec.yaml         container-scoped (matchNamespaces=container) sys_execve

  PASS — no host-wide kprobe overlap detected
  PASS — sys_execve coverage: sovereign-kernel-fence (host) + agent-guard-shell-exec (container) — non-overlapping
  PASS — all policies have distinct metadata.name
```

Output (failure example):
```
sovereign-kernel-fence.yaml         host-scoped sys_execve allowlist
agent-guard-newfeature.yaml         host-scoped sys_execve (NOT scoped to container!)

  FAIL — agent-guard-newfeature.yaml asserts on sys_execve without matchNamespaces=container scope
       — would conflict with sovereign-kernel-fence's host-wide allowlist
       — Fix: add 'matchNamespaces: { operator: In, values: [container] }' to the selector

Exit 1.
```

Implementation: parse the YAML files in `/etc/tetragon/tracing-policies/`, extract `spec.kprobes[].call` (syscall name) + `spec.kprobes[].selectors[].matchNamespaces` (scope), assert non-overlapping coverage.

Crate: `crates/selfdef-cli/src/perimeter.rs` (new module under selfdef-cli).

### 3. `selfdefctl perimeter diff`

```sh
sudo selfdefctl perimeter diff
```

Shows the operator what's loaded in Tetragon vs what's on disk:

```
LOADED IN TETRAGON                          ON DISK (/etc/tetragon/tracing-policies/)
sovereign-kernel-fence  v1                  sovereign-kernel-fence.yaml          (matches)
agent-guard-etc-write   v2.3                agent-guard-etc-write.yaml           (matches)
agent-guard-shell-exec  v2.1                agent-guard-shell-exec.yaml          (matches)
(missing)                                   agent-guard-newfeature.yaml          (on disk but not loaded — restart tetragon?)
agent-guard-stale       v1.0                (missing)                            (loaded but not on disk — drift!)
```

Drift detection: any "loaded but not on disk" or "on disk but not loaded" prompts operator to reconcile (`sovereign-osctl perimeter reload` or `systemctl restart tetragon`).

### 4. Config block

```toml
# /etc/selfdef/selfdef.toml addition:
[perimeter]
# When target=sain01, automatically run check-overlap on every
# 'selfdefctl modules apply' invocation. Refuse to apply policies
# that would conflict with sovereign-kernel-fence.
check_overlap_on_apply = true

# Path to where sovereign-os ships its policies. selfdef reads these
# to know what to NOT overlap with.
sovereign_kernel_fence_path = "/etc/tetragon/tracing-policies/sovereign-kernel-fence.yaml"

# Optional: warn (not block) on overlap during apply (false = block by default).
overlap_warn_only = false
```

When `[deployment.target] = "sain01"` and this block is absent, defaults to `check_overlap_on_apply = true`. When `target = "generic"`, this block is ignored entirely (no sovereign-os assumption).

### 5. Audit-trail integration

Per SDD-014, the `shared-audit-summary` channel emits one summary line per event to `/mnt/vault/context/security_audit.log`. **Tetragon kill events that DON'T originate from a selfdef-authored policy** are emitted by sovereign-os's `guardian-core` daemon (component=`tetragon`).

selfdef's filter discriminator: read the Tetragon event's `policy_name` field; if it starts with `agent-guard-`, selfdef logs the event. Otherwise, it's `guardian-core`'s responsibility.

Both daemons subscribe to the same Tetragon event stream; their filter discriminators are mutually exclusive — no event is double-handled or missed.

### 6. CLI surface

```sh
sudo selfdefctl perimeter status        # existing — extends to show coexistence active
sudo selfdefctl perimeter check-overlap # new — exit 0 on pass; 1 on overlap
sudo selfdefctl perimeter diff          # new — loaded vs on-disk reconciliation
sudo selfdefctl modules apply           # extended — runs check-overlap if config says so
```

### 7. Regression-prevention tests

```rust
#[test]
fn no_overlap_passes() { /* synthetic 2 policies, host vs container scope */ }

#[test]
fn host_scoped_sys_execve_in_agent_guard_fails_overlap() { /* synthetic; selfdef policy lacks matchNamespaces */ }

#[test]
fn duplicate_metadata_name_fails() { /* two policies same name */ }

#[test]
fn loaded_vs_disk_drift_detected() { /* mock tetragon socket; agent-guard-stale loaded, not on disk */ }

#[test]
fn check_overlap_skipped_on_generic_target() { /* deployment.target=generic; coexistence not assumed */ }

#[test]
fn audit_log_filter_by_policy_name_prefix() { /* selfdef sees agent-guard-* events only */ }
```

Integration test: `tests/it/perimeter_coexistence.rs` — spawns Tetragon (or mocks via test-only daemon socket) + verifies the discriminator works end-to-end.

## Goals

1. **Non-overlapping policy authority** — sovereign-os owns host-scoped perimeter; selfdef owns container-internal. Boundary documented + enforced.
2. **Operator-visible coexistence** — `selfdefctl perimeter check-overlap` + `diff` make the integration introspectable.
3. **Pre-apply gating** — when `target=sain01`, selfdef refuses to install a policy that would overlap with sovereign-kernel-fence (unless operator explicit-allows via `overlap_warn_only`).
4. **Audit discrimination** — `policy_name` prefix filter ensures each daemon sees only its own events; no double-processing.
5. **Non-SAIN-01 unchanged** — `target=generic` deployments never run check-overlap (Q-G honored).

## Non-goals (this SDD)

- Does NOT modify the existing agent-guard TracingPolicies. SDD-015 ships the OVERLAP-CHECK tooling; agent-guard policies stay as today.
- Does NOT implement the `oracle-triage` channel (SDD-016).
- Does NOT change sovereign-os's `sovereign-kernel-fence.yaml` shape — that's owned by sovereign-os Stage-2+.
- Does NOT specify Tetragon merge semantics (Tetragon's responsibility upstream).

## Open sub-questions

- **Q15-A** — Should `check-overlap` parse Tetragon's runtime state (via socket query) or just YAML files on disk? Recommend: **YAML files first** (no Tetragon-socket dep); `diff` command separately queries the socket.
- **Q15-B** — Format of the overlap warning when overlap_warn_only=true? Recommend: stderr WARN line + journald entry; non-fail exit.
- **Q15-C** — Should sovereign-os's `sovereign-osctl perimeter check-overlap` also exist (peer command in the other repo) for the operator to invoke from either side? Recommend: **YES** — surface in sovereign-os Stage-2+ enhancement; this SDD doesn't ship that, but agrees it's natural.
- **Q15-D** — How to handle a third-party (non-sovereign-os, non-selfdef) Tetragon policy author landing files in the same dir? Recommend: warn + treat as opaque (don't fail; operator's discretion).

## Way forward

1. **This PR** — spec.
2. **Impl PR** — new selfdef-cli perimeter.rs module + check-overlap + diff + apply-time integration + tests.
3. **SDD-016 PR** — `oracle-triage` channel (Q-D resolution); the last of 4 Stage-2 SDDs.

Stage-2 progress: SDD-013 ✅ → SDD-014 (in review) → **SDD-015 (this)** → SDD-016 (next).

## Cross-references

- SDD-012 § Q-A (the design this implements)
- SDD-013 (deployment.target — gates the check-overlap-on-apply behavior)
- SDD-014 (shared-audit-summary; the audit-discrimination mechanism)
- SDD-008 (notifications-orchestration; policy_name filter pattern)
- SDD-001 (ai-machine-end-to-end; agent-guard's container-internal scope)
- SDD-004 (security-threat-model; threat surface this perimeter addresses)
- sovereign-os `scripts/hooks/post-install/tetragon-policy-load.sh` (installs sovereign-kernel-fence.yaml)
- sovereign-os `scripts/sovereign-osctl` `perimeter reload` subcommand (the peer-side reload action)
- sovereign-os SDD-011 (inference stack; Logic Engine + Oracle Core run in containers governed by both perimeters)
