# SDD-033 — Agent-guard host-level invariants on AI agents — MS017

> Status: **draft** — Stage-2 architectural spec retrofitted for the
> shipped `agent-guard` module under `modules/agent-guard/`. The
> module ships in production (5 Tetragon TracingPolicies +
> `install/apply.sh` with profile + per-policy controls); this SDD
> canonicalizes its design so operators have a single architectural
> reference for AI-agent-in-container hardening.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS017 (catalog `backlog/milestones/MS017-agent-guard-host-level-invariants-on-ai-agents.md`)
> Builds on: SDD-032 (eBPF substrate + TracingPolicy ledger — MS016
> substrate this module consumes via `depends_on = ["tetragon"]`)
> Companions: SDD-028 (perimeter engine — sister kernel-fence layer
> for non-AI workloads), the L2 bats suite at
> `packaging/test/L2-agent-guard.bats` (25 tests).

## Problem

AI agents running on a sovereign workstation (Claude Code, openarms,
local LLM agent loops) execute long sessions inside containers with
access to:
- the operator's filesystem (read-write)
- the network (outbound, including to the operator's own services)
- the operator's secrets (env vars, mounted credentials)
- the host's GPUs (if mounted into the container)

Without a kernel-side hardening layer, a misbehaving / compromised
agent can:
- write into `/etc/` and persist a backdoor
- exfiltrate via egress to an attacker-controlled endpoint
- spawn an interactive shell that breaks out of the agent loop
- touch GPU devices outside its scheduled allocation
- emit OCSF SecureMessage events that bypass the operator's audit
  trail

`agent-guard` adds 5 Tetragon TracingPolicies that hook at the kernel
level + apply per-policy actions (audit or killProcess) based on the
operator's profile.

## Operator directive — verbatim (sacrosanct)

> "I told you, you cannot invent crap, its my projects and there is
>  no room for your trash, I have enough work for years.... The list
>  is mostly done for Selfdef and sovereign-OS and for work in SDD
>  and TDD and be an architect first, then a DevOps Software Engineer
>  and Fullstack and UX Design Specialist."

Translation for MS017: the 5 TracingPolicies must be SHIPPED + the
operator must be able to flip audit↔enforce + toggle individual
policies + override per-policy actions + scope the policies by pod
label — all via a single TOML config at
`/etc/selfdef/modules/agent-guard.toml`.

## Module inventory (shipped, as of 2026-05-21)

| Artifact | Path | What it is |
|---|---|---|
| Manifest | `modules/agent-guard/module.toml` | Declares `depends_on = ["tetragon"]`, profile-list `[audit, enforce]`, install.kind=script, MS017 contract surface |
| Policies | `modules/agent-guard/policies/*.yaml` | 5 TracingPolicies (etc-write-guard, container-shell-guard, egress-guard, securemessage-guard, gpu-device-guard) |
| Apply | `modules/agent-guard/install/apply.sh` | Renders the 5 policies with operator-config substitutions + lands them under Tetragon's `policy_dir` |
| Check | `modules/agent-guard/install/check.sh` | Read-only verifier; emits structured status JSON |
| Uninstall | `modules/agent-guard/install/uninstall.sh` | Idempotent removal of rendered policies |
| Helper lib | `modules/agent-guard/install/lib.sh` | TOML readers + status emitters |
| L2 tests | `packaging/test/L2-agent-guard.bats` | 25 tests (module shape + apply.sh contract + 5 policy structural checks + dry-run smoke + idempotency + malformed-profile rejection) |

## Required coverage (Stage-2 acceptance)

### Deliverable 1 — Five TracingPolicies + per-policy controls

Each policy supports four orthogonal axes:

| Axis | Config key (`agent-guard.toml`) | Values | Default |
|---|---|---|---|
| Enable / disable | `<policy>_enabled` | `"true"` / `"false"` | `"true"` |
| Action override | `<policy>_action` | `"default"` (= profile) / `"audit"` / `"killProcess"` / `"Post"` | `"default"` |
| Profile (global) | `profile` | `"audit"` / `"enforce"` | `"audit"` |
| Scope filter | `pod_label_key` + `pod_label_value` | string + string | `""` (any) |

Profile-to-default-action mapping:

| Profile | etc-write | container-shell | egress | securemessage | gpu-device |
|---|---|---|---|---|---|
| `audit` | audit | audit | audit | **Post** (forced) | audit |
| `enforce` | killProcess | killProcess | killProcess | **Post** (forced) | killProcess |

`securemessage-guard` is forced to **Post** regardless of profile —
the operator's OCSF SecureMessage audit trail must never be killed
by the kernel fence. This is the one non-overridable contract.

### Deliverable 2 — Egress allowlist + SecureMessage endpoint splice

Two policies have operator-pluggable substitutions:

```toml
# /etc/selfdef/modules/agent-guard.toml
egress_allowlist        = "10.0.0.0/8 192.168.0.0/16 selfdef.local"
securemessage_endpoint  = "https://oracle.example.invalid:443/ocsf"
```

`apply.sh` splices these into the rendered YAML before writing to the
policy_dir. The allowlist is enforced at kernel-syscall time (Tetragon
matches `connect(2)` destination); the endpoint becomes the
`SecureMessage` Post target.

### Deliverable 3 — Scope filter (pod-label-based)

When `pod_label_key` + `pod_label_value` are set, every rendered policy
narrows to pods that carry that label. This lets operators run
agent-guard on the AI-agent containers without affecting unrelated
pods (e.g. database containers, system services).

When both are empty, the policies apply to all containerized
processes (the default — sovereign-workstation single-tenant case).

### Deliverable 4 — Operator-facing surface

| Verb | Command | Effect |
|---|---|---|
| Install | `sudo selfdefctl modules apply` (with `[modules.agent-guard]` activated in `/etc/selfdef/modules.toml`) | Renders policies + lands in Tetragon's policy_dir + waits for Tetragon to pick them up (Tetragon watches the dir) |
| Verify | `selfdefctl modules check agent-guard` | Runs `check.sh`; emits JSON status (ok or missing) |
| Uninstall | `sudo selfdefctl modules uninstall agent-guard` | Removes rendered policies; Tetragon auto-evicts them |
| Profile swap | edit `/etc/selfdef/modules/agent-guard.toml` + re-apply | Idempotent (apply.sh re-renders byte-identical on no-op) |

### Deliverable 5 — Dry-run + idempotency contract

`SELFDEF_DRY_RUN=1 selfdefctl modules apply --only agent-guard` MUST:
- print intended changes
- NOT mutate any file under `/etc/tetragon/`
- exit 0

Two back-to-back applies MUST be byte-identical on the second run
(no "changes detected" output, no policy_dir touch). The L2 bats
suite verifies this (`packaging/test/L2-agent-guard.bats:agent-guard
dry-run is idempotent (two runs both succeed)`).

## Production-readiness gates

| Gate | Verification |
|---|---|
| 5 TracingPolicies ship | `ls modules/agent-guard/policies/ \| wc -l` == 5 |
| Every policy parses as YAML | L2 bats tests 16-20 |
| Every policy has kind: TracingPolicy(Namespaced) + metadata.name | L2 bats tests 21-22 |
| apply.sh exposes 5 enable toggles + 5 action overrides | L2 bats tests 13-14 |
| Both profiles (audit, enforce) supported | L2 bats test 11 |
| Dry-run idempotency holds | L2 bats test 24 |
| Manifest declares MS016 tetragon dependency | L2 bats test 3 |
| Coherence harness includes L2-agent-guard | `make coherence` includes it (auto-discovered) |

## Implementation order (retrospective — already shipped)

1. ✅ Manifest declaring tetragon dependency + [audit, enforce] profiles
2. ✅ 5 TracingPolicy YAML templates under `policies/`
3. ✅ `install/apply.sh` with profile dispatch + per-policy controls +
   egress allowlist + SecureMessage endpoint splice + scope filter
4. ✅ `install/check.sh` read-only verifier
5. ✅ `install/uninstall.sh` idempotent removal
6. ✅ `install/lib.sh` shared TOML readers + status emitters
7. ✅ `L2-agent-guard.bats` (25 tests, all PASS)

## Cross-references

- MS016 substrate: `docs/sdd/032-ebpf-substrate-and-tetragon-policy-ledger.md`
- Sister kernel-fence (non-AI workloads): `docs/sdd/028-perimeter-engine.md`
- Tetragon TracingPolicy ledger contract (rules/tetragon/) is documented
  in SDD-032 D6
- Module-author contract: `docs/dev/modules.md`
- L2 verification: `packaging/test/L2-agent-guard.bats`

## Authorization for Stage-3+ work

This SDD authorizes:

- New policies under `modules/agent-guard/policies/` — drop a YAML +
  add per-policy enable/action keys to `apply.sh` + add 2 L2 bats
  tests (parse + metadata.name) → expand the L2 suite from 25 to 27
- Operator-author extension via `rules/tetragon/` (per SDD-032 D6) —
  not under agent-guard's authorship but consumed by Tetragon
- L3 integration: a systemd-nspawn boot-replay test that runs
  agent-guard in a container + asserts a policy fires on a synthetic
  agent-misbehavior (deferred to operator-hardware-gated work per
  SDD-030 D7)

Mark a Stage-3+ extension DONE only when it reaches production per the
operator's "you cannot mark something done if it hasn't reached Prod"
discipline.

— End of SDD-033 / MS017 Stage-2.
