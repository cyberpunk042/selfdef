# SDD-055 — Partial milestone landscape — what remains + what closes it

> Status: **implemented** — Stage-2 documentation of the 6 remaining
> `partial` milestones as of 2026-05-21. Each row enumerates the
> deferred work explicitly so the next session (operator or agent)
> can pick up without re-discovering the landscape from source.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Companions: backlog/milestones/INDEX.md (the source of truth for
> done/partial/stage-1 status); SDD-032 (eBPF substrate roadmap);
> SDD-026 (operator-dashboard Z-vectors); SDD-054 (dashboard
> as-shipped retrospective).

## Problem

The operator's standing rule is "**You cannot mark something done
if it hasn't reached Prod**." 6 of 48 milestones remain `partial`.
Each has explicit deferred-for-cause reasons but those reasons are
scattered across the catalog row + matching SDD + crate README.
A single document collecting all 6 lets the next session pick the
next promotion target deterministically.

## Goals

For each of the 6 partials:

1. Cite the exact deferred work
2. Cite the operator-architectural gating (if any)
3. Specify the surface that would close the partial → done
4. Estimate scope (single-commit / multi-commit / multi-day)
5. Link the relevant SDD + companion documents

## Non-goals

- This SDD does NOT decide priority order — the operator decides
  what closes next; this SDD just enumerates the surface
- It does NOT supersede the existing per-milestone catalog files;
  it is a synthesis layer pointing back at them

## The 6 partials

### MS002 — Collector fabric

**Status**: collector crates shipped (eBPF collector + tetragon
collector + eventstream + journald); 3 more eBPF programs deferred
per SDD-032.

**Deferred**: 3 of the 5 planned kernel-side eBPF programs:
- `proc-ancestry` — full process-tree tracking with parent
  inheritance + orphan-shell detection
- `hidden-process` — ground-truth process list from `task_struct`
  walk, cross-checked against `/proc`
- `tcp-fingerprint` — passive TCP fingerprinting on inbound SYN

**Closes when**: each program ships as a `#[tracepoint]` /
`#[lsm]` / `#[kprobe]` handler in `bpf/selfdef-bpf/src/` + the
matching `EventKind` enum variant + userspace decode path in
`selfdef-collector-ebpf`.

**Scope**: multi-day per program. Needs nightly Rust + aya +
bpf-linker + kernel BTF.

**SDD**: SDD-032 + `selfdef-ebpf/README.md`.

### MS008 — selfdef on sain-01 integration

**Status**: Sain-01 hardware inventory + `/v1/hardware/sain01`
verdict + doctor integration shipped (SDD-017 implemented).

**Deferred**: full sain-01 deployment integration — SDD-010
scoping; SDD-012 review (operator-gated).

**Closes when**: operator scopes SDD-010 + ratifies SDD-012's
locked-by-operator-gate proposals. The Stage-3 implementation
work follows the operator's next-phase audit.

**Scope**: operator-driven; agent unblocks but does not lead.

**SDD**: SDD-010 (scoping) + SDD-012 (review) + SDD-017
(implemented; hardware-inventory portion shipped).

### MS011 — Operator dashboard + flex profile

**Status**: 13 of 13 Z-vectors shipped at probe/discovery level.
4 substantive multi-commit follow-up arcs remain.

**Deferred**:
- **Z-1 full 8-tab UX restructure** — SDD-026 ratifies an 8-tab
  layout (Models / Modules / Profiles / Hardware / Network / Logs
  / MCP / REPL); today's 17-panel single-page layout is the
  intermediate state (SDD-054 retrospective). Full restructure
  needs a framework choice (askama+minijinja+HTMX per SDD-026 vs
  continuing vanilla-JS-PWA).
- **Z-2 shell-out invocation** — the inference-backend probe
  surface ships (probe + CLI + HTTP + dashboard panel). The
  actual shell-out invocation of operator-installed backends is
  the next arc.
- **Z-3 apply + revert mutation surfaces** — the
  `selfdef-flex-profile` crate + discovery layer ship. Apply +
  revert mutation goes through SDD-043 commit-authority + SDD-044
  capability-tokens — needs the caller-integration arc.
- **Z-13 SD-R87 topological install plan + SD-R86 hardware-gate
  enrichment** — dep-readiness ships; topological sort + hardware-
  gate enrichment need `HardwareRequirements` moved from
  `selfdef-cli`'s pub(crate) types to a shared crate.

**Closes when**: each arc ships its own Stage-3 set. Z-1 likely
needs its own SDD-056 (8-tab restructure spec); Z-3 mutation
needs the existing SDD-043 + SDD-044 caller-integration arc; Z-13
needs the `selfdef-hardware-requirements` shared crate split.

**Scope**: 4 multi-commit arcs. Z-1 is the biggest (full UX
restructure).

**SDD**: SDD-026 + SDD-054 (retrospective).

### MS013 — 27 SDD charter framework

**Status**: 44 implemented / 5 draft / 2 review / 3 scoping / 1
living / 55 total SDDs.

**Deferred**: ongoing charter-tracking. The 5 `draft` SDDs are
forward-looking cycle vector specs (SDD-019 / 020 / 021 / 024 /
025) — appropriately draft because they describe prospective
tensions, not retroactive shipped work. The 2 `review` SDDs
(SDD-012 + SDD-026) are operator-gated. The 3 `scoping` SDDs
(SDD-009 / 010 / 011) are operator-gated.

**Closes when**: MS013 is intentionally an evergreen tracking
milestone — it doesn't have a single "done" terminus. The
charter framework continues to evolve as production catches up
to specification.

**Scope**: ongoing; not a closeable milestone in the conventional
sense.

**SDD**: every SDD-NNN.md doc tracks against this.

### MS016 — eBPF programs + Tetragon TracingPolicies

**Status**: 1 eBPF program (execve) + Tetragon TracingPolicy
directory + collector crates shipped.

**Deferred**: 4 of the 5 planned eBPF programs (same set as
MS002's deferred list, plus `kmod-watch` and `ld-preload-watch`
which MS016 owns whereas MS002 covers the collector fabric):
- `kmod-watch` — kernel module load/unload signed/unsigned
  tracking
- `ld-preload-watch` — `LD_PRELOAD` + `/etc/ld.so.preload` use
- `proc-ancestry`, `hidden-process`, `tcp-fingerprint` (overlap
  with MS002 — same kernel-side work, different milestone
  perspective)

**Closes when**: each program ships per the SDD-032 pattern.

**Scope**: multi-day per program. Same toolchain as MS002.

**SDD**: SDD-032.

## Cross-cutting observations

1. **2 of the 6 partials are eBPF kernel work** (MS002 + MS016).
   They share the same 5-program deferred list; shipping one
   program closes 2 partial entries simultaneously.

2. **1 partial is operator-gated** (MS008) — agent unblocks but
   does NOT lead. Waits on SDD-010 + SDD-012 operator decisions.

3. **1 partial is intentionally evergreen** (MS013). It tracks
   the SDD ledger which evolves with every cycle.

4. **2 partials are MS011 + multi-commit arcs**. The Z-vector
   discovery layer is end-to-end; mutation + UX restructure + LM
   Studio invocation are the next Stage-3 rounds.

## Recommended next-session targets

Per operator-readable scope:

| Target | Effort | Unblocks |
|---|---|---|
| Ship 1 eBPF program (e.g. `kmod-watch`) | Multi-day | MS002 + MS016 simultaneously |
| Author SDD-056 for Z-1 8-tab restructure | Single-commit | Plans MS011 Z-1 |
| `selfdef-hardware-requirements` crate split | Multi-commit | Unblocks Z-13 SD-R86 hardware-gate |
| Z-3 apply/revert through SDD-043+044 | Multi-commit | Closes Z-3 |

Any of these qualifies as a meaningful next slice. The eBPF arc
has the highest yield (2 milestones closed per program) but the
highest startup cost (nightly + bpf-linker + kernel BTF).

## Open questions

- **D-1**: Is MS013 actually closeable, or does it stay
  intentionally evergreen as the SDD-ledger tracker?
  **Recommendation**: keep evergreen. The catalog of milestones
  may end; the SDD ledger doesn't.

- **D-2**: Should MS002 + MS016 merge into a single milestone
  given their deferred lists overlap? **Recommendation**: no —
  MS002 is the collector fabric (userspace decode + bus); MS016
  is the kernel-side programs. They share the deferred list but
  have distinct domains.

- **D-3**: Should Z-1 (8-tab restructure) be a separate milestone
  from MS011? **Recommendation**: keep within MS011 — the Z-N
  vectors are the natural decomposition; the restructure is one
  vector.
