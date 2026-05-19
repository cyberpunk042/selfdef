# selfdef backlog catalog — operator-mandated decomposition

> **Status:** scaffold tier — pure identification + writing of the
> selfdef catalog per the operator's standing directive:
>
> > "THE FIRST THING IS IDENTIFYING AND WRITING THOSE 10000+ requirements
> > in a clear timeline, multiple milestones and 400+ Epics and 1000+
> > modules and 5000+ features/tasks before starting working on them in
> > order in SDD."
> >
> > "Do not minimize the work in selfdef..." (2026-05-19)
>
> selfdef is one of the **two ultimate solutions** named by the operator
> (the other is `sovereign-os`). Both projects carry the full
> operator-stated decomposition. This catalog mirrors
> `cyberpunk042/sovereign-os` `backlog/` in structure, with selfdef-
> specific scope and a separate repo-scoped ID space.

## Scope (selfdef-specific)

selfdef owns the **security daemon** layer of the Ultimate AI
Workstation: the perimeter / sandbox / policy / trust-ring / capability-
token / sensor-fabric / responder / notifier-fabric stack that the
sovereign-os runtime sits inside. selfdef ALSO carries its own
operator-facing surfaces (selfdefctl CLI, dashboard, doctor, modules
catalog, audit cycles).

| Surface | Operator-stated target (selfdef scope) | Catalog target |
|---|---|---|
| Requirements (each ≥ 10 hard non-negotiable sub-requirements) | 10000+ | progressive — start at scaffold, fill over many SDD rounds |
| Epics | 400+ | progressive |
| Modules | 1000+ | progressive |
| Features / tasks | 5000+ | progressive |
| Milestones | "multiple" | 42 milestones reserved at scaffold open |

The numeric targets are **per-project** in the absence of explicit
operator partitioning. If the operator clarifies that the 10000+ is
project-wide (sovereign-os + selfdef combined), the catalog adjusts;
no row in this catalog is invalidated by that adjustment.

## Source authority

| Layer | Source | Where it lives |
|---|---|---|
| **L0 — operator verbatim** | every `/goal` block + every operator turn 2026-05-17 → 2026-05-19 → present | `~/sovereign-os/docs/standing-directives/2026-05-17-operator-mandate.md` (shared standing mandate) + `~/infohub/raw/notes/2026-05-19-operator-directive-avx-sovereign-os-arc-opening.md` |
| **L0 — raw dump** | the 18,341-line tech-stack dump | `~/infohub/raw/dumps/2026-05-18-the-ultimate-exploitation-of-the-tech-stack-AVX-plus-plus.md` |
| **L0 — existing selfdef repo state** | 14 modules + 47 crates + 27 SDDs + 14 notifier integrations + 8/8 cross-repo typed-mirror crates SATURATED | repo root |
| **L1 — this catalog** | derived, verbatim refs back to L0 only | `backlog/` |
| **L2+ — SDDs / TDDs / impl** | per Architect → DevOps → Fullstack → UX hat order | `docs/sdd/`, `crates/`, `modules/`, `tests/`, `dashboard/`, etc. |

## ID schema (repo-scoped)

| Surface | Format | Notes |
|---|---|---|
| Milestone | `MS###` | selfdef-scoped; cross-repo refs use `selfdef:MS001` |
| Epic | `E####` | selfdef-scoped |
| Module | `M#####` | selfdef-scoped |
| Feature / task | `F#####` | selfdef-scoped |
| Requirement | `R#####` | selfdef-scoped |
| Sub-requirement | `R#####.##` | inline in parent row |

IDs are **repo-scoped**. When this catalog references a sovereign-os
artifact, the ref is qualified: `sovereign-os:E0078`, `sovereign-os:R01531`,
etc. Cross-repo binding crates (the SD-R-XXX series) are the existing
canonical bridge layer; new SD-R-XXX IDs continue to be the cross-repo
binding contract IDs, separate from this catalog's E/M/F/R IDs.

## Row schema

Identical to sovereign-os `backlog/README.md`. Every row carries:
`id` / `title` / `dump_lines` (or `repo_path`) / `parent` (when applicable) /
`class` (requirements) / `opt_in` (features) / `composite` (features) /
`is_main` (features) / `profile_affected` (features) /
`sub_requirements_count` (requirements, ≥ 10) /
`acceptance` (measurable outcome — tests / evals / build artefacts /
SDD presence — NEVER "operator confirms").

## Cross-repo binding (sacrosanct invariant)

selfdef-side typed-mirror crates **must remain saturated**: every
sovereign-os compliance instrument has a typed selfdef-side mirror crate.
Current state: **8/8 SATURATED** (per `crates/selfdef-cross-repo-saturation`
+ `tests/lint/test_cross_repo_saturation_invariant.py` in sovereign-os).

| Sovereign-os consumer | Cross-repo binding ID | Selfdef-side crate |
|---|---|---|
| `bashrc-install.sh` | `SD-R-BASHRC-1` | `selfdef-bashrc-install` |
| `global-history.py` | `SD-R-EVENT-LOG-1` | `selfdef-history-sink` |
| `auth-tier.py` | `SD-R-AUTH-TIER-1` | `selfdef-auth-tier` |
| `master-dashboard.py discover` | `SD-R-DASHBOARD-MANIFEST-1` | `selfdef-dashboard-manifest` |
| `surface-map.py selfdef` | `SD-R-MULTI-SURFACE-AUDIT-1` | `selfdef-surface-manifest` |
| `ux-design-audit.py selfdef` | `SD-R-UX-CHECKLIST-1` | `selfdef-ux-checklist` |
| `anti-minimization-audit.py selfdef` | `SD-R-AUDIT-1` | `selfdef-audit-manifest` |
| `doc-coverage.py selfdef` | `SD-R-DOC-MANIFEST-1` | `selfdef-doc-manifest` |

Any new sovereign-os compliance instrument requires its typed
selfdef-side mirror in the same arc, or the saturation invariant fails.

## What this catalog is NOT

- Not a status board. Implementation status lives in commit history +
  the existing CHANGELOG + per-cycle audit ledgers (`docs/review/`).
- Not a re-decomposition of the existing 27 SDDs. The SDDs are the
  authoritative spec layer; this catalog references them.
- Not a deletion / restart of any existing crate or module. Existing
  ground truth is preserved; the catalog **maps** it and extends.
- Not the implementation plan. SFIF stage 2 (Foundation) picks up after
  this catalog is at scaffold-tier closure.

## How rounds use this catalog

1. Architect hat picks the next entry that needs its source ref / sub-
   row fleshed out.
2. DevOps SWE hat names systemd unit / cgroup slice / AppArmor profile /
   ZFS dataset / Quadlet / OTel span / Tetragon TracingPolicy /
   eBPF program / Suricata rule path.
3. Fullstack hat names data model / API endpoint / message-bus topic
   (`selfdef-bus` / `selfdef-nats`) / test substrate (L1–L5).
4. UX hat names dashboard view / `selfdefctl` verb / doctor advisory /
   notifier channel layout / interaction states.
5. Each round commits the catalog update; cross-repo binding lint stays
   green via the SD-R-XXX saturation invariant.

## Cross-references

- Operator standing directive (shared): `~/sovereign-os/docs/standing-directives/2026-05-17-operator-mandate.md`
- AVX++ arc opening (shared): `~/infohub/raw/notes/2026-05-19-operator-directive-avx-sovereign-os-arc-opening.md`
- Sovereign-os catalog (sister): `~/sovereign-os/backlog/`
- Existing selfdef SDD ledger: `docs/sdd/`
- Existing selfdef module catalog: `modules/`
- Existing selfdef crate index: `crates/`
- Cross-repo binding doctrine: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md`
- Cross-repo saturation invariant: `~/sovereign-os/tests/lint/test_cross_repo_saturation_invariant.py`

## Decision log (confirmed-provisional, operator-overrideable)

| ID | Decision | Reasoning |
|---|---|---|
| D-SD-CAT-001 | selfdef catalog lives at `backlog/` (mirrors sovereign-os layout). | Symmetry with sister project; common operator mental model. |
| D-SD-CAT-002 | IDs are repo-scoped (E0001, M00001, R00001) within selfdef. | Avoids ID collision with sovereign-os; cross-repo refs are qualified by repo name. |
| D-SD-CAT-003 | Operator-stated 10000+/400+/1000+/5000+ counts assumed per-project until operator clarifies. | Safer default — fewer rows under-targeted than required; operator can collapse if combined-count was intended. |
| D-SD-CAT-004 | 42 selfdef milestones reserved at scaffold open. | One per existing module (14) + one per existing crate cluster + one per dump-named security boundary + per audit-cycle vector + per cross-repo binding + per notifier-fabric axis. Reservation, not commitment to specific names beyond the named seeds. |
| D-SD-CAT-005 | SD-R-XXX cross-repo binding IDs continue to be the canonical bridge layer, SEPARATE from this catalog's E/M/F/R numbering. | Existing saturation invariant must keep working; the catalog references SD-R-XXX IDs but does not renumber them. |
| D-SD-CAT-006 | Existing 27 SDDs (000-charter through 026-operator-dashboard-and-flex-profile, plus newer numbered SDDs) are the authoritative spec layer. The catalog references them by number; the catalog does NOT rewrite them. | Forensic preservation — operator-touched specs stay verbatim. |
| D-SD-CAT-007 | No deletion of any existing module / crate / SDD / commit. The catalog is **additive**. | Operator directive 2026-05-19: "STOP WORKING IN the second-brain you fucking trash" + "you discard[ed] an entire branch" (re-issued 2026-05-19). Additive discipline is the standing rule. |
