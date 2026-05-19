# MS009 — Audit cycles

> Parent: `backlog/milestones/INDEX.md` row MS009.
> Source: `docs/sdd/019-cycle3-forward-looking-spec.md` + `docs/sdd/020-cycle3-vectors.md` + `docs/sdd/021-cycle4-vectors.md` + `docs/sdd/024-cycle5-vectors.md` + `docs/sdd/025-cycle6-vectors.md` + `docs/review/{00-charter,10-inventory,20-crate-audit,30-module-audit,40-integration-audit,50-docs-audit,60-tests-audit,70-recent-prs-audit,80-security-audit,99-findings-ledger}.md` + `docs/review/phase-6/{00..99}.md` + `docs/review/phase-7/{00..99}.md` + `docs/review/phase-8/{00-charter,99-findings-ledger}.md`. All entries below extract verbatim from these source files. No invention.

## Epics (E0091–E0100)

| Epic ID | Phrase | Source |
|---|---|---|
| E0091 | Phase 6 audit — SDD-008 cycle close (10 sections: charter / inventory / recent-PRs / crate / module / integration / docs / tests / security / findings) | `docs/review/phase-6/` |
| E0092 | Phase 7 audit — post-Phase-6 cycle close (10 sections, parallel structure to Phase 6) | `docs/review/phase-7/` |
| E0093 | Phase 8 audit — deferral doctrine (charter + findings-ledger only; deferral over thin compliance) | `docs/review/phase-8/` |
| E0094 | SDD-019 cycle-3 forward-looking spec — open tensions T-1..T-6 + in-cycle closures R43 SDD authoring → R48 | `docs/sdd/019-cycle3-forward-looking-spec.md` |
| E0095 | SDD-020 cycle-3 vectors — V-1..V-7 (audit subject expansion / per-predicate metrics / custom predicates / RBAC / signing / thermal / mid-cycle V-7 hardware rollup) | `docs/sdd/020-cycle3-vectors.md` |
| E0096 | SDD-021 cycle-4 vectors — W-1..W-6 (slice-plan schema / signing key rotation / fleet aggregation / real-runtime integration test / sigstore / per-module quotas) | `docs/sdd/021-cycle4-vectors.md` |
| E0097 | SDD-024 cycle-5 vectors — X-1..X-6 (composable predicates / depends_optional / simulate / LoRA lifecycle / --reprobe-hardware / module-class taxonomy) | `docs/sdd/024-cycle5-vectors.md` |
| E0098 | SDD-025 cycle-6 vectors — Y-1..Y-6 (`any_of` Layer-B / LoRA registry state / `models suggest` cross-repo bridge / `modules show-effective` / `--reprobe-hardware` action / `[whitelabel]` block) | `docs/sdd/025-cycle6-vectors.md` |
| E0099 | Findings-ledger continuity — single rolling 99-findings-ledger per phase, plus top-level `docs/review/99-findings-ledger.md` master | `docs/review/99-findings-ledger.md` + per-phase 99 files |
| E0100 | Audit-cycle doctrine — every cycle closes with the 10 sections + opens next cycle's forward-looking SDD; cycle ratification = operator answers + CHANGELOG close note | charter pattern across Phases 6/7/8 + SDD-019/020/021/024/025 |

## Modules (M00213–M00238)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00213 | phase-6/00-charter — Why Phase 6 now + scope + methodology + predicted outcome + naming | `docs/review/phase-6/00-charter.md` | E0091 |
| M00214 | phase-6/10-inventory — repo state at audit start (crates / modules / SDDs / dashboards) | `docs/review/phase-6/10-inventory.md` | E0091 |
| M00215 | phase-6/20-recent-prs-audit — PR review covering SDD-008 cycle | `docs/review/phase-6/20-recent-prs-audit.md` | E0091 |
| M00216 | phase-6/30-crate-audit — 47 selfdef-* crates audited | `docs/review/phase-6/30-crate-audit.md` | E0091 |
| M00217 | phase-6/40-module-audit — 14 functional modules audited | `docs/review/phase-6/40-module-audit.md` | E0091 |
| M00218 | phase-6/50-integration-audit — 14 notifier integrations audited | `docs/review/phase-6/50-integration-audit.md` | E0091 |
| M00219 | phase-6/60-docs-audit — SDDs + READMEs + CHANGELOG audited | `docs/review/phase-6/60-docs-audit.md` | E0091 |
| M00220 | phase-6/70-tests-audit — L1-L5 harness audit | `docs/review/phase-6/70-tests-audit.md` | E0091 |
| M00221 | phase-6/80-security-audit — supply-chain + AppArmor + eBPF + threat-model | `docs/review/phase-6/80-security-audit.md` | E0091 |
| M00222 | phase-6/99-findings-ledger — rolling Phase-6 findings | `docs/review/phase-6/99-findings-ledger.md` | E0099 |
| M00223 | phase-7 audit set — 10 sections parallel to Phase 6 | `docs/review/phase-7/` | E0092 |
| M00224 | phase-7/99-findings-ledger — Phase-7 findings continuity | `docs/review/phase-7/99-findings-ledger.md` | E0099 |
| M00225 | phase-8/00-charter — deferral over thin compliance (TL;DR + bias analysis) | `docs/review/phase-8/00-charter.md` | E0093 |
| M00226 | phase-8 trigger conditions — when to open Phase 8 for real | `docs/review/phase-8/00-charter.md` (trigger conditions section) | E0093 |
| M00227 | SDD-019 T-1 ANY-vs-ALL gate-predicate semantics + T-2 operator-override audit trail | `docs/sdd/019-cycle3-forward-looking-spec.md` T-1, T-2 | E0094 |
| M00228 | SDD-019 T-3..T-6 (registry-artifact verification / cross-repo schema drift / matrix codified-vs-inlined / schedule.json schema) | `docs/sdd/019-cycle3-forward-looking-spec.md` T-3..T-6 | E0094 |
| M00229 | SDD-020 V-1..V-7 cycle-3 vectors (audit-trail subjects / Layer-B metrics / custom predicates / RBAC / signing / thermal / V-7 hardware rollup) | `docs/sdd/020-cycle3-vectors.md` | E0095 |
| M00230 | SDD-021 W-1..W-6 cycle-4 vectors (slice-plan / key rotation / fleet API / runtime test / sigstore / per-module quotas) | `docs/sdd/021-cycle4-vectors.md` | E0096 |
| M00231 | SDD-024 X-1..X-6 cycle-5 vectors (composable predicates / depends_optional / simulate / LoRA lifecycle / --reprobe-hardware / module-class taxonomy) | `docs/sdd/024-cycle5-vectors.md` | E0097 |
| M00232 | SDD-025 Y-1..Y-6 cycle-6 vectors (`any_of` Layer-B / LoRA state / `models suggest` / show-effective / reprobe-action / whitelabel) | `docs/sdd/025-cycle6-vectors.md` | E0098 |
| M00233 | Cycle-close → forward-looking pattern — each cycle opens next cycle's vectors SDD | SDD-019/020/021/024/025 ordering | E0100 |
| M00234 | Findings-ledger authority — operator-readable single-source-of-truth per phase | `docs/review/99-findings-ledger.md` + per-phase 99 | E0099 |
| M00235 | Audit charter naming convention — Phase-N numbering + section number prefixes (00 / 10 / 20 / .../99) | charter naming sections in phase-6/-7 charters | E0100 |
| M00236 | `docs/review/` subdirectory layout — top-level audit + per-phase subdir + findings-ledger files | `docs/review/` tree | E0100 |
| M00237 | Cycle ratification mechanism — operator answers + CHANGELOG close note + closing SDD links to opening vectors SDD | "How operators ratify" sections in SDD-019/020/021/024/025 | E0100 |
| M00238 | Audit-cycle boundary — audit cycles are doctrine-only (no impl); paired implementation work happens under successor SDD-NNN | charter "Out of scope" sections | E0100 |

## Features (F00961–F01080)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00961 | Phase-6 charter — Why-Phase-6-now rationale | phase-6/00-charter | M00213 | composite | false |
| F00962 | Phase-6 charter — what changed during SDD-008 cycle | phase-6/00-charter | M00213 | composite | false |
| F00963 | Phase-6 charter — scope of this phase | phase-6/00-charter | M00213 | composite | false |
| F00964 | Phase-6 charter — out-of-scope deferral to Phase 7 or later | phase-6/00-charter | M00213 | composite | false |
| F00965 | Phase-6 charter — methodology | phase-6/00-charter | M00213 | composite | false |
| F00966 | Phase-6 charter — predicted outcome | phase-6/00-charter | M00213 | composite | false |
| F00967 | Phase-6 charter — status field | phase-6/00-charter | M00213 | composite | false |
| F00968 | Phase-6 charter — naming convention rationale | phase-6/00-charter | M00213 | composite | false |
| F00969 | Phase-6 inventory — crate count snapshot | phase-6/10-inventory | M00214 | composite | false |
| F00970 | Phase-6 inventory — module count snapshot | phase-6/10-inventory | M00214 | composite | false |
| F00971 | Phase-6 inventory — SDD count snapshot | phase-6/10-inventory | M00214 | composite | false |
| F00972 | Phase-6 inventory — dashboard / packaging / ansible / rules / bpf / supply-chain subtree snapshot | phase-6/10-inventory | M00214 | composite | false |
| F00973 | Phase-6 recent-PRs audit — PRs in SDD-008 cycle | phase-6/20-recent-prs-audit | M00215 | composite | false |
| F00974 | Phase-6 crate audit — per-crate findings rows | phase-6/30-crate-audit | M00216 | composite | false |
| F00975 | Phase-6 module audit — per-module findings rows | phase-6/40-module-audit | M00217 | composite | false |
| F00976 | Phase-6 integration audit — per-notifier findings rows | phase-6/50-integration-audit | M00218 | composite | false |
| F00977 | Phase-6 docs audit — per-SDD findings + README drift | phase-6/60-docs-audit | M00219 | composite | false |
| F00978 | Phase-6 tests audit — L1-L5 harness coverage findings | phase-6/70-tests-audit | M00220 | composite | false |
| F00979 | Phase-6 security audit — supply-chain findings | phase-6/80-security-audit | M00221 | composite | false |
| F00980 | Phase-6 security audit — AppArmor profile findings | phase-6/80-security-audit | M00221 | composite | false |
| F00981 | Phase-6 security audit — eBPF / Tetragon TracingPolicy findings | phase-6/80-security-audit | M00221 | composite | false |
| F00982 | Phase-6 security audit — threat-model drift findings | phase-6/80-security-audit | M00221 | composite | false |
| F00983 | Phase-6 findings ledger — finding rows rolled up | phase-6/99-findings-ledger | M00222 | composite | false |
| F00984 | Phase-7 charter — Why-Phase-7-now rationale | phase-7/00-charter | M00223 | composite | false |
| F00985 | Phase-7 charter — what changed during post-Phase-6 cycle | phase-7/00-charter | M00223 | composite | false |
| F00986 | Phase-7 charter — scope + methodology + predicted outcome | phase-7/00-charter | M00223 | composite | false |
| F00987 | Phase-7 charter — status + naming | phase-7/00-charter | M00223 | composite | false |
| F00988 | Phase-7 inventory snapshot | phase-7/10-inventory | M00223 | composite | false |
| F00989 | Phase-7 recent-PRs audit | phase-7/20-recent-prs-audit | M00223 | composite | false |
| F00990 | Phase-7 crate audit | phase-7/30-crate-audit | M00223 | composite | false |
| F00991 | Phase-7 module audit | phase-7/40-module-audit | M00223 | composite | false |
| F00992 | Phase-7 integration audit | phase-7/50-integration-audit | M00223 | composite | false |
| F00993 | Phase-7 docs audit | phase-7/60-docs-audit | M00223 | composite | false |
| F00994 | Phase-7 tests audit | phase-7/70-tests-audit | M00223 | composite | false |
| F00995 | Phase-7 security audit | phase-7/80-security-audit | M00223 | composite | false |
| F00996 | Phase-7 findings ledger | phase-7/99-findings-ledger | M00224 | composite | false |
| F00997 | Phase-8 deferral — TL;DR | phase-8/00-charter | M00225 | composite | false |
| F00998 | Phase-8 deferral — why deferral over thin compliance audit | phase-8/00-charter | M00225 | composite | false |
| F00999 | Phase-8 — the cycle Phase 8 would have audited (sub-cycle 1: PRs #156-#163 orient + resolve infrastructure) | phase-8/00-charter | M00225 | composite | false |
| F01000 | Phase-8 — sub-cycle 2: PRs #164-#169 cleanup decisions + doc-drift fixes | phase-8/00-charter | M00225 | composite | false |
| F01001 | Phase-8 — sub-cycle 3: PRs #170-#171 write(1) integration + dashboard requirements | phase-8/00-charter | M00225 | composite | false |
| F01002 | Phase-8 — cross-repo scope listing | phase-8/00-charter | M00225 | composite | false |
| F01003 | Phase-8 — by-the-numbers section | phase-8/00-charter | M00225 | composite | false |
| F01004 | Phase-8 — bias analysis | phase-8/00-charter | M00225 | composite | false |
| F01005 | Phase-8 — trigger conditions for opening Phase 8 for real | phase-8/00-charter | M00226 | composite | false |
| F01006 | Phase-8 — what Phase 9 (or next opened) inherits | phase-8/00-charter | M00225 | composite | false |
| F01007 | Phase-8 findings ledger — deferral entry | phase-8/99-findings-ledger | M00225 | composite | false |
| F01008 | SDD-019 T-1 — gate predicate semantics ANY-vs-ALL design tension | SDD-019 T-1 | M00227 | composite | false |
| F01009 | SDD-019 T-2 — operator-override audit trail design tension | SDD-019 T-2 | M00227 | composite | false |
| F01010 | SDD-019 T-3 — model registry artifact verification design tension | SDD-019 T-3 | M00228 | composite | false |
| F01011 | SDD-019 T-4 — cross-repo schema drift detection design tension | SDD-019 T-4 | M00228 | composite | false |
| F01012 | SDD-019 T-5 — recommendation matrix codified-vs-inlined design tension | SDD-019 T-5 | M00228 | composite | false |
| F01013 | SDD-019 T-6 — schedule.json schema design tension | SDD-019 T-6 | M00228 | composite | false |
| F01014 | SDD-019 in-cycle tension closures R43 SDD authoring → R48 | SDD-019 R43→R48 | M00227 | composite | false |
| F01015 | SDD-019 recommended cycle-3 priorities (operator-rankable) | SDD-019 | M00227 | composite | false |
| F01016 | SDD-019 non-goals for cycle 3 | SDD-019 | M00227 | composite | false |
| F01017 | SDD-019 — how operators ratify | SDD-019 | M00237 | composite | false |
| F01018 | SDD-019 — cycle-2 learnings (delivered surface section) | SDD-019 | M00227 | composite | false |
| F01019 | SDD-019 — open operator questions (cycle 3) | SDD-019 | M00227 | composite | false |
| F01020 | SDD-020 V-1 — per-module audit-trail subjects beyond `--ignore-hardware` | SDD-020 V-1 | M00229 | composite | false |
| F01021 | SDD-020 V-2 — per-predicate Layer-B metrics | SDD-020 V-2 | M00229 | composite | false |
| F01022 | SDD-020 V-3 — operator-defined custom predicates | SDD-020 V-3 | M00229 | composite | false |
| F01023 | SDD-020 V-4 — per-module RBAC integration | SDD-020 V-4 | M00229 | composite | false |
| F01024 | SDD-020 V-5 — module manifest signing | SDD-020 V-5 | M00229 | composite | false |
| F01025 | SDD-020 V-6 — predictive thermal modelling | SDD-020 V-6 | M00229 | composite | false |
| F01026 | SDD-020 V-7 — mid-cycle emergence: hardware-exploitation rollup | SDD-020 V-7 | M00229 | composite | false |
| F01027 | SDD-020 cycle-3 priority ranking | SDD-020 | M00229 | composite | false |
| F01028 | SDD-020 non-goals for cycle 3 | SDD-020 | M00229 | composite | false |
| F01029 | SDD-020 — how operators ratify | SDD-020 | M00237 | composite | false |
| F01030 | SDD-020 — SDD-019 closing status | SDD-020 | M00229 | composite | false |
| F01031 | SDD-020 — V-N NEW vector naming convention (V = cycle 3) | SDD-020 | M00235 | composite | false |
| F01032 | SDD-021 W-1 — tensor-parallel slice-plan schema doc | SDD-021 W-1 | M00230 | composite | false |
| F01033 | SDD-021 W-2 — module signing key rotation | SDD-021 W-2 | M00230 | composite | false |
| F01034 | SDD-021 W-3 — cross-host fleet aggregation API | SDD-021 W-3 | M00230 | composite | false |
| F01035 | SDD-021 W-4 — selfdef integration test against a real BitNet runtime | SDD-021 W-4 | M00230 | composite | false |
| F01036 | SDD-021 W-5 — module manifest sigstore / cosign alternative | SDD-021 W-5 | M00230 | composite | false |
| F01037 | SDD-021 W-6 — per-module resource quotas | SDD-021 W-6 | M00230 | composite | false |
| F01038 | SDD-021 cycle-4 priority ranking | SDD-021 | M00230 | composite | false |
| F01039 | SDD-021 non-goals for cycle 4 | SDD-021 | M00230 | composite | false |
| F01040 | SDD-021 — how operators ratify | SDD-021 | M00237 | composite | false |
| F01041 | SDD-021 — doctrine layer state | SDD-021 | M00230 | composite | false |
| F01042 | SDD-021 — SDD-020 carry-over to cycle 4 | SDD-021 | M00230 | composite | false |
| F01043 | SDD-021 — W-N NEW vector naming convention (W = cycle 4) | SDD-021 | M00235 | composite | false |
| F01044 | SDD-024 X-1 — composable predicates (AND/OR combinators) | SDD-024 X-1 | M00231 | composite | false |
| F01045 | SDD-024 X-2 — cross-module dependency negotiation (`depends_optional`) | SDD-024 X-2 | M00231 | composite | false |
| F01046 | SDD-024 X-3 — per-module preflight `simulate` mode | SDD-024 X-3 | M00231 | composite | false |
| F01047 | SDD-024 X-4 — real LoRA-adapter lifecycle on the registry | SDD-024 X-4 | M00231 | composite | false |
| F01048 | SDD-024 X-5 — apply-time hardware re-probe (`--reprobe-hardware`) | SDD-024 X-5 | M00231 | composite | false |
| F01049 | SDD-024 X-6 — module-class taxonomy (parallel to R212 model class) | SDD-024 X-6 | M00231 | composite | false |
| F01050 | SDD-024 cycle-5 priority ranking | SDD-024 | M00231 | composite | false |
| F01051 | SDD-024 non-goals for cycle 5 | SDD-024 | M00231 | composite | false |
| F01052 | SDD-024 — how operators ratify | SDD-024 | M00237 | composite | false |
| F01053 | SDD-024 — cycle-3 + cycle-4 closing status | SDD-024 | M00231 | composite | false |
| F01054 | SDD-024 — cross-references section | SDD-024 | M00231 | composite | false |
| F01055 | SDD-024 — X-N NEW vector naming convention (X = cycle 5) | SDD-024 | M00235 | composite | false |
| F01056 | SDD-025 Y-1 — `any_of` Layer-B observability | SDD-025 Y-1 | M00232 | composite | false |
| F01057 | SDD-025 Y-2 — LoRA registry state file format | SDD-025 Y-2 | M00232 | composite | false |
| F01058 | SDD-025 Y-3 — `models suggest` cross-repo bridge | SDD-025 Y-3 | M00232 | composite | false |
| F01059 | SDD-025 Y-4 — `modules show-effective` after any_of evaluation | SDD-025 Y-4 | M00232 | composite | false |
| F01060 | SDD-025 Y-5 — `--reprobe-hardware` actually does something | SDD-025 Y-5 | M00232 | composite | false |
| F01061 | SDD-025 Y-6 — module `[whitelabel]` block | SDD-025 Y-6 | M00232 | composite | false |
| F01062 | SDD-025 cycle-6 priority ranking | SDD-025 | M00232 | composite | false |
| F01063 | SDD-025 non-goals for cycle 6 | SDD-025 | M00232 | composite | false |
| F01064 | SDD-025 — how operators ratify | SDD-025 | M00237 | composite | false |
| F01065 | SDD-025 — cycle-5 closing status | SDD-025 | M00232 | composite | false |
| F01066 | SDD-025 — cross-references section | SDD-025 | M00232 | composite | false |
| F01067 | SDD-025 — Y-N NEW vector naming convention (Y = cycle 6) | SDD-025 | M00235 | composite | false |
| F01068 | Findings-ledger top-level `docs/review/99-findings-ledger.md` rolls up per-phase | `docs/review/99-findings-ledger.md` | M00234 | composite | false |
| F01069 | Per-phase findings-ledger files (phase-6/-7/-8 each owns its 99) | per-phase 99 files | M00234 | composite | false |
| F01070 | Cycle-close → forward-looking pattern — each closing SDD opens next vectors SDD | SDD-019→020→021→024→025 | M00233 | composite | false |
| F01071 | Audit charter naming — `Phase N` (N is integer) + section-number prefixes 00..99 | charter naming sections | M00235 | composite | false |
| F01072 | `docs/review/` top-level audit files (00-charter / 10-inventory / 20-crate / 30-module / 40-integration / 50-docs / 60-tests / 70-recent-prs / 80-security / 99-findings) | `docs/review/` | M00236 | composite | false |
| F01073 | `docs/review/phase-N/` subdirectory layout (same 10 sections, phase-scoped) | phase-6 / phase-7 layout | M00236 | composite | false |
| F01074 | Cycle ratification — operator answers open questions + CHANGELOG entry closes the cycle | SDD-019/020/021/024/025 ratify sections | M00237 | composite | false |
| F01075 | Audit cycles are doctrine-only — implementation effort happens under successor SDD-NNN | charter out-of-scope sections | M00238 | composite | false |
| F01076 | Composite — every audit cycle closes with 10 sections + opens next cycle's forward-looking SDD | E0100 doctrine | M00233 | composite | false |
| F01077 | Composite — findings-ledger is operator-readable single-source-of-truth per phase | E0099 | M00234 | composite | false |
| F01078 | Composite — Phase-8 deferral is a first-class outcome (NOT a thin compliance audit) | phase-8/00-charter | M00225 | composite | false |
| F01079 | Composite — audit cycles preserve cross-repo binding doctrine (SDD-038) — no cross-repo audit invents typed-mirror crate; only mirrors existing 8/8 SATURATED set | MS007 + SDD-038 | M00238 | composite | false |
| F01080 | Composite — audit-cycle authority — only the operator ratifies a cycle close; AI sessions propose findings, never close | charter ratify sections | M00237 | composite | false |

## Requirements (R01921–R02160)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R01921 | Phase 6 audit cycle exists at `docs/review/phase-6/` | `docs/review/phase-6/` | E0091 | non-negotiable | false | 10 |
| R01922 | Phase 6 charter document `phase-6/00-charter.md` exists and states Why-Phase-6-now | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01923 | Phase 6 charter states what changed during the SDD-008 cycle | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01924 | Phase 6 charter declares scope of the phase | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01925 | Phase 6 charter declares out-of-scope deferrals to Phase 7 or later | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01926 | Phase 6 charter declares methodology | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01927 | Phase 6 charter declares predicted outcome | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01928 | Phase 6 charter declares status field | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01929 | Phase 6 charter declares naming convention rationale | phase-6/00-charter | M00213 | non-negotiable | false | 10 |
| R01930 | Phase 6 inventory `phase-6/10-inventory.md` snapshots repo state at audit start | phase-6/10-inventory | M00214 | non-negotiable | false | 10 |
| R01931 | Phase 6 inventory records crate count snapshot | phase-6/10-inventory | F00969 | non-negotiable | false | 10 |
| R01932 | Phase 6 inventory records module count snapshot | phase-6/10-inventory | F00970 | non-negotiable | false | 10 |
| R01933 | Phase 6 inventory records SDD count snapshot | phase-6/10-inventory | F00971 | non-negotiable | false | 10 |
| R01934 | Phase 6 inventory records dashboard / packaging / ansible / rules / bpf / supply-chain subtree snapshot | phase-6/10-inventory | F00972 | non-negotiable | false | 10 |
| R01935 | Phase 6 recent-PRs audit `phase-6/20-recent-prs-audit.md` covers SDD-008 cycle PRs | phase-6/20-recent-prs-audit | M00215 | non-negotiable | false | 10 |
| R01936 | Phase 6 crate audit `phase-6/30-crate-audit.md` covers the 47 selfdef-* crates | phase-6/30-crate-audit | M00216 | non-negotiable | false | 10 |
| R01937 | Phase 6 module audit `phase-6/40-module-audit.md` covers the 14 functional modules | phase-6/40-module-audit | M00217 | non-negotiable | false | 10 |
| R01938 | Phase 6 integration audit `phase-6/50-integration-audit.md` covers the 14 notifier integrations | phase-6/50-integration-audit | M00218 | non-negotiable | false | 10 |
| R01939 | Phase 6 docs audit `phase-6/60-docs-audit.md` covers SDDs + READMEs + CHANGELOG | phase-6/60-docs-audit | M00219 | non-negotiable | false | 10 |
| R01940 | Phase 6 tests audit `phase-6/70-tests-audit.md` covers L1-L5 harness | phase-6/70-tests-audit | M00220 | non-negotiable | false | 10 |
| R01941 | Phase 6 security audit `phase-6/80-security-audit.md` covers supply-chain + AppArmor + eBPF + threat-model | phase-6/80-security-audit | M00221 | non-negotiable | false | 10 |
| R01942 | Phase 6 security audit records supply-chain findings | phase-6/80-security-audit | F00979 | non-negotiable | false | 10 |
| R01943 | Phase 6 security audit records AppArmor profile findings | phase-6/80-security-audit | F00980 | non-negotiable | false | 10 |
| R01944 | Phase 6 security audit records eBPF / Tetragon TracingPolicy findings | phase-6/80-security-audit | F00981 | non-negotiable | false | 10 |
| R01945 | Phase 6 security audit records threat-model drift findings | phase-6/80-security-audit | F00982 | non-negotiable | false | 10 |
| R01946 | Phase 6 findings ledger `phase-6/99-findings-ledger.md` rolls up finding rows | phase-6/99-findings-ledger | M00222 | non-negotiable | false | 10 |
| R01947 | Phase 7 audit cycle exists at `docs/review/phase-7/` | `docs/review/phase-7/` | E0092 | non-negotiable | false | 10 |
| R01948 | Phase 7 charter `phase-7/00-charter.md` states Why-Phase-7-now | phase-7/00-charter | M00223 | non-negotiable | false | 10 |
| R01949 | Phase 7 charter states what changed during the post-Phase-6 cycle | phase-7/00-charter | M00223 | non-negotiable | false | 10 |
| R01950 | Phase 7 charter declares scope + methodology + predicted outcome | phase-7/00-charter | M00223 | non-negotiable | false | 10 |
| R01951 | Phase 7 charter declares status + naming | phase-7/00-charter | M00223 | non-negotiable | false | 10 |
| R01952 | Phase 7 inventory snapshot exists | phase-7/10-inventory | M00223 | non-negotiable | false | 10 |
| R01953 | Phase 7 recent-PRs audit exists | phase-7/20-recent-prs-audit | M00223 | non-negotiable | false | 10 |
| R01954 | Phase 7 crate audit exists | phase-7/30-crate-audit | M00223 | non-negotiable | false | 10 |
| R01955 | Phase 7 module audit exists | phase-7/40-module-audit | M00223 | non-negotiable | false | 10 |
| R01956 | Phase 7 integration audit exists | phase-7/50-integration-audit | M00223 | non-negotiable | false | 10 |
| R01957 | Phase 7 docs audit exists | phase-7/60-docs-audit | M00223 | non-negotiable | false | 10 |
| R01958 | Phase 7 tests audit exists | phase-7/70-tests-audit | M00223 | non-negotiable | false | 10 |
| R01959 | Phase 7 security audit exists | phase-7/80-security-audit | M00223 | non-negotiable | false | 10 |
| R01960 | Phase 7 findings ledger `phase-7/99-findings-ledger.md` rolls up Phase-7 findings | phase-7/99-findings-ledger | M00224 | non-negotiable | false | 10 |
| R01961 | Phase 7 follows the same 10-section structure as Phase 6 (parallel structure) | phase-7/ + phase-6/ | M00223 | non-negotiable | false | 10 |
| R01962 | Phase 8 audit cycle exists at `docs/review/phase-8/` as a deferral outcome | `docs/review/phase-8/` | E0093 | non-negotiable | false | 10 |
| R01963 | Phase 8 charter `phase-8/00-charter.md` declares deferral over thin compliance | phase-8/00-charter | M00225 | non-negotiable | false | 10 |
| R01964 | Phase 8 charter contains TL;DR section | phase-8/00-charter | F00997 | non-negotiable | false | 10 |
| R01965 | Phase 8 charter contains "Why deferral rather than a thin compliance audit" section | phase-8/00-charter | F00998 | non-negotiable | false | 10 |
| R01966 | Phase 8 charter records the cycle Phase 8 would have audited | phase-8/00-charter | M00225 | non-negotiable | false | 10 |
| R01967 | Phase 8 charter records sub-cycle 1 — PRs #156-#163 orient + resolve infrastructure | phase-8/00-charter | F00999 | non-negotiable | false | 10 |
| R01968 | Phase 8 charter records sub-cycle 2 — PRs #164-#169 cleanup decisions + doc-drift fixes | phase-8/00-charter | F01000 | non-negotiable | false | 10 |
| R01969 | Phase 8 charter records sub-cycle 3 — PRs #170-#171 write(1) integration + dashboard requirements | phase-8/00-charter | F01001 | non-negotiable | false | 10 |
| R01970 | Phase 8 charter records cross-repo scope | phase-8/00-charter | F01002 | non-negotiable | false | 10 |
| R01971 | Phase 8 charter records by-the-numbers section | phase-8/00-charter | F01003 | non-negotiable | false | 10 |
| R01972 | Phase 8 charter contains bias-analysis section | phase-8/00-charter | F01004 | non-negotiable | false | 10 |
| R01973 | Phase 8 charter declares trigger conditions for opening Phase 8 for real | phase-8/00-charter | M00226 | non-negotiable | false | 10 |
| R01974 | Phase 8 charter declares what Phase 9 (or next opened) inherits | phase-8/00-charter | F01006 | non-negotiable | false | 10 |
| R01975 | Phase 8 charter declares status | phase-8/00-charter | M00225 | non-negotiable | false | 10 |
| R01976 | Phase 8 charter declares cross-references | phase-8/00-charter | M00225 | non-negotiable | false | 10 |
| R01977 | Phase 8 findings ledger `phase-8/99-findings-ledger.md` records the deferral as a first-class finding | phase-8/99-findings-ledger | F01007 | non-negotiable | false | 10 |
| R01978 | Phase 8 deferral is doctrine — NOT a thin compliance audit | phase-8/00-charter | F01078 | non-negotiable | false | 10 |
| R01979 | SDD-019 cycle-3 forward-looking spec exists at `docs/sdd/019-cycle3-forward-looking-spec.md` | SDD-019 | E0094 | non-negotiable | false | 10 |
| R01980 | SDD-019 captures in-cycle tension closures from R43 SDD authoring → R48 | SDD-019 | F01014 | non-negotiable | false | 10 |
| R01981 | SDD-019 declares "Why this SDD exists" | SDD-019 | M00227 | non-negotiable | false | 10 |
| R01982 | SDD-019 records cycle-2 learnings (delivered surface section) | SDD-019 | F01018 | non-negotiable | false | 10 |
| R01983 | SDD-019 enumerates open design tensions T-1..T-6 | SDD-019 | M00227 | non-negotiable | false | 10 |
| R01984 | SDD-019 T-1 — gate predicate semantics ANY-vs-ALL | SDD-019 T-1 | F01008 | non-negotiable | true | 10 |
| R01985 | SDD-019 T-2 — operator override audit trail | SDD-019 T-2 | F01009 | non-negotiable | true | 10 |
| R01986 | SDD-019 T-3 — model registry artifact verification | SDD-019 T-3 | F01010 | non-negotiable | true | 10 |
| R01987 | SDD-019 T-4 — cross-repo schema drift detection | SDD-019 T-4 | F01011 | non-negotiable | true | 10 |
| R01988 | SDD-019 T-5 — recommendation matrix codified vs inlined | SDD-019 T-5 | F01012 | non-negotiable | true | 10 |
| R01989 | SDD-019 T-6 — schedule.json schema | SDD-019 T-6 | F01013 | non-negotiable | true | 10 |
| R01990 | SDD-019 enumerates open operator questions (cycle 3) | SDD-019 | F01019 | non-negotiable | false | 10 |
| R01991 | SDD-019 declares recommended cycle-3 priorities (operator-rankable) | SDD-019 | F01015 | non-negotiable | false | 10 |
| R01992 | SDD-019 declares non-goals for cycle 3 | SDD-019 | F01016 | non-negotiable | false | 10 |
| R01993 | SDD-019 declares how operators ratify | SDD-019 | F01017 | non-negotiable | false | 10 |
| R01994 | SDD-020 cycle-3 vectors exist at `docs/sdd/020-cycle3-vectors.md` | SDD-020 | E0095 | non-negotiable | false | 10 |
| R01995 | SDD-020 declares "Why this SDD exists" | SDD-020 | M00229 | non-negotiable | false | 10 |
| R01996 | SDD-020 records SDD-019 closing status | SDD-020 | F01030 | non-negotiable | false | 10 |
| R01997 | SDD-020 enumerates cycle-3 vectors V-1..V-7 (V-N NEW naming) | SDD-020 | F01031 | non-negotiable | false | 10 |
| R01998 | SDD-020 V-1 — per-module audit trail subjects beyond `--ignore-hardware` | SDD-020 V-1 | F01020 | non-negotiable | true | 10 |
| R01999 | SDD-020 V-2 — per-predicate Layer-B metrics | SDD-020 V-2 | F01021 | non-negotiable | true | 10 |
| R02000 | SDD-020 V-3 — operator-defined custom predicates | SDD-020 V-3 | F01022 | non-negotiable | true | 10 |
| R02001 | SDD-020 V-4 — per-module RBAC integration | SDD-020 V-4 | F01023 | non-negotiable | true | 10 |
| R02002 | SDD-020 V-5 — module manifest signing | SDD-020 V-5 | F01024 | non-negotiable | true | 10 |
| R02003 | SDD-020 V-6 — predictive thermal modelling | SDD-020 V-6 | F01025 | non-negotiable | true | 10 |
| R02004 | SDD-020 V-7 — mid-cycle emergence: hardware-exploitation rollup | SDD-020 V-7 | F01026 | non-negotiable | true | 10 |
| R02005 | SDD-020 records cycle-3 priority ranking | SDD-020 | F01027 | non-negotiable | false | 10 |
| R02006 | SDD-020 declares non-goals for cycle 3 | SDD-020 | F01028 | non-negotiable | false | 10 |
| R02007 | SDD-020 declares how operators ratify | SDD-020 | F01029 | non-negotiable | false | 10 |
| R02008 | SDD-021 cycle-4 vectors exist at `docs/sdd/021-cycle4-vectors.md` | SDD-021 | E0096 | non-negotiable | false | 10 |
| R02009 | SDD-021 declares "Why this SDD exists" | SDD-021 | M00230 | non-negotiable | false | 10 |
| R02010 | SDD-021 records doctrine layer state | SDD-021 | F01041 | non-negotiable | false | 10 |
| R02011 | SDD-021 records SDD-020 carry-over to cycle 4 | SDD-021 | F01042 | non-negotiable | false | 10 |
| R02012 | SDD-021 enumerates cycle-4 vectors W-1..W-6 (W-N NEW naming) | SDD-021 | F01043 | non-negotiable | false | 10 |
| R02013 | SDD-021 W-1 — tensor-parallel slice-plan schema doc | SDD-021 W-1 | F01032 | non-negotiable | true | 10 |
| R02014 | SDD-021 W-2 — module signing key rotation | SDD-021 W-2 | F01033 | non-negotiable | true | 10 |
| R02015 | SDD-021 W-3 — cross-host fleet aggregation API | SDD-021 W-3 | F01034 | non-negotiable | true | 10 |
| R02016 | SDD-021 W-4 — selfdef integration test against a real BitNet runtime | SDD-021 W-4 | F01035 | non-negotiable | true | 10 |
| R02017 | SDD-021 W-5 — module manifest sigstore / cosign alternative | SDD-021 W-5 | F01036 | non-negotiable | true | 10 |
| R02018 | SDD-021 W-6 — per-module resource quotas | SDD-021 W-6 | F01037 | non-negotiable | true | 10 |
| R02019 | SDD-021 records cycle-4 priority ranking | SDD-021 | F01038 | non-negotiable | false | 10 |
| R02020 | SDD-021 declares non-goals for cycle 4 | SDD-021 | F01039 | non-negotiable | false | 10 |
| R02021 | SDD-021 declares how operators ratify | SDD-021 | F01040 | non-negotiable | false | 10 |
| R02022 | SDD-024 cycle-5 vectors exist at `docs/sdd/024-cycle5-vectors.md` | SDD-024 | E0097 | non-negotiable | false | 10 |
| R02023 | SDD-024 declares "Why this SDD exists" | SDD-024 | M00231 | non-negotiable | false | 10 |
| R02024 | SDD-024 records cycle-3 + cycle-4 closing status | SDD-024 | F01053 | non-negotiable | false | 10 |
| R02025 | SDD-024 enumerates cycle-5 design tensions X-1..X-6 (X-N NEW naming) | SDD-024 | F01055 | non-negotiable | false | 10 |
| R02026 | SDD-024 X-1 — composable predicates (AND/OR combinators) | SDD-024 X-1 | F01044 | non-negotiable | true | 10 |
| R02027 | SDD-024 X-2 — cross-module dependency negotiation (`depends_optional`) | SDD-024 X-2 | F01045 | non-negotiable | true | 10 |
| R02028 | SDD-024 X-3 — per-module preflight `simulate` mode | SDD-024 X-3 | F01046 | non-negotiable | true | 10 |
| R02029 | SDD-024 X-4 — real LoRA-adapter lifecycle on the registry | SDD-024 X-4 | F01047 | non-negotiable | true | 10 |
| R02030 | SDD-024 X-5 — apply-time hardware re-probe (`--reprobe-hardware`) | SDD-024 X-5 | F01048 | non-negotiable | true | 10 |
| R02031 | SDD-024 X-6 — module-class taxonomy (parallel to R212 model class) | SDD-024 X-6 | F01049 | non-negotiable | true | 10 |
| R02032 | SDD-024 records cycle-5 priority ranking | SDD-024 | F01050 | non-negotiable | false | 10 |
| R02033 | SDD-024 declares non-goals for cycle 5 | SDD-024 | F01051 | non-negotiable | false | 10 |
| R02034 | SDD-024 declares how operators ratify | SDD-024 | F01052 | non-negotiable | false | 10 |
| R02035 | SDD-024 declares cross-references | SDD-024 | F01054 | non-negotiable | false | 10 |
| R02036 | SDD-025 cycle-6 vectors exist at `docs/sdd/025-cycle6-vectors.md` | SDD-025 | E0098 | non-negotiable | false | 10 |
| R02037 | SDD-025 declares "Why this SDD exists" | SDD-025 | M00232 | non-negotiable | false | 10 |
| R02038 | SDD-025 records cycle-5 closing status | SDD-025 | F01065 | non-negotiable | false | 10 |
| R02039 | SDD-025 enumerates cycle-6 design tensions Y-1..Y-6 (Y-N NEW naming) | SDD-025 | F01067 | non-negotiable | false | 10 |
| R02040 | SDD-025 Y-1 — `any_of` Layer-B observability | SDD-025 Y-1 | F01056 | non-negotiable | true | 10 |
| R02041 | SDD-025 Y-2 — LoRA registry state file format | SDD-025 Y-2 | F01057 | non-negotiable | true | 10 |
| R02042 | SDD-025 Y-3 — `models suggest` cross-repo bridge | SDD-025 Y-3 | F01058 | non-negotiable | true | 10 |
| R02043 | SDD-025 Y-4 — `modules show-effective` after any_of evaluation | SDD-025 Y-4 | F01059 | non-negotiable | true | 10 |
| R02044 | SDD-025 Y-5 — `--reprobe-hardware` actually does something | SDD-025 Y-5 | F01060 | non-negotiable | true | 10 |
| R02045 | SDD-025 Y-6 — module `[whitelabel]` block | SDD-025 Y-6 | F01061 | non-negotiable | true | 10 |
| R02046 | SDD-025 records cycle-6 priority ranking | SDD-025 | F01062 | non-negotiable | false | 10 |
| R02047 | SDD-025 declares non-goals for cycle 6 | SDD-025 | F01063 | non-negotiable | false | 10 |
| R02048 | SDD-025 declares how operators ratify | SDD-025 | F01064 | non-negotiable | false | 10 |
| R02049 | SDD-025 declares cross-references | SDD-025 | F01066 | non-negotiable | false | 10 |
| R02050 | Findings-ledger continuity — top-level `docs/review/99-findings-ledger.md` rolls up per-phase | `docs/review/99-findings-ledger.md` | F01068 | non-negotiable | false | 10 |
| R02051 | Findings-ledger continuity — each phase owns its own 99-findings-ledger file | per-phase 99 files | F01069 | non-negotiable | false | 10 |
| R02052 | Findings-ledger is operator-readable single-source-of-truth per phase | per-phase 99 + top-level 99 | F01077 | non-negotiable | false | 10 |
| R02053 | Audit-cycle doctrine — every cycle closes with the 10 sections (00 charter / 10 inventory / 20 recent-PRs / 30 crate / 40 module / 50 integration / 60 docs / 70 tests / 80 security / 99 findings) | phase-6 + phase-7 structure | M00238 | non-negotiable | false | 10 |
| R02054 | Audit-cycle doctrine — every closing SDD opens the next cycle's forward-looking SDD | SDD-019→020→021→024→025 | F01070 | non-negotiable | false | 10 |
| R02055 | Audit-cycle doctrine — cycle ratification = operator answers open questions + CHANGELOG close entry | SDD-019/020/021/024/025 ratify sections | F01074 | non-negotiable | false | 10 |
| R02056 | Audit-cycle doctrine — audit cycles are doctrine-only (no implementation effort) | charter out-of-scope sections | F01075 | non-negotiable | false | 10 |
| R02057 | Audit-cycle doctrine — implementation effort happens under successor SDD-NNN | charter out-of-scope sections | F01075 | non-negotiable | false | 10 |
| R02058 | Audit-cycle doctrine — only the operator ratifies a cycle close; AI sessions propose findings, never close | charter ratify sections | F01080 | non-negotiable | false | 10 |
| R02059 | Audit charter naming convention — `Phase N` numbering (N is integer) | charter naming sections | F01071 | non-negotiable | false | 10 |
| R02060 | Audit section naming — section number prefixes 00 / 10 / 20 / 30 / 40 / 50 / 60 / 70 / 80 / 99 | charter naming sections | F01071 | non-negotiable | false | 10 |
| R02061 | `docs/review/` layout — top-level audit files + per-phase subdirectories | `docs/review/` tree | F01072 | non-negotiable | false | 10 |
| R02062 | `docs/review/phase-N/` subdirectory — same 10 sections, phase-scoped | phase-6 / phase-7 layout | F01073 | non-negotiable | false | 10 |
| R02063 | Phase-8 deferral is a first-class outcome (NOT a thin compliance audit) | phase-8/00-charter | F01078 | non-negotiable | false | 10 |
| R02064 | Phase-8 deferral charter records bias analysis (why deferral is bias-resistant) | phase-8/00-charter | F01004 | non-negotiable | false | 10 |
| R02065 | Phase-8 deferral records trigger conditions for opening Phase 8 for real | phase-8/00-charter | M00226 | non-negotiable | false | 10 |
| R02066 | Phase-8 deferral records what the next opened phase inherits | phase-8/00-charter | F01006 | non-negotiable | false | 10 |
| R02067 | Top-level audit files exist: `00-charter.md` | `docs/review/00-charter.md` | F01072 | non-negotiable | false | 10 |
| R02068 | Top-level audit files exist: `10-inventory.md` | `docs/review/10-inventory.md` | F01072 | non-negotiable | false | 10 |
| R02069 | Top-level audit files exist: `20-crate-audit.md` | `docs/review/20-crate-audit.md` | F01072 | non-negotiable | false | 10 |
| R02070 | Top-level audit files exist: `30-module-audit.md` | `docs/review/30-module-audit.md` | F01072 | non-negotiable | false | 10 |
| R02071 | Top-level audit files exist: `40-integration-audit.md` | `docs/review/40-integration-audit.md` | F01072 | non-negotiable | false | 10 |
| R02072 | Top-level audit files exist: `50-docs-audit.md` | `docs/review/50-docs-audit.md` | F01072 | non-negotiable | false | 10 |
| R02073 | Top-level audit files exist: `60-tests-audit.md` | `docs/review/60-tests-audit.md` | F01072 | non-negotiable | false | 10 |
| R02074 | Top-level audit files exist: `70-recent-prs-audit.md` | `docs/review/70-recent-prs-audit.md` | F01072 | non-negotiable | false | 10 |
| R02075 | Top-level audit files exist: `80-security-audit.md` | `docs/review/80-security-audit.md` | F01072 | non-negotiable | false | 10 |
| R02076 | Top-level audit files exist: `99-findings-ledger.md` | `docs/review/99-findings-ledger.md` | F01072 | non-negotiable | false | 10 |
| R02077 | Audit cycles preserve cross-repo binding doctrine (SDD-038) | MS007 + SDD-038 | F01079 | non-negotiable | false | 10 |
| R02078 | Audit cycles do NOT invent typed-mirror crates; they only mirror existing 8/8 SATURATED set | MS007 + SDD-038 | F01079 | non-negotiable | false | 10 |
| R02079 | SDD-019 connects forward — its R43→R48 in-cycle closures feed SDD-020 | SDD-019→020 | F01070 | non-negotiable | false | 10 |
| R02080 | SDD-020 connects forward — its V-7 mid-cycle emergence feeds SDD-021 (carry-over) | SDD-020→021 | F01042 | non-negotiable | false | 10 |
| R02081 | SDD-021 connects forward — its W-1..W-6 status feeds SDD-024 cycle-5 carry-over | SDD-021→024 | F01053 | non-negotiable | false | 10 |
| R02082 | SDD-024 connects forward — its X-1..X-6 status feeds SDD-025 cycle-6 carry-over | SDD-024→025 | F01065 | non-negotiable | false | 10 |
| R02083 | SDD-025 connects forward — cross-references section names next vectors SDD | SDD-025 | F01066 | non-negotiable | false | 10 |
| R02084 | Audit cycle has predicted-outcome section in each charter | phase-6/-7 charter | M00213 | non-negotiable | false | 10 |
| R02085 | Audit cycle has status section in each charter (in-progress / closed / deferred) | phase-6/-7/-8 charter | M00213 | non-negotiable | false | 10 |
| R02086 | Audit cycle has cross-references section in each charter | phase-6/-7/-8 charter | M00213 | non-negotiable | false | 10 |
| R02087 | Audit cycle methodology section names the audit verbs (read / grep / cargo metadata / cross-ref) | phase-6/-7 charter methodology | M00213 | non-negotiable | false | 10 |
| R02088 | Audit cycle methodology requires audit findings to cite repo file paths verbatim (no invention) | phase-6/-7 charter methodology | M00213 | non-negotiable | false | 10 |
| R02089 | Audit cycle methodology forbids deletion of prior audit findings (additive only) | charter doctrine | M00213 | non-negotiable | false | 10 |
| R02090 | Findings-ledger row schema — finding ID + phase + section + severity + status + cross-ref | per-phase 99 + top-level 99 | F01068 | non-negotiable | false | 10 |
| R02091 | Findings-ledger severity scale — observation / suggestion / risk / blocker | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02092 | Findings-ledger status — open / closed / deferred / superseded | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02093 | Findings-ledger close mechanism — closing entry references the SDD or PR that closes | per-phase 99 | F01074 | non-negotiable | false | 10 |
| R02094 | Findings-ledger superseded mechanism — superseded entry references the new finding ID | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02095 | Findings-ledger deferral mechanism — deferred entry names the phase it defers to | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02096 | Phase-6 covered the SDD-008 cycle (operator-pull dashboard + notifications orchestration cycle) | phase-6/00-charter what-changed | F00962 | non-negotiable | false | 10 |
| R02097 | Phase-7 covered the post-Phase-6 cycle (hardware-aware modules / cycle-3 forward-looking close) | phase-7/00-charter what-changed | F00985 | non-negotiable | false | 10 |
| R02098 | Phase-8 deferral protects against thin-compliance bias (charter bias analysis) | phase-8/00-charter | F01004 | non-negotiable | false | 10 |
| R02099 | Audit cycle scope explicitly excludes implementation patches (charter out-of-scope) | charter out-of-scope | F01075 | non-negotiable | false | 10 |
| R02100 | Audit cycle out-of-scope items are deferred to a named next phase | charter out-of-scope | F01075 | non-negotiable | false | 10 |
| R02101 | SDD-020 mid-cycle V-7 emergence is documented as `(post-hoc)` to flag retroactive | SDD-020 V-7 | F01026 | non-negotiable | false | 10 |
| R02102 | SDD-019 in-cycle closures section names exact R-IDs (R43→R48) | SDD-019 | F01014 | non-negotiable | false | 10 |
| R02103 | Each cycle vectors SDD names the cycle integer in title and prefix letter (V=3 / W=4 / X=5 / Y=6) | SDD-020/021/024/025 | F01031 | non-negotiable | false | 10 |
| R02104 | Each cycle vectors SDD has a `## How operators ratify` section | SDD-019/020/021/024/025 | F01074 | non-negotiable | false | 10 |
| R02105 | Each cycle vectors SDD has a `## Non-goals` section | SDD-019/020/021/024/025 | M00229 | non-negotiable | false | 10 |
| R02106 | Each cycle vectors SDD has a `## Priority ranking` section | SDD-020/021/024/025 | M00229 | non-negotiable | false | 10 |
| R02107 | Audit cycle naming uses zero-padded section numbers (00 / 10 / 20 / 30 / 40 / 50 / 60 / 70 / 80 / 99) | charter naming | F01071 | non-negotiable | false | 10 |
| R02108 | Audit cycle file extensions are `.md` only | `docs/review/` tree | F01072 | non-negotiable | false | 10 |
| R02109 | Audit cycle subdirectories are `phase-N/` lowercase-hyphen-integer | `docs/review/phase-6/`, `docs/review/phase-7/`, `docs/review/phase-8/` | F01073 | non-negotiable | false | 10 |
| R02110 | Phase 6 has all 10 section files | phase-6/ | M00213 | non-negotiable | false | 10 |
| R02111 | Phase 7 has all 10 section files | phase-7/ | M00223 | non-negotiable | false | 10 |
| R02112 | Phase 8 has only charter + findings (deferral outcome) | phase-8/ | M00225 | non-negotiable | false | 10 |
| R02113 | SDD-019 cross-references row points to SDD-020 (next cycle vectors) | SDD-019 cross-refs | F01017 | non-negotiable | false | 10 |
| R02114 | SDD-020 cross-references row points to SDD-021 (next cycle vectors) | SDD-020 cross-refs | F01029 | non-negotiable | false | 10 |
| R02115 | SDD-021 cross-references row points to SDD-024 (next cycle vectors) | SDD-021 cross-refs | F01040 | non-negotiable | false | 10 |
| R02116 | SDD-024 cross-references row points to SDD-025 (next cycle vectors) | SDD-024 cross-refs | F01054 | non-negotiable | false | 10 |
| R02117 | SDD-025 cross-references row points to next cycle vectors SDD | SDD-025 cross-refs | F01066 | non-negotiable | false | 10 |
| R02118 | Audit cycle covers crates (47 total) — crate audit row per crate | phase-6/30-crate + phase-7/30-crate | M00216 | non-negotiable | false | 10 |
| R02119 | Audit cycle covers modules (14 total) — module audit row per module | phase-6/40-module + phase-7/40-module | M00217 | non-negotiable | false | 10 |
| R02120 | Audit cycle covers integrations (14 total) — integration audit row per integration | phase-6/50-integration + phase-7/50-integration | M00218 | non-negotiable | false | 10 |
| R02121 | Audit cycle covers SDDs (27+ total) — docs audit row per SDD | phase-6/60-docs + phase-7/60-docs | M00219 | non-negotiable | false | 10 |
| R02122 | Audit cycle covers L1-L5 test harness — tests audit per layer | phase-6/70-tests + phase-7/70-tests | M00220 | non-negotiable | false | 10 |
| R02123 | Audit cycle security audit covers supply-chain (cargo-audit + cargo-deny + cargo-vet) | phase-6/80-security + phase-7/80-security | F00979 | non-negotiable | false | 10 |
| R02124 | Audit cycle security audit covers AppArmor profiles per crate/module | phase-6/80-security + phase-7/80-security | F00980 | non-negotiable | false | 10 |
| R02125 | Audit cycle security audit covers eBPF + Tetragon TracingPolicy drift | phase-6/80-security + phase-7/80-security | F00981 | non-negotiable | false | 10 |
| R02126 | Audit cycle security audit covers threat-model (SDD-004) drift | phase-6/80-security + phase-7/80-security | F00982 | non-negotiable | false | 10 |
| R02127 | Audit cycle recent-PRs section covers all PRs in the closing cycle window | phase-6/20-recent-prs + phase-7/20-recent-prs | M00215 | non-negotiable | false | 10 |
| R02128 | Audit cycle inventory section captures crate/module/SDD/dashboard/packaging snapshot | phase-6/10-inventory + phase-7/10-inventory | M00214 | non-negotiable | false | 10 |
| R02129 | Audit cycle docs audit identifies README / CHANGELOG drift findings | phase-6/60-docs + phase-7/60-docs | M00219 | non-negotiable | false | 10 |
| R02130 | Audit cycle docs audit identifies SDD cross-reference drift | phase-6/60-docs + phase-7/60-docs | M00219 | non-negotiable | false | 10 |
| R02131 | Project boundary — audit cycles audit selfdef-scope only (NEVER sovereign-os runtime crates) | architecture | F01079 | non-negotiable | false | 10 |
| R02132 | Project boundary — cross-repo audit findings cite typed-mirror crate (MS007) only | MS007 + SDD-038 | F01079 | non-negotiable | false | 10 |
| R02133 | Project boundary — Oracle-Triage (MS004 E0036) findings flow via the only runtime cross-repo bridge | MS004 E0036 + SDD-038 | F01079 | non-negotiable | false | 10 |
| R02134 | SDD-019 declares cycle-2 learnings as "delivered surface" (closes the prior cycle) | SDD-019 | F01018 | non-negotiable | false | 10 |
| R02135 | SDD-019 records open operator questions distinct from open design tensions | SDD-019 | F01019 | non-negotiable | false | 10 |
| R02136 | SDD-020 records "SDD-019 closing status" before opening V-N vectors | SDD-020 | F01030 | non-negotiable | false | 10 |
| R02137 | SDD-021 records "SDD-020 carry-over to cycle 4" as W-N inputs | SDD-021 | F01042 | non-negotiable | false | 10 |
| R02138 | SDD-024 records "cycle-3 + cycle-4 closing status" before opening X-N vectors | SDD-024 | F01053 | non-negotiable | false | 10 |
| R02139 | SDD-025 records "cycle-5 closing status" before opening Y-N vectors | SDD-025 | F01065 | non-negotiable | false | 10 |
| R02140 | SDD-021 records "doctrine layer state" (gate predicates / module manifest / hardware probe / model registry) | SDD-021 | F01041 | non-negotiable | false | 10 |
| R02141 | Findings-ledger entries are append-only (no destructive edits) | per-phase 99 | F01077 | non-negotiable | false | 10 |
| R02142 | Findings-ledger entries are dated (ISO-8601) | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02143 | Findings-ledger entries reference exact file paths and line ranges | per-phase 99 | F01068 | non-negotiable | false | 10 |
| R02144 | Audit cycle close note appears in CHANGELOG.md naming the closing SDD | SDD-019/020/021/024/025 ratify + CHANGELOG | F01074 | non-negotiable | false | 10 |
| R02145 | Audit cycle close note names the opening SDD of the next cycle | SDD-019→020 / SDD-020→021 / SDD-021→024 / SDD-024→025 | F01070 | non-negotiable | false | 10 |
| R02146 | SDD-024 X-1 composable predicates AND-combinator semantics | SDD-024 X-1 | F01044 | non-negotiable | true | 10 |
| R02147 | SDD-024 X-1 composable predicates OR-combinator semantics | SDD-024 X-1 | F01044 | non-negotiable | true | 10 |
| R02148 | SDD-024 X-2 `depends_optional` semantics (optional cross-module dependency) | SDD-024 X-2 | F01045 | non-negotiable | true | 10 |
| R02149 | SDD-024 X-3 `simulate` mode = preflight-only (no side effects) | SDD-024 X-3 | F01046 | non-negotiable | true | 10 |
| R02150 | SDD-024 X-4 LoRA lifecycle — register / load / unload / verify | SDD-024 X-4 | F01047 | non-negotiable | true | 10 |
| R02151 | SDD-024 X-5 `--reprobe-hardware` apply-time invariant verification | SDD-024 X-5 | F01048 | non-negotiable | true | 10 |
| R02152 | SDD-024 X-6 module-class taxonomy parallels R212 model class | SDD-024 X-6 | F01049 | non-negotiable | true | 10 |
| R02153 | SDD-025 Y-1 `any_of` Layer-B observability surfaces predicate-branch evaluation | SDD-025 Y-1 | F01056 | non-negotiable | true | 10 |
| R02154 | SDD-025 Y-2 LoRA registry state file format is operator-readable | SDD-025 Y-2 | F01057 | non-negotiable | true | 10 |
| R02155 | SDD-025 Y-3 `models suggest` cross-repo bridge consumes typed-mirror crate (MS007) | SDD-025 Y-3 + MS007 | F01058 | non-negotiable | true | 10 |
| R02156 | SDD-025 Y-4 `modules show-effective` operator-readable evaluated state | SDD-025 Y-4 | F01059 | non-negotiable | true | 10 |
| R02157 | SDD-025 Y-5 `--reprobe-hardware` action — re-runs hardware probe + re-evaluates gates | SDD-025 Y-5 | F01060 | non-negotiable | true | 10 |
| R02158 | SDD-025 Y-6 module `[whitelabel]` block — operator-rebrandable module surface | SDD-025 Y-6 | F01061 | non-negotiable | true | 10 |
| R02159 | Audit-cycle catalog row count — Phase 6 + Phase 7 + Phase 8 + 5 cycle-vector SDDs = 8 docs sets | this milestone | E0100 | non-negotiable | false | 10 |
| R02160 | Audit-cycle authority — only the operator closes a cycle (AI sessions enumerate findings; operator ratifies) | charter ratify sections | F01080 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS008: 1920 + 2400 = 4320 sub-requirements when MS009 lands

## Cross-references

- Sister milestones: MS001 daemon core / MS002 collector fabric / MS003 correlator+store+responder+signing / MS004 14 integrations / MS005 notifier engine+orchestrator / MS006 14 functional modules / MS007 8/8 typed mirrors / MS008 selfdef-on-SAIN-01
- Sister sovereign-os audit cycles: `~/sovereign-os/docs/review/` (separate phase numbering)
- Cross-repo binding doctrine: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md`
- Selfdef CHANGELOG audit-close entries: `CHANGELOG.md`
