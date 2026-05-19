# MS013 — 27-SDD charter framework

> Parent: `backlog/milestones/INDEX.md` row MS013.
> Source: `docs/sdd/000-charter.md` (115 lines; "living document, owner = audit team; refers to Phase 1 findings ledger at `docs/review/99-findings-ledger.md`"; 9-point SDD spec; numbering convention 3-digit zero-padded no gaps no recycle; 5-state Status field draft/review/accepted/implemented/abandoned; linkage to findings ledger F-2026-NNN; canonical template 13-section skeleton; 4 anti-patterns SDD avoids; style rules). Charter applies to all 27 SDDs `docs/sdd/000-charter.md` through `docs/sdd/026-operator-dashboard-and-flex-profile.md`. All entries below extract verbatim. No invention.

## Epics (E0131–E0140)

| Epic ID | Phrase | Source |
|---|---|---|
| E0131 | SDD definition (9-point spec) — short self-contained markdown file that (1) Names the problem one-paragraph plain language / (2) Cites Phase 1 findings F-2026-NNN ids it closes / (3) Defines explicit goals and non-goals / (4) Surveys ≥2 alternative designs honestly / (5) Recommends one design + explains why / (6) Specifies enough detail (interfaces / data shapes / file paths) that implementation PR can be reviewed without re-arguing architecture / (7) Lists test requirements implementation must satisfy / (8) Calls out rollout / migration story if any / (9) Closes with open questions author hasn't decided. SDD is NOT the implementation; implementation PR cites SDD by id + links in PR body + references inline in non-obvious comments | SDD-000 § "What an SDD is, here" |
| E0132 | Numbering convention — three-digit zero-padded (`001`, `002`, … `099`); no gaps for politeness; if SDD abandoned, file stays with status=abandoned + note explaining why; number is NOT recycled | SDD-000 § Numbering |
| E0133 | Status field — every SDD opens with `Status: <draft\|review\|accepted\|implemented\|abandoned>` + `Owner` + `Last updated` + `Closes findings`; 5-state lifecycle (draft author still writing / review author wants feedback not yet contract / accepted operating team agreed contract / implemented landed in main historical record / abandoned superseded or no longer relevant); only `accepted` SDDs are contracts | SDD-000 § Status field |
| E0134 | Linkage to findings ledger — every SDD section "Problem" cites F-2026-NNN ids it closes; when SDD reaches `implemented`, ledger back-references SDD id + PR that landed it; closes the Phase 1 surface-area-discovery loop | SDD-000 § Linkage to the findings ledger |
| E0135 | Canonical template (13-section skeleton) — # SDD-NNN — `<title>` header + Status frontmatter + Problem / Goals / Non-goals / Glossary / Current state / Design alternatives considered (Alternative A / B / C) / Recommended design / Detailed design / Test plan / Rollout / migration / Open questions / Appendix | SDD-000 § Template |
| E0136 | Style + anti-patterns — 4 things SDD avoids (vendor advocacy / code listings longer than a function / speculation past immediate horizon / anything that should be a code comment) + style rules (tight paragraphs / file:line citations / no emojis / no decorative dividers / no marketing language / every claim cites code or is labelled open question) | SDD-000 § "What an SDD avoids" + § Style |
| E0137 | Foundational SDD layer (000–009) — 000 charter / 001 ai-machine-end-to-end / 002 defaults-that-work / 003 vpn-bridge-multi-instance / 004 security-threat-model / 005 test-contract / 006 shared-module-script-lib / 007 per-token-sse-subscriber-quota / 008 notifications-orchestration / 009 dashboard | `docs/sdd/000..009.md` |
| E0138 | SAIN-01 integration SDD layer (010–017) — 010 selfdef-on-sain01 / 011 sovereign-os-arc-opening / 012 selfdef-on-sain01-integration-design / 013 deployment-target-config / 014 shared-audit-summary-channel / 015 perimeter-coexistence / 016 oracle-triage-channel / 017 sain01-hardware-inventory | `docs/sdd/010..017.md` |
| E0139 | Hardware exploit + cross-repo doctrine SDD layer (018–023) — 018 hardware-aware-modules-and-tune-surface / 019 cycle3-forward-looking-spec / 020 cycle3-vectors / 021 cycle4-vectors / 022 hardware-exploit-doctrine / 023 cross-repo-model-taxonomy-mirror | `docs/sdd/018..023.md` |
| E0140 | Cycle vectors + dashboard SDD layer (024–026) — 024 cycle5-vectors / 025 cycle6-vectors / 026 operator-dashboard-and-flex-profile | `docs/sdd/024..026.md` |

## Modules (M00317–M00342)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00317 | SDD spec point 1 — names the problem (one paragraph, plain language) | SDD-000 § "What an SDD is, here" 1 | E0131 |
| M00318 | SDD spec point 2 — cites Phase 1 findings it closes (F-2026-NNN ids) | SDD-000 § "What an SDD is, here" 2 | E0131 |
| M00319 | SDD spec point 3 — defines explicit goals and non-goals | SDD-000 § "What an SDD is, here" 3 | E0131 |
| M00320 | SDD spec point 4 — surveys ≥2 alternative designs honestly | SDD-000 § "What an SDD is, here" 4 | E0131 |
| M00321 | SDD spec point 5 — recommends one design + explains why | SDD-000 § "What an SDD is, here" 5 | E0131 |
| M00322 | SDD spec point 6 — specifies enough detail (interfaces / data shapes / file paths) for impl-PR review without re-arguing architecture | SDD-000 § "What an SDD is, here" 6 | E0131 |
| M00323 | SDD spec point 7 — lists test requirements implementation must satisfy | SDD-000 § "What an SDD is, here" 7 | E0131 |
| M00324 | SDD spec point 8 — calls out rollout / migration story if any | SDD-000 § "What an SDD is, here" 8 | E0131 |
| M00325 | SDD spec point 9 — closes with open questions author hasn't decided | SDD-000 § "What an SDD is, here" 9 | E0131 |
| M00326 | SDD-000 charter (this document; living; owner = audit team; refers to docs/review/99-findings-ledger.md) | `docs/sdd/000-charter.md` | E0137 |
| M00327 | SDD-001 ai-machine-end-to-end (canonical template reference) | `docs/sdd/001-ai-machine-end-to-end.md` | E0137 |
| M00328 | SDD-002 defaults-that-work | `docs/sdd/002-defaults-that-work.md` | E0137 |
| M00329 | SDD-003 vpn-bridge-multi-instance | `docs/sdd/003-vpn-bridge-multi-instance.md` | E0137 |
| M00330 | SDD-004 security-threat-model | `docs/sdd/004-security-threat-model.md` | E0137 |
| M00331 | SDD-005 test-contract (L1–L5 layered harness) | `docs/sdd/005-test-contract.md` | E0137 |
| M00332 | SDD-006 shared-module-script-lib | `docs/sdd/006-shared-module-script-lib.md` | E0137 |
| M00333 | SDD-007 per-token-sse-subscriber-quota | `docs/sdd/007-per-token-sse-subscriber-quota.md` | E0137 |
| M00334 | SDD-008 notifications-orchestration | `docs/sdd/008-notifications-orchestration.md` | E0137 |
| M00335 | SDD-009 dashboard | `docs/sdd/009-dashboard.md` | E0137 |
| M00336 | SDD-010 selfdef-on-sain01 (scoping stub for SAIN-01 deployment integration) | `docs/sdd/010-selfdef-on-sain01.md` | E0138 |
| M00337 | SDD-011 sovereign-os-arc-opening + SDD-012 selfdef-on-sain01-integration-design + SDD-013 deployment-target-config + SDD-014 shared-audit-summary-channel | `docs/sdd/011..014.md` | E0138 |
| M00338 | SDD-015 perimeter-coexistence + SDD-016 oracle-triage-channel + SDD-017 sain01-hardware-inventory | `docs/sdd/015..017.md` | E0138 |
| M00339 | SDD-018 hardware-aware-modules-and-tune-surface + SDD-022 hardware-exploit-doctrine + SDD-023 cross-repo-model-taxonomy-mirror | `docs/sdd/018,022,023.md` | E0139 |
| M00340 | SDD-019 cycle3-forward-looking-spec + SDD-020 cycle3-vectors + SDD-021 cycle4-vectors + SDD-024 cycle5-vectors + SDD-025 cycle6-vectors (cycle ladder) | `docs/sdd/019,020,021,024,025.md` | E0139 + E0140 |
| M00341 | SDD-026 operator-dashboard-and-flex-profile (Z-N vector grid; Stage-7+) | `docs/sdd/026-operator-dashboard-and-flex-profile.md` | E0140 |
| M00342 | Canonical template skeleton (13 sections) + style rules (6 directives) + 4 anti-patterns | SDD-000 § Template + Style + "What an SDD avoids" | E0135 + E0136 |

## Features (F01441–F01560)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F01441 | SDD charter is a living document | SDD-000 § header | M00326 | composite | false |
| F01442 | SDD charter owner = audit team | SDD-000 § header | M00326 | composite | false |
| F01443 | SDD charter refers to Phase 1 findings ledger at `docs/review/99-findings-ledger.md` | SDD-000 § header | M00326 | composite | false |
| F01444 | SDD definition — short, self-contained markdown file | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01445 | SDD spec 1 — Names the problem (one paragraph, plain language) | SDD-000 § "What an SDD is, here" 1 | M00317 | composite | false |
| F01446 | SDD spec 2 — Cites Phase 1 findings it closes (F-2026-NNN ids) | SDD-000 § "What an SDD is, here" 2 | M00318 | composite | false |
| F01447 | SDD spec 3 — Defines explicit goals and non-goals | SDD-000 § "What an SDD is, here" 3 | M00319 | composite | false |
| F01448 | SDD spec 4 — Surveys ≥2 alternative designs honestly | SDD-000 § "What an SDD is, here" 4 | M00320 | composite | false |
| F01449 | SDD spec 5 — Recommends one design + explains why | SDD-000 § "What an SDD is, here" 5 | M00321 | composite | false |
| F01450 | SDD spec 6 — Specifies enough detail (interfaces / data shapes / file paths) | SDD-000 § "What an SDD is, here" 6 | M00322 | composite | false |
| F01451 | SDD spec 6 detail allows impl PR review without re-arguing the architecture | SDD-000 § "What an SDD is, here" 6 | M00322 | composite | false |
| F01452 | SDD spec 7 — Lists test requirements the implementation must satisfy | SDD-000 § "What an SDD is, here" 7 | M00323 | composite | false |
| F01453 | SDD spec 8 — Calls out the rollout / migration story if any | SDD-000 § "What an SDD is, here" 8 | M00324 | composite | false |
| F01454 | SDD spec 9 — Closes with open questions the author hasn't decided | SDD-000 § "What an SDD is, here" 9 | M00325 | composite | false |
| F01455 | An SDD is NOT the implementation | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01456 | Implementation PR cites the SDD by id | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01457 | Implementation PR links to SDD from the PR body | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01458 | Implementation PR references SDD inline in any non-obvious code comment | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01459 | Numbering — three-digit zero-padded | SDD-000 § Numbering | E0132 | composite | false |
| F01460 | Numbering — `001` minimum | SDD-000 § Numbering | E0132 | composite | false |
| F01461 | Numbering — `099` maximum (current series) | SDD-000 § Numbering | E0132 | composite | false |
| F01462 | Numbering — no gaps for politeness | SDD-000 § Numbering | E0132 | composite | false |
| F01463 | Numbering — abandoned SDD file stays with status=abandoned | SDD-000 § Numbering | E0132 | composite | false |
| F01464 | Numbering — abandoned SDD includes note explaining why | SDD-000 § Numbering | E0132 | composite | false |
| F01465 | Numbering — abandoned number is NOT recycled | SDD-000 § Numbering | E0132 | composite | false |
| F01466 | Status frontmatter — Status field | SDD-000 § Status field | E0133 | composite | false |
| F01467 | Status frontmatter — Owner field | SDD-000 § Status field | E0133 | composite | false |
| F01468 | Status frontmatter — Last updated field (YYYY-MM-DD) | SDD-000 § Status field | E0133 | composite | false |
| F01469 | Status frontmatter — Closes findings field (F-2026-NNN, F-2026-MMM, ...) | SDD-000 § Status field | E0133 | composite | false |
| F01470 | Status value — draft (author still writing) | SDD-000 § Status field | E0133 | composite | true |
| F01471 | Status value — review (author wants feedback; not yet a contract) | SDD-000 § Status field | E0133 | composite | true |
| F01472 | Status value — accepted (operating team has agreed; impl PR can reference) | SDD-000 § Status field | E0133 | composite | true |
| F01473 | Status value — implemented (implementation has landed in main; SDD is historical record) | SDD-000 § Status field | E0133 | composite | true |
| F01474 | Status value — abandoned (superseded or no longer relevant) | SDD-000 § Status field | E0133 | composite | true |
| F01475 | Abandoned body explains the path not taken | SDD-000 § Status field | E0133 | composite | false |
| F01476 | A draft or review SDD does NOT bind any implementation PR | SDD-000 § Status field | E0133 | composite | false |
| F01477 | Only `accepted` SDDs are contracts | SDD-000 § Status field | E0133 | composite | false |
| F01478 | Linkage — every SDD § Problem cites the F-2026-NNN ids it closes | SDD-000 § Linkage | E0134 | composite | false |
| F01479 | Linkage — when SDD reaches `implemented`, the ledger back-references SDD id + PR | SDD-000 § Linkage | E0134 | composite | false |
| F01480 | Linkage — closes the loop with Phase 1's surface-area discovery | SDD-000 § Linkage | E0134 | composite | false |
| F01481 | Template — see `001-ai-machine-end-to-end.md` for canonical template | SDD-000 § Template | M00327 | composite | false |
| F01482 | Template skeleton section — `# SDD-NNN — <title>` header | SDD-000 § Template | E0135 | composite | false |
| F01483 | Template skeleton section — Status frontmatter (Status / Owner / Last updated / Closes findings) | SDD-000 § Template | E0135 | composite | false |
| F01484 | Template skeleton section — ## Problem | SDD-000 § Template | E0135 | composite | false |
| F01485 | Template skeleton section — ## Goals | SDD-000 § Template | E0135 | composite | false |
| F01486 | Template skeleton section — ## Non-goals | SDD-000 § Template | E0135 | composite | false |
| F01487 | Template skeleton section — ## Glossary | SDD-000 § Template | E0135 | composite | false |
| F01488 | Template skeleton section — ## Current state | SDD-000 § Template | E0135 | composite | false |
| F01489 | Template skeleton section — ## Design alternatives considered | SDD-000 § Template | E0135 | composite | false |
| F01490 | Template skeleton — ### Alternative A — ... | SDD-000 § Template | E0135 | composite | false |
| F01491 | Template skeleton — ### Alternative B — ... | SDD-000 § Template | E0135 | composite | false |
| F01492 | Template skeleton — ### Alternative C — ... | SDD-000 § Template | E0135 | composite | false |
| F01493 | Template skeleton section — ## Recommended design | SDD-000 § Template | E0135 | composite | false |
| F01494 | Template skeleton section — ## Detailed design | SDD-000 § Template | E0135 | composite | false |
| F01495 | Template skeleton section — ## Test plan | SDD-000 § Template | E0135 | composite | false |
| F01496 | Template skeleton section — ## Rollout / migration | SDD-000 § Template | E0135 | composite | false |
| F01497 | Template skeleton section — ## Open questions | SDD-000 § Template | E0135 | composite | false |
| F01498 | Template skeleton section — ## Appendix | SDD-000 § Template | E0135 | composite | false |
| F01499 | SDD avoids — vendor advocacy ("we use foo because foo is great") | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01500 | SDD avoids — must state the property foo gives you, name alternatives, justify trade-off | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01501 | SDD avoids — code listings longer than a function | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01502 | SDD avoids — SDDs sketch interfaces; implementation PR carries the code | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01503 | SDD avoids — speculation past the immediate horizon | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01504 | SDD avoids — Phase 4/5 implications listed as "future work" then stop | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01505 | SDD avoids — anything that should be a code comment (one-paragraph rationale = inline comment, not SDD) | SDD-000 § "What an SDD avoids" | E0136 | composite | false |
| F01506 | Style — same as audit docs | SDD-000 § Style | E0136 | composite | false |
| F01507 | Style — tight paragraphs | SDD-000 § Style | E0136 | composite | false |
| F01508 | Style — file:line citations where applicable | SDD-000 § Style | E0136 | composite | false |
| F01509 | Style — no emojis | SDD-000 § Style | E0136 | composite | false |
| F01510 | Style — no decorative section dividers | SDD-000 § Style | E0136 | composite | false |
| F01511 | Style — no marketing language | SDD-000 § Style | E0136 | composite | false |
| F01512 | Style — every claim either cites code or is labelled as an open question | SDD-000 § Style | E0136 | composite | false |
| F01513 | SDD-000 charter (this milestone's namesake; living document) | `docs/sdd/000-charter.md` | M00326 | composite | false |
| F01514 | SDD-001 ai-machine-end-to-end (canonical template reference) | `docs/sdd/001-ai-machine-end-to-end.md` | M00327 | composite | false |
| F01515 | SDD-002 defaults-that-work | `docs/sdd/002-defaults-that-work.md` | M00328 | composite | false |
| F01516 | SDD-003 vpn-bridge-multi-instance | `docs/sdd/003-vpn-bridge-multi-instance.md` | M00329 | composite | false |
| F01517 | SDD-004 security-threat-model | `docs/sdd/004-security-threat-model.md` | M00330 | composite | false |
| F01518 | SDD-005 test-contract (L1–L5 layered harness — MS020) | `docs/sdd/005-test-contract.md` | M00331 | composite | false |
| F01519 | SDD-006 shared-module-script-lib (MS021) | `docs/sdd/006-shared-module-script-lib.md` | M00332 | composite | false |
| F01520 | SDD-007 per-token-sse-subscriber-quota (MS022) | `docs/sdd/007-per-token-sse-subscriber-quota.md` | M00333 | composite | false |
| F01521 | SDD-008 notifications-orchestration | `docs/sdd/008-notifications-orchestration.md` | M00334 | composite | false |
| F01522 | SDD-009 dashboard (operator dashboard scaffold; predecessor to SDD-026) | `docs/sdd/009-dashboard.md` | M00335 | composite | false |
| F01523 | SDD-010 selfdef-on-sain01 (scoping stub; MS008 source) | `docs/sdd/010-selfdef-on-sain01.md` | M00336 | composite | false |
| F01524 | SDD-011 sovereign-os-arc-opening (Stage-1 opener) | `docs/sdd/011-sovereign-os-arc-opening.md` | M00337 | composite | false |
| F01525 | SDD-012 selfdef-on-sain01-integration-design (Stage-2; closes SDD-010 Q-A..Q-H) | `docs/sdd/012-selfdef-on-sain01-integration-design.md` | M00337 | composite | false |
| F01526 | SDD-013 deployment-target-config (Stage-2 PR 1/4) | `docs/sdd/013-deployment-target-config.md` | M00337 | composite | false |
| F01527 | SDD-014 shared-audit-summary-channel (Stage-2 PR 2/4) | `docs/sdd/014-shared-audit-summary-channel.md` | M00337 | composite | false |
| F01528 | SDD-015 perimeter-coexistence (Stage-2 PR 3/4; MS012 source) | `docs/sdd/015-perimeter-coexistence.md` | M00338 | composite | false |
| F01529 | SDD-016 oracle-triage-channel (Stage-2 PR 4/4; MS004 E0036 source) | `docs/sdd/016-oracle-triage-channel.md` | M00338 | composite | false |
| F01530 | SDD-017 sain01-hardware-inventory (Stage-2 hardware inventory; MS008 source) | `docs/sdd/017-sain01-hardware-inventory.md` | M00338 | composite | false |
| F01531 | SDD-018 hardware-aware-modules-and-tune-surface (SD-R14..R32 arc; MS010 source) | `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` | M00339 | composite | false |
| F01532 | SDD-019 cycle3-forward-looking-spec (T-1..T-6 + R43→R48 closures) | `docs/sdd/019-cycle3-forward-looking-spec.md` | M00340 | composite | false |
| F01533 | SDD-020 cycle3-vectors (V-1..V-7) | `docs/sdd/020-cycle3-vectors.md` | M00340 | composite | false |
| F01534 | SDD-021 cycle4-vectors (W-1..W-6) | `docs/sdd/021-cycle4-vectors.md` | M00340 | composite | false |
| F01535 | SDD-022 hardware-exploit-doctrine | `docs/sdd/022-hardware-exploit-doctrine.md` | M00339 | composite | false |
| F01536 | SDD-023 cross-repo-model-taxonomy-mirror (R212 catalog) | `docs/sdd/023-cross-repo-model-taxonomy-mirror.md` | M00339 | composite | false |
| F01537 | SDD-024 cycle5-vectors (X-1..X-6) | `docs/sdd/024-cycle5-vectors.md` | M00340 | composite | false |
| F01538 | SDD-025 cycle6-vectors (Y-1..Y-6) | `docs/sdd/025-cycle6-vectors.md` | M00340 | composite | false |
| F01539 | SDD-026 operator-dashboard-and-flex-profile (Z-1..Z-13; MS011 source) | `docs/sdd/026-operator-dashboard-and-flex-profile.md` | M00341 | composite | false |
| F01540 | Charter is the source of truth for SDD authoring conventions in this repo | SDD-000 § "What an SDD is, here" | E0131 | composite | false |
| F01541 | Charter is referenced from `backlog/milestones/INDEX.md` | INDEX.md row MS013 | E0131 | composite | false |
| F01542 | Charter applies to all 27 SDDs (000–026) in the repo today | repo state | E0137 + E0138 + E0139 + E0140 | composite | false |
| F01543 | Audit cycle (MS009) phase-6/-7 docs audit covers every SDD against this charter | MS009 phase-6/-7 60-docs-audit | E0131 | composite | false |
| F01544 | Audit cycle (MS009) findings ledger records charter violations as F-2026-NNN entries | MS009 phase-6/-7 99-findings-ledger | E0134 | composite | false |
| F01545 | SDD findings linkage — F-2026-NNN closure creates traceability from finding → SDD → implementation PR → CHANGELOG | SDD-000 § Linkage | E0134 | composite | false |
| F01546 | SDD findings linkage — implementation PR back-references SDD in CHANGELOG entry | SDD-000 § Linkage | E0134 | composite | false |
| F01547 | Charter never recycles abandoned SDD numbers | SDD-000 § Numbering | F01465 | composite | false |
| F01548 | Charter forbids vendor advocacy as marketing-driven SDD content | SDD-000 § "What an SDD avoids" | F01499 | composite | false |
| F01549 | Charter requires every property claim to be justified by trade-off (not raw assertion) | SDD-000 § "What an SDD avoids" | F01500 | composite | false |
| F01550 | Charter forbids speculative Phase-N+1 design in current SDD (future work listed + stop) | SDD-000 § "What an SDD avoids" | F01504 | composite | false |
| F01551 | Charter directs one-paragraph rationale to inline code comment, NOT new SDD | SDD-000 § "What an SDD avoids" | F01505 | composite | false |
| F01552 | Charter forbids emojis in SDDs | SDD-000 § Style | F01509 | composite | false |
| F01553 | Charter forbids decorative section dividers in SDDs | SDD-000 § Style | F01510 | composite | false |
| F01554 | Charter forbids marketing language in SDDs | SDD-000 § Style | F01511 | composite | false |
| F01555 | Charter requires file:line citations where applicable | SDD-000 § Style | F01508 | composite | false |
| F01556 | Charter requires every claim either cites code or is labelled open question | SDD-000 § Style | F01512 | composite | false |
| F01557 | Composite — 27 SDDs share a single 9-point spec + 13-section template + 4 anti-patterns + 6-rule style | SDD-000 entire | E0137 + E0138 + E0139 + E0140 | composite | false |
| F01558 | Composite — SDD authorship is bounded by charter; charter is unbounded by SDD authorship (living document) | SDD-000 § header | M00326 | composite | false |
| F01559 | Composite — cycle ladder (SDD-019 → 020 → 021 → 024 → 025) is a deliberate evolution pattern (cycle 3 → 4 → 5 → 6); each closing SDD opens next cycle's vectors SDD | SDD-019/020/021/024/025 cross-refs | M00340 | composite | false |
| F01560 | Composite — SDD ledger growth pattern — 27 SDDs in 2026 (existing); future SDD numbers extend by integer increment; charter remains stable | repo state | E0131 + E0132 | composite | false |

## Requirements (R02881–R03120)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R02881 | SDD charter exists at `docs/sdd/000-charter.md` | `docs/sdd/000-charter.md` | M00326 | non-negotiable | false | 10 |
| R02882 | SDD charter is a living document | SDD-000 § header | F01441 | non-negotiable | false | 10 |
| R02883 | SDD charter owner = audit team | SDD-000 § header | F01442 | non-negotiable | false | 10 |
| R02884 | SDD charter refers to Phase 1 findings ledger `docs/review/99-findings-ledger.md` | SDD-000 § header | F01443 | non-negotiable | false | 10 |
| R02885 | An SDD is a short, self-contained markdown file | SDD-000 § "What an SDD is, here" | E0131 | non-negotiable | false | 10 |
| R02886 | SDD spec 1 — Names the problem (one paragraph, plain language) | SDD-000 § 1 | M00317 | non-negotiable | true | 10 |
| R02887 | SDD spec 2 — Cites the Phase 1 findings it closes (F-2026-NNN ids) | SDD-000 § 2 | M00318 | non-negotiable | true | 10 |
| R02888 | SDD spec 3 — Defines explicit goals and non-goals | SDD-000 § 3 | M00319 | non-negotiable | true | 10 |
| R02889 | SDD spec 4 — Surveys ≥2 alternative designs honestly | SDD-000 § 4 | M00320 | non-negotiable | true | 10 |
| R02890 | SDD spec 5 — Recommends one design and explains why | SDD-000 § 5 | M00321 | non-negotiable | true | 10 |
| R02891 | SDD spec 6 — Specifies enough detail (interfaces, data shapes, file paths) | SDD-000 § 6 | M00322 | non-negotiable | true | 10 |
| R02892 | SDD spec 6 — Impl PR can be reviewed against the SDD without re-arguing the architecture | SDD-000 § 6 | F01451 | non-negotiable | false | 10 |
| R02893 | SDD spec 7 — Lists test requirements the implementation must satisfy | SDD-000 § 7 | M00323 | non-negotiable | true | 10 |
| R02894 | SDD spec 8 — Calls out the rollout / migration story if any | SDD-000 § 8 | M00324 | non-negotiable | true | 10 |
| R02895 | SDD spec 9 — Closes with open questions the author hasn't decided | SDD-000 § 9 | M00325 | non-negotiable | true | 10 |
| R02896 | An SDD is NOT the implementation | SDD-000 § "What an SDD is, here" | F01455 | non-negotiable | false | 10 |
| R02897 | Implementation PR cites the SDD by id | SDD-000 § "What an SDD is, here" | F01456 | non-negotiable | false | 10 |
| R02898 | Implementation PR links to SDD from the PR body | SDD-000 § "What an SDD is, here" | F01457 | non-negotiable | false | 10 |
| R02899 | Implementation PR references SDD inline in any non-obvious code comment | SDD-000 § "What an SDD is, here" | F01458 | non-negotiable | false | 10 |
| R02900 | Numbering — three-digit zero-padded format (`001`, `002`, ..., `099`) | SDD-000 § Numbering | E0132 | non-negotiable | false | 10 |
| R02901 | Numbering — no gaps for politeness | SDD-000 § Numbering | F01462 | non-negotiable | false | 10 |
| R02902 | Numbering — abandoned SDD file stays in place with status=abandoned | SDD-000 § Numbering | F01463 | non-negotiable | false | 10 |
| R02903 | Numbering — abandoned SDD file includes note explaining why | SDD-000 § Numbering | F01464 | non-negotiable | false | 10 |
| R02904 | Numbering — abandoned SDD number is NOT recycled | SDD-000 § Numbering | F01465 | non-negotiable | false | 10 |
| R02905 | Status frontmatter — Status field present | SDD-000 § Status field | F01466 | non-negotiable | false | 10 |
| R02906 | Status frontmatter — Owner field present | SDD-000 § Status field | F01467 | non-negotiable | false | 10 |
| R02907 | Status frontmatter — Last updated field present (YYYY-MM-DD format) | SDD-000 § Status field | F01468 | non-negotiable | false | 10 |
| R02908 | Status frontmatter — Closes findings field present (F-2026-NNN ids) | SDD-000 § Status field | F01469 | non-negotiable | false | 10 |
| R02909 | Status value — draft means author is still writing it | SDD-000 § Status field | F01470 | non-negotiable | true | 10 |
| R02910 | Status value — review means author wants feedback; not yet a contract | SDD-000 § Status field | F01471 | non-negotiable | true | 10 |
| R02911 | Status value — accepted means operating team has agreed this is the design we're building | SDD-000 § Status field | F01472 | non-negotiable | true | 10 |
| R02912 | Status value — accepted means impl PR can reference it from now on | SDD-000 § Status field | F01472 | non-negotiable | false | 10 |
| R02913 | Status value — implemented means the implementation has landed in main | SDD-000 § Status field | F01473 | non-negotiable | true | 10 |
| R02914 | Status value — implemented SDD is a historical record | SDD-000 § Status field | F01473 | non-negotiable | false | 10 |
| R02915 | Status value — abandoned means superseded or no longer relevant | SDD-000 § Status field | F01474 | non-negotiable | true | 10 |
| R02916 | Status value — abandoned body explains the path not taken | SDD-000 § Status field | F01475 | non-negotiable | false | 10 |
| R02917 | A draft or review SDD does NOT bind any implementation PR | SDD-000 § Status field | F01476 | non-negotiable | false | 10 |
| R02918 | Only `accepted` SDDs are contracts | SDD-000 § Status field | F01477 | non-negotiable | false | 10 |
| R02919 | Linkage — every SDD § Problem cites F-2026-NNN ids it closes | SDD-000 § Linkage | F01478 | non-negotiable | false | 10 |
| R02920 | Linkage — when SDD reaches `implemented`, ledger back-references SDD id | SDD-000 § Linkage | F01479 | non-negotiable | false | 10 |
| R02921 | Linkage — when SDD reaches `implemented`, ledger back-references the PR that landed it | SDD-000 § Linkage | F01479 | non-negotiable | false | 10 |
| R02922 | Linkage — Phase 2/3 closes the loop with Phase 1's surface area discovery | SDD-000 § Linkage | F01480 | non-negotiable | false | 10 |
| R02923 | Template reference — `001-ai-machine-end-to-end.md` is the canonical template | SDD-000 § Template | F01481 | non-negotiable | false | 10 |
| R02924 | Template skeleton section — `# SDD-NNN — <title>` header | SDD-000 § Template | F01482 | non-negotiable | true | 10 |
| R02925 | Template skeleton — Status frontmatter (Status / Owner / Last updated / Closes findings) | SDD-000 § Template | F01483 | non-negotiable | true | 10 |
| R02926 | Template skeleton section — ## Problem | SDD-000 § Template | F01484 | non-negotiable | true | 10 |
| R02927 | Template skeleton section — ## Goals | SDD-000 § Template | F01485 | non-negotiable | true | 10 |
| R02928 | Template skeleton section — ## Non-goals | SDD-000 § Template | F01486 | non-negotiable | true | 10 |
| R02929 | Template skeleton section — ## Glossary | SDD-000 § Template | F01487 | non-negotiable | true | 10 |
| R02930 | Template skeleton section — ## Current state | SDD-000 § Template | F01488 | non-negotiable | true | 10 |
| R02931 | Template skeleton section — ## Design alternatives considered | SDD-000 § Template | F01489 | non-negotiable | true | 10 |
| R02932 | Template skeleton — ### Alternative A (≥2 alternatives required) | SDD-000 § Template + § 4 | F01490 | non-negotiable | true | 10 |
| R02933 | Template skeleton — ### Alternative B (≥2 alternatives required) | SDD-000 § Template + § 4 | F01491 | non-negotiable | true | 10 |
| R02934 | Template skeleton — ### Alternative C (often present; not mandatory but typical) | SDD-000 § Template | F01492 | non-negotiable | true | 10 |
| R02935 | Template skeleton section — ## Recommended design | SDD-000 § Template | F01493 | non-negotiable | true | 10 |
| R02936 | Template skeleton section — ## Detailed design | SDD-000 § Template | F01494 | non-negotiable | true | 10 |
| R02937 | Template skeleton section — ## Test plan | SDD-000 § Template | F01495 | non-negotiable | true | 10 |
| R02938 | Template skeleton section — ## Rollout / migration | SDD-000 § Template | F01496 | non-negotiable | true | 10 |
| R02939 | Template skeleton section — ## Open questions | SDD-000 § Template | F01497 | non-negotiable | true | 10 |
| R02940 | Template skeleton section — ## Appendix | SDD-000 § Template | F01498 | non-negotiable | true | 10 |
| R02941 | SDD avoids — vendor advocacy ("we use foo because foo is great") | SDD-000 § "What an SDD avoids" | F01499 | non-negotiable | false | 10 |
| R02942 | SDD must state the property foo gives you | SDD-000 § "What an SDD avoids" | F01500 | non-negotiable | false | 10 |
| R02943 | SDD must name the alternatives | SDD-000 § "What an SDD avoids" | F01500 | non-negotiable | false | 10 |
| R02944 | SDD must justify the trade-off | SDD-000 § "What an SDD avoids" | F01500 | non-negotiable | false | 10 |
| R02945 | SDD avoids — code listings longer than a function | SDD-000 § "What an SDD avoids" | F01501 | non-negotiable | false | 10 |
| R02946 | SDDs sketch interfaces; implementation PR carries the code | SDD-000 § "What an SDD avoids" | F01502 | non-negotiable | false | 10 |
| R02947 | SDD avoids — speculation past the immediate horizon | SDD-000 § "What an SDD avoids" | F01503 | non-negotiable | false | 10 |
| R02948 | SDD lists Phase 4/Phase 5 implications as "future work" then stops | SDD-000 § "What an SDD avoids" | F01504 | non-negotiable | false | 10 |
| R02949 | SDD avoids — anything that should be a comment in code | SDD-000 § "What an SDD avoids" | F01505 | non-negotiable | false | 10 |
| R02950 | One-paragraph rationale → inline comment, not SDD | SDD-000 § "What an SDD avoids" | F01505 | non-negotiable | false | 10 |
| R02951 | Style — same as audit docs | SDD-000 § Style | F01506 | non-negotiable | false | 10 |
| R02952 | Style — tight paragraphs | SDD-000 § Style | F01507 | non-negotiable | false | 10 |
| R02953 | Style — file:line citations where applicable | SDD-000 § Style | F01508 | non-negotiable | false | 10 |
| R02954 | Style — no emojis | SDD-000 § Style | F01509 | non-negotiable | false | 10 |
| R02955 | Style — no decorative section dividers | SDD-000 § Style | F01510 | non-negotiable | false | 10 |
| R02956 | Style — no marketing language | SDD-000 § Style | F01511 | non-negotiable | false | 10 |
| R02957 | Style — every claim either cites code or is labelled as an open question | SDD-000 § Style | F01512 | non-negotiable | false | 10 |
| R02958 | SDD-000 charter exists | `docs/sdd/000-charter.md` | M00326 | non-negotiable | false | 10 |
| R02959 | SDD-001 ai-machine-end-to-end exists (template reference) | `docs/sdd/001-ai-machine-end-to-end.md` | M00327 | non-negotiable | false | 10 |
| R02960 | SDD-002 defaults-that-work exists | `docs/sdd/002-defaults-that-work.md` | M00328 | non-negotiable | false | 10 |
| R02961 | SDD-003 vpn-bridge-multi-instance exists (MS018 source) | `docs/sdd/003-vpn-bridge-multi-instance.md` | M00329 | non-negotiable | false | 10 |
| R02962 | SDD-004 security-threat-model exists (MS019 source) | `docs/sdd/004-security-threat-model.md` | M00330 | non-negotiable | false | 10 |
| R02963 | SDD-005 test-contract exists (MS020 source — L1-L5 layered harness) | `docs/sdd/005-test-contract.md` | M00331 | non-negotiable | false | 10 |
| R02964 | SDD-006 shared-module-script-lib exists (MS021 source) | `docs/sdd/006-shared-module-script-lib.md` | M00332 | non-negotiable | false | 10 |
| R02965 | SDD-007 per-token-sse-subscriber-quota exists (MS022 source) | `docs/sdd/007-per-token-sse-subscriber-quota.md` | M00333 | non-negotiable | false | 10 |
| R02966 | SDD-008 notifications-orchestration exists | `docs/sdd/008-notifications-orchestration.md` | M00334 | non-negotiable | false | 10 |
| R02967 | SDD-009 dashboard exists (operator dashboard scaffold; predecessor to SDD-026) | `docs/sdd/009-dashboard.md` | M00335 | non-negotiable | false | 10 |
| R02968 | SDD-010 selfdef-on-sain01 exists (MS008 scoping stub) | `docs/sdd/010-selfdef-on-sain01.md` | M00336 | non-negotiable | false | 10 |
| R02969 | SDD-011 sovereign-os-arc-opening exists (Stage-1 opener) | `docs/sdd/011-sovereign-os-arc-opening.md` | M00337 | non-negotiable | false | 10 |
| R02970 | SDD-012 selfdef-on-sain01-integration-design exists (Stage-2; closes SDD-010 Q-A..Q-H) | `docs/sdd/012-selfdef-on-sain01-integration-design.md` | M00337 | non-negotiable | false | 10 |
| R02971 | SDD-013 deployment-target-config exists (Stage-2 PR 1/4) | `docs/sdd/013-deployment-target-config.md` | M00337 | non-negotiable | false | 10 |
| R02972 | SDD-014 shared-audit-summary-channel exists (Stage-2 PR 2/4) | `docs/sdd/014-shared-audit-summary-channel.md` | M00337 | non-negotiable | false | 10 |
| R02973 | SDD-015 perimeter-coexistence exists (Stage-2 PR 3/4; MS012 source) | `docs/sdd/015-perimeter-coexistence.md` | M00338 | non-negotiable | false | 10 |
| R02974 | SDD-016 oracle-triage-channel exists (Stage-2 PR 4/4; MS004 E0036 source) | `docs/sdd/016-oracle-triage-channel.md` | M00338 | non-negotiable | false | 10 |
| R02975 | SDD-017 sain01-hardware-inventory exists (MS008 source) | `docs/sdd/017-sain01-hardware-inventory.md` | M00338 | non-negotiable | false | 10 |
| R02976 | SDD-018 hardware-aware-modules-and-tune-surface exists (SD-R14..R32 arc; MS010 source) | `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` | M00339 | non-negotiable | false | 10 |
| R02977 | SDD-019 cycle3-forward-looking-spec exists (T-1..T-6 + R43→R48 closures) | `docs/sdd/019-cycle3-forward-looking-spec.md` | M00340 | non-negotiable | false | 10 |
| R02978 | SDD-020 cycle3-vectors exists (V-1..V-7) | `docs/sdd/020-cycle3-vectors.md` | M00340 | non-negotiable | false | 10 |
| R02979 | SDD-021 cycle4-vectors exists (W-1..W-6) | `docs/sdd/021-cycle4-vectors.md` | M00340 | non-negotiable | false | 10 |
| R02980 | SDD-022 hardware-exploit-doctrine exists | `docs/sdd/022-hardware-exploit-doctrine.md` | M00339 | non-negotiable | false | 10 |
| R02981 | SDD-023 cross-repo-model-taxonomy-mirror exists (R212 catalog) | `docs/sdd/023-cross-repo-model-taxonomy-mirror.md` | M00339 | non-negotiable | false | 10 |
| R02982 | SDD-024 cycle5-vectors exists (X-1..X-6) | `docs/sdd/024-cycle5-vectors.md` | M00340 | non-negotiable | false | 10 |
| R02983 | SDD-025 cycle6-vectors exists (Y-1..Y-6) | `docs/sdd/025-cycle6-vectors.md` | M00340 | non-negotiable | false | 10 |
| R02984 | SDD-026 operator-dashboard-and-flex-profile exists (Z-1..Z-13; MS011 source) | `docs/sdd/026-operator-dashboard-and-flex-profile.md` | M00341 | non-negotiable | false | 10 |
| R02985 | Charter applies to all 27 SDDs (000–026) in repo today | repo state | F01542 | non-negotiable | false | 10 |
| R02986 | Charter is the source-of-truth for SDD authoring conventions in this repo | SDD-000 entire | F01540 | non-negotiable | false | 10 |
| R02987 | Charter is referenced from `backlog/milestones/INDEX.md` row MS013 | INDEX.md | F01541 | non-negotiable | false | 10 |
| R02988 | Audit cycle (MS009) phase-6/-7 docs audit covers every SDD against this charter | MS009 phase-6/-7 60-docs-audit | F01543 | non-negotiable | false | 10 |
| R02989 | Audit cycle findings ledger records charter violations as F-2026-NNN entries | MS009 phase-6/-7 99-findings-ledger | F01544 | non-negotiable | false | 10 |
| R02990 | SDD findings linkage creates traceability — finding → SDD → impl PR → CHANGELOG | SDD-000 § Linkage | F01545 | non-negotiable | false | 10 |
| R02991 | Implementation PR back-references SDD in CHANGELOG entry | SDD-000 § Linkage | F01546 | non-negotiable | false | 10 |
| R02992 | Charter forbids — vendor advocacy as marketing-driven SDD content | SDD-000 § "What an SDD avoids" | F01548 | non-negotiable | false | 10 |
| R02993 | Charter requires — every property claim justified by trade-off (not raw assertion) | SDD-000 § "What an SDD avoids" | F01549 | non-negotiable | false | 10 |
| R02994 | Charter forbids — speculative Phase-N+1 design in current SDD | SDD-000 § "What an SDD avoids" | F01550 | non-negotiable | false | 10 |
| R02995 | Charter directs — one-paragraph rationale → inline code comment, NOT new SDD | SDD-000 § "What an SDD avoids" | F01551 | non-negotiable | false | 10 |
| R02996 | Charter forbids — emojis in SDDs | SDD-000 § Style | F01552 | non-negotiable | false | 10 |
| R02997 | Charter forbids — decorative section dividers in SDDs | SDD-000 § Style | F01553 | non-negotiable | false | 10 |
| R02998 | Charter forbids — marketing language in SDDs | SDD-000 § Style | F01554 | non-negotiable | false | 10 |
| R02999 | Charter requires — file:line citations where applicable | SDD-000 § Style | F01555 | non-negotiable | false | 10 |
| R03000 | Charter requires — every claim cites code OR is labelled as open question | SDD-000 § Style | F01556 | non-negotiable | false | 10 |
| R03001 | 27 SDDs share a single 9-point spec | SDD-000 § "What an SDD is, here" | F01557 | non-negotiable | false | 10 |
| R03002 | 27 SDDs share a single 13-section canonical template | SDD-000 § Template | F01557 | non-negotiable | false | 10 |
| R03003 | 27 SDDs share a single 4-item anti-patterns list ("What an SDD avoids") | SDD-000 § "What an SDD avoids" | F01557 | non-negotiable | false | 10 |
| R03004 | 27 SDDs share a single 6-rule style guide | SDD-000 § Style | F01557 | non-negotiable | false | 10 |
| R03005 | SDD authorship is bounded by charter | SDD-000 § header | F01558 | non-negotiable | false | 10 |
| R03006 | Charter is unbounded by SDD authorship (living document) | SDD-000 § header | F01558 | non-negotiable | false | 10 |
| R03007 | Cycle ladder — SDD-019 → SDD-020 → SDD-021 → SDD-024 → SDD-025 (cycle 3 → 4 → 5 → 6) | SDD-019/020/021/024/025 cross-refs | F01559 | non-negotiable | false | 10 |
| R03008 | Each closing SDD opens next cycle's vectors SDD | SDD-019/020/021/024/025 § Way forward | F01559 | non-negotiable | false | 10 |
| R03009 | SDD ledger growth — 27 SDDs in 2026 (existing) | repo state | F01560 | non-negotiable | false | 10 |
| R03010 | SDD ledger growth — future SDD numbers extend by integer increment | SDD-000 § Numbering | F01560 | non-negotiable | false | 10 |
| R03011 | SDD ledger growth — charter remains stable across SDD evolution | SDD-000 § header | F01560 | non-negotiable | false | 10 |
| R03012 | Foundational SDD layer — SDD-000 through SDD-009 cover core spec + threat model + test contract + shared lib + SSE quota + notifications + dashboard scaffold | `docs/sdd/000..009.md` | E0137 | non-negotiable | false | 10 |
| R03013 | SAIN-01 integration SDD layer — SDD-010 through SDD-017 cover deployment scope + integration design + Stage-2 PR 1/4 through 4/4 + hardware inventory | `docs/sdd/010..017.md` | E0138 | non-negotiable | false | 10 |
| R03014 | Hardware exploit + cross-repo doctrine SDD layer — SDD-018 (SD-R14..R32) / SDD-022 hardware-exploit-doctrine / SDD-023 cross-repo-model-taxonomy-mirror | `docs/sdd/018,022,023.md` | E0139 | non-negotiable | false | 10 |
| R03015 | Cycle vectors SDD layer — SDD-019 (T-1..T-6 + R43→R48) / SDD-020 (V-1..V-7) / SDD-021 (W-1..W-6) / SDD-024 (X-1..X-6) / SDD-025 (Y-1..Y-6) | `docs/sdd/019,020,021,024,025.md` | E0139 + E0140 | non-negotiable | false | 10 |
| R03016 | Dashboard SDD layer — SDD-026 operator-dashboard-and-flex-profile (Z-1..Z-13) | `docs/sdd/026-operator-dashboard-and-flex-profile.md` | E0140 | non-negotiable | false | 10 |
| R03017 | SDD-000 charter is the ONLY meta-SDD (the SDD about SDDs) | `docs/sdd/000-charter.md` | M00326 | non-negotiable | false | 10 |
| R03018 | SDD-000 charter status = "living document" (not draft / not review / not accepted / not implemented / not abandoned) | SDD-000 § header | M00326 | non-negotiable | false | 10 |
| R03019 | Every other SDD must pick one of 5 lifecycle status values | SDD-000 § Status field | E0133 | non-negotiable | false | 10 |
| R03020 | F-2026-NNN finding-id format is the charter-canonical phase-1 finding identifier | SDD-000 § 2 + § Linkage | F01446 | non-negotiable | false | 10 |
| R03021 | Status frontmatter parses on every SDD by automated lint (M00316 integration test pattern; future MS009 audit cycle check) | SDD-000 § Status field + MS009 | E0133 | non-negotiable | false | 10 |
| R03022 | Closes findings field is empty allowed (some SDDs are forward-looking — e.g. SDD-019 cycle 3 forward-looking spec) | SDD-000 § Status field + SDD-019 | F01469 | non-negotiable | false | 10 |
| R03023 | Charter-canonical template is the FLOOR not the ceiling — additional sections allowed (e.g. SDD-018 ships "Contracts locked in by this SDD" + "Cross-repo bridge" + "Decision log" beyond skeleton) | SDD-000 § Template + SDD-018 | E0135 | non-negotiable | false | 10 |
| R03024 | Project boundary — charter applies to selfdef SDDs only | architecture | E0131 | non-negotiable | false | 10 |
| R03025 | Project boundary — sovereign-os has its own SDD ledger at `~/sovereign-os/docs/sdd/` with its own charter (NOT this charter) | architecture + sovereign-os repo | E0131 | non-negotiable | false | 10 |
| R03026 | Project boundary — cross-repo doctrine SDD (SDD-038 in sovereign-os) is the typed-mirror binding spec; selfdef MS007 implements it | sovereign-os SDD-038 + MS007 | E0139 | non-negotiable | false | 10 |
| R03027 | Project boundary — selfdef SDDs may CITE sovereign-os SDDs but never INVENT cross-repo content (only mirror) | architecture + MS007 + SDD-038 | E0131 | non-negotiable | false | 10 |
| R03028 | Phase 1 = audit cycles (MS009); phase 2 = SDD authorship; phase 3 = implementation PR; phase 4 = CHANGELOG close — full traceability cycle | SDD-000 § Linkage + MS009 | E0134 | non-negotiable | false | 10 |
| R03029 | Charter MUST be referenced from any new SDD's frontmatter (via `Builds on: SDD-000`) | SDD-000 § header + SDD authoring convention | E0131 | non-negotiable | false | 10 |
| R03030 | Charter constraints are TESTABLE — every SDD can be lint-checked against 9-point spec + 13-section template + Status frontmatter + Closes findings format | SDD-000 entire + MS009 | E0131 | non-negotiable | false | 10 |
| R03031 | SDD-001 is the canonical worked example operators read when learning the template | SDD-000 § Template + SDD-001 | M00327 | non-negotiable | false | 10 |
| R03032 | SDD-002 defaults-that-work codifies operator-default-config conventions | `docs/sdd/002-defaults-that-work.md` | M00328 | non-negotiable | false | 10 |
| R03033 | SDD-003 vpn-bridge-multi-instance codifies vpn-bridge multi-instance architecture (MS018 source) | `docs/sdd/003-vpn-bridge-multi-instance.md` | M00329 | non-negotiable | false | 10 |
| R03034 | SDD-004 security-threat-model codifies threat surface (MS019 source) | `docs/sdd/004-security-threat-model.md` | M00330 | non-negotiable | false | 10 |
| R03035 | SDD-005 test-contract codifies L1-L5 layered test harness (MS020 source) | `docs/sdd/005-test-contract.md` | M00331 | non-negotiable | false | 10 |
| R03036 | SDD-006 shared-module-script-lib codifies module install/check/uninstall script library (MS021 source) | `docs/sdd/006-shared-module-script-lib.md` | M00332 | non-negotiable | false | 10 |
| R03037 | SDD-007 per-token-sse-subscriber-quota codifies SSE subscriber quota (MS022 source) | `docs/sdd/007-per-token-sse-subscriber-quota.md` | M00333 | non-negotiable | false | 10 |
| R03038 | SDD-008 notifications-orchestration codifies notification orchestration (MS005 source) | `docs/sdd/008-notifications-orchestration.md` | M00334 | non-negotiable | false | 10 |
| R03039 | SDD-009 dashboard is the scaffold/predecessor SDD to SDD-026 (which adds Z-1..Z-13 vector grid) | `docs/sdd/009-dashboard.md` + `docs/sdd/026-operator-dashboard-and-flex-profile.md` | M00335 + M00341 | non-negotiable | false | 10 |
| R03040 | SDD-010 selfdef-on-sain01 is the scoping stub closed by SDD-012 (Q-A..Q-H resolved by SDD-012) | `docs/sdd/010-selfdef-on-sain01.md` + `docs/sdd/012-selfdef-on-sain01-integration-design.md` | M00336 + M00337 | non-negotiable | false | 10 |
| R03041 | SDD-012 closes 8 SDD-010 questions Q-A..Q-H | `docs/sdd/012-selfdef-on-sain01-integration-design.md` | M00337 | non-negotiable | false | 10 |
| R03042 | Stage-2 = 4 PRs (SDD-013 PR 1/4 deployment-target-config / SDD-014 PR 2/4 shared-audit-summary / SDD-015 PR 3/4 perimeter-coexistence / SDD-016 PR 4/4 oracle-triage) | `docs/sdd/013..016.md` | M00337 + M00338 | non-negotiable | false | 10 |
| R03043 | Stage-2 PR ordering is documented in SDD-012 Q-H | `docs/sdd/012-selfdef-on-sain01-integration-design.md` Q-H | M00337 | non-negotiable | false | 10 |
| R03044 | SDD-017 hardware-inventory is the SAIN-01 hardware-discovery spec consumed by `crates/selfdef-hardware` | `docs/sdd/017-sain01-hardware-inventory.md` + `crates/selfdef-hardware/` | M00338 | non-negotiable | false | 10 |
| R03045 | SDD-018 SD-R14..R32 cycle 1+2 progressively locks contracts (cycle 1 SD-R14..R23 merged PR #190; cycle 2 SD-R24..R32 accumulating PR #191) | `docs/sdd/018-hardware-aware-modules-and-tune-surface.md` | M00339 | non-negotiable | false | 10 |
| R03046 | Cycle ladder pattern — each forward-looking SDD (019/020/021/024/025) records previous-cycle closing status + opens new vectors | SDD-019/020/021/024/025 | M00340 | non-negotiable | false | 10 |
| R03047 | Cycle ladder vector naming — V=cycle3 / W=cycle4 / X=cycle5 / Y=cycle6 / Z=cycle7+ (SDD-026 dashboard) | SDD-020 V / SDD-021 W / SDD-024 X / SDD-025 Y / SDD-026 Z | M00340 + M00341 | non-negotiable | false | 10 |
| R03048 | Charter integration with audit cycles (MS009) — phase-6/60-docs-audit + phase-7/60-docs-audit verify every SDD against this charter | MS009 phase-6/-7 | F01543 | non-negotiable | false | 10 |
| R03049 | Charter integration with backlog (MS001-MS042) — every milestone cites the SDD(s) it derives from | this repo's backlog/milestones/ tree | E0131 | non-negotiable | false | 10 |
| R03050 | Charter integration with CHANGELOG — each SDD's `implemented` status carries CHANGELOG entry naming the PR | SDD-000 § Linkage + CHANGELOG.md | E0134 | non-negotiable | false | 10 |
| R03051 | Charter forbids — abandoning an SDD without explaining the path not taken | SDD-000 § Status field abandoned | F01475 | non-negotiable | false | 10 |
| R03052 | Charter forbids — using an unaccepted SDD as an implementation contract | SDD-000 § Status field | F01476 + F01477 | non-negotiable | false | 10 |
| R03053 | Charter forbids — recycling abandoned SDD numbers | SDD-000 § Numbering | F01465 | non-negotiable | false | 10 |
| R03054 | Charter forbids — SDDs without a Problem section that cites F-2026-NNN findings | SDD-000 § 2 + § Linkage | F01446 + F01478 | non-negotiable | false | 10 |
| R03055 | Charter forbids — SDDs with vendor advocacy unsupported by trade-off justification | SDD-000 § "What an SDD avoids" | F01548 | non-negotiable | false | 10 |
| R03056 | Charter forbids — SDDs with code listings longer than a function | SDD-000 § "What an SDD avoids" | F01501 | non-negotiable | false | 10 |
| R03057 | Charter forbids — SDDs speculating past Phase 4/5 | SDD-000 § "What an SDD avoids" | F01550 | non-negotiable | false | 10 |
| R03058 | Charter forbids — SDDs containing emojis | SDD-000 § Style | F01552 | non-negotiable | false | 10 |
| R03059 | Charter forbids — SDDs with marketing language | SDD-000 § Style | F01554 | non-negotiable | false | 10 |
| R03060 | Charter forbids — SDD claims without code citation or "open question" label | SDD-000 § Style | F01556 | non-negotiable | false | 10 |
| R03061 | Charter forbids — SDD-NNN file name format other than `NNN-<title-slug>.md` | SDD-000 § Numbering + repo state | E0132 | non-negotiable | false | 10 |
| R03062 | Charter forbids — SDD numbering outside `001`-`099` range (3-digit zero-padded) | SDD-000 § Numbering | F01459 + F01461 | non-negotiable | false | 10 |
| R03063 | Charter forbids — SDDs without Status / Owner / Last updated / Closes findings frontmatter | SDD-000 § Status field | F01466 + F01467 + F01468 + F01469 | non-negotiable | false | 10 |
| R03064 | Charter requires — SDD-NNN files extensions `.md` only | SDD-000 § "What an SDD is, here" | E0131 | non-negotiable | false | 10 |
| R03065 | Charter requires — SDDs live in `docs/sdd/` (not `docs/specs/`, not `docs/` root) | repo state | E0131 | non-negotiable | false | 10 |
| R03066 | Charter requires — SDDs use ASCII (English) — no localization | repo state | E0131 | non-negotiable | false | 10 |
| R03067 | Charter integration with MS013 (this milestone) — MS013 enumerates the 27-SDD ledger as it stands at 2026-05-17 | this milestone + SDD-026 (latest) | E0131 | non-negotiable | false | 10 |
| R03068 | MS013 integrates with MS009 audit cycles — phase-6/-7 60-docs-audit covers MS013-listed SDDs | MS009 phase-6/-7 | F01543 | non-negotiable | false | 10 |
| R03069 | MS013 integrates with MS001-MS012 — every earlier milestone references at least one SDD | repo state + earlier milestones | E0131 | non-negotiable | false | 10 |
| R03070 | MS013 stability — charter changes are RARE (living document; substantive change requires audit-team consensus) | SDD-000 § header | M00326 | non-negotiable | false | 10 |
| R03071 | MS013 evolution — new SDDs (SDD-027+) extend ledger; charter remains stable | SDD-000 § Numbering + § header | F01560 | non-negotiable | false | 10 |
| R03072 | MS013 — SDD authorship is fundamentally markdown-as-documentation (per SDD-000 spec point 6 — "interfaces / data shapes / file paths"; NOT executable specifications) | SDD-000 § "What an SDD is, here" 6 | F01451 | non-negotiable | false | 10 |
| R03073 | MS013 — SDDs are reviewed via standard PR mechanism (status=review state); accepted via operator approval (status=accepted state) | SDD-000 § Status field | E0133 | non-negotiable | false | 10 |
| R03074 | MS013 — implementation PR can reference an `accepted` SDD; not a `draft` or `review` SDD | SDD-000 § Status field | F01476 + F01477 | non-negotiable | false | 10 |
| R03075 | MS013 — `implemented` is the terminal happy-path state (`abandoned` is the terminal sad-path state) | SDD-000 § Status field | F01473 + F01474 | non-negotiable | false | 10 |
| R03076 | MS013 — Audit-team owns charter changes; per-SDD owner owns SDD changes | SDD-000 § header + § Status field Owner field | M00326 + F01467 | non-negotiable | false | 10 |
| R03077 | MS013 — SDD-019 cycle3 forward-looking spec is the FIRST forward-looking-mode SDD (other SDDs are problem-driven) | SDD-019 | M00340 | non-negotiable | false | 10 |
| R03078 | MS013 — cycle vectors SDDs (020/021/024/025) accumulate forward-looking content (NEW V/W/X/Y vectors) over cycle iterations | SDD-020/021/024/025 | M00340 | non-negotiable | false | 10 |
| R03079 | MS013 — SDD-026 operator-dashboard is currently the highest-numbered cycle SDD (Z-1..Z-13 vector grid) | SDD-026 | M00341 | non-negotiable | false | 10 |
| R03080 | MS013 — next SDD slot is `027-<title-slug>.md` (per Numbering convention) | SDD-000 § Numbering + repo state | E0132 | non-negotiable | false | 10 |
| R03081 | MS013 sub-ledger 000-009 (foundational) — 10 SDDs cover core architecture | repo state | E0137 | non-negotiable | false | 10 |
| R03082 | MS013 sub-ledger 010-017 (SAIN-01 integration) — 8 SDDs cover deployment + integration + hardware inventory | repo state | E0138 | non-negotiable | false | 10 |
| R03083 | MS013 sub-ledger 018-023 (hardware exploit + cross-repo) — 6 SDDs cover SD-R arc + hardware exploit + model taxonomy mirror | repo state | E0139 | non-negotiable | false | 10 |
| R03084 | MS013 sub-ledger 024-026 (cycle vectors + dashboard) — 3 SDDs cover cycle 5 / cycle 6 / dashboard | repo state | E0140 | non-negotiable | false | 10 |
| R03085 | MS013 sub-ledger total — 10 + 8 + 6 + 3 = 27 SDDs at 2026-05-17 (matches charter "27-SDD" descriptor in INDEX.md MS013 row) | repo state | E0131 | non-negotiable | false | 10 |
| R03086 | Cycle ladder cross-references — SDD-019 R43→R48 in-cycle closures feed SDD-020 V-N opens; SDD-020 V-7 mid-cycle emergence feeds SDD-021 W-N opens; SDD-021 W-1..W-6 status feeds SDD-024 X-N opens; SDD-024 X-1..X-6 status feeds SDD-025 Y-N opens; SDD-025 Y-1..Y-6 status feeds future cycle-7 SDD | SDD-019/020/021/024/025 cross-refs | F01559 | non-negotiable | false | 10 |
| R03087 | Cross-repo SDD cross-references — SDD-018 cross-repo bridge cites sovereign-os R170/R172/R173/R177/R178/R179/R180/R181 consumers | SDD-018 § Cross-repo bridge | M00339 | non-negotiable | false | 10 |
| R03088 | Cross-repo SDD cross-references — SDD-023 cross-repo-model-taxonomy-mirror cites sovereign-os R212 model catalog | SDD-023 | M00339 | non-negotiable | false | 10 |
| R03089 | Cross-repo SDD cross-references — SDD-038 (in sovereign-os) is the typed-mirror binding doctrine; selfdef MS007 implements it | sovereign-os SDD-038 + MS007 | E0139 | non-negotiable | false | 10 |
| R03090 | Audit-cycle SDD cross-references — every audit cycle (Phase 6, 7) covers every SDD in scope | MS009 phase-6/-7 60-docs-audit | F01543 | non-negotiable | false | 10 |
| R03091 | Audit-cycle finding scope — F-2026-NNN findings can target any SDD (or repo state); SDD authoring closes findings | SDD-000 § Linkage | F01478 | non-negotiable | false | 10 |
| R03092 | Audit-cycle ratification — operator answers open questions; CHANGELOG entry closes the cycle | SDD-019/020/021/024/025 § Way forward / Ratify sections | F01546 | non-negotiable | false | 10 |
| R03093 | Charter compliance — every SDD-NNN file's frontmatter satisfies parser (Status / Owner / Last updated / Closes findings) | SDD-000 § Status field + repo state | F01466 + F01467 + F01468 + F01469 | non-negotiable | false | 10 |
| R03094 | Charter compliance — every SDD-NNN file's content covers 9-point spec | SDD-000 § "What an SDD is, here" + repo state | E0131 | non-negotiable | false | 10 |
| R03095 | Charter compliance — every SDD-NNN file's content uses 13-section template (or documents extension via additional sections) | SDD-000 § Template + repo state | E0135 | non-negotiable | false | 10 |
| R03096 | Charter compliance — every SDD-NNN file's content avoids 4 anti-patterns | SDD-000 § "What an SDD avoids" + repo state | E0136 | non-negotiable | false | 10 |
| R03097 | Charter compliance — every SDD-NNN file's content satisfies 6 style rules | SDD-000 § Style + repo state | E0136 | non-negotiable | false | 10 |
| R03098 | Charter compliance MS009 audit — every charter rule lint-checkable in audit cycle | MS009 phase-6/-7 60-docs-audit + SDD-000 entire | F01543 + R03030 | non-negotiable | false | 10 |
| R03099 | Charter immutability — charter is "owner = audit team"; per-SDD `Owner` field is per-SDD | SDD-000 § header + § Status field | M00326 + F01467 | non-negotiable | false | 10 |
| R03100 | Charter scope — applies to selfdef SDDs only (NOT sovereign-os SDDs, which have their own charter) | repo boundary + sovereign-os repo | R03025 | non-negotiable | false | 10 |
| R03101 | Charter authoring — markdown source under `docs/sdd/000-charter.md` (single file; living document; commits via standard PR mechanism) | repo state | M00326 | non-negotiable | false | 10 |
| R03102 | Charter section ordering — fixed (header / What an SDD is / Numbering / Status field / Linkage / Template / What an SDD avoids / Style) | SDD-000 entire | M00326 | non-negotiable | false | 10 |
| R03103 | Charter style — same as audit docs ("tight paragraphs, file:line citations where applicable, no emojis, no decorative section dividers, no marketing language") | SDD-000 § Style | F01506 + F01511 | non-negotiable | false | 10 |
| R03104 | Charter style — "every claim either cites code or is labelled as an open question" applies to the charter itself | SDD-000 § Style | F01512 | non-negotiable | false | 10 |
| R03105 | Charter authoring path — operator-supervised (audit-team-owned); changes via PR; reviewed by audit team | SDD-000 § header + standard PR workflow | M00326 | non-negotiable | false | 10 |
| R03106 | Charter test plan — N/A (charter is documentation; verification is via audit cycle MS009 + per-SDD lint-check) | SDD-000 entire (no test plan in SDD-000) | M00326 | non-negotiable | false | 10 |
| R03107 | Charter rollout — N/A (charter is the rollout target for all other SDDs) | SDD-000 entire (no rollout in SDD-000) | M00326 | non-negotiable | false | 10 |
| R03108 | Charter migration — N/A (charter is the migration target for all other SDDs) | SDD-000 entire (no migration in SDD-000) | M00326 | non-negotiable | false | 10 |
| R03109 | Charter open questions — N/A (charter is reference; per-SDD open questions live in each SDD) | SDD-000 entire (no open questions in SDD-000) | M00326 | non-negotiable | false | 10 |
| R03110 | Charter is itself a documentation contract — operators read SDD-000 to know what SDDs are (and aren't) | SDD-000 § "What an SDD is, here" | E0131 | non-negotiable | false | 10 |
| R03111 | Charter integration with MS001 daemon core — every daemon-core SDD references charter conventions | MS001 + SDD-000 | E0131 | non-negotiable | false | 10 |
| R03112 | Charter integration with MS006 functional modules — every module-specific SDD references charter conventions | MS006 + SDD-000 | E0131 | non-negotiable | false | 10 |
| R03113 | Charter integration with MS007 cross-repo typed mirrors — SDD-038 (sovereign-os side) + selfdef MS007 implementation reference charter conventions per-repo | MS007 + SDD-000 + sovereign-os SDD-038 | E0131 | non-negotiable | false | 10 |
| R03114 | Charter integration with MS010 hardware-aware modules — SDD-017 + SDD-018 + SDD-022 reference charter conventions | MS010 + SDD-000 | E0131 | non-negotiable | false | 10 |
| R03115 | Charter integration with MS011 operator dashboard — SDD-009 + SDD-026 reference charter conventions; SDD-026 adds Z-N vector pattern compatible with cycle ladder | MS011 + SDD-000 + cycle ladder | M00341 | non-negotiable | false | 10 |
| R03116 | Charter integration with MS012 perimeter coexistence — SDD-015 + SDD-016 reference charter conventions | MS012 + SDD-000 | E0131 | non-negotiable | false | 10 |
| R03117 | MS013 closing — 27-SDD ledger is the snapshot at 2026-05-17; future SDDs extend the ledger; charter remains the binding meta-spec | repo state + SDD-026 last-updated date | F01542 + F01560 | non-negotiable | false | 10 |
| R03118 | MS013 ratification — operator ratifies charter changes via standard PR review on `docs/sdd/000-charter.md` | SDD-000 § header + standard PR workflow | M00326 | non-negotiable | false | 10 |
| R03119 | MS013 audit — every cycle (Phase 6, 7, future Phase 9+) re-audits 27-SDD ledger compliance + records F-2026-NNN findings on violations | MS009 phase-6/-7 + future phases + SDD-000 | F01543 + F01544 | non-negotiable | false | 10 |
| R03120 | Composite — 27-SDD charter framework is the meta-architecture binding selfdef SDD authorship; SDD-000 charter is the source of truth; 9-point spec + 13-section template + 4 anti-patterns + 6 style rules + 5-state lifecycle + F-2026-NNN findings linkage define the framework; 27 SDDs (000–026) extend the ledger as of 2026-05-17; sovereign-os has its own SDD ledger + charter; cross-repo binding is doctrine-only (SDD-038 + MS007 typed mirrors), not direct SDD import | SDD-000 entire + MS007 + sovereign-os SDD-038 | E0131 + E0132 + E0133 + E0134 + E0135 + E0136 + E0137 + E0138 + E0139 + E0140 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS012: 11520 + 2400 = 13920 sub-requirements when MS013 lands

## Cross-references

- All 27 SDDs: `docs/sdd/000-charter.md` (this charter) + `docs/sdd/001-ai-machine-end-to-end.md` … `docs/sdd/026-operator-dashboard-and-flex-profile.md`
- Phase 1 findings ledger: `docs/review/99-findings-ledger.md` (the F-2026-NNN canonical source)
- Audit cycles: MS009 (phase-6 / phase-7 60-docs-audit verifies every SDD against charter)
- Sister sovereign-os SDD ledger: `~/sovereign-os/docs/sdd/` (independent ledger with its own charter)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` + MS007 typed-mirror crates
- Cycle ladder cross-refs: SDD-019 → SDD-020 → SDD-021 → SDD-024 → SDD-025 (each closing opens next cycle's vectors SDD)
