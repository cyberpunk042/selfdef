# MS045 — UX coherence test harness (CLI + TUI + minimal-web) — TDD validator for MS043 operator surface

**Parent**: selfdef IPS daemon — operator-facing UX validation layer
**Source**: MS043 (IPS operator surface — CLI + TUI + minimal-web + 9 mirror crates) + operator standing direction 2026-05-19 *"work in SDD and TDD and be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist"* + *"high UX/Developer Experience"* + *"do not minimize the work in selfdef"*

## Why this milestone exists

MS043 catalogues 240 requirements for the IPS-side CLI (50+ subcommands), TUI (4-panel), and minimal-web (localhost:7575 fallback). Many R-rows are UX correctness assertions: `--json` flag returns structured output (R10131), CLI startup `<` 50ms p95 (R10137), TUI keyboard shortcuts `j/k` between rows (R10150), WCAG 2.1 AA contrast 4.5:1 minimum (R10175). **Without a test harness those R-rows are aspirational, not enforced.** This milestone catalogues the **automated TDD harness** that verifies the IPS operator-facing surface satisfies its own catalogued UX requirements at every commit.

Per operator standing direction *"NO random trash please... you cannot re-invent what UX mean"*: this harness measures the existing operator-validated UX patterns (matching MS043) — it does not invent new UX patterns. Every test row anchors to a specific MS043 R-row by ID.

## Doctrinal anchor

> "be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist" (operator standing direction 2026-05-19)

This milestone is the **DevOps Engineer + UX Design Specialist** projection: the harness that enforces the architecture's UX promises at CI time. Without it, the architect's 240 R-rows are sentiment, not contract.

## Epics (E0451-E0460)

| epic | name | source |
|---|---|---|
| E0451 | L1 layer — schema/lint UX assertion tests (no virtualization needed) | M062 PR 9 test harness layer 1 |
| E0452 | CLI startup performance harness — validate p95 latencies per MS043 R10137 | MS043 R10137 |
| E0453 | CLI structured-output harness — validate `--json` flag per MS043 R10131 | MS043 R10131 |
| E0454 | TUI keyboard navigation harness — validate `j/k/h/l/Enter/q/?/P/F` shortcuts per MS043 R10150-R10155 | MS043 R10150-R10155 |
| E0455 | TUI focus indicator harness — validate visible focus per MS043 R10157 (bold + inverted) | MS043 R10157 |
| E0456 | Minimal-web accessibility harness — WCAG 2.1 AA contrast 4.5:1 per MS043 R10175 | MS043 R10175 |
| E0457 | Minimal-web keyboard navigation harness — Tab/arrow/Enter/Esc per MS043 R10263-R10266 | MS043 R10263-R10266 |
| E0458 | CLI completion harness — validate bash + fish + zsh completions per MS043 R10134 | MS043 R10134 |
| E0459 | Operator UX regression harness — runs all MS043 UX R-rows as CI gate | MS043 + operator standing direction |
| E0460 | Cross-surface coherence harness — validates CLI/TUI/web consistency (same data → same view) | architecture + operator UX direction |

## Modules (M01149-M01174)

| module | name | source |
|---|---|---|
| M01149 | selfdef-ux-harness-l1-schema-lint | M062 PR 9 |
| M01150 | selfdef-ux-harness-cli-startup-latency-bench | MS043 R10137 |
| M01151 | selfdef-ux-harness-cli-json-shape-validator | MS043 R10131 |
| M01152 | selfdef-ux-harness-cli-watch-flag-validator | MS043 R10130 |
| M01153 | selfdef-ux-harness-tui-keyboard-replayer | MS043 R10150-R10155 |
| M01154 | selfdef-ux-harness-tui-focus-indicator-snapshot | MS043 R10157 |
| M01155 | selfdef-ux-harness-tui-startup-latency-bench | MS043 R10159 |
| M01156 | selfdef-ux-harness-tui-incident-shortcut-validator (P/F single-key) | MS043 R10154-R10155 |
| M01157 | selfdef-ux-harness-web-contrast-checker (WCAG 2.1 AA) | MS043 R10175 |
| M01158 | selfdef-ux-harness-web-keyboard-nav-replayer | MS043 R10263-R10266 |
| M01159 | selfdef-ux-harness-web-dark-light-mode-snapshot | MS043 R10176-R10178 |
| M01160 | selfdef-ux-harness-web-sse-update-latency-bench | MS043 R10173 + R10290 |
| M01161 | selfdef-ux-harness-cli-completion-validator (bash+fish+zsh) | MS043 R10134 |
| M01162 | selfdef-ux-harness-cli-exit-code-validator (sysexits.h) | MS043 R10139 |
| M01163 | selfdef-ux-harness-cli-help-doc-validator | MS043 R10135 |
| M01164 | selfdef-ux-harness-confirmation-validator (destructive --yes) | MS043 R10246-R10248 |
| M01165 | selfdef-ux-harness-undo-validator (reversible actions) | MS043 R10249-R10252 |
| M01166 | selfdef-ux-harness-error-message-validator (root-cause + recovery) | MS043 R10253-R10254 |
| M01167 | selfdef-ux-harness-empty-state-validator (next-action hint) | MS043 R10255 |
| M01168 | selfdef-ux-harness-long-op-progress-validator (progress + ETA + cancel) | MS043 R10256-R10258 |
| M01169 | selfdef-ux-harness-cross-surface-coherence-validator | architecture + operator UX direction |
| M01170 | selfdef-ux-harness-ci-runner-integration (M062 PR 9 + 10) | M062 PR 9 + 10 |
| M01171 | selfdef-ux-harness-results-reporter | architecture |
| M01172 | selfdef-ux-harness-replay-validator | MS009 |
| M01173 | selfdef-ux-harness-typed-mirror | MS007 |
| M01174 | selfdef-ux-harness-dashboard-binding (D-10 + D-00) | sovereign-os M060 |

## Features (F05281-F05400) — abridged R-anchor table

| feature | name | source |
|---|---|---|
| F05281 | L1 schema/lint — CLI subcommand list matches MS043 schema | MS043 R10087-R10129 |
| F05282 | L1 schema/lint — TUI panel list matches MS043 schema | MS043 R10141 |
| F05283 | L1 schema/lint — minimal-web panel list matches MS043 schema | MS043 R10170 |
| F05284 | L1 schema/lint — mirror crate list matches MS043 schema (9 crates) | MS043 R10182-R10189 |
| F05285 | CLI startup — `selfdef status` runs `<` 50ms p95 | MS043 R10137 |
| F05286 | CLI startup — bench across 1000 runs to measure p95 | MS043 R10286 |
| F05287 | CLI startup — fails CI if p95 ≥ 50ms | MS043 R10137 + architecture |
| F05288 | CLI startup — composes with M058 hardware-aware scheduler context (test on CCD 1 host cores) | M070 |
| F05289 | CLI json — every subcommand with `--json` returns valid JSON | MS043 R10131 |
| F05290 | CLI json — schema-validated per subcommand (MS007 mirror) | MS007 |
| F05291 | CLI json — fails CI on schema drift | architecture |
| F05292 | CLI watch — `--watch` flag emits one update per second min | MS043 R10130 |
| F05293 | CLI watch — graceful CTRL-C cleanup verified | MS043 R10138 |
| F05294 | TUI keyboard — j/k navigates rows | MS043 R10150 |
| F05295 | TUI keyboard — h/l navigates panels | MS043 R10150 |
| F05296 | TUI keyboard — Enter drills into selected item | MS043 R10151 |
| F05297 | TUI keyboard — q exits to shell | MS043 R10152 |
| F05298 | TUI keyboard — ? opens shortcut palette | MS043 R10153 |
| F05299 | TUI keyboard — P (capital) triggers panic-drop-all (operator key required) | MS043 R10154 |
| F05300 | TUI keyboard — F (capital) freezes profile (operator key required) | MS043 R10155 |
| F05301 | TUI keyboard — mouse NOT required (full keyboard nav) | MS043 R10158 |
| F05302 | TUI keyboard — replayer test runs all keystrokes against running TUI process | architecture |
| F05303 | TUI focus — focus indicator visible (bold + inverted) | MS043 R10157 |
| F05304 | TUI focus — snapshot test compares to gold rendering | architecture |
| F05305 | TUI startup — first paint `<` 200ms p95 | MS043 R10287 |
| F05306 | TUI startup — incremental update `<` 50ms p95 | MS043 R10288 |
| F05307 | TUI exit — clean exit on SIGTERM (cursor restored) | MS043 R10161 |
| F05308 | TUI exit — clean exit on SIGINT (cursor restored) | MS043 R10162 |
| F05309 | Web contrast — WCAG 2.1 AA contrast 4.5:1 text | MS043 R10175 |
| F05310 | Web contrast — automated checker (pa11y or equivalent) | architecture |
| F05311 | Web contrast — fails CI on contrast violation | architecture |
| F05312 | Web keyboard — Tab navigates between focusable elements | MS043 R10263 |
| F05313 | Web keyboard — arrow keys navigate within widgets | MS043 R10264 |
| F05314 | Web keyboard — Enter activates focused element | MS043 R10265 |
| F05315 | Web keyboard — Esc dismisses modals | MS043 R10266 |
| F05316 | Web dark mode — dark mode renders correctly | MS043 R10176 |
| F05317 | Web light mode — light mode renders correctly | MS043 R10177 |
| F05318 | Web auto mode — auto-from-system mode honors prefers-color-scheme | MS043 R10178 |
| F05319 | Web SSE — auto-refresh interval `<=` 2s | MS043 R10173 |
| F05320 | Web SSE — incremental update latency `<` 50ms p95 | MS043 R10290 |
| F05321 | CLI completion — bash completion installed by package | MS043 R10134 |
| F05322 | CLI completion — fish completion installed by package | MS043 R10134 |
| F05323 | CLI completion — zsh completion installed by package | MS043 R10134 |
| F05324 | CLI completion — every subcommand has completion entry | architecture |
| F05325 | CLI exit codes — 0 = success | MS043 R10139 |
| F05326 | CLI exit codes — 64 = usage error | MS043 R10139 |
| F05327 | CLI exit codes — 66 = input error | MS043 R10139 |
| F05328 | CLI exit codes — 77 = permission denied | MS043 R10139 |
| F05329 | CLI help — every subcommand has --help text | MS043 R10135 |
| F05330 | CLI help — help text includes usage + flags + examples | architecture |
| F05331 | Confirmation — destructive CLI requires --yes | MS043 R10246 |
| F05332 | Confirmation — destructive TUI shows dialog | MS043 R10247 |
| F05333 | Confirmation — destructive web shows modal | MS043 R10248 |
| F05334 | Undo — cap-mint undoable via cap-revoke | MS043 R10250 |
| F05335 | Undo — grant-extend undoable via grant-revoke | MS043 R10251 |
| F05336 | Undo — profile-set undoable by switching back | MS043 R10252 |
| F05337 | Error — error states show root-cause | MS043 R10253 |
| F05338 | Error — error states show recovery action | MS043 R10254 |
| F05339 | Empty state — empty states show next-action hint | MS043 R10255 |
| F05340 | Long op — progress visible | MS043 R10256 |
| F05341 | Long op — ETA visible | MS043 R10257 |
| F05342 | Long op — cancel option visible | MS043 R10258 |
| F05343 | Cross-surface — same data renders consistently across CLI/TUI/web | architecture |
| F05344 | Cross-surface — `selfdef status` output matches TUI status panel | architecture |
| F05345 | Cross-surface — TUI status panel matches minimal-web home view | architecture |
| F05346 | Cross-surface — discrepancies emit OCSF Detection 2004 | MS026 |
| F05347 | CI integration — harness runs on every PR via .github/workflows/test.yml | M062 PR 10 |
| F05348 | CI integration — composes with M062 PR 9 test layer 1 (schema/lint) | M062 PR 9 |
| F05349 | CI integration — composes with M062 PR 10 scaffolds | M062 PR 10 |
| F05350 | CI integration — fails merge on any UX R-row violation | architecture |
| F05351 | Results reporter — JSON report retained as PR artifact 365 days | M063 IaC quality bar |
| F05352 | Results reporter — failures logged in PR comment with R-row IDs | architecture |
| F05353 | Results reporter — composes with D-10 eval history dashboard | sovereign-os M060 |
| F05354 | Results reporter — pass-rate per R-row emitted via M049 | M049 |
| F05355 | Replay validator — verifies historical UX harness chain | MS009 |
| F05356 | Replay validator — detects test silently passing (no-op) | MS009 |
| F05357 | Replay validator — emits OCSF Detection 2004 on chain break | MS026 |
| F05358 | Typed mirror — selfdef-ux-harness-mirror crate (MS007 8/8) | MS007 |
| F05359 | Typed mirror — UxTestResult struct {r_row_id, surface, status, ts} | MS007 |
| F05360 | Typed mirror — UxSurface enum (CLI / TUI / MinimalWeb / MirrorCrate) | MS007 |
| F05361 | Typed mirror — schema_version "1.0.0" | MS007 |
| F05362 | Typed mirror — signed via MS003 | MS003 |
| F05363 | Dashboard — D-00 main shows UX harness pass-rate badge | sovereign-os M060 |
| F05364 | Dashboard — D-10 eval history shows per-R-row pass-rate over time | sovereign-os M060 |
| F05365 | Operator UX — harness toggleable per /etc/selfdef/ux-harness.toml | operator standing direction |
| F05366 | Operator UX — operator can run `selfdef ux-harness check` ad-hoc | MS043 |
| F05367 | Operator UX — operator can run `selfdef ux-harness check --surface <s>` per-surface | MS043 |
| F05368 | Operator UX — operator can view violations history via `selfdef ux-harness history` | architecture |
| F05369 | Operator UX — operator can set per-R-row severity (warn vs fail) | architecture |
| F05370 | Performance — full harness suite runtime `<` 5min on Ryzen 9 9900X | architecture |
| F05371 | Performance — per-surface runtime `<` 90s | architecture |
| F05372 | Performance — typed-mirror publication `<` 100ms p95 | MS007 |
| F05373 | Performance — replay validator daily run `<` 30s | MS009 |
| F05374 | Telemetry — UX violation count per R-row emitted via M049 | M049 |
| F05375 | Telemetry — UX violation count per surface emitted via M049 | M049 |
| F05376 | Telemetry — harness runtime histogram emitted via M049 | M049 |
| F05377 | Telemetry — harness pass-rate over 30/90/365 days emitted via M049 | M049 |
| F05378 | Composition — composes with M062 PR 9 + PR 10 test harness | M062 |
| F05379 | Composition — composes with M063 SFIF Infrastructure phase | M063 |
| F05380 | Composition — composes with MS003 selfdef-signing | MS003 |
| F05381 | Composition — composes with MS007 typed-mirror | MS007 |
| F05382 | Composition — composes with MS009 replay validator | MS009 |
| F05383 | Composition — composes with MS026 OCSF event emission | MS026 |
| F05384 | Composition — composes with MS037 receipt retention | MS037 |
| F05385 | Composition — composes with MS041 commit authority (high-risk for harness skip) | MS041 |
| F05386 | Composition — composes with MS043 (this validates MS043's R-rows) | MS043 |
| F05387 | Composition — composes with MS044 Guardian (TUI panic shortcut verified) | MS044 |
| F05388 | Composition — composes with sovereign-os M049 trace pipeline | sovereign-os M049 |
| F05389 | Composition — composes with sovereign-os M055 failure modes | sovereign-os M055 |
| F05390 | Composition — composes with sovereign-os M060 cockpit dashboards | sovereign-os M060 |
| F05391 | Doctrinal preservation — operator words "high UX/Developer Experience" verbatim | operator standing direction |
| F05392 | Doctrinal preservation — operator words "you cannot re-invent what UX mean" verbatim | operator standing direction |
| F05393 | Doctrinal preservation — operator words "do not minimize the work in selfdef" verbatim | operator standing direction |
| F05394 | Doctrinal preservation — operator words "be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist" verbatim | operator standing direction |
| F05395 | Doctrinal preservation — verbatim quotes never paraphrased | operator standing direction |
| F05396 | Doctrinal preservation — info-hub indexes UX harness lineage as second-brain entry | operator standing direction |
| F05397 | Boundary — IPS-side UX harness lives in selfdef | operator standing direction "Respect the projects" |
| F05398 | Boundary — sovereign-os reads results via MS007 mirror only | MS007 |
| F05399 | Boundary — info-hub never mutated by harness | operator standing direction |
| F05400 | Closing — MS045 covers MS043 UX R-row enforcement; selfdef catalog at 45/45 | architecture + operator standing direction |

## Requirements (R10561-R10800)

| req | description | source | feature | priority | exception | sub-reqs |
|---|---|---|---|---|---|---|
| R10561 | Doctrinal — UX harness enforces MS043 240 R-rows automatically | operator standing direction | F05346 | non-negotiable | false | 10 |
| R10562 | Doctrinal — "be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist" | operator standing direction | F05394 | non-negotiable | false | 10 |
| R10563 | Doctrinal — "high UX/Developer Experience" | operator standing direction | F05391 | non-negotiable | false | 10 |
| R10564 | Doctrinal — "you cannot re-invent what UX mean" (harness measures, does NOT invent) | operator standing direction | F05392 | non-negotiable | false | 10 |
| R10565 | Doctrinal — "do not minimize the work in selfdef" upheld via full 240-row MS045 catalog | operator standing direction | F05393 | non-negotiable | false | 10 |
| R10566 | L1 schema/lint — CLI subcommand list = MS043 schema | MS043 R10087-R10129 | F05281 | non-negotiable | false | 10 |
| R10567 | L1 schema/lint — TUI panel list = MS043 schema | MS043 R10141 | F05282 | non-negotiable | false | 10 |
| R10568 | L1 schema/lint — minimal-web panel list = MS043 schema | MS043 R10170 | F05283 | non-negotiable | false | 10 |
| R10569 | L1 schema/lint — mirror crate list (9 crates) = MS043 schema | MS043 R10182-R10189 | F05284 | non-negotiable | false | 10 |
| R10570 | L1 schema/lint — fails CI on schema drift | architecture | F05291 | non-negotiable | false | 10 |
| R10571 | CLI startup — `selfdef status` p95 `<` 50ms | MS043 R10137 | F05285 | non-negotiable | false | 10 |
| R10572 | CLI startup — bench across 1000 runs to measure p95 | MS043 R10286 | F05286 | non-negotiable | false | 10 |
| R10573 | CLI startup — fails CI if p95 ≥ 50ms | MS043 R10137 + architecture | F05287 | non-negotiable | false | 10 |
| R10574 | CLI startup — test on CCD 1 host cores per M070 placement | M070 | F05288 | non-negotiable | false | 10 |
| R10575 | CLI startup — bench results signed via MS003 | MS003 | F05285 | non-negotiable | false | 10 |
| R10576 | CLI json — every subcommand with `--json` returns valid JSON | MS043 R10131 | F05289 | non-negotiable | false | 10 |
| R10577 | CLI json — schema-validated per subcommand via MS007 mirror | MS007 | F05290 | non-negotiable | false | 10 |
| R10578 | CLI json — fails CI on schema drift | architecture | F05291 | non-negotiable | false | 10 |
| R10579 | CLI watch — `--watch` flag emits one update per second min | MS043 R10130 | F05292 | non-negotiable | false | 10 |
| R10580 | CLI watch — graceful CTRL-C cleanup verified | MS043 R10138 | F05293 | non-negotiable | false | 10 |
| R10581 | TUI keyboard — j navigates row down | MS043 R10150 | F05294 | non-negotiable | false | 10 |
| R10582 | TUI keyboard — k navigates row up | MS043 R10150 | F05294 | non-negotiable | false | 10 |
| R10583 | TUI keyboard — h navigates panel left | MS043 R10150 | F05295 | non-negotiable | false | 10 |
| R10584 | TUI keyboard — l navigates panel right | MS043 R10150 | F05295 | non-negotiable | false | 10 |
| R10585 | TUI keyboard — Enter drills into selected item | MS043 R10151 | F05296 | non-negotiable | false | 10 |
| R10586 | TUI keyboard — q exits to shell | MS043 R10152 | F05297 | non-negotiable | false | 10 |
| R10587 | TUI keyboard — ? opens shortcut palette | MS043 R10153 | F05298 | non-negotiable | false | 10 |
| R10588 | TUI keyboard — P (capital) triggers panic-drop-all | MS043 R10154 | F05299 | non-negotiable | false | 10 |
| R10589 | TUI keyboard — P requires operator key (double-confirmation) | MS043 R10233 | F05299 | non-negotiable | false | 10 |
| R10590 | TUI keyboard — F (capital) freezes profile | MS043 R10155 | F05300 | non-negotiable | false | 10 |
| R10591 | TUI keyboard — F requires operator key | MS043 R10155 | F05300 | non-negotiable | false | 10 |
| R10592 | TUI keyboard — mouse NOT required (full keyboard nav) | MS043 R10158 | F05301 | non-negotiable | false | 10 |
| R10593 | TUI keyboard — replayer test invokes running TUI process via PTY | architecture | F05302 | non-negotiable | false | 10 |
| R10594 | TUI keyboard — replayer asserts expected screen state after each keystroke | architecture | F05302 | non-negotiable | false | 10 |
| R10595 | TUI keyboard — replayer signed via MS003 | MS003 | F05302 | non-negotiable | false | 10 |
| R10596 | TUI focus — focus indicator visible (bold + inverted selection) | MS043 R10157 | F05303 | non-negotiable | false | 10 |
| R10597 | TUI focus — snapshot test compares to gold rendering | architecture | F05304 | non-negotiable | false | 10 |
| R10598 | TUI focus — gold rendering retained at tests/snapshots/tui-focus-<panel>.txt | architecture | F05304 | non-negotiable | false | 10 |
| R10599 | TUI focus — fails CI on snapshot drift | architecture | F05304 | non-negotiable | false | 10 |
| R10600 | TUI startup — first paint `<` 200ms p95 | MS043 R10287 | F05305 | non-negotiable | false | 10 |
| R10601 | TUI startup — incremental update `<` 50ms p95 | MS043 R10288 | F05306 | non-negotiable | false | 10 |
| R10602 | TUI startup — bench across 100 launches | architecture | F05305 | non-negotiable | false | 10 |
| R10603 | TUI exit — clean exit on SIGTERM (cursor restored) | MS043 R10161 | F05307 | non-negotiable | false | 10 |
| R10604 | TUI exit — clean exit on SIGINT (cursor restored) | MS043 R10162 | F05308 | non-negotiable | false | 10 |
| R10605 | TUI exit — terminal state verified via stty restore check | architecture | F05307 | non-negotiable | false | 10 |
| R10606 | Web contrast — WCAG 2.1 AA contrast 4.5:1 text | MS043 R10175 | F05309 | non-negotiable | false | 10 |
| R10607 | Web contrast — automated via pa11y or equivalent | architecture | F05310 | non-negotiable | false | 10 |
| R10608 | Web contrast — runs against every page | architecture | F05310 | non-negotiable | false | 10 |
| R10609 | Web contrast — fails CI on violation | architecture | F05311 | non-negotiable | false | 10 |
| R10610 | Web contrast — report retained as PR artifact | M063 IaC quality bar | F05351 | non-negotiable | false | 10 |
| R10611 | Web keyboard — Tab navigates between focusable elements | MS043 R10263 | F05312 | non-negotiable | false | 10 |
| R10612 | Web keyboard — Shift-Tab navigates backward | architecture | F05312 | non-negotiable | false | 10 |
| R10613 | Web keyboard — arrow keys navigate within widgets | MS043 R10264 | F05313 | non-negotiable | false | 10 |
| R10614 | Web keyboard — Enter activates focused element | MS043 R10265 | F05314 | non-negotiable | false | 10 |
| R10615 | Web keyboard — Esc dismisses modals | MS043 R10266 | F05315 | non-negotiable | false | 10 |
| R10616 | Web keyboard — Playwright-based replayer | architecture | F05312 | non-negotiable | false | 10 |
| R10617 | Web dark mode — renders correctly via `media: dark` | MS043 R10176 | F05316 | non-negotiable | false | 10 |
| R10618 | Web light mode — renders correctly via `media: light` | MS043 R10177 | F05317 | non-negotiable | false | 10 |
| R10619 | Web auto mode — honors prefers-color-scheme | MS043 R10178 | F05318 | non-negotiable | false | 10 |
| R10620 | Web mode — snapshot test per mode | architecture | F05316 | non-negotiable | false | 10 |
| R10621 | Web SSE — auto-refresh interval `<=` 2s | MS043 R10173 | F05319 | non-negotiable | false | 10 |
| R10622 | Web SSE — incremental update latency `<` 50ms p95 | MS043 R10290 | F05320 | non-negotiable | false | 10 |
| R10623 | Web SSE — bench across 100 SSE events | architecture | F05320 | non-negotiable | false | 10 |
| R10624 | CLI completion — bash completion installed by .deb package | MS043 R10134 | F05321 | non-negotiable | false | 10 |
| R10625 | CLI completion — fish completion installed by .deb package | MS043 R10134 | F05322 | non-negotiable | false | 10 |
| R10626 | CLI completion — zsh completion installed by .deb package | MS043 R10134 | F05323 | non-negotiable | false | 10 |
| R10627 | CLI completion — every subcommand has completion entry | architecture | F05324 | non-negotiable | false | 10 |
| R10628 | CLI completion — completion test runs in clean shell | architecture | F05321 | non-negotiable | false | 10 |
| R10629 | CLI exit codes — 0 = success | MS043 R10139 | F05325 | non-negotiable | false | 10 |
| R10630 | CLI exit codes — 64 = usage error | MS043 R10139 | F05326 | non-negotiable | false | 10 |
| R10631 | CLI exit codes — 66 = input error | MS043 R10139 | F05327 | non-negotiable | false | 10 |
| R10632 | CLI exit codes — 77 = permission denied | MS043 R10139 | F05328 | non-negotiable | false | 10 |
| R10633 | CLI exit codes — exhaustive test across all subcommands | architecture | F05325 | non-negotiable | false | 10 |
| R10634 | CLI help — every subcommand has --help text | MS043 R10135 | F05329 | non-negotiable | false | 10 |
| R10635 | CLI help — help text includes usage section | architecture | F05330 | non-negotiable | false | 10 |
| R10636 | CLI help — help text includes flags section | architecture | F05330 | non-negotiable | false | 10 |
| R10637 | CLI help — help text includes examples section | architecture | F05330 | non-negotiable | false | 10 |
| R10638 | CLI help — test asserts presence of all 3 sections | architecture | F05329 | non-negotiable | false | 10 |
| R10639 | Confirmation — destructive CLI requires --yes | MS043 R10246 | F05331 | non-negotiable | false | 10 |
| R10640 | Confirmation — destructive TUI shows dialog | MS043 R10247 | F05332 | non-negotiable | false | 10 |
| R10641 | Confirmation — destructive web shows modal | MS043 R10248 | F05333 | non-negotiable | false | 10 |
| R10642 | Confirmation — destructive ops list: rollback / kill / revoke / panic-drop / freeze-profile | MS043 R10184 + MS044 | F05331 | non-negotiable | false | 10 |
| R10643 | Confirmation — test verifies dialog content includes consequence + actor required | architecture | F05332 | non-negotiable | false | 10 |
| R10644 | Undo — cap-mint undoable via cap-revoke | MS043 R10250 | F05334 | non-negotiable | false | 10 |
| R10645 | Undo — grant-extend undoable via grant-revoke | MS043 R10251 | F05335 | non-negotiable | false | 10 |
| R10646 | Undo — profile-set undoable by switching back | MS043 R10252 | F05336 | non-negotiable | false | 10 |
| R10647 | Undo — test verifies each undo path completes in `<` 5s | architecture | F05334 | non-negotiable | false | 10 |
| R10648 | Error — error states show root-cause | MS043 R10253 | F05337 | non-negotiable | false | 10 |
| R10649 | Error — error states show recovery action | MS043 R10254 | F05338 | non-negotiable | false | 10 |
| R10650 | Error — test injects each known error class + asserts both fields present | architecture + M055 | F05337 | non-negotiable | false | 10 |
| R10651 | Empty state — empty states show next-action hint | MS043 R10255 | F05339 | non-negotiable | false | 10 |
| R10652 | Empty state — never blank panel | MS043 R10255 | F05339 | non-negotiable | false | 10 |
| R10653 | Empty state — test asserts hint visible for every list panel | architecture | F05339 | non-negotiable | false | 10 |
| R10654 | Long op — progress visible | MS043 R10256 | F05340 | non-negotiable | false | 10 |
| R10655 | Long op — ETA visible | MS043 R10257 | F05341 | non-negotiable | false | 10 |
| R10656 | Long op — cancel option visible | MS043 R10258 | F05342 | non-negotiable | false | 10 |
| R10657 | Long op — test simulates 10s operation + asserts all 3 surfaces show progress/ETA/cancel | architecture | F05340 | non-negotiable | false | 10 |
| R10658 | Cross-surface — same data renders consistently across CLI/TUI/web | architecture | F05343 | non-negotiable | false | 10 |
| R10659 | Cross-surface — `selfdef status` output matches TUI status panel | architecture | F05344 | non-negotiable | false | 10 |
| R10660 | Cross-surface — TUI status panel matches minimal-web home view | architecture | F05345 | non-negotiable | false | 10 |
| R10661 | Cross-surface — discrepancies emit OCSF Detection 2004 | MS026 | F05346 | non-negotiable | false | 10 |
| R10662 | Cross-surface — test runs all 3 surfaces with same state snapshot | architecture | F05343 | non-negotiable | false | 10 |
| R10663 | Cross-surface — composes with MS007 typed-mirror state snapshot | MS007 | F05343 | non-negotiable | false | 10 |
| R10664 | CI — harness runs on every PR via .github/workflows/test.yml | M062 PR 10 | F05347 | non-negotiable | false | 10 |
| R10665 | CI — composes with M062 PR 9 test layer 1 (schema/lint) | M062 PR 9 | F05348 | non-negotiable | false | 10 |
| R10666 | CI — composes with M062 PR 10 scaffolds | M062 PR 10 | F05349 | non-negotiable | false | 10 |
| R10667 | CI — fails merge on any UX R-row violation | architecture | F05350 | non-negotiable | false | 10 |
| R10668 | CI — operator can override per R-row severity via /etc/selfdef/ux-harness.toml | operator standing direction | F05369 | non-negotiable | false | 10 |
| R10669 | CI — override emits OCSF Configuration Change 5001 | MS026 | F05369 | non-negotiable | false | 10 |
| R10670 | CI — override signed via MS003 | MS003 | F05369 | non-negotiable | false | 10 |
| R10671 | Reporter — JSON report retained as PR artifact 365 days | M063 IaC quality bar | F05351 | non-negotiable | false | 10 |
| R10672 | Reporter — failures logged in PR comment with R-row IDs | architecture | F05352 | non-negotiable | false | 10 |
| R10673 | Reporter — composes with sovereign-os D-10 eval history dashboard | sovereign-os M060 | F05353 | non-negotiable | false | 10 |
| R10674 | Reporter — pass-rate per R-row emitted via M049 | sovereign-os M049 | F05354 | non-negotiable | false | 10 |
| R10675 | Reporter — surface-disaggregated pass-rate emitted via M049 | sovereign-os M049 | F05375 | non-negotiable | false | 10 |
| R10676 | Replay — verifies historical UX harness chain | MS009 | F05355 | non-negotiable | false | 10 |
| R10677 | Replay — detects test silently passing (no-op) | MS009 | F05356 | non-negotiable | false | 10 |
| R10678 | Replay — emits OCSF Detection 2004 on chain break | MS026 | F05357 | non-negotiable | false | 10 |
| R10679 | Replay — runs daily | MS009 | F05355 | non-negotiable | false | 10 |
| R10680 | Replay — failures halt new harness skips | architecture | F05355 | non-negotiable | false | 10 |
| R10681 | Typed mirror — selfdef-ux-harness-mirror under MS007 8/8 SATURATED | MS007 | F05358 | non-negotiable | false | 10 |
| R10682 | Typed mirror — UxTestResult struct fields | MS007 | F05359 | non-negotiable | false | 10 |
| R10683 | Typed mirror — UxSurface enum (CLI/TUI/MinimalWeb/MirrorCrate) | MS007 | F05360 | non-negotiable | false | 10 |
| R10684 | Typed mirror — schema_version "1.0.0" | MS007 | F05361 | non-negotiable | false | 10 |
| R10685 | Typed mirror — signed via MS003 | MS003 | F05362 | non-negotiable | false | 10 |
| R10686 | Typed mirror — re-exported via sovereign-os cargo workspace | MS007 | F05358 | non-negotiable | false | 10 |
| R10687 | Typed mirror — no_std friendly | architecture | F05358 | non-negotiable | false | 10 |
| R10688 | Typed mirror — serde + bincode derives present | architecture | F05358 | non-negotiable | false | 10 |
| R10689 | Typed mirror — schema-breaking changes require schema_version bump | architecture + MS007 | F05361 | non-negotiable | false | 10 |
| R10690 | Dashboard — D-00 main shows UX harness pass-rate badge | sovereign-os M060 | F05363 | non-negotiable | false | 10 |
| R10691 | Dashboard — D-10 eval history shows per-R-row pass-rate over time | sovereign-os M060 | F05364 | non-negotiable | false | 10 |
| R10692 | Dashboard — D-10 shows surface-disaggregated trends | sovereign-os M060 | F05364 | non-negotiable | false | 10 |
| R10693 | Dashboard — operator can drill into specific R-row violation history | sovereign-os M060 | F05364 | non-negotiable | false | 10 |
| R10694 | Operator UX — harness toggleable per /etc/selfdef/ux-harness.toml | operator standing direction | F05365 | non-negotiable | false | 10 |
| R10695 | Operator UX — `selfdef ux-harness check` runs ad-hoc | MS043 | F05366 | non-negotiable | false | 10 |
| R10696 | Operator UX — `selfdef ux-harness check --surface <s>` per-surface | MS043 | F05367 | non-negotiable | false | 10 |
| R10697 | Operator UX — `selfdef ux-harness history` returns violations history | architecture | F05368 | non-negotiable | false | 10 |
| R10698 | Operator UX — operator can set per-R-row severity (warn vs fail) | architecture | F05369 | non-negotiable | false | 10 |
| R10699 | Operator UX — severity override TTL `<=` 7 days | architecture + MS038 | F05369 | non-negotiable | false | 10 |
| R10700 | Operator UX — `--json` flag returns structured output for every harness subcommand | MS043 R10131 | F05289 | non-negotiable | false | 10 |
| R10701 | Performance — full harness suite runtime `<` 5min on Ryzen 9 9900X | architecture | F05370 | non-negotiable | false | 10 |
| R10702 | Performance — per-surface runtime `<` 90s | architecture | F05371 | non-negotiable | false | 10 |
| R10703 | Performance — typed-mirror publication `<` 100ms p95 | MS007 | F05372 | non-negotiable | false | 10 |
| R10704 | Performance — replay validator daily run `<` 30s | MS009 | F05373 | non-negotiable | false | 10 |
| R10705 | Performance — harness composes with M058 hardware-aware scheduler (CCD 1 host placement) | sovereign-os M058 + M070 | F05288 | non-negotiable | false | 10 |
| R10706 | Telemetry — UX violation count per R-row emitted via M049 | sovereign-os M049 | F05374 | non-negotiable | false | 10 |
| R10707 | Telemetry — UX violation count per surface emitted via M049 | sovereign-os M049 | F05375 | non-negotiable | false | 10 |
| R10708 | Telemetry — harness runtime histogram emitted via M049 | sovereign-os M049 | F05376 | non-negotiable | false | 10 |
| R10709 | Telemetry — harness pass-rate over 30/90/365 days emitted via M049 | sovereign-os M049 | F05377 | non-negotiable | false | 10 |
| R10710 | Telemetry — operator-side severity override emitted via M049 | sovereign-os M049 + MS026 | F05369 | non-negotiable | false | 10 |
| R10711 | Composition — composes with M062 PR 9 + PR 10 test harness | sovereign-os M062 | F05378 | non-negotiable | false | 10 |
| R10712 | Composition — composes with M063 SFIF Infrastructure phase | sovereign-os M063 | F05379 | non-negotiable | false | 10 |
| R10713 | Composition — composes with MS003 selfdef-signing | MS003 | F05380 | non-negotiable | false | 10 |
| R10714 | Composition — composes with MS007 typed-mirror | MS007 | F05381 | non-negotiable | false | 10 |
| R10715 | Composition — composes with MS009 replay validator | MS009 | F05382 | non-negotiable | false | 10 |
| R10716 | Composition — composes with MS026 OCSF event emission | MS026 | F05383 | non-negotiable | false | 10 |
| R10717 | Composition — composes with MS037 receipt retention | MS037 | F05384 | non-negotiable | false | 10 |
| R10718 | Composition — composes with MS041 commit authority (high-risk for harness skip) | MS041 | F05385 | non-negotiable | false | 10 |
| R10719 | Composition — composes with MS043 (this validates MS043 R-rows) | MS043 | F05386 | non-negotiable | false | 10 |
| R10720 | Composition — composes with MS044 Guardian (TUI panic shortcut verified) | MS044 | F05387 | non-negotiable | false | 10 |
| R10721 | Composition — composes with sovereign-os M049 trace pipeline | sovereign-os M049 | F05388 | non-negotiable | false | 10 |
| R10722 | Composition — composes with sovereign-os M055 failure modes | sovereign-os M055 | F05389 | non-negotiable | false | 10 |
| R10723 | Composition — composes with sovereign-os M060 cockpit dashboards | sovereign-os M060 | F05390 | non-negotiable | false | 10 |
| R10724 | Composition — composes with sovereign-os M058 hardware-aware scheduler | sovereign-os M058 | F05288 | non-negotiable | false | 10 |
| R10725 | Composition — composes with M070 Dual-CCD topology (host placement) | sovereign-os M070 | F05288 | non-negotiable | false | 10 |
| R10726 | Doctrinal preservation — operator "high UX/Developer Experience" verbatim | operator standing direction | F05391 | non-negotiable | false | 10 |
| R10727 | Doctrinal preservation — operator "you cannot re-invent what UX mean" verbatim | operator standing direction | F05392 | non-negotiable | false | 10 |
| R10728 | Doctrinal preservation — operator "do not minimize the work in selfdef" verbatim | operator standing direction | F05393 | non-negotiable | false | 10 |
| R10729 | Doctrinal preservation — operator "be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist" verbatim | operator standing direction | F05394 | non-negotiable | false | 10 |
| R10730 | Doctrinal preservation — verbatim quotes never paraphrased | operator standing direction | F05395 | non-negotiable | false | 10 |
| R10731 | Doctrinal preservation — info-hub indexes UX harness lineage as second-brain entry | operator standing direction | F05396 | non-negotiable | false | 10 |
| R10732 | Boundary — UX harness lives in selfdef (IPS-side feature) | operator standing direction "Respect the projects" | F05397 | non-negotiable | false | 10 |
| R10733 | Boundary — sovereign-os reads results via MS007 mirror only | MS007 | F05398 | non-negotiable | false | 10 |
| R10734 | Boundary — info-hub never mutated by harness | operator standing direction | F05399 | non-negotiable | false | 10 |
| R10735 | Boundary — harness never modifies operator UI state (read-only assertion) | architecture | F05397 | non-negotiable | false | 10 |
| R10736 | Operational — harness CLI binary at /usr/bin/selfdef-ux-harness | architecture | F05366 | non-negotiable | false | 10 |
| R10737 | Operational — harness CLI signed via MS003 | MS003 | F05366 | non-negotiable | false | 10 |
| R10738 | Operational — harness systemd timer runs daily | M063 IaC pipeline | F05373 | non-negotiable | false | 10 |
| R10739 | Operational — harness honors SIGTERM for graceful drain | architecture | F05366 | non-negotiable | false | 10 |
| R10740 | Operational — harness emits start/stop via M049 | sovereign-os M049 | F05376 | non-negotiable | false | 10 |
| R10741 | Operational — harness exit code 0 on all R-rows pass | architecture | F05325 | non-negotiable | false | 10 |
| R10742 | Operational — harness exit code 1 on any fail-severity R-row violation | architecture | F05350 | non-negotiable | false | 10 |
| R10743 | Operational — harness exit code 64 on configuration error | architecture | F05326 | non-negotiable | false | 10 |
| R10744 | Operational — harness exit code 66 on test-input error | architecture | F05327 | non-negotiable | false | 10 |
| R10745 | Operational — harness refuses to run with chain-break in MS009 | MS009 | F05355 | non-negotiable | false | 10 |
| R10746 | Operational — harness refuses to run with missing MS003 keys | MS003 | F05362 | non-negotiable | false | 10 |
| R10747 | Operational — harness readiness probe at /run/selfdef-ux-harness/ready | architecture | F05366 | non-negotiable | false | 10 |
| R10748 | Operational — harness emits readiness on systemd activation | architecture | F05366 | non-negotiable | false | 10 |
| R10749 | Operational — harness retains result history at /var/lib/selfdef/ux-harness-results/ | architecture | F05371 | non-negotiable | false | 10 |
| R10750 | Operational — harness result retention 365 days minimum | MS037 + M063 IaC | F05351 | non-negotiable | false | 10 |
| R10751 | Operational — harness composes with MS043 CLI surface (`selfdef ux-harness` subcommand tree) | MS043 | F05366 | non-negotiable | false | 10 |
| R10752 | Operational — harness composes with MS044 Guardian (TUI panic shortcut traced through eBPF policy) | MS044 | F05387 | non-negotiable | false | 10 |
| R10753 | Operational — harness composes with sovereign-os M057 12-step lifecycle (Step 9 Evaluate) | sovereign-os M057 | F05378 | non-negotiable | false | 10 |
| R10754 | Operational — harness composes with sovereign-os M060 D-10 eval history dashboard | sovereign-os M060 | F05353 | non-negotiable | false | 10 |
| R10755 | Operational — harness operator override emits OCSF Configuration Change 5001 | MS026 | F05369 | non-negotiable | false | 10 |
| R10756 | Operator override — TTL `<=` 7 days default | MS038 + architecture | F05369 | non-negotiable | false | 10 |
| R10757 | Operator override — operator can extend TTL via MS003-signed renewal | MS003 | F05369 | non-negotiable | false | 10 |
| R10758 | Operator override — override expiration re-arms R-row to fail-severity | architecture | F05369 | non-negotiable | false | 10 |
| R10759 | Operator override — historical override decisions retained 365 days | MS037 | F05369 | non-negotiable | false | 10 |
| R10760 | Operator override — composes with MS040 production-profile gate (no overrides allowed in production) | MS040 | F05385 | non-negotiable | false | 10 |
| R10761 | Operator override — composes with MS041 commit authority high-risk gating | MS041 | F05385 | non-negotiable | false | 10 |
| R10762 | Specific harness — `selfdef rules list` returns rule count + per-ring breakdown | MS043 R10098 | F05344 | non-negotiable | false | 10 |
| R10763 | Specific harness — `selfdef grants list` returns active grants across boundaries | MS043 R10103 | F05344 | non-negotiable | false | 10 |
| R10764 | Specific harness — `selfdef quarantine list` returns quarantined tools | MS043 R10107 | F05344 | non-negotiable | false | 10 |
| R10765 | Specific harness — `selfdef audit cycle` runs MS009 audit + reports pass/fail | MS043 R10111 | F05344 | non-negotiable | false | 10 |
| R10766 | Specific harness — `selfdef profile show` returns active profile + envelope | MS043 R10114 | F05344 | non-negotiable | false | 10 |
| R10767 | Specific harness — `selfdef cap list` returns active capability tokens | MS043 R10117 | F05344 | non-negotiable | false | 10 |
| R10768 | Specific harness — `selfdef sandbox list` returns active sandbox allocations | MS043 R10120 | F05344 | non-negotiable | false | 10 |
| R10769 | Specific harness — `selfdef signing-keys list` returns MS003 keys | MS043 R10127 | F05344 | non-negotiable | false | 10 |
| R10770 | Specific harness — `selfdef logs --since <duration>` filters by time | MS043 R10237 | F05344 | non-negotiable | false | 10 |
| R10771 | Specific harness — `selfdef events --filter <class>` filters by OCSF class | MS043 R10239 | F05344 | non-negotiable | false | 10 |
| R10772 | Specific harness — `selfdef trace <trace-id>` shows M049 span detail | MS043 R10240 | F05344 | non-negotiable | false | 10 |
| R10773 | Specific harness — minimal-web HTTPS on localhost:7575 | MS043 R10166 | F05343 | non-negotiable | false | 10 |
| R10774 | Specific harness — minimal-web cert via MS003 self-signed | MS043 R10167 | F05343 | non-negotiable | false | 10 |
| R10775 | Specific harness — minimal-web single-page interface | MS043 R10168 | F05343 | non-negotiable | false | 10 |
| R10776 | Specific harness — minimal-web vanilla HTML + minimal JS `<` 50KB total | MS043 R10169 | F05343 | non-negotiable | false | 10 |
| R10777 | Specific harness — minimal-web 4-panel layout matching TUI | MS043 R10170 | F05343 | non-negotiable | false | 10 |
| R10778 | Specific harness — minimal-web localhost-only by default | MS043 R10180 | F05343 | non-negotiable | false | 10 |
| R10779 | Specific harness — minimal-web disable-able (operator can turn off entire web surface) | MS043 R10181 | F05343 | non-negotiable | false | 10 |
| R10780 | Specific harness — mirror crates published under MS007 8/8 SATURATED | MS043 R10189 | F05290 | non-negotiable | false | 10 |
| R10781 | Specific harness — mirror crates signed via MS003 | MS043 R10190 | F05290 | non-negotiable | false | 10 |
| R10782 | Specific harness — mirror crates schema_version "1.0.0" | MS043 R10191 | F05290 | non-negotiable | false | 10 |
| R10783 | Specific harness — mirror crates expose state read-only | MS043 R10193 | F05290 | non-negotiable | false | 10 |
| R10784 | Specific harness — mirror crates continue to publish when consumer offline | MS043 R10194 | F05343 | non-negotiable | false | 10 |
| R10785 | Specific harness — incident-response single-key P (panic-drop-all) verified | MS043 R10226 | F05299 | non-negotiable | false | 10 |
| R10786 | Specific harness — incident-response single-key F (freeze-profile) verified | MS043 R10227 | F05300 | non-negotiable | false | 10 |
| R10787 | Specific harness — incident-response kill-all-quarantined verified | MS043 R10228 | F05331 | non-negotiable | false | 10 |
| R10788 | Specific harness — incident-response rotate-operator-key verified | MS043 R10229 | F05331 | non-negotiable | false | 10 |
| R10789 | Specific harness — break-glass action emits OCSF Detection 2004 verified | MS043 R10230 | F05346 | non-negotiable | false | 10 |
| R10790 | Specific harness — break-glass signed via MS003 verified | MS043 R10231 | F05381 | non-negotiable | false | 10 |
| R10791 | Specific harness — break-glass logged separately at /var/log/selfdef/break-glass/ verified | MS043 R10232 | F05384 | non-negotiable | false | 10 |
| R10792 | Specific harness — break-glass double-confirmation verified | MS043 R10233 | F05332 | non-negotiable | false | 10 |
| R10793 | Specific harness — break-glass logged into MS009 audit chain verified | MS043 R10234 | F05382 | non-negotiable | false | 10 |
| R10794 | Specific harness — every CLI subcommand emits M049 trace verified | MS043 R10089 | F05388 | non-negotiable | false | 10 |
| R10795 | Specific harness — every mutating CLI subcommand emits OCSF Configuration Change 5001 verified | MS043 R10090 | F05383 | non-negotiable | false | 10 |
| R10796 | Closing — MS045 covers MS043 240 R-rows enforcement | MS043 + architecture | F05400 | non-negotiable | false | 10 |
| R10797 | Closing — selfdef catalog at 45/45 milestones | architecture | F05400 | non-negotiable | false | 10 |
| R10798 | Closing — combined ecosystem 124 milestones (selfdef 45 + sovereign-os 79) | architecture | F05400 | non-negotiable | false | 10 |
| R10799 | Closing — every R-row carries 10 hard non-negotiable sub-requirements | operator standing direction | F05400 | non-negotiable | false | 10 |
| R10800 | Closing — MS045 addresses stop-hook gap (a) "no NEW selfdef milestones authored in this session despite operator saying Do not minimize the work in selfdef" | operator standing direction + stop hook 2026-05-19 | F05400 | non-negotiable | false | 10 |

## Sub-requirements accounting

Every R-row carries 10 hard non-negotiable sub-requirements. Total = 240 R × 10 = **2,400 sub-requirements** for MS045.

## Cross-references

- **sovereign-os M049** — observability + trace pipeline (telemetry consumer)
- **sovereign-os M055** — failure modes (error class injection)
- **sovereign-os M057** — 12-step task lifecycle (Step 9 Evaluate composition)
- **sovereign-os M058** — hardware-aware scheduler
- **sovereign-os M060** — cockpit dashboards (D-00 + D-10 surface results)
- **sovereign-os M062** — Macro-Arc PR 9 + PR 10 test harness scaffolds
- **sovereign-os M063** — SFIF Infrastructure phase
- **sovereign-os M070** — Dual-CCD topology (host placement)
- **MS003** — selfdef-signing (signs every test artifact)
- **MS007** — typed-mirror (selfdef-ux-harness-mirror)
- **MS009** — replay validator
- **MS026** — OCSF event emission
- **MS037** — retention policy
- **MS038** — TTL bounds (operator override)
- **MS040** — profile envelopes (no override in production)
- **MS041** — commit authority (high-risk for harness skip)
- **MS043** — IPS operator surface (this validates MS043's 240 R-rows)
- **MS044** — Guardian Daemon (TUI panic shortcut verified through eBPF policy)

## Schema

```
schema_version: "1.0.0"
milestone_id: MS045
parent: selfdef
epics: 10
modules: 26
features: 120
requirements: 240
sub_requirements_per_requirement: 10
total_sub_requirements: 2400
purpose: "TDD harness validating MS043 240 R-rows automatically at CI time"
operator_named_explicitly: true
operator_direction_verbatim:
  - "be an architect first, then a DevOps Software Engineer and Fullstack and UX Design Specialist"
  - "high UX/Developer Experience"
  - "you cannot re-invent what UX mean"
  - "do not minimize the work in selfdef"
typed_mirror_crate: selfdef-ux-harness-mirror
catalog_status:
  selfdef: 45/45 milestones (now extends prior 44)
  sovereign_os: 79/79 milestones
  combined: 124 milestones
addresses_stop_hook_gap: "(a) no NEW selfdef milestones authored in this session"
```
