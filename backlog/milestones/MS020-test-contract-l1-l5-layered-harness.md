# MS020 — Test contract — L1–L5 layered harness

> Parent: `backlog/milestones/INDEX.md` row MS020.
> Source: `docs/sdd/005-test-contract.md` (493 lines; status=implemented; owner=audit team; last updated 2026-05-13; closes F-2026-082 + F-2026-030 + F-2026-031 + F-2026-032 + F-2026-033 + F-2026-034 + F-2026-035 + F-2026-036) + `docs/dev/test-contract.md` runbook + 6 implementation Test-N PRs (collapsed to one per operator's "big chunks" steer). Operator-level naming "L1–L5 layered harness" frames the SDD's 4-category content (Category 1 Translation / Category 2 Pipeline / Category 3 Module-script / Category 4 Seam) plus the underlying 3 test surfaces (in-source unit / per-crate integration / replay corpora). All entries below extract verbatim. No invention.

## Epics (E0201–E0210)

| Epic ID | Phrase | Source |
|---|---|---|
| E0201 | SDD-005 mission — test contract for the daemon ↔ module seam; closes F-2026-082 parent SDD-debt + 7 implementation findings (F-2026-030..036); 6 Test-N PRs collapsed to single PR per operator's "big chunks" steer | SDD-005 § header + § Implementation status |
| E0202 | Problem — Phase 1 audit PR retrospective (docs/review/70-recent-prs-audit.md) called out recurring pattern across PRs #21/#22/#23: "tests verified the unit, not the flow"; AI-machine track shipped without end-to-end test that would have caught I-007 + I-008; F-2026-082 SDD-debt finding tracks pattern | SDD-005 § Problem |
| E0203 | 7 missing tests / loose assertions — F-2026-030 (module dry-run-negative not asserted) + F-2026-031 (Prometheus substring match not format strict) + F-2026-032 (/metrics no read-cap test) + F-2026-033 (correlator no SIGHUP-while-processing test) + F-2026-034 (selfdef-store no concurrent-insert or crash-recovery test) + F-2026-035 (selfdef-nats no real-broker round-trip; JetStream durability unverified) + F-2026-036 (selfdef-collector-tetragon no isolation test) | SDD-005 § Problem |
| E0204 | 4 Goals + 4 Non-goals — Goals: (1) define what "integration-tested" means for 6 flagged seams; (2) small set of test categories with explicit contracts; (3) patterns for 6 missing tests; (4) avoid re-litigating per-test design in future PRs (SDD is appeal authority). Non-goals: general-purpose test-harness rewrite / coverage target (% not a contract) / property-testing or fuzzing (separate scope) / performance/load tests (separate scope) | SDD-005 § Goals + § Non-goals |
| E0205 | 6-term glossary — Unit test (`#[cfg(test)] mod tests` same crate) + Integration test (`crates/<name>/tests/*.rs` public API) + Daemon integration test (`crates/selfdef-daemon/tests/` multi-crate end-to-end) + Module integration test (`crates/selfdef-cli/tests/module_*.rs` spawns bash) + Seam (place where data crosses crate/module/process boundary; 6 audit-flagged) + Hermetic (own tempdir; no host services beyond explicit shims) | SDD-005 § Glossary |
| E0206 | 3 Test surfaces today — (1) in-source unit tests (`#[cfg(test)] mod tests`; dominant style; selfdef-core snapshot+property; selfdef-bus lossy+multi-subscriber); (2) per-crate integration tests (`tests/*.rs`; selfdef-cli 12 files / selfdef-daemon 8 / selfdef-api 1 / selfdef-correlator 1 / selfdef-core 2; 15 crates have ZERO); (3) replay corpora (`tests/replay/<source>/*.jsonl`; sigma discovery-style walking + ad-hoc collector loading); WHAT'S MISSING — written contract for each surface's responsibility | SDD-005 § Current state |
| E0207 | 3 Alternatives + recommended C — A (write categorisation; revise existing files to match; massive scope); B (just write 7 missing tests; ad-hoc; doesn't address F-2026-082 parent); C RECOMMENDED (contract + patterns + reference implementations; addresses both F-2026-082 parent + 7 implementation findings) | SDD-005 § Design alternatives + § Recommended design |
| E0208 | D-1 — 4 Test Categories: Cat 1 Translation (source-crate `#[cfg(test)]` or `tests/translation.rs`; every translation branch has positive test + tolerance test); Cat 2 Pipeline (`crates/selfdef-daemon/tests/`; minimal in-process pipeline bus+collector+correlator+responder+store; every daemon "promise" exercised); Cat 3 Module-script (`crates/selfdef-cli/tests/module_*.rs`; bash against install/*.sh hermetic tempdir; both dry-run-negative + live-positive asserted); Cat 4 Seam (`crates/selfdef-daemon/tests/seam_*.rs`; two-side behaviour at seam; every audit-flagged seam has ≥1 seam test); categories overlap deliberately ("at-least-one-of" coverage, not exclusive categorisation) | SDD-005 § D-1 |
| E0209 | D-2 — 3 Shared Patterns: D-2a `dry_run_must_be_a_noop` wrapper (`crates/selfdef-cli/tests/common/mod.rs`; tempdir snapshot before/after + byte-equality; closes F-2026-030); D-2b Prometheus exposition parser (`m12_api.rs` strict Content-Type match + tuple parse + dedup-key check; closes F-2026-031 + F-2026-032); D-2c real-broker NATS fixture (`crates/selfdef-nats/tests/integration.rs`; #[ignore]-gated if nats-server not on PATH; closes F-2026-035) | SDD-005 § D-2 |
| E0210 | D-3 + D-4 + D-5 + 6 shipped Test-N + Test plan + open Q-A/B/C + Appendix — Test-1 dry-run-negative helper + Test-2 Prometheus parser + Test-3 real-broker NATS fixture + Test-4 correlator hot-reload (SIGHUP-under-traffic atomicity + non-destructive failure path) + Test-5 store concurrency + crash-recovery (8 tasks × 200 inserts/handle + crash-and-reopen + composition) + Test-6 Tetragon collector isolation (10 translation tests + 3 tolerance + `pub fn translate_line`); D-4 SDD-001 AI-machine end-to-end test is Cat 2 + Cat 4; D-5 contract lives in `docs/dev/test-contract.md`; meta-test plan 8 checks; Q-A/B/C all answered 2026-05-15 (D-016/017/018); appendix interactions with SDD-001/002/003/004 | SDD-005 § Implementation status + § D-3 + § D-4 + § D-5 + § Test plan + § Open questions + § Appendix |

## Modules (M00499–M00524)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00499 | F-2026-082 SDD-debt parent — "Tests verified the unit, not the flow. Need a design doc on what 'integration-tested' means at the daemon ↔ module seam." | SDD-005 § Problem | E0202 |
| M00500 | F-2026-030 — module dry-run-negative not asserted (regression making dry-run mutate state passes silently) | SDD-005 § Problem | E0203 |
| M00501 | F-2026-031 — `/metrics` test substring-match (Content-Type starts_with + body substring presence; format violations could pass) | SDD-005 § Problem | E0203 |
| M00502 | F-2026-032 — no test asserts `/metrics` accepts Read-only bearer token | SDD-005 § Problem | E0203 |
| M00503 | F-2026-033 — no SIGHUP-while-processing test for correlator (hot-reload claim from ARCHITECTURE.md unverified) | SDD-005 § Problem | E0203 |
| M00504 | F-2026-034 — selfdef-store has no concurrent-insert or crash-recovery test | SDD-005 § Problem | E0203 |
| M00505 | F-2026-035 — selfdef-nats has no real-broker round-trip test (JetStream durability promises unverified) | SDD-005 § Problem | E0203 |
| M00506 | F-2026-036 — selfdef-collector-tetragon has no isolation test (every translation goes through daemon tests only) | SDD-005 § Problem | E0203 |
| M00507 | Test surface 1 — in-source unit tests (`#[cfg(test)] mod tests`; dominant style) | SDD-005 § Current state | E0206 |
| M00508 | Test surface 2 — per-crate integration tests (`tests/*.rs` per crate; selfdef-cli 12 files; 15 crates have zero) | SDD-005 § Current state | E0206 |
| M00509 | Test surface 3 — replay corpora (`tests/replay/<source>/*.jsonl`) | SDD-005 § Current state | E0206 |
| M00510 | Category 1 — Translation tests (source crate `#[cfg(test)] mod tests` OR `crates/<name>/tests/translation.rs`; positive + tolerance per branch) | SDD-005 § D-1 | E0208 |
| M00511 | Category 2 — Pipeline tests (`crates/selfdef-daemon/tests/`; minimal in-process pipeline; every daemon-side promise exercised) | SDD-005 § D-1 | E0208 |
| M00512 | Category 3 — Module-script tests (`crates/selfdef-cli/tests/module_*.rs`; spawn bash on hermetic tempdir; dry-run-negative + live-positive asserted) | SDD-005 § D-1 | E0208 |
| M00513 | Category 4 — Seam tests (`crates/selfdef-daemon/tests/seam_*.rs`; two-side behaviour; every audit-flagged seam ≥1 test) | SDD-005 § D-1 | E0208 |
| M00514 | D-2a — `crates/selfdef-cli/tests/common/mod.rs` with `snapshot_tree` + `assert_tree_unchanged` (hand-rolled length+first-32-bytes fingerprint; no hash-crate dep) | SDD-005 § D-2a + § Implementation status | E0209 |
| M00515 | D-2b — `mod prom` in `crates/selfdef-api/tests/m12_api.rs` (Sample tuples + dedup-key check + no comment shapes outside HELP/TYPE) | SDD-005 § D-2b + § Implementation status | E0209 |
| M00516 | D-2c — `crates/selfdef-nats/tests/integration.rs` (#[ignore]-gated; spawns real nats-server on free port; round-trip + JetStream stream/consumer setup) | SDD-005 § D-2c + § Implementation status | E0209 |
| M00517 | Test-4 — `crates/selfdef-correlator/tests/hot_reload.rs` (correlator_swaps_rules_atomically_under_live_traffic + correlator_load_rules_keeps_prior_set_on_parse_failure) | SDD-005 § Implementation status | E0210 |
| M00518 | Test-5 — `crates/selfdef-store/tests/concurrent.rs` (concurrent_inserts_do_not_lose_rows 8tasks×200 inserts + crash_recovery_surfaces_every_committed_insert + composition test) | SDD-005 § Implementation status | E0210 |
| M00519 | Test-6 — `crates/selfdef-collector-tetragon/tests/translation.rs` (10 translation tests + 3 tolerance branches; `pub fn TetragonCollector::translate_line(&str) -> Option<Event>` added; `process_line` is thin publisher) | SDD-005 § Implementation status | E0210 |
| M00520 | D-5 — `docs/dev/test-contract.md` (under `docs/src/dev/` to appear in mdbook); 4 categories + 3 shared patterns as operator-authoring guidance | SDD-005 § D-5 + § Implementation status | E0210 |
| M00521 | Meta-test plan — 8 checks (test-contract.md exists / common/mod.rs helper / m12_api.rs uses parser / nats integration.rs #[ignore]-gated / correlator hot_reload.rs / store concurrent.rs / collector-tetragon translation.rs / 6 PRs cite SDD-005) | SDD-005 § Test plan | E0210 |
| M00522 | Q-A answer (D-016, 2026-05-15) — pipeline + seam test required for modules introducing new event source; NOT required for purely passive modules | SDD-005 § Open questions Q-A | E0210 |
| M00523 | Q-B answer (D-017, 2026-05-15) — test-contract doc goes under `docs/src/dev/` (mdbook-visible to contributors); both locations acceptable | SDD-005 § Open questions Q-B | E0210 |
| M00524 | Q-C answer (D-018, 2026-05-15) — every Phase-N audit re-asks "do these categories still match the codebase?" + surfaces contract drift as findings | SDD-005 § Open questions Q-C | E0210 |

## Features (F02281–F02400)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F02281 | SDD-005 status = implemented | SDD-005 § header | E0201 | composite | false |
| F02282 | SDD-005 closes F-2026-082 (SDD-debt parent) | SDD-005 § header | M00499 | composite | false |
| F02283 | SDD-005 closes F-2026-030 (reference adoption) | SDD-005 § header | M00500 | composite | false |
| F02284 | SDD-005 closes F-2026-031 | SDD-005 § header | M00501 | composite | false |
| F02285 | SDD-005 closes F-2026-032 | SDD-005 § header | M00502 | composite | false |
| F02286 | SDD-005 closes F-2026-033 | SDD-005 § header | M00503 | composite | false |
| F02287 | SDD-005 closes F-2026-034 | SDD-005 § header | M00504 | composite | false |
| F02288 | SDD-005 closes F-2026-035 (#[ignore]-gated) | SDD-005 § header | M00505 | composite | false |
| F02289 | SDD-005 closes F-2026-036 | SDD-005 § header | M00506 | composite | false |
| F02290 | 6 Test-N PRs collapsed to single PR per operator's "big chunks" steer | SDD-005 § Implementation status | E0201 | composite | false |
| F02291 | F-2026-082 statement — "Tests verified the unit, not the flow. Need a design doc on what 'integration-tested' means at the daemon ↔ module seam." | SDD-005 § Problem | M00499 | composite | false |
| F02292 | Phase 1 audit PR retrospective (docs/review/70-recent-prs-audit.md) called out recurring pattern across PRs #21, #22, #23 | SDD-005 § Problem | E0202 | composite | false |
| F02293 | "Tests verified the unit, not the flow" | SDD-005 § Problem | E0202 | composite | false |
| F02294 | integrity-sentinel emit test wrote to a tempdir | SDD-005 § Problem | E0202 | composite | false |
| F02295 | /metrics integration test asserted substring matches | SDD-005 § Problem | E0202 | composite | false |
| F02296 | AI-machine track shipped without end-to-end test that would have caught I-007 + I-008 | SDD-005 § Problem | E0202 | composite | false |
| F02297 | F-2026-030 — every module_*.rs test runs apply.sh with SELFDEF_DRY_RUN=1 but never asserts zero side effects | SDD-005 § Problem | M00500 | composite | false |
| F02298 | F-2026-030 — regression making dry-run mutate state passes silently | SDD-005 § Problem | M00500 | composite | false |
| F02299 | F-2026-031 — m12_api.rs's /metrics test asserts Content-Type with `starts_with("text/plain")` | SDD-005 § Problem | M00501 | composite | false |
| F02300 | F-2026-031 — body asserted with substring presence | SDD-005 § Problem | M00501 | composite | false |
| F02301 | F-2026-031 — format violations could pass | SDD-005 § Problem | M00501 | composite | false |
| F02302 | F-2026-032 — no test asserts /metrics accepts Read-only bearer token | SDD-005 § Problem | M00502 | composite | false |
| F02303 | F-2026-033 — no SIGHUP-while-processing test for correlator | SDD-005 § Problem | M00503 | composite | false |
| F02304 | F-2026-033 — hot-reload claim from ARCHITECTURE.md is unverified | SDD-005 § Problem | M00503 | composite | false |
| F02305 | F-2026-034 — selfdef-store has no concurrent-insert test | SDD-005 § Problem | M00504 | composite | false |
| F02306 | F-2026-034 — selfdef-store has no crash-recovery test | SDD-005 § Problem | M00504 | composite | false |
| F02307 | F-2026-035 — selfdef-nats has no real-broker round-trip test | SDD-005 § Problem | M00505 | composite | false |
| F02308 | F-2026-035 — JetStream durability promises unverified | SDD-005 § Problem | M00505 | composite | false |
| F02309 | F-2026-036 — selfdef-collector-tetragon has no isolation test | SDD-005 § Problem | M00506 | composite | false |
| F02310 | F-2026-036 — every translation goes through daemon tests only | SDD-005 § Problem | M00506 | composite | false |
| F02311 | Goal 1 — define what "integration-tested" means for 6 audit-flagged seams | SDD-005 § Goals 1 | E0204 | composite | false |
| F02312 | Audit-flagged seam 1 — module ↔ daemon (eventstream JSONL) | SDD-005 § Goals 1 | E0205 | composite | false |
| F02313 | Audit-flagged seam 2 — daemon ↔ Prometheus (/metrics) | SDD-005 § Goals 1 | E0205 | composite | false |
| F02314 | Audit-flagged seam 3 — correlator hot-reload | SDD-005 § Goals 1 | E0205 | composite | false |
| F02315 | Audit-flagged seam 4 — store concurrent writes | SDD-005 § Goals 1 | E0205 | composite | false |
| F02316 | Audit-flagged seam 5 — NATS round-trip | SDD-005 § Goals 1 | E0205 | composite | false |
| F02317 | Audit-flagged seam 6 — collector isolation | SDD-005 § Goals 1 | E0205 | composite | false |
| F02318 | Goal 2 — small set of test categories with explicit contracts | SDD-005 § Goals 2 | E0204 | composite | false |
| F02319 | Goal 3 — patterns the implementation PR will use for 6 missing tests | SDD-005 § Goals 3 | E0204 | composite | false |
| F02320 | Goal 4 — avoid re-litigating per-test design in every future PR — the SDD is the appeal authority | SDD-005 § Goals 4 | E0204 | composite | false |
| F02321 | Non-goal — general-purpose test-harness rewrite | SDD-005 § Non-goals | E0204 | composite | false |
| F02322 | Non-goal — coverage target (% not a contract; contract is about WHAT is tested, not HOW MUCH) | SDD-005 § Non-goals | E0204 | composite | false |
| F02323 | Non-goal — property-testing or fuzzing strategy (separate scope) | SDD-005 § Non-goals | E0204 | composite | false |
| F02324 | Non-goal — performance / load tests (separate scope) | SDD-005 § Non-goals | E0204 | composite | false |
| F02325 | Glossary — Unit test (`#[cfg(test)] mod tests` same crate; exercises one function/type in isolation) | SDD-005 § Glossary | E0205 | composite | false |
| F02326 | Glossary — Integration test (`crates/<name>/tests/*.rs`; runs against crate's public API as downstream consumer) | SDD-005 § Glossary | E0205 | composite | false |
| F02327 | Glossary — Daemon integration test (`crates/selfdef-daemon/tests/`; spins up multiple crates in-process; end-to-end flow) | SDD-005 § Glossary | E0205 | composite | false |
| F02328 | Glossary — Module integration test (`crates/selfdef-cli/tests/module_*.rs`; spawns bash against module's install/apply.sh + check.sh + uninstall.sh) | SDD-005 § Glossary | E0205 | composite | false |
| F02329 | Glossary — Seam (place where data crosses crate/module/process boundary; audit flagged 6) | SDD-005 § Glossary | E0205 | composite | false |
| F02330 | Glossary — Hermetic (test allocates own tempdir; doesn't read/write outside; no host services beyond explicit shims) | SDD-005 § Glossary | E0205 | composite | false |
| F02331 | Test surface — in-source unit tests (dominant style) | SDD-005 § Current state | M00507 | composite | true |
| F02332 | Test surface — selfdef-core has snapshot + property tests | SDD-005 § Current state | M00507 | composite | false |
| F02333 | Test surface — selfdef-bus has lossy / multiple-subscriber tests | SDD-005 § Current state | M00507 | composite | false |
| F02334 | Test surface — per-crate integration tests | SDD-005 § Current state | M00508 | composite | true |
| F02335 | Per-crate integration — selfdef-cli has 12 files | SDD-005 § Current state | M00508 | composite | false |
| F02336 | Per-crate integration — selfdef-daemon has 8 files | SDD-005 § Current state | M00508 | composite | false |
| F02337 | Per-crate integration — selfdef-api has 1 file | SDD-005 § Current state | M00508 | composite | false |
| F02338 | Per-crate integration — selfdef-correlator has 1 file | SDD-005 § Current state | M00508 | composite | false |
| F02339 | Per-crate integration — selfdef-core has 2 files | SDD-005 § Current state | M00508 | composite | false |
| F02340 | Per-crate integration — the other 15 crates have zero | SDD-005 § Current state | M00508 | composite | false |
| F02341 | Test surface — replay corpora `tests/replay/<source>/*.jsonl` | SDD-005 § Current state | M00509 | composite | true |
| F02342 | Replay corpora — shared by daemon and per-collector tests | SDD-005 § Current state | M00509 | composite | false |
| F02343 | Replay corpora — discovery-style walking used for sigma rule tests; ad-hoc loading for collector tests | SDD-005 § Current state | M00509 | composite | false |
| F02344 | What's missing — written contract for what each surface is responsible for | SDD-005 § Current state | E0206 | composite | false |
| F02345 | Alternative A — write categorisation; revise existing test files to match | SDD-005 § Alternative A | E0207 | composite | false |
| F02346 | Alternative A con — massive scope (6 findings turn into dozens) | SDD-005 § Alternative A | E0207 | composite | false |
| F02347 | Alternative A con — low marginal value over shipping missing tests | SDD-005 § Alternative A | E0207 | composite | false |
| F02348 | Alternative A con — categorisation isn't useful if no future test is written against it | SDD-005 § Alternative A | E0207 | composite | false |
| F02349 | Alternative B — just write 7 missing tests | SDD-005 § Alternative B | E0207 | composite | false |
| F02350 | Alternative B con — doesn't address F-2026-082 parent | SDD-005 § Alternative B | E0207 | composite | false |
| F02351 | Alternative B con — 7 tests get written ad-hoc, each in own style, reinforcing helper-duplication problem F-2026-060 | SDD-005 § Alternative B | E0207 | composite | false |
| F02352 | Alternative C (recommended) — contract + patterns + reference implementations | SDD-005 § Alternative C + § Recommended design | E0207 | composite | false |
| F02353 | Alternative C — 4 test categories with explicit "what counts as enough" rule | SDD-005 § Alternative C | E0208 | composite | false |
| F02354 | Alternative C — 3 shared patterns (dry-run-negative wrapper / Prometheus parser / real-broker NATS fixture) | SDD-005 § Alternative C | E0209 | composite | false |
| F02355 | Alternative C — implementation PR ships 7 missing tests using patterns + updates existing test files | SDD-005 § Alternative C | E0210 | composite | false |
| F02356 | Alternative C addresses both F-2026-082 parent + 7 implementation findings | SDD-005 § Alternative C | E0207 | composite | false |
| F02357 | Category 1 — Translation tests | SDD-005 § D-1 Cat 1 | M00510 | composite | true |
| F02358 | Category 1 location — source crate's `#[cfg(test)] mod tests` OR `crates/<name>/tests/translation.rs` | SDD-005 § D-1 Cat 1 | M00510 | composite | false |
| F02359 | Category 1 contract — every translation branch has ≥1 positive test (input shape, expected Event field projection) | SDD-005 § D-1 Cat 1 | M00510 | composite | false |
| F02360 | Category 1 contract — ≥1 tolerance test (input shape that's malformed in documented way → no panic, logged warning) | SDD-005 § D-1 Cat 1 | M00510 | composite | false |
| F02361 | Category 2 — Pipeline tests | SDD-005 § D-1 Cat 2 | M00511 | composite | true |
| F02362 | Category 2 location — `crates/selfdef-daemon/tests/` | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02363 | Category 2 — Spins up minimal in-process pipeline of bus + collector + correlator + responder + store | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02364 | Category 2 contract — every "promise" daemon makes operator-side must be exercised by ≥1 pipeline test that would fail if regressed | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02365 | Category 2 promise example — finding lands in store with right severity | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02366 | Category 2 promise example — NotifyAction is invoked | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02367 | Category 2 promise example — API returns expected JSON | SDD-005 § D-1 Cat 2 | M00511 | composite | false |
| F02368 | Category 3 — Module-script tests | SDD-005 § D-1 Cat 3 | M00512 | composite | true |
| F02369 | Category 3 location — `crates/selfdef-cli/tests/module_*.rs` | SDD-005 § D-1 Cat 3 | M00512 | composite | false |
| F02370 | Category 3 — Spawns bash on module's install/*.sh against hermetic tempdir | SDD-005 § D-1 Cat 3 | M00512 | composite | false |
| F02371 | Category 3 contract — both dry-run-negative AND live-positive paths asserted per script | SDD-005 § D-1 Cat 3 | M00512 | composite | false |
| F02372 | Category 3 contract — dry-run-negative (SELFDEF_DRY_RUN=1 produces zero on-disk delta) | SDD-005 § D-1 Cat 3 | M00512 | composite | false |
| F02373 | Category 3 contract — live-positive (SELFDEF_DRY_RUN=0 produces documented effect) | SDD-005 § D-1 Cat 3 | M00512 | composite | false |
| F02374 | Category 4 — Seam tests | SDD-005 § D-1 Cat 4 | M00513 | composite | true |
| F02375 | Category 4 location — `crates/selfdef-daemon/tests/` OR `crates/selfdef-daemon/tests/seam_*.rs` family | SDD-005 § D-1 Cat 4 | M00513 | composite | false |
| F02376 | Category 4 — Asserts two-side behaviour at seam: writer produces what reader parses, including failure modes | SDD-005 § D-1 Cat 4 | M00513 | composite | false |
| F02377 | Category 4 contract — every seam flagged (`docs/review/40-integration-audit.md` Flows 1-6) has ≥1 seam test | SDD-005 § D-1 Cat 4 | M00513 | composite | false |
| F02378 | 4 categories overlap deliberately — at-least-one-of coverage, not exclusive categorisation | SDD-005 § D-1 | E0208 | composite | false |
| F02379 | D-2a — `dry_run_must_be_a_noop` wrapper in `crates/selfdef-cli/tests/common/mod.rs` | SDD-005 § D-2a | M00514 | composite | true |
| F02380 | D-2a — takes module's apply.sh path + fixture builder | SDD-005 § D-2a | M00514 | composite | false |
| F02381 | D-2a — runs apply with SELFDEF_DRY_RUN=1 | SDD-005 § D-2a | M00514 | composite | false |
| F02382 | D-2a — snapshots tempdir before and after | SDD-005 § D-2a | M00514 | composite | false |
| F02383 | D-2a — asserts byte-equality | SDD-005 § D-2a | M00514 | composite | false |
| F02384 | D-2a implementation — `snapshot_tree` + `assert_tree_unchanged` (hand-rolled length+first-32-bytes fingerprint; no hash-crate dep) | SDD-005 § Implementation status D-2a | M00514 | composite | false |
| F02385 | D-2a reference adoption — `endpoint_dry_run_must_be_a_noop_on_disk` in `crates/selfdef-cli/tests/module_vpn_bridge.rs` | SDD-005 § Implementation status | M00514 | composite | false |
| F02386 | D-2b — Prometheus exposition parser in `m12_api.rs` | SDD-005 § D-2b | M00515 | composite | true |
| F02387 | D-2b — Verifies Content-Type matches `text/plain; version=0.0.4; charset=utf-8` exact (not prefix) | SDD-005 § D-2b | M00515 | composite | false |
| F02388 | D-2b — Parses body into (name, labels, value) tuples | SDD-005 § D-2b | M00515 | composite | false |
| F02389 | D-2b — Asserts presence of expected metrics by name + label set | SDD-005 § D-2b | M00515 | composite | false |
| F02390 | D-2b — Asserts absence of duplicate (name, labels) keys (Prometheus invariant) | SDD-005 § D-2b | M00515 | composite | false |
| F02391 | D-2b implementation — `mod prom` in `crates/selfdef-api/tests/m12_api.rs` (Sample tuples + dedup-key check + no comment shapes outside HELP/TYPE) | SDD-005 § Implementation status D-2b | M00515 | composite | false |
| F02392 | D-2b shipped tests — `metrics_exposition_passes_format_strict_parse` + `metrics_allows_read_capability` | SDD-005 § Implementation status D-2b | M00515 | composite | true |
| F02393 | D-2c — real-broker NATS fixture | SDD-005 § D-2c | M00516 | composite | true |
| F02394 | D-2c — `crates/selfdef-nats/tests/integration.rs` | SDD-005 § D-2c | M00516 | composite | true |
| F02395 | D-2c — Skips with #[ignore] if nats-server not on PATH (CI without binary stays green) | SDD-005 § D-2c | M00516 | composite | false |
| F02396 | D-2c — When binary present, spawns it on free port, waits for it to bind | SDD-005 § D-2c | M00516 | composite | false |
| F02397 | D-2c — Runs bridge against it, publishes one event from "host A" + asserts it arrives on "host B" | SDD-005 § D-2c | M00516 | composite | false |
| F02398 | D-2c — Two Bridge instances pointed at same broker, distinct host_tag values | SDD-005 § D-2c | M00516 | composite | false |
| F02399 | D-2c — Tears down broker on test exit | SDD-005 § D-2c | M00516 | composite | false |
| F02400 | Composite — SDD-005 test contract = 4 categories (Translation / Pipeline / Module-script / Seam) + 3 shared patterns (dry-run-negative wrapper / Prometheus parser / real-broker NATS fixture) + 6 Test-N PRs covering F-2026-030..036 + meta-test plan 8 checks + open Q-A/B/C all answered 2026-05-15 + linkage to SDD-001 AI-machine end-to-end + Phase-N audit re-asks "do categories still match codebase?" + `docs/dev/test-contract.md` is the operator-authoring runbook | SDD-005 entire | E0201 + E0202 + E0203 + E0204 + E0205 + E0206 + E0207 + E0208 + E0209 + E0210 | composite | false |

## Requirements (R04561–R04800)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R04561 | SDD-005 status = implemented | SDD-005 § header | F02281 | non-negotiable | false | 10 |
| R04562 | SDD-005 closes F-2026-082 SDD-debt parent | SDD-005 § header | F02282 | non-negotiable | false | 10 |
| R04563 | SDD-005 closes F-2026-030 (reference adoption) | SDD-005 § header | F02283 | non-negotiable | false | 10 |
| R04564 | SDD-005 closes F-2026-031 | SDD-005 § header | F02284 | non-negotiable | false | 10 |
| R04565 | SDD-005 closes F-2026-032 | SDD-005 § header | F02285 | non-negotiable | false | 10 |
| R04566 | SDD-005 closes F-2026-033 | SDD-005 § header | F02286 | non-negotiable | false | 10 |
| R04567 | SDD-005 closes F-2026-034 | SDD-005 § header | F02287 | non-negotiable | false | 10 |
| R04568 | SDD-005 closes F-2026-035 (#[ignore]-gated) | SDD-005 § header | F02288 | non-negotiable | false | 10 |
| R04569 | SDD-005 closes F-2026-036 | SDD-005 § header | F02289 | non-negotiable | false | 10 |
| R04570 | 6 Test-N PRs collapsed to single PR per operator's "big chunks" steer | SDD-005 § Implementation status | F02290 | non-negotiable | false | 10 |
| R04571 | F-2026-082 — "Tests verified the unit, not the flow" | SDD-005 § Problem | F02291 | non-negotiable | false | 10 |
| R04572 | F-2026-082 — "Need a design doc on what 'integration-tested' means at the daemon ↔ module seam" | SDD-005 § Problem | F02291 | non-negotiable | false | 10 |
| R04573 | Phase 1 audit (docs/review/70-recent-prs-audit.md) called out recurring pattern across PRs #21, #22, #23 | SDD-005 § Problem | F02292 | non-negotiable | false | 10 |
| R04574 | AI-machine track shipped without end-to-end test that would have caught I-007 + I-008 | SDD-005 § Problem | F02296 | non-negotiable | false | 10 |
| R04575 | F-2026-030 — every module_*.rs test runs apply.sh with SELFDEF_DRY_RUN=1 but never asserts zero side effects | SDD-005 § Problem | F02297 | non-negotiable | false | 10 |
| R04576 | F-2026-030 — regression making dry-run mutate state passes silently | SDD-005 § Problem | F02298 | non-negotiable | false | 10 |
| R04577 | F-2026-031 — m12_api.rs /metrics test substring-matches Content-Type | SDD-005 § Problem | F02299 | non-negotiable | false | 10 |
| R04578 | F-2026-031 — body substring presence | SDD-005 § Problem | F02300 | non-negotiable | false | 10 |
| R04579 | F-2026-031 — format violations could pass | SDD-005 § Problem | F02301 | non-negotiable | false | 10 |
| R04580 | F-2026-032 — no test asserts /metrics accepts Read-only bearer token | SDD-005 § Problem | F02302 | non-negotiable | false | 10 |
| R04581 | F-2026-033 — no SIGHUP-while-processing test for correlator | SDD-005 § Problem | F02303 | non-negotiable | false | 10 |
| R04582 | F-2026-033 — hot-reload claim from ARCHITECTURE.md is unverified | SDD-005 § Problem | F02304 | non-negotiable | false | 10 |
| R04583 | F-2026-034 — selfdef-store has no concurrent-insert test | SDD-005 § Problem | F02305 | non-negotiable | false | 10 |
| R04584 | F-2026-034 — selfdef-store has no crash-recovery test | SDD-005 § Problem | F02306 | non-negotiable | false | 10 |
| R04585 | F-2026-035 — selfdef-nats has no real-broker round-trip test | SDD-005 § Problem | F02307 | non-negotiable | false | 10 |
| R04586 | F-2026-035 — JetStream durability promises unverified | SDD-005 § Problem | F02308 | non-negotiable | false | 10 |
| R04587 | F-2026-036 — selfdef-collector-tetragon has no isolation test | SDD-005 § Problem | F02309 | non-negotiable | false | 10 |
| R04588 | F-2026-036 — every translation goes through daemon tests only | SDD-005 § Problem | F02310 | non-negotiable | false | 10 |
| R04589 | Goal 1 — define what "integration-tested" means in this codebase for 6 audit-flagged seams | SDD-005 § Goals 1 | F02311 | non-negotiable | false | 10 |
| R04590 | Audit-flagged seam — module ↔ daemon (eventstream JSONL) | SDD-005 § Goals 1 | F02312 | non-negotiable | false | 10 |
| R04591 | Audit-flagged seam — daemon ↔ Prometheus (/metrics) | SDD-005 § Goals 1 | F02313 | non-negotiable | false | 10 |
| R04592 | Audit-flagged seam — correlator hot-reload | SDD-005 § Goals 1 | F02314 | non-negotiable | false | 10 |
| R04593 | Audit-flagged seam — store concurrent writes | SDD-005 § Goals 1 | F02315 | non-negotiable | false | 10 |
| R04594 | Audit-flagged seam — NATS round-trip | SDD-005 § Goals 1 | F02316 | non-negotiable | false | 10 |
| R04595 | Audit-flagged seam — collector isolation | SDD-005 § Goals 1 | F02317 | non-negotiable | false | 10 |
| R04596 | Goal 2 — small set of test categories with explicit contracts | SDD-005 § Goals 2 | F02318 | non-negotiable | false | 10 |
| R04597 | Goal 3 — patterns the implementation PR will use for 6 missing tests | SDD-005 § Goals 3 | F02319 | non-negotiable | false | 10 |
| R04598 | Goal 4 — avoid re-litigating per-test design in every future PR; SDD is appeal authority | SDD-005 § Goals 4 | F02320 | non-negotiable | false | 10 |
| R04599 | Non-goal — general-purpose test-harness rewrite | SDD-005 § Non-goals | F02321 | non-negotiable | false | 10 |
| R04600 | Non-goal — coverage % target (contract is about WHAT is tested, not HOW MUCH) | SDD-005 § Non-goals | F02322 | non-negotiable | false | 10 |
| R04601 | Non-goal — property-testing or fuzzing strategy (useful but separate scope) | SDD-005 § Non-goals | F02323 | non-negotiable | false | 10 |
| R04602 | Non-goal — performance / load tests (useful but separate scope) | SDD-005 § Non-goals | F02324 | non-negotiable | false | 10 |
| R04603 | Glossary — Unit test definition | SDD-005 § Glossary | F02325 | non-negotiable | false | 10 |
| R04604 | Glossary — Integration test definition | SDD-005 § Glossary | F02326 | non-negotiable | false | 10 |
| R04605 | Glossary — Daemon integration test definition | SDD-005 § Glossary | F02327 | non-negotiable | false | 10 |
| R04606 | Glossary — Module integration test definition | SDD-005 § Glossary | F02328 | non-negotiable | false | 10 |
| R04607 | Glossary — Seam definition | SDD-005 § Glossary | F02329 | non-negotiable | false | 10 |
| R04608 | Glossary — Hermetic definition | SDD-005 § Glossary | F02330 | non-negotiable | false | 10 |
| R04609 | Test surface 1 — in-source unit tests (`#[cfg(test)] mod tests`) is dominant style | SDD-005 § Current state | F02331 | non-negotiable | false | 10 |
| R04610 | Test surface 1 — selfdef-core has snapshot + property tests | SDD-005 § Current state | F02332 | non-negotiable | false | 10 |
| R04611 | Test surface 1 — selfdef-bus has lossy + multiple-subscriber tests | SDD-005 § Current state | F02333 | non-negotiable | false | 10 |
| R04612 | Test surface 2 — per-crate integration tests (`tests/*.rs`) | SDD-005 § Current state | F02334 | non-negotiable | false | 10 |
| R04613 | Per-crate integration — selfdef-cli has 12 files | SDD-005 § Current state | F02335 | non-negotiable | false | 10 |
| R04614 | Per-crate integration — selfdef-daemon has 8 files | SDD-005 § Current state | F02336 | non-negotiable | false | 10 |
| R04615 | Per-crate integration — selfdef-api has 1 file | SDD-005 § Current state | F02337 | non-negotiable | false | 10 |
| R04616 | Per-crate integration — selfdef-correlator has 1 file | SDD-005 § Current state | F02338 | non-negotiable | false | 10 |
| R04617 | Per-crate integration — selfdef-core has 2 files | SDD-005 § Current state | F02339 | non-negotiable | false | 10 |
| R04618 | Per-crate integration — other 15 crates have zero integration tests | SDD-005 § Current state | F02340 | non-negotiable | false | 10 |
| R04619 | Test surface 3 — replay corpora (`tests/replay/<source>/*.jsonl`) | SDD-005 § Current state | F02341 | non-negotiable | false | 10 |
| R04620 | Replay corpora shared by daemon and per-collector tests | SDD-005 § Current state | F02342 | non-negotiable | false | 10 |
| R04621 | Replay corpora — discovery-style walking used for sigma rule tests | SDD-005 § Current state | F02343 | non-negotiable | false | 10 |
| R04622 | Replay corpora — ad-hoc loading for collector tests | SDD-005 § Current state | F02343 | non-negotiable | false | 10 |
| R04623 | What's missing — written contract for what each surface is responsible for | SDD-005 § Current state | F02344 | non-negotiable | false | 10 |
| R04624 | Alternative A (rejected) — write test categorisation, revise existing tests | SDD-005 § Alternative A | F02345 | non-negotiable | false | 10 |
| R04625 | Alternative A con — massive scope; 6 findings turn into dozens | SDD-005 § Alternative A | F02346 | non-negotiable | false | 10 |
| R04626 | Alternative A con — low marginal value over shipping missing tests | SDD-005 § Alternative A | F02347 | non-negotiable | false | 10 |
| R04627 | Alternative A con — categorisation isn't useful if no future test is written against it | SDD-005 § Alternative A | F02348 | non-negotiable | false | 10 |
| R04628 | Alternative B (rejected) — just write 7 missing tests | SDD-005 § Alternative B | F02349 | non-negotiable | false | 10 |
| R04629 | Alternative B con — doesn't address F-2026-082 parent | SDD-005 § Alternative B | F02350 | non-negotiable | false | 10 |
| R04630 | Alternative B con — 7 tests get written ad-hoc, each in own style, reinforcing F-2026-060 helper-duplication | SDD-005 § Alternative B | F02351 | non-negotiable | false | 10 |
| R04631 | Alternative C (recommended) — contract + patterns + reference implementations | SDD-005 § Alternative C + § Recommended design | F02352 | non-negotiable | false | 10 |
| R04632 | Alternative C — 4 test categories each with "what counts as enough" rule | SDD-005 § Alternative C | F02353 | non-negotiable | false | 10 |
| R04633 | Alternative C — 3 shared patterns | SDD-005 § Alternative C | F02354 | non-negotiable | false | 10 |
| R04634 | Alternative C — implementation PR ships 7 missing tests using patterns | SDD-005 § Alternative C | F02355 | non-negotiable | false | 10 |
| R04635 | Alternative C addresses both F-2026-082 parent + 7 implementation findings | SDD-005 § Alternative C | F02356 | non-negotiable | false | 10 |
| R04636 | Category 1 — Translation tests | SDD-005 § D-1 Cat 1 | F02357 | non-negotiable | true | 10 |
| R04637 | Category 1 location — source crate's `#[cfg(test)] mod tests` OR `crates/<name>/tests/translation.rs` | SDD-005 § D-1 Cat 1 | F02358 | non-negotiable | false | 10 |
| R04638 | Category 1 — asserts crate correctly translates input format (Tetragon JSON / Suricata EVE / journald / auditd) into selfdef_core::Event | SDD-005 § D-1 Cat 1 | M00510 | non-negotiable | false | 10 |
| R04639 | Category 1 contract — every translation branch has ≥1 positive test (input shape, expected Event field projection) | SDD-005 § D-1 Cat 1 | F02359 | non-negotiable | false | 10 |
| R04640 | Category 1 contract — ≥1 tolerance test (input shape malformed in documented way → no panic, logged warning) | SDD-005 § D-1 Cat 1 | F02360 | non-negotiable | false | 10 |
| R04641 | Category 2 — Pipeline tests | SDD-005 § D-1 Cat 2 | F02361 | non-negotiable | true | 10 |
| R04642 | Category 2 location — `crates/selfdef-daemon/tests/` | SDD-005 § D-1 Cat 2 | F02362 | non-negotiable | false | 10 |
| R04643 | Category 2 — spins up minimal in-process pipeline of bus + collector + correlator + responder + store | SDD-005 § D-1 Cat 2 | F02363 | non-negotiable | false | 10 |
| R04644 | Category 2 — asserts full flow (event in, expected effect at end) | SDD-005 § D-1 Cat 2 | F02363 | non-negotiable | false | 10 |
| R04645 | Category 2 contract — every "promise" the daemon makes operator-side must be exercised by ≥1 pipeline test that would fail if regressed | SDD-005 § D-1 Cat 2 | F02364 | non-negotiable | false | 10 |
| R04646 | Category 2 example promise — finding lands in store with right severity | SDD-005 § D-1 Cat 2 | F02365 | non-negotiable | false | 10 |
| R04647 | Category 2 example promise — NotifyAction is invoked | SDD-005 § D-1 Cat 2 | F02366 | non-negotiable | false | 10 |
| R04648 | Category 2 example promise — API returns expected JSON | SDD-005 § D-1 Cat 2 | F02367 | non-negotiable | false | 10 |
| R04649 | Category 3 — Module-script tests | SDD-005 § D-1 Cat 3 | F02368 | non-negotiable | true | 10 |
| R04650 | Category 3 location — `crates/selfdef-cli/tests/module_*.rs` | SDD-005 § D-1 Cat 3 | F02369 | non-negotiable | false | 10 |
| R04651 | Category 3 — spawns bash on module's install/*.sh against hermetic tempdir | SDD-005 § D-1 Cat 3 | F02370 | non-negotiable | false | 10 |
| R04652 | Category 3 contract — for each script, both dry-run-negative AND live-positive paths asserted | SDD-005 § D-1 Cat 3 | F02371 | non-negotiable | false | 10 |
| R04653 | Category 3 dry-run-negative — SELFDEF_DRY_RUN=1 produces zero on-disk delta | SDD-005 § D-1 Cat 3 | F02372 | non-negotiable | false | 10 |
| R04654 | Category 3 live-positive — SELFDEF_DRY_RUN=0 produces documented effect | SDD-005 § D-1 Cat 3 | F02373 | non-negotiable | false | 10 |
| R04655 | Category 4 — Seam tests | SDD-005 § D-1 Cat 4 | F02374 | non-negotiable | true | 10 |
| R04656 | Category 4 location — `crates/selfdef-daemon/tests/` OR `crates/selfdef-daemon/tests/seam_*.rs` family | SDD-005 § D-1 Cat 4 | F02375 | non-negotiable | false | 10 |
| R04657 | Category 4 — asserts two-side behaviour at seam (writer produces what reader parses, including failure modes) | SDD-005 § D-1 Cat 4 | F02376 | non-negotiable | false | 10 |
| R04658 | Category 4 contract — every seam audit flagged (docs/review/40-integration-audit.md Flows 1-6) has ≥1 seam test | SDD-005 § D-1 Cat 4 | F02377 | non-negotiable | false | 10 |
| R04659 | 4 categories overlap deliberately | SDD-005 § D-1 | F02378 | non-negotiable | false | 10 |
| R04660 | Contract is at-least-one-of coverage, NOT exclusive categorisation | SDD-005 § D-1 | F02378 | non-negotiable | false | 10 |
| R04661 | D-2a — dry_run_must_be_a_noop helper exists in `crates/selfdef-cli/tests/common/mod.rs` | SDD-005 § D-2a + § Implementation status | F02379 | non-negotiable | false | 10 |
| R04662 | D-2a — helper takes module's apply.sh path + fixture builder | SDD-005 § D-2a | F02380 | non-negotiable | false | 10 |
| R04663 | D-2a — runs apply with SELFDEF_DRY_RUN=1 | SDD-005 § D-2a | F02381 | non-negotiable | false | 10 |
| R04664 | D-2a — snapshots tempdir before and after | SDD-005 § D-2a | F02382 | non-negotiable | false | 10 |
| R04665 | D-2a — asserts byte-equality | SDD-005 § D-2a | F02383 | non-negotiable | false | 10 |
| R04666 | D-2a implementation — `snapshot_tree` + `assert_tree_unchanged` | SDD-005 § Implementation status D-2a | F02384 | non-negotiable | false | 10 |
| R04667 | D-2a implementation — hand-rolled length+first-32-bytes fingerprint (no hash-crate dep) | SDD-005 § Implementation status D-2a | F02384 | non-negotiable | false | 10 |
| R04668 | D-2a reference adoption — `endpoint_dry_run_must_be_a_noop_on_disk` in `crates/selfdef-cli/tests/module_vpn_bridge.rs` | SDD-005 § Implementation status | F02385 | non-negotiable | false | 10 |
| R04669 | D-2a — other module-test files follow same pattern when next touched | SDD-005 § Implementation status | E0209 | non-negotiable | false | 10 |
| R04670 | D-2a closes F-2026-030 for reference module | SDD-005 § Implementation status | M00500 | non-negotiable | false | 10 |
| R04671 | D-2b — Prometheus exposition parser replaces substring-matching in m12_api.rs | SDD-005 § D-2b + § Implementation status | F02386 | non-negotiable | false | 10 |
| R04672 | D-2b — verifies Content-Type matches `text/plain; version=0.0.4; charset=utf-8` exact (not prefix) | SDD-005 § D-2b | F02387 | non-negotiable | false | 10 |
| R04673 | D-2b — parses body into (name, labels, value) tuples | SDD-005 § D-2b | F02388 | non-negotiable | false | 10 |
| R04674 | D-2b — asserts presence of expected metrics by name + label set | SDD-005 § D-2b | F02389 | non-negotiable | false | 10 |
| R04675 | D-2b — asserts absence of duplicate (name, labels) keys (Prometheus invariant) | SDD-005 § D-2b | F02390 | non-negotiable | false | 10 |
| R04676 | D-2b implementation — `mod prom` in `crates/selfdef-api/tests/m12_api.rs` | SDD-005 § Implementation status D-2b | F02391 | non-negotiable | false | 10 |
| R04677 | D-2b implementation — strict exposition parser (Sample tuples / dedup-key check / no comment shapes outside HELP/TYPE) | SDD-005 § Implementation status D-2b | F02391 | non-negotiable | false | 10 |
| R04678 | D-2b shipped test — `metrics_exposition_passes_format_strict_parse` (closes F-2026-031) | SDD-005 § Implementation status D-2b | F02392 | non-negotiable | true | 10 |
| R04679 | D-2b shipped test — `metrics_allows_read_capability` (closes F-2026-032) | SDD-005 § Implementation status D-2b | F02392 | non-negotiable | true | 10 |
| R04680 | D-2c — real-broker NATS fixture at `crates/selfdef-nats/tests/integration.rs` | SDD-005 § D-2c + § Implementation status | F02393 + F02394 | non-negotiable | false | 10 |
| R04681 | D-2c — Skips with #[ignore] if nats-server not on PATH | SDD-005 § D-2c | F02395 | non-negotiable | false | 10 |
| R04682 | D-2c — CI without binary stays green | SDD-005 § D-2c | F02395 | non-negotiable | false | 10 |
| R04683 | D-2c — When binary present, spawns it on free port + waits for it to bind | SDD-005 § D-2c | F02396 | non-negotiable | false | 10 |
| R04684 | D-2c — runs bridge against it | SDD-005 § D-2c | F02397 | non-negotiable | false | 10 |
| R04685 | D-2c — publishes one event from "host A" + asserts it arrives on "host B" | SDD-005 § D-2c | F02397 | non-negotiable | false | 10 |
| R04686 | D-2c — two Bridge instances pointed at same broker, distinct host_tag values | SDD-005 § D-2c | F02398 | non-negotiable | false | 10 |
| R04687 | D-2c — tears down broker on test exit | SDD-005 § D-2c | F02399 | non-negotiable | false | 10 |
| R04688 | D-2c shipped tests — `core_bridge_round_trips_event_between_two_hosts` + `jetstream_bridge_creates_stream_and_durable_consumer` | SDD-005 § Implementation status D-2c | M00516 | non-negotiable | true | 10 |
| R04689 | D-2c — runbook documents the local-run incantation | SDD-005 § Implementation status D-2c | M00516 | non-negotiable | false | 10 |
| R04690 | D-2c closes F-2026-035 with documented caveat | SDD-005 § Implementation status D-2c | M00505 | non-negotiable | false | 10 |
| R04691 | Test-4 — `crates/selfdef-correlator/tests/hot_reload.rs` exists | SDD-005 § Implementation status Test-4 | M00517 | non-negotiable | false | 10 |
| R04692 | Test-4 — `correlator_swaps_rules_atomically_under_live_traffic` test exists | SDD-005 § Implementation status Test-4 | M00517 | non-negotiable | true | 10 |
| R04693 | Test-4 — `correlator_load_rules_keeps_prior_set_on_parse_failure` test exists | SDD-005 § Implementation status Test-4 | M00517 | non-negotiable | true | 10 |
| R04694 | Test-4 closes F-2026-033 | SDD-005 § Implementation status Test-4 | M00503 | non-negotiable | false | 10 |
| R04695 | Test-5 — `crates/selfdef-store/tests/concurrent.rs` exists | SDD-005 § Implementation status Test-5 | M00518 | non-negotiable | false | 10 |
| R04696 | Test-5 — `concurrent_inserts_do_not_lose_rows` (8 tasks × 200 inserts/handle) | SDD-005 § Implementation status Test-5 | M00518 | non-negotiable | true | 10 |
| R04697 | Test-5 — `crash_recovery_surfaces_every_committed_insert` (drop and reopen the on-disk file) | SDD-005 § Implementation status Test-5 | M00518 | non-negotiable | true | 10 |
| R04698 | Test-5 — composition test combining concurrency and crash-recovery | SDD-005 § Implementation status Test-5 | M00518 | non-negotiable | true | 10 |
| R04699 | Test-5 closes F-2026-034 | SDD-005 § Implementation status Test-5 | M00504 | non-negotiable | false | 10 |
| R04700 | Test-6 — `crates/selfdef-collector-tetragon/tests/translation.rs` exists | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | false | 10 |
| R04701 | Test-6 — 10 translation tests covering every branch | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | false | 10 |
| R04702 | Test-6 — process_exec covered | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04703 | Test-6 — process_kprobe (file/socket/unknown) covered | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04704 | Test-6 — process_exit covered | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04705 | Test-6 — unknown-top-level covered | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04706 | Test-6 — 3 tolerance branches: empty line | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04707 | Test-6 — 3 tolerance branches: malformed JSON | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04708 | Test-6 — 3 tolerance branches: missing-fields | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | true | 10 |
| R04709 | Test-6 — `pub fn TetragonCollector::translate_line(&str) -> Option<Event>` added (external test surface) | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | false | 10 |
| R04710 | Test-6 — `process_line` is a thin publisher on top | SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | false | 10 |
| R04711 | Test-6 closes F-2026-036 | SDD-005 § Implementation status Test-6 | M00506 | non-negotiable | false | 10 |
| R04712 | D-3 — implementation PR breakdown (6 small PRs each verifiable against contract); R-002 audit finding warns against PRs too large | SDD-005 § D-3 | E0210 | non-negotiable | false | 10 |
| R04713 | D-3 PR Test-1 — `tests/common/mod.rs` + dry_run_must_be_a_noop wrapper (D-2a); reference module-test adoption | SDD-005 § D-3 | M00514 | non-negotiable | false | 10 |
| R04714 | D-3 PR Test-2 — Prometheus exposition parser (D-2b); touches only m12_api.rs; closes F-2026-031 + F-2026-032 | SDD-005 § D-3 | M00515 | non-negotiable | false | 10 |
| R04715 | D-3 PR Test-3 — real-broker NATS fixture (D-2c); new selfdef-nats/tests/integration.rs; closes F-2026-035 | SDD-005 § D-3 | M00516 | non-negotiable | false | 10 |
| R04716 | D-3 PR Test-4 — SIGHUP-under-traffic correlator test; new crates/selfdef-correlator/tests/hot_reload.rs; closes F-2026-033 | SDD-005 § D-3 | M00517 | non-negotiable | false | 10 |
| R04717 | D-3 PR Test-5 — store concurrent-insert + crash-recovery; new crates/selfdef-store/tests/concurrent.rs; closes F-2026-034 | SDD-005 § D-3 | M00518 | non-negotiable | false | 10 |
| R04718 | D-3 PR Test-6 — Tetragon collector isolation tests; new crates/selfdef-collector-tetragon/tests/translation.rs; closes F-2026-036; aligns with SDD-001 collector work | SDD-005 § D-3 | M00519 | non-negotiable | false | 10 |
| R04719 | D-4 — SDD-001 AI-machine end-to-end test in `crates/selfdef-daemon/tests/m_ai_machine.rs` is Cat 2 + Cat 4 combined | SDD-005 § D-4 | E0210 | non-negotiable | false | 10 |
| R04720 | D-4 — future similar modules (host-hardening-guard etc.) must ship their own pipeline + seam tests by default | SDD-005 § D-4 | E0210 | non-negotiable | false | 10 |
| R04721 | D-5 — `docs/dev/test-contract.md` under `docs/src/dev/` (visible in mdbook) carries 4 categories + 3 patterns as operator-authoring guidance | SDD-005 § D-5 + § Implementation status | M00520 | non-negotiable | true | 10 |
| R04722 | D-5 — SDD is design rationale; doc is the runbook for contributors writing new tests | SDD-005 § D-5 | M00520 | non-negotiable | false | 10 |
| R04723 | Meta-test plan check 1 — `docs/dev/test-contract.md` exists + matches D-1 + D-2 | SDD-005 § Test plan 1 | M00521 | non-negotiable | false | 10 |
| R04724 | Meta-test plan check 2 — `crates/selfdef-cli/tests/common/mod.rs` exists with dry_run_must_be_a_noop helper | SDD-005 § Test plan 2 | M00521 | non-negotiable | false | 10 |
| R04725 | Meta-test plan check 3 — `crates/selfdef-api/tests/m12_api.rs` uses exposition parser; substring assertions for /metrics body are gone | SDD-005 § Test plan 3 | M00521 | non-negotiable | false | 10 |
| R04726 | Meta-test plan check 4 — `crates/selfdef-nats/tests/integration.rs` exists + #[ignore]-gated on nats-server presence | SDD-005 § Test plan 4 | M00521 | non-negotiable | false | 10 |
| R04727 | Meta-test plan check 5 — `crates/selfdef-correlator/tests/hot_reload.rs` exists | SDD-005 § Test plan 5 | M00521 | non-negotiable | false | 10 |
| R04728 | Meta-test plan check 6 — `crates/selfdef-store/tests/concurrent.rs` exists | SDD-005 § Test plan 6 | M00521 | non-negotiable | false | 10 |
| R04729 | Meta-test plan check 7 — `crates/selfdef-collector-tetragon/tests/translation.rs` exists | SDD-005 § Test plan 7 | M00521 | non-negotiable | false | 10 |
| R04730 | Meta-test plan check 8 — each of 6 implementation PRs cites SDD-005 in body | SDD-005 § Test plan 8 | M00521 | non-negotiable | false | 10 |
| R04731 | Rollout — no public API changes; new tests + one new helper module | SDD-005 § Rollout / migration | E0210 | non-negotiable | false | 10 |
| R04732 | Rollout — CI may need nats-server installed in test job | SDD-005 § Rollout / migration | M00516 | non-negotiable | true | 10 |
| R04733 | Rollout — if not, test stays #[ignore]-gated and runs locally | SDD-005 § Rollout / migration | M00516 | non-negotiable | false | 10 |
| R04734 | Rollout — existing tests are not deleted; where overlap a new pattern (substring-matching metrics body), new test supersedes | SDD-005 § Rollout / migration | E0210 | non-negotiable | false | 10 |
| R04735 | Risk R-1 — contract becomes paperwork burden for small fixes; mitigated by making it runbook for new tests, not gate on existing ones | SDD-005 § Risks R-1 | E0204 | non-negotiable | false | 10 |
| R04736 | Risk R-2 — real-broker NATS test makes CI flaky if broker takes too long to bind; mitigated by #[ignore]-by-default + generous wait-for-bind with explicit timeout | SDD-005 § Risks R-2 | M00516 | non-negotiable | false | 10 |
| R04737 | Risk R-3 — dry-run-negative wrapper false-positives on metadata changes (mtime, atime); mitigated by snapshotting only file paths + sha256 of contents (not full stat) | SDD-005 § Risks R-3 | M00514 | non-negotiable | false | 10 |
| R04738 | Q-A answer (D-016, 2026-05-15) — pipeline + seam test required for modules introducing new event source; NOT for purely passive modules | SDD-005 § Open questions Q-A | M00522 | non-negotiable | false | 10 |
| R04739 | Q-A passive example — host-baseline module is pure passive observation; doesn't require pipeline+seam test | SDD-005 § Open questions Q-A | M00522 | non-negotiable | false | 10 |
| R04740 | Q-B answer (D-017, 2026-05-15) — test-contract doc goes under docs/src/dev/ (mdbook-visible) | SDD-005 § Open questions Q-B | M00523 | non-negotiable | false | 10 |
| R04741 | Q-B — both docs/sdd/ and docs/src/dev/ acceptable | SDD-005 § Open questions Q-B | M00523 | non-negotiable | false | 10 |
| R04742 | Q-C answer (D-018, 2026-05-15) — every Phase-N audit (yearly) re-asks "do these categories still match the codebase?" | SDD-005 § Open questions Q-C | M00524 | non-negotiable | false | 10 |
| R04743 | Q-C — surfaces contract drift as findings | SDD-005 § Open questions Q-C | M00524 | non-negotiable | false | 10 |
| R04744 | Q-C — current audit at docs/review/ is Phase 1; future Phases re-run seven explorers against updated inventory | SDD-005 § Open questions Q-C | M00524 | non-negotiable | false | 10 |
| R04745 | Appendix — SDD-001 implementation PR carries AI-machine pipeline + seam test (Cat 2 + Cat 4) | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04746 | Appendix — SDD-001's test pattern is reusable for future modules | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04747 | Appendix — SDD-002 implementation PR adds `[daemon_requires]` and validator; both unit tests (Cat 1) AND integration test (Cat 3 — apply.sh refusal on mismatch) | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04748 | Appendix — SDD-002 tests align with this contract | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04749 | Appendix — SDD-003 profile-aware multi-instance check is Cat 1 (manifest deserialisation) + Cat 3 (resolver refusal at apply time); aligns | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04750 | Appendix — SDD-004 is doc-only; no test contract implication | SDD-005 § Appendix | E0210 | non-negotiable | false | 10 |
| R04751 | "L1–L5 layered harness" naming framing — operator-level abstraction in standing mandate; SDD-005 codifies the underlying 4-category content | INDEX.md MS020 + SDD-005 | E0208 | non-negotiable | false | 10 |
| R04752 | Test contract integrates with MS001 daemon core — pipeline tests live in selfdef-daemon | MS001 + SDD-005 § D-1 Cat 2 | M00511 | non-negotiable | false | 10 |
| R04753 | Test contract integrates with MS002 collector fabric — Cat 1 translation tests cover Tetragon JSON / Suricata EVE / journald / auditd | MS002 + SDD-005 § D-1 Cat 1 | M00510 | non-negotiable | false | 10 |
| R04754 | Test contract integrates with MS003 correlator+responder+store-sink — pipeline tests cover correlator + responder + store | MS003 + SDD-005 § D-1 Cat 2 | M00511 | non-negotiable | false | 10 |
| R04755 | Test contract integrates with MS003 — correlator hot-reload test (Test-4) covers SIGHUP-under-traffic atomicity | MS003 + SDD-005 § Implementation status Test-4 | M00517 | non-negotiable | false | 10 |
| R04756 | Test contract integrates with MS003 — store concurrency + crash-recovery tests (Test-5) cover persistence | MS003 + SDD-005 § Implementation status Test-5 | M00518 | non-negotiable | false | 10 |
| R04757 | Test contract integrates with MS006 functional modules — Cat 3 module-script tests cover every module | MS006 + SDD-005 § D-1 Cat 3 | M00512 | non-negotiable | false | 10 |
| R04758 | Test contract integrates with MS007 typed-mirror crates — test pattern schema may be carried for cross-repo audit | MS007 + SDD-038 | E0210 | non-negotiable | false | 10 |
| R04759 | Test contract integrates with MS008 SAIN-01 — pipeline tests verify cross-repo event integration | MS008 + SDD-005 § D-1 Cat 2 | M00511 | non-negotiable | false | 10 |
| R04760 | Test contract integrates with MS009 audit cycles — phase-6/70-tests-audit covers SDD-005 4 categories + 3 patterns + 6 Test-N | MS009 phase-6 70-tests-audit | E0210 | non-negotiable | false | 10 |
| R04761 | Test contract integrates with MS010 hardware-aware modules — Cat 3 module-script tests cover [requires_hardware] gate refusal | MS010 + SDD-005 § D-1 Cat 3 | M00512 | non-negotiable | false | 10 |
| R04762 | Test contract integrates with MS011 operator dashboard — Cat 2 pipeline tests cover dashboard MCP tab + Modules tab data flow | MS011 + SDD-005 § D-1 Cat 2 | M00511 | non-negotiable | false | 10 |
| R04763 | Test contract integrates with MS012 perimeter coexistence — Cat 4 seam tests verify selfdef + sovereign-os Tetragon coexistence | MS012 + SDD-005 § D-1 Cat 4 | M00513 | non-negotiable | false | 10 |
| R04764 | Test contract integrates with MS013 27-SDD charter — SDD-005 is foundational 000-009 layer per MS013 R03012 | MS013 + SDD-005 | E0201 | non-negotiable | false | 10 |
| R04765 | Test contract integrates with MS014 SSH-wrap — ssh-wrap event emission tested via Cat 4 seam (eventstream JSONL) | MS014 + SDD-005 § Goals 1 | F02312 | non-negotiable | false | 10 |
| R04766 | Test contract integrates with MS015 NATS messaging — D-2c real-broker NATS fixture closes F-2026-035 + jetstream durability assertions | MS015 + SDD-005 § D-2c | M00516 | non-negotiable | false | 10 |
| R04767 | Test contract integrates with MS016 eBPF + Tetragon — Test-6 collector isolation tests (translation.rs) cover Tetragon translation branches | MS016 + SDD-005 § Implementation status Test-6 | M00519 | non-negotiable | false | 10 |
| R04768 | Test contract integrates with MS017 agent-guard — Cat 3 tests cover agent-guard install scripts; Cat 4 seam tests cover policy_name discriminator | MS017 + SDD-005 § D-1 Cat 3 + Cat 4 | M00512 + M00513 | non-negotiable | false | 10 |
| R04769 | Test contract integrates with MS018 vpn-bridge — Cat 3 dry-run-negative wrapper adopted in `crates/selfdef-cli/tests/module_vpn_bridge.rs` | MS018 + SDD-005 § Implementation status D-2a | F02385 | non-negotiable | false | 10 |
| R04770 | Test contract integrates with MS019 security threat model — Cat 2+4 pipeline + seam tests validate threat-model invariants (no bypass) | MS019 + SDD-005 § D-1 Cat 2 + Cat 4 | M00511 + M00513 | non-negotiable | false | 10 |
| R04771 | Project boundary — SDD-005 is selfdef-scope only; sovereign-os has its own test contract | architecture + MS007 + SDD-038 | E0201 | non-negotiable | false | 10 |
| R04772 | Project boundary — cross-repo binding via documented test categories + replay corpora (NOT direct crate import) | MS007 + SDD-038 | E0210 | non-negotiable | false | 10 |
| R04773 | Doctrine — contract is operator-readable runbook for new tests, not gate on existing ones | SDD-005 § Risks R-1 | E0204 | non-negotiable | false | 10 |
| R04774 | Doctrine — at-least-one-of coverage; not exclusive categorisation | SDD-005 § D-1 | F02378 | non-negotiable | false | 10 |
| R04775 | Doctrine — dry-run-negative + live-positive paired (Cat 3 invariant) | SDD-005 § D-1 Cat 3 | F02371 | non-negotiable | false | 10 |
| R04776 | Doctrine — positive + tolerance paired (Cat 1 invariant) | SDD-005 § D-1 Cat 1 | F02359 + F02360 | non-negotiable | false | 10 |
| R04777 | Doctrine — every daemon-side promise has ≥1 pipeline test (Cat 2 invariant) | SDD-005 § D-1 Cat 2 | F02364 | non-negotiable | false | 10 |
| R04778 | Doctrine — every audit-flagged seam has ≥1 seam test (Cat 4 invariant) | SDD-005 § D-1 Cat 4 | F02377 | non-negotiable | false | 10 |
| R04779 | Doctrine — hermetic tests own their tempdir; no host services beyond explicit shims | SDD-005 § Glossary | F02330 | non-negotiable | false | 10 |
| R04780 | Doctrine — #[ignore]-gated tests for external dependencies (nats-server) keep CI green without binary | SDD-005 § D-2c | F02395 | non-negotiable | false | 10 |
| R04781 | Doctrine — Phase-N audit re-asks "do categories still match codebase?" (Q-C) | SDD-005 § Open questions Q-C | M00524 | non-negotiable | false | 10 |
| R04782 | Doctrine — pipeline + seam test required for modules introducing new event source; NOT for purely passive (Q-A) | SDD-005 § Open questions Q-A | M00522 | non-negotiable | false | 10 |
| R04783 | Doctrine — test-contract.md in docs/src/dev/ for contributor visibility (Q-B) | SDD-005 § Open questions Q-B | M00523 | non-negotiable | false | 10 |
| R04784 | Doctrine — SDD is appeal authority; runbook is operator-authoring guidance | SDD-005 § Goals 4 + § D-5 | F02320 | non-negotiable | false | 10 |
| R04785 | Doctrine — implementation PRs cite SDD-005 in body (Test-1..6) | SDD-005 § Test plan 8 | M00521 | non-negotiable | false | 10 |
| R04786 | Doctrine — small PRs verifiable against contract (R-002 audit finding) | SDD-005 § D-3 | E0210 | non-negotiable | false | 10 |
| R04787 | Doctrine — existing tests not deleted; new test supersedes when overlap | SDD-005 § Rollout / migration | E0210 | non-negotiable | false | 10 |
| R04788 | Composite — 4 test categories address Goal 2; 3 shared patterns address Goal 3; SDD as appeal authority addresses Goal 4; categorisation of 6 seams addresses Goal 1 | SDD-005 § Goals + § D-1 + § D-2 + § D-3 | E0204 | non-negotiable | false | 10 |
| R04789 | Composite — 4 categories overlap deliberately; "at-least-one-of" coverage means a single test may satisfy multiple category contracts | SDD-005 § D-1 | F02378 | non-negotiable | false | 10 |
| R04790 | Composite — 6 implementation Test-N PRs collapsed to one PR (operator's big-chunks steer); each Test-N section in Implementation status documents what shipped | SDD-005 § Implementation status | E0201 + E0210 | non-negotiable | false | 10 |
| R04791 | Composite — 4 Categories + 3 Patterns + 6 Test-N + 8-step Meta-test plan + 3 answered Open questions (Q-A/B/C) + 4-SDD Appendix linkage | SDD-005 entire | F02400 | non-negotiable | false | 10 |
| R04792 | Composite — `docs/dev/test-contract.md` is the canonical contributor runbook for selfdef test authoring | SDD-005 § D-5 + § Implementation status | M00520 | non-negotiable | false | 10 |
| R04793 | Composite — SDD-005 closes 8 findings total (1 parent F-2026-082 + 7 implementation F-2026-030..036) | SDD-005 § header | F02282 + F02283 + F02284 + F02285 + F02286 + F02287 + F02288 + F02289 | non-negotiable | false | 10 |
| R04794 | Composite — SDD-005 lays foundation for "L1-L5 layered harness" operator-level naming via SDD's underlying 4 categories | INDEX.md MS020 + SDD-005 § D-1 | R04751 | non-negotiable | false | 10 |
| R04795 | Composite — every new module introducing event source MUST ship pipeline + seam test by default (per Q-A answer + D-4 SDD-001 linkage) | SDD-005 § Open questions Q-A + § D-4 | M00522 + E0210 | non-negotiable | false | 10 |
| R04796 | Composite — coverage % is NOT a contract; WHAT is tested matters more than HOW MUCH | SDD-005 § Non-goals | F02322 | non-negotiable | false | 10 |
| R04797 | Composite — property-testing and fuzzing remain separate scope (future SDD) | SDD-005 § Non-goals | F02323 | non-negotiable | false | 10 |
| R04798 | Composite — performance and load tests remain separate scope (future SDD) | SDD-005 § Non-goals | F02324 | non-negotiable | false | 10 |
| R04799 | Composite — F-2026-082 SDD-debt parent + F-2026-030/031/032/033/034/035/036 implementation findings all closed by SDD-005 implementation PR + 6 Test-N | SDD-005 § header + § Implementation status | F02282 + F02400 | non-negotiable | false | 10 |
| R04800 | Composite — MS020 covers SDD-005 4 categories + 3 patterns + 6 Test-N + docs/dev/test-contract.md runbook + 8-step meta-test plan + 3 answered Q-A/B/C + 4-SDD appendix; integrates with MS001-MS019; project boundary preserved (selfdef-scope; cross-repo via documented test categories + replay corpora + MS007 typed mirrors) | INDEX.md MS020 + SDD-005 + MS001-MS019 | E0201 + E0202 + E0203 + E0204 + E0205 + E0206 + E0207 + E0208 + E0209 + E0210 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS019: 28320 + 2400 = 30720 sub-requirements when MS020 lands

## Cross-references

- SDD source: `docs/sdd/005-test-contract.md` (493 lines; status=implemented; closes F-2026-082 + F-2026-030..036)
- Contributor runbook: `docs/dev/test-contract.md` (under `docs/src/dev/` for mdbook visibility)
- Shared pattern files: `crates/selfdef-cli/tests/common/mod.rs` (D-2a) / `crates/selfdef-api/tests/m12_api.rs` mod prom (D-2b) / `crates/selfdef-nats/tests/integration.rs` (D-2c)
- 6 Test-N PRs (collapsed to one): D-2a + D-2b + D-2c + Test-4 hot_reload + Test-5 concurrent + Test-6 translation
- Sister milestones: MS001-MS019 (test contract applies to all; specifically MS018 vpn-bridge adopts D-2a reference / MS019 SDD-004 has no test contract implication / MS016 eBPF + Tetragon hosts Test-6 / MS015 NATS hosts D-2c / MS003 correlator hosts Test-4 + store hosts Test-5)
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (test contract is selfdef-scope; sovereign-os has own test contract; cross-repo via documented test categories + replay corpora + MS007 typed mirrors)
