# MS022 — Per-token SSE subscriber quota

> Parent: `backlog/milestones/INDEX.md` row MS022.
> Source: `docs/sdd/007-per-token-sse-subscriber-quota.md` (252 lines; status=implemented all 5 Ds shipped; closes F-2028-037 + F-2028-039) + `crates/selfdef-api/src/transport.rs` TokenFingerprint + `crates/selfdef-api/tests/m12_api.rs` 3 new integration tests + selfdef-config ApiConfig fields + STARTER_CONFIG. All entries below extract verbatim. No invention.

## Epics (E0221–E0230)

| Epic ID | Phrase | Source |
|---|---|---|
| E0221 | SDD-007 mission — Per-token SSE subscriber quota; closes F-2028-037 + F-2028-039; "Implemented. All five Ds shipped" | SDD-007 § header + § Status |
| E0222 | Why now — Phase 2 closed F-2027-061 with process-global subscriber cap `MAX_SSE_SUBSCRIBERS = 64` (Arc<AtomicUsize> + RAII SubscriberGuard); Phase 3 security explorer PR #91 raised F-2028-037 important: cap is process-global but bearer-token treats every token as equivalent; one bearer-holder opening 64 concurrent /events/stream from single process saturates cap + denies service to every other authenticated client (authenticated-only DoS); F-2028-039 is design counterpart | SDD-007 § Why now |
| E0223 | 3 Goals — (1) Bound abuse from single token (token-holder can exhaust at most per-token slice of global cap, not whole cap); (2) Preserve revocation timeliness (when operator rotates/revokes token, every connection counting against that token's quota frees its slot immediately, not at next bus message); (3) No regression in legitimate single-operator case (one rotated token running one `selfdefctl events follow --url` shouldn't hit per-token cap) | SDD-007 § Goals |
| E0224 | D-1 Token identity — TokenFingerprint (SHA-256, 32-byte) in `crates/selfdef-api/src/transport.rs`; 4 alternatives considered (raw token bytes / token fingerprint / token role / source IP); decision = SHA-256 fingerprint (doesn't keep secret in maps; fingerprint stable handle; one extra hash per request); computed once in bearer_auth middleware that already inspects token bytes; 32-byte handle stored in request.extensions() so events_stream handler reads without re-hashing; `with_full_capability_for_fingerprint` is test-helpers analogue | SDD-007 § D-1 + § Implementation status D-1 |
| E0225 | D-2 Dual-counter SubscriberGuard — `ApiState` carries `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` per-token map alongside existing global AtomicUsize; `SubscriberGuard::try_acquire` checks per-token first (so typed 503 reason identifies abusive token's slice when it's the cause), then global cap; on global-cap failure undoes per-token increment; `SubscriberGuard::Drop` decrements both counters + prunes HashMap entry when per-token count hits zero (no leak across rotations); 5-step quota flow (read fingerprint / acquire-or-create per-fingerprint counter / CAS-increment against per-token quota / 503 if at quota / otherwise increment global counter too) | SDD-007 § D-2 + § Implementation status D-2 |
| E0226 | D-3 Revocation interaction — bearer-auth middleware starts rejecting requests bearing old token; existing connections under old token NOT terminated — they keep SubscriberGuard alive + continue draining; for F-2028-037 threat model that's adequate (abusive token-holder loses ability to open new connections at moment of rotation, existing ones drain via normal client-disconnect / slow-client-timeout); stricter terminate-all-existing model = future hardening (drained_at: Option<Instant> + writer task checks on every send); D-3 answered D-002 2026-05-15 = keep current behavior; F-2027-062 slow-client timeout is documented upper bound on leak window | SDD-007 § D-3 + § Implementation status D-3 |
| E0227 | D-4 Config surface — `[api]` block gains two optional knobs (`max_sse_subscribers_per_token = 8` default; `max_sse_subscribers = 64` default; F-2028-037 backstop + F-2027-061 global second-line defence); `selfdef-config::ApiConfig` gains optional `max_sse_subscribers: Option<usize>` + `max_sse_subscribers_per_token: Option<usize>`; daemon copies them into `ApiState::sse_caps` via `ApiState::with_sse_caps(SseCaps { … })` builder; `SubscriberGuard::try_acquire` consults state-supplied overrides ahead of compiled-in constants; None/Some(0) fall back to defaults (64 global, 8 per-token); init-template STARTER_CONFIG ships two knobs commented at defaults so operators see them when bootstrapping | SDD-007 § D-4 + § Implementation status D-4 |
| E0228 | D-5 Test coverage — 3 new integration tests in `crates/selfdef-api/tests/m12_api.rs`: per-token cap reached (D-5.1) + per-token cap is per-fingerprint (D-5.2) + per-token counter drops to zero on disconnect (D-5.5); D-5.3 (global cap still applies) covered by existing `events_stream_rejects_over_cap_with_503` from F-2027-061's closure (its with_full_capability fixture has no fingerprint so test still exercises global-cap path); D-5.4 (rotation frees slots eventually) covered by SDD-004 metrics-token rotation tests + slow-client timeout path; 2 new integration tests pin override contract for both caps (Phase D-4 follow-up) | SDD-007 § D-5 + § Implementation status |
| E0229 | D-6 Status-code semantics — both caps return 503; JSON body distinguishes them: `{"error": "sse subscriber cap reached"}` (global; MAX_SSE_SUBSCRIBERS exhausted; no single token to blame) + `{"error": "per-token sse cap reached"}` (this token's per-token slice is full; rotate the abusive token or wait for connections to drain); both surface through F-2028-016 JSON-extraction path in `events_follow_tcp` | SDD-007 § D-6 + § Implementation status D-6 |
| E0230 | Out-of-scope deferrals + Phasing + Status — Out of scope: Per-IP quota (NATted operators would suffer; audit didn't surface use case) + quota-exhaustion Prometheus counter (mentioned for awareness; not blocking) + token-issuer-time / audience / scope quota (daemon doesn't know which audience/scope token issued for; bearer-auth treats every token equivalently; per-audience quotas need rotation tool to thread audience metadata; separate redesign); Phasing: A (D-1+D-2+D-3+D-4 single PR closes F-2028-037+F-2028-039) + B (D-5 paired or immediate follow-up) + C (D-6 explicit contract); Status = implemented; all five Ds shipped | SDD-007 § Out of scope + § Phasing + § Status |

## Modules (M00551–M00576)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00551 | F-2027-061 process-global cap baseline — `MAX_SSE_SUBSCRIBERS = 64` (Arc<AtomicUsize> + RAII SubscriberGuard) | SDD-007 § Why now | E0222 |
| M00552 | F-2028-037 important finding (Phase 3 security explorer PR #91) — process-global cap saturable by single bearer-holder | SDD-007 § Why now | E0222 |
| M00553 | F-2028-039 design counterpart — scope per-token quota mechanism, then implement | SDD-007 § Why now | E0222 |
| M00554 | TokenFingerprint type — SHA-256, 32-byte | SDD-007 § D-1 + § Implementation status D-1 | E0224 |
| M00555 | TokenFingerprint location — `crates/selfdef-api/src/transport.rs` | SDD-007 § Implementation status D-1 | E0224 |
| M00556 | bearer_auth middleware threads TokenFingerprint into request.extensions() alongside Capability | SDD-007 § Implementation status D-1 | E0224 |
| M00557 | Test helper — `with_full_capability_for_fingerprint` (in-process tests analogue to with_full_capability) | SDD-007 § Implementation status D-1 | E0224 |
| M00558 | ApiState per-token map — `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` | SDD-007 § D-2 + § Implementation status D-2 | E0225 |
| M00559 | SubscriberGuard::try_acquire — checks per-token first then global | SDD-007 § D-2 + § Implementation status D-2 | E0225 |
| M00560 | SubscriberGuard::Drop — decrements both counters + prunes HashMap entry when per-token count hits zero | SDD-007 § D-2 + § Implementation status D-2 | E0225 |
| M00561 | Quota flow step 1 — Read fingerprint from request.extensions() | SDD-007 § D-2 | E0225 |
| M00562 | Quota flow step 2 — Acquire / create per-fingerprint counter under brief write lock | SDD-007 § D-2 | E0225 |
| M00563 | Quota flow step 3 — CAS-increment per-fingerprint counter against MAX_SSE_SUBSCRIBERS_PER_TOKEN (default 8) | SDD-007 § D-2 | E0225 |
| M00564 | Quota flow step 4 — 503 with typed reason "per-token sse cap reached" if per-token counter at quota | SDD-007 § D-2 + § D-6 | E0225 + E0229 |
| M00565 | Quota flow step 5 — Increment global counter too (process-wide cap stays as backstop) | SDD-007 § D-2 | E0225 |
| M00566 | Revocation behavior — bearer-auth refuses NEW connections immediately on rotation | SDD-007 § D-3 | E0226 |
| M00567 | Revocation behavior — existing connections drain via F-2027-062 slow-client timeout + normal client-disconnect | SDD-007 § D-3 + § Implementation status D-3 | E0226 |
| M00568 | Future hardening (out of scope D-3) — `drained_at: Option<Instant>` + writer task checks on every send | SDD-007 § D-3 | E0226 |
| M00569 | Config knob — `max_sse_subscribers_per_token` (Option<usize>; default 8) | SDD-007 § D-4 + § Implementation status D-4 | E0227 |
| M00570 | Config knob — `max_sse_subscribers` (Option<usize>; default 64) | SDD-007 § D-4 + § Implementation status D-4 | E0227 |
| M00571 | ApiConfig location — `selfdef-config::ApiConfig` fields | SDD-007 § Implementation status D-4 | E0227 |
| M00572 | Daemon builder — `ApiState::with_sse_caps(SseCaps { … })` | SDD-007 § Implementation status D-4 | E0227 |
| M00573 | STARTER_CONFIG init-template — two knobs commented at defaults | SDD-007 § Implementation status D-4 | E0227 |
| M00574 | Integration test file — `crates/selfdef-api/tests/m12_api.rs` | SDD-007 § D-5 + § Implementation status D-5 | E0228 |
| M00575 | Out-of-scope deferral — Per-IP quota / quota-exhaustion Prometheus metric / token-issuer-time audience/scope quota | SDD-007 § Out of scope | E0230 |
| M00576 | Phasing — Phase A (single PR D-1+D-2+D-3+D-4) / Phase B (D-5 tests) / Phase C (D-6 explicit contract); collapsed to single PR per "big chunks" steer | SDD-007 § Phasing + § Status | E0230 |

## Features (F02521–F02640)

| F ID | Phrase | Source | Parent | Category | Opt-in |
|---|---|---|---|---|---|
| F02521 | SDD-007 status = "implemented (all five Ds shipped)" | SDD-007 § header | E0221 | composite | false |
| F02522 | SDD-007 closes F-2028-037 | SDD-007 § header | M00552 | composite | false |
| F02523 | SDD-007 closes F-2028-039 | SDD-007 § header | M00553 | composite | false |
| F02524 | SDD-007 last updated 2026-05-14 | SDD-007 § header | E0221 | composite | false |
| F02525 | Phase 2 closed F-2027-061 with process-global subscriber cap | SDD-007 § Why now | E0222 | composite | false |
| F02526 | F-2027-061 — `MAX_SSE_SUBSCRIBERS = 64` constant | SDD-007 § Why now | M00551 | composite | false |
| F02527 | F-2027-061 — implementation via Arc<AtomicUsize> + RAII SubscriberGuard | SDD-007 § Why now | M00551 | composite | false |
| F02528 | Phase 3 security explorer (PR #91) raised F-2028-037 (important) | SDD-007 § Why now | M00552 | composite | false |
| F02529 | F-2028-037 — cap is process-global but bearer-token model treats every token as equivalent | SDD-007 § Why now | M00552 | composite | false |
| F02530 | F-2028-037 — one bearer-holder opening 64 concurrent /events/stream from single process saturates cap | SDD-007 § Why now | M00552 | composite | false |
| F02531 | F-2028-037 — denies service to every other authenticated client | SDD-007 § Why now | M00552 | composite | false |
| F02532 | F-2028-037 — authenticated-only DoS but real for operators who hand out tokens with same audience as read endpoints | SDD-007 § Why now | M00552 | composite | false |
| F02533 | F-2028-039 — design counterpart to F-2028-037 (scope per-token quota mechanism, then implement) | SDD-007 § Why now | M00553 | composite | false |
| F02534 | Goal 1 — Bound abuse from single token (token-holder exhausts at most per-token slice, not whole cap) | SDD-007 § Goals 1 | E0223 | composite | false |
| F02535 | Goal 2 — Preserve revocation timeliness (rotation frees slots immediately, not at next bus message) | SDD-007 § Goals 2 | E0223 | composite | false |
| F02536 | Goal 3 — No regression in legitimate single-operator case (one rotated token, one selfdefctl events follow doesn't hit cap) | SDD-007 § Goals 3 | E0223 | composite | false |
| F02537 | D-1 identity option — Raw token bytes (rejected — stores secrets in memory's hash table; revocation needs token-list pull) | SDD-007 § D-1 table | E0224 | composite | false |
| F02538 | D-1 identity option (RECOMMENDED) — Token fingerprint (SHA-256 of the bytes); doesn't keep secret in maps; fingerprint stable handle; one extra hash per request | SDD-007 § D-1 table + § decision | M00554 | composite | false |
| F02539 | D-1 identity option — Token role / audience (rejected — doesn't address one-role-holder-many-connections abuse) | SDD-007 § D-1 table | E0224 | composite | false |
| F02540 | D-1 identity option — Source IP (rejected — doesn't compose with token rotation; NAT collapses many holders) | SDD-007 § D-1 table | E0224 | composite | false |
| F02541 | D-1 decision — token fingerprint (SHA-256) | SDD-007 § D-1 decision | M00554 | composite | false |
| F02542 | D-1 — fingerprint computed once per request inside bearer-auth middleware | SDD-007 § D-1 | M00556 | composite | false |
| F02543 | D-1 — fingerprint is 32-byte handle stored in request.extensions() | SDD-007 § D-1 | M00556 | composite | false |
| F02544 | D-1 — events_stream handler reads fingerprint without re-hashing | SDD-007 § D-1 | M00556 | composite | false |
| F02545 | D-1 location — `crates/selfdef-api/src/transport.rs` | SDD-007 § Implementation status D-1 | M00555 | composite | false |
| F02546 | D-1 test helper — `with_full_capability_for_fingerprint` (analogue for in-process tests) | SDD-007 § Implementation status D-1 | M00557 | composite | true |
| F02547 | D-2 ApiState — `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` per-token map | SDD-007 § D-2 + § Implementation status D-2 | M00558 | composite | false |
| F02548 | D-2 ApiState — per-token map alongside existing global AtomicUsize | SDD-007 § Implementation status D-2 | M00558 | composite | false |
| F02549 | D-2 — SubscriberGuard::try_acquire checks per-token first | SDD-007 § Implementation status D-2 | M00559 | composite | false |
| F02550 | D-2 — typed 503 reason identifies abusive token's slice when it's the cause | SDD-007 § Implementation status D-2 | M00559 | composite | false |
| F02551 | D-2 — try_acquire then checks global cap | SDD-007 § Implementation status D-2 | M00559 | composite | false |
| F02552 | D-2 — on global-cap failure, undoes per-token increment | SDD-007 § Implementation status D-2 | M00559 | composite | false |
| F02553 | D-2 — SubscriberGuard::Drop decrements both counters | SDD-007 § D-2 + § Implementation status D-2 | M00560 | composite | false |
| F02554 | D-2 — SubscriberGuard::Drop prunes HashMap entry when per-token count hits zero | SDD-007 § Implementation status D-2 | M00560 | composite | false |
| F02555 | D-2 — no leak across rotations (HashMap pruning) | SDD-007 § Implementation status D-2 | M00560 | composite | false |
| F02556 | D-2 quota flow step 1 — Read fingerprint from request.extensions() | SDD-007 § D-2 | M00561 | composite | false |
| F02557 | D-2 quota flow step 2 — Acquire/create per-fingerprint counter under brief write lock | SDD-007 § D-2 | M00562 | composite | false |
| F02558 | D-2 quota flow step 3 — CAS-increment per-fingerprint counter against per-token quota | SDD-007 § D-2 | M00563 | composite | false |
| F02559 | D-2 quota flow — MAX_SSE_SUBSCRIBERS_PER_TOKEN default 8 | SDD-007 § D-2 | M00563 | composite | true |
| F02560 | D-2 quota flow step 4 — 503 with typed reason "per-token sse cap reached" if at quota | SDD-007 § D-2 | M00564 | composite | false |
| F02561 | D-2 quota flow — reason distinguishable from existing "sse subscriber cap reached" so operators tell which limit they hit | SDD-007 § D-2 | M00564 | composite | false |
| F02562 | D-2 quota flow step 5 — Otherwise increment global counter too | SDD-007 § D-2 | M00565 | composite | false |
| F02563 | D-2 — process-wide cap stays as backstop (many tokens each fitting under per-token but collectively exhausting process resources) | SDD-007 § D-2 | M00565 | composite | false |
| F02564 | D-3 — bearer-auth middleware starts rejecting requests bearing old token on rotation | SDD-007 § D-3 | M00566 | composite | false |
| F02565 | D-3 — existing connections under old token NOT terminated by middleware | SDD-007 § D-3 | M00567 | composite | false |
| F02566 | D-3 — existing connections keep SubscriberGuard alive + continue draining | SDD-007 § D-3 | M00567 | composite | false |
| F02567 | D-3 threat model adequacy — abusive token-holder loses ability to open NEW connections at moment of rotation | SDD-007 § D-3 | E0226 | composite | false |
| F02568 | D-3 — existing connections drain via normal client-disconnect / slow-client-timeout | SDD-007 § D-3 | M00567 | composite | false |
| F02569 | D-3 stricter model (future hardening) — `drained_at: Option<Instant>` + writer task checks on every send | SDD-007 § D-3 | M00568 | composite | false |
| F02570 | D-3 — out of scope for D-2 first cut | SDD-007 § D-3 | M00568 | composite | false |
| F02571 | D-3 — D-3 marked "future hardening" + revisit only if operator demand surfaces | SDD-007 § D-3 | M00568 | composite | false |
| F02572 | D-3 answered (D-002, 2026-05-15) — keep current behavior; F-2027-062 slow-client timeout is documented upper bound on leak window | SDD-007 § Implementation status D-3 | E0226 | composite | false |
| F02573 | D-4 — [api] block in selfdef.toml gains 2 optional knobs | SDD-007 § D-4 | E0227 | composite | true |
| F02574 | D-4 knob — `max_sse_subscribers_per_token = 8` default | SDD-007 § D-4 + § Implementation status D-4 | M00569 | composite | true |
| F02575 | D-4 — per-token cap is backstop for malicious / leaked tokens | SDD-007 § D-4 | M00569 | composite | false |
| F02576 | D-4 knob — `max_sse_subscribers = 64` default (F-2027-061 global; unchanged from prior) | SDD-007 § D-4 + § Implementation status D-4 | M00570 | composite | true |
| F02577 | D-4 — global cap kept as second-line defence (many distinct tokens each fitting under per-token but process can't hold them all) | SDD-007 § D-4 | M00570 | composite | false |
| F02578 | D-4 — `selfdef-config::ApiConfig` gains optional `max_sse_subscribers: Option<usize>` field | SDD-007 § Implementation status D-4 | M00571 | composite | true |
| F02579 | D-4 — `selfdef-config::ApiConfig` gains optional `max_sse_subscribers_per_token: Option<usize>` field | SDD-007 § Implementation status D-4 | M00571 | composite | true |
| F02580 | D-4 — daemon copies into `ApiState::sse_caps` via `ApiState::with_sse_caps(SseCaps { … })` builder | SDD-007 § Implementation status D-4 | M00572 | composite | false |
| F02581 | D-4 — SubscriberGuard::try_acquire consults state-supplied overrides ahead of compiled-in constants | SDD-007 § Implementation status D-4 | M00559 | composite | false |
| F02582 | D-4 — `None`/`Some(0)` fall back to defaults (64 global, 8 per-token) | SDD-007 § Implementation status D-4 | M00569 + M00570 | composite | false |
| F02583 | D-4 — init-template STARTER_CONFIG ships two knobs commented at defaults so operators see them when bootstrapping | SDD-007 § Implementation status D-4 | M00573 | composite | true |
| F02584 | D-4 — 2 new integration tests pin override contract for both caps | SDD-007 § Implementation status D-4 | E0228 | composite | false |
| F02585 | D-5 test 1 — Per-token cap reached (open MAX_SSE_SUBSCRIBERS_PER_TOKEN + 1 connections same token; assert last gets 503 "per-token sse cap reached") | SDD-007 § D-5 1 + § Implementation status D-5 | M00574 | composite | true |
| F02586 | D-5 test 2 — Per-token cap is per-token (open MAX with token A then 1 with token B; assert B succeeds) | SDD-007 § D-5 2 + § Implementation status D-5 | M00574 | composite | true |
| F02587 | D-5 test 3 — Global cap still applies (open enough across distinct tokens to hit MAX_SSE_SUBSCRIBERS; assert 503 "sse subscriber cap reached") | SDD-007 § D-5 3 | E0228 | composite | true |
| F02588 | D-5 test 3 — covered by existing `events_stream_rejects_over_cap_with_503` from F-2027-061's closure | SDD-007 § Implementation status D-5 | E0228 | composite | false |
| F02589 | D-5 test 3 — `with_full_capability` fixture has no fingerprint so test still exercises global-cap path | SDD-007 § Implementation status D-5 | E0228 | composite | false |
| F02590 | D-5 test 4 — Rotation frees slots eventually (open per-token cap, rotate, close old, open new with new token, assert succeeds) | SDD-007 § D-5 4 | E0228 | composite | true |
| F02591 | D-5 test 5 — Per-token counter drops to zero (open then close N connections; assert HashMap empty) | SDD-007 § D-5 5 + § Implementation status D-5 | M00574 | composite | true |
| F02592 | D-5 — existing `events_stream_rejects_over_cap_with_503` test upgrades to also exercise per-token path (or splits into global_cap + per_token_cap) | SDD-007 § D-5 | E0228 | composite | false |
| F02593 | D-6 — both cap exhaustion modes return 503 Service Unavailable | SDD-007 § D-6 + § Implementation status D-6 | E0229 | composite | false |
| F02594 | D-6 — JSON body `{"error": "sse subscriber cap reached"}` for global cap | SDD-007 § D-6 | E0229 | composite | true |
| F02595 | D-6 global cap reason — MAX_SSE_SUBSCRIBERS exhausted; no single token to blame | SDD-007 § D-6 | E0229 | composite | false |
| F02596 | D-6 — JSON body `{"error": "per-token sse cap reached"}` for per-token cap | SDD-007 § D-6 | E0229 | composite | true |
| F02597 | D-6 per-token cap reason — this token's per-token slice is full; rotate the abusive token or wait for connections to drain | SDD-007 § D-6 | E0229 | composite | false |
| F02598 | D-6 — both surface through F-2028-016 JSON-extraction path in `events_follow_tcp` | SDD-007 § D-6 + § Implementation status D-6 | E0229 | composite | false |
| F02599 | Out of scope — Per-IP quota (would need coexist with token-quota path; audit didn't surface use case; NATted operators would suffer) | SDD-007 § Out of scope | M00575 | composite | false |
| F02600 | Out of scope — Quota-exhaustion metric (emit Prometheus counter so operators detect abusive tokens; mentioned for awareness; not blocking) | SDD-007 § Out of scope | M00575 | composite | false |
| F02601 | Out of scope — Token-issuer-time quota (daemon doesn't know which audience/scope token issued for; bearer-auth treats every token equivalently; per-audience quotas need rotation tool to thread audience metadata; separate redesign) | SDD-007 § Out of scope | M00575 | composite | false |
| F02602 | Phase A — D-1+D-2+D-3+D-4 implementation single PR; closes F-2028-037 + F-2028-039 | SDD-007 § Phasing | M00576 | composite | false |
| F02603 | Phase B — D-5 test coverage (paired with Phase A or immediate follow-up) | SDD-007 § Phasing | M00576 | composite | false |
| F02604 | Phase C — D-6 status-code semantics (already implicit in D-2 but called out as explicit contract) | SDD-007 § Phasing | M00576 | composite | false |
| F02605 | Phasing assumes one operator-time-bounded PR for implementation + one for tests (both can ship in same chunk) | SDD-007 § Phasing | M00576 | composite | false |
| F02606 | Status — Implemented; all 5 Ds shipped | SDD-007 § Status | E0221 | composite | false |
| F02607 | Status — D-1 fingerprint shipped | SDD-007 § Status | M00554 | composite | true |
| F02608 | Status — D-2 dual-counter guard shipped | SDD-007 § Status | M00558 | composite | true |
| F02609 | Status — D-3 deferred terminate-on-revoke (kept current behavior) | SDD-007 § Status | M00567 | composite | true |
| F02610 | Status — D-4 config knobs shipped | SDD-007 § Status | M00569 + M00570 | composite | true |
| F02611 | Status — D-5 tests shipped | SDD-007 § Status | M00574 | composite | true |
| F02612 | Status — D-6 distinguishable 503 reasons shipped | SDD-007 § Status | E0229 | composite | true |
| F02613 | Test plan covered — events_stream_rejects_over_cap_with_503 (existing from F-2027-061 closure) | SDD-007 § Implementation status D-5 | E0228 | composite | false |
| F02614 | Test plan — D-5.1 / D-5.2 / D-5.5 are 3 new tests in m12_api.rs | SDD-007 § Implementation status D-5 | M00574 | composite | false |
| F02615 | F-2027-062 slow-client timeout — documented upper bound on leak window per D-3 answer (D-002, 2026-05-15) | SDD-007 § Implementation status D-3 | M00567 | composite | false |
| F02616 | F-2028-016 — JSON-extraction path in events_follow_tcp (CLI side) | SDD-007 § D-6 + § Implementation status D-6 | E0229 | composite | false |
| F02617 | F-2027-059 cousin — STARTER_CONFIG ships two knobs commented at defaults | SDD-007 § D-4 | M00573 | composite | false |
| F02618 | Operator workflow — bootstrap selfdef.toml from STARTER_CONFIG; two knobs visible commented | SDD-007 § Implementation status D-4 | M00573 | composite | false |
| F02619 | Operator workflow — uncomment + tune `max_sse_subscribers_per_token` for per-token cap | SDD-007 § D-4 | M00569 | composite | false |
| F02620 | Operator workflow — uncomment + tune `max_sse_subscribers` for global cap | SDD-007 § D-4 | M00570 | composite | false |
| F02621 | Operator workflow — operator sees which cap was hit via JSON error body (D-6) | SDD-007 § D-6 | E0229 | composite | false |
| F02622 | Operator workflow — operator rotates abusive token via `selfdefctl api rotate-token` (SDD-004) to free per-token slice | SDD-007 § D-3 + cross-ref SDD-004 | M00566 | composite | false |
| F02623 | Project boundary — SDD-007 is selfdef-scope; sovereign-os doesn't consume /events/stream directly | architecture | E0221 | composite | false |
| F02624 | Project boundary — sovereign-os MAY consume via NATS bridge (MS015) which has its own per-host cap (operator-deployed) | MS015 + architecture | E0221 | composite | false |
| F02625 | Project boundary — MS007 typed-mirror crates may carry SseCaps schema for cross-repo audit | MS007 + SDD-038 | M00572 | composite | false |
| F02626 | Doctrine — per-token cap is FIRST line of defence; global cap is SECOND line | SDD-007 § D-4 | M00569 + M00570 | composite | false |
| F02627 | Doctrine — typed 503 reasons let operator diagnose which limit hit (per-token vs global) | SDD-007 § D-2 + § D-6 | M00564 + E0229 | composite | false |
| F02628 | Doctrine — fingerprint-based identity avoids storing secrets in HashMap | SDD-007 § D-1 | M00554 | composite | false |
| F02629 | Doctrine — HashMap pruning on counter==0 avoids leaks across token rotations | SDD-007 § D-2 | M00560 | composite | false |
| F02630 | Doctrine — revocation: terminate-new-immediately + drain-existing-naturally | SDD-007 § D-3 | M00566 + M00567 | composite | false |
| F02631 | Doctrine — operator-overridable via [api] config knobs (None/Some(0) = defaults) | SDD-007 § D-4 | M00569 + M00570 | composite | false |
| F02632 | Doctrine — STARTER_CONFIG visibility for new operators | SDD-007 § D-4 + § Implementation status D-4 | M00573 | composite | false |
| F02633 | Doctrine — both caps tested independently + together | SDD-007 § D-5 | E0228 | composite | false |
| F02634 | Doctrine — F-2027-062 slow-client timeout is the upper bound on revocation leak window (D-3 answer) | SDD-007 § Implementation status D-3 | F02615 | composite | false |
| F02635 | Audit-cycle integration — MS009 phase-6 80-security-audit covers F-2028-037 + F-2028-039 closure | MS009 phase-6 80-security-audit | E0221 | composite | false |
| F02636 | Audit-cycle integration — MS009 phase-6 70-tests-audit covers 5 D-5 integration tests | MS009 phase-6 70-tests-audit | M00574 | composite | false |
| F02637 | Audit-cycle integration — F-2026-NNN findings ledger tracks per-IP quota deferral + Prometheus metric deferral + audience/scope quota deferral | MS009 99-findings-ledger | M00575 | composite | false |
| F02638 | Integration with MS001 daemon core — `ApiState` + `ApiState::with_sse_caps` lifecycle | MS001 + SDD-007 § Implementation status D-4 | M00572 | composite | false |
| F02639 | Integration with MS019 security threat model — F-2028-037 closed at Adversary/Mitigation/Known gaps level via Token-bearer abuser branch | MS019 + SDD-007 § Why now | E0222 | composite | false |
| F02640 | Composite — SDD-007 ships per-token SSE subscriber quota via TokenFingerprint SHA-256 + dual-counter SubscriberGuard + 8/64 defaults + 2 config knobs + STARTER_CONFIG visibility + 3 new D-5 integration tests + 2 override-pinning tests + distinguishable 503 reasons; closes F-2028-037 + F-2028-039; D-3 deferred (slow-client timeout is upper bound on leak window); 3 deferrals (Per-IP / Prometheus metric / audience quota); all 5 Ds shipped in single PR collapse | SDD-007 entire | E0221 + E0222 + E0223 + E0224 + E0225 + E0226 + E0227 + E0228 + E0229 + E0230 | composite | false |

## Requirements (R05041–R05280)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R05041 | SDD-007 status = implemented (all 5 Ds shipped) | SDD-007 § header | F02521 | non-negotiable | false | 10 |
| R05042 | SDD-007 closes F-2028-037 | SDD-007 § header | F02522 | non-negotiable | false | 10 |
| R05043 | SDD-007 closes F-2028-039 | SDD-007 § header | F02523 | non-negotiable | false | 10 |
| R05044 | SDD-007 last updated 2026-05-14 | SDD-007 § header | F02524 | non-negotiable | false | 10 |
| R05045 | Phase 2 closed F-2027-061 with process-global subscriber cap MAX_SSE_SUBSCRIBERS = 64 | SDD-007 § Why now | F02525 + F02526 | non-negotiable | false | 10 |
| R05046 | F-2027-061 cap implemented via Arc<AtomicUsize> + RAII SubscriberGuard | SDD-007 § Why now | F02527 | non-negotiable | false | 10 |
| R05047 | Phase 3 security explorer PR #91 raised F-2028-037 (important) | SDD-007 § Why now | F02528 | non-negotiable | false | 10 |
| R05048 | F-2028-037 — cap is process-global but bearer-token treats every token as equivalent | SDD-007 § Why now | F02529 | non-negotiable | false | 10 |
| R05049 | F-2028-037 — one bearer-holder opening 64 concurrent /events/stream saturates cap | SDD-007 § Why now | F02530 | non-negotiable | false | 10 |
| R05050 | F-2028-037 — denies service to every other authenticated client | SDD-007 § Why now | F02531 | non-negotiable | false | 10 |
| R05051 | F-2028-037 — authenticated-only DoS but real for operators handing out tokens with same audience as read endpoints | SDD-007 § Why now | F02532 | non-negotiable | false | 10 |
| R05052 | F-2028-039 design counterpart — scope per-token quota mechanism, then implement | SDD-007 § Why now | F02533 | non-negotiable | false | 10 |
| R05053 | Goal 1 — bound abuse from single token; token-holder exhausts at most per-token slice, not whole cap | SDD-007 § Goals 1 | F02534 | non-negotiable | false | 10 |
| R05054 | Goal 2 — preserve revocation timeliness; rotation frees slots immediately, not at next bus message | SDD-007 § Goals 2 | F02535 | non-negotiable | false | 10 |
| R05055 | Goal 3 — no regression in legitimate single-operator case | SDD-007 § Goals 3 | F02536 | non-negotiable | false | 10 |
| R05056 | D-1 identity rejected option — Raw token bytes (stores secrets in memory) | SDD-007 § D-1 table | F02537 | non-negotiable | false | 10 |
| R05057 | D-1 identity chosen — Token fingerprint (SHA-256 of bytes) | SDD-007 § D-1 + § decision | F02538 + F02541 | non-negotiable | false | 10 |
| R05058 | D-1 identity rejected option — Token role/audience (doesn't address one-role abuse) | SDD-007 § D-1 table | F02539 | non-negotiable | false | 10 |
| R05059 | D-1 identity rejected option — Source IP (doesn't compose with rotation; NAT collapses holders) | SDD-007 § D-1 table | F02540 | non-negotiable | false | 10 |
| R05060 | TokenFingerprint type — SHA-256 / 32-byte | SDD-007 § Implementation status D-1 | M00554 | non-negotiable | true | 10 |
| R05061 | TokenFingerprint location — `crates/selfdef-api/src/transport.rs` | SDD-007 § Implementation status D-1 | M00555 | non-negotiable | false | 10 |
| R05062 | bearer_auth middleware threads TokenFingerprint into request.extensions() alongside Capability | SDD-007 § Implementation status D-1 | F02542 | non-negotiable | false | 10 |
| R05063 | Fingerprint computed once per request | SDD-007 § D-1 | F02542 | non-negotiable | false | 10 |
| R05064 | Fingerprint 32-byte handle stored in request.extensions() | SDD-007 § D-1 | F02543 | non-negotiable | false | 10 |
| R05065 | events_stream handler reads fingerprint without re-hashing | SDD-007 § D-1 | F02544 | non-negotiable | false | 10 |
| R05066 | Test helper — `with_full_capability_for_fingerprint` (in-process tests analogue) | SDD-007 § Implementation status D-1 | F02546 | non-negotiable | true | 10 |
| R05067 | ApiState per-token map — `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` | SDD-007 § D-2 + § Implementation status D-2 | F02547 | non-negotiable | false | 10 |
| R05068 | ApiState per-token map alongside existing global AtomicUsize | SDD-007 § Implementation status D-2 | F02548 | non-negotiable | false | 10 |
| R05069 | SubscriberGuard::try_acquire checks per-token first | SDD-007 § Implementation status D-2 | F02549 | non-negotiable | false | 10 |
| R05070 | SubscriberGuard::try_acquire rationale — typed 503 reason identifies abusive token's slice when it's the cause | SDD-007 § Implementation status D-2 | F02550 | non-negotiable | false | 10 |
| R05071 | SubscriberGuard::try_acquire then checks global cap | SDD-007 § Implementation status D-2 | F02551 | non-negotiable | false | 10 |
| R05072 | SubscriberGuard::try_acquire — on global-cap failure undoes per-token increment | SDD-007 § Implementation status D-2 | F02552 | non-negotiable | false | 10 |
| R05073 | SubscriberGuard::Drop decrements both counters | SDD-007 § D-2 + § Implementation status D-2 | F02553 | non-negotiable | false | 10 |
| R05074 | SubscriberGuard::Drop prunes HashMap entry when per-token count hits zero | SDD-007 § Implementation status D-2 | F02554 | non-negotiable | false | 10 |
| R05075 | No leak across rotations (HashMap pruning) | SDD-007 § Implementation status D-2 | F02555 | non-negotiable | false | 10 |
| R05076 | Quota flow step 1 — Read fingerprint from request.extensions() | SDD-007 § D-2 1 | F02556 | non-negotiable | false | 10 |
| R05077 | Quota flow step 2 — Acquire/create per-fingerprint counter under brief write lock | SDD-007 § D-2 2 | F02557 | non-negotiable | false | 10 |
| R05078 | Quota flow step 3 — CAS-increment per-fingerprint counter against per-token quota | SDD-007 § D-2 3 | F02558 | non-negotiable | false | 10 |
| R05079 | MAX_SSE_SUBSCRIBERS_PER_TOKEN default 8 | SDD-007 § D-2 | F02559 | non-negotiable | true | 10 |
| R05080 | Quota flow step 4 — 503 with typed reason "per-token sse cap reached" if at quota | SDD-007 § D-2 4 + § D-6 | F02560 | non-negotiable | false | 10 |
| R05081 | Typed 503 reason distinguishable from existing "sse subscriber cap reached" | SDD-007 § D-2 | F02561 | non-negotiable | false | 10 |
| R05082 | Quota flow step 5 — Otherwise increment global counter too | SDD-007 § D-2 5 | F02562 | non-negotiable | false | 10 |
| R05083 | Process-wide cap stays as backstop | SDD-007 § D-2 | F02563 | non-negotiable | false | 10 |
| R05084 | D-3 — bearer-auth middleware rejects new requests bearing old token on rotation | SDD-007 § D-3 | F02564 | non-negotiable | false | 10 |
| R05085 | D-3 — existing connections under old token NOT terminated by middleware | SDD-007 § D-3 | F02565 | non-negotiable | false | 10 |
| R05086 | D-3 — existing connections keep SubscriberGuard alive + continue draining | SDD-007 § D-3 | F02566 | non-negotiable | false | 10 |
| R05087 | D-3 threat-model adequacy — abusive token-holder loses ability to open NEW connections at moment of rotation | SDD-007 § D-3 | F02567 | non-negotiable | false | 10 |
| R05088 | D-3 — existing connections drain via normal client-disconnect / slow-client-timeout | SDD-007 § D-3 | F02568 | non-negotiable | false | 10 |
| R05089 | D-3 stricter model (future hardening) — `drained_at: Option<Instant>` + writer task checks on every send | SDD-007 § D-3 | F02569 | non-negotiable | false | 10 |
| R05090 | D-3 stricter model — out of scope for D-2 first cut | SDD-007 § D-3 | F02570 | non-negotiable | false | 10 |
| R05091 | D-3 future hardening — revisit only if operator demand surfaces | SDD-007 § D-3 | F02571 | non-negotiable | false | 10 |
| R05092 | D-3 answered (D-002, 2026-05-15) — keep current behavior | SDD-007 § Implementation status D-3 | F02572 | non-negotiable | false | 10 |
| R05093 | D-3 answer rationale — F-2027-062 slow-client timeout is documented upper bound on leak window | SDD-007 § Implementation status D-3 | F02615 | non-negotiable | false | 10 |
| R05094 | D-4 — [api] block in selfdef.toml gains 2 optional knobs | SDD-007 § D-4 | F02573 | non-negotiable | true | 10 |
| R05095 | D-4 knob — `max_sse_subscribers_per_token = 8` default | SDD-007 § D-4 + § Implementation status D-4 | F02574 | non-negotiable | true | 10 |
| R05096 | D-4 per-token cap rationale — backstop for malicious/leaked tokens | SDD-007 § D-4 | F02575 | non-negotiable | false | 10 |
| R05097 | D-4 knob — `max_sse_subscribers = 64` default (F-2027-061 unchanged) | SDD-007 § D-4 + § Implementation status D-4 | F02576 | non-negotiable | true | 10 |
| R05098 | D-4 global cap rationale — second-line defence | SDD-007 § D-4 | F02577 | non-negotiable | false | 10 |
| R05099 | D-4 — `selfdef-config::ApiConfig` gains optional `max_sse_subscribers: Option<usize>` | SDD-007 § Implementation status D-4 | F02578 | non-negotiable | true | 10 |
| R05100 | D-4 — `selfdef-config::ApiConfig` gains optional `max_sse_subscribers_per_token: Option<usize>` | SDD-007 § Implementation status D-4 | F02579 | non-negotiable | true | 10 |
| R05101 | D-4 — daemon copies into ApiState::sse_caps via `ApiState::with_sse_caps(SseCaps { … })` builder | SDD-007 § Implementation status D-4 | F02580 | non-negotiable | false | 10 |
| R05102 | D-4 — SubscriberGuard::try_acquire consults state-supplied overrides ahead of compiled-in constants | SDD-007 § Implementation status D-4 | F02581 | non-negotiable | false | 10 |
| R05103 | D-4 — `None` / `Some(0)` fall back to defaults (64 global, 8 per-token) | SDD-007 § Implementation status D-4 | F02582 | non-negotiable | false | 10 |
| R05104 | D-4 — STARTER_CONFIG ships two knobs commented at defaults so operators see them when bootstrapping | SDD-007 § Implementation status D-4 | F02583 | non-negotiable | true | 10 |
| R05105 | D-4 — 2 new integration tests pin override contract for both caps | SDD-007 § Implementation status D-4 | F02584 | non-negotiable | false | 10 |
| R05106 | D-5 test 1 — Per-token cap reached (MAX + 1 connections same token; last 503 "per-token sse cap reached") | SDD-007 § D-5 1 + § Implementation status D-5 | F02585 | non-negotiable | true | 10 |
| R05107 | D-5 test 2 — Per-token cap is per-token (token A maxed; token B succeeds) | SDD-007 § D-5 2 + § Implementation status D-5 | F02586 | non-negotiable | true | 10 |
| R05108 | D-5 test 3 — Global cap still applies (distinct tokens hitting MAX_SSE_SUBSCRIBERS; 503 "sse subscriber cap reached") | SDD-007 § D-5 3 | F02587 | non-negotiable | true | 10 |
| R05109 | D-5 test 3 — covered by existing `events_stream_rejects_over_cap_with_503` from F-2027-061 closure | SDD-007 § Implementation status D-5 | F02588 | non-negotiable | false | 10 |
| R05110 | D-5 test 3 — `with_full_capability` fixture has no fingerprint so test still exercises global-cap path | SDD-007 § Implementation status D-5 | F02589 | non-negotiable | false | 10 |
| R05111 | D-5 test 4 — Rotation frees slots eventually (open per-token cap, rotate, close old, open new with new token, assert succeeds) | SDD-007 § D-5 4 | F02590 | non-negotiable | true | 10 |
| R05112 | D-5 test 5 — Per-token counter drops to zero (open then close N connections; assert HashMap empty) | SDD-007 § D-5 5 + § Implementation status D-5 | F02591 | non-negotiable | true | 10 |
| R05113 | D-5 — existing test upgrades to also exercise per-token path (or splits into global_cap + per_token_cap) | SDD-007 § D-5 | F02592 | non-negotiable | false | 10 |
| R05114 | D-6 — both cap exhaustion modes return 503 Service Unavailable | SDD-007 § D-6 + § Implementation status D-6 | F02593 | non-negotiable | false | 10 |
| R05115 | D-6 — JSON body `{"error": "sse subscriber cap reached"}` for global cap | SDD-007 § D-6 | F02594 | non-negotiable | true | 10 |
| R05116 | D-6 global cap reason — MAX_SSE_SUBSCRIBERS exhausted; no single token to blame | SDD-007 § D-6 | F02595 | non-negotiable | false | 10 |
| R05117 | D-6 — JSON body `{"error": "per-token sse cap reached"}` for per-token cap | SDD-007 § D-6 | F02596 | non-negotiable | true | 10 |
| R05118 | D-6 per-token cap reason — this token's per-token slice is full | SDD-007 § D-6 | F02597 | non-negotiable | false | 10 |
| R05119 | D-6 — operator action: rotate the abusive token or wait for connections to drain | SDD-007 § D-6 | F02597 | non-negotiable | false | 10 |
| R05120 | D-6 — both surface through F-2028-016 JSON-extraction path in `events_follow_tcp` | SDD-007 § D-6 + § Implementation status D-6 | F02598 | non-negotiable | false | 10 |
| R05121 | Out-of-scope deferral — Per-IP quota (NATted operators would suffer) | SDD-007 § Out of scope | F02599 | non-negotiable | false | 10 |
| R05122 | Out-of-scope deferral — Quota-exhaustion Prometheus counter (mentioned for awareness; not blocking) | SDD-007 § Out of scope | F02600 | non-negotiable | false | 10 |
| R05123 | Out-of-scope deferral — Token-issuer-time / audience / scope quota (separate redesign) | SDD-007 § Out of scope | F02601 | non-negotiable | false | 10 |
| R05124 | Phasing — Phase A: D-1+D-2+D-3+D-4 implementation single PR | SDD-007 § Phasing | F02602 | non-negotiable | false | 10 |
| R05125 | Phasing — Phase A closes F-2028-037 + F-2028-039 | SDD-007 § Phasing | F02602 | non-negotiable | false | 10 |
| R05126 | Phasing — Phase B: D-5 test coverage (paired with Phase A or immediate follow-up) | SDD-007 § Phasing | F02603 | non-negotiable | false | 10 |
| R05127 | Phasing — Phase C: D-6 status-code semantics (already implicit in D-2 but explicit contract) | SDD-007 § Phasing | F02604 | non-negotiable | false | 10 |
| R05128 | Phasing — both PRs can ship in same chunk if test-fixture work doesn't bloat diff | SDD-007 § Phasing | F02605 | non-negotiable | false | 10 |
| R05129 | Status — Implemented; all 5 Ds shipped | SDD-007 § Status | F02606 | non-negotiable | false | 10 |
| R05130 | Status — D-1 fingerprint shipped | SDD-007 § Status | F02607 | non-negotiable | true | 10 |
| R05131 | Status — D-2 dual-counter guard shipped | SDD-007 § Status | F02608 | non-negotiable | true | 10 |
| R05132 | Status — D-3 deferred terminate-on-revoke (kept current behavior per D-002 answer) | SDD-007 § Status | F02609 | non-negotiable | true | 10 |
| R05133 | Status — D-4 config knobs shipped | SDD-007 § Status | F02610 | non-negotiable | true | 10 |
| R05134 | Status — D-5 tests shipped | SDD-007 § Status | F02611 | non-negotiable | true | 10 |
| R05135 | Status — D-6 distinguishable 503 reasons shipped | SDD-007 § Status | F02612 | non-negotiable | true | 10 |
| R05136 | Test integration file — `crates/selfdef-api/tests/m12_api.rs` | SDD-007 § D-5 + § Implementation status D-5 | M00574 | non-negotiable | false | 10 |
| R05137 | Test coverage — D-5.1 / D-5.2 / D-5.5 are 3 new tests | SDD-007 § Implementation status D-5 | F02614 | non-negotiable | false | 10 |
| R05138 | F-2027-062 — slow-client timeout (per D-3 answer is documented upper bound on leak window) | SDD-007 § Implementation status D-3 | F02615 | non-negotiable | false | 10 |
| R05139 | F-2028-016 — JSON-extraction path in events_follow_tcp (CLI side) | SDD-007 § D-6 + § Implementation status D-6 | F02616 | non-negotiable | false | 10 |
| R05140 | F-2027-059 cousin — STARTER_CONFIG ships two knobs commented at defaults | SDD-007 § D-4 | F02617 | non-negotiable | false | 10 |
| R05141 | Operator workflow — bootstrap selfdef.toml from STARTER_CONFIG; 2 knobs visible commented | SDD-007 § Implementation status D-4 | F02618 | non-negotiable | false | 10 |
| R05142 | Operator workflow — uncomment + tune max_sse_subscribers_per_token | SDD-007 § D-4 | F02619 | non-negotiable | false | 10 |
| R05143 | Operator workflow — uncomment + tune max_sse_subscribers | SDD-007 § D-4 | F02620 | non-negotiable | false | 10 |
| R05144 | Operator workflow — operator sees which cap was hit via JSON error body | SDD-007 § D-6 | F02621 | non-negotiable | false | 10 |
| R05145 | Operator workflow — rotate abusive token via `selfdefctl api rotate-token` (SDD-004) to free per-token slice | SDD-007 § D-3 + cross-ref SDD-004 | F02622 | non-negotiable | false | 10 |
| R05146 | Project boundary — SDD-007 is selfdef-scope; sovereign-os doesn't consume /events/stream directly | architecture | F02623 | non-negotiable | false | 10 |
| R05147 | Project boundary — sovereign-os MAY consume via NATS bridge (MS015) which has own per-host cap (operator-deployed) | MS015 + architecture | F02624 | non-negotiable | false | 10 |
| R05148 | Project boundary — MS007 typed-mirror crates may carry SseCaps schema for cross-repo audit | MS007 + SDD-038 | F02625 | non-negotiable | false | 10 |
| R05149 | Doctrine — per-token cap is FIRST line of defence; global cap is SECOND line | SDD-007 § D-4 | F02626 | non-negotiable | false | 10 |
| R05150 | Doctrine — typed 503 reasons enable operator diagnosis (per-token vs global) | SDD-007 § D-2 + § D-6 | F02627 | non-negotiable | false | 10 |
| R05151 | Doctrine — fingerprint-based identity avoids storing secrets in HashMap | SDD-007 § D-1 | F02628 | non-negotiable | false | 10 |
| R05152 | Doctrine — HashMap pruning on counter==0 avoids leaks across token rotations | SDD-007 § D-2 | F02629 | non-negotiable | false | 10 |
| R05153 | Doctrine — revocation: terminate-new-immediately + drain-existing-naturally | SDD-007 § D-3 | F02630 | non-negotiable | false | 10 |
| R05154 | Doctrine — operator-overridable via [api] config knobs | SDD-007 § D-4 | F02631 | non-negotiable | false | 10 |
| R05155 | Doctrine — STARTER_CONFIG visibility for new operators | SDD-007 § D-4 + § Implementation status D-4 | F02632 | non-negotiable | false | 10 |
| R05156 | Doctrine — both caps tested independently AND together | SDD-007 § D-5 | F02633 | non-negotiable | false | 10 |
| R05157 | Doctrine — F-2027-062 slow-client timeout is upper bound on revocation leak window | SDD-007 § Implementation status D-3 | F02634 | non-negotiable | false | 10 |
| R05158 | Audit-cycle integration — MS009 phase-6 80-security-audit covers F-2028-037+F-2028-039 closure | MS009 phase-6 80-security-audit | F02635 | non-negotiable | false | 10 |
| R05159 | Audit-cycle integration — MS009 phase-6 70-tests-audit covers 5 D-5 integration tests | MS009 phase-6 70-tests-audit | F02636 | non-negotiable | false | 10 |
| R05160 | Audit-cycle integration — F-2026-NNN findings ledger tracks 3 out-of-scope deferrals | MS009 99-findings-ledger | F02637 | non-negotiable | false | 10 |
| R05161 | Integration with MS001 daemon core — ApiState + ApiState::with_sse_caps lifecycle | MS001 + SDD-007 § Implementation status D-4 | F02638 | non-negotiable | false | 10 |
| R05162 | Integration with MS019 security threat model — F-2028-037 closed at Adversary/Mitigation/Known-gaps level | MS019 + SDD-007 § Why now | F02639 | non-negotiable | false | 10 |
| R05163 | Integration with MS013 27-SDD charter — SDD-007 is foundational 000-009 layer per MS013 R03012 | MS013 + SDD-007 | E0221 | non-negotiable | false | 10 |
| R05164 | Integration with MS020 test contract — 5 D-5 tests follow Cat 2 (Pipeline) + Cat 4 (Seam) pattern | MS020 + SDD-007 § D-5 | E0228 | non-negotiable | false | 10 |
| R05165 | Integration with MS019 SDD-004 D-4 metrics-token rotation — rotation flow integrates with per-token quota release | MS019 SDD-004 D-4 + SDD-007 § D-3 | M00566 | non-negotiable | false | 10 |
| R05166 | Symbol — TokenFingerprint (SHA-256 32-byte) | SDD-007 § Implementation status D-1 | M00554 | non-negotiable | false | 10 |
| R05167 | Symbol — request.extensions() carries TokenFingerprint alongside Capability | SDD-007 § Implementation status D-1 | F02542 | non-negotiable | false | 10 |
| R05168 | Symbol — with_full_capability_for_fingerprint (test-helpers analogue) | SDD-007 § Implementation status D-1 | F02546 | non-negotiable | true | 10 |
| R05169 | Symbol — `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` (ApiState per-token map) | SDD-007 § D-2 + § Implementation status D-2 | F02547 | non-negotiable | false | 10 |
| R05170 | Symbol — `SubscriberGuard::try_acquire` (RAII guard acquire path) | SDD-007 § Implementation status D-2 | F02549 | non-negotiable | false | 10 |
| R05171 | Symbol — `SubscriberGuard::Drop` (RAII guard release path) | SDD-007 § Implementation status D-2 | F02553 | non-negotiable | false | 10 |
| R05172 | Symbol — `MAX_SSE_SUBSCRIBERS_PER_TOKEN` compiled-in constant (default 8) | SDD-007 § D-2 | F02559 | non-negotiable | true | 10 |
| R05173 | Symbol — `MAX_SSE_SUBSCRIBERS` compiled-in constant (default 64) | SDD-007 § Why now | F02526 | non-negotiable | true | 10 |
| R05174 | Symbol — `ApiState::with_sse_caps(SseCaps { … })` builder | SDD-007 § Implementation status D-4 | F02580 | non-negotiable | false | 10 |
| R05175 | Symbol — `SseCaps` struct (carries max_sse_subscribers + max_sse_subscribers_per_token) | SDD-007 § Implementation status D-4 | F02580 | non-negotiable | false | 10 |
| R05176 | Symbol — `selfdef-config::ApiConfig` extended with 2 Option<usize> fields | SDD-007 § Implementation status D-4 | F02578 + F02579 | non-negotiable | false | 10 |
| R05177 | Symbol — `STARTER_CONFIG` init-template with 2 knobs commented at defaults | SDD-007 § Implementation status D-4 | F02583 | non-negotiable | false | 10 |
| R05178 | Symbol — `events_stream_rejects_over_cap_with_503` (existing test from F-2027-061 closure) | SDD-007 § Implementation status D-5 | F02588 | non-negotiable | false | 10 |
| R05179 | Symbol — `with_full_capability` (existing test fixture; no fingerprint; exercises global-cap path) | SDD-007 § Implementation status D-5 | F02589 | non-negotiable | false | 10 |
| R05180 | Symbol — `events_follow_tcp` (CLI side; F-2028-016 JSON-extraction path) | SDD-007 § D-6 + § Implementation status D-6 | F02616 | non-negotiable | false | 10 |
| R05181 | Symbol — JSON error key `"error"` (D-6 contract field) | SDD-007 § D-6 | F02594 + F02596 | non-negotiable | false | 10 |
| R05182 | Symbol — JSON error value `"sse subscriber cap reached"` (global cap) | SDD-007 § D-6 | F02594 | non-negotiable | true | 10 |
| R05183 | Symbol — JSON error value `"per-token sse cap reached"` (per-token cap) | SDD-007 § D-6 | F02596 | non-negotiable | true | 10 |
| R05184 | Symbol — HTTP status 503 Service Unavailable (both cap modes) | SDD-007 § D-6 + § Implementation status D-6 | F02593 | non-negotiable | false | 10 |
| R05185 | Identity contract — SHA-256 of token bytes computed once per request | SDD-007 § D-1 | F02542 | non-negotiable | false | 10 |
| R05186 | Identity contract — 32-byte fingerprint stored in request.extensions() | SDD-007 § D-1 | F02543 | non-negotiable | false | 10 |
| R05187 | Identity contract — events_stream handler reads without re-hashing | SDD-007 § D-1 | F02544 | non-negotiable | false | 10 |
| R05188 | Identity contract — bearer-auth middleware computes fingerprint once + threads through request.extensions() | SDD-007 § D-1 | F02542 | non-negotiable | false | 10 |
| R05189 | Identity contract — fingerprint is stable handle across rotations? No — rotation changes token bytes → fingerprint changes | SDD-007 § D-3 | M00566 | non-negotiable | false | 10 |
| R05190 | Per-token contract — counter is keyed by fingerprint | SDD-007 § D-2 + § Implementation status D-2 | F02547 | non-negotiable | false | 10 |
| R05191 | Per-token contract — counter is AtomicUsize | SDD-007 § D-2 + § Implementation status D-2 | F02547 | non-negotiable | false | 10 |
| R05192 | Per-token contract — counter incremented on try_acquire success | SDD-007 § D-2 | M00559 | non-negotiable | false | 10 |
| R05193 | Per-token contract — counter decremented on SubscriberGuard::Drop | SDD-007 § D-2 + § Implementation status D-2 | M00560 | non-negotiable | false | 10 |
| R05194 | Per-token contract — HashMap entry pruned when counter hits zero | SDD-007 § Implementation status D-2 | F02554 | non-negotiable | false | 10 |
| R05195 | Per-token contract — pruning avoids leak across token rotations | SDD-007 § Implementation status D-2 | F02555 | non-negotiable | false | 10 |
| R05196 | Per-token contract — quota compared against MAX_SSE_SUBSCRIBERS_PER_TOKEN (default 8, operator-overridable) | SDD-007 § D-2 + § D-4 | F02559 | non-negotiable | false | 10 |
| R05197 | Per-token contract — quota check via CAS-increment | SDD-007 § D-2 3 | F02558 | non-negotiable | false | 10 |
| R05198 | Per-token contract — failure returns 503 "per-token sse cap reached" | SDD-007 § D-2 4 + § D-6 | F02560 | non-negotiable | false | 10 |
| R05199 | Per-token contract — success increments global counter too | SDD-007 § D-2 5 | F02562 | non-negotiable | false | 10 |
| R05200 | Per-token contract — global-cap failure undoes per-token increment | SDD-007 § Implementation status D-2 | F02552 | non-negotiable | false | 10 |
| R05201 | Global contract — counter is process-wide AtomicUsize | SDD-007 § Why now | F02527 | non-negotiable | false | 10 |
| R05202 | Global contract — quota compared against MAX_SSE_SUBSCRIBERS (default 64, operator-overridable) | SDD-007 § Why now + § D-4 | M00551 + F02576 | non-negotiable | false | 10 |
| R05203 | Global contract — second-line defence for many tokens fitting under per-token but exhausting process resources | SDD-007 § D-2 + § D-4 | F02563 + F02577 | non-negotiable | false | 10 |
| R05204 | Global contract — failure returns 503 "sse subscriber cap reached" | SDD-007 § D-6 | F02594 | non-negotiable | false | 10 |
| R05205 | Revocation contract — bearer-auth refuses NEW connections immediately on rotation | SDD-007 § D-3 | F02564 | non-negotiable | false | 10 |
| R05206 | Revocation contract — existing connections NOT terminated; drain via normal client-disconnect / slow-client-timeout | SDD-007 § D-3 | F02565 + F02568 | non-negotiable | false | 10 |
| R05207 | Revocation contract — F-2027-062 slow-client timeout is documented upper bound on leak window | SDD-007 § Implementation status D-3 | F02615 | non-negotiable | false | 10 |
| R05208 | Revocation contract — abusive token-holder loses ability to open NEW connections at moment of rotation | SDD-007 § D-3 | F02567 | non-negotiable | false | 10 |
| R05209 | Revocation contract — terminate-all-existing is FUTURE HARDENING (D-3 deferred, D-002 answered) | SDD-007 § Implementation status D-3 | F02569 + F02572 | non-negotiable | false | 10 |
| R05210 | Config contract — knobs are operator-overridable via [api] block | SDD-007 § D-4 | F02573 | non-negotiable | false | 10 |
| R05211 | Config contract — None/Some(0) fall back to compiled-in defaults | SDD-007 § Implementation status D-4 | F02582 | non-negotiable | false | 10 |
| R05212 | Config contract — STARTER_CONFIG init-template ships both knobs commented at defaults | SDD-007 § Implementation status D-4 | F02583 | non-negotiable | false | 10 |
| R05213 | Config contract — `selfdef-config::ApiConfig` is the canonical Rust shape | SDD-007 § Implementation status D-4 | M00571 | non-negotiable | false | 10 |
| R05214 | Config contract — `ApiState::with_sse_caps(SseCaps { … })` is the builder | SDD-007 § Implementation status D-4 | M00572 | non-negotiable | false | 10 |
| R05215 | Test contract — D-5.1 in m12_api.rs (Per-token cap reached) | SDD-007 § Implementation status D-5 | M00574 + F02585 | non-negotiable | false | 10 |
| R05216 | Test contract — D-5.2 in m12_api.rs (Per-token cap is per-fingerprint) | SDD-007 § Implementation status D-5 | M00574 + F02586 | non-negotiable | false | 10 |
| R05217 | Test contract — D-5.5 in m12_api.rs (Per-token counter drops to zero on disconnect) | SDD-007 § Implementation status D-5 | M00574 + F02591 | non-negotiable | false | 10 |
| R05218 | Test contract — D-5.3 covered by existing events_stream_rejects_over_cap_with_503 | SDD-007 § Implementation status D-5 | F02588 | non-negotiable | false | 10 |
| R05219 | Test contract — D-5.4 covered by rotation flow + slow-client timeout (D-3 answer) | SDD-007 § Implementation status D-5 | F02590 | non-negotiable | false | 10 |
| R05220 | Test contract — 2 new integration tests pin D-4 override contract for both caps | SDD-007 § Implementation status D-4 | F02584 | non-negotiable | false | 10 |
| R05221 | Status-code contract — 503 Service Unavailable on both cap exhaustion modes | SDD-007 § D-6 + § Implementation status D-6 | F02593 | non-negotiable | false | 10 |
| R05222 | Status-code contract — distinguishable JSON error body identifies which cap | SDD-007 § D-6 | F02594 + F02596 | non-negotiable | false | 10 |
| R05223 | Status-code contract — `events_follow_tcp` surfaces both reasons (F-2028-016 JSON-extraction path) | SDD-007 § D-6 + § Implementation status D-6 | F02598 | non-negotiable | false | 10 |
| R05224 | Out-of-scope — Per-IP quota (NAT collapse + audit didn't surface use case) | SDD-007 § Out of scope | F02599 | non-negotiable | false | 10 |
| R05225 | Out-of-scope — Quota-exhaustion Prometheus counter (awareness only; not blocking) | SDD-007 § Out of scope | F02600 | non-negotiable | false | 10 |
| R05226 | Out-of-scope — Token-issuer-time / audience / scope quota (separate redesign; needs rotation tool to thread audience metadata) | SDD-007 § Out of scope | F02601 | non-negotiable | false | 10 |
| R05227 | Phasing — Phase A single PR | SDD-007 § Phasing | F02602 | non-negotiable | false | 10 |
| R05228 | Phasing — Phase B paired or follow-up | SDD-007 § Phasing | F02603 | non-negotiable | false | 10 |
| R05229 | Phasing — Phase C explicit contract | SDD-007 § Phasing | F02604 | non-negotiable | false | 10 |
| R05230 | Phasing — both PRs ship in same chunk if test-fixture doesn't bloat | SDD-007 § Phasing | F02605 | non-negotiable | false | 10 |
| R05231 | Status reaffirmation — D-1 fingerprint shipped | SDD-007 § Status | F02607 | non-negotiable | true | 10 |
| R05232 | Status reaffirmation — D-2 dual-counter guard shipped | SDD-007 § Status | F02608 | non-negotiable | true | 10 |
| R05233 | Status reaffirmation — D-3 deferred per D-002 answer | SDD-007 § Status | F02609 | non-negotiable | true | 10 |
| R05234 | Status reaffirmation — D-4 config knobs shipped | SDD-007 § Status | F02610 | non-negotiable | true | 10 |
| R05235 | Status reaffirmation — D-5 tests shipped | SDD-007 § Status | F02611 | non-negotiable | true | 10 |
| R05236 | Status reaffirmation — D-6 distinguishable 503 reasons shipped | SDD-007 § Status | F02612 | non-negotiable | true | 10 |
| R05237 | Audit-cycle integration — MS009 phase-6 80-security-audit covers F-2028-037+F-2028-039 closure | MS009 phase-6 80-security-audit | F02635 | non-negotiable | false | 10 |
| R05238 | Audit-cycle integration — MS009 phase-6 70-tests-audit covers 5 D-5 integration tests | MS009 phase-6 70-tests-audit | F02636 | non-negotiable | false | 10 |
| R05239 | Audit-cycle integration — F-2026-NNN findings ledger tracks 3 out-of-scope deferrals | MS009 99-findings-ledger | F02637 | non-negotiable | false | 10 |
| R05240 | Integration with MS013 27-SDD charter — SDD-007 foundational 000-009 layer per MS013 R03012 | MS013 | E0221 | non-negotiable | false | 10 |
| R05241 | Integration with MS019 SDD-004 — metrics-token rotation + per-token quota integrate (rotation frees per-token slice immediately for new connections; existing connections drain) | MS019 + SDD-007 § D-3 | F02622 | non-negotiable | false | 10 |
| R05242 | Integration with MS020 test contract — 5 D-5 tests are Cat 2 (Pipeline) + Cat 4 (Seam) per SDD-005 contract | MS020 + SDD-007 § D-5 | E0228 | non-negotiable | false | 10 |
| R05243 | Integration with MS001 daemon core — ApiState + ApiState::with_sse_caps lifecycle | MS001 + SDD-007 § Implementation status D-4 | F02638 | non-negotiable | false | 10 |
| R05244 | Integration with MS013 27-SDD charter — SDD-007 cites SDD-004 (api.token + control_token_file) in Appendix | MS013 + SDD-007 references | E0227 | non-negotiable | false | 10 |
| R05245 | Project boundary — selfdef-scope only; sovereign-os doesn't consume /events/stream directly | architecture | F02623 | non-negotiable | false | 10 |
| R05246 | Project boundary — sovereign-os MAY consume via NATS bridge (MS015) which has own per-host cap | MS015 + architecture | F02624 | non-negotiable | false | 10 |
| R05247 | Project boundary — MS007 typed-mirror crates may carry SseCaps schema for cross-repo audit | MS007 + SDD-038 | F02625 | non-negotiable | false | 10 |
| R05248 | Project boundary — Oracle-Triage MS004 E0036 may carry SSE cap events for cross-repo correlation | MS004 E0036 + SDD-007 | E0226 | non-negotiable | false | 10 |
| R05249 | Doctrine — per-token cap is FIRST line; global cap is SECOND line | SDD-007 § D-4 | F02626 | non-negotiable | false | 10 |
| R05250 | Doctrine — typed 503 reasons enable operator diagnosis | SDD-007 § D-2 + § D-6 | F02627 | non-negotiable | false | 10 |
| R05251 | Doctrine — fingerprint identity avoids storing secrets | SDD-007 § D-1 | F02628 | non-negotiable | false | 10 |
| R05252 | Doctrine — HashMap pruning avoids leaks | SDD-007 § D-2 | F02629 | non-negotiable | false | 10 |
| R05253 | Doctrine — revocation terminate-new + drain-existing | SDD-007 § D-3 | F02630 | non-negotiable | false | 10 |
| R05254 | Doctrine — operator-overridable defaults | SDD-007 § D-4 | F02631 | non-negotiable | false | 10 |
| R05255 | Doctrine — STARTER_CONFIG visibility | SDD-007 § Implementation status D-4 | F02632 | non-negotiable | false | 10 |
| R05256 | Doctrine — both caps tested independently + together | SDD-007 § D-5 | F02633 | non-negotiable | false | 10 |
| R05257 | Doctrine — F-2027-062 slow-client timeout = revocation leak-window upper bound | SDD-007 § Implementation status D-3 | F02634 | non-negotiable | false | 10 |
| R05258 | Doctrine — fingerprint NEVER stored alongside secret (one-way hash) | SDD-007 § D-1 | F02538 | non-negotiable | false | 10 |
| R05259 | Doctrine — quota flow is per-fingerprint-first then global (NOT global-first) | SDD-007 § D-2 + § Implementation status D-2 | F02549 | non-negotiable | false | 10 |
| R05260 | Doctrine — terminate-all-existing on rotation is future hardening (NOT current behavior per D-002 answer) | SDD-007 § Implementation status D-3 | F02572 | non-negotiable | false | 10 |
| R05261 | Doctrine — quota knobs are Option<usize> with None/Some(0) falling back to defaults | SDD-007 § Implementation status D-4 | F02582 | non-negotiable | false | 10 |
| R05262 | Doctrine — both quota knobs visible in STARTER_CONFIG commented at defaults | SDD-007 § Implementation status D-4 | F02583 | non-negotiable | false | 10 |
| R05263 | Doctrine — per-IP quota deliberately NOT shipped (NAT collapse) | SDD-007 § Out of scope | F02599 | non-negotiable | false | 10 |
| R05264 | Doctrine — Prometheus exhaustion metric deliberately deferred to future SDD | SDD-007 § Out of scope | F02600 | non-negotiable | false | 10 |
| R05265 | Doctrine — audience/scope quota deliberately deferred to separate redesign | SDD-007 § Out of scope | F02601 | non-negotiable | false | 10 |
| R05266 | Composite — SDD-007 covers F-2028-037+F-2028-039 closure via TokenFingerprint SHA-256 + dual-counter SubscriberGuard | SDD-007 entire | F02640 | non-negotiable | false | 10 |
| R05267 | Composite — 8/64 defaults; 2 config knobs; STARTER_CONFIG visibility; 3 D-5 tests; 2 override-pinning tests; distinguishable 503 reasons | SDD-007 entire | F02640 | non-negotiable | false | 10 |
| R05268 | Composite — D-3 deferred (slow-client timeout is upper bound on leak window per D-002 answer 2026-05-15) | SDD-007 § Implementation status D-3 + § Status | F02572 + F02609 | non-negotiable | false | 10 |
| R05269 | Composite — 3 deferrals (Per-IP / Prometheus metric / audience quota) | SDD-007 § Out of scope | F02599 + F02600 + F02601 | non-negotiable | false | 10 |
| R05270 | Composite — all 5 Ds shipped in single PR collapse per operator big-chunks steer | SDD-007 § Implementation status + § Status | F02606 | non-negotiable | false | 10 |
| R05271 | Composite — integrates with MS001 daemon core / MS013 27-SDD charter / MS019 security threat model (SDD-004 metrics-token rotation) / MS020 test contract (Cat 2 + Cat 4) | SDD-007 + MS001 + MS013 + MS019 + MS020 | E0221 + E0228 | non-negotiable | false | 10 |
| R05272 | Composite — project boundary preserved (selfdef-scope; cross-repo via NATS+MS007+Oracle-Triage MS004 E0036) | architecture + MS015 + MS007 + MS004 E0036 | F02623 + F02624 + F02625 | non-negotiable | false | 10 |
| R05273 | Composite — doctrine surface (8 design doctrines from F02626-F02634; 9 invariant doctrines from R05258-R05265) | SDD-007 entire | F02626-F02634 + R05258-R05265 | non-negotiable | false | 10 |
| R05274 | Composite — symbol surface (TokenFingerprint + with_full_capability_for_fingerprint + ApiState per-token map + SubscriberGuard::try_acquire + SubscriberGuard::Drop + 2 compiled-in constants + SseCaps + STARTER_CONFIG + 2 JSON error values + 503 status code) | SDD-007 entire | R05166-R05184 | non-negotiable | false | 10 |
| R05275 | Composite — identity contract + per-token contract + global contract + revocation contract + config contract + test contract + status-code contract = 7 layered contracts | SDD-007 entire | R05185-R05223 | non-negotiable | false | 10 |
| R05276 | Composite — operator workflow surface (5 steps: bootstrap STARTER_CONFIG → uncomment per-token knob → uncomment global knob → diagnose via 503 JSON body → rotate abusive token) | SDD-007 entire | F02618 + F02619 + F02620 + F02621 + F02622 | non-negotiable | false | 10 |
| R05277 | Composite — phasing was 3-phase (A implementation / B tests / C contract) collapsed to single PR | SDD-007 § Phasing | F02602 + F02603 + F02604 + F02605 | non-negotiable | false | 10 |
| R05278 | Composite — MS022 covers SDD-007 + integrates with MS001 daemon core + MS013 27-SDD charter + MS019 SDD-004 security threat model (metrics-token rotation) + MS020 test contract (Cat 2 + Cat 4) | INDEX.md MS022 + SDD-007 + MS001 + MS013 + MS019 + MS020 | E0221 + E0228 + E0229 + E0230 | non-negotiable | false | 10 |
| R05279 | Composite — F-2028-037 important finding closed; F-2028-039 design counterpart closed; F-2027-061 global cap preserved as backstop | SDD-007 § header + § Why now | F02522 + F02523 + F02527 | non-negotiable | false | 10 |
| R05280 | Composite — SDD-007 = Per-token SSE subscriber quota; status implemented (all 5 Ds: D-1 fingerprint / D-2 dual-counter / D-3 deferred terminate-on-revoke / D-4 config knobs / D-5 tests / D-6 distinguishable 503 reasons); project boundary preserved (selfdef-scope) | SDD-007 entire | F02640 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 R-rows × 10 sub-reqs each = 2400 sub-requirements declared
- Combined with MS001-MS021: 33120 + 2400 = 35520 sub-requirements when MS022 lands

## Cross-references

- SDD source: `docs/sdd/007-per-token-sse-subscriber-quota.md` (252 lines; status=implemented all 5 Ds shipped; closes F-2028-037 + F-2028-039)
- Implementation crate: `crates/selfdef-api/src/transport.rs` (TokenFingerprint) + ApiState (Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>> per-token + Arc<AtomicUsize> global) + SubscriberGuard (RAII)
- Integration test file: `crates/selfdef-api/tests/m12_api.rs` (5 D-5 tests: per-token cap reached / per-fingerprint / global still applies / rotation / counter drops to zero)
- Config crate: `selfdef-config::ApiConfig` (Option<usize> max_sse_subscribers + max_sse_subscribers_per_token)
- Init template: STARTER_CONFIG (2 knobs commented at defaults: 8 per-token / 64 global)
- Sister milestones: MS001 daemon core (ApiState lifecycle) / MS013 27-SDD charter (SDD-007 is foundational 000-009 layer) / MS019 security threat model (SDD-004 metrics-token rotation integrates) / MS020 test contract (5 D-5 tests are Cat 2 Pipeline + Cat 4 Seam) / MS021 shared module-script lib (unrelated; daemon-internal SSE quota)
- 3 deferred follow-ups: Per-IP quota / Prometheus exhaustion counter / audience-scope quota
- Cross-repo binding: `~/sovereign-os/docs/sdd/038-cross-repo-binding-doctrine.md` (SDD-007 is selfdef-scope; sovereign-os MAY consume events via NATS bridge MS015 with own per-host cap; MS007 typed-mirror crates may carry SseCaps schema)
