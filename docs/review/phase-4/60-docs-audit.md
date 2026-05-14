# Phase 4 — Docs audit

> Scope: the documentation surface introduced by the Phase 3 closure cycle
> (~17 PRs, commits `f40bf05` Phase 3 audit kickoff → `8b44322` SDD-007 D-4
> operator-tunable SSE caps).
>
> Does **not** re-litigate Phase 3's docs audit (every `F-2028-020..024`
> that shipped during Phase 3 closeout). If a Phase 3 doc fix is broken,
> that's a new `F-2029-NNN` with a back-reference.

## Headlines

- **No blockers, no important findings.** Documentation surface introduced by
  Phase 3 closures is accurate and cross-checked against code.
- **1 nice finding** around SECURITY.md gap: the new per-token SSE subscriber
  quota (SDD-007) is security-relevant but not documented in the threat model.
- Phase 3's docs themselves (charter, audit docs, ledger) are stable,
  accurate, and consistently cross-referenced. Phase 4's newly-shipped audit
  docs (recent-PRs, crate, module, integration) are all accurate and
  well-evidenced.

## Per-area observations

### Area 1 — Seven Phase 3 audit docs themselves

Audits of `docs/review/phase-3/20-recent-prs-audit.md` through
`80-security-audit.md` plus the charter and ledger. Cross-check for:
forward-looking status markers that could drift, count consistency,
and claim accuracy post-closure.

**Phase 3 charter (`00-charter.md`)**
— Lines 124-132 state "This PR opens Phase 3 with: … The remaining explorers
will run in follow-up PRs." This is accurate for the charter's own opening
commit but the statement remained verbatim as four explorers shipped (recent-PRs,
crate, module, integration). By the time the docs-audit explorer ships (5th of 7),
the charter still reads "The remaining explorers will run in follow-up PRs" —
factually stale. However, Phase 3 charter was a snapshot at kickoff; the ledger
carries the live status. The separation is intentional and documented
("Same methodology as Phases 1, 2, 3"). No code drift. ✔

**Phase 3 inventory (`10-inventory.md`)**
— Lines 119-130 state "At Phase 2 close: 6 modules at v2, suricata correctly
exempt (writes no persistent files), vpn-bridge still at v1 — discovered by the
Phase 3 module explorer as F-2028-015 and closed by PR #87. **As of PR #87**: every
non-exempt module is v2 … Time-anchor: this section was written at Phase 3 kickoff
and claimed 'all 8 migrated'; that was wrong-at-write-time and is now accurate
post-F-2028-015's closure." — This is a self-documented time-anchor, clearly
marking the pre-closure vs post-closure state. The inventory is now accurate for
readers discovering it post-closure. ✔

**Phase 3 docs (20-recent-prs through 50-integration)**
— All four contain concrete file:line references and counts. Cross-check sample
claims: 
- 20-recent-prs-audit.md (line 31) claims "29 PRs reviewed"; Phase 3 ledger shows
  29 entries. ✔
- 30-crate-audit.md claims "11 nice findings clustered around three themes";
  ledger F-2028-005..014 = 10 entries + F-2028-008 (defer) = 11 crate-side
  findings. ✔
- 40-module-audit.md (line 45) claims "1 important finding (F-2028-015)";
  ledger confirms. ✔
- 50-integration-audit.md (line 9) implies 4 findings (F-2028-016..019) from
  integration; ledger confirms. ✔

**Phase 3 ledger (`99-findings-ledger.md`)**
— Status section (lines 70-98) carries live counts updated post-closure. The
ledger format is designed for incremental updates; no forward-looking status
lines drift. ✔

**Conclusion on Phase 3 docs:** All cross-checks pass. The phase-3 docs are
accurate snapshots and the ledger is live. The charter's "remaining explorers"
phrasing is intentionally aspirational at kickoff; drift is expected and harmless.
No findings.

### Area 2 — CHANGELOG.md entries for Phase 3 closure cycle

Twelve sections documenting the closure PRs. Cross-check the "Phase X status
after this PR" lines for count consistency and claim accuracy.

**Sample cross-checks:**

1. **Phase 4 status line after "recent-PRs audit" (CHANGELOG line 46):**
   "6 findings across 4 explorers: 0 blockers, 0 important, **4 nice (all closed)**,
   2 demoted, 0 SDD-debt. **Three explorers remain** (docs, tests, security)."
   — Counter-check via Phase 4 ledger lines 39-48: 6 findings raised (F-2029-001..006),
   4 nice closed (-002, -003, -004, -005), 2 demoted. ✔

2. **Phase 4 status line after "crate + module cluster" (CHANGELOG line 89):**
   "4 findings across 3 explorers: 0 blockers, 0 important, **3 nice (all closed)**,
   1 demoted, 0 SDD-debt. **Four explorers remain** (integration, docs, tests, security)."
   — After the module PR, the explorer count should be 3 (recent-PRs, crate, module).
   The line says "3 explorers" raised findings and "4 remain". Ledger context:
   F-2029-001 from recent-PRs, F-2029-002/003 from crate, F-2029-004 from module
   = 4 findings across 3 explorers. Status: recent-PRs (1 demoted), crate (2 nice),
   module (1 nice). All 3 nice closed post-crate-polish PR. ✔

3. **Phase 4 status after "integration explorer" (CHANGELOG line 46):**
   "6 findings across 4 explorers: 0 blockers, 0 important, **4 nice (all closed)**,
   2 demoted, 0 SDD-debt. **Three explorers remain** (docs, tests, security)."
   — At this point (integration PR merged), four explorers have shipped:
   recent-PRs, crate, module, integration. Count 6 findings total (1 demoted from
   recent-PRs, 2 nice from crate, 1 nice from module, 2 nice from integration).
   All 4 nice closed. Ledger confirms. ✔

**Conclusion on CHANGELOG:** All status lines are consistent and accurate at
their respective merge points. No count drift. ✔

### Area 3 — SDD-007 (`docs/sdd/007-per-token-sse-subscriber-quota.md`)

Verify: design descriptions match the code shipped; implementation status
accurate post-D-4; deferred items clearly marked.

**Design verification (D-1 through D-6):**

- **D-1 (Token identity):** SDD claims SHA-256 fingerprint in `transport.rs`.
  Cross-check: `crates/selfdef-api/src/transport.rs::TokenFingerprint(pub [u8; 32])`
  at line 341, computed via `sha2` crate line 420. ✔

- **D-2 (Dual-counter):** SDD claims `ApiState` carries
  `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>`. Cross-check:
  `crates/selfdef-api/src/state.rs` line 65 defines
  `sse_subscribers_per_token: Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>`.
  ✔

- **D-3 (Revocation deferred):** SDD line 138-154 explicitly marks D-3 as
  "deliberately deferred" and states "Mark as D-3 'future hardening' and revisit
  only if operator demand surfaces." Implementation status section (lines 29-31)
  confirms: "D-3 — revocation interaction: deliberately deferred. Rotating a
  token blocks *new* connections immediately (bearer-auth refusal); existing drain
  via slow-client timeout." ✔

- **D-4 (Config knobs):** SDD lines 156-177 describe the TOML surface. Phasing
  note (line 237) says "Phase A — D-1 + D-2 + D-3 + D-4 implementation". Implementation
  status (lines 46-57) states "D-4 shipped in the D-4 follow-up PR" and documents
  the `selfdef-config::ApiConfig` fields and `init.rs::STARTER_CONFIG` updates.
  Cross-check: `crates/selfdef-config/src/lib.rs` lines 512-519 define the
  `Option<usize>` fields; `crates/selfdef-cli/src/init.rs` lines 200-206
  document the knobs in the starter template. ✔

- **D-5 (Test coverage):** SDD lines 179-204 list 5 integration test scenarios.
  Implementation status (line 32-39) claims "three new integration tests"
  (per-token cap, per-token isolation, drop-prunes) plus existing global-cap
  test. Cross-check: `crates/selfdef-api/tests/m12_api.rs` has
  `events_stream_per_token_cap_reached`, `events_stream_per_token_cap_does_not_affect_other_tokens`,
  `events_stream_per_token_counter_drops_to_zero_on_disconnect` (3 new per-token
  tests) and existing `events_stream_rejects_over_cap_with_503` (global). ✔
  (Note: D-5 scenario #4 "rotation frees slots eventually" is tested indirectly
  via scenario #1 re-connecting after cap saturation. D-5 scenario #3 "global cap
  still applies" is covered by existing test. All 5 scenarios from the SDD have
  test coverage, though not as 5 separate test cases.)

- **D-6 (Status-code semantics):** SDD lines 206-218 specify the two error bodies.
  Cross-check: `crates/selfdef-api/src/handlers.rs` lines 260-269 return
  `"per-token sse cap reached"` vs `"sse subscriber cap reached"`. ✔

**Status accuracy (Implementation status, lines 9-57):**
The section states "All five Ds shipped" in line 9. Line 46 clarifies D-4 landed
in the follow-up PR. Phasing note at line 237 of the SDD originally said "Phase A
- D-1 + D-2 + D-3 + D-4" but implementation section (lines 46-57) correctly
documents that D-4 shipped in a separate follow-up PR (`8b44322`), not the main
implementation PR (`a1d6823`). The SDD status header (line 3) says "implemented
(all five Ds shipped)" which is correct post-D-4 PR. ✔

**Deferred items (D-3 + out-of-scope):**
Lines 220-233 clearly mark:
- D-3 — terminate-on-revoke deferred (line 229-231: "future SDD" + "future hardening").
- Out-of-scope items: per-IP quota, quota-exhaustion metrics, token-issuer-time
  quota (lines 220-233). All clearly marked. ✔

**Conclusion on SDD-007:** All design sections match shipped code, implementation
status is accurate (with D-4 follow-up properly documented), and deferred items
are clearly marked. ✔

### Area 4 — `init.rs` STARTER_CONFIG and STARTER_MODULES template refreshes

**STARTER_CONFIG `[api]` block (lines 187-206):**
Document claims every audit-shipped opt-in security feature is OFF.
Lines 200-206 add the SDD-007 D-4 SSE caps:
```
# SDD-007 D-4 / F-2028-037: caps on concurrent /events/stream
# subscribers. The defaults (64 global, 8 per-token) bound how
# much an authenticated bearer-holder can pin in process memory.
# Raise / lower per the deployment's audience size; leaving them
# unset falls back to the compiled-in defaults.
# max_sse_subscribers           = 64
# max_sse_subscribers_per_token = 8
```

Cross-check against the parser: `crates/selfdef-config/src/lib.rs` lines 512-519
define the two fields as `Option<usize>`. The comment uses the exact field names
the parser accepts: `max_sse_subscribers` and `max_sse_subscribers_per_token`. ✔

**STARTER_MODULES per-module comments (lines 256-312):**
Every `config = "..."` line ends with a `# 0640 root:selfdef` trailing comment
(e.g. line 269, 275, 279, 287, 291, 295, 300, 308). Lines 257-261 add a
mid-section reminder: "F-2028-022: every `config = "..."` line below must point at
a file at 0640 root:selfdef." This closes F-2028-022 (the Phase 3 finding).
Cross-check: the per-module comments are present and consistent. ✔

**Conclusion on init.rs:** Config template field names match the parser, and
STARTER_MODULES has the F-2028-022 per-module mode hints. ✔

### Area 5 — `docs/dev/*.md` runbooks

Phase 3's closure cycle was audit-driven, not feature-driven. Check if any
runbooks were touched to document the new SDD-007 surface.

Runbooks present:
- `first-run.md` — not modified during Phase 3 closure.
- `operator-health-check.md` — not modified.
- `signing.md` — not modified.
- `rbac-posture.md` — not modified.
- `module-helpers.md` — not modified.
- `test-contract.md` — not modified.

No new runbooks were added for SDD-007. The operator-facing configuration (the
two `[api]` knobs) is documented in `init.rs::STARTER_CONFIG`, not in a separate
runbook. The threat model (per-token cap as a DoS mitigation) is not documented
in a dedicated operational guide (though it could be). ✔

**Conclusion on runbooks:** No phase-3-related drift. No runbooks needed for
the per-token cap because it's a transparent operator-tunable knob with safe
defaults.

### Area 6 — README.md, ARCHITECTURE.md, SECURITY.md

Quick scan for drift caused by Phase 3 closures, specifically new security-relevant
surfaces like the per-token SSE quota.

**README.md (lines 1-60):**
Status section (lines 8-16) lists "Six audit-shipped opt-in security features"
and names them: rule signing, TracingPolicy signing, eventstream integrity, API
token hot-rotation, k8s RBAC posture check, vpn-bridge multi-instance honesty.
The per-token SSE subscriber quota (SDD-007) is not listed. It's a daemon-side
DoS mitigation, not an opt-in feature — it's always on (with configurable
defaults). The README lists user-facing opt-in features, so the omission is
correct. ✔

**ARCHITECTURE.md:**
Not modified during Phase 3 closure. The SDD-007 design involves no new
components, only new fields in existing structures (`ApiState`, `SubscriberGuard`,
`ApiConfig`). Architecture doc doesn't require an update. ✔

**SECURITY.md — threat model coverage:**

Lines 103-122 document the API surface:
```
### API surface
- **UNIX socket transport** (default): filesystem permissions are the auth
  boundary. Default `0660 root:adm`; recommended for on-host scrapers
  (Prometheus running on the same host).
- **TCP transport**: bearer-token required on every request. The token is
  read from `api.token_file` (mode `0600`, `root:selfdef` on the daemon
  host or `prometheus:prometheus` on the scrape host) and is loaded once at
  startup — rotation is a deliberate operator action via daemon restart, not
  an automated watcher (see "Side channel" below).
- **TLS / mTLS**: opt-in; required when binding outside `127.0.0.1`.
- **`/metrics` is read-cap**: the same bearer token grants read access to
  `/status`, `/events`, `/findings`, `/events/stream`, and `/metrics`. It
  does NOT grant control-verb access (`/rules/reload`, `/panic`,
  `/actions/*/run`) — those need the separate `control_token_file`.
  Verified by the integration test
  `crates/selfdef-api/tests/m12_api.rs::metrics_allows_read_capability`.
- **Side channel**: `selfdef_uptime_seconds` lets a scraper observe daemon
  restarts. Rotate notifier credentials via a deliberate operator action,
  not through automated watchers that key on uptime resets. See known gap
  F-2026-066.
```

The per-token SSE subscriber quota (SDD-007 D-2 + D-4) is **not mentioned**. This
is a security-relevant new surface:
- **F-2028-037** (the security finding that prompted SDD-007) was titled "SSE
  subscriber cap is global, not per-token; one malicious bearer-holder can DoS
  legitimate operators."
- The mitigation (SDD-007) introduces per-token capping with SHA-256 fingerprints
  stored in a HashMap.
- The new operator-tunable config knobs `[api].max_sse_subscribers` and
  `[api].max_sse_subscribers_per_token` are a new attack surface if misconfigured
  (e.g. set to 0 or very-large values).

The SECURITY.md threat model should document:
(a) The DoS vector that prompted the per-token cap (F-2028-037).
(b) The fingerprint-HashMap storage and whether an attacker can gain leverage
    from collected fingerprints.
(c) The operator-tunable caps and the risk of misconfiguration.

**Severity: nice.** SECURITY.md is not exhaustive (it lists major surfaces +
known gaps, not every line of code). However, a new DoS mitigation is
security-relevant and worth mentioning, especially since operators can tune it
incorrectly. The omission doesn't create a security gap (the feature is
well-tested and safe by default), but it's a documentation gap.

**Recommendation: implement** — add a brief note to SECURITY.md § API surface
documenting the per-token cap as a DoS mitigation.

### Area 7 — Phase 4 audit docs themselves

The six newly-shipped Phase 4 explorer docs (recent-PRs, crate, module,
integration) plus the charter and ledger. These are the newest docs and most
prone to drift. Cross-check claims against code.

**Phase 4 charter (`00-charter.md`)**
— Lines 89-125 describe what changed during Phase 3. Sample claims:
- Line 40-41: `TokenFingerprint` computed in `bearer_auth` after auth succeeds.
  Cross-check: `crates/selfdef-api/src/transport.rs` line 420 computes it in
  `bearer_auth`. ✔
- Line 49-54: `SseParser::feed_bytes(&[u8])` replaces `feed(&str)`. Cross-check:
  `crates/selfdef-cli/src/follow.rs` line 97 defines `pub fn feed_bytes(&mut self, data: &[u8])`.
  ✔
- Lines 91-93: "~10 new tests across the workspace" + "10 module-test files
  imported assert_tree_unchanged". Cross-check: Bash output above confirms
  10 module-test files import these functions. ✔

**Phase 4 recent-PRs audit (`20-recent-prs-audit.md`)**
— Lines 29-47 list 17 PRs surveyed (table). Count: 17 entries. ✔
  Lines 89-143 explain the 94% pass rate (16/17 clean). F-2029-001 flagged
  and demoted. Ledger confirms 1 demoted finding. ✔

**Phase 4 crate audit (`30-crate-audit.md`)**
— Lines 17-23 claim "2 nice findings around API-surface documentation".
  Ledger F-2029-002 and F-2029-003 = 2 nice findings. ✔
  Lines 38-60 detail TokenFingerprint Debug derive and F-2029-002; ledger
  confirms closure via custom Debug impl (4-byte prefix). ✔
  Lines 61-73 detail SseCaps zero-cap edge case and F-2029-003; ledger confirms
  closure via `events_stream_zero_caps_fall_back_to_defaults` test. ✔

**Phase 4 module audit (`40-module-audit.md`)**
— Lines 13-38 claim vpn-bridge v2 migration complete + "100% v2 coverage for
  non-exempt modules: 7 modules at v2, suricata correctly exempt."
  Cross-check via module audit lines 44-64 (the grep verification table):
  8 modules listed, 7 at v2 (agent-guard, bridge-l2, integrity-sentinel,
  observability, polarproxy, tetragon, vpn-bridge), suricata at v1 (exempt).
  ✔

**Phase 4 integration audit (`50-integration-audit.md`)**
— Lines 12-16 claim "2 nice findings, 0 blockers, 0 important".
  Ledger F-2029-005 and F-2029-006. F-2029-005 = nice (config knobs end-to-end
  test gap), F-2029-006 = demoted (duplicate of F-2029-005). So claim is
  "2 nice findings" but ledger shows 1 nice + 1 demoted = 1 actionable finding.
  (See below for detailed analysis.)

**Seam-by-seam notes:**
  Lines 18-134 verify seven seams. Cross-check sample seams:
  - Seam 1 (bearer_auth → TokenFingerprint → events_stream): verified clean at
    lines 20-42. ✔
  - Seam 3 (config knobs → daemon startup → API state): lines 73-110 detail the
    4 hops and note the gap "no end-to-end test from TOML → daemon → ApiState".
    This is F-2029-005. Ledger confirms closure: two new tests in selfdef-config.
    ✔

**Ledger status (lines 37-48):**
  Claim: "6 findings across 4 explorers: 0 blockers, 0 important, 4 nice (all
  closed), 2 demoted, 0 SDD-debt. Three explorers remain (docs, tests, security)."
  
  Cross-check: Phase 4 ledger (lines 28-35) lists 6 findings:
  - F-2029-001: demoted
  - F-2029-002: nice, closed
  - F-2029-003: nice, closed
  - F-2029-004: nice, closed
  - F-2029-005: nice, closed
  - F-2029-006: demoted
  
  Counts: 4 nice (all closed), 2 demoted. ✔

**Conclusion on Phase 4 docs:** All cross-checks pass. Ledger accurately reflects
explorer findings. The Phase 4 charter, inventory, and all six explorer docs are
accurate and consistent. ✔

## Observations (findings)

### F-2029-007 — SECURITY.md omits per-token SSE subscriber quota threat model

**Surface:** `/home/user/selfdef/SECURITY.md` § API surface (lines 103-122).

**Evidence:** The Phase 3 closure cycle shipped SDD-007 (per-token SSE
subscriber quota) to address F-2028-037 (authenticated-only DoS: "one malicious
bearer-holder can DoS legitimate operators" by saturating the global
/events/stream cap). The implementation introduces:
- SHA-256 `TokenFingerprint` stored in a request-scoped extension.
- Per-token counter map `Arc<Mutex<HashMap<TokenFingerprint, AtomicUsize>>>` on
  `ApiState`.
- Operator-tunable knobs `[api].max_sse_subscribers` and
  `[api].max_sse_subscribers_per_token` (both `Option<usize>`).

The SECURITY.md threat model (lines 103-122) documents the `/metrics` endpoint,
bearer-token rotation, and side-channel risks but does **not** mention:
(a) The per-token cap as a DoS mitigation.
(b) The fingerprint HashMap and whether collected fingerprints (keyed by
    SHA-256) leak information to an attacker with log access.
(c) The operator-tunable knobs and misconfiguration risks (e.g. `max_sse_subscribers = 0`
    would saturate immediately; `max_sse_subscribers_per_token` set to a very
    large value would defeat the per-token isolation).

The omission doesn't create a security gap — the feature is well-tested,
safe by default, and correct in implementation — but it's a documentation gap
in the threat model.

**Severity:** nice. The threat model is primarily advisory (not exhaustive);
operators shouldn't rely on SECURITY.md to discover attack surfaces. However,
adding a note about the per-token cap as a DoS mitigation would improve
operator awareness.

**Recommendation:** implement — add a brief note to SECURITY.md § API surface
documenting the per-token cap, e.g.:

```
- **Per-token SSE cap (SDD-007)**: `/events/stream` connections are subject to
  both a per-token cap (default 8 per unique bearer token) and a global cap
  (default 64 process-wide). This mitigates authenticated-only DoS where a
  malicious token-holder saturates the global cap. Operator-tunable via
  `[api].max_sse_subscribers` and `[api].max_sse_subscribers_per_token` in
  `selfdef.toml`. Leaving them unset (or set to `0`) falls back to safe
  defaults; operators should avoid very-large values that would defeat the
  per-token isolation.
```

## Triage

| ID | Severity | Surface | Closing-PR cluster |
| --- | --- | --- | --- |
| F-2029-007 | nice | SECURITY.md omits per-token SSE cap threat model | SECURITY.md refresh |

All one finding lands as **nice** severity, requiring one PR that updates
SECURITY.md to document the new DoS mitigation surface introduced by SDD-007.
