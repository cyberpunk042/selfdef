# MS003 — Correlator + store + responder + signing — time-windowed rules pipeline

> Parent: `backlog/milestones/INDEX.md` row MS003.
> Source: existing repo crates `selfdef-correlator` + `selfdef-store` (with migrations + tests) + `selfdef-responder` + `selfdef-signing`; SDD-000 charter; selfdef README §"Goals" (Correlate / Respond / Defend).

## Epics (E0021–E0030)

| Epic ID | Phrase | Source |
|---|---|---|
| E0021 | Correlator — time-windowed rules engine over collector event stream | `crates/selfdef-correlator` |
| E0022 | Store — persisted event + verdict + action ledger with replay surface | `crates/selfdef-store` + migrations/ |
| E0023 | Responder — active response (lockdown egress / freeze logins / snapshot state / notify / engage deception) | `crates/selfdef-responder` |
| E0024 | Signing — cryptographic integrity for rules + TracingPolicies + eventstream | `crates/selfdef-signing` |
| E0025 | Time-windowed rule contract — id / pattern / window / threshold / action | `crates/selfdef-correlator` + `selfdef-core` Rule |
| E0026 | Verdict synthesis — Benign / Suspicious / Malicious with confidence + evidence chain | `crates/selfdef-correlator` + `selfdef-core` Verdict |
| E0027 | Action ledger — every Action committed by Responder is immutably logged | `crates/selfdef-responder` + `crates/selfdef-store` |
| E0028 | Rule signing — only operator-signed Rules accepted (audit-shipped opt-in) | `crates/selfdef-signing` + `crates/selfdef-correlator` |
| E0029 | Store schema — events / verdicts / actions / rules / signing-trust tables | `crates/selfdef-store/migrations/` |
| E0030 | Pipeline boundary — Correlator consumes Events; Responder consumes Verdicts; Signing gates Rules + Actions; Store persists all | this milestone |

## Modules (M00053–M00078)

| Mod ID | Phrase | Source | Parent epic |
|---|---|---|---|
| M00053 | Rule loader — TOML/YAML parse + schema validate + signing-verify | `crates/selfdef-correlator` RuleLoader | E0021 |
| M00054 | Sliding time window — operator-tunable per-rule (10s / 1m / 5m / 1h / 24h) | `crates/selfdef-correlator` SlidingWindow | E0021 |
| M00055 | Pattern matcher — boolean expression over Event fields (subject/identity/payload) | `crates/selfdef-correlator` PatternMatcher | E0021 |
| M00056 | Threshold counter — N-occurrences-within-window trigger | `crates/selfdef-correlator` ThresholdCounter | E0021 |
| M00057 | Correlator hot path — per-Event fan-out to all matching rules + sliding aggregations | `crates/selfdef-correlator` Engine | E0021 |
| M00058 | Verdict synthesizer — collects matching-rule outputs → produces Verdict + evidence chain | `crates/selfdef-correlator` VerdictSynth | E0026 |
| M00059 | Store — SQLite/PostgreSQL backend (operator-selectable) | `crates/selfdef-store` Backend | E0022 |
| M00060 | Store schema — `events` table | `crates/selfdef-store/migrations/` | E0029 |
| M00061 | Store schema — `verdicts` table | `crates/selfdef-store/migrations/` | E0029 |
| M00062 | Store schema — `actions` table | `crates/selfdef-store/migrations/` | E0029 |
| M00063 | Store schema — `rules` table | `crates/selfdef-store/migrations/` | E0029 |
| M00064 | Store schema — `signing_trust` table (trusted signer fingerprints) | `crates/selfdef-store/migrations/` | E0029 |
| M00065 | Store retention policy — operator-tunable per-table TTL | `crates/selfdef-store` Retention | E0022 |
| M00066 | Store replay API — chronological + filtered event/verdict/action playback | `crates/selfdef-store` Replay | E0022 |
| M00067 | Responder — Action `lockdown_egress` (block all outbound except whitelist) | `crates/selfdef-responder` LockdownEgress | E0023 |
| M00068 | Responder — Action `freeze_login` (disable named user / SSH key) | `crates/selfdef-responder` FreezeLogin | E0023 |
| M00069 | Responder — Action `snapshot_state` (ZFS snapshot or btrfs subvolume snapshot) | `crates/selfdef-responder` SnapshotState | E0023 |
| M00070 | Responder — Action `notify` (route to notifier orchestrator per SDD-008) | `crates/selfdef-responder` Notify | E0023 |
| M00071 | Responder — Action `engage_deception` (activate canary services / honey responses) | `crates/selfdef-responder` EngageDeception | E0023 |
| M00072 | Responder — Action `no_op` (audit-only verdict; logged but no side effect) | `crates/selfdef-responder` NoOp | E0023 |
| M00073 | Responder dry-run mode — Action.commit() previews without side effects | `crates/selfdef-responder` DryRun | E0023 |
| M00074 | Action ledger — append-only `actions` table with action + caused-by-verdict + caused-by-rules chain | `crates/selfdef-store` + `crates/selfdef-responder` | E0027 |
| M00075 | Signing — Ed25519 detached signature over rule body | `crates/selfdef-signing` Ed25519 | E0024 |
| M00076 | Signing — operator-managed trust root (`/etc/selfdef/trust/<fingerprint>.pub`) | `crates/selfdef-signing` Trust | E0024 |
| M00077 | Signing — rule signing verification (audit-shipped opt-in) | `crates/selfdef-correlator` SignedRuleGate | E0028 |
| M00078 | Signing — Tetragon TracingPolicy signing verification (audit-shipped opt-in) | `crates/selfdef-collector-tetragon` SignedPolicyGate | E0028 |

## Features (F00241–F00360)

| F ID | Phrase | Source | Parent module | Category | Opt-in |
|---|---|---|---|---|---|
| F00241 | Toggle correlator backend (native rust / regex-only fallback) | `crates/selfdef-correlator` | E0021 | mode | true |
| F00242 | Profile knob — `correlator_backend = native \| regex_fallback` | `crates/selfdef-config` | E0021 | profile | true |
| F00243 | Env var `SELFDEF_CORRELATOR_BACKEND` | `crates/selfdef-config` | E0021 | env_var | true |
| F00244 | Rule loader — TOML rule files | `crates/selfdef-correlator` | M00053 | composite | false |
| F00245 | Rule loader — YAML rule files (Sigma-compat) | `crates/selfdef-correlator` | M00053 | composite | false |
| F00246 | Rule loader — schema validation (operator-readable error on invalid rule) | `crates/selfdef-correlator` | M00053 | composite | false |
| F00247 | Rule loader — signing verification gate | `crates/selfdef-signing` | M00077 | composite | true |
| F00248 | Rule sliding window — 10s preset | `crates/selfdef-correlator` | M00054 | composite | true |
| F00249 | Rule sliding window — 1m preset | `crates/selfdef-correlator` | M00054 | composite | true |
| F00250 | Rule sliding window — 5m preset | `crates/selfdef-correlator` | M00054 | composite | true |
| F00251 | Rule sliding window — 1h preset | `crates/selfdef-correlator` | M00054 | composite | true |
| F00252 | Rule sliding window — 24h preset | `crates/selfdef-correlator` | M00054 | composite | true |
| F00253 | Rule sliding window — operator-custom duration | `crates/selfdef-correlator` | M00054 | composite | true |
| F00254 | Pattern matcher — boolean expression over event.subject | `crates/selfdef-correlator` | M00055 | composite | false |
| F00255 | Pattern matcher — boolean expression over event.identity | `crates/selfdef-correlator` | M00055 | composite | false |
| F00256 | Pattern matcher — boolean expression over event.payload | `crates/selfdef-correlator` | M00055 | composite | false |
| F00257 | Pattern matcher — regex against string fields | `crates/selfdef-correlator` | M00055 | composite | false |
| F00258 | Pattern matcher — CIDR match against network endpoints | `crates/selfdef-correlator` | M00055 | composite | true |
| F00259 | Pattern matcher — glob match against file paths | `crates/selfdef-correlator` | M00055 | composite | true |
| F00260 | Threshold counter — N-occurrences trigger | `crates/selfdef-correlator` | M00056 | composite | false |
| F00261 | Threshold counter — distinct-source trigger (N distinct IPs within window) | `crates/selfdef-correlator` | M00056 | composite | true |
| F00262 | Threshold counter — rate trigger (events/sec above threshold) | `crates/selfdef-correlator` | M00056 | composite | true |
| F00263 | Verdict synthesizer — verdict = Benign | `crates/selfdef-correlator` | M00058 | composite | false |
| F00264 | Verdict synthesizer — verdict = Suspicious | `crates/selfdef-correlator` | M00058 | composite | false |
| F00265 | Verdict synthesizer — verdict = Malicious | `crates/selfdef-correlator` | M00058 | composite | false |
| F00266 | Verdict synthesizer — confidence score 0.0..1.0 | `crates/selfdef-correlator` | M00058 | composite | false |
| F00267 | Verdict synthesizer — evidence chain (list of matching rule ids + event ids) | `crates/selfdef-correlator` | M00058 | composite | false |
| F00268 | Verdict synthesizer — operator-extensible verdict enum | `crates/selfdef-core` | M00058 | composite | true |
| F00269 | Store backend — SQLite (default) | `crates/selfdef-store` | M00059 | mode | true |
| F00270 | Store backend — PostgreSQL (opt-in for multi-host) | `crates/selfdef-store` | M00059 | mode | true |
| F00271 | Profile knob — `store_backend = sqlite \| postgres` | `crates/selfdef-config` | M00059 | profile | true |
| F00272 | Env var `SELFDEF_STORE_BACKEND` | `crates/selfdef-config` | M00059 | env_var | true |
| F00273 | Env var `SELFDEF_STORE_PATH` (sqlite path) | `crates/selfdef-config` | M00059 | env_var | true |
| F00274 | Env var `SELFDEF_STORE_PG_URL` (postgres connection) | `crates/selfdef-config` | M00059 | env_var | true |
| F00275 | Store table — `events` columns (id / timestamp / collector / identity / subject / payload / signed_chain) | `crates/selfdef-store/migrations/` | M00060 | data_model | false |
| F00276 | Store table — `verdicts` columns (id / timestamp / event_ids / verdict / confidence / evidence_rule_ids) | `crates/selfdef-store/migrations/` | M00061 | data_model | false |
| F00277 | Store table — `actions` columns (id / timestamp / verdict_id / action / target / dry_run / committed) | `crates/selfdef-store/migrations/` | M00062 | data_model | false |
| F00278 | Store table — `rules` columns (id / name / source_path / signing_fingerprint / loaded_at / disabled) | `crates/selfdef-store/migrations/` | M00063 | data_model | false |
| F00279 | Store table — `signing_trust` columns (fingerprint / owner / key_pem / added_at / revoked_at) | `crates/selfdef-store/migrations/` | M00064 | data_model | false |
| F00280 | Store retention — events TTL default 30d (operator-tunable) | `crates/selfdef-store` | M00065 | profile | true |
| F00281 | Store retention — verdicts TTL default 90d (operator-tunable) | `crates/selfdef-store` | M00065 | profile | true |
| F00282 | Store retention — actions TTL default 1y (operator-tunable) | `crates/selfdef-store` | M00065 | profile | true |
| F00283 | Profile knob — `store.retention.events_ttl_days` | `crates/selfdef-config` | M00065 | profile | true |
| F00284 | Profile knob — `store.retention.verdicts_ttl_days` | `crates/selfdef-config` | M00065 | profile | true |
| F00285 | Profile knob — `store.retention.actions_ttl_days` | `crates/selfdef-config` | M00065 | profile | true |
| F00286 | Store replay API — chronological cursor | `crates/selfdef-store` | M00066 | composite | true |
| F00287 | Store replay API — filter by event subject glob | `crates/selfdef-store` | M00066 | composite | true |
| F00288 | Store replay API — filter by verdict type | `crates/selfdef-store` | M00066 | composite | true |
| F00289 | Store replay API — filter by action type | `crates/selfdef-store` | M00066 | composite | true |
| F00290 | Responder Action — `lockdown_egress` | `crates/selfdef-responder` | M00067 | composite | true |
| F00291 | Responder Action — `freeze_login` | `crates/selfdef-responder` | M00068 | composite | true |
| F00292 | Responder Action — `snapshot_state` | `crates/selfdef-responder` | M00069 | composite | true |
| F00293 | Responder Action — `notify` | `crates/selfdef-responder` | M00070 | composite | true |
| F00294 | Responder Action — `engage_deception` | `crates/selfdef-responder` | M00071 | composite | true |
| F00295 | Responder Action — `no_op` (audit-only) | `crates/selfdef-responder` | M00072 | composite | false |
| F00296 | Responder dry-run mode (preview without side effects) | `crates/selfdef-responder` | M00073 | mode | true |
| F00297 | Profile knob — `responder.dry_run = bool` | `crates/selfdef-config` | M00073 | profile | true |
| F00298 | Env var `SELFDEF_RESPONDER_DRY_RUN` | `crates/selfdef-config` | M00073 | env_var | true |
| F00299 | Action ledger — caused-by-verdict chain | `crates/selfdef-responder` + `crates/selfdef-store` | M00074 | composite | false |
| F00300 | Action ledger — caused-by-rules chain | `crates/selfdef-responder` + `crates/selfdef-store` | M00074 | composite | false |
| F00301 | Action ledger — append-only (no in-place mutation) | `crates/selfdef-store` | M00074 | composite | false |
| F00302 | Signing — Ed25519 algorithm | `crates/selfdef-signing` | M00075 | composite | false |
| F00303 | Signing — detached signature format (`<rule>.sig` next to `<rule>.toml`) | `crates/selfdef-signing` | M00075 | composite | false |
| F00304 | Signing trust root — `/etc/selfdef/trust/<fingerprint>.pub` | `crates/selfdef-signing` | M00076 | composite | false |
| F00305 | Signing — operator-managed trust list (add/remove via `selfdefctl trust add/remove`) | `crates/selfdef-cli` | M00076 | composite | true |
| F00306 | Signing — fingerprint revocation list | `crates/selfdef-signing` + `crates/selfdef-store` `signing_trust` | M00076 | composite | true |
| F00307 | Rule signing verification (audit-shipped opt-in) | `crates/selfdef-correlator` | M00077 | composite | true |
| F00308 | Profile knob — `correlator.rule_signing_required = bool` | `crates/selfdef-config` | M00077 | profile | true |
| F00309 | Env var `SELFDEF_RULE_SIGNING_REQUIRED` | `crates/selfdef-config` | M00077 | env_var | true |
| F00310 | Tetragon TracingPolicy signing verification (audit-shipped opt-in) | `crates/selfdef-collector-tetragon` | M00078 | composite | true |
| F00311 | API `GET /v1/correlator/rules` (lists loaded rules + signing-state) | `crates/selfdef-api` | M00053 | api_endpoint | true |
| F00312 | API `POST /v1/correlator/reload` (hot-reload rules without daemon restart) | `crates/selfdef-api` | M00053 | api_endpoint | true |
| F00313 | API `GET /v1/store/events` (paginated event replay) | `crates/selfdef-api` | M00066 | api_endpoint | true |
| F00314 | API `GET /v1/store/verdicts` (paginated verdict replay) | `crates/selfdef-api` | M00066 | api_endpoint | true |
| F00315 | API `GET /v1/store/actions` (paginated action replay) | `crates/selfdef-api` | M00066 | api_endpoint | true |
| F00316 | API `GET /v1/store/replay?since=<ts>&until=<ts>` (window replay) | `crates/selfdef-api` | M00066 | api_endpoint | true |
| F00317 | API `POST /v1/responder/dry-run` (preview Action commit) | `crates/selfdef-api` | M00073 | api_endpoint | true |
| F00318 | API `POST /v1/responder/commit` (operator-triggered Action commit) | `crates/selfdef-api` | E0023 | api_endpoint | true |
| F00319 | API `GET /v1/signing/trust` (lists trusted fingerprints) | `crates/selfdef-api` | M00076 | api_endpoint | true |
| F00320 | API `POST /v1/signing/trust/add` (add fingerprint to trust list) | `crates/selfdef-api` | M00076 | api_endpoint | true |
| F00321 | API `POST /v1/signing/trust/revoke` (revoke fingerprint) | `crates/selfdef-api` | M00076 | api_endpoint | true |
| F00322 | CLI `selfdefctl rules list` | `crates/selfdef-cli` | M00053 | cli_verb | true |
| F00323 | CLI `selfdefctl rules reload` | `crates/selfdef-cli` | M00053 | cli_verb | true |
| F00324 | CLI `selfdefctl rules verify <path>` | `crates/selfdef-cli` | M00077 | cli_verb | true |
| F00325 | CLI `selfdefctl store events --since <ts>` | `crates/selfdef-cli` | M00066 | cli_verb | true |
| F00326 | CLI `selfdefctl store verdicts --since <ts>` | `crates/selfdef-cli` | M00066 | cli_verb | true |
| F00327 | CLI `selfdefctl store actions --since <ts>` | `crates/selfdef-cli` | M00066 | cli_verb | true |
| F00328 | CLI `selfdefctl store replay --since <ts> --until <ts>` | `crates/selfdef-cli` | M00066 | cli_verb | true |
| F00329 | CLI `selfdefctl responder dry-run --verdict-id <id>` | `crates/selfdef-cli` | M00073 | cli_verb | true |
| F00330 | CLI `selfdefctl responder commit --verdict-id <id>` (requires `--apply`) | `crates/selfdef-cli` | E0023 | cli_verb | true |
| F00331 | CLI `selfdefctl trust list` | `crates/selfdef-cli` | M00076 | cli_verb | true |
| F00332 | CLI `selfdefctl trust add --fingerprint <fp> --key-path <path>` | `crates/selfdef-cli` | M00076 | cli_verb | true |
| F00333 | CLI `selfdefctl trust revoke --fingerprint <fp>` | `crates/selfdef-cli` | M00076 | cli_verb | true |
| F00334 | Dashboard — correlator hot-path rate (events/sec, rules-evaluated/sec) | `dashboard/` | M00057 | dashboard | true |
| F00335 | Dashboard — top-firing rules histogram | `dashboard/` | M00053 | dashboard | true |
| F00336 | Dashboard — verdict distribution (Benign / Suspicious / Malicious live count) | `dashboard/` | M00058 | dashboard | true |
| F00337 | Dashboard — verdict timeline + evidence chain inspector | `dashboard/` | M00058 | dashboard | true |
| F00338 | Dashboard — Responder action queue + dry-run vs committed counts | `dashboard/` | E0023 | dashboard | true |
| F00339 | Dashboard — Action ledger (chronological with verdict + rule chain) | `dashboard/` | M00074 | dashboard | true |
| F00340 | Dashboard — Store table sizes + retention next-prune | `dashboard/` | M00065 | dashboard | true |
| F00341 | Dashboard — Signing trust list (active + revoked) | `dashboard/` | M00076 | dashboard | true |
| F00342 | Dashboard — Rule signing state (per-rule: signed / unsigned / revoked-fingerprint) | `dashboard/` | M00077 | dashboard | true |
| F00343 | Metric `selfdef_correlator_events_processed_total` | `crates/selfdef-correlator` | M00057 | observability_metric | true |
| F00344 | Metric `selfdef_correlator_rules_loaded_count` | `crates/selfdef-correlator` | M00053 | observability_metric | true |
| F00345 | Metric `selfdef_correlator_rule_fired_total{rule_id}` | `crates/selfdef-correlator` | M00057 | observability_metric | true |
| F00346 | Metric `selfdef_verdict_emitted_total{verdict,confidence_bucket}` | `crates/selfdef-correlator` | M00058 | observability_metric | true |
| F00347 | Metric `selfdef_responder_action_total{action,dry_run,outcome}` | `crates/selfdef-responder` | E0023 | observability_metric | true |
| F00348 | Metric `selfdef_store_rows_total{table}` | `crates/selfdef-store` | M00059 | observability_metric | true |
| F00349 | Metric `selfdef_store_retention_pruned_total{table}` | `crates/selfdef-store` | M00065 | observability_metric | true |
| F00350 | Metric `selfdef_signing_verify_total{outcome}` | `crates/selfdef-signing` | M00075 | observability_metric | true |
| F00351 | Metric `selfdef_signing_trust_size` | `crates/selfdef-signing` | M00076 | observability_metric | true |
| F00352 | Test — rule loader rejects malformed TOML with operator-readable error | tests/ | M00053 | test | false |
| F00353 | Test — sliding-window correctness on synthetic event stream (N events within window → fire; N events spanning > window → no fire) | tests/ | M00054 | test | false |
| F00354 | Test — pattern matcher boolean expression evaluates correctly across subject/identity/payload | tests/ | M00055 | test | false |
| F00355 | Test — verdict synthesis chains evidence (rule_ids + event_ids) deterministically | tests/ | M00058 | test | false |
| F00356 | Test — Responder dry-run produces side-effect-free preview matching commit's planned actions | tests/ | M00073 | test | false |
| F00357 | Test — Action ledger append-only invariant (no in-place mutation) | tests/ | M00074 | test | false |
| F00358 | Test — signed rule with valid signature loads | tests/ | M00077 | test | false |
| F00359 | Test — signed rule with revoked-fingerprint signature is rejected | tests/ | M00077 | test | false |
| F00360 | Test — Store retention prunes rows past TTL on schedule | tests/ | M00065 | test | false |

## Requirements (R00481–R00720)

| R ID | Phrase | Source | Parent | Class | Opt-in | Sub-reqs |
|---|---|---|---|---|---|---|
| R00481 | Correlator consumes Events from `selfdef-bus` | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00482 | Correlator applies time-windowed rules to Event stream | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00483 | Correlator emits Verdicts onto `selfdef-bus` for Responder consumption | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00484 | Correlator is implemented as `selfdef-correlator` Rust crate | repo | E0021 | non-negotiable | false | 10 |
| R00485 | Correlator rule loader parses TOML rule files | `crates/selfdef-correlator` | F00244 | non-negotiable | false | 10 |
| R00486 | Correlator rule loader parses YAML rule files (Sigma-compat) | `crates/selfdef-correlator` | F00245 | non-negotiable | false | 10 |
| R00487 | Correlator rule loader validates schema | `crates/selfdef-correlator` | F00246 | non-negotiable | false | 10 |
| R00488 | Correlator rule loader emits operator-readable error on invalid rule | `crates/selfdef-correlator` | F00246 | non-negotiable | true | 10 |
| R00489 | Correlator rule loader supports operator-extensible rule paths | `crates/selfdef-config` | E0021 | non-negotiable | true | 10 |
| R00490 | Correlator rule loader supports hot-reload without daemon restart | `crates/selfdef-correlator` | F00312 | non-negotiable | true | 10 |
| R00491 | Correlator rule sliding window supports 10s preset | `crates/selfdef-correlator` | F00248 | non-negotiable | true | 10 |
| R00492 | Correlator rule sliding window supports 1m preset | `crates/selfdef-correlator` | F00249 | non-negotiable | true | 10 |
| R00493 | Correlator rule sliding window supports 5m preset | `crates/selfdef-correlator` | F00250 | non-negotiable | true | 10 |
| R00494 | Correlator rule sliding window supports 1h preset | `crates/selfdef-correlator` | F00251 | non-negotiable | true | 10 |
| R00495 | Correlator rule sliding window supports 24h preset | `crates/selfdef-correlator` | F00252 | non-negotiable | true | 10 |
| R00496 | Correlator rule sliding window supports operator-custom duration | `crates/selfdef-correlator` | F00253 | non-negotiable | true | 10 |
| R00497 | Correlator pattern matcher evaluates boolean expressions over Event.subject | `crates/selfdef-correlator` | F00254 | non-negotiable | false | 10 |
| R00498 | Correlator pattern matcher evaluates boolean expressions over Event.identity | `crates/selfdef-correlator` | F00255 | non-negotiable | false | 10 |
| R00499 | Correlator pattern matcher evaluates boolean expressions over Event.payload | `crates/selfdef-correlator` | F00256 | non-negotiable | false | 10 |
| R00500 | Correlator pattern matcher supports regex on string fields | `crates/selfdef-correlator` | F00257 | non-negotiable | false | 10 |
| R00501 | Correlator pattern matcher supports CIDR match | `crates/selfdef-correlator` | F00258 | non-negotiable | true | 10 |
| R00502 | Correlator pattern matcher supports glob match on file paths | `crates/selfdef-correlator` | F00259 | non-negotiable | true | 10 |
| R00503 | Correlator threshold counter supports N-occurrences trigger | `crates/selfdef-correlator` | F00260 | non-negotiable | false | 10 |
| R00504 | Correlator threshold counter supports distinct-source trigger | `crates/selfdef-correlator` | F00261 | non-negotiable | true | 10 |
| R00505 | Correlator threshold counter supports rate trigger | `crates/selfdef-correlator` | F00262 | non-negotiable | true | 10 |
| R00506 | Correlator processes single events with low latency (target < 1ms per event under steady load) | `crates/selfdef-correlator` | M00057 | preferable | false | 10 |
| R00507 | Correlator scales to 10K+ events/sec sustained | `crates/selfdef-correlator` | M00057 | preferable | false | 10 |
| R00508 | Verdict synthesizer emits Benign verdict | `crates/selfdef-correlator` | F00263 | non-negotiable | false | 10 |
| R00509 | Verdict synthesizer emits Suspicious verdict | `crates/selfdef-correlator` | F00264 | non-negotiable | false | 10 |
| R00510 | Verdict synthesizer emits Malicious verdict | `crates/selfdef-correlator` | F00265 | non-negotiable | false | 10 |
| R00511 | Verdict carries confidence score 0.0..1.0 | `crates/selfdef-correlator` | F00266 | non-negotiable | false | 10 |
| R00512 | Verdict carries evidence chain (matching rule_ids + event_ids) | `crates/selfdef-correlator` | F00267 | non-negotiable | false | 10 |
| R00513 | Verdict synthesizer supports operator-extensible verdict enum | `crates/selfdef-core` | F00268 | non-negotiable | true | 10 |
| R00514 | Store backend supports SQLite (default) | `crates/selfdef-store` | F00269 | non-negotiable | true | 10 |
| R00515 | Store backend supports PostgreSQL (opt-in for multi-host) | `crates/selfdef-store` | F00270 | non-negotiable | true | 10 |
| R00516 | Store backend operator-selectable via `store_backend = sqlite \| postgres` | `crates/selfdef-config` | F00271 | non-negotiable | true | 10 |
| R00517 | Store SQLite path operator-overrideable via `SELFDEF_STORE_PATH` | `crates/selfdef-config` | F00273 | non-negotiable | true | 10 |
| R00518 | Store PostgreSQL connection operator-overrideable via `SELFDEF_STORE_PG_URL` | `crates/selfdef-config` | F00274 | non-negotiable | true | 10 |
| R00519 | Store table `events` columns: id / timestamp / collector / identity / subject / payload / signed_chain | `crates/selfdef-store/migrations/` | F00275 | non-negotiable | false | 10 |
| R00520 | Store table `verdicts` columns: id / timestamp / event_ids / verdict / confidence / evidence_rule_ids | `crates/selfdef-store/migrations/` | F00276 | non-negotiable | false | 10 |
| R00521 | Store table `actions` columns: id / timestamp / verdict_id / action / target / dry_run / committed | `crates/selfdef-store/migrations/` | F00277 | non-negotiable | false | 10 |
| R00522 | Store table `rules` columns: id / name / source_path / signing_fingerprint / loaded_at / disabled | `crates/selfdef-store/migrations/` | F00278 | non-negotiable | false | 10 |
| R00523 | Store table `signing_trust` columns: fingerprint / owner / key_pem / added_at / revoked_at | `crates/selfdef-store/migrations/` | F00279 | non-negotiable | false | 10 |
| R00524 | Store events TTL default 30d | `crates/selfdef-store` | F00280 | non-negotiable | true | 10 |
| R00525 | Store verdicts TTL default 90d | `crates/selfdef-store` | F00281 | non-negotiable | true | 10 |
| R00526 | Store actions TTL default 1y | `crates/selfdef-store` | F00282 | non-negotiable | true | 10 |
| R00527 | Store retention TTLs operator-tunable via `store.retention.<table>_ttl_days` | `crates/selfdef-config` | M00065 | non-negotiable | true | 10 |
| R00528 | Store retention prunes rows past TTL on schedule | tests/ | F00360 | non-negotiable | false | 10 |
| R00529 | Store replay API exposes chronological cursor | `crates/selfdef-store` | F00286 | non-negotiable | true | 10 |
| R00530 | Store replay API supports filter by event subject glob | `crates/selfdef-store` | F00287 | non-negotiable | true | 10 |
| R00531 | Store replay API supports filter by verdict type | `crates/selfdef-store` | F00288 | non-negotiable | true | 10 |
| R00532 | Store replay API supports filter by action type | `crates/selfdef-store` | F00289 | non-negotiable | true | 10 |
| R00533 | Store all writes are append-only (no in-place mutation) | `crates/selfdef-store` | E0022 | non-negotiable | false | 10 |
| R00534 | Store schema migrations are reversible (per-migration down() function) | `crates/selfdef-store/migrations/` | E0029 | non-negotiable | false | 10 |
| R00535 | Store migrations run on daemon start when schema_version < target | `crates/selfdef-store` | E0029 | non-negotiable | false | 10 |
| R00536 | Store migrations refuse to run on schema_version > target (operator-readable error) | `crates/selfdef-store` | E0029 | non-negotiable | false | 10 |
| R00537 | Responder consumes Verdicts from `selfdef-bus` | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00538 | Responder emits Action commit records to `selfdef-store` | `crates/selfdef-responder` | E0027 | non-negotiable | false | 10 |
| R00539 | Responder supports Action `lockdown_egress` (block all outbound except whitelist) | `crates/selfdef-responder` | F00290 | non-negotiable | true | 10 |
| R00540 | Responder supports Action `freeze_login` (disable named user / SSH key) | `crates/selfdef-responder` | F00291 | non-negotiable | true | 10 |
| R00541 | Responder supports Action `snapshot_state` (ZFS or btrfs snapshot) | `crates/selfdef-responder` | F00292 | non-negotiable | true | 10 |
| R00542 | Responder supports Action `notify` (routes to notifier orchestrator per SDD-008) | `crates/selfdef-responder` | F00293 | non-negotiable | true | 10 |
| R00543 | Responder supports Action `engage_deception` (activates canary services / honey responses) | `crates/selfdef-responder` | F00294 | non-negotiable | true | 10 |
| R00544 | Responder supports Action `no_op` (audit-only verdict; logged but no side effect) | `crates/selfdef-responder` | F00295 | non-negotiable | false | 10 |
| R00545 | Responder dry-run mode previews Action without side effects | `crates/selfdef-responder` | M00073 | non-negotiable | true | 10 |
| R00546 | Responder dry-run mode operator-toggleable via `responder.dry_run = bool` | `crates/selfdef-config` | F00297 | non-negotiable | true | 10 |
| R00547 | Responder dry-run mode operator-toggleable via `SELFDEF_RESPONDER_DRY_RUN` env | `crates/selfdef-config` | F00298 | non-negotiable | true | 10 |
| R00548 | Responder Action carries caused-by-verdict id | `crates/selfdef-store` actions table | F00299 | non-negotiable | false | 10 |
| R00549 | Responder Action carries caused-by-rules chain (list of rule_ids) | `crates/selfdef-store` actions table | F00300 | non-negotiable | false | 10 |
| R00550 | Action ledger is append-only (no in-place mutation) | `crates/selfdef-store` | F00301 | non-negotiable | false | 10 |
| R00551 | Responder never commits Action without a signed Rule chain (per SDD-004) | `crates/selfdef-signing` + `crates/selfdef-correlator` | E0028 | non-negotiable | false | 10 |
| R00552 | Responder never deletes user data without operator triple-gate (per SDD-004) | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00553 | Responder never modifies `/etc/` outside `/etc/selfdef/` without operator triple-gate | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00554 | Responder never escalates Verdict from Suspicious → Malicious without matching signed correlation rule | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00555 | Responder kill-switch — emergency stop for all in-flight Actions | `crates/selfdef-responder` | E0023 | non-negotiable | true | 10 |
| R00556 | Responder rollback — undo previously committed Action when operator triggers | `crates/selfdef-responder` | E0023 | preferable | true | 10 |
| R00557 | Signing uses Ed25519 algorithm | `crates/selfdef-signing` | F00302 | non-negotiable | false | 10 |
| R00558 | Signing produces detached signature format (`<rule>.sig` next to `<rule>.toml`) | `crates/selfdef-signing` | F00303 | non-negotiable | false | 10 |
| R00559 | Signing trust root path is `/etc/selfdef/trust/<fingerprint>.pub` | `crates/selfdef-signing` | F00304 | non-negotiable | false | 10 |
| R00560 | Signing trust list operator-manageable via `selfdefctl trust add/remove` | `crates/selfdef-cli` | F00305 | non-negotiable | true | 10 |
| R00561 | Signing fingerprint revocation list supported | `crates/selfdef-signing` + signing_trust table | F00306 | non-negotiable | true | 10 |
| R00562 | Signing — keys NEVER in repo (operator-supplied only) | architecture | M00076 | non-negotiable | false | 10 |
| R00563 | Signing private keys NEVER read by daemon (verify-only) | `crates/selfdef-signing` | M00075 | non-negotiable | false | 10 |
| R00564 | Signing trust changes are append-only ledgered (added_at + revoked_at preserved) | `crates/selfdef-store` signing_trust | M00076 | non-negotiable | false | 10 |
| R00565 | Rule signing verification is audit-shipped opt-in feature | `crates/selfdef-correlator` | F00307 | non-negotiable | true | 10 |
| R00566 | Rule signing required operator-toggleable via `correlator.rule_signing_required = bool` | `crates/selfdef-config` | F00308 | non-negotiable | true | 10 |
| R00567 | Rule signing required operator-toggleable via `SELFDEF_RULE_SIGNING_REQUIRED` env | `crates/selfdef-config` | F00309 | non-negotiable | true | 10 |
| R00568 | Signed rule with valid signature loads | tests/ | F00358 | non-negotiable | false | 10 |
| R00569 | Signed rule with revoked-fingerprint signature is rejected | tests/ | F00359 | non-negotiable | false | 10 |
| R00570 | Tetragon TracingPolicy signing verification is audit-shipped opt-in feature | `crates/selfdef-collector-tetragon` | F00310 | non-negotiable | true | 10 |
| R00571 | API `GET /v1/correlator/rules` lists loaded rules + signing-state | `crates/selfdef-api` | F00311 | non-negotiable | true | 10 |
| R00572 | API `POST /v1/correlator/reload` hot-reloads rules without daemon restart | `crates/selfdef-api` | F00312 | non-negotiable | true | 10 |
| R00573 | API `GET /v1/store/events` paginated event replay | `crates/selfdef-api` | F00313 | non-negotiable | true | 10 |
| R00574 | API `GET /v1/store/verdicts` paginated verdict replay | `crates/selfdef-api` | F00314 | non-negotiable | true | 10 |
| R00575 | API `GET /v1/store/actions` paginated action replay | `crates/selfdef-api` | F00315 | non-negotiable | true | 10 |
| R00576 | API `GET /v1/store/replay?since=<ts>&until=<ts>` window replay | `crates/selfdef-api` | F00316 | non-negotiable | true | 10 |
| R00577 | API `POST /v1/responder/dry-run` preview Action commit | `crates/selfdef-api` | F00317 | non-negotiable | true | 10 |
| R00578 | API `POST /v1/responder/commit` operator-triggered Action commit | `crates/selfdef-api` | F00318 | non-negotiable | true | 10 |
| R00579 | API `GET /v1/signing/trust` lists trusted fingerprints | `crates/selfdef-api` | F00319 | non-negotiable | true | 10 |
| R00580 | API `POST /v1/signing/trust/add` adds fingerprint | `crates/selfdef-api` | F00320 | non-negotiable | true | 10 |
| R00581 | API `POST /v1/signing/trust/revoke` revokes fingerprint | `crates/selfdef-api` | F00321 | non-negotiable | true | 10 |
| R00582 | CLI `selfdefctl rules list` | `crates/selfdef-cli` | F00322 | non-negotiable | true | 10 |
| R00583 | CLI `selfdefctl rules reload` | `crates/selfdef-cli` | F00323 | non-negotiable | true | 10 |
| R00584 | CLI `selfdefctl rules verify <path>` | `crates/selfdef-cli` | F00324 | non-negotiable | true | 10 |
| R00585 | CLI `selfdefctl store events --since <ts>` | `crates/selfdef-cli` | F00325 | non-negotiable | true | 10 |
| R00586 | CLI `selfdefctl store verdicts --since <ts>` | `crates/selfdef-cli` | F00326 | non-negotiable | true | 10 |
| R00587 | CLI `selfdefctl store actions --since <ts>` | `crates/selfdef-cli` | F00327 | non-negotiable | true | 10 |
| R00588 | CLI `selfdefctl store replay --since <ts> --until <ts>` | `crates/selfdef-cli` | F00328 | non-negotiable | true | 10 |
| R00589 | CLI `selfdefctl responder dry-run --verdict-id <id>` | `crates/selfdef-cli` | F00329 | non-negotiable | true | 10 |
| R00590 | CLI `selfdefctl responder commit --verdict-id <id>` requires `--apply` confirm flag | `crates/selfdef-cli` | F00330 | non-negotiable | true | 10 |
| R00591 | CLI `selfdefctl trust list` | `crates/selfdef-cli` | F00331 | non-negotiable | true | 10 |
| R00592 | CLI `selfdefctl trust add --fingerprint <fp> --key-path <path>` | `crates/selfdef-cli` | F00332 | non-negotiable | true | 10 |
| R00593 | CLI `selfdefctl trust revoke --fingerprint <fp>` | `crates/selfdef-cli` | F00333 | non-negotiable | true | 10 |
| R00594 | Dashboard surface — correlator hot-path rate (events/sec, rules-evaluated/sec) | `dashboard/` | F00334 | non-negotiable | true | 10 |
| R00595 | Dashboard surface — top-firing rules histogram | `dashboard/` | F00335 | non-negotiable | true | 10 |
| R00596 | Dashboard surface — verdict distribution live | `dashboard/` | F00336 | non-negotiable | true | 10 |
| R00597 | Dashboard surface — verdict timeline + evidence chain inspector | `dashboard/` | F00337 | non-negotiable | true | 10 |
| R00598 | Dashboard surface — Responder action queue + dry-run vs committed counts | `dashboard/` | F00338 | non-negotiable | true | 10 |
| R00599 | Dashboard surface — Action ledger chronological view | `dashboard/` | F00339 | non-negotiable | true | 10 |
| R00600 | Dashboard surface — Store table sizes + retention next-prune | `dashboard/` | F00340 | non-negotiable | true | 10 |
| R00601 | Dashboard surface — Signing trust list (active + revoked) | `dashboard/` | F00341 | non-negotiable | true | 10 |
| R00602 | Dashboard surface — Rule signing state per-rule | `dashboard/` | F00342 | non-negotiable | true | 10 |
| R00603 | Metric `selfdef_correlator_events_processed_total` | `crates/selfdef-correlator` | F00343 | non-negotiable | true | 10 |
| R00604 | Metric `selfdef_correlator_rules_loaded_count` | `crates/selfdef-correlator` | F00344 | non-negotiable | true | 10 |
| R00605 | Metric `selfdef_correlator_rule_fired_total{rule_id}` | `crates/selfdef-correlator` | F00345 | non-negotiable | true | 10 |
| R00606 | Metric `selfdef_verdict_emitted_total{verdict,confidence_bucket}` | `crates/selfdef-correlator` | F00346 | non-negotiable | true | 10 |
| R00607 | Metric `selfdef_responder_action_total{action,dry_run,outcome}` | `crates/selfdef-responder` | F00347 | non-negotiable | true | 10 |
| R00608 | Metric `selfdef_store_rows_total{table}` | `crates/selfdef-store` | F00348 | non-negotiable | true | 10 |
| R00609 | Metric `selfdef_store_retention_pruned_total{table}` | `crates/selfdef-store` | F00349 | non-negotiable | true | 10 |
| R00610 | Metric `selfdef_signing_verify_total{outcome}` | `crates/selfdef-signing` | F00350 | non-negotiable | true | 10 |
| R00611 | Metric `selfdef_signing_trust_size` | `crates/selfdef-signing` | F00351 | non-negotiable | true | 10 |
| R00612 | Test — rule loader rejects malformed TOML | tests/ | F00352 | non-negotiable | false | 10 |
| R00613 | Test — sliding-window correctness on synthetic stream | tests/ | F00353 | non-negotiable | false | 10 |
| R00614 | Test — pattern matcher across subject/identity/payload | tests/ | F00354 | non-negotiable | false | 10 |
| R00615 | Test — verdict synthesis deterministic evidence chain | tests/ | F00355 | non-negotiable | false | 10 |
| R00616 | Test — Responder dry-run = commit's planned actions | tests/ | F00356 | non-negotiable | false | 10 |
| R00617 | Test — Action ledger append-only invariant | tests/ | F00357 | non-negotiable | false | 10 |
| R00618 | Test — signed rule valid-signature loads | tests/ | F00358 | non-negotiable | false | 10 |
| R00619 | Test — signed rule revoked-fingerprint rejected | tests/ | F00359 | non-negotiable | false | 10 |
| R00620 | Test — Store retention prunes past TTL | tests/ | F00360 | non-negotiable | false | 10 |
| R00621 | Test — Store schema migration round-trip (up + down) | tests/ | E0029 | non-negotiable | false | 10 |
| R00622 | Test — SQLite backend integration | tests/ | F00269 | non-negotiable | false | 10 |
| R00623 | Test — PostgreSQL backend integration | tests/ | F00270 | non-negotiable | true | 10 |
| R00624 | Test — Responder Action commit emits ledger row | tests/ | F00299 | non-negotiable | false | 10 |
| R00625 | Test — Responder Action dry-run does NOT emit ledger row | tests/ | F00296 | non-negotiable | false | 10 |
| R00626 | Test — Responder rejects Action when caused-by-rules chain is empty | tests/ | R00551 | non-negotiable | false | 10 |
| R00627 | Test — Responder rejects Action when caused-by-rule signing fails | tests/ | R00551 | non-negotiable | false | 10 |
| R00628 | Test — Correlator hot-reload swaps rules atomically (no half-loaded state) | tests/ | F00312 | non-negotiable | false | 10 |
| R00629 | Test — Correlator drop-on-overflow honors per-rule queue capacity | tests/ | M00052 | non-negotiable | false | 10 |
| R00630 | Test — Verdict confidence within 0.0..1.0 across all paths | tests/ | F00266 | non-negotiable | false | 10 |
| R00631 | Test — Store replay returns events in chronological order | tests/ | F00286 | non-negotiable | false | 10 |
| R00632 | Test — Store replay filter by subject glob | tests/ | F00287 | non-negotiable | false | 10 |
| R00633 | Test — Store replay filter by verdict type | tests/ | F00288 | non-negotiable | false | 10 |
| R00634 | Test — Store replay filter by action type | tests/ | F00289 | non-negotiable | false | 10 |
| R00635 | Test — Responder kill-switch halts in-flight Actions | tests/ | R00555 | non-negotiable | true | 10 |
| R00636 | Test — Signing private key absence on daemon process (verify-only) | tests/ | R00563 | non-negotiable | false | 10 |
| R00637 | Test — Signing trust changes ledgered append-only | tests/ | R00564 | non-negotiable | false | 10 |
| R00638 | Test — Tetragon TracingPolicy signing gate enforced when policy_signing_required=true | tests/ | F00310 | non-negotiable | false | 10 |
| R00639 | Pipeline boundary — Correlator NEVER reaches into sovereign-os runtime state | architecture | E0030 | non-negotiable | false | 10 |
| R00640 | Pipeline boundary — Responder NEVER reaches into sovereign-os runtime state | architecture | E0030 | non-negotiable | false | 10 |
| R00641 | Pipeline boundary — Store NEVER stores sovereign-os runtime data directly (only selfdef-collected events + verdicts + actions) | architecture | E0030 | non-negotiable | false | 10 |
| R00642 | Pipeline boundary — Signing NEVER imports sovereign-os crate code | architecture | E0030 | non-negotiable | false | 10 |
| R00643 | Pipeline boundary — sovereign-os runtime trace events MAY be ingested into selfdef via eventstream collector (operator opt-in only) | architecture | E0030 | non-negotiable | true | 10 |
| R00644 | Project boundary — selfdef correlator + store + responder + signing are IPS-scope (host security domain); NOT sovereign-os runtime scope | this milestone | E0030 | non-negotiable | false | 10 |
| R00645 | Project boundary — Cross-repo binding (selfdef ↔ sovereign-os) flows via typed-mirror crates per SDD-038 | SDD-038 | E0030 | non-negotiable | false | 10 |
| R00646 | Correlator integrates with `selfdef-bus` (consumes Events) | `crates/selfdef-bus` | E0021 | non-negotiable | false | 10 |
| R00647 | Correlator integrates with `selfdef-store` (persists rules + verdicts) | `crates/selfdef-store` | E0021 | non-negotiable | false | 10 |
| R00648 | Correlator integrates with `selfdef-signing` (verifies rule signatures) | `crates/selfdef-signing` | E0028 | non-negotiable | false | 10 |
| R00649 | Correlator integrates with Sigma rule pack from MS002 (per-category Sigma rules feed correlator) | `crates/selfdef-correlator` + `rules/sigma/` | E0021 | non-negotiable | false | 10 |
| R00650 | Responder integrates with `selfdef-store` (Action ledger) | `crates/selfdef-store` | E0027 | non-negotiable | false | 10 |
| R00651 | Responder integrates with `selfdef-notifier-orchestrator` (Action `notify`) | `crates/selfdef-notifier-orchestrator` | F00293 | non-negotiable | false | 10 |
| R00652 | Responder integrates with `selfdef-signing` (refuses Action when caused-by-rule signature fails) | `crates/selfdef-signing` | R00551 | non-negotiable | false | 10 |
| R00653 | Responder integrates with SDD-008 notification orchestration | SDD-008 | F00293 | non-negotiable | false | 10 |
| R00654 | Store integrates with `selfdef-correlator` (Verdicts persisted) | `crates/selfdef-store` | E0022 | non-negotiable | false | 10 |
| R00655 | Store integrates with `selfdef-responder` (Actions persisted) | `crates/selfdef-store` | E0022 | non-negotiable | false | 10 |
| R00656 | Store integrates with collector fabric (Events persisted) | `crates/selfdef-store` + collectors | E0022 | non-negotiable | false | 10 |
| R00657 | Store integrates with SDD-005 L1–L5 layered test harness | SDD-005 | E0022 | non-negotiable | false | 10 |
| R00658 | Store integrates with SDD-029 round-ledger doctrine for traceability | SDD-029 | E0022 | non-negotiable | false | 10 |
| R00659 | Signing integrates with `selfdef-correlator` (rule signing) | `crates/selfdef-signing` | E0028 | non-negotiable | false | 10 |
| R00660 | Signing integrates with `selfdef-collector-tetragon` (TracingPolicy signing) | `crates/selfdef-signing` | E0028 | non-negotiable | false | 10 |
| R00661 | Signing integrates with `selfdef-collector-eventstream` (signed event chain) | `crates/selfdef-signing` | E0024 | non-negotiable | false | 10 |
| R00662 | Signing integrates with operator-managed trust root at `/etc/selfdef/trust/` | filesystem | E0024 | non-negotiable | false | 10 |
| R00663 | UX — `selfdefctl rules list` output ≤ 1 screen on green case | `crates/selfdef-cli` | F00322 | preferable | true | 10 |
| R00664 | UX — `selfdefctl rules list` groups rules by category + signed-state | `crates/selfdef-cli` | F00322 | non-negotiable | true | 10 |
| R00665 | UX — `selfdefctl responder commit` requires triple-gate (`--apply` + `--confirm-commit` + named verdict id) | `crates/selfdef-cli` | F00330 | non-negotiable | false | 10 |
| R00666 | UX — `selfdefctl responder commit` shows preview-then-prompt diff before applying | `crates/selfdef-cli` | F00330 | non-negotiable | true | 10 |
| R00667 | UX — `selfdefctl trust add` requires triple-gate (`--apply` + `--confirm-trust` + named fingerprint) | `crates/selfdef-cli` | F00332 | non-negotiable | false | 10 |
| R00668 | UX — Dashboard surfaces high-severity verdict as red banner | `dashboard/` | F00336 | non-negotiable | true | 10 |
| R00669 | UX — Dashboard surfaces signed-rule loaded-success as green tile | `dashboard/` | F00342 | non-negotiable | true | 10 |
| R00670 | UX — Dashboard surfaces signed-rule load-failure as red tile with operator-next-step | `dashboard/` | F00342 | non-negotiable | true | 10 |
| R00671 | UX — `selfdefctl --json` output available for every rules/store/responder/trust verb | `crates/selfdef-cli` | E0021 | non-negotiable | true | 10 |
| R00672 | UX — Responder Action ledger viewer surfaces rollback option when rollback supported | `dashboard/` | R00556 | preferable | true | 10 |
| R00673 | UX — Verdict evidence-chain inspector links to source events + rules | `dashboard/` | F00337 | non-negotiable | true | 10 |
| R00674 | UX — Store replay UI supports operator-discoverable time-window picker | `dashboard/` | F00316 | non-negotiable | true | 10 |
| R00675 | Correlator emits journald-recognizable structured logs | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00676 | Responder emits journald-recognizable structured logs | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00677 | Store emits journald-recognizable structured logs | `crates/selfdef-store` | E0022 | non-negotiable | false | 10 |
| R00678 | Signing emits journald-recognizable structured logs | `crates/selfdef-signing` | E0024 | non-negotiable | false | 10 |
| R00679 | Correlator emits OpenTelemetry traces per Verdict | `crates/selfdef-correlator` | E0021 | preferable | true | 10 |
| R00680 | Responder emits OpenTelemetry traces per Action commit | `crates/selfdef-responder` | E0023 | preferable | true | 10 |
| R00681 | Correlator survives daemon restart (rules reload deterministically) | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00682 | Responder survives daemon restart (in-flight Actions drain via SDD-008 handoff) | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00683 | Store survives daemon restart (schema_version checked + migrations applied) | `crates/selfdef-store` | E0029 | non-negotiable | false | 10 |
| R00684 | Signing survives daemon restart (trust list re-loaded from /etc/selfdef/trust/) | `crates/selfdef-signing` | E0024 | non-negotiable | false | 10 |
| R00685 | Correlator backpressure — per-rule queue capacity tunable | `crates/selfdef-correlator` | M00057 | non-negotiable | true | 10 |
| R00686 | Responder backpressure — per-Action-type queue capacity tunable | `crates/selfdef-responder` | E0023 | non-negotiable | true | 10 |
| R00687 | Store backpressure — write-batch size + flush interval tunable | `crates/selfdef-store` | E0022 | non-negotiable | true | 10 |
| R00688 | Correlator graceful shutdown — drains in-flight rule evaluations on SIGTERM | `crates/selfdef-correlator` | E0021 | non-negotiable | false | 10 |
| R00689 | Responder graceful shutdown — drains in-flight Actions on SIGTERM | `crates/selfdef-responder` | E0023 | non-negotiable | false | 10 |
| R00690 | Store graceful shutdown — flushes pending writes on SIGTERM | `crates/selfdef-store` | E0022 | non-negotiable | false | 10 |
| R00691 | Documentation — every responder Action has a README describing target / risk / rollback / dry-run preview shape | `crates/selfdef-responder/README.md` | E0023 | non-negotiable | true | 10 |
| R00692 | Documentation — store schema documented at `crates/selfdef-store/migrations/README.md` | `crates/selfdef-store/migrations/README.md` | E0029 | non-negotiable | true | 10 |
| R00693 | Documentation — signing workflow documented at `crates/selfdef-signing/README.md` | `crates/selfdef-signing/README.md` | E0024 | non-negotiable | true | 10 |
| R00694 | Documentation — operator-facing rule-authoring guide at top-level docs/ | `docs/` | E0021 | non-negotiable | true | 10 |
| R00695 | Anti-pattern — Correlator NEVER auto-escalates Verdict (only matching rules can escalate) | `crates/selfdef-correlator` | R00554 | non-negotiable | false | 10 |
| R00696 | Anti-pattern — Responder NEVER commits Action without operator-config consent (per Action type opt-in) | `crates/selfdef-config` | E0023 | non-negotiable | false | 10 |
| R00697 | Anti-pattern — Store NEVER mutates `events` rows after insert (append-only invariant) | `crates/selfdef-store` | R00533 | non-negotiable | false | 10 |
| R00698 | Anti-pattern — Signing NEVER reads private keys (verify-only daemon) | `crates/selfdef-signing` | R00563 | non-negotiable | false | 10 |
| R00699 | Anti-pattern — Correlator NEVER applies unverified Sigma rule when rule_signing_required=true | `crates/selfdef-correlator` | R00565 | non-negotiable | false | 10 |
| R00700 | Anti-pattern — Tetragon TracingPolicy NEVER loaded when policy_signing_required=true and signature absent | `crates/selfdef-collector-tetragon` | F00310 | non-negotiable | false | 10 |
| R00701 | Default — Responder dry_run defaults to TRUE on fresh install (operator opts INTO commits) | `crates/selfdef-config` | F00296 | non-negotiable | true | 10 |
| R00702 | Default — Correlator rule_signing_required defaults to FALSE (operator opts INTO signing) | `crates/selfdef-config` | R00566 | non-negotiable | true | 10 |
| R00703 | Default — Store backend defaults to SQLite (operator opts INTO PostgreSQL) | `crates/selfdef-config` | F00269 | non-negotiable | true | 10 |
| R00704 | Default — Store retention TTLs are conservative (30d / 90d / 1y) | `crates/selfdef-config` | M00065 | non-negotiable | true | 10 |
| R00705 | L1 lint — every Responder Action has a unique enum variant in `selfdef-core::Action` | tests/lint | E0023 | non-negotiable | false | 10 |
| R00706 | L1 lint — every Store table has a corresponding migration file | tests/lint | E0029 | non-negotiable | false | 10 |
| R00707 | L1 lint — every Verdict variant has a confidence-bucket label | tests/lint | E0026 | non-negotiable | false | 10 |
| R00708 | L3 smoke — correlator + store + responder + signing daemon-startup readiness within 5s | tests/ | E0030 | non-negotiable | false | 10 |
| R00709 | L3 smoke — synthetic Event stream → Verdict emission → Responder dry-run Action → Store ledger row in < 1s | tests/ | E0030 | non-negotiable | false | 10 |
| R00710 | L5 real-substrate — Correlator + Store + Responder run on real Debian 13 VM with 7 collectors live | tests/ | E0030 | non-negotiable | false | 10 |
| R00711 | Cross-repo binding — selfdef-side typed-mirror crate per SDD-038 doctrine | SDD-038 | E0030 | non-negotiable | false | 10 |
| R00712 | Cross-repo binding — Verdict envelope mirrors to sovereign-os trace consumer (operator opt-in) | SDD-038 | E0030 | non-negotiable | true | 10 |
| R00713 | Cross-repo binding — Action ledger surfaces to sovereign-os trace consumer (operator opt-in) | SDD-038 | E0030 | non-negotiable | true | 10 |
| R00714 | Cross-repo binding — selfdef NEVER pulls sovereign-os runtime state directly (only via eventstream collector) | architecture | E0030 | non-negotiable | false | 10 |
| R00715 | Cross-repo binding — sovereign-os NEVER pulls selfdef store directly (only via typed-mirror crate) | architecture | E0030 | non-negotiable | false | 10 |
| R00716 | Cross-repo binding — saturation invariant must cover any new sovereign-os instrument that needs selfdef-side mirror | SDD-038 | E0030 | non-negotiable | false | 10 |
| R00717 | SDD respect — Correlator + Store + Responder + Signing all governed by SDD-004 threat model | SDD-004 | E0030 | non-negotiable | false | 10 |
| R00718 | SDD respect — Pipeline boundary documented in SDD-029 round-ledger | SDD-029 | E0030 | non-negotiable | false | 10 |
| R00719 | SDD respect — Cross-repo binding doctrine documented in SDD-038 | SDD-038 | E0030 | non-negotiable | false | 10 |
| R00720 | Composite — Correlator + Store + Responder + Signing form selfdef's post-collection pipeline; together with MS002 collector fabric they form the complete IPS substrate | this milestone | E0030 | non-negotiable | false | 10 |

— End of MS003 milestone file.
