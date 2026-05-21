# SDD-016 — `oracle-triage` notifier channel (Stage-2 PR 4/4)

> Status: **implemented** — fourth + final Stage-2 SDD per SDD-012 Q-H
> ordering; shipped end-to-end:
>  - `[oracle_triage]` config block (endpoint + rate-limit per
>    operator policy)
>  - Notifier-engine channel delivers triage payloads to the operator-
>    configured Oracle Core endpoint
>  - `check_oracle_triage` doctor check
>    (`crates/selfdef-cli/src/doctor.rs:444`) — surfaces rate-limit
>    state + rejects malformed endpoints + skipped when disabled
>  - 4 unit tests in `crates/selfdef-cli/src/doctor.rs::sdd_013_tests`
>    covering rate-limit surfaced, zero-rate warn, bad-endpoint reject,
>    skipped-when-disabled
> Owner: operator-supervised; agent-authored
> Last updated: 2026-05-21 (status: review → implemented)
> Closes findings: SDD-012 Q-D (selfdef-side Oracle Core integration)
> Derived from: SDD-012 (integration design); SDD-014 (shared-audit-summary); sovereign-os SDD-011 (inference backend stack); sovereign-os SDD-005 (sain-01 profile)

## Problem

SDD-012 Q-D resolved: **selfdef stays Oracle-Core-unaware in v1; opt-in `oracle-triage` notifier channel post-procurement**.

The channel emits selfdef event payloads to the sovereign-os inference router (`http://127.0.0.1:8080` per SDD-011 default) which dispatches them to whichever tier wins each request's classify() rule:
- code/math-pattern events → Oracle Core (vLLM + DFlash drafts on Blackwell)
- structured-output / JSON-mode events → Logic Engine (vLLM on 3090 VFIO)
- short, low-entropy events → Pulse (bitnet.cpp on CPU)

selfdef gets per-event triage suggestions back; the operator dashboard surfaces them; **selfdef remains the event-detection authority**, the inference stack remains the dispatch authority. Decoupled by design.

This SDD specifies the channel that emits payloads to the router + handles responses.

## Required coverage

### 1. New crate

`crates/selfdef-integration-oracle-triage/` — per-transport-crate pattern (per D-024).

### 2. Channel config

```toml
# /etc/selfdef/selfdef.toml addition:
[notifier.oracle_triage]
enabled = true                              # opt-in; never auto-enabled even on sain01
endpoint = "http://127.0.0.1:8080"          # sovereign-os router (SDD-011 default port)
model = "auto"                              # auto-route via router.classify(); or pin "microsoft/bitnet-b1.58-2B-4T"
timeout_seconds = 30                        # event-dispatch must complete in 30s
api_key_env = "SOVEREIGN_OS_ROUTER_API_KEY" # optional; only if router is remote + token-gated

# What events to triage (filter by severity + kind)
[notifier.oracle_triage.filter]
min_severity = "WARN"                       # only WARN/ERROR; ignore INFO
kinds = ["POLICY_VIOLATION", "CONN_ANOMALY", "CORRELATOR_ALERT"]

# Where to write the triage response
output_target = "operator-dashboard"        # operator-dashboard | shared-audit-summary | both
```

**Default: `enabled = false`**. SDD-012 Q-D explicitly: selfdef stays Oracle-unaware in v1; operator must opt-in.

When `[deployment.target] = "sain01"` (SDD-013), this channel is still NOT auto-enabled — the operator's explicit `enabled = true` is required.

### 3. Request shape

selfdef emits an OpenAI-compatible chat-completions request:

```json
{
  "model": "auto",
  "messages": [
    {
      "role": "system",
      "content": "You are a security triage assistant for the sovereign-os SAIN-01 deployment. Analyze the following selfdef event and recommend operator-actionable next steps in 3-5 bullet points. Be specific. Cite the event-id."
    },
    {
      "role": "user",
      "content": "Event evt-9f2c at 2026-05-16T03:45:30Z\nKind: POLICY_VIOLATION\nSeverity: ERROR\nDetail: ...full event JSON..."
    }
  ],
  "response_format": {"type": "json_object"},
  "max_tokens": 512
}
```

The `response_format: json_object` + the presence of `tools` (if operator configures any) routes the request via SDD-011's classifier to the Logic Engine by default. Code/math-heavy event payloads (e.g., events containing stack traces or shellcode patterns) route to Oracle Core. The classifier handles the per-event dispatch — selfdef doesn't pick the tier.

### 4. Response handling

```json
{
  "id": "...",
  "choices": [
    {
      "message": {
        "content": "{\"event_id\": \"evt-9f2c\", \"triage\": [\"Review allowlist match on /usr/bin/python3 — was this expected?\", \"Check sovereign-os Tetragon log at /mnt/vault/context/security_audit.log for correlated kills\", \"Consider tightening agent-guard's matchPIDs scope\"], \"severity_assessment\": \"medium\", \"correlation_hints\": [\"evt-9f2a\"]}"
      }
    }
  ]
}
```

selfdef parses the JSON, writes the triage block to:
- `operator-dashboard` (when output_target includes it) — the dashboard fetches via selfdef's existing `events {tail,alerts}` API
- `shared-audit-summary` (when output_target includes it) — appends a single line to `/mnt/vault/context/security_audit.log` per SDD-014 format

### 5. Resilience

If the router is unreachable (503 / timeout / connection refused):
- Log the failure to selfdef's own log
- Continue with the OTHER notifier channels
- Mark the event as "oracle-triage pending" in selfdef's persistent escalation engine; retry on next event-batch
- `selfdefctl doctor` warns when oracle_triage error rate > 5% over last 100 events

### 6. Authentication

By default `endpoint = http://127.0.0.1:8080` (local-only); no auth needed.

If operator points oracle_triage at a remote router (e.g., another SAIN-01 node), set `api_key_env = "X"`; selfdef reads the env var at startup and includes `Authorization: Bearer $X` header.

Never log the API key. Redact in `selfdefctl doctor` output.

### 7. CLI integration

```sh
# Operator visibility
sudo selfdefctl status                          # gains 'oracle-triage: enabled / disabled' line
sudo selfdefctl notify test oracle-triage       # sends a synthetic event; validates round-trip
sudo selfdefctl events triage <event-id>        # manual on-demand re-triage
sudo selfdefctl doctor                          # checks router reachability when oracle_triage enabled
```

### 8. Regression-prevention tests

```rust
#[test]
fn disabled_by_default() { /* even on sain01 */ }

#[test]
fn opt_in_required_explicit() { /* explicit enabled=true; not auto */ }

#[test]
fn request_shape_matches_openai_spec() { /* json schema compliance */ }

#[test]
fn response_parsed_as_triage_block() { /* triage[], severity_assessment, correlation_hints */ }

#[test]
fn min_severity_filter_skips_info_events() { /* INFO events never dispatched */ }

#[test]
fn kinds_filter_skips_unlisted_kinds() { /* only POLICY_VIOLATION/CONN_ANOMALY/etc. */ }

#[test]
fn router_unreachable_logs_does_not_break_chain() { /* resilience */ }

#[test]
fn api_key_redacted_in_logs() { /* SOVEREIGN_OS_ROUTER_API_KEY never appears in journal */ }

#[test]
fn check_overlap_skipped_on_generic_target_no_router() { /* SDD-012 Q-G honor */ }
```

Integration test: `tests/it/notifier_oracle_triage.rs` — spawns a mock OpenAI-compatible HTTP server + verifies the full request/response cycle.

## Goals

1. **Decoupling preserved** — selfdef event-detection authority + sovereign-os inference dispatch authority remain distinct (SDD-012 Q-D core).
2. **Opt-in only** — never auto-enabled; operator's explicit `enabled = true` required.
3. **OpenAI-compatible** — uses the sovereign-os router via standard chat-completions; no selfdef-specific protocol on the wire.
4. **Per-event filtering** — severity + kind filters keep noise out of the inference budget.
5. **Resilient** — router unreachable doesn't break the other 12+1 (SDD-014) notifier channels.
6. **Non-SAIN-01 unchanged** — `target=generic` defaults to disabled; never wired by default (Q-G honored).

## Non-goals (this SDD)

- Does NOT specify the system prompt's full content (kept in this SDD as an example; operator can override via `[notifier.oracle_triage].system_prompt_path`).
- Does NOT decide which Oracle Core model gets the request (SDD-011 router's classify() handles per-request dispatch).
- Does NOT alter sovereign-os router behavior. Router is consumed AS-IS.
- Does NOT process the triage suggestions automatically (no agent loop; operator-reviewed only).

## Open sub-questions

- **Q16-A** — Should selfdef cache the system prompt + send hash on each request to leverage Anthropic / OpenRouter prompt-caching? Recommend: **DEFER** until volume justifies; current expected event rate (~10-100/day) doesn't pressure caching budgets.
- **Q16-B** — Streaming responses (SSE) vs blocking? Recommend: **blocking** — triage events are async-from-operator anyway; SSE adds complexity without value.
- **Q16-C** — Should oracle_triage emit a JSON-mode-tools call to invoke selfdef CLI actions (e.g., "tighten the matchPIDs scope")? Recommend: **NO** — triage is advisory only; operator reviews + applies actions manually. Agentic auto-action is out of scope for this SDD.
- **Q16-D** — Cost / token-budget controls? Recommend: **YES** — `max_events_per_hour = 100` config block; rate-limit at selfdef side to prevent runaway Oracle Core utilization.

## Way forward

1. **This PR** — spec.
2. **Impl PR** — crate + config + tests + CLI wiring.
3. **Stage-2 complete** — SDD-012's 4-PR plan done. Operator can begin first real selfdef-on-SAIN-01 boot once hardware arrives.

Stage-2 progress: SDD-013 ✅ → SDD-014 ✅ → SDD-015 (in review) → **SDD-016 (this, last)**.

## Cross-references

- SDD-012 § Q-D (the design this implements)
- SDD-013 (deployment.target — required predecessor)
- SDD-014 (shared-audit-summary — one of oracle_triage's output_target options)
- SDD-008 (notifications-orchestration; 12+1+1 channels now)
- SDD-002 (config plumbing pattern)
- SDD-005 (test contract)
- D-024 (per-transport-crate pattern)
- sovereign-os SDD-011 (inference backend stack — the router this channel targets)
- sovereign-os `scripts/inference/router.py` (the classify() that dispatches the triage requests)
- sovereign-os `scripts/inference/start-oracle-core.sh` (the destination tier for code/math-heavy events)
- sovereign-os `profiles/sain-01.yaml` `whitelabel.legal_compliance` (operator's posture; informs whether oracle_triage requests should add legal disclaimers)
- info-hub `wiki/comparisons/cmp-ling-26-flash-vs-nemotron-3-nano-omni.md` (Oracle Core model picks; informs which model handles the triage request)
