# SDD-050 — Tool authority — typed authority on every tool intent (MS042)

> Status: **implemented** — 10+ tool-* crates shipped covering the
> tool-authority surface:
>  - `selfdef-tool-capability-policy` (12 tests) — 8 canonical tool
>    IDs × ExecutionMode × Profile authorization matrix
>  - `selfdef-tool-call-latency-budget` — per-Profile per-call
>    wall-clock soft/hard budget
>  - `selfdef-tool-cancellation-policy` — CancelMode × ExecPhase
>    cancel gating
>  - `selfdef-tool-version-pinning` — exact-semver OR sha256-digest
>    version pinning
>  - `selfdef-tool-stream-watchdog` — silence + total timeout
>    watchdog
>  - `selfdef-tool-invocation-rate-limit` — per-tool token-bucket
>    rate limit
>  - `selfdef-tool-output-language-policy` — output-shape gate
>    (JSON/YAML/free-form)
>  - `selfdef-tool-arg-redaction-policy` — sensitive-arg redaction
>    (exact / suffix / prefix / wildcard globs)
>  - `selfdef-tool-output-truncation-policy` — per-tool byte budget
>    + 3-strategy truncation (HeadOnly / HeadTail / MiddleEllipsis)
>  - `selfdef-tool-output-trust-veil` — typed wrapping forcing
>    explicit tier-unwrap before downstream consumption
>  - `selfdef-tool-output-byte-quota` — per-invocation warn/hard
>    byte budget
>
> Stage-2 SDD authored retroactively over the shipped crate set.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS042 (catalogued in
> `backlog/milestones/MS042-tool-authority.md`)
> Builds on: SDD-004, SDD-007, SDD-043 (commit-authority — every
> tool side-effect is a ToolSideEffect commit), SDD-044
> (capability-tokens — tool authority resolved through scope check),
> SDD-046 (network-boundary — WebFetch tool gates through
> NetworkProfile), SDD-047 (sandbox-tiers — tool dispatch via per-
> tier policy), SDD-048 (communication-boundary — ToolPlan message
> type), SDD-049 (authority + profiles — tool capability gated
> through ProfileEnvelope).
> Cross-repo: sovereign-os tool-authority canon (M056) mirrored
> via MS007.

## Problem

The IPS gates many "tools" — operator-invocable verbs that produce
side effects (Shell, FsRead, FsWrite, WebFetch, ModelInference,
McpBridge, ReplayControl, CliBridge). Without typed authority on
every tool intent:

1. **Implicit authorization** — any call site can spawn `Shell`
   without authorization check; privilege escalation invisible.
2. **No per-Profile envelope** — `private` profile permits Shell
   the same as `experimental`; massive blast-radius asymmetry.
3. **No latency budget** — runaway tool calls hang the daemon.
4. **No cancellation discipline** — operator can't safely
   cancel mid-stream tool output.
5. **No version pinning** — tool author silently upgrades; behaviour
   drifts under operator's feet.
6. **No output discipline** — tool emits gigabytes; daemon OOMs.
7. **No sensitive-arg redaction** — passwords + API tokens in
   audit logs.
8. **No trust-tier discipline** — Tier3-tool output flows into a
   Tier1 caller's state; implicit privilege escalation.

## Goals

Per dump 17422-17445 + the 10+ shipped crates:

1. **8 canonical tool IDs** + their `(ExecutionMode, Profile)`
   authorization matrix per `selfdef-tool-capability-policy`.
2. **Per-call latency budget**: soft_ms + hard_ms per Profile,
   verdicts OnTime / SoftExpired / HardExpired.
3. **CancelMode × ExecPhase matrix**: refuses cancel-after-Commit
   on tools that can't safely reverse.
4. **Version pinning**: exact-semver OR sha256-digest. Runtime
   refuses to invoke tool whose observed version doesn't match.
5. **Silence + total timeout watchdog**: bytes-since-last + overall
   budget; verdict Ok / Silence / TotalElapsed.
6. **Token-bucket rate limit**: per-tool max_calls_per_minute +
   burst_size + lazy refill on admit.
7. **Output-shape gate**: JSON output must start with `{` or `[`;
   YAML first line must not start with `<` / `{`; Pass /
   ShapeMismatch verdict.
8. **Arg redaction**: 4 pattern types (exact, suffix `*_token`,
   prefix `aws_*`, full wildcard) for sensitive-name detection.
9. **Output truncation**: HeadOnly / HeadTail / MiddleEllipsis
   strategies; TruncationReceipt {kept_bytes, dropped_bytes,
   strategy} returned.
10. **Trust-veil typed wrapping**: tool output bytes wrapped in
    `Veil` that consumers must `unveil_with_tier(expected)` —
    yields bytes only when declared tier matches caller expectation;
    prevents implicit promotion across IPS↔runtime boundary.
11. **Per-invocation byte quota**: warn_bytes + hard_bytes;
    chunk-by-chunk admission with Truncate {kept} verdict at warn
    and Refuse at hard.

## Non-goals

- This SDD does NOT cover specific tool IMPLEMENTATIONS (Shell
  binding, WebFetch HTTP client, etc.) — those are tool-author
  responsibility.
- It does NOT cover operator-invented custom tools (separate
  third-party-tool-plugin arc; that runs at Trust Ring 3 per
  SDD-049).

## Alternative designs considered

**Alt 1 (rejected): single `allow_tools: Vec<String>` config key.**
Trivially small. Rejected — collapses 11+ orthogonal policy
dimensions (latency, cancel, version, rate-limit, shape, redaction,
truncation, veil, quota) into a string list.

**Alt 2 (rejected): per-tool policy struct.** One struct per tool
with all fields inlined. Rejected — different tools need different
policy dimensions; the orthogonal-crates approach lets call sites
compose only what they need.

**Alt 3 (CHOSEN): 11 orthogonal policy crates + composition.**
Each crate owns one decision dimension; call site invokes the
policies it needs in sequence (rate-limit → version-pin → permits →
invoke → watchdog → quota → truncate → redact-args → veil).

## Recommended design

### 8 canonical tool IDs (per `selfdef-tool-capability-policy`)

```rust
pub enum ToolId {
    Shell,           // arbitrary shell command
    FsRead,          // filesystem read
    FsWrite,         // filesystem write
    WebFetch,        // HTTP GET / POST
    ModelInference,  // LLM call
    McpBridge,       // MCP tool dispatch
    ReplayControl,   // replay / counterfactual
    CliBridge,       // selfdefctl bridge call
}
```

### Composition pipeline

Every tool invocation passes through 9 gates in order:

```
admit (rate-limit) → permits (capability+profile) → version-pin →
  redact-args (for audit) → audit (SDD-043 ToolSideEffect commit) →
  invoke → watchdog (silence/total) → admit_chunk (byte-quota) →
  truncate → shape-check → veil-wrap → return Veil to caller
```

Any gate returning a non-Allow verdict refuses the invocation
with an operator-readable error citing the specific gate.

### Caller contract

Every tool-invocation call site MUST:

1. Construct `ToolInvocation {tool_id, args, requested_mode,
   requested_profile, requested_authority_level}`.
2. Call `selfdef_tool_invocation_rate_limit::admit()`; refuse on
   Denied.
3. Call `selfdef_tool_capability_policy::permits(tool_id, mode,
   profile)`; refuse if (mode, profile) not in the authorized set.
4. Call `selfdef_tool_version_pinning::admit()`; refuse on version
   mismatch.
5. Redact args via `selfdef_tool_arg_redaction_policy::redact_args`
   BEFORE audit-logging — never log raw sensitive args.
6. Emit SDD-043 `CommitEnvelope` (commit_type = `ToolSideEffect`).
7. Invoke the tool.
8. Per chunk: `selfdef_tool_stream_watchdog::observe` +
   `selfdef_tool_output_byte_quota::admit_chunk`.
9. On completion: `selfdef_tool_output_truncation_policy::truncate`
   then `selfdef_tool_output_language_policy::check`.
10. Wrap bytes in `selfdef_tool_output_trust_veil::Veil` and return;
    downstream consumers must `unveil_with_tier(expected)` before
    using the bytes.

## Implementation status

**Crates**: 11+ shipped. The composition pipeline is fully type-
covered; each gate is independently testable + composable.

**Caller integration**: deferred. Natural first integration: the
existing selfdefctl tool-invoking verbs (`selfdefctl notify resend`,
`selfdefctl events tail`, `selfdefctl scheduler replay`) route
through the pipeline.

## Test requirements

- Per-crate unit tests covering every gate's Allow/Deny branches.
  ✅ shipped.
- Integration test through the full 9-gate pipeline. ⏳ deferred.

## Rollout

Retroactive SDD over shipped crate code.

## Open questions

- **D-1**: `selfdefctl tool-authority {tools, permits <tool> <mode>
  <profile>, gates}` CLI? **Recommendation: yes**, follows the
  SDD-043..049 D-1 pattern.
- **D-2**: `GET /v1/tool-authority` HTTP discovery returning the 8
  tool IDs + permits matrix + the 9-gate pipeline order +
  per-gate decision vocabulary? **Recommendation: yes** after D-1.
- **D-3**: Live tool-call observability — `selfdef_tool_calls_total
  {tool_id, profile, outcome}` Prometheus counter? **Recommendation:
  yes**, mirrors the watchdog-metrics pattern from MS027.
- **D-4**: Veil-tier opt-out — should there be an operator escape
  hatch when downstream code legitimately needs Tier-N bytes from a
  Tier-N+1 tool? **Recommendation: NO** — Veil is enforced by type;
  operator wanting cross-tier flow should mint a new capability
  token with the matching scope (per SDD-044).
