# SDD-048 — Communication boundary — 4 transports + 8 message types (MS034)

> Status: **implemented** — `selfdef-communication-boundary` crate
> (372 LOC) shipped with the full E0342-E0349 doctrine encoded:
> 4-transport ladder + 8-message-type schema + Direction enum +
> MessageEnvelope struct + 2 verbatim doctrinal phrases preserved.
> Stage-2 SDD authored retroactively over the shipped crate.
> Owner: operator-supervised; agent-authored.
> Last updated: 2026-05-21.
> Implements milestone: MS034 (catalogued in
> `backlog/milestones/MS034-communication-boundary.md`)
> Builds on: SDD-004 (security threat model), SDD-007 (audit chain),
> SDD-043 (commit-authority — every VM→host commit is a Commit per
> the doctrine), SDD-044 (capability tokens — message authority gated
> via tokens), SDD-045 (filesystem-boundary — SharedFolder transport
> uses explicit exchange dirs), SDD-046 (network-boundary — composes
> with NetworkProfile), SDD-047 (sandbox-tiers — per-tier transport
> selection).
> Cross-repo: sovereign-os communication-boundary canon mirrored via
> MS007.

## Problem

Sandboxed agent VMs need a typed communication channel to/from the
host. Ad-hoc protocols invite drift + privilege escalation:

1. **Implicit message shapes** — VM could send arbitrary JSON; host
   parses optimistically + commits unintended state.
2. **No direction discipline** — patches could flow host→VM by
   accident, inverting the trust boundary.
3. **No transport discipline** — picking AF_VSOCK vs gRPC vs shared-
   folder per-call invites driver mismatches.
4. **No proposal/final distinction** — VM might believe its
   `PatchProposal` was committed when the host rejected it; vice
   versa.
5. **No doctrinal anchor** — without verbatim phrases, code-comments
   drift over time and the operator's intent is lost.

## Goals

1. 4-transport ladder per E0342 dump 3456-3462:
   - `VirtioVsock` — AF_VSOCK virtio (host↔VM kernel-level)
   - `GrpcOverVsock` — gRPC framed over AF_VSOCK
   - `UnixSocketProxy` — Unix-socket forwarded over shared mount
   - `SharedFolder` — explicit-exchange dirs per SDD-045 (slowest;
     used for large patch payloads)

2. 8 canonical message types per E0343-E0345 dump 3466-3473:

   | type             | direction | content                                |
   |------------------|-----------|----------------------------------------|
   | `DraftRequest`   | host→VM   | ask for generation                     |
   | `DraftResult`    | VM→host   | drafts response                        |
   | `EmbeddingRequest`| host→VM  | ask for embeddings                     |
   | `RerankResult`   | VM→host   | reranked candidates                    |
   | `VisionResult`   | VM→host   | vision / GUI / perception output       |
   | `ToolPlan`       | VM→host   | proposed tool calls (PROPOSAL)         |
   | `RiskAssessment` | VM→host   | scored risk (PROPOSAL)                 |
   | `PatchProposal`  | VM→host   | file patches (PROPOSAL — SDD-045 flow) |

3. `Direction` enum (HostToVm / VmToHost) — exposed via
   `MessageType::direction()` so callers can verify direction
   matches expectation.

4. `MessageType::is_proposal()` — discriminates the 3 proposal
   types (ToolPlan / RiskAssessment / PatchProposal) so the host
   can gate them through SDD-043 commit-authority.

5. `MessageEnvelope` struct carrying the message + transport +
   actor + trace_ref so every cross-boundary message has identity
   + audit-trail.

6. Preserve doctrines verbatim per E0346 + E0347:
   - "Never let the VM directly mutate host truth"
   - "The VM proposes. Host commits."

## Non-goals

- This SDD does NOT cover the VM-side message library (that's the
  VM's own integration; selfdef owns the HOST-side contract).
- It does NOT cover the protobuf / capnp / postcard serialization
  choice (separate sub-arc).
- It does NOT cover multi-VM federation (single host's IPS is the
  bounded scope; cross-host = sovereign-os concern).

## Alternative designs considered

**Alt 1 (rejected): one big JSON message type with `kind: string`.**
Trivially extensible. Rejected — no compile-time exhaustiveness
checks; refactors can drop a kind without compiler help.

**Alt 2 (rejected): per-transport message types.** Different
schemas over AF_VSOCK vs gRPC. Rejected — couples message shape
to transport; can't swap transports.

**Alt 3 (CHOSEN): single typed `MessageType` enum + uniform
`MessageEnvelope`.** Same 8 types across all 4 transports.
Compile-time exhaustiveness guarantees no kind is silently dropped.

## Recommended design

### Types (shipped in `crates/selfdef-communication-boundary/src/lib.rs`)

```rust
pub enum Transport {
    VirtioVsock,
    GrpcOverVsock,
    UnixSocketProxy,
    SharedFolder,
}

pub enum MessageType {
    DraftRequest, DraftResult,
    EmbeddingRequest, RerankResult,
    VisionResult, ToolPlan,
    RiskAssessment, PatchProposal,
}

pub enum Direction { HostToVm, VmToHost }

pub struct MessageEnvelope {
    pub schema_version: String,
    pub transport: Transport,
    pub message_type: MessageType,
    pub actor: String,           // MS003 fingerprint of sender
    pub trace_ref: String,       // MS049 cross-cutting trace
    pub payload: serde_json::Value,
}

impl MessageType {
    pub fn direction(self) -> Direction;
    pub fn is_proposal(self) -> bool;
}

pub fn assert_doctrines_intact(vm_never: &str, vm_proposes: &str) -> Result<(), CommError>;
```

### Caller contract

Every host-side message receive MUST:

1. Deserialize as `MessageEnvelope`.
2. Validate `transport` is one of the 4 supported variants.
3. Verify `message_type.direction() == Direction::VmToHost`.
4. If `is_proposal()`, gate the host-side commit through SDD-043
   `CommitAuthority::validate` + SDD-044 capability-token check
   + (for `PatchProposal`) the SDD-045 filesystem-boundary import
   pipeline.
5. On commit: emit SDD-043 `CommitEnvelope` with commit_type =
   `ToolSideEffect` (ToolPlan) | `RiskAssessment` (RiskAssessment) |
   `FileWrite` (PatchProposal).
6. Refuse-to-commit if `message_type.direction() == HostToVm`
   appeared on the receive side — that's a misrouted message; log
   to audit chain + drop.

Every host-side message send MUST:

1. Construct `MessageEnvelope` with direction = `HostToVm`.
2. Pick `Transport` per the SDD-047 sandbox-tier policy (Tier0/1
   = forbid; Tier2 = VirtioVsock only; Tier3+ = any).
3. Audit the send via SDD-043 commit envelope (informational —
   commit_type = `WorkflowCompletion`).

## Implementation status

**Crate**: shipped (372 LOC). 4 transport variants + 8 message types
+ Direction + envelope + 2 doctrine constants + assertion helper.

**Caller integration**: deferred. Natural first integration target
is the VM-channel implementation in the upcoming MS032 Tier3+
dispatcher arc.

## Test requirements

- Unit tests covering all 8 message-type directions + proposal
  classification. ✅ shipped.
- Integration test refusing misrouted direction + invalid transport.
  ⏳ deferred to caller-integration arc.

## Rollout

Retroactive SDD over shipped crate code.

## Open questions

- **D-1**: `selfdefctl communication-boundary {transports, types,
  doctrine, classify <envelope.json>}` CLI? **Recommendation: yes**,
  follows the SDD-043..047 D-1 pattern.
- **D-2**: `GET /v1/communication-boundary` HTTP discovery returning
  the 4 transports + 8 message types + direction table + proposal
  classifier + 2 doctrine constants? **Recommendation: yes** after D-1.
- **D-3**: Serialization choice — protobuf / capnp / postcard?
  **Recommendation**: defer; a wrapper crate `selfdef-comm-codec`
  can encode/decode `MessageEnvelope` in any of these without
  changing the boundary type. JSON shipping today is sufficient
  for operator-readable diagnostics.
- **D-4**: Live message-flow observability — should the daemon
  emit per-message-type counters (`selfdef_comm_messages_total
  {direction, type}`) to Prometheus? **Recommendation: yes**, ship
  as a follow-up that mirrors the watchdog-metrics pattern from
  MS027.
