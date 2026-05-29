# SDD-068 — API/web-token revocation action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** SDD-067 §3 open question #2 — *"Web/API token
revocation. PAM only catches shell auth. How do we revoke
selfdef-api / sovereign-os-cockpit tokens?"*. Spec writes that
open question into a concrete fourth primitive joining the
SDD-065/066/067 IPS trio.
**Pairs with:** SDD-065 (network), SDD-066 (process), SDD-067
(shell session), SDD-068 (API/web token = this spec). Together:
**the IPS enforcement quartet** — perimeter + process + identity
+ API-credential.

## Purpose

The trio's missing fourth action: **revoke all active API/web
tokens for a principal**. Where SDD-067 kills shell + sudo + PAM-
side sessions, SDD-068 kills the HTTP-side tokens that those
shells may never have touched. Common attack: principal's API
token is exfiltrated; attacker uses it from a fresh IP that
SDD-065 hasn't blocked yet, in a new process SDD-066 has no pid
for, without any PAM session SDD-067 can touch. SDD-068 closes
that gap.

Token surfaces under selfdef's authority:

- **selfdef-api tokens** (existing selfdef-api crate JWT
  authentication). Operator-issued.
- **sovereign-os cockpit bearer tokens** (existing
  config/dashboard-auth.toml.example structure). Sovereign-os
  subscribes; selfdef-bus event triggers eviction.
- **mcp-aggregate session keys** (sovereign-os
  scripts/interop/mcp-aggregate.py). Subscribe-and-evict pattern.

## Non-goals

- Not OAuth/OIDC issuer-side revocation. Out-of-scope; that lives
  at the IdP.
- Not container registry / image-pull token revocation. Out of
  scope (separate SDD-069 candidate).
- Not generic JWT introspection RFC 7662. SDD-068 is locally
  authoritative — when selfdef revokes, ALL participating
  surfaces drop the token.

## Surface

### 1. CLI verbs

```
selfdefctl revoke-tokens <principal> --reason <text>
                                     [--duration <human>]   # default 1h; max 72h
                                     [--authority <tier>]
                                     [--token-class <api|cockpit|mcp|all>]
                                     [--dry-run]

selfdefctl restore-tokens <principal-or-handle> [--force]
```

The `--token-class` flag scopes which surface(s) the revocation
hits. `all` revokes across every participating surface.

### 2. Library — `selfdef-responder::ApiTokenRevocationAction`

```rust
pub struct ApiTokenRevocationAction {
    backend:   Arc<dyn ApiTokenRevocationBackend>,
    audit:     Arc<dyn AuditWriter>,
    authority: AuthorityTier,
    duration:  Duration,
    token_class: TokenClassMask,
    reason_prefix: String,
}
```

Event-driven source-extraction: `event.actor.user.name` for the
principal id. Same Skipped pattern as SDD-067 when absent.

### 3. Backend trait

```rust
pub enum TokenClassMask {
    All,
    Specific(Vec<TokenClass>), // Api | Cockpit | Mcp
}

#[async_trait]
pub trait ApiTokenRevocationBackend: Send + Sync {
    async fn revoke_tokens(
        &self, req: TokenRevokeRequest,
    ) -> Result<TokenRevokeReceipt, TokenRevocationError>;
    async fn restore_tokens(
        &self, handle: TokenRevocationHandle,
    ) -> Result<TokenRestoreReceipt, TokenRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingTokenRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &TokenRevocationHandle) -> bool { false }
}
```

Production adapters (MS1b feature-gated):

- **`BusEventBackend`** — publishes a typed selfdef-bus event
  `TokenRevoked { principal, classes, duration, handle }`. Each
  participating surface (selfdef-api, sovereign-os cockpit,
  mcp-aggregate) subscribes and updates its local deny-list with
  TTL = `duration`. Tokens fail validation until TTL expires.
- **`InMemoryBackend`** — hermetic test substrate per the
  MS1-substrate decision.

### 4. Authority + TTL matrix

| Authority tier        | Max revocation window |
|-----------------------|-----------------------|
| `autonomous`          | 2 min                 |
| `responder`           | 1 hour                |
| `operator`            | 8 hours               |
| `operator-overridden` | 72 hours              |

Longer ceilings than SDD-067 (which acts on the shell side and
risks locking operator out of their console) — token revocation
is recoverable (operator issues new token via console/cockpit),
so 72h is acceptable.

### 5. Audit + observability

Per-revoke audit envelope:

```json
{
  "ts":          "2026-05-29T20:00:00Z",
  "action":      "revoke_tokens",
  "principal":   "alice",
  "token_classes": ["api", "cockpit"],
  "reason":      "exfiltrated_token (responder)",
  "duration_sec": 3600,
  "authority":    "responder",
  "source":       "selfdef-correlator",
  "handle":       "tok-2026-05-29-001",
  "surfaces_notified": ["selfdef-api", "sovereign-os-cockpit"],
  "outcome":      "revoked"
}
```

Textfile gauges (new 22nd sibling observer
`selfdef-token-revocations-textfile.sh`, OnBootSec=660s):

- `selfdef_token_revocations_active_count`
- `selfdef_token_revocations_pending_restores`
- `selfdef_token_revocations_classes_active_total{class=…}`
- `selfdef_token_revocations_oldest_expiry_unix`
- `selfdef_token_revocations_last_run_unix`
- `selfdef_token_revocations_textfile_emit_failed`

### 6. Operator UX

Reuse the documented MS5b paired-enforcement-primitive cockpit
pattern (see info-hub
`wiki/patterns/01_drafts/paired-enforcement-primitive-five-milestone-architecture.md`):

- `scripts/cockpit/token-revocations-queue.py` — same shape as
  the three trio queues.
- `card_token_revocations_queue` in dashboard serve.py.

The cockpit's CARDS list ordering surfaces all FOUR enforcement-
queue cards together:

```python
CARDS = [
    card_morning_brief,
    card_operator_posture,
    card_blockset_queue,          # SDD-065 IP-block
    card_quarantine_queue,        # SDD-066 process-freeze
    card_revocations_queue,       # SDD-067 shell-session-revoke
    card_token_revocations_queue, # SDD-068 API-token-revoke (NEW)
    card_gpu,
    ...
]
```

When the correlator chains the **quartet** on one incident,
operator sees 4 paired-handle decisions in a single row.

### 7. Cross-action coordination — the IPS quartet

```
exfil-2026-05-29-099
  - block:           203.0.113.42       (SDD-065, 32m left)
  - quarantine:      pid 12345           (SDD-066, 14m left)
  - revoke-sessions: alice               (SDD-067, 28m left)
  - revoke-tokens:   alice (api+cockpit) (SDD-068, 58m left, NEW)
  [ extend-block 24h ]  [ release-process ]  [ extend-revoke 4h ]
                                              [ restore-now ]
                                              [ extend-tokens 8h ]
```

## Implementation order (6 milestones — same pattern as SDD-065/066/067)

| MS | Slice | Depends on |
|----|-------|-----------|
| 1  | `selfdef-api-token-revocation-backend` — trait + InMemoryBackend + ~14 TDD tests | none |
| 1b | BusEventBackend (feature `bus-event-backend`) | MS1 + selfdef-bus event type |
| 2  | `selfdef-responder::ApiTokenRevocationAction` | MS1 |
| 3  | `selfdefctl revoke-tokens / restore-tokens` CLI verbs | MS2 |
| 4  | 22nd sibling observer + sovereign-os alerts + dashboard + obs-status vertical 22 | MS1 |
| 5  | MS5b cockpit consumer + quartet-paired-handle row | MS5b (SDD-065/066/067) |

## Open questions

- **Token-class enumeration.** Operator-extensible vs hardcoded
  `Api | Cockpit | Mcp`? Proposal: enum-with-`Other(String)`
  extensible.
- **Cross-surface ack required?** Should `revoke_tokens` wait
  for ack from all participating surfaces before returning Ok?
  Proposal: fire-and-forget bus event; each surface logs its
  ack to its own audit log; receipts include `surfaces_notified`
  list from the bus subscriber count at fire time.
- **Surface failure semantics.** If sovereign-os cockpit is
  down when selfdef fires the event, cockpit tokens stay valid
  on restart until subscriber catches up. Tradeoff: false-
  negative window vs hard-fail-on-disconnect. Proposal:
  false-negative window; selfdefd resubmits unacked events
  every 30s for 5m.

## Standing-rule alignment

R10212 + "we do not minimize" + "cannot mark done if not in
Prod" — same alignment block as SDD-065/066/067. Selfdef vends
the trait + backend + audit; sovereign-os + mcp-aggregate
subscribe to the bus event and update their local deny-lists.
