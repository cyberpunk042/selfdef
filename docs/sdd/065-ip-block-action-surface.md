# SDD-065 — IP-block action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** stop-hook feedback (2026-05-29) — "DO NOT STOP AT
DEFINING/REGISTERING THE REQUIREMENT and doing the scaffolds, we
expect the full production progressively through the workflow.
SDD does not stop at the shell nor the core it drive from it
through all the layers. You cannot mark something done if it
hasn't reached Prod."
**Pairs with:** SDD-049 (authority model), SDD-051 (policy bus),
SDD-046 (network boundary), SDD-064 (observed discipline), this
session's 14th-sibling nftables observer (selfdef
`packaging/scripts/selfdef-nftables-textfile.sh` commit `2c303c4`).

## Purpose

Bridge the observability signals (auth-events login-failure storms,
nftables ruleset state, fail2ban defensive-response gauges) to a
concrete operator-actionable + responder-automatable IP-block
enforcement primitive. This is the **enforcement layer** that turns
the observer surfaces into IPS action — the missing piece between
"we can see the attack" and "the attack is mitigated."

The existing `selfdef-responder` crate carries `NotifyAction`,
`LockdownEgressAction`, `SnapshotProcAction`, `KillPidAction`,
`ForensicsBundleAction`, `VelociraptorEscalateAction`. It does NOT
carry a per-source-IP block primitive. This SDD specifies that
addition end-to-end: trait → adapter → CLI verb → audit → operator
UX.

## Non-goals

- Not a fail2ban replacement. fail2ban-jail-state is the 13th
  sibling observer — this primitive can act alongside fail2ban
  with a distinct policy lane (e.g., fail2ban handles auth-only
  ban policy; this handles whole-traffic-class blocks ordered by
  selfdefd's authority chain).
- Not arbitrary nftables rule editing. The action surface vends a
  narrowly-defined set of ban primitives; the operator's full
  firewall remains under their own ruleset management.
- Not a router/upstream ASN block — host-local only. Upstream
  propagation is a separate concern (out of scope for SDD-065;
  candidate for SDD-067+).

## Surface

### 1. CLI verb — `selfdefctl block-ip <ip> [flags]`

```
selfdefctl block-ip <addr> --reason <text>
                    [--duration <human>]   # default 1h; max 720h
                    [--scope <ipv4|ipv6|auto>]
                    [--authority <tier>]   # operator | responder | autonomous
                    [--dry-run]            # plan + audit only, no apply
                    [--release-handle]     # echo opaque release key for unblock
```

Exit codes:
- `0` — block applied (or dry-run plan emitted).
- `2` — authority tier insufficient for requested duration / scope.
- `3` — IP already blocked under conflicting policy.
- `4` — nftables backend unreachable (selfdef-quarantine-engine
        cannot reach kernel netlink).
- `1` — generic error.

Companion verb: `selfdefctl unblock-ip <handle-or-ip> [--force]`.

### 2. Library surface — `selfdef-responder::BlockIpAction`

```rust
pub struct BlockIpAction {
    quarantine: Arc<dyn QuarantineBackend>,  // selfdef-quarantine-engine
    audit:      Arc<dyn AuditWriter>,        // selfdef-audit-log-writer
    policy:    Arc<BlockIpPolicy>,           // tier + max-duration matrix
}

#[derive(Clone, Debug)]
pub struct BlockIpRequest {
    pub addr:       IpAddr,
    pub reason:     String,                 // mandatory; rejected if empty
    pub duration:   Duration,
    pub authority:  AuthorityTier,
    pub source:     ActionSource,           // operator-cli | responder | autonomous
    pub idempotency_key: IdempotencyKey,    // selfdef-action-idempotency-key
}

#[async_trait]
impl Action for BlockIpAction { /* … */ }
```

The action implements `selfdef-action-lifecycle` (precondition →
plan → apply → witness → audit-emit → outcome-ledger). It MUST
participate in `selfdef-action-idempotency-key` so the same
{addr, reason, authority} pair produces the same ledger entry
rather than stacking duplicate rules.

### 3. Backend trait — `QuarantineBackend::block_ip`

Today `selfdef-quarantine-engine` carries process-level
quarantine. Extend its trait:

```rust
#[async_trait]
pub trait QuarantineBackend: Send + Sync {
    async fn quarantine_process(&self, …) -> Result<…>;
    async fn block_ip(
        &self,
        addr: IpAddr,
        duration: Duration,
        handle: BlockHandle,
    ) -> Result<BlockReceipt, BackendError>;
    async fn unblock_ip(&self, handle: BlockHandle)
        -> Result<UnblockReceipt, BackendError>;
}
```

Default implementation: **nftables `selfdef-blockset` set** owned
by selfdef-quarantine-engine, namespaced as `inet selfdef-blocks`
table. Rules:

```nftables
table inet selfdef-blocks {
  set v4 { type ipv4_addr; flags timeout; }
  set v6 { type ipv6_addr; flags timeout; }
  chain enforce {
    type filter hook input priority -100; policy accept;
    ip  saddr @v4 drop
    ip6 saddr @v6 drop
  }
}
```

The `flags timeout` enables kernel-level TTL — `duration` maps to
`add element` with `timeout <duration>`, so even if selfdefd
crashes, the block expires naturally. (Operator's "kernel does the
right thing if userland dies" principle.)

### 4. Authority + TTL matrix

| Authority tier        | Max duration | Requires operator confirmation? |
|-----------------------|--------------|---------------------------------|
| `autonomous`          | 5 min        | No (silent; audited)            |
| `responder`           | 1 hour       | No (correlated event chain)     |
| `operator`            | 24 hours     | No (operator initiated)         |
| `operator-overridden` | 720 hours    | Yes (`--confirm-extended`)      |

`autonomous` is the burst-response tier — selfdefd can act
without operator while a brute-force wave is ongoing, but the
block expires fast (5 min) so legitimate retries aren't punished
indefinitely. `responder` covers the correlator/responder chain
firing on event patterns (e.g., 30+ failed logins in 60s).
`operator` covers the CLI verb. The 30-day tier exists for known-
hostile ASNs and requires explicit confirmation.

This matrix is enforced via `selfdef-action-class-taxonomy` +
`selfdef-action-confirmation-tier`.

### 5. Audit + observability

Every block + unblock emits two records:

1. **Audit trail** via `selfdef-audit-log-writer`:
   ```json
   {
     "ts":     "2026-05-29T17:42:00Z",
     "action": "block_ip",
     "addr":   "203.0.113.42",
     "reason": "sshd brute force (auth-events correlated)",
     "duration_sec": 3600,
     "authority":    "responder",
     "source":       "selfdef-correlator",
     "handle":       "blk-2026-05-29-017",
     "outcome":      "applied"
   }
   ```
   Replicated to the audit-mirror via existing `selfdef-audit-mirror`
   plumbing — sovereign-os consumes read-only.

2. **textfile gauges** via a new wrapper
   `packaging/scripts/selfdef-blockset-textfile.sh` (would be the
   19th sibling observer, ~570s boot offset). Exposes:
   - `selfdef_blockset_v4_count`, `selfdef_blockset_v6_count`
   - `selfdef_blockset_actions_applied_total{authority=…}`
   - `selfdef_blockset_actions_rejected_total{reason=…}`
   - `selfdef_blockset_oldest_expiry_unix`

### 6. Operator UX (sovereign-os consumer side)

Per R10212 sovereign-os consumes — it does **not** call
`block-ip` directly. Operator UX surfaces are:

- **Dashboard panel** (sovereign-os Grafana, paired with the
  fail2ban dashboard): current block count, recent applies/release
  rate, top reasons, top source ASNs (if augmented).
- **Operator confirmation surface** (sovereign-os cockpit):
  pending responder-tier blocks awaiting operator-extended
  duration get surfaced as a queue; operator clicks "extend to
  24h" → cockpit shells `selfdefctl block-ip <addr>
  --duration 24h --authority operator-overridden` over an
  authenticated channel.
- **Alert rule** (sovereign-os Prometheus):
  `SelfdefBlocksetActionsRejectedSpike` — fires when reject rate
  > 10/min for 5m (operator misconfiguration OR adversary probing
  the authority matrix).

These are sovereign-os consumer surfaces; the enforcement primitive
itself stays in selfdef.

## Implementation order (5 milestones)

| MS | Slice | Cost |
|----|-------|------|
| 1  | `selfdef-quarantine-engine::block_ip` trait + nftables backend + unit tests | medium |
| 2  | `selfdef-responder::BlockIpAction` action + idempotency-key integration + audit-writer wiring | small |
| 3  | `selfdefctl block-ip` / `unblock-ip` CLI verbs in selfdef-api / selfdef-cli + completions | small |
| 4  | 19th sibling textfile observer + sovereign-os alert rules + Grafana panel | small (proven pattern) |
| 5  | Sovereign-os cockpit confirmation queue surface (operator UX) | medium |

Each milestone gets:
- A failing TDD test FIRST (L1 unit + L3 stage-acceptance).
- SDD spec line items checked off as implemented.
- Bash/L3 nspawn smoke that exercises real nftables in a
  throwaway netns.
- Audit-trail replay test in `selfdef-audit-registry`.

## Test contract

L1 (Cargo unit):
- BlockIpRequest validation (reason non-empty, duration <= tier
  max, idempotency-key stable).
- Authority-tier matrix enforcement.

L2 (integration):
- nftables backend round-trips a block + unblock in a netns.
- Audit-mirror sees the entries within 1 cycle.

L3 (stage-acceptance, nspawn):
- Full chain: simulated brute-force → correlator emits responder
  action → BlockIpAction fires → nftables set populated → TTL
  expires → kernel cleans set → audit chain intact.

L5 (operator):
- Cockpit confirmation queue presents the pending extend; operator
  click → block reaches 24h tier; audit shows operator-overridden
  authority.

## Open questions

- **IPv6 link-local handling.** Drop or allowlist by interface?
  Proposal: allowlist `fe80::/10` always (avoid breaking local
  link discovery); document in the implementation.
- **Concurrent CLI vs. autonomous race.** If operator runs
  `unblock-ip` while autonomous tier is mid-apply for the same
  IP — last-writer-wins? Proposal: idempotency key includes
  authority tier, so they are separate ledger entries; the
  effective rule is the union; unblock-ip releases the
  operator-tier handle but the autonomous-tier handle persists
  until its 5-min TTL.
- **Audit truncation.** With aggressive autonomous blocks the
  audit volume could be high. Existing `selfdef-audit-rotation-policy`
  applies, but should this action carry a per-tier digest
  (autonomous tier → 5-minute rollup instead of per-event)?
  Decision deferred to operator review.

## Standing-rule alignment

- **R10212 read-only doctrine:** enforcement lives in selfdef;
  sovereign-os consumes (dashboards, alerts, confirmation-queue
  UX shell). The cockpit invokes `selfdefctl`; it does NOT touch
  nftables directly.
- **"We do not minimize anything":** action carries full audit +
  observability + authority + idempotency + TTL — not a
  stripped-down "just call `nft add element`" shortcut.
- **"Cannot mark done if it hasn't reached Prod":** the
  acceptance criterion for this SDD is the 5-milestone slice
  landing on selfdef main AND being exercised in L3 in CI AND
  having operator UX in sovereign-os main.
