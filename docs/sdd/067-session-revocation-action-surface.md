# SDD-067 — Session revocation action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** Trio completion — SDD-065 (network perimeter,
IP-block) + SDD-066 (process boundary, freeze) +
SDD-067 (session boundary, this spec). The three together form
the operator's complete buy-time-then-decide IPS response trio:
"block them at the wire, freeze what's running, kill their
existing sessions."
**Pairs with:** SDD-065 (IP-block at perimeter), SDD-066 (process
freeze), SDD-049 (authority model), SDD-051 (policy bus),
auth-events 11th sibling observer (login-failure detection).

## Purpose

The trio's missing third action: **kill all active sessions for
a specific principal (user + optional source-IP scope), forcing
re-authentication**. This complements SDD-065/066:

- **SDD-065 IP-block** drops new packets from a hostile IP — but
  existing established connections from that IP keep running.
- **SDD-066 process-quarantine** freezes a specific known-bad
  pid — but the attacker may have spawned multiple shells.
- **SDD-067 session-revocation** terminates ALL of the
  principal's currently-active sessions: SSH (loginctl
  terminate-user / pkill matching), sudo grace tokens (rm
  /var/run/sudo/ts/<user>), systemd-user-runtime sessions
  (loginctl kill-session), web/API tokens (signal selfdef-api
  to revoke). Forces re-auth before the principal can take any
  further action.

Together: complete defense-in-depth across perimeter + process +
identity.

## Non-goals

- Not a permanent user-disable. SDD-067 terminates current
  sessions; the principal can still authenticate again. To
  permanently disable, operator uses standard `usermod -L` /
  `chage -E` outside selfdef.
- Not a password reset. Out of scope.
- Not a kerberos/realm-wide revocation. Host-local sessions only.

## Surface

### 1. CLI verbs — `selfdefctl revoke-sessions <user> [flags]`

```
selfdefctl revoke-sessions <user> --reason <text>
                           [--scope <local|source-ip>]
                           [--source-ip <addr>]   # required when scope=source-ip
                           [--duration <human>]   # the "stay revoked" window;
                                                  # default 30m; max 24h
                           [--authority <tier>]
                           [--dry-run]

selfdefctl restore-sessions <user-or-handle>
```

The "stay revoked" window is enforced via a deny-list entry
in selfdef-grant-registry (existing crate) keyed by user; the
PAM hook checks it on next auth attempt and refuses for the
duration. After the window expires, auth resumes normally.

Exit codes mirror SDD-065 §1 pattern.

### 2. Library surface — `selfdef-responder::RevokeSessionAction`

```rust
pub struct RevokeSessionAction {
    backend:   Arc<dyn SessionRevocationBackend>,
    audit:     Arc<dyn AuditWriter>,
    authority: AuthorityTier,
    duration:  Duration,
    scope:     RevocationScope,    // Local | SourceIp(IpAddr)
    reason_prefix: String,
}
```

Event-driven source-extraction: `event.actor.user.name`
(existing field in selfdef-core::observable::Actor) — Skipped
when absent.

### 3. Backend trait — `SessionRevocationBackend`

```rust
#[async_trait]
pub trait SessionRevocationBackend: Send + Sync {
    async fn revoke_sessions(
        &self, req: RevokeRequest,
    ) -> Result<RevokeReceipt, RevocationError>;
    async fn restore_sessions(
        &self, handle: RevocationHandle,
    ) -> Result<RestoreReceipt, RevocationError>;
    async fn pending_restores(&self) -> Vec<PendingRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &RevocationHandle) -> bool { false }
}
```

Production adapters (MS1b feature-gated):

- **`LoginctlBackend`** — invokes `loginctl terminate-user
  <user>` for systemd-logind sessions + `pkill -KILL -u
  <user>` for any non-logind shells + removes
  `/var/run/sudo/ts/<user>` sudo grace cache + appends a
  selfdef-grant-registry deny entry with the duration TTL.
- **`InMemoryBackend`** — hermetic test/CI substrate per
  MS1-substrate decision (info-hub
  `decisions/01_drafts/in-memory-backend-as-ms1-substrate.md`).

### 4. Authority + TTL matrix

| Authority tier        | Max revocation window |
|-----------------------|-----------------------|
| `autonomous`          | 1 min                 |
| `responder`           | 30 min                |
| `operator`            | 4 hours               |
| `operator-overridden` | 24 hours              |

Shorter than SDD-065/066 because session-revocation directly
affects the principal's ability to work; long windows risk
locking out the operator themselves if they trigger the rule
against their own account. 24h ceiling is absolute.

### 5. Audit + observability

Per-revoke audit envelope:

```json
{
  "ts":     "2026-05-29T19:00:00Z",
  "action": "revoke_sessions",
  "user":   "alice",
  "scope":  "local",
  "reason": "anomalous_sudo_pattern (responder)",
  "duration_sec": 1800,
  "authority":    "responder",
  "source":       "selfdef-correlator",
  "handle":       "rev-2026-05-29-001",
  "sessions_terminated": 3,
  "outcome":      "revoked"
}
```

Textfile gauges (new 21st sibling observer
`selfdef-revocations-textfile.sh`, OnBootSec=630s):

- `selfdef_revocations_active_count`
- `selfdef_revocations_pending_restores`
- `selfdef_revocations_handles_total`
- `selfdef_revocations_sessions_terminated_total{authority=…}`
- `selfdef_revocations_oldest_expiry_unix`
- `selfdef_revocations_last_run_unix`
- `selfdef_revocations_textfile_emit_failed`

### 6. Operator UX (sovereign-os consumer)

Reuse the paired-enforcement-primitive cockpit pattern:

- `scripts/cockpit/revocations-queue.py` — same shape as
  blockset-queue.py + quarantine-queue.py.
- `card_revocations_queue` in dashboard serve.py.
- New alert `SelfdefRevocationLongHeld` — fires when handle
  held > 12h.

### 7. Cross-action coordination — the IPS trio

When the correlator emits a high-severity attack verdict, all
three actions chain:

```
sshd-bf-2026-05-29-042
  - block:      203.0.113.42       (SDD-065, 32m left)
  - quarantine: pid 12345           (SDD-066, 14m left)
  - revoke:     alice               (SDD-067, 28m left)
  [ extend-block 24h ]  [ release-process ]  [ extend-revoke 4h ]
                                              [ restore-now ]
```

The cockpit row groups the three handles under one incident id
for paired-handle operator review.

## Implementation order (6 milestones — same pattern as SDD-065/066)

| MS | Slice | Depends on |
|----|-------|-----------|
| 1  | `selfdef-session-revocation-backend` — trait + InMemoryBackend + ~12 TDD tests | none |
| 1b | LoginctlBackend (feature `loginctl-backend`, needs CAP_KILL + write to /var/run/sudo) | MS1 |
| 2  | `selfdef-responder::RevokeSessionAction` + event.actor.user extraction | MS1 |
| 3  | `selfdefctl revoke-sessions / restore-sessions` CLI verbs | MS2 |
| 4  | 21st sibling observer + sovereign-os alerts + dashboard + observability-status vertical 21 | MS1 |
| 5  | MS5b cockpit consumer + paired-handle trio row | MS5b (SDD-065 + 066) |

## Test contract

Mirrors SDD-066's L1/L2/L3/L5 pattern.

## Open questions

- **Operator self-revoke safety.** If operator triggers a rule
  against their own account, autonomous-tier (1m) lets them
  recover quickly via the locally-attached console / serial.
  Should we add a hard exclusion list of "operator-essential"
  accounts (root + the operator's named account) that NO
  tier can revoke? Proposal: yes — config-driven via
  `/etc/selfdef/revocation-exclusions.toml`; default includes
  root + the user listed in `[deployment].operator_account`.
- **Web/API token revocation.** PAM only catches shell auth.
  How do we revoke selfdef-api / sovereign-os-cockpit tokens?
  Proposal: SDD-067 publishes a bus event
  `RevokeUserSessions{user, duration}`; selfdef-api +
  sovereign-os cockpit subscribe and drop tokens. Each web
  surface handles its own dispatch.
- **Login session vs sudo grace.** Treat as separate scopes?
  Proposal: keep unified for MS1; if operator wants
  finer-grained control later, add `--include sudo|ssh|api`
  flags in MS3.

## Standing-rule alignment

R10212 + "we do not minimize" + "cannot mark done if not in
Prod" — same alignment block as SDD-065/066.
