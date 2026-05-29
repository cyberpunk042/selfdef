# SDD-069 — MFA-grant revocation action surface (selfdef enforcement layer)

**Status:** draft / architectural spec
**Author:** selfdef IPS authority chain
**Stems from:** Quartet → pentet expansion. The IPS-quartet
(SDD-065/066/067/068) covers network + process + shell-session +
API-token. SDD-069 adds the **MFA grant** identity-axis — when
the principal's 2FA token is suspected stolen or coerced, the
operator revokes the cached MFA grant so the principal must
re-MFA on next auth.
**Pairs with:** SDD-067 (shell session — together kills the
session AND requires fresh MFA before re-login). The combination
is incident-response gold: attacker can't re-use the principal's
session AND can't authenticate again without fresh MFA.

## Purpose

Operator-actionable revocation of cached MFA grants. Most systems
cache "MFA satisfied" tokens for some time after successful 2FA
(common: 24h browser cookie). When a principal's account shows
compromise indicators, the operator wants to:

1. Kill existing sessions (SDD-067 — already in prod).
2. **Force fresh MFA on next auth (SDD-069 — this spec).**

Without SDD-069, attacker can wait for the SDD-067 ban TTL, then
log in using the cached MFA grant from BEFORE the compromise
window. SDD-069 invalidates that cache, forcing fresh 2FA
challenge.

Grant surfaces under selfdef's authority:

- **PAM `pam_oath` grants** (TOTP/HOTP cache, `~/.oath_user`).
- **sshd `MaxAuthTries` MFA tokens** if `AuthenticationMethods`
  multi-step is configured.
- **selfdef-api MFA refresh tokens** (`/var/lib/selfdef/api/mfa-grants/`).
- **sovereign-os cockpit second-factor cookies** — subscribe-
  and-evict via bus event (same pattern as SDD-068 token surfaces).

## Non-goals

- Not a totp-secret rotation. That's a separate operator workflow.
- Not a hardware-key reset. Out of scope.
- Not a federation-wide MFA cache invalidation. Host-local only.

## Surface

### 1. CLI verbs

```
selfdefctl revoke-mfa-grant <principal> --reason <text>
                            [--duration <human>]   # default 30m; max 24h
                            [--authority <tier>]
                            [--grant-scope <pam|api|cockpit|all>]
                            [--dry-run]

selfdefctl restore-mfa-grant <principal-or-handle> [--force]
```

The `--grant-scope` flag scopes which MFA surface(s) the revocation
hits. `all` revokes across every participating surface.

### 2. Library — `selfdef-responder::MfaGrantRevocationAction`

Same Action-trait pattern. Extracts principal from
`event.actor.user.name`. Skipped when absent.

### 3. Backend trait — `MfaGrantRevocationBackend`

```rust
pub enum MfaGrantScope {
    All,
    Specific(Vec<MfaGrantSurface>), // Pam | Api | Cockpit
}

#[async_trait]
pub trait MfaGrantRevocationBackend: Send + Sync {
    async fn revoke_mfa_grants(
        &self, req: MfaGrantRevokeRequest,
    ) -> Result<MfaGrantRevokeReceipt, MfaGrantRevocationError>;
    async fn restore_mfa_grants(
        &self, handle: MfaGrantRevocationHandle,
    ) -> Result<MfaGrantRestoreReceipt, MfaGrantRevocationError>;
    async fn pending_restores(&self) -> Vec<PendingMfaGrantRestore> { Vec::new() }
    async fn mark_restore_decided(&self, _: &MfaGrantRevocationHandle) -> bool { false }
}
```

### 4. Authority + TTL matrix

| Authority tier        | Max revocation window |
|-----------------------|-----------------------|
| `autonomous`          | 5 min                 |
| `responder`           | 30 min                |
| `operator`            | 4 hours               |
| `operator-overridden` | 24 hours              |

Same ceilings as SDD-067 (both act on the identity axis with
similar lock-out risk profile).

### 5. Audit + observability

- 23rd sibling textfile observer `selfdef-mfa-grant-revocations-textfile.sh`
  (OnBootSec=690s).
- 6 canonical gauges (mirror of 22nd sibling pattern).

### 6. Operator UX

MS5b cockpit card `card_mfa_grant_revocations_queue` adjacent to
the four quartet cards — completes the **pentet-paired-handle
row**.

## Implementation order (6 milestones — same pattern)

| MS | Slice |
|----|-------|
| 1  | `selfdef-mfa-grant-revocation-backend` — trait + InMemoryBackend + ~12 TDD tests |
| 1b | PamGrantBackend (feature `pam-grant-backend`, removes ~/.oath_user) + ApiGrantBackend (feature `api-grant-backend`, walks /var/lib/selfdef/api/mfa-grants/) |
| 2  | `selfdef-responder::MfaGrantRevocationAction` |
| 3  | `selfdefctl revoke-mfa-grant / restore-mfa-grant` CLI verbs |
| 4  | 23rd sibling observer + sovereign-os alerts + dashboard #43 + obs-status vertical 23 |
| 5  | MS5b cockpit consumer + pentet-paired-handle row |

## Open questions

- **TOTP window leniency.** When MFA is revoked, does the next
  successful TOTP code require a fresh-after-revoke timestamp
  proof? Proposal: yes — the backend records `revoked_at`; PAM
  module checks `code_emitted_at > revoked_at` before accepting.
- **Hardware-key fallback path.** If principal has a YubiKey
  paired, does revocation also invalidate that or only TOTP?
  Proposal: TOTP only by default; `--include hardware-key`
  flag for explicit hardware-key invalidation (rare).
- **Revoke window vs. next-auth-time skew.** Operator revokes at
  T; principal had MFA-cached at T-1h; principal logs in at T+10m.
  Without SDD-069, cache allows entry. With SDD-069, cache
  rejects. Document that the revocation effect is immediate, not
  retroactive — past auths stand, future auths require fresh MFA.

## Standing-rule alignment

R10212 + "we do not minimize" + "cannot mark done if not in Prod" —
same as SDD-065/066/067/068.
