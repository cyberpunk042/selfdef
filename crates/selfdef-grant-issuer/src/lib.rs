//! `selfdef-grant-issuer` — companion engine to selfdef-grants-mirror.
//!
//! Per MS035 + MS037 + MS038 + R09175 (default 60s TTL ceiling).
//!
//! Given a signed operator request the engine returns a typed grant
//! that the daemon then applies to the relevant boundary enforcement
//! layer. Refuses unsigned requests, over-TTL requests, and empty-scope
//! requests.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::{GrantEntry, GrantKind, GrantState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Default TTL ceiling per R09175 dump 3175 — 60 seconds for first-issue grants.
pub const DEFAULT_TTL_SECONDS: u32 = 60;

/// Hard upper bound — 86400 seconds (24h) per MS040 R09407 / MS038 ceiling.
pub const MAX_TTL_SECONDS: u32 = 86_400;

/// One operator-signed grant request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRequest {
    /// Grant kind requested.
    pub kind: GrantKind,
    /// Scope (path glob / FQDN / CIDR / capability tag).
    pub scope: String,
    /// Operator-authored reason.
    pub reason: String,
    /// Profile at request time.
    pub profile: String,
    /// Requesting actor MS003 fingerprint.
    pub actor: String,
    /// Desired TTL in seconds.
    pub ttl_seconds: u32,
    /// MS003 signature over the canonical-JSON request.
    pub signature: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IssueError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Signature missing.
    #[error("request unsigned (MS003 signature required)")]
    Unsigned,
    /// Scope empty.
    #[error("scope empty")]
    EmptyScope,
    /// Reason empty (R09657).
    #[error("reason empty (R09657 non-empty requirement)")]
    EmptyReason,
    /// Actor empty.
    #[error("actor empty")]
    EmptyActor,
    /// Profile empty.
    #[error("profile empty")]
    EmptyProfile,
    /// TTL above ceiling.
    #[error("ttl {0}s above {1}s ceiling")]
    TtlAboveCeiling(u32, u32),
    /// TTL zero.
    #[error("ttl=0 not allowed (grants must have non-zero lifetime)")]
    TtlZero,
}

/// Issue a grant from a signed request. Sets state to Pending; caller
/// is responsible for transitioning to Active after the underlying
/// boundary applier succeeds.
pub fn issue(
    req: &GrantRequest,
    grant_id: &str,
    issued_at: &str,
    expires_at: &str,
    trace_id: &str,
) -> Result<GrantEntry, IssueError> {
    if req.signature.is_empty() {
        return Err(IssueError::Unsigned);
    }
    if req.scope.is_empty() { return Err(IssueError::EmptyScope); }
    if req.reason.is_empty() { return Err(IssueError::EmptyReason); }
    if req.actor.is_empty() { return Err(IssueError::EmptyActor); }
    if req.profile.is_empty() { return Err(IssueError::EmptyProfile); }
    if req.ttl_seconds == 0 { return Err(IssueError::TtlZero); }
    if req.ttl_seconds > MAX_TTL_SECONDS {
        return Err(IssueError::TtlAboveCeiling(req.ttl_seconds, MAX_TTL_SECONDS));
    }
    Ok(GrantEntry {
        grant_id: grant_id.into(),
        kind: req.kind,
        scope: req.scope.clone(),
        reason: req.reason.clone(),
        issued_at: issued_at.into(),
        expires_at: expires_at.into(),
        ttl_seconds: req.ttl_seconds,
        profile: req.profile.clone(),
        actor: req.actor.clone(),
        state: GrantState::Pending,
        trace_id: trace_id.into(),
        signature: req.signature.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_req() -> GrantRequest {
        GrantRequest {
            kind: GrantKind::Filesystem,
            scope: "/workspace/**".into(),
            reason: "ship feature X".into(),
            profile: "careful".into(),
            actor: "operator-fp".into(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn ok_request_issues_pending() {
        let g = issue(&ok_req(), "gr-001", "2026-05-19T03:00:00Z", "2026-05-19T04:00:00Z", "trace-001").unwrap();
        assert_eq!(g.grant_id, "gr-001");
        assert_eq!(g.state, GrantState::Pending);
        assert_eq!(g.ttl_seconds, 3600);
    }

    #[test]
    fn unsigned_rejected() {
        let mut r = ok_req();
        r.signature = String::new();
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::Unsigned));
    }

    #[test]
    fn empty_scope_rejected() {
        let mut r = ok_req();
        r.scope = String::new();
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::EmptyScope));
    }

    #[test]
    fn empty_reason_rejected() {
        let mut r = ok_req();
        r.reason = String::new();
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::EmptyReason));
    }

    #[test]
    fn empty_actor_rejected() {
        let mut r = ok_req();
        r.actor = String::new();
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::EmptyActor));
    }

    #[test]
    fn empty_profile_rejected() {
        let mut r = ok_req();
        r.profile = String::new();
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::EmptyProfile));
    }

    #[test]
    fn zero_ttl_rejected() {
        let mut r = ok_req();
        r.ttl_seconds = 0;
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::TtlZero));
    }

    #[test]
    fn ttl_above_ceiling_rejected() {
        let mut r = ok_req();
        r.ttl_seconds = 100_000;
        assert!(matches!(issue(&r, "g", "t", "t", "tr").unwrap_err(), IssueError::TtlAboveCeiling(100_000, 86_400)));
    }

    #[test]
    fn ceiling_constants_per_doctrine() {
        assert_eq!(DEFAULT_TTL_SECONDS, 60);  // R09175
        assert_eq!(MAX_TTL_SECONDS, 86_400);  // R09407 / MS038
    }

    #[test]
    fn all_5_grant_kinds_can_issue() {
        for k in [
            GrantKind::Filesystem, GrantKind::Network, GrantKind::Capability,
            GrantKind::Communication, GrantKind::Sandbox,
        ] {
            let mut r = ok_req();
            r.kind = k;
            assert!(issue(&r, "g", "t", "t", "tr").is_ok());
        }
    }

    #[test]
    fn grant_request_serde_roundtrip() {
        let r = ok_req();
        let j = serde_json::to_string(&r).unwrap();
        let back: GrantRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
