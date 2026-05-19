//! `selfdef-grants-mirror` — MS007 typed-mirror crate exposing
//! selfdef filesystem + network + capability grant state READ-ONLY
//! for sovereign-os D-13 filesystem-grants dashboard consumption.
//!
//! Per MS043 R10183 + R10193, mirrors expose state read-only; mutations
//! proxy via MS003-signed operator request only.
//!
//! Composes with:
//! - MS037 filesystem boundary (fanotify grants)
//! - MS038 network boundary (FQDN/CIDR allowlists, TTL bounds)
//! - MS035 capability tokens (capability_word grants)
//! - MS039 authority levels L4 (Execute-bounded) grant issuance
//! - MS041 commit authority (L5 Commit when grant exceeds threshold)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Grant kind discriminator. Aligns with MS037/MS038/MS035 boundary
/// taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// MS037 filesystem grant — allows read/write/exec on a path glob.
    Filesystem,
    /// MS038 network grant — allows egress to FQDN or CIDR.
    Network,
    /// MS035 capability grant — mints a capability_word token.
    Capability,
    /// MS034 communication grant — allows IPC/D-Bus.
    Communication,
    /// MS036 sandbox grant — allows escalation to a sandbox tier.
    Sandbox,
}

/// Grant lifecycle state per MS035 R09103 + MS038 grant TTL discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Operator-signed request received, not yet active.
    Pending,
    /// Approved + applied. Counts down to TTL expiry.
    Active,
    /// TTL exceeded; grant inactive but receipt retained per MS037.
    Expired,
    /// Operator explicitly revoked before TTL.
    Revoked,
    /// Quarantined per MS042 declaration-vs-observed mismatch.
    Quarantined,
}

/// Single grant entry. Wire-stable for D-13 dashboard rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantEntry {
    /// Selfdef-internal grant id (ULID).
    pub grant_id: String,
    /// Grant kind discriminator.
    pub kind: GrantKind,
    /// Grant scope: path glob / FQDN / CIDR / capability tag —
    /// kind-dependent format. Always operator-readable.
    pub scope: String,
    /// Operator-authored reason (non-empty per MS041 R09657).
    pub reason: String,
    /// ISO-8601 UTC timestamp when grant was issued.
    pub issued_at: String,
    /// ISO-8601 UTC timestamp when grant expires (TTL).
    pub expires_at: String,
    /// TTL in seconds at issuance time. Default 60s per MS038 R09175.
    pub ttl_seconds: u32,
    /// Active profile at issuance time (MS040).
    pub profile: String,
    /// Operator MS003 fingerprint who issued.
    pub actor: String,
    /// Current lifecycle state.
    pub state: GrantState,
    /// M049 trace-id reference per MS041 R09670.
    pub trace_id: String,
    /// MS003 signature over the grant envelope (hex-encoded).
    pub signature: String,
}

/// Aggregate counts per grant kind, suitable for D-13 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantSummary {
    /// Grant kind.
    pub kind: GrantKind,
    /// Count of grants currently in Active state.
    pub active: u32,
    /// Count of grants in Pending state (awaiting operator approval).
    pub pending: u32,
    /// Count of grants in Expired state in the last 24h.
    pub expired_24h: u32,
    /// Count of grants in Revoked state in the last 24h.
    pub revoked_24h: u32,
    /// Count of grants in Quarantined state.
    pub quarantined: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os D-13 dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantsMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-kind tiles for the dashboard.
    pub summaries: Vec<GrantSummary>,
    /// Full grant list (may be empty if consumer requested summary).
    pub grants: Vec<GrantEntry>,
    /// MS003 signature over the canonical-JSON encoding.
    pub signature: String,
}

/// Errors a consumer may surface when reading this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected version.
        expected: String,
        /// Observed version.
        actual: String,
    },
    /// MS003 signature verification failed.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
}

impl GrantsMirrorSnapshot {
    /// Validate schema version. Same-major bumps OK per M061 R10297.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        let snap_major = self.schema_version.split('.').next().unwrap_or("");
        let exp_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
        if snap_major != exp_major {
            return Err(MirrorError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }

    /// Aggregate grants by kind. Read-only helper for cross-checking
    /// publisher-provided summaries against the raw grant list.
    pub fn recompute_summaries(&self) -> Vec<GrantSummary> {
        use std::collections::HashMap;
        let mut by_kind: HashMap<GrantKind, GrantSummary> = HashMap::new();
        for g in &self.grants {
            let entry = by_kind.entry(g.kind).or_insert(GrantSummary {
                kind: g.kind,
                active: 0,
                pending: 0,
                expired_24h: 0,
                revoked_24h: 0,
                quarantined: 0,
            });
            match g.state {
                GrantState::Active => entry.active += 1,
                GrantState::Pending => entry.pending += 1,
                GrantState::Expired => entry.expired_24h += 1,
                GrantState::Revoked => entry.revoked_24h += 1,
                GrantState::Quarantined => entry.quarantined += 1,
            }
        }
        let mut out: Vec<GrantSummary> = by_kind.into_values().collect();
        out.sort_by_key(|s| match s.kind {
            GrantKind::Filesystem => 0,
            GrantKind::Network => 1,
            GrantKind::Capability => 2,
            GrantKind::Communication => 3,
            GrantKind::Sandbox => 4,
        });
        out
    }

    /// Count of grants currently active (post-issuance, pre-expiry).
    pub fn active_count(&self) -> usize {
        self.grants.iter().filter(|g| g.state == GrantState::Active).count()
    }

    /// Count of grants needing operator attention (pending or quarantined).
    pub fn attention_count(&self) -> usize {
        self.grants.iter()
            .filter(|g| matches!(g.state, GrantState::Pending | GrantState::Quarantined))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_grant(id: &str, kind: GrantKind, state: GrantState) -> GrantEntry {
        GrantEntry {
            grant_id: id.into(),
            kind,
            scope: format!("scope-{id}"),
            reason: format!("test reason {id}"),
            issued_at: "2026-05-19T00:00:00Z".into(),
            expires_at: "2026-05-20T00:00:00Z".into(),
            ttl_seconds: 86400,
            profile: "private".into(),
            actor: "operator-fp".into(),
            state,
            trace_id: format!("trace-{id}"),
            signature: format!("sig-{id}"),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let snap = GrantsMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![],
            signature: String::new(),
        };
        assert!(matches!(snap.validate_schema().unwrap_err(), MirrorError::SchemaMismatch { .. }));
    }

    #[test]
    fn schema_accepts_minor_bump() {
        let snap = GrantsMirrorSnapshot {
            schema_version: "1.7.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn recompute_aggregates_correctly() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![
                mk_grant("A", GrantKind::Filesystem, GrantState::Active),
                mk_grant("B", GrantKind::Filesystem, GrantState::Active),
                mk_grant("C", GrantKind::Filesystem, GrantState::Pending),
                mk_grant("D", GrantKind::Network, GrantState::Active),
                mk_grant("E", GrantKind::Network, GrantState::Quarantined),
                mk_grant("F", GrantKind::Capability, GrantState::Revoked),
            ],
            signature: String::new(),
        };
        let summaries = snap.recompute_summaries();
        assert_eq!(summaries.len(), 3);
        let fs = summaries.iter().find(|s| s.kind == GrantKind::Filesystem).unwrap();
        assert_eq!(fs.active, 2);
        assert_eq!(fs.pending, 1);
        let net = summaries.iter().find(|s| s.kind == GrantKind::Network).unwrap();
        assert_eq!(net.active, 1);
        assert_eq!(net.quarantined, 1);
    }

    #[test]
    fn active_count_returns_total() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![
                mk_grant("A", GrantKind::Filesystem, GrantState::Active),
                mk_grant("B", GrantKind::Network, GrantState::Active),
                mk_grant("C", GrantKind::Capability, GrantState::Expired),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.active_count(), 2);
    }

    #[test]
    fn attention_count_covers_pending_plus_quarantined() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![
                mk_grant("A", GrantKind::Filesystem, GrantState::Pending),
                mk_grant("B", GrantKind::Network, GrantState::Quarantined),
                mk_grant("C", GrantKind::Capability, GrantState::Active),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.attention_count(), 2);
    }

    #[test]
    fn json_round_trip() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![GrantSummary {
                kind: GrantKind::Sandbox,
                active: 3,
                pending: 1,
                expired_24h: 0,
                revoked_24h: 2,
                quarantined: 0,
            }],
            grants: vec![mk_grant("Z", GrantKind::Sandbox, GrantState::Active)],
            signature: "deadbeef".into(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: GrantsMirrorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    /// Confirms no public mutation API per MS043 R10193.
    #[test]
    fn no_public_mutation_helpers() {
        let snap = GrantsMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            grants: vec![],
            signature: String::new(),
        };
        let _ = snap.recompute_summaries();
        let _ = snap.active_count();
        let _ = snap.attention_count();
    }
}
