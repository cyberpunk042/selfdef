//! `selfdef-capability-mirror` — MS007 typed-mirror crate exposing
//! selfdef capability_word token state READ-ONLY for sovereign-os D-14
//! capability-tokens dashboard consumption.
//!
//! Per MS043 R10184 + R10193, mirrors expose state read-only; mutations
//! proxy via MS003-signed operator request only.
//!
//! capability_word is a 64-bit handle per MS035 R08219 carrying:
//! - identity bits (operator MS003 fingerprint hash)
//! - scope bits (allowed tools / sandbox tier / network egress / fs reach)
//! - trust bits (Ring 0..4 per MS039)
//! - lifecycle bits (TTL window, parent-child inheritance per F04146)
//!
//! Composes with:
//! - MS035 capability tokens (issuance + revocation)
//! - MS034 communication boundary (8 message types carry capability_word)
//! - MS036 tool sandboxes (allowed-tools bits + sandbox-tier dim)
//! - MS039 authority levels L0..L6 (mapped to trust bits)
//! - MS040 six profiles (private/fast/careful/autonomous/experimental/production)
//! - MS049 13-field span (capability_word logged in every TraceEvent)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Token lifecycle state. Mirror of MS035 R09103 token state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenState {
    /// Operator-signed request received, not yet issued.
    Pending,
    /// Issued + active. Decrements toward TTL expiry.
    Active,
    /// TTL exceeded; receipt retained per MS035 R09110.
    Expired,
    /// Operator explicitly revoked before TTL.
    Revoked,
    /// Quarantined per MS042 declaration-vs-observed mismatch.
    Quarantined,
}

/// Trust ring assignment per MS039 R09430 Ring 0..4 topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRing {
    /// Ring 0 — kernel-equivalent (selfdef daemon only).
    Ring0,
    /// Ring 1 — Guardian + audit (signed binaries, no operator-CLI).
    Ring1,
    /// Ring 2 — operator-signed CLI surface.
    Ring2,
    /// Ring 3 — sandboxed agent.
    Ring3,
    /// Ring 4 — untrusted / quarantined.
    Ring4,
}

/// Authority level per MS039 R09413 L0..L6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityLevel {
    /// L0 Observe — read state, no side effects.
    L0Observe,
    /// L1 Suggest — produce candidate, no apply.
    L1Suggest,
    /// L2 Simulate — dry-run with side-effect equivalence.
    L2Simulate,
    /// L3 Prepare — stage durable change, await L4+.
    L3Prepare,
    /// L4 Execute — apply ephemeral side effect.
    L4Execute,
    /// L5 Commit — apply durable change.
    L5Commit,
    /// L6 Persist — change survives reboot + replication.
    L6Persist,
}

/// Single capability token entry. Wire-stable for D-14 rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEntry {
    /// Selfdef-internal token id (ULID).
    pub token_id: String,
    /// 64-bit capability_word per MS035 R08219, hex-encoded.
    pub capability_word: String,
    /// Operator MS003 fingerprint who issued (hex).
    pub actor: String,
    /// Active profile at issuance time (MS040).
    pub profile: String,
    /// Trust ring assignment.
    pub trust_ring: TrustRing,
    /// Highest authority level minted into this token.
    pub authority_level: AuthorityLevel,
    /// Allowed tool names per the allowed-tools bit field.
    /// Wire-stable expansion of capability_word's tool bits.
    pub allowed_tools: Vec<String>,
    /// Sandbox tier (MS036 A/B/C/D) authorized by this token.
    pub sandbox_tier: String,
    /// ISO-8601 UTC issuance timestamp.
    pub issued_at: String,
    /// ISO-8601 UTC expiry timestamp (TTL bound).
    pub expires_at: String,
    /// TTL in seconds at issuance.
    pub ttl_seconds: u32,
    /// Current lifecycle state.
    pub state: TokenState,
    /// M049 trace_id reference per F04144.
    pub trace_id: String,
    /// Parent capability token id for inheritance per F04146.
    /// Empty when this is a root token.
    pub parent_token_id: String,
    /// MS003 signature over the token envelope (hex).
    pub signature: String,
}

/// Aggregate counts per trust ring, suitable for D-14 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingSummary {
    /// Trust ring.
    pub ring: TrustRing,
    /// Count of tokens currently active in this ring.
    pub active: u32,
    /// Count of tokens pending in this ring.
    pub pending: u32,
    /// Count of tokens expired in this ring in the last 24h.
    pub expired_24h: u32,
    /// Count of tokens revoked in this ring in the last 24h.
    pub revoked_24h: u32,
    /// Count of tokens quarantined in this ring.
    pub quarantined: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os D-14 dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-ring tiles.
    pub summaries: Vec<RingSummary>,
    /// Full token list (may be empty if consumer requested summary).
    pub tokens: Vec<CapabilityEntry>,
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

impl CapabilityMirrorSnapshot {
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

    /// Aggregate tokens by trust ring. Read-only cross-check helper.
    pub fn recompute_summaries(&self) -> Vec<RingSummary> {
        use std::collections::HashMap;
        let mut by_ring: HashMap<TrustRing, RingSummary> = HashMap::new();
        for t in &self.tokens {
            let entry = by_ring.entry(t.trust_ring).or_insert(RingSummary {
                ring: t.trust_ring,
                active: 0,
                pending: 0,
                expired_24h: 0,
                revoked_24h: 0,
                quarantined: 0,
            });
            match t.state {
                TokenState::Active => entry.active += 1,
                TokenState::Pending => entry.pending += 1,
                TokenState::Expired => entry.expired_24h += 1,
                TokenState::Revoked => entry.revoked_24h += 1,
                TokenState::Quarantined => entry.quarantined += 1,
            }
        }
        let mut out: Vec<RingSummary> = by_ring.into_values().collect();
        out.sort_by_key(|s| match s.ring {
            TrustRing::Ring0 => 0,
            TrustRing::Ring1 => 1,
            TrustRing::Ring2 => 2,
            TrustRing::Ring3 => 3,
            TrustRing::Ring4 => 4,
        });
        out
    }

    /// Count of tokens currently active across all rings.
    pub fn active_count(&self) -> usize {
        self.tokens.iter().filter(|t| t.state == TokenState::Active).count()
    }

    /// Count of tokens needing operator attention (pending or quarantined).
    pub fn attention_count(&self) -> usize {
        self.tokens.iter()
            .filter(|t| matches!(t.state, TokenState::Pending | TokenState::Quarantined))
            .count()
    }

    /// Build a parent-child token map for inheritance audit per F04146.
    /// Returns map from parent_token_id to list of child token_ids.
    pub fn inheritance_map(&self) -> std::collections::HashMap<String, Vec<String>> {
        use std::collections::HashMap;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for t in &self.tokens {
            if !t.parent_token_id.is_empty() {
                map.entry(t.parent_token_id.clone())
                    .or_default()
                    .push(t.token_id.clone());
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_token(id: &str, ring: TrustRing, state: TokenState) -> CapabilityEntry {
        CapabilityEntry {
            token_id: id.into(),
            capability_word: format!("0x{:016x}", id.len() as u64),
            actor: "operator-fp".into(),
            profile: "private".into(),
            trust_ring: ring,
            authority_level: AuthorityLevel::L4Execute,
            allowed_tools: vec!["fs.read".into(), "net.egress".into()],
            sandbox_tier: "B".into(),
            issued_at: "2026-05-19T00:00:00Z".into(),
            expires_at: "2026-05-19T01:00:00Z".into(),
            ttl_seconds: 3600,
            state,
            trace_id: format!("trace-{id}"),
            parent_token_id: String::new(),
            signature: format!("sig-{id}"),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![],
            signature: String::new(),
        };
        assert!(matches!(snap.validate_schema().unwrap_err(), MirrorError::SchemaMismatch { .. }));
    }

    #[test]
    fn schema_accepts_minor_bump() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: "1.7.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn recompute_summaries_groups_by_ring() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![
                mk_token("a", TrustRing::Ring0, TokenState::Active),
                mk_token("b", TrustRing::Ring0, TokenState::Active),
                mk_token("c", TrustRing::Ring2, TokenState::Pending),
                mk_token("d", TrustRing::Ring3, TokenState::Quarantined),
            ],
            signature: String::new(),
        };
        let summaries = snap.recompute_summaries();
        assert_eq!(summaries.len(), 3);
        let ring0 = summaries.iter().find(|s| s.ring == TrustRing::Ring0).unwrap();
        assert_eq!(ring0.active, 2);
        let ring2 = summaries.iter().find(|s| s.ring == TrustRing::Ring2).unwrap();
        assert_eq!(ring2.pending, 1);
        let ring3 = summaries.iter().find(|s| s.ring == TrustRing::Ring3).unwrap();
        assert_eq!(ring3.quarantined, 1);
    }

    #[test]
    fn active_count_filters_state() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![
                mk_token("a", TrustRing::Ring2, TokenState::Active),
                mk_token("b", TrustRing::Ring2, TokenState::Expired),
                mk_token("c", TrustRing::Ring2, TokenState::Active),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.active_count(), 2);
    }

    #[test]
    fn attention_count_includes_pending_and_quarantined() {
        let snap = CapabilityMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![
                mk_token("a", TrustRing::Ring2, TokenState::Pending),
                mk_token("b", TrustRing::Ring2, TokenState::Active),
                mk_token("c", TrustRing::Ring3, TokenState::Quarantined),
                mk_token("d", TrustRing::Ring4, TokenState::Revoked),
            ],
            signature: String::new(),
        };
        assert_eq!(snap.attention_count(), 2);
    }

    #[test]
    fn inheritance_map_builds_parent_child_graph() {
        let mut parent = mk_token("root", TrustRing::Ring2, TokenState::Active);
        parent.parent_token_id = String::new();
        let mut child1 = mk_token("c1", TrustRing::Ring3, TokenState::Active);
        child1.parent_token_id = "root".into();
        let mut child2 = mk_token("c2", TrustRing::Ring3, TokenState::Active);
        child2.parent_token_id = "root".into();
        let snap = CapabilityMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            tokens: vec![parent, child1, child2],
            signature: String::new(),
        };
        let map = snap.inheritance_map();
        assert_eq!(map.len(), 1);
        assert_eq!(map["root"].len(), 2);
    }

    #[test]
    fn roundtrip_serde_preserves_fields() {
        let original = mk_token("alpha", TrustRing::Ring1, TokenState::Active);
        let j = serde_json::to_string(&original).unwrap();
        let back: CapabilityEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn token_state_serde_uses_snake_case() {
        let j = serde_json::to_string(&TokenState::Quarantined).unwrap();
        assert_eq!(j, "\"quarantined\"");
    }

    #[test]
    fn trust_ring_serde_uses_snake_case() {
        let j = serde_json::to_string(&TrustRing::Ring0).unwrap();
        assert_eq!(j, "\"ring0\"");
    }

    #[test]
    fn authority_level_serde_uses_snake_case() {
        let j = serde_json::to_string(&AuthorityLevel::L5Commit).unwrap();
        assert_eq!(j, "\"l5_commit\"");
    }
}
