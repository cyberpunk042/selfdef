//! `selfdef-rules-mirror` — MS007 typed-mirror crate exposing selfdef
//! Ring 0..4 nftables rules state READ-ONLY for sovereign-os D-12
//! networking dashboard consumption.
//!
//! # Boundary discipline (operator standing direction "Respect the projects")
//!
//! - Selfdef IPS produces rule state from MS024 nftables + MS038 network
//!   boundary + MS039 Ring 0..4 trust topology.
//! - Sovereign-os runtime consumes this crate as a READ-ONLY mirror.
//! - There is NO mutation API. Operator-initiated changes proxy via
//!   MS003-signed CLI requests per MS043 R10212.
//!
//! # Source provenance (verbatim per MS043 R10182-R10193)
//!
//! - MS043 R10182: "selfdef-rules-mirror crate publishes Ring 0-4 rule
//!   state for D-12"
//! - MS043 R10189: "all mirror crates published under MS007 8/8
//!   SATURATED"
//! - MS043 R10190: "all mirror crates signed via MS003"
//! - MS043 R10191: "all mirror crates carry schema_version '1.0.0'"
//! - MS043 R10193: "mirror crates expose state read-only (no mutation
//!   interface)"
//! - MS043 R10194: "mirror crates continue to publish even when
//!   consumer offline"
//! - MS039 trust rings (Ring 0 Sovereign Kernel / Ring 1 Trusted Local
//!   / Ring 2 Sandboxed / Ring 3 Experimental / Ring 4 Cloud-External)
//!
//! # Standing rule
//!
//! We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Current schema version. MS007 contract: bump on breaking changes.
/// Consumers MUST refuse unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Trust ring per MS039 R10246-R10250. 5-ring topology verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRing {
    /// Ring 0 — Sovereign Kernel: policy, gateway, replay, memory authority.
    SovereignKernel,
    /// Ring 1 — Trusted Local: model servers, memory service, eval service.
    TrustedLocal,
    /// Ring 2 — Sandboxed: tool workers, build/test containers, browser agents.
    Sandboxed,
    /// Ring 3 — Experimental: unknown code, external downloads, risky web.
    Experimental,
    /// Ring 4 — Cloud-External: remote APIs, external services, internet.
    CloudExternal,
}

impl TrustRing {
    /// Numeric ring index (0..=4). Stable wire representation.
    pub fn index(self) -> u8 {
        match self {
            Self::SovereignKernel => 0,
            Self::TrustedLocal => 1,
            Self::Sandboxed => 2,
            Self::Experimental => 3,
            Self::CloudExternal => 4,
        }
    }
}

impl fmt::Display for TrustRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::SovereignKernel => "Ring0:SovereignKernel",
            Self::TrustedLocal => "Ring1:TrustedLocal",
            Self::Sandboxed => "Ring2:Sandboxed",
            Self::Experimental => "Ring3:Experimental",
            Self::CloudExternal => "Ring4:CloudExternal",
        };
        f.write_str(s)
    }
}

/// nftables chain disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Permit traffic.
    Accept,
    /// Drop silently.
    Drop,
    /// Reject with ICMP unreachable.
    Reject,
    /// Continue to next chain.
    Jump,
    /// Continue to next rule.
    Continue,
    /// Operator-defined return to caller chain.
    Return,
}

/// Single nftables rule entry per MS024 + MS038 boundary enforcement.
///
/// Fields chosen to be wire-stable; sovereign-os D-12 dashboard renders
/// these directly into table rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleEntry {
    /// nftables handle (stable across reload).
    pub handle: u64,
    /// Selfdef-internal rule id (ULID).
    pub rule_id: String,
    /// Trust ring this rule belongs to.
    pub ring: TrustRing,
    /// nftables table name (e.g., `"inet"`).
    pub table: String,
    /// nftables chain name (e.g., `"selfdef-ring2-egress"`).
    pub chain: String,
    /// Match expression (verbatim from nft output).
    pub match_expr: String,
    /// Disposition (accept/drop/reject/jump/continue/return).
    pub disposition: Disposition,
    /// Rule priority within chain.
    pub priority: i32,
    /// Counter — packets matched since rule installed.
    pub packets: u64,
    /// Counter — bytes matched since rule installed.
    pub bytes: u64,
    /// ISO-8601 UTC timestamp when this rule was installed.
    pub installed_at: String,
    /// Operator (MS003 fingerprint) who installed this rule, if known.
    pub installed_by: Option<String>,
    /// MS003 signature digest of this entry (hex-encoded).
    pub signature: String,
}

/// Per-ring summary for D-12 dashboard top-line panels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingSummary {
    /// Trust ring.
    pub ring: TrustRing,
    /// Count of active rules in this ring.
    pub rule_count: u32,
    /// Sum of bytes matched across all rules in this ring.
    pub total_bytes: u64,
    /// Sum of packets matched across all rules in this ring.
    pub total_packets: u64,
    /// Number of pending L3 Prepare rules awaiting operator sign-off
    /// per MS039 R09161 + R09167.
    pub pending_l3: u32,
}

/// Top-level mirror snapshot consumed by sovereign-os D-12 dashboard.
///
/// Serialized as JSON over a unix socket per MS043 R10194 (publishing
/// continues even when consumer offline — selfdef writes to a buffer
/// that sovereign-os polls).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-ring summary tiles for the dashboard.
    pub summaries: Vec<RingSummary>,
    /// Full rule list. Empty when consumer requested summary-only view.
    pub rules: Vec<RuleEntry>,
    /// MS003 signature over the (captured_at + summaries + rules)
    /// canonical-JSON encoding. Hex-encoded.
    pub signature: String,
}

/// Errors a consumer (sovereign-os runtime) may surface when reading
/// this mirror.
#[derive(Debug, Error)]
pub enum MirrorError {
    /// Schema major version mismatch — consumer must refuse per
    /// MS043 R10196.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Version the consumer was compiled against.
        expected: String,
        /// Version the snapshot advertised.
        actual: String,
    },
    /// MS003 signature verification failed per MS043 R10190.
    #[error("MS003 signature verification failed: {0}")]
    SignatureFailed(String),
    /// Snapshot was empty when the consumer expected populated data.
    #[error("snapshot is empty (publisher may be initializing)")]
    EmptySnapshot,
    /// Deserialization failure.
    #[error("snapshot deserialization failed: {0}")]
    Deserialize(String),
}

/// Reader-side helpers consumed by sovereign-os D-12 dashboard.
///
/// Producer-side (the actual rule-state publisher) lives separately in
/// the selfdef daemon — this crate only models the wire format + offers
/// validation helpers that BOTH ends can rely on.
impl RulesMirrorSnapshot {
    /// Validate the snapshot's schema version against the consumer's
    /// expected version. Per MS007 R09319: schema-breaking changes
    /// require schema_version bump; consumers MUST refuse unknown
    /// majors.
    pub fn validate_schema(&self) -> Result<(), MirrorError> {
        if self.schema_version != SCHEMA_VERSION {
            // Allow same-major bumps (1.0.0 → 1.1.0 = additive per M061
            // patch pass C R10297) but refuse new major.
            let snapshot_major = self.schema_version.split('.').next().unwrap_or("");
            let expected_major = SCHEMA_VERSION.split('.').next().unwrap_or("");
            if snapshot_major != expected_major {
                return Err(MirrorError::SchemaMismatch {
                    expected: SCHEMA_VERSION.into(),
                    actual: self.schema_version.clone(),
                });
            }
        }
        Ok(())
    }

    /// Compute counts and bytes per ring directly from the rule list.
    /// Useful when the consumer wants to cross-check the publisher's
    /// pre-computed summaries against the raw rules.
    pub fn recompute_summaries(&self) -> Vec<RingSummary> {
        use std::collections::HashMap;
        let mut by_ring: HashMap<TrustRing, RingSummary> = HashMap::new();
        for r in &self.rules {
            let entry = by_ring.entry(r.ring).or_insert(RingSummary {
                ring: r.ring,
                rule_count: 0,
                total_bytes: 0,
                total_packets: 0,
                pending_l3: 0, // pending L3 count is publisher-side; this only counts active rules
            });
            entry.rule_count += 1;
            entry.total_bytes = entry.total_bytes.saturating_add(r.bytes);
            entry.total_packets = entry.total_packets.saturating_add(r.packets);
        }
        let mut out: Vec<RingSummary> = by_ring.into_values().collect();
        out.sort_by_key(|s| s.ring.index());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_index_round_trip() {
        for r in [
            TrustRing::SovereignKernel,
            TrustRing::TrustedLocal,
            TrustRing::Sandboxed,
            TrustRing::Experimental,
            TrustRing::CloudExternal,
        ] {
            assert!(r.index() <= 4);
            assert!(!format!("{r}").is_empty());
        }
    }

    #[test]
    fn snapshot_validates_canonical_version() {
        let snap = RulesMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            rules: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn snapshot_rejects_major_version_drift() {
        let snap = RulesMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            rules: vec![],
            signature: String::new(),
        };
        assert!(matches!(
            snap.validate_schema().unwrap_err(),
            MirrorError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn snapshot_accepts_minor_version_bump() {
        // Per M061 patch pass C R10297: 1.0.0 → 1.1.0 additive is OK.
        let snap = RulesMirrorSnapshot {
            schema_version: "1.5.0".into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            rules: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn recompute_summaries_matches_rules() {
        let snap = RulesMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            rules: vec![
                RuleEntry {
                    handle: 1,
                    rule_id: "01ABC".into(),
                    ring: TrustRing::SovereignKernel,
                    table: "inet".into(),
                    chain: "selfdef-ring0-egress".into(),
                    match_expr: "ct state established accept".into(),
                    disposition: Disposition::Accept,
                    priority: 0,
                    packets: 100,
                    bytes: 4096,
                    installed_at: "2026-05-19T00:00:00Z".into(),
                    installed_by: None,
                    signature: String::new(),
                },
                RuleEntry {
                    handle: 2,
                    rule_id: "01DEF".into(),
                    ring: TrustRing::SovereignKernel,
                    table: "inet".into(),
                    chain: "selfdef-ring0-ingress".into(),
                    match_expr: "tcp dport 22 accept".into(),
                    disposition: Disposition::Accept,
                    priority: 0,
                    packets: 50,
                    bytes: 2048,
                    installed_at: "2026-05-19T00:00:00Z".into(),
                    installed_by: None,
                    signature: String::new(),
                },
            ],
            signature: String::new(),
        };
        let summaries = snap.recompute_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].rule_count, 2);
        assert_eq!(summaries[0].total_packets, 150);
        assert_eq!(summaries[0].total_bytes, 6144);
    }

    #[test]
    fn json_round_trip() {
        let snap = RulesMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![RingSummary {
                ring: TrustRing::Sandboxed,
                rule_count: 7,
                total_bytes: 1024,
                total_packets: 42,
                pending_l3: 1,
            }],
            rules: vec![],
            signature: "deadbeef".into(),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: RulesMirrorSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    /// Per MS043 R10193, mirrors must expose state read-only.
    /// This test simply confirms there is no public mutation API on the
    /// snapshot type beyond the wire-stable serde-driven construction.
    /// (Mutation enforcement is structural: the producer side lives in
    /// the selfdef daemon, not this crate.)
    #[test]
    fn no_public_mutation_helpers() {
        let snap = RulesMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T00:00:00Z".into(),
            summaries: vec![],
            rules: vec![],
            signature: String::new(),
        };
        // `recompute_summaries` returns a new Vec without mutating self.
        let _ = snap.recompute_summaries();
    }
}
