//! `selfdef-audit-mirror` — MS007 typed-mirror crate exposing
//! selfdef audit chain status (MS009/MS033) + M049 13-field span +
//! MS026 OCSF 16-event taxonomy READ-ONLY for sovereign-os D-16 audit
//! cycles + D-19 super-model manifest dashboards.
//!
//! Per MS043 R10186 + R10193, mirrors expose state read-only; mutations
//! proxy via MS003-signed operator request only.
//!
//! Composes with:
//! - MS009 audit cycles (doctrine + chain integrity)
//! - MS033 Phase 3 policy + trace (7-step model-call template, 5-step tool-call template)
//! - M049 13-field span schema (profile/model/provider/hardware/tokens/latency/cost/risk/memory_refs/tool_refs/policy_result/branch_id/trace_id) per R07722
//! - MS026 OCSF 16-event taxonomy (1001 process, 1003 file, 2004 network, 4001 host, 5001 authority)
//! - MS016 atomic ZFS audit log (chain-head hash + per-event SHA-256 of prev)
//! - MS003 operator signature (envelope-level verification)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// MS026 OCSF event category. 16-event taxonomy per R07810.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcsfCategory {
    /// 1001 — process activity (exec/fork/exit).
    ProcessActivity,
    /// 1003 — file system activity (open/read/write/unlink).
    FileSystemActivity,
    /// 2004 — network activity (connect/accept/dns).
    NetworkActivity,
    /// 4001 — host inventory (hardware/topology change).
    HostInventory,
    /// 5001 — authority decision (allow/deny/ask/sandbox per MS033 R07731-R07734).
    AuthorityDecision,
    /// Other OCSF category outside the 5 selfdef-canonical buckets.
    Other,
}

/// MS033 4-state policy decision outcome per R07731-R07734.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Decision: allow (action proceeds).
    Allow,
    /// Decision: deny (action blocked).
    Deny,
    /// Decision: ask operator (queued for D-06 pending approvals).
    Ask,
    /// Decision: sandbox (action escalates into MS036 tier sandbox).
    Sandbox,
}

/// Single 13-field span entry per M049 R07722. Wire-stable for D-16/D-19.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanEntry {
    /// Field 1 — trace_id (ULID).
    pub trace_id: String,
    /// Field 2 — profile name at span time (MS040).
    pub profile: String,
    /// Field 3 — model identifier (Trinity Pulse/Weaver/Auditor or external).
    pub model: String,
    /// Field 4 — provider (local-rocm / local-cuda / cloud-openai / cloud-anthropic).
    pub provider: String,
    /// Field 5 — hardware target (cpu_pulse / rocm_logic / blackwell_oracle / 3090_logic).
    pub hardware: String,
    /// Field 6 — token counts (prompt + completion).
    pub tokens_prompt: u32,
    /// Field 6b — token counts (completion).
    pub tokens_completion: u32,
    /// Field 7 — latency total milliseconds (start → end).
    pub latency_ms: u32,
    /// Field 8 — cost in USD millicents (1/1000 USD).
    pub cost_millicents: u32,
    /// Field 9 — risk score (0..100 from MS027 Value Plane).
    pub risk_score: u8,
    /// Field 10 — memory references (M028 memory item ids).
    pub memory_refs: Vec<String>,
    /// Field 11 — tool references (MS035 capability_word entries).
    pub tool_refs: Vec<String>,
    /// Field 12 — policy result.
    pub policy_result: PolicyOutcome,
    /// Field 13 — branch_id (M027 value-plane branch).
    pub branch_id: String,
    /// MS026 OCSF taxonomy category.
    pub ocsf_category: OcsfCategory,
    /// ISO-8601 UTC timestamp when span closed.
    pub closed_at: String,
    /// SHA-256 hash of previous chain entry per MS016 (hex).
    pub prev_chain_hash: String,
    /// SHA-256 hash of this entry (hex). Becomes prev for next.
    pub chain_hash: String,
    /// MS003 signature over canonical-JSON encoding (hex).
    pub signature: String,
}

/// Aggregate counts by OCSF category for D-16/D-19 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategorySummary {
    /// OCSF category.
    pub category: OcsfCategory,
    /// Total spans in this category in window.
    pub total: u32,
    /// Total allow outcomes.
    pub allow: u32,
    /// Total deny outcomes.
    pub deny: u32,
    /// Total ask outcomes (operator queue).
    pub ask: u32,
    /// Total sandbox outcomes.
    pub sandbox: u32,
}

/// Chain integrity report. Surfaces tampering or gaps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainIntegrityReport {
    /// Most recent chain_hash on disk (atomic ZFS audit log head).
    pub head_hash: String,
    /// Total chain length (entries since genesis).
    pub total_entries: u64,
    /// True if every entry's prev_chain_hash matches the prior entry's chain_hash.
    pub continuous: bool,
    /// Index of first detected discontinuity, if any.
    pub first_gap_at: Option<u64>,
    /// ISO-8601 UTC of last integrity verification.
    pub verified_at: String,
}

/// Top-level mirror snapshot consumed by D-16 + D-19 dashboards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-category tiles.
    pub summaries: Vec<CategorySummary>,
    /// Chain integrity report.
    pub integrity: ChainIntegrityReport,
    /// Span tail (most recent spans, dashboard-friendly bounded list).
    pub spans: Vec<SpanEntry>,
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
    /// Chain integrity broken (discontinuity in prev_chain_hash linkage).
    #[error("audit chain broken at index {0}")]
    ChainBroken(u64),
}

impl AuditMirrorSnapshot {
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

    /// Re-verify chain continuity across the embedded span tail.
    /// Returns Ok if every consecutive pair links correctly, or
    /// Err(ChainBroken) at the first gap (0-indexed within `spans`).
    pub fn verify_chain_continuity(&self) -> Result<(), MirrorError> {
        for (i, window) in self.spans.windows(2).enumerate() {
            let prev = &window[0];
            let next = &window[1];
            if next.prev_chain_hash != prev.chain_hash {
                return Err(MirrorError::ChainBroken((i + 1) as u64));
            }
        }
        Ok(())
    }

    /// Aggregate spans by OCSF category. Read-only cross-check helper.
    pub fn recompute_summaries(&self) -> Vec<CategorySummary> {
        use std::collections::HashMap;
        let mut by_cat: HashMap<OcsfCategory, CategorySummary> = HashMap::new();
        for s in &self.spans {
            let entry = by_cat.entry(s.ocsf_category).or_insert(CategorySummary {
                category: s.ocsf_category,
                total: 0,
                allow: 0,
                deny: 0,
                ask: 0,
                sandbox: 0,
            });
            entry.total += 1;
            match s.policy_result {
                PolicyOutcome::Allow => entry.allow += 1,
                PolicyOutcome::Deny => entry.deny += 1,
                PolicyOutcome::Ask => entry.ask += 1,
                PolicyOutcome::Sandbox => entry.sandbox += 1,
            }
        }
        let mut out: Vec<CategorySummary> = by_cat.into_values().collect();
        out.sort_by_key(|s| match s.category {
            OcsfCategory::ProcessActivity => 0,
            OcsfCategory::FileSystemActivity => 1,
            OcsfCategory::NetworkActivity => 2,
            OcsfCategory::HostInventory => 3,
            OcsfCategory::AuthorityDecision => 4,
            OcsfCategory::Other => 5,
        });
        out
    }

    /// Sum total token cost in millicents across the span tail.
    pub fn total_cost_millicents(&self) -> u64 {
        self.spans.iter().map(|s| s.cost_millicents as u64).sum()
    }

    /// Mean latency across spans, in milliseconds (0 if empty).
    pub fn mean_latency_ms(&self) -> u32 {
        if self.spans.is_empty() {
            return 0;
        }
        let total: u64 = self.spans.iter().map(|s| s.latency_ms as u64).sum();
        (total / self.spans.len() as u64) as u32
    }

    /// Count spans by policy outcome (sum across all categories).
    pub fn outcome_counts(&self) -> (u32, u32, u32, u32) {
        let mut a = 0u32;
        let mut d = 0u32;
        let mut k = 0u32;
        let mut x = 0u32;
        for s in &self.spans {
            match s.policy_result {
                PolicyOutcome::Allow => a += 1,
                PolicyOutcome::Deny => d += 1,
                PolicyOutcome::Ask => k += 1,
                PolicyOutcome::Sandbox => x += 1,
            }
        }
        (a, d, k, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_span(
        trace: &str,
        cat: OcsfCategory,
        out: PolicyOutcome,
        prev: &str,
        hash: &str,
    ) -> SpanEntry {
        SpanEntry {
            trace_id: trace.into(),
            profile: "private".into(),
            model: "claude-opus".into(),
            provider: "cloud-anthropic".into(),
            hardware: "blackwell_oracle".into(),
            tokens_prompt: 1200,
            tokens_completion: 800,
            latency_ms: 1400,
            cost_millicents: 25,
            risk_score: 12,
            memory_refs: vec!["mem-a".into(), "mem-b".into()],
            tool_refs: vec!["fs.read".into()],
            policy_result: out,
            branch_id: "branch-main".into(),
            ocsf_category: cat,
            closed_at: "2026-05-19T03:30:00Z".into(),
            prev_chain_hash: prev.into(),
            chain_hash: hash.into(),
            signature: format!("sig-{trace}"),
        }
    }

    fn mk_integrity() -> ChainIntegrityReport {
        ChainIntegrityReport {
            head_hash: "0xdeadbeef".into(),
            total_entries: 1_234_567,
            continuous: true,
            first_gap_at: None,
            verified_at: "2026-05-19T03:30:00Z".into(),
        }
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn schema_rejects_major_drift() {
        let snap = AuditMirrorSnapshot {
            schema_version: "2.0.0".into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![],
            signature: String::new(),
        };
        assert!(matches!(
            snap.validate_schema().unwrap_err(),
            MirrorError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn chain_continuity_passes_when_linked() {
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![
                mk_span(
                    "t1",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Allow,
                    "0x00",
                    "0xaa",
                ),
                mk_span(
                    "t2",
                    OcsfCategory::FileSystemActivity,
                    PolicyOutcome::Allow,
                    "0xaa",
                    "0xbb",
                ),
                mk_span(
                    "t3",
                    OcsfCategory::NetworkActivity,
                    PolicyOutcome::Sandbox,
                    "0xbb",
                    "0xcc",
                ),
            ],
            signature: String::new(),
        };
        snap.verify_chain_continuity().unwrap();
    }

    #[test]
    fn chain_continuity_detects_gap() {
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![
                mk_span(
                    "t1",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Allow,
                    "0x00",
                    "0xaa",
                ),
                mk_span(
                    "t2",
                    OcsfCategory::FileSystemActivity,
                    PolicyOutcome::Allow,
                    "WRONG",
                    "0xbb",
                ),
            ],
            signature: String::new(),
        };
        match snap.verify_chain_continuity().unwrap_err() {
            MirrorError::ChainBroken(idx) => assert_eq!(idx, 1),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn recompute_summaries_groups_by_category() {
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![
                mk_span(
                    "t1",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Allow,
                    "0x00",
                    "0xaa",
                ),
                mk_span(
                    "t2",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Deny,
                    "0xaa",
                    "0xbb",
                ),
                mk_span(
                    "t3",
                    OcsfCategory::NetworkActivity,
                    PolicyOutcome::Ask,
                    "0xbb",
                    "0xcc",
                ),
                mk_span(
                    "t4",
                    OcsfCategory::AuthorityDecision,
                    PolicyOutcome::Sandbox,
                    "0xcc",
                    "0xdd",
                ),
            ],
            signature: String::new(),
        };
        let s = snap.recompute_summaries();
        assert_eq!(s.len(), 3);
        let proc = s
            .iter()
            .find(|x| x.category == OcsfCategory::ProcessActivity)
            .unwrap();
        assert_eq!(proc.total, 2);
        assert_eq!(proc.allow, 1);
        assert_eq!(proc.deny, 1);
        let net = s
            .iter()
            .find(|x| x.category == OcsfCategory::NetworkActivity)
            .unwrap();
        assert_eq!(net.ask, 1);
    }

    #[test]
    fn outcome_counts_returns_all_four() {
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![
                mk_span(
                    "t1",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Allow,
                    "0x00",
                    "0xaa",
                ),
                mk_span(
                    "t2",
                    OcsfCategory::ProcessActivity,
                    PolicyOutcome::Allow,
                    "0xaa",
                    "0xbb",
                ),
                mk_span(
                    "t3",
                    OcsfCategory::NetworkActivity,
                    PolicyOutcome::Deny,
                    "0xbb",
                    "0xcc",
                ),
                mk_span(
                    "t4",
                    OcsfCategory::FileSystemActivity,
                    PolicyOutcome::Ask,
                    "0xcc",
                    "0xdd",
                ),
                mk_span(
                    "t5",
                    OcsfCategory::AuthorityDecision,
                    PolicyOutcome::Sandbox,
                    "0xdd",
                    "0xee",
                ),
            ],
            signature: String::new(),
        };
        let (a, d, k, x) = snap.outcome_counts();
        assert_eq!((a, d, k, x), (2, 1, 1, 1));
    }

    #[test]
    fn total_cost_sums() {
        let mut s1 = mk_span(
            "t1",
            OcsfCategory::ProcessActivity,
            PolicyOutcome::Allow,
            "0x00",
            "0xaa",
        );
        s1.cost_millicents = 100;
        let mut s2 = mk_span(
            "t2",
            OcsfCategory::ProcessActivity,
            PolicyOutcome::Allow,
            "0xaa",
            "0xbb",
        );
        s2.cost_millicents = 250;
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![s1, s2],
            signature: String::new(),
        };
        assert_eq!(snap.total_cost_millicents(), 350);
    }

    #[test]
    fn mean_latency_handles_empty_and_populated() {
        let empty = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![],
            signature: String::new(),
        };
        assert_eq!(empty.mean_latency_ms(), 0);

        let mut s1 = mk_span(
            "t1",
            OcsfCategory::ProcessActivity,
            PolicyOutcome::Allow,
            "0x00",
            "0xaa",
        );
        s1.latency_ms = 100;
        let mut s2 = mk_span(
            "t2",
            OcsfCategory::ProcessActivity,
            PolicyOutcome::Allow,
            "0xaa",
            "0xbb",
        );
        s2.latency_ms = 300;
        let snap = AuditMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            integrity: mk_integrity(),
            spans: vec![s1, s2],
            signature: String::new(),
        };
        assert_eq!(snap.mean_latency_ms(), 200);
    }

    #[test]
    fn span_serde_roundtrip_preserves_13_fields() {
        let original = mk_span(
            "alpha",
            OcsfCategory::AuthorityDecision,
            PolicyOutcome::Sandbox,
            "0xff",
            "0xee",
        );
        let j = serde_json::to_string(&original).unwrap();
        let back: SpanEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        // Field-level checks per M049 R07722 13-field span
        assert_eq!(back.tokens_prompt, 1200);
        assert_eq!(back.memory_refs.len(), 2);
        assert_eq!(back.tool_refs.len(), 1);
        assert_eq!(back.ocsf_category, OcsfCategory::AuthorityDecision);
        assert_eq!(back.policy_result, PolicyOutcome::Sandbox);
    }

    #[test]
    fn ocsf_category_serde_uses_snake_case() {
        let j = serde_json::to_string(&OcsfCategory::FileSystemActivity).unwrap();
        assert_eq!(j, "\"file_system_activity\"");
    }

    #[test]
    fn policy_outcome_serde_uses_snake_case() {
        let j = serde_json::to_string(&PolicyOutcome::Sandbox).unwrap();
        assert_eq!(j, "\"sandbox\"");
    }
}
