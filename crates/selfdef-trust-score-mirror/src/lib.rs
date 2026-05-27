//! `selfdef-trust-score-mirror` — MS007 typed-mirror crate exposing
//! per-tool trust score history READ-ONLY for sovereign-os D-18 trust
//! scores dashboard consumption.
//!
//! Per MS043 R10188 + R10193, mirrors expose state read-only; score
//! adjustments proxy via MS003-signed operator request only.
//!
//! Composes with:
//! - MS042 selfdef-tool-trust-score-tracker (M01095)
//! - M049 per-tool trust-score telemetry (R09999, R10039)
//! - MS040 six-profile authority matrix (profile evaluation reads trust score)
//! - MS027 Value Plane (trust delta feeds back into reward / branch criticality)
//!
//! Trust score is a 0..1000 fixed-point value:
//! - 1000 = baseline trust at first MS003-signed admission
//! - >= 800 = "trusted" (Tier A/B auto-approve eligible)
//! - 500..799 = "watched" (telemetry retained, profile-gated)
//! - 200..499 = "suspect" (escalated to Tier C/D, operator-ask)
//! - < 200 = "untrusted" (auto-quarantine, forfeit candidate)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version. Bump on breaking changes; consumers MUST refuse
/// unknown major versions.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Reason for a trust score delta. Mirrors the MS042 enforcement taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaReason {
    /// First successful MS003-signed admission (baseline +1000).
    Baseline,
    /// Successful execution without mismatch.
    SuccessfulExecution,
    /// MS042 declaration-vs-observed minor mismatch (-N).
    MismatchMinor,
    /// MS042 declaration-vs-observed major mismatch (-N).
    MismatchMajor,
    /// MS042 declaration-vs-observed critical mismatch (-N).
    MismatchCritical,
    /// Operator-signed manual adjustment.
    OperatorAdjustment,
    /// Decay over time (no usage).
    Decay,
    /// Recovery after operator-signed release from quarantine.
    QuarantineRelease,
    /// Forfeiture (score capped to 0).
    Forfeiture,
}

/// Coarse trust band per the score banding doctrine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustBand {
    /// >= 800. Tier A/B auto-approve eligible.
    Trusted,
    /// 500..=799. Telemetry retained, profile-gated.
    Watched,
    /// 200..=499. Operator-ask required, Tier C/D escalation.
    Suspect,
    /// < 200. Auto-quarantine, forfeiture candidate.
    Untrusted,
}

impl TrustBand {
    /// Map a 0..=1000 score to a band per the standing doctrine.
    pub fn for_score(score: u16) -> Self {
        match score {
            800..=1000 => TrustBand::Trusted,
            500..=799 => TrustBand::Watched,
            200..=499 => TrustBand::Suspect,
            _ => TrustBand::Untrusted,
        }
    }
}

/// Single trust-score delta entry. Wire-stable for D-18 spark-line history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaEntry {
    /// ISO-8601 UTC timestamp when delta was applied.
    pub applied_at: String,
    /// Reason for the delta.
    pub reason: DeltaReason,
    /// Signed delta amount (negative for penalties).
    pub delta: i32,
    /// Score AFTER the delta (cumulative).
    pub score_after: u16,
    /// M049 trace_id of the triggering event, if any.
    pub trace_id: String,
    /// MS003 signature over the delta envelope (hex).
    pub signature: String,
}

/// Per-tool trust score record. Wire-stable for D-18 rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolScoreEntry {
    /// Tool identifier (canonical name).
    pub tool: String,
    /// MS003 declarer fingerprint.
    pub declarer: String,
    /// Current score (0..=1000).
    pub current_score: u16,
    /// Computed trust band.
    pub band: TrustBand,
    /// ISO-8601 UTC of first admission.
    pub first_admitted_at: String,
    /// ISO-8601 UTC of last delta.
    pub last_delta_at: String,
    /// Count of all-time successful executions.
    pub executions_total: u32,
    /// Count of all-time mismatches.
    pub mismatches_total: u32,
    /// Score history (bounded tail; publisher truncates).
    pub history: Vec<DeltaEntry>,
    /// M049 trace_id of last execution.
    pub last_trace_id: String,
    /// MS003 signature over the tool record envelope (hex).
    pub signature: String,
}

/// Aggregate counts per band for D-18 top-line tiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BandSummary {
    /// Trust band.
    pub band: TrustBand,
    /// Count of tools currently in this band.
    pub count: u32,
    /// Mean score among tools in this band.
    pub mean_score: u16,
}

/// Top-level mirror snapshot consumed by sovereign-os D-18 dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustScoreMirrorSnapshot {
    /// Wire-stable schema version. MUST equal [`SCHEMA_VERSION`].
    pub schema_version: String,
    /// ISO-8601 UTC timestamp when snapshot was captured.
    pub captured_at: String,
    /// Per-band tiles.
    pub summaries: Vec<BandSummary>,
    /// Full per-tool entries.
    pub tools: Vec<ToolScoreEntry>,
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
    /// Score exceeds the 0..=1000 fixed-point range.
    #[error("score {0} outside valid range 0..=1000")]
    ScoreOutOfRange(u16),
    /// Reported band does not match score banding doctrine.
    #[error("band mismatch for score {score}: declared {declared:?}, expected {expected:?}")]
    BandMismatch {
        /// Score value.
        score: u16,
        /// Declared band on entry.
        declared: TrustBand,
        /// Doctrinal band from [`TrustBand::for_score`].
        expected: TrustBand,
    },
}

impl TrustScoreMirrorSnapshot {
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

    /// Validate all scores are within 0..=1000 and bands match doctrine.
    pub fn validate_scores(&self) -> Result<(), MirrorError> {
        for t in &self.tools {
            if t.current_score > 1000 {
                return Err(MirrorError::ScoreOutOfRange(t.current_score));
            }
            let expected = TrustBand::for_score(t.current_score);
            if t.band != expected {
                return Err(MirrorError::BandMismatch {
                    score: t.current_score,
                    declared: t.band,
                    expected,
                });
            }
            for h in &t.history {
                if h.score_after > 1000 {
                    return Err(MirrorError::ScoreOutOfRange(h.score_after));
                }
            }
        }
        Ok(())
    }

    /// Aggregate tools by current band.
    pub fn recompute_summaries(&self) -> Vec<BandSummary> {
        use std::collections::HashMap;
        let mut by_band: HashMap<TrustBand, (u64, u32)> = HashMap::new();
        for t in &self.tools {
            let e = by_band.entry(t.band).or_insert((0, 0));
            e.0 += t.current_score as u64;
            e.1 += 1;
        }
        let mut out: Vec<BandSummary> = by_band
            .into_iter()
            .map(|(band, (total, count))| BandSummary {
                band,
                count,
                mean_score: if count == 0 {
                    0
                } else {
                    (total / count as u64) as u16
                },
            })
            .collect();
        out.sort_by_key(|s| match s.band {
            TrustBand::Trusted => 0,
            TrustBand::Watched => 1,
            TrustBand::Suspect => 2,
            TrustBand::Untrusted => 3,
        });
        out
    }

    /// Find tools with downward trends (last 5 deltas summing negative).
    pub fn tools_trending_down(&self) -> Vec<&ToolScoreEntry> {
        self.tools
            .iter()
            .filter(|t| {
                let tail: Vec<&DeltaEntry> = t.history.iter().rev().take(5).collect();
                if tail.is_empty() {
                    return false;
                }
                let net: i32 = tail.iter().map(|d| d.delta).sum();
                net < 0
            })
            .collect()
    }

    /// Mean score across all tools.
    pub fn mean_score(&self) -> u16 {
        if self.tools.is_empty() {
            return 0;
        }
        let total: u64 = self.tools.iter().map(|t| t.current_score as u64).sum();
        (total / self.tools.len() as u64) as u16
    }

    /// Reliability ratio = successful executions / (executions + mismatches), per tool.
    pub fn reliability(t: &ToolScoreEntry) -> f64 {
        let total = t.executions_total + t.mismatches_total;
        if total == 0 {
            return 1.0;
        }
        t.executions_total as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_delta(at: &str, reason: DeltaReason, delta: i32, score_after: u16) -> DeltaEntry {
        DeltaEntry {
            applied_at: at.into(),
            reason,
            delta,
            score_after,
            trace_id: "trace-x".into(),
            signature: "sig-x".into(),
        }
    }
    fn mk_tool(name: &str, score: u16, history: Vec<DeltaEntry>) -> ToolScoreEntry {
        ToolScoreEntry {
            tool: name.into(),
            declarer: "operator-fp".into(),
            current_score: score,
            band: TrustBand::for_score(score),
            first_admitted_at: "2026-05-19T00:00:00Z".into(),
            last_delta_at: "2026-05-19T03:00:00Z".into(),
            executions_total: 100,
            mismatches_total: 2,
            history,
            last_trace_id: "trace-1".into(),
            signature: "sig-1".into(),
        }
    }

    #[test]
    fn band_thresholds_match_doctrine() {
        assert_eq!(TrustBand::for_score(1000), TrustBand::Trusted);
        assert_eq!(TrustBand::for_score(800), TrustBand::Trusted);
        assert_eq!(TrustBand::for_score(799), TrustBand::Watched);
        assert_eq!(TrustBand::for_score(500), TrustBand::Watched);
        assert_eq!(TrustBand::for_score(499), TrustBand::Suspect);
        assert_eq!(TrustBand::for_score(200), TrustBand::Suspect);
        assert_eq!(TrustBand::for_score(199), TrustBand::Untrusted);
        assert_eq!(TrustBand::for_score(0), TrustBand::Untrusted);
    }

    #[test]
    fn schema_validates_canonical() {
        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![],
            signature: String::new(),
        };
        snap.validate_schema().unwrap();
    }

    #[test]
    fn validate_scores_catches_out_of_range() {
        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![{
                let mut t = mk_tool("rg", 900, vec![]);
                t.current_score = 1500;
                t
            }],
            signature: String::new(),
        };
        assert!(matches!(
            snap.validate_scores().unwrap_err(),
            MirrorError::ScoreOutOfRange(1500)
        ));
    }

    #[test]
    fn validate_scores_catches_band_mismatch() {
        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![{
                let mut t = mk_tool("rg", 900, vec![]);
                t.band = TrustBand::Untrusted; // wrong! 900 should be Trusted
                t
            }],
            signature: String::new(),
        };
        match snap.validate_scores().unwrap_err() {
            MirrorError::BandMismatch {
                score,
                declared,
                expected,
            } => {
                assert_eq!(score, 900);
                assert_eq!(declared, TrustBand::Untrusted);
                assert_eq!(expected, TrustBand::Trusted);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn recompute_summaries_groups_by_band() {
        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![
                mk_tool("rg", 980, vec![]),
                mk_tool("rustc", 920, vec![]),
                mk_tool("cargo", 600, vec![]),
                mk_tool("browser", 350, vec![]),
                mk_tool("untrust", 50, vec![]),
            ],
            signature: String::new(),
        };
        let s = snap.recompute_summaries();
        let trusted = s.iter().find(|x| x.band == TrustBand::Trusted).unwrap();
        assert_eq!(trusted.count, 2);
        assert_eq!(trusted.mean_score, 950);
        let watched = s.iter().find(|x| x.band == TrustBand::Watched).unwrap();
        assert_eq!(watched.count, 1);
        assert_eq!(watched.mean_score, 600);
    }

    #[test]
    fn tools_trending_down_detects_net_negative_tail() {
        let downward = mk_tool(
            "flaky",
            600,
            vec![
                mk_delta("t0", DeltaReason::SuccessfulExecution, 5, 600),
                mk_delta("t1", DeltaReason::MismatchMinor, -10, 590),
                mk_delta("t2", DeltaReason::MismatchMinor, -10, 580),
                mk_delta("t3", DeltaReason::MismatchMajor, -50, 530),
                mk_delta("t4", DeltaReason::MismatchMinor, -10, 520),
            ],
        );
        let stable = mk_tool(
            "steady",
            900,
            vec![
                mk_delta("t0", DeltaReason::SuccessfulExecution, 1, 900),
                mk_delta("t1", DeltaReason::SuccessfulExecution, 1, 901),
                mk_delta("t2", DeltaReason::SuccessfulExecution, 1, 902),
            ],
        );
        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![downward, stable],
            signature: String::new(),
        };
        let down = snap.tools_trending_down();
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].tool, "flaky");
    }

    #[test]
    fn mean_score_handles_empty_and_populated() {
        let empty = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![],
            signature: String::new(),
        };
        assert_eq!(empty.mean_score(), 0);

        let snap = TrustScoreMirrorSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            captured_at: "2026-05-19T03:30:00Z".into(),
            summaries: vec![],
            tools: vec![mk_tool("a", 800, vec![]), mk_tool("b", 400, vec![])],
            signature: String::new(),
        };
        assert_eq!(snap.mean_score(), 600);
    }

    #[test]
    fn reliability_computes_ratio() {
        let mut t = mk_tool("rg", 900, vec![]);
        t.executions_total = 95;
        t.mismatches_total = 5;
        assert_eq!(TrustScoreMirrorSnapshot::reliability(&t), 0.95);
    }

    #[test]
    fn reliability_returns_1_when_no_history() {
        let mut t = mk_tool("fresh", 1000, vec![]);
        t.executions_total = 0;
        t.mismatches_total = 0;
        assert_eq!(TrustScoreMirrorSnapshot::reliability(&t), 1.0);
    }

    #[test]
    fn tool_serde_roundtrip() {
        let original = mk_tool(
            "rg",
            950,
            vec![
                mk_delta("t0", DeltaReason::Baseline, 1000, 1000),
                mk_delta("t1", DeltaReason::MismatchMinor, -50, 950),
            ],
        );
        let j = serde_json::to_string(&original).unwrap();
        let back: ToolScoreEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(original, back);
        assert_eq!(back.history.len(), 2);
        assert_eq!(back.history[1].delta, -50);
    }

    #[test]
    fn delta_reason_serde_uses_snake_case() {
        let j = serde_json::to_string(&DeltaReason::MismatchCritical).unwrap();
        assert_eq!(j, "\"mismatch_critical\"");
    }

    #[test]
    fn trust_band_serde_uses_snake_case() {
        let j = serde_json::to_string(&TrustBand::Untrusted).unwrap();
        assert_eq!(j, "\"untrusted\"");
    }
}
