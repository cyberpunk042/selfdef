//! `selfdef-retention-policy` — 8 record-kinds, 8 retention windows.
//!
//! Each on-disk store the daemon writes to has a declared retention rule.
//! The pruner reads this policy at boot + before each prune cycle and
//! refuses to delete anything below the floor.
//!
//! Kinds (canonical 8):
//! - Audit         — MS016 chained audit records (Forever)
//! - Decision      — MS033 policy decisions (Days(365))
//! - Span          — M049 trace spans (Days(90))
//! - Quarantine    — collector quarantine ledger (Days(180))
//! - Evidence      — evidence ledger (Forever)
//! - TrustScore    — trust-score history (Days(365))
//! - CollectorEps  — sampled EPS time series (Days(30))
//! - ReplayBuffer  — replay JSONL ring (EventCount(1_000_000))
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 8 record kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKind {
    /// MS016 audit (hash-chained).
    Audit,
    /// MS033 policy decision.
    Decision,
    /// M049 trace span.
    Span,
    /// Collector quarantine ledger entry.
    Quarantine,
    /// Evidence ledger.
    Evidence,
    /// Trust-score sample.
    TrustScore,
    /// Sampled per-collector EPS.
    CollectorEps,
    /// Replay ring buffer.
    ReplayBuffer,
}

/// Retention rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum RetentionRule {
    /// Never prune.
    Forever,
    /// Keep records younger than N days.
    Days(u32),
    /// Keep at most N events (FIFO drop oldest).
    EventCount(u64),
    /// Keep at most N bytes (FIFO drop oldest).
    SizeBytes(u64),
}

/// Per-kind retention record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionRecord {
    /// Kind.
    pub kind: RecordKind,
    /// Rule.
    pub rule: RetentionRule,
}

/// Policy envelope — 8 records, one per kind.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 8 entries.
    pub records: Vec<RetentionRecord>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RetentionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 8.
    #[error("retention count {0} != 8 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing kind: {0:?}")]
    Missing(RecordKind),
    /// Zero is disallowed in Days / EventCount / SizeBytes (would delete everything).
    #[error("zero-valued rule for {0:?}")]
    ZeroValued(RecordKind),
}

impl RetentionPolicy {
    /// Canonical policy.
    pub fn canonical() -> Self {
        let records = vec![
            RetentionRecord {
                kind: RecordKind::Audit,
                rule: RetentionRule::Forever,
            },
            RetentionRecord {
                kind: RecordKind::Decision,
                rule: RetentionRule::Days(365),
            },
            RetentionRecord {
                kind: RecordKind::Span,
                rule: RetentionRule::Days(90),
            },
            RetentionRecord {
                kind: RecordKind::Quarantine,
                rule: RetentionRule::Days(180),
            },
            RetentionRecord {
                kind: RecordKind::Evidence,
                rule: RetentionRule::Forever,
            },
            RetentionRecord {
                kind: RecordKind::TrustScore,
                rule: RetentionRule::Days(365),
            },
            RetentionRecord {
                kind: RecordKind::CollectorEps,
                rule: RetentionRule::Days(30),
            },
            RetentionRecord {
                kind: RecordKind::ReplayBuffer,
                rule: RetentionRule::EventCount(1_000_000),
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            records,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RetentionError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RetentionError::SchemaMismatch);
        }
        if self.records.len() != 8 {
            return Err(RetentionError::CountInvalid(self.records.len()));
        }
        for k in [
            RecordKind::Audit,
            RecordKind::Decision,
            RecordKind::Span,
            RecordKind::Quarantine,
            RecordKind::Evidence,
            RecordKind::TrustScore,
            RecordKind::CollectorEps,
            RecordKind::ReplayBuffer,
        ] {
            if !self.records.iter().any(|r| r.kind == k) {
                return Err(RetentionError::Missing(k));
            }
        }
        for r in &self.records {
            match r.rule {
                RetentionRule::Days(0)
                | RetentionRule::EventCount(0)
                | RetentionRule::SizeBytes(0) => {
                    return Err(RetentionError::ZeroValued(r.kind));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Lookup by kind.
    pub fn get(&self, k: RecordKind) -> Option<&RetentionRule> {
        self.records.iter().find(|r| r.kind == k).map(|r| &r.rule)
    }

    /// Whether a record with given age_days should be retained under the policy.
    /// For Forever / EventCount / SizeBytes rules, always returns true here
    /// (those are evaluated by event/size pruners, not age pruners).
    pub fn retain_by_age(&self, kind: RecordKind, age_days: u32) -> bool {
        match self.get(kind) {
            Some(RetentionRule::Days(n)) => age_days < *n,
            Some(_) | None => true,
        }
    }

    /// Whether a kind is "forever" (never prune by age or count).
    pub fn is_forever(&self, kind: RecordKind) -> bool {
        matches!(self.get(kind), Some(RetentionRule::Forever))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        RetentionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn eight_kinds_present() {
        let p = RetentionPolicy::canonical();
        for k in [
            RecordKind::Audit,
            RecordKind::Decision,
            RecordKind::Span,
            RecordKind::Quarantine,
            RecordKind::Evidence,
            RecordKind::TrustScore,
            RecordKind::CollectorEps,
            RecordKind::ReplayBuffer,
        ] {
            assert!(p.get(k).is_some(), "missing {k:?}");
        }
    }

    #[test]
    fn audit_and_evidence_are_forever() {
        let p = RetentionPolicy::canonical();
        assert!(p.is_forever(RecordKind::Audit));
        assert!(p.is_forever(RecordKind::Evidence));
    }

    #[test]
    fn decision_retains_under_365_days() {
        let p = RetentionPolicy::canonical();
        assert!(p.retain_by_age(RecordKind::Decision, 100));
        assert!(p.retain_by_age(RecordKind::Decision, 364));
        assert!(!p.retain_by_age(RecordKind::Decision, 365));
        assert!(!p.retain_by_age(RecordKind::Decision, 1000));
    }

    #[test]
    fn span_retains_under_90_days() {
        let p = RetentionPolicy::canonical();
        assert!(p.retain_by_age(RecordKind::Span, 30));
        assert!(!p.retain_by_age(RecordKind::Span, 90));
    }

    #[test]
    fn forever_kind_always_retained() {
        let p = RetentionPolicy::canonical();
        // Audit is Forever — even age=10000 retains
        assert!(p.retain_by_age(RecordKind::Audit, 10_000));
    }

    #[test]
    fn replay_buffer_uses_event_count_not_days() {
        let p = RetentionPolicy::canonical();
        match p.get(RecordKind::ReplayBuffer) {
            Some(RetentionRule::EventCount(n)) => assert_eq!(*n, 1_000_000),
            other => panic!("unexpected rule: {other:?}"),
        }
        // age-based retain returns true (not the relevant axis)
        assert!(p.retain_by_age(RecordKind::ReplayBuffer, 10_000));
    }

    #[test]
    fn zero_valued_caught() {
        let mut p = RetentionPolicy::canonical();
        for r in p.records.iter_mut() {
            if r.kind == RecordKind::Span {
                r.rule = RetentionRule::Days(0);
            }
        }
        assert!(matches!(
            p.validate().unwrap_err(),
            RetentionError::ZeroValued(RecordKind::Span)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = RetentionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RetentionError::SchemaMismatch
        ));
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = RetentionPolicy::canonical();
        p.records.pop();
        assert!(matches!(
            p.validate().unwrap_err(),
            RetentionError::CountInvalid(7)
        ));
    }

    #[test]
    fn missing_kind_caught() {
        let mut p = RetentionPolicy::canonical();
        // Replace Span with a duplicate Audit → Span missing
        for r in p.records.iter_mut() {
            if r.kind == RecordKind::Span {
                r.kind = RecordKind::Audit;
                r.rule = RetentionRule::Forever;
            }
        }
        assert!(matches!(
            p.validate().unwrap_err(),
            RetentionError::Missing(RecordKind::Span)
        ));
    }

    #[test]
    fn rule_serde_tagged_kebab() {
        let r = RetentionRule::Days(90);
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"kind\":\"days\""));
        assert!(j.contains("\"value\":90"));
        let back: RetentionRule = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
        let f = RetentionRule::Forever;
        let jf = serde_json::to_string(&f).unwrap();
        assert!(jf.contains("\"kind\":\"forever\""));
    }

    #[test]
    fn kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&RecordKind::CollectorEps).unwrap(),
            "\"collector-eps\""
        );
        assert_eq!(
            serde_json::to_string(&RecordKind::ReplayBuffer).unwrap(),
            "\"replay-buffer\""
        );
        assert_eq!(
            serde_json::to_string(&RecordKind::TrustScore).unwrap(),
            "\"trust-score\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = RetentionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: RetentionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
