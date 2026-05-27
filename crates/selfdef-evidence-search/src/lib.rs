//! `selfdef-evidence-search` — tag + subject + time-range filter.
//!
//! Each `EvidenceRow` is a free-standing row (tag, subject, summary,
//! at). The search takes a `Query` (optional tag, optional subject,
//! optional from/to ISO-8601 strings) and returns matching rows up
//! to `max_hits`.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_evidence_tag::EvidenceTag;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One evidence row (compact view).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRow {
    /// Tag.
    pub tag: EvidenceTag,
    /// Subject id.
    pub subject: String,
    /// Operator-readable summary.
    pub summary: String,
    /// ISO-8601 UTC.
    pub at: String,
}

/// Search query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    /// Optional tag filter.
    pub tag: Option<EvidenceTag>,
    /// Optional subject filter.
    pub subject: Option<String>,
    /// Inclusive from (ISO-8601).
    pub from: Option<String>,
    /// Exclusive to (ISO-8601).
    pub to: Option<String>,
    /// Max hits.
    pub max_hits: u32,
}

/// Search index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSearchIndex {
    /// Schema version.
    pub schema_version: String,
    /// Rows.
    pub rows: Vec<EvidenceRow>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SearchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_hits zero.
    #[error("max_hits zero")]
    ZeroMaxHits,
    /// from > to.
    #[error("from {from} > to {to}")]
    BadRange {
        /// from.
        from: String,
        /// to.
        to: String,
    },
}

impl EvidenceSearchIndex {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            rows: Vec::new(),
        }
    }

    /// Add a row.
    pub fn push(&mut self, row: EvidenceRow) {
        self.rows.push(row);
    }

    /// Run query.
    pub fn search(&self, q: &Query) -> Result<Vec<&EvidenceRow>, SearchError> {
        if q.max_hits == 0 {
            return Err(SearchError::ZeroMaxHits);
        }
        if let (Some(f), Some(t)) = (&q.from, &q.to) {
            if t < f {
                return Err(SearchError::BadRange {
                    from: f.clone(),
                    to: t.clone(),
                });
            }
        }
        let mut hits = Vec::new();
        for r in &self.rows {
            if let Some(tag) = q.tag {
                if r.tag != tag {
                    continue;
                }
            }
            if let Some(subject) = &q.subject {
                if &r.subject != subject {
                    continue;
                }
            }
            if let Some(f) = &q.from {
                if &r.at < f {
                    continue;
                }
            }
            if let Some(t) = &q.to {
                if &r.at >= t {
                    continue;
                }
            }
            hits.push(r);
            if hits.len() as u32 >= q.max_hits {
                break;
            }
        }
        Ok(hits)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), SearchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SearchError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for EvidenceSearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(tag: EvidenceTag, subject: &str, at: &str) -> EvidenceRow {
        EvidenceRow {
            tag,
            subject: subject.into(),
            summary: String::new(),
            at: at.into(),
        }
    }

    fn ix() -> EvidenceSearchIndex {
        let mut i = EvidenceSearchIndex::new();
        i.push(row(EvidenceTag::Decision, "alice", "2026-05-19T01:00:00Z"));
        i.push(row(EvidenceTag::Grant, "bob", "2026-05-19T02:00:00Z"));
        i.push(row(EvidenceTag::Decision, "alice", "2026-05-19T03:00:00Z"));
        i.push(row(
            EvidenceTag::Quarantine,
            "alice",
            "2026-05-19T04:00:00Z",
        ));
        i.push(row(EvidenceTag::Promotion, "bob", "2026-05-19T05:00:00Z"));
        i
    }

    #[test]
    fn no_filters_returns_all() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: None,
                subject: None,
                from: None,
                to: None,
                max_hits: 10,
            })
            .unwrap();
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn tag_filter() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: Some(EvidenceTag::Decision),
                subject: None,
                from: None,
                to: None,
                max_hits: 10,
            })
            .unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn subject_filter() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: None,
                subject: Some("alice".into()),
                from: None,
                to: None,
                max_hits: 10,
            })
            .unwrap();
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn time_range_filter() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: None,
                subject: None,
                from: Some("2026-05-19T02:00:00Z".into()),
                to: Some("2026-05-19T04:00:00Z".into()),
                max_hits: 10,
            })
            .unwrap();
        // 02:00 included, 03:00 included, 04:00 excluded
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn combined_filter() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: Some(EvidenceTag::Decision),
                subject: Some("alice".into()),
                from: None,
                to: None,
                max_hits: 10,
            })
            .unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn max_hits_caps() {
        let i = ix();
        let r = i
            .search(&Query {
                tag: None,
                subject: None,
                from: None,
                to: None,
                max_hits: 2,
            })
            .unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn zero_max_hits_rejected() {
        let i = ix();
        let err = i
            .search(&Query {
                tag: None,
                subject: None,
                from: None,
                to: None,
                max_hits: 0,
            })
            .unwrap_err();
        assert!(matches!(err, SearchError::ZeroMaxHits));
    }

    #[test]
    fn inverted_range_rejected() {
        let i = ix();
        let err = i
            .search(&Query {
                tag: None,
                subject: None,
                from: Some("2026-05-19T05:00:00Z".into()),
                to: Some("2026-05-19T01:00:00Z".into()),
                max_hits: 10,
            })
            .unwrap_err();
        assert!(matches!(err, SearchError::BadRange { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut i = EvidenceSearchIndex::new();
        i.schema_version = "9.9.9".into();
        assert!(matches!(
            i.validate().unwrap_err(),
            SearchError::SchemaMismatch
        ));
    }

    #[test]
    fn index_serde_roundtrip() {
        let i = ix();
        let j = serde_json::to_string(&i).unwrap();
        let back: EvidenceSearchIndex = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }
}
