//! `selfdef-grant-coverage-summary` — per-(actor × kind) coverage rollup.
//!
//! Given a list of `GrantEntry`s from `selfdef-grants-mirror`, produces:
//! - `by_actor`: counts of active grants per actor
//! - `by_kind`: counts of active grants per GrantKind
//! - `earliest_expiry`: earliest ISO-8601 expiration across all active
//!
//! Only `GrantState::Active` grants count toward coverage.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::{GrantEntry, GrantKind, GrantState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Coverage summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageSummary {
    /// Schema version.
    pub schema_version: String,
    /// Counts keyed by actor MS003 fingerprint.
    pub by_actor: BTreeMap<String, u32>,
    /// Counts keyed by GrantKind (as string for serde compatibility).
    pub by_kind: BTreeMap<String, u32>,
    /// ISO-8601 of earliest expiration (empty if no active grants).
    pub earliest_expiry: String,
    /// Total active grants.
    pub total_active: u32,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CoverageError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

fn kind_key(k: GrantKind) -> &'static str {
    match k {
        GrantKind::Filesystem => "filesystem",
        GrantKind::Network => "network",
        GrantKind::Capability => "capability",
        GrantKind::Communication => "communication",
        GrantKind::Sandbox => "sandbox",
    }
}

impl CoverageSummary {
    /// Build a summary from grant entries.
    pub fn build(entries: &[GrantEntry]) -> Self {
        let mut by_actor: BTreeMap<String, u32> = BTreeMap::new();
        let mut by_kind: BTreeMap<String, u32> = BTreeMap::new();
        let mut earliest: Option<&str> = None;
        let mut total = 0u32;
        for e in entries {
            if e.state != GrantState::Active { continue; }
            total += 1;
            *by_actor.entry(e.actor.clone()).or_insert(0) += 1;
            *by_kind.entry(kind_key(e.kind).into()).or_insert(0) += 1;
            match earliest {
                None => earliest = Some(&e.expires_at),
                Some(cur) if e.expires_at.as_str() < cur => earliest = Some(&e.expires_at),
                _ => {}
            }
        }
        Self {
            schema_version: SCHEMA_VERSION.into(),
            by_actor, by_kind,
            earliest_expiry: earliest.unwrap_or("").into(),
            total_active: total,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), CoverageError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(CoverageError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(actor: &str, kind: GrantKind, state: GrantState, expires_at: &str) -> GrantEntry {
        GrantEntry {
            grant_id: "g".into(),
            kind,
            scope: "/x".into(),
            reason: "need".into(),
            issued_at: "2026-05-19T00:00:00Z".into(),
            expires_at: expires_at.into(),
            ttl_seconds: 60,
            profile: "careful".into(),
            actor: actor.into(),
            state,
            trace_id: "tr".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn empty_input_produces_empty_summary() {
        let s = CoverageSummary::build(&[]);
        assert_eq!(s.total_active, 0);
        assert!(s.by_actor.is_empty());
        assert!(s.by_kind.is_empty());
        assert_eq!(s.earliest_expiry, "");
        s.validate().unwrap();
    }

    #[test]
    fn counts_active_only() {
        let entries = vec![
            entry("alice", GrantKind::Filesystem, GrantState::Active, "2026-05-19T01:00:00Z"),
            entry("alice", GrantKind::Network, GrantState::Active, "2026-05-19T02:00:00Z"),
            entry("alice", GrantKind::Filesystem, GrantState::Expired, "2026-05-19T03:00:00Z"),
            entry("bob", GrantKind::Capability, GrantState::Revoked, "2026-05-19T04:00:00Z"),
            entry("bob", GrantKind::Sandbox, GrantState::Active, "2026-05-19T05:00:00Z"),
        ];
        let s = CoverageSummary::build(&entries);
        assert_eq!(s.total_active, 3);
        assert_eq!(s.by_actor["alice"], 2);
        assert_eq!(s.by_actor["bob"], 1);
        assert_eq!(s.by_kind["filesystem"], 1);
        assert_eq!(s.by_kind["network"], 1);
        assert_eq!(s.by_kind["sandbox"], 1);
    }

    #[test]
    fn earliest_expiry_picked_min() {
        let entries = vec![
            entry("a", GrantKind::Filesystem, GrantState::Active, "2026-05-19T05:00:00Z"),
            entry("a", GrantKind::Network, GrantState::Active, "2026-05-19T01:00:00Z"),
            entry("a", GrantKind::Sandbox, GrantState::Active, "2026-05-19T03:00:00Z"),
        ];
        let s = CoverageSummary::build(&entries);
        assert_eq!(s.earliest_expiry, "2026-05-19T01:00:00Z");
    }

    #[test]
    fn all_inactive_no_earliest() {
        let entries = vec![
            entry("a", GrantKind::Filesystem, GrantState::Expired, "t"),
            entry("a", GrantKind::Network, GrantState::Revoked, "t"),
        ];
        let s = CoverageSummary::build(&entries);
        assert_eq!(s.earliest_expiry, "");
        assert_eq!(s.total_active, 0);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = CoverageSummary::build(&[]);
        s.schema_version = "9.9.9".into();
        assert!(matches!(s.validate().unwrap_err(), CoverageError::SchemaMismatch));
    }

    #[test]
    fn summary_serde_roundtrip() {
        let entries = vec![
            entry("a", GrantKind::Filesystem, GrantState::Active, "2026-05-19T01:00:00Z"),
        ];
        let s = CoverageSummary::build(&entries);
        let j = serde_json::to_string(&s).unwrap();
        let back: CoverageSummary = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
