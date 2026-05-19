//! `selfdef-grant-overlap-detector` — flag grants whose scopes overlap.
//!
//! Overlap rules per kind:
//! - `Filesystem`: one scope is a path-prefix of the other.
//! - `Network`:    exact same scope or domain-suffix-overlap.
//! - `Capability`: exact same scope.
//! - `Sandbox`:    exact same scope.
//! - `Communication`: exact same scope.
//!
//! Returns a `Vec<OverlapPair>` for every overlapping pair detected
//! among active grants.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::{GrantEntry, GrantKind, GrantState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One overlap pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlapPair {
    /// First grant id.
    pub grant_a: String,
    /// Second grant id.
    pub grant_b: String,
    /// Shared kind.
    pub kind: GrantKind,
    /// One-line reason.
    pub reason: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum OverlapError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

fn overlaps(kind: GrantKind, a: &str, b: &str) -> Option<String> {
    if a == b {
        return Some(format!("identical scope {a}"));
    }
    match kind {
        GrantKind::Filesystem => {
            // Use slash-separated prefix match. "/workspace" overlaps "/workspace/foo".
            let a_t = trim_trailing_slash(a);
            let b_t = trim_trailing_slash(b);
            let a_p = format!("{a_t}/");
            let b_p = format!("{b_t}/");
            if b.starts_with(&a_p) {
                return Some(format!("{a} prefix of {b}"));
            }
            if a.starts_with(&b_p) {
                return Some(format!("{b} prefix of {a}"));
            }
            None
        }
        GrantKind::Network => {
            // Suffix overlap (".example.org" covers "a.example.org").
            if a.starts_with('.') && b.ends_with(a) { return Some(format!("{a} suffix-covers {b}")); }
            if b.starts_with('.') && a.ends_with(b) { return Some(format!("{b} suffix-covers {a}")); }
            None
        }
        // Other kinds: only exact-match (handled above).
        _ => None,
    }
}

fn trim_trailing_slash(s: &str) -> &str {
    if s.len() > 1 && s.ends_with('/') { &s[..s.len() - 1] } else { s }
}

/// Scan active grants and return overlap pairs.
pub fn scan(grants: &[GrantEntry]) -> Vec<OverlapPair> {
    let active: Vec<&GrantEntry> = grants.iter().filter(|g| g.state == GrantState::Active).collect();
    let mut out = Vec::new();
    for i in 0..active.len() {
        for j in (i + 1)..active.len() {
            let a = active[i];
            let b = active[j];
            if a.kind != b.kind { continue; }
            if let Some(reason) = overlaps(a.kind, &a.scope, &b.scope) {
                out.push(OverlapPair {
                    grant_a: a.grant_id.clone(),
                    grant_b: b.grant_id.clone(),
                    kind: a.kind,
                    reason,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, kind: GrantKind, scope: &str, state: GrantState) -> GrantEntry {
        GrantEntry {
            grant_id: id.into(),
            kind,
            scope: scope.into(),
            reason: "r".into(),
            issued_at: "2026-05-19T00:00:00Z".into(),
            expires_at: "2026-05-19T01:00:00Z".into(),
            ttl_seconds: 60,
            profile: "careful".into(),
            actor: "op".into(),
            state,
            trace_id: "tr".into(),
            signature: "s".into(),
        }
    }

    #[test]
    fn no_overlap_disjoint() {
        let g = vec![
            entry("g1", GrantKind::Filesystem, "/a", GrantState::Active),
            entry("g2", GrantKind::Filesystem, "/b", GrantState::Active),
        ];
        assert!(scan(&g).is_empty());
    }

    #[test]
    fn identical_scope_overlaps() {
        let g = vec![
            entry("g1", GrantKind::Filesystem, "/workspace", GrantState::Active),
            entry("g2", GrantKind::Filesystem, "/workspace", GrantState::Active),
        ];
        assert_eq!(scan(&g).len(), 1);
    }

    #[test]
    fn filesystem_prefix_overlap() {
        let g = vec![
            entry("g1", GrantKind::Filesystem, "/workspace", GrantState::Active),
            entry("g2", GrantKind::Filesystem, "/workspace/foo", GrantState::Active),
        ];
        let pairs = scan(&g);
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn network_suffix_overlap() {
        let g = vec![
            entry("g1", GrantKind::Network, ".example.org", GrantState::Active),
            entry("g2", GrantKind::Network, "a.example.org", GrantState::Active),
        ];
        let pairs = scan(&g);
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn distinct_kinds_no_overlap() {
        let g = vec![
            entry("g1", GrantKind::Filesystem, "/x", GrantState::Active),
            entry("g2", GrantKind::Network, "/x", GrantState::Active),
        ];
        assert!(scan(&g).is_empty());
    }

    #[test]
    fn inactive_grants_ignored() {
        let g = vec![
            entry("g1", GrantKind::Filesystem, "/a", GrantState::Active),
            entry("g2", GrantKind::Filesystem, "/a", GrantState::Expired),
        ];
        assert!(scan(&g).is_empty());
    }

    #[test]
    fn capability_only_exact_overlap() {
        let g = vec![
            entry("g1", GrantKind::Capability, "cap:proc.spawn", GrantState::Active),
            entry("g2", GrantKind::Capability, "cap:fs.write", GrantState::Active),
        ];
        assert!(scan(&g).is_empty());
        let g2 = vec![
            entry("g1", GrantKind::Capability, "cap:proc.spawn", GrantState::Active),
            entry("g2", GrantKind::Capability, "cap:proc.spawn", GrantState::Active),
        ];
        assert_eq!(scan(&g2).len(), 1);
    }

    #[test]
    fn pair_serde_roundtrip() {
        let p = OverlapPair {
            grant_a: "g1".into(), grant_b: "g2".into(),
            kind: GrantKind::Filesystem,
            reason: "x".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        let back: OverlapPair = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
