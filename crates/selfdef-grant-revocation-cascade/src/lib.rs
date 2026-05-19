//! `selfdef-grant-revocation-cascade` — compute revocation cascade.
//!
//! Given a parent grant_id and a slice of Active GrantEntry, returns
//! the cascade set: any grant issued after the parent whose scope is a
//! `Filesystem` path-prefix of the parent's scope, or shares the same
//! Network/Capability/Sandbox/Communication scope.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_grants_mirror::{GrantEntry, GrantKind, GrantState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One cascade hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CascadeHit {
    /// Child grant id.
    pub grant_id: String,
    /// Why it cascaded.
    pub reason: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum CascadeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Parent grant_id not found in input.
    #[error("parent grant {0} not found")]
    ParentMissing(String),
    /// Parent grant not Active.
    #[error("parent grant {0} not Active")]
    ParentNotActive(String),
}

fn trim_trailing_slash(s: &str) -> &str {
    if s.len() > 1 && s.ends_with('/') { &s[..s.len() - 1] } else { s }
}

fn fs_is_child(parent: &str, child: &str) -> bool {
    if parent == child { return false; } // self
    let p = trim_trailing_slash(parent);
    let c = trim_trailing_slash(child);
    let p_with_sep = format!("{p}/");
    c.starts_with(&p_with_sep)
}

/// Compute cascade set.
pub fn compute_cascade(grants: &[GrantEntry], parent_id: &str) -> Result<Vec<CascadeHit>, CascadeError> {
    let parent = grants.iter().find(|g| g.grant_id == parent_id)
        .ok_or_else(|| CascadeError::ParentMissing(parent_id.into()))?;
    if parent.state != GrantState::Active {
        return Err(CascadeError::ParentNotActive(parent_id.into()));
    }
    let mut out = Vec::new();
    for g in grants {
        if g.grant_id == parent_id { continue; }
        if g.state != GrantState::Active { continue; }
        if g.kind != parent.kind { continue; }
        // Issued after parent (string compare on ISO-8601).
        if g.issued_at <= parent.issued_at { continue; }
        match parent.kind {
            GrantKind::Filesystem => {
                if fs_is_child(&parent.scope, &g.scope) {
                    out.push(CascadeHit {
                        grant_id: g.grant_id.clone(),
                        reason: format!("filesystem child of {}", parent.scope),
                    });
                }
            }
            // Other kinds: exact-scope match cascades.
            _ => {
                if g.scope == parent.scope {
                    out.push(CascadeHit {
                        grant_id: g.grant_id.clone(),
                        reason: format!("same {:?} scope {}", parent.kind, parent.scope),
                    });
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, kind: GrantKind, scope: &str, state: GrantState, issued_at: &str) -> GrantEntry {
        GrantEntry {
            grant_id: id.into(),
            kind, scope: scope.into(),
            reason: "r".into(),
            issued_at: issued_at.into(),
            expires_at: "2026-05-19T05:00:00Z".into(),
            ttl_seconds: 60,
            profile: "careful".into(),
            actor: "op".into(),
            state,
            trace_id: "tr".into(),
            signature: "s".into(),
        }
    }

    #[test]
    fn empty_cascade_for_isolated_parent() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/workspace", GrantState::Active, "t1"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn filesystem_child_cascades() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/workspace", GrantState::Active, "2026-05-19T01:00:00Z"),
            entry("c", GrantKind::Filesystem, "/workspace/sub", GrantState::Active, "2026-05-19T02:00:00Z"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].grant_id, "c");
    }

    #[test]
    fn filesystem_earlier_grant_not_cascaded() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/workspace", GrantState::Active, "2026-05-19T03:00:00Z"),
            entry("c", GrantKind::Filesystem, "/workspace/sub", GrantState::Active, "2026-05-19T01:00:00Z"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn network_exact_match_cascades() {
        let g = vec![
            entry("p", GrantKind::Network, ".example.org", GrantState::Active, "t1"),
            entry("c", GrantKind::Network, ".example.org", GrantState::Active, "t2"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn distinct_kinds_no_cascade() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/x", GrantState::Active, "t1"),
            entry("c", GrantKind::Network, "/x", GrantState::Active, "t2"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn inactive_children_excluded() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/workspace", GrantState::Active, "t1"),
            entry("c", GrantKind::Filesystem, "/workspace/sub", GrantState::Expired, "t2"),
        ];
        let c = compute_cascade(&g, "p").unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn parent_missing_rejected() {
        let g = vec![];
        assert!(matches!(compute_cascade(&g, "none").unwrap_err(), CascadeError::ParentMissing(_)));
    }

    #[test]
    fn parent_not_active_rejected() {
        let g = vec![
            entry("p", GrantKind::Filesystem, "/x", GrantState::Expired, "t1"),
        ];
        assert!(matches!(compute_cascade(&g, "p").unwrap_err(), CascadeError::ParentNotActive(_)));
    }

    #[test]
    fn hit_serde_roundtrip() {
        let h = CascadeHit { grant_id: "g".into(), reason: "x".into() };
        let j = serde_json::to_string(&h).unwrap();
        let back: CascadeHit = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
    }
}
