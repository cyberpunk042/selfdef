//! `selfdef-grant-registry` — daemon-resident, persistent registry of
//! issued grants. The live D-13 state the selfdef daemon projects into
//! the `selfdef-grants-mirror` MS007 snapshot for sovereign-os to render
//! READ-ONLY.
//!
//! This closes the publisher gap: the `selfdef-grants-mirror` crate
//! defines the wire schema and `selfdef-grant-issuer` issues a single
//! typed grant, but nothing held the *set* of live grants or persisted
//! it. This crate is that registry:
//!
//! - holds a [`GrantsMirrorSnapshot`] (the same wire type the mirror
//!   publishes — no parallel schema),
//! - persists atomically to `/var/lib/selfdef/grants.json`
//!   ([`DEFAULT_STATE_PATH`]) — the daemon-resident store the export
//!   loop reads,
//! - issues via [`selfdef_grant_issuer::issue`] (TTL ceiling + MS003
//!   signature + non-empty-field gates), appends, recomputes summaries,
//! - transitions grants through their MS035/MS038 lifecycle
//!   (Pending → Active, → Revoked, → Expired).
//!
//! Mutation is an IPS-side verb (selfdefctl + MS003); sovereign-os never
//! mutates this — it renders the published mirror READ-ONLY (MS043 R10212).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports: consumers (daemon, CLI) depend only on this crate
// for the grant types, not on the underlying mirror/issuer crates. These
// `pub use`s also bring the names into scope for this module's own use.
pub use selfdef_grant_issuer::{GrantRequest, IssueError};
pub use selfdef_grants_mirror::{
    GrantEntry, GrantKind, GrantState, GrantsMirrorSnapshot, SCHEMA_VERSION,
};

/// Default on-disk path for the persisted registry (operator override
/// via daemon config / env). The daemon's mirror-export loop reads this
/// resident store and republishes it to the sovereign-os mirror dir.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/grants.json";

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Underlying issuance refused the request.
    #[error("issue refused: {0}")]
    Issue(#[from] IssueError),
    /// Persisted store was present but malformed.
    #[error("malformed grants store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("grants store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed (should not happen with Rfc3339).
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
}

/// Daemon-resident grant registry.
#[derive(Debug, Clone)]
pub struct GrantRegistry {
    snapshot: GrantsMirrorSnapshot,
}

impl Default for GrantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantRegistry {
    /// New empty registry (no grants), schema-version pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: GrantsMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: String::new(),
                summaries: Vec::new(),
                grants: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Adopt an existing snapshot as the registry state.
    #[must_use]
    pub fn from_snapshot(snapshot: GrantsMirrorSnapshot) -> Self {
        Self { snapshot }
    }

    /// Load the persisted registry. An ABSENT store is not an error — it
    /// yields an empty registry (the resident store simply has no grants
    /// yet). A PRESENT-but-malformed store is an error (operators should
    /// see corruption loudly, not silently lose grants).
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => {
                return Err(RegistryError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        let snapshot = serde_json::from_str(&text).map_err(|e| RegistryError::Malformed {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(Self { snapshot })
    }

    /// Atomically persist the registry (sibling tempfile + rename).
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let io_err = |e: std::io::Error| RegistryError::Io {
            path: path.display().to_string(),
            source: e,
        };
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(io_err)?;
            }
        }
        let body =
            serde_json::to_string_pretty(&self.snapshot).map_err(|e| RegistryError::Malformed {
                path: path.display().to_string(),
                source: e,
            })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body).map_err(io_err)?;
        std::fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }

    /// Issue a grant from a signed request as of `now`. Computes
    /// `issued_at`/`expires_at` (now + ttl) in RFC3339, appends the
    /// resulting grant (state Pending per the issuer contract), and
    /// recomputes the per-kind summaries + capture timestamp. Returns the
    /// new grant id.
    pub fn issue(
        &mut self,
        req: &GrantRequest,
        grant_id: &str,
        trace_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, RegistryError> {
        let issued_at = now.format(&Rfc3339)?;
        let expires = now + time::Duration::seconds(i64::from(req.ttl_seconds));
        let expires_at = expires.format(&Rfc3339)?;
        let entry = selfdef_grant_issuer::issue(req, grant_id, &issued_at, &expires_at, trace_id)?;
        self.snapshot.grants.push(entry);
        self.recompute(now)?;
        Ok(grant_id.to_string())
    }

    /// Transition a Pending grant to Active (the boundary applier
    /// succeeded). Returns true if a matching grant was transitioned.
    pub fn activate(&mut self, grant_id: &str, now: OffsetDateTime) -> Result<bool, RegistryError> {
        self.set_state(grant_id, GrantState::Active, now)
    }

    /// Revoke a grant (operator-forced or drift). Returns true if a
    /// matching grant was transitioned.
    pub fn revoke(&mut self, grant_id: &str, now: OffsetDateTime) -> Result<bool, RegistryError> {
        self.set_state(grant_id, GrantState::Revoked, now)
    }

    /// Expire every Active/Pending grant whose `expires_at` is at or
    /// before `now`. Returns the count expired. Pure lifecycle hygiene
    /// the daemon runs each export tick so the mirror never shows a
    /// past-TTL grant as Active.
    pub fn expire_due(&mut self, now: OffsetDateTime) -> Result<usize, RegistryError> {
        let mut changed = 0usize;
        for g in &mut self.snapshot.grants {
            if matches!(g.state, GrantState::Active | GrantState::Pending) {
                if let Ok(exp) = OffsetDateTime::parse(&g.expires_at, &Rfc3339) {
                    if exp <= now {
                        g.state = GrantState::Expired;
                        changed += 1;
                    }
                }
            }
        }
        if changed > 0 {
            self.recompute(now)?;
        }
        Ok(changed)
    }

    fn set_state(
        &mut self,
        grant_id: &str,
        state: GrantState,
        now: OffsetDateTime,
    ) -> Result<bool, RegistryError> {
        let found = self
            .snapshot
            .grants
            .iter_mut()
            .find(|g| g.grant_id == grant_id);
        match found {
            Some(g) => {
                g.state = state;
                self.recompute(now)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Recompute per-kind summaries + stamp `captured_at`. Keeps the
    /// snapshot's summaries consistent with its grant list.
    fn recompute(&mut self, now: OffsetDateTime) -> Result<(), RegistryError> {
        self.snapshot.summaries = self.snapshot.recompute_summaries();
        self.snapshot.captured_at = now.format(&Rfc3339)?;
        Ok(())
    }

    /// The current registry state as the published mirror snapshot.
    #[must_use]
    pub fn snapshot(&self) -> &GrantsMirrorSnapshot {
        &self.snapshot
    }

    /// The live grant entries.
    #[must_use]
    pub fn grants(&self) -> &[GrantEntry] {
        &self.snapshot.grants
    }

    /// Count of grants currently Active.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.snapshot.active_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn req(kind: GrantKind, ttl: u32) -> GrantRequest {
        GrantRequest {
            kind,
            scope: "/workspace/**".into(),
            reason: "ship feature X".into(),
            profile: "careful".into(),
            actor: "operator-fp".into(),
            ttl_seconds: ttl,
            signature: "ms003-sig".into(),
        }
    }

    #[test]
    fn new_is_empty_and_schema_pinned() {
        let r = GrantRegistry::new();
        assert!(r.grants().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn issue_appends_pending_and_sets_expiry() {
        let mut r = GrantRegistry::new();
        let id = r
            .issue(&req(GrantKind::Filesystem, 3600), "gr-1", "t1", now())
            .unwrap();
        assert_eq!(id, "gr-1");
        assert_eq!(r.grants().len(), 1);
        let g = &r.grants()[0];
        assert_eq!(g.state, GrantState::Pending);
        assert_eq!(g.issued_at, "2027-01-15T08:00:00Z");
        // 1h later
        assert_eq!(g.expires_at, "2027-01-15T09:00:00Z");
        // summaries recomputed: 1 pending filesystem grant
        let fs = r
            .snapshot()
            .summaries
            .iter()
            .find(|s| s.kind == GrantKind::Filesystem)
            .unwrap();
        assert_eq!(fs.pending, 1);
        assert!(!r.snapshot().captured_at.is_empty());
    }

    #[test]
    fn issue_rejects_unsigned() {
        let mut r = GrantRegistry::new();
        let mut bad = req(GrantKind::Network, 60);
        bad.signature = String::new();
        assert!(matches!(
            r.issue(&bad, "g", "t", now()).unwrap_err(),
            RegistryError::Issue(IssueError::Unsigned)
        ));
        assert!(r.grants().is_empty());
    }

    #[test]
    fn activate_then_revoke_transitions_state() {
        let mut r = GrantRegistry::new();
        r.issue(&req(GrantKind::Capability, 3600), "gr-1", "t1", now())
            .unwrap();
        assert!(r.activate("gr-1", now()).unwrap());
        assert_eq!(r.grants()[0].state, GrantState::Active);
        assert_eq!(r.active_count(), 1);
        assert!(r.revoke("gr-1", now()).unwrap());
        assert_eq!(r.grants()[0].state, GrantState::Revoked);
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn transition_unknown_id_returns_false() {
        let mut r = GrantRegistry::new();
        assert!(!r.activate("nope", now()).unwrap());
        assert!(!r.revoke("nope", now()).unwrap());
    }

    #[test]
    fn expire_due_marks_past_ttl_grants() {
        let mut r = GrantRegistry::new();
        r.issue(&req(GrantKind::Sandbox, 60), "gr-1", "t1", now())
            .unwrap();
        r.activate("gr-1", now()).unwrap();
        // 61s later → past the 60s TTL
        let later = now() + time::Duration::seconds(61);
        assert_eq!(r.expire_due(later).unwrap(), 1);
        assert_eq!(r.grants()[0].state, GrantState::Expired);
        // idempotent
        assert_eq!(r.expire_due(later).unwrap(), 0);
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let mut r = GrantRegistry::new();
        r.issue(&req(GrantKind::Filesystem, 3600), "gr-1", "t1", now())
            .unwrap();
        r.activate("gr-1", now()).unwrap();
        r.save(&path).unwrap();
        assert!(!path.with_extension("json.tmp").exists(), "tmp cleaned up");

        let back = GrantRegistry::load(&path).unwrap();
        assert_eq!(back.grants().len(), 1);
        assert_eq!(back.grants()[0].state, GrantState::Active);
        back.snapshot().validate_schema().unwrap();
    }

    #[test]
    fn load_absent_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = GrantRegistry::load(&dir.path().join("nope.json")).unwrap();
        assert!(r.grants().is_empty());
    }

    #[test]
    fn load_malformed_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        std::fs::write(&path, "{ not valid json").unwrap();
        assert!(matches!(
            GrantRegistry::load(&path).unwrap_err(),
            RegistryError::Malformed { .. }
        ));
    }
}
