//! D-13 grants mutation + read surface.
//!
//! `GET /v1/grants` returns the current daemon-resident grant snapshot;
//! `POST /v1/grants/issue` issues a signed grant; `POST /v1/grants/revoke`
//! revokes one. Mutations persist the registry to the resident store
//! (`selfdef-grant-registry::DEFAULT_STATE_PATH`, override via
//! `SELFDEF_GRANTS_PATH`) — the exact store the daemon's mirror-export
//! loop republishes READ-ONLY for the sovereign-os D-13 dashboard.
//!
//! This is the permission-correct write path: operators reach it through
//! the (root) daemon API rather than writing `/var/lib/selfdef` directly.
//! Mirrors the MS011 Z-3 flex-profile mutation precedent (same router,
//! no separate control-token gate yet — that cross-cutting commit-
//! authority arc is SDD-055, tracked there for all mutation surfaces).

use std::path::{Path, PathBuf};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use selfdef_grant_registry::{
    GrantEntry, GrantRegistry, GrantRequest, GrantState, GrantsMirrorSnapshot, RegistryError,
};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::state::{ApiState, GrantsOverlapPolicy};

/// Resident grant store path. Honors `SELFDEF_GRANTS_PATH` (kept in sync
/// with the daemon's mirror-export reader), else the crate default.
fn state_path() -> PathBuf {
    std::env::var("SELFDEF_GRANTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_grant_registry::DEFAULT_STATE_PATH))
}

fn load(path: &Path) -> Result<GrantRegistry, (StatusCode, String)> {
    GrantRegistry::load(path).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn save(reg: &GrantRegistry, path: &Path) -> Result<(), (StatusCode, String)> {
    reg.save(path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Validation refusals (unsigned / empty-field / TTL) are the caller's
/// fault → 400; storage/format problems are the daemon's → 500.
fn map_err(e: RegistryError) -> (StatusCode, String) {
    match e {
        RegistryError::Issue(inner) => (StatusCode::BAD_REQUEST, inner.to_string()),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// `POST /v1/grants/revoke` body.
#[derive(Debug, Deserialize)]
pub(crate) struct RevokeRequest {
    /// Grant id to revoke.
    pub grant_id: String,
}

/// `GET /v1/grants` — current resident grant snapshot (the same wire
/// type the mirror publishes). Absent store → empty-but-valid snapshot.
///
/// Applies presentation-time TTL expiry (in-memory, not persisted — the
/// durable store is selfdefctl's) so this surface never reports a past-TTL
/// grant as `Active`, matching the sovereign-os mirror's already-established
/// hygiene (`mirror_export_loop::publish_grants`). Without this the two grant
/// read surfaces disagreed on an expired grant's state.
pub(crate) async fn show() -> Result<Json<GrantsMirrorSnapshot>, (StatusCode, String)> {
    let mut reg = load(&state_path())?;
    let _ = reg.expire_due(OffsetDateTime::now_utc());
    Ok(Json(reg.snapshot().clone()))
}

/// `POST /v1/grants/issue` — body is the operator-signed [`GrantRequest`].
/// The daemon mints the `grant_id` + `trace_id` (callers never supply
/// them) and stamps `now`. Returns the issued (Pending) grant.
///
/// Grant-governance: when `[grants].overlap_policy` is `warn`/`refuse`, the
/// freshly-minted grant is checked against the registry's existing *active*
/// grants (path-prefix for filesystem, domain-suffix for network, exact for
/// the rest) via [`selfdef_grant_overlap_detector`]. Under `refuse` an
/// overlapping grant is rejected with 409 and never persisted — fail-safe,
/// since refusing to *add* an overlapping grant can never narrow existing
/// access. Default `off` preserves the historical unconditional issue.
pub(crate) async fn issue(
    State(state): State<ApiState>,
    _cap: crate::control::RequireControl,
    Json(req): Json<GrantRequest>,
) -> Result<Json<GrantEntry>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let nanos = now.unix_timestamp_nanos();
    let grant_id = format!("gr-{nanos:x}");
    let trace_id = format!("tr-{nanos:x}");
    let id = reg
        .issue(&req, &grant_id, &trace_id, now)
        .map_err(map_err)?;

    // Issuance-cooldown gate. Refuse re-minting a grant of identical identity
    // (actor + kind + scope) within `[grants].issuance_cooldown_secs` — bounds
    // re-mint churn even of an already-expired/revoked grant (which the
    // active-only overlap gate below does not catch). Drops the unsaved
    // registry on refusal, so the mint never lands.
    let cooldown_secs = state.grants_issuance_cooldown_secs();
    if cooldown_secs > 0 {
        let key = grant_key_req(&req);
        let now_ms = (now.unix_timestamp_nanos() / 1_000_000) as u64;
        if let Some(ready_at_ms) =
            cooldown_ready_at_ms(reg.grants(), &id, &key, cooldown_secs, now_ms)
        {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "grant {id} ({key}) re-issued within the {cooldown_secs}s issuance \
                     cooldown; ready at epoch-ms {ready_at_ms}"
                ),
            ));
        }
    }

    // Overlap-governance gate. The candidate is `Pending` immediately after
    // `issue`; the detector only pairs `Active` grants, so we project the
    // candidate as active for the scan and look for any pair naming it.
    let policy = state.grants_overlap_policy();
    if policy != GrantsOverlapPolicy::Off {
        if let Some(other) = candidate_overlap(reg.grants(), &id) {
            match policy {
                GrantsOverlapPolicy::Refuse => {
                    // Drop the in-memory registry WITHOUT saving: load is
                    // per-request, so the mint never lands on disk.
                    return Err((
                        StatusCode::CONFLICT,
                        format!(
                            "grant {id} ({}) overlaps active grant {}: {}",
                            req.scope, other.grant_id, other.reason
                        ),
                    ));
                }
                GrantsOverlapPolicy::Warn => {
                    tracing::warn!(
                        grant_id = %id,
                        overlaps = %other.grant_id,
                        reason = %other.reason,
                        "grants: issued grant overlaps an existing active grant (warn policy)"
                    );
                }
                GrantsOverlapPolicy::Off => unreachable!("guarded above"),
            }
        }
    }

    save(&reg, &path)?;
    let entry = reg
        .grants()
        .iter()
        .find(|g| g.grant_id == id)
        .cloned()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "issued grant missing from registry".to_string(),
        ))?;
    Ok(Json(entry))
}

/// The overlap pair (if any) naming the just-issued candidate. The candidate
/// is `Pending` in `grants`, so we build a scan view of (existing active
/// grants + the candidate forced active) and return the *other* grant in the
/// first pair the detector reports for the candidate.
fn candidate_overlap(grants: &[GrantEntry], candidate_id: &str) -> Option<GrantEntry> {
    let mut for_scan: Vec<GrantEntry> = grants
        .iter()
        .filter(|g| g.state == GrantState::Active || g.grant_id == candidate_id)
        .cloned()
        .collect();
    for g in &mut for_scan {
        if g.grant_id == candidate_id {
            g.state = GrantState::Active;
        }
    }
    let pair = selfdef_grant_overlap_detector::scan(&for_scan)
        .into_iter()
        .find(|p| p.grant_a == candidate_id || p.grant_b == candidate_id)?;
    let other_id = if pair.grant_a == candidate_id {
        pair.grant_b
    } else {
        pair.grant_a
    };
    for_scan.into_iter().find(|g| g.grant_id == other_id)
}

/// Stable identity key for the issuance-cooldown ledger: `actor|kind|scope`.
/// Used only as an in-memory cooldown key, never serialized to the wire.
fn grant_key_req(req: &GrantRequest) -> String {
    format!("{}|{:?}|{}", req.actor, req.kind, req.scope)
}

/// Same identity key, computed from a stored [`GrantEntry`].
fn grant_key_entry(g: &GrantEntry) -> String {
    format!("{}|{:?}|{}", g.actor, g.kind, g.scope)
}

/// Parse an RFC3339 `issued_at` string into epoch-ms.
fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| (t.unix_timestamp_nanos() / 1_000_000) as u64)
}

/// `Some(ready_at_ms)` when an identical-identity grant was issued within the
/// cooldown window, else `None` (clear to issue). Drives the orphaned
/// `selfdef-grant-issuance-cooldown` crate's `classify` on the single relevant
/// key, seeded with the most-recent prior issuance of that identity.
fn cooldown_ready_at_ms(
    grants: &[GrantEntry],
    candidate_id: &str,
    candidate_key: &str,
    cooldown_secs: u64,
    now_ms: u64,
) -> Option<u64> {
    use selfdef_grant_issuance_cooldown::{CooldownVerdict, GrantIssuanceCooldown};

    let latest_prior_ms = grants
        .iter()
        .filter(|g| g.grant_id != candidate_id)
        .filter(|g| grant_key_entry(g) == candidate_key)
        .filter_map(|g| parse_rfc3339_ms(&g.issued_at))
        .max()?;

    let mut ledger = GrantIssuanceCooldown::new(cooldown_secs.saturating_mul(1000));
    ledger.record_issued(candidate_key, latest_prior_ms).ok()?;
    match ledger.classify(candidate_key, now_ms) {
        CooldownVerdict::Ready => None,
        CooldownVerdict::Cooldown { ready_at_ms } => Some(ready_at_ms),
    }
}

/// `POST /v1/grants/revoke` — revoke a grant by id. 404 when unknown.
/// Returns the updated snapshot.
pub(crate) async fn revoke(
    _cap: crate::control::RequireControl,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<GrantsMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let mut reg = load(&path)?;
    let now = OffsetDateTime::now_utc();
    let found = reg.revoke(&req.grant_id, now).map_err(map_err)?;
    if !found {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no grant with id {}", req.grant_id),
        ));
    }
    save(&reg, &path)?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_grant_registry::{GrantKind, GrantState};

    fn req(kind: GrantKind) -> GrantRequest {
        GrantRequest {
            kind,
            scope: "/workspace/**".into(),
            reason: "ship feature".into(),
            profile: "careful".into(),
            actor: "operator-fp".into(),
            ttl_seconds: 3600,
            signature: "ms003-sig".into(),
        }
    }

    /// Issue → persist → revoke cycle through the registry, driving the
    /// same code path the handlers use (sans the axum Json wrapper).
    #[test]
    fn issue_persist_revoke_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let now = OffsetDateTime::now_utc();

        let mut reg = GrantRegistry::load(&path).unwrap();
        let id = reg
            .issue(&req(GrantKind::Filesystem), "gr-x", "tr-x", now)
            .unwrap();
        save(&reg, &path).unwrap();

        let reloaded = GrantRegistry::load(&path).unwrap();
        assert_eq!(reloaded.grants().len(), 1);
        assert_eq!(reloaded.grants()[0].state, GrantState::Pending);

        let mut reg2 = GrantRegistry::load(&path).unwrap();
        assert!(reg2.revoke(&id, now).unwrap());
        save(&reg2, &path).unwrap();
        assert_eq!(
            GrantRegistry::load(&path).unwrap().grants()[0].state,
            GrantState::Revoked
        );
    }

    /// The `show` handler applies presentation-time expiry: a grant whose TTL
    /// has elapsed must read as `Expired`, not `Active`, matching the mirror.
    /// Drives the same load → expire_due → snapshot path the handler uses.
    #[test]
    fn show_path_expires_past_ttl_grants_for_presentation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let issued = OffsetDateTime::now_utc();

        let mut reg = GrantRegistry::load(&path).unwrap();
        // 1s TTL.
        let mut r = req(GrantKind::Filesystem);
        r.ttl_seconds = 1;
        let id = reg.issue(&r, "gr-ttl", "tr-ttl", issued).unwrap();
        reg.activate(&id, issued).unwrap();
        save(&reg, &path).unwrap();

        // The durable store still holds it Active (selfdefctl owns durable
        // expiry); but the show path applies presentation-time expiry.
        let mut shown = GrantRegistry::load(&path).unwrap();
        assert_eq!(shown.grants()[0].state, GrantState::Active, "stored Active");
        let later = issued + time::Duration::seconds(5);
        let _ = shown.expire_due(later);
        assert_eq!(
            shown.snapshot().grants[0].state,
            GrantState::Expired,
            "show must present a past-TTL grant as Expired"
        );
    }

    #[test]
    fn unsigned_request_maps_to_400() {
        let mut bad = req(GrantKind::Network);
        bad.signature = String::new();
        let mut reg = GrantRegistry::new();
        let err = reg
            .issue(&bad, "g", "t", OffsetDateTime::now_utc())
            .map_err(map_err)
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // ---- grant-overlap governance gate (candidate_overlap) ----

    fn fs_req(scope: &str) -> GrantRequest {
        let mut r = req(GrantKind::Filesystem);
        r.scope = scope.into();
        r
    }

    /// A freshly-issued grant whose scope is a path-prefix child of an
    /// existing *active* grant must be flagged by `candidate_overlap` — the
    /// exact signal the handler turns into a 409 under `refuse`.
    #[test]
    fn candidate_overlap_flags_filesystem_prefix() {
        let now = OffsetDateTime::now_utc();
        let mut reg = GrantRegistry::new();
        let existing = reg
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        reg.activate(&existing, now).unwrap();
        // Candidate under /workspace — overlaps the active parent grant.
        let cand = reg
            .issue(&fs_req("/workspace/foo"), "gr-2", "tr-2", now)
            .unwrap();
        let other = candidate_overlap(reg.grants(), &cand).expect("overlap expected");
        assert_eq!(other.grant_id, existing);
    }

    /// Disjoint scopes do not overlap — issuance under any policy proceeds.
    #[test]
    fn candidate_overlap_none_when_disjoint() {
        let now = OffsetDateTime::now_utc();
        let mut reg = GrantRegistry::new();
        let existing = reg
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        reg.activate(&existing, now).unwrap();
        let cand = reg.issue(&fs_req("/var/log"), "gr-2", "tr-2", now).unwrap();
        assert!(candidate_overlap(reg.grants(), &cand).is_none());
    }

    /// An existing grant that is NOT active (e.g. Pending/Revoked) is not a
    /// scan target — the detector only governs against live access.
    #[test]
    fn candidate_overlap_ignores_inactive_existing() {
        let now = OffsetDateTime::now_utc();
        let mut reg = GrantRegistry::new();
        // gr-1 stays Pending (never activated).
        let _existing = reg
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        let cand = reg
            .issue(&fs_req("/workspace/foo"), "gr-2", "tr-2", now)
            .unwrap();
        assert!(candidate_overlap(reg.grants(), &cand).is_none());
    }

    /// Mirrors the handler decision: under `refuse`, an overlapping mint is
    /// dropped WITHOUT saving (load is per-request, so it never lands); under
    /// `off`, the same mint persists. Drives the registry + `candidate_overlap`
    /// exactly as the handler does (sans the axum State/Json wrappers).
    #[test]
    fn refuse_skips_save_off_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let now = OffsetDateTime::now_utc();

        // Seed an active parent grant on disk.
        let mut seed = GrantRegistry::load(&path).unwrap();
        let parent = seed
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        seed.activate(&parent, now).unwrap();
        save(&seed, &path).unwrap();

        // Helper that runs the handler's core: load, issue, gate, conditional save.
        let attempt = |policy: GrantsOverlapPolicy| -> bool {
            let mut reg = GrantRegistry::load(&path).unwrap();
            let id = reg
                .issue(&fs_req("/workspace/foo"), "gr-2", "tr-2", now)
                .unwrap();
            let overlap = candidate_overlap(reg.grants(), &id);
            if policy == GrantsOverlapPolicy::Refuse && overlap.is_some() {
                // handler returns 409 here, dropping `reg` unsaved.
                return false;
            }
            save(&reg, &path).unwrap();
            true
        };

        // Refuse → not persisted.
        assert!(!attempt(GrantsOverlapPolicy::Refuse));
        assert_eq!(
            GrantRegistry::load(&path).unwrap().grants().len(),
            1,
            "refuse must not persist the overlapping grant"
        );

        // Off → persisted (historical behavior preserved).
        assert!(attempt(GrantsOverlapPolicy::Off));
        assert_eq!(
            GrantRegistry::load(&path).unwrap().grants().len(),
            2,
            "off must persist as before"
        );
    }

    // ---- grant issuance-cooldown gate (cooldown_ready_at_ms) ----

    /// A re-issue of an identical-identity grant inside the cooldown window is
    /// blocked; the same identity is clear once the window elapses. Drives the
    /// orphaned cooldown crate via `cooldown_ready_at_ms` exactly as the
    /// handler does.
    #[test]
    fn cooldown_blocks_in_window_clears_after() {
        let now = OffsetDateTime::now_utc();
        let issued_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut reg = GrantRegistry::new();
        // A prior grant of the same identity, issued "now".
        let _prior = reg
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        // Candidate of identical identity.
        let cand = reg
            .issue(&fs_req("/workspace"), "gr-2", "tr-2", now)
            .unwrap();
        let key = grant_key_req(&fs_req("/workspace"));
        let now_ms = (now.unix_timestamp_nanos() / 1_000_000) as u64;

        // Within a 60s window → blocked (prior was issued at `now`).
        assert!(
            cooldown_ready_at_ms(reg.grants(), &cand, &key, 60, now_ms).is_some(),
            "re-issue inside the window must be blocked: prior issued_at={issued_at}"
        );
        // 120s later → clear.
        let later_ms = now_ms + 120_000;
        assert!(
            cooldown_ready_at_ms(reg.grants(), &cand, &key, 60, later_ms).is_none(),
            "identity must clear once the cooldown elapses"
        );
    }

    /// A different identity (distinct scope) is never blocked by the cooldown,
    /// and a zero-history identity is always clear.
    #[test]
    fn cooldown_ignores_distinct_identity() {
        let now = OffsetDateTime::now_utc();
        let mut reg = GrantRegistry::new();
        let _prior = reg
            .issue(&fs_req("/workspace"), "gr-1", "tr-1", now)
            .unwrap();
        // Candidate with a DIFFERENT scope → different identity key.
        let cand = reg.issue(&fs_req("/var/log"), "gr-2", "tr-2", now).unwrap();
        let key = grant_key_req(&fs_req("/var/log"));
        let now_ms = (now.unix_timestamp_nanos() / 1_000_000) as u64;
        assert!(
            cooldown_ready_at_ms(reg.grants(), &cand, &key, 60, now_ms).is_none(),
            "a distinct-identity grant is never cooldown-blocked"
        );
    }
}
