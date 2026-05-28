//! M060 D-02 (R10063-R10068): daemon-side cross-repo mirror export.
//!
//! When `[deployment].selfdef_mirror_dir` is set, the daemon publishes
//! the MS007 typed-mirror artifacts READ-ONLY into that directory for
//! the sovereign-os cockpit dashboards to render. Currently published:
//!
//! - **D-02 active-profile** (`active-profile.json`) — projected from
//!   the live flex-profile state (MS011 Z-3 / SDD-026) + the MS040
//!   authority envelope. Always published (the R09535 Private default
//!   is the honest value when no flex-profile exists).
//! - **D-13 grants** (`grants.json`) — the daemon-resident grant
//!   registry (`selfdef-grant-registry`). Published ONLY when the
//!   resident store exists.
//! - **D-14 capability-tokens** (`capability-tokens.json`) — the
//!   daemon-resident capability-token registry
//!   (`selfdef-capability-registry`, composing the 64-bit
//!   `capability_word`). Same honesty bar: published ONLY when the
//!   resident store exists, so the dashboard stays honestly offline
//!   until a token is issued.
//!
//! Project boundary: this is IPS state published READ-ONLY. sovereign-os
//! NEVER mutates it — mutations are `selfdefctl` + MS003 verbs on this
//! (IPS) side only (MS043 R10212). Remaining mirror domains
//! (sandbox/quarantine/trust) stay honestly offline pending their own
//! daemon-resident registries (follow-on increments).
//!
//! The pure projection is in [`project_snapshot`] (no I/O, unit-tested
//! in isolation). The loop does file I/O + tokio ticks + cooperates
//! with the daemon shutdown signal, mirroring `hardware_probe_loop`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_capability_registry::CapabilityRegistry;
use selfdef_flex_profile::FlexProfile;
use selfdef_grant_registry::GrantRegistry;
use selfdef_profile_authority_gate::Profile as GateProfile;
use selfdef_profile_mirror::{Profile as MirrorProfile, ProfileMirrorSnapshot};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Re-publish cadence in seconds. The active profile changes rarely +
/// the projection is cheap (one small file read + one small write), so
/// a 30s refresh keeps the dashboard fresh without meaningful cost.
const MIRROR_EXPORT_INTERVAL_SECS: u64 = 30;

/// Published artifact filename inside `selfdef_mirror_dir`. Wire-stable
/// with the sovereign-os consumer
/// (`scripts/mirror/selfdef-profile-mirror.py`).
const ACTIVE_PROFILE_FILE: &str = "active-profile.json";

/// Published grants artifact filename, wire-stable with the sovereign-os
/// D-13 consumer (`scripts/mirror/selfdef-grants-mirror.py`).
const GRANTS_FILE: &str = "grants.json";

/// Published capability-tokens artifact filename, wire-stable with the
/// sovereign-os D-14 consumer (`scripts/mirror/selfdef-capability-mirror.py`).
const CAPABILITY_TOKENS_FILE: &str = "capability-tokens.json";

/// The active-profile selection has no tracked "set at" timestamp —
/// flex-profile records model/LoRA delta provenance, not baseline
/// switches. Publish an honest marker rather than fabricate one.
const SINCE_UNTRACKED: &str = "—";

/// Likewise no tracked operator fingerprint for the baseline selection.
const ACTOR_UNTRACKED: &str = "unknown";

/// Map the mirror-crate profile token to the authority-gate profile so
/// the MS040 envelope can be derived from the single source of truth.
fn gate_profile(p: MirrorProfile) -> GateProfile {
    match p {
        MirrorProfile::Private => GateProfile::Private,
        MirrorProfile::Fast => GateProfile::Fast,
        MirrorProfile::Careful => GateProfile::Careful,
        MirrorProfile::Autonomous => GateProfile::Autonomous,
        MirrorProfile::Experimental => GateProfile::Experimental,
        MirrorProfile::Production => GateProfile::Production,
    }
}

/// MS040 envelope summary for a profile, derived from the authority
/// gate's `max_authority` + `max_trust_ring` ceilings. Operator-readable.
fn envelope_for(p: MirrorProfile) -> String {
    let g = gate_profile(p);
    format!(
        "max authority {:?} · max trust {:?}",
        g.max_authority(),
        g.max_trust_ring()
    )
}

/// Project the active-profile mirror snapshot from the live flex-profile
/// state. Pure — no I/O. When `flex` is absent or its baseline is not an
/// MS040 profile, falls back to Private per MS040 R09535 (the documented
/// offline default) rather than fabricating a selection.
#[must_use]
pub(crate) fn project_snapshot(flex: Option<&FlexProfile>) -> ProfileMirrorSnapshot {
    let active = flex
        .and_then(|f| MirrorProfile::from_token(&f.baseline.to_ascii_lowercase()))
        .unwrap_or(MirrorProfile::Private);
    let envelope = envelope_for(active);
    ProfileMirrorSnapshot::new(
        active,
        SINCE_UNTRACKED.to_string(),
        ACTOR_UNTRACKED.to_string(),
        envelope,
    )
}

/// Read + parse the persisted flex-profile state. Returns `None` on any
/// failure (absent / malformed) — the caller falls back to the R09535
/// default, never crashes.
fn read_flex_profile(path: &Path) -> Option<FlexProfile> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Atomically publish a serializable value to `dir/filename` via a
/// sibling tempfile + rename (same-dir rename is atomic on POSIX).
fn write_json_atomic<T: serde::Serialize>(
    dir: &Path,
    filename: &str,
    value: &T,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let target = dir.join(filename);
    let tmp = dir.join(format!(".{filename}.tmp"));
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &target)?;
    Ok(target)
}

/// Publish the active-profile mirror. Always published (the MS040 R09535
/// default — Private — is the honest value when no flex-profile exists).
fn publish_profile(mirror_dir: &Path, flex_path: &Path) {
    let flex = read_flex_profile(flex_path);
    let snapshot = project_snapshot(flex.as_ref());
    match write_json_atomic(mirror_dir, ACTIVE_PROFILE_FILE, &snapshot) {
        Ok(path) => debug!(
            path = %path.display(),
            active = snapshot.active.as_str(),
            "mirror export: active-profile published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: active-profile write failed; will retry"
        ),
    }
}

/// Publish the D-13 grants mirror from the daemon-resident grant
/// registry. Published ONLY when the resident store exists — an absent
/// store means no grants registry has been provisioned, so the dashboard
/// stays honestly offline rather than report a fabricated empty-online
/// state. TTL expiry is applied at publish time (presentation-only; the
/// resident store is read, never mutated, by the export).
fn publish_grants(mirror_dir: &Path, grants_store: &Path, now: OffsetDateTime) {
    if !grants_store.exists() {
        return;
    }
    let mut registry = match GrantRegistry::load(grants_store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %grants_store.display(),
                error = %e,
                "mirror export: grants store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    // Presentation-time lifecycle hygiene so the mirror never shows a
    // past-TTL grant as Active. In-memory only — selfdefctl owns the
    // durable store.
    let _ = registry.expire_due(now);
    match write_json_atomic(mirror_dir, GRANTS_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            grants = registry.grants().len(),
            active = registry.active_count(),
            "mirror export: grants published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: grants write failed; will retry"
        ),
    }
}

/// Publish the D-14 capability-tokens mirror from the daemon-resident
/// capability registry. Same honesty bar as grants: only published when
/// the resident store exists. TTL expiry is presentation-only.
fn publish_capability_tokens(mirror_dir: &Path, store: &Path, now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let mut registry = match CapabilityRegistry::load(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: capability-tokens store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    let _ = registry.expire_due(now);
    match write_json_atomic(mirror_dir, CAPABILITY_TOKENS_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            tokens = registry.tokens().len(),
            active = registry.active_count(),
            "mirror export: capability-tokens published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: capability-tokens write failed; will retry"
        ),
    }
}

/// One publish pass across every wired mirror domain. Best-effort —
/// per-domain failures are logged + retried next tick, never fatal.
fn publish_all(
    mirror_dir: &Path,
    flex_path: &Path,
    grants_store: &Path,
    capability_tokens_store: &Path,
) {
    let now = OffsetDateTime::now_utc();
    publish_profile(mirror_dir, flex_path);
    publish_grants(mirror_dir, grants_store, now);
    publish_capability_tokens(mirror_dir, capability_tokens_store, now);
}

/// M060 mirror-export loop (D-02 active-profile + D-13 grants + D-14
/// capability-tokens). Publishes once at startup, then every
/// [`MIRROR_EXPORT_INTERVAL_SECS`], cooperating with the daemon shutdown
/// signal (clean exit on cancel).
pub(crate) async fn run_mirror_export_loop(
    mirror_dir: PathBuf,
    flex_path: PathBuf,
    grants_store: PathBuf,
    capability_tokens_store: PathBuf,
    shutdown: CancellationToken,
) {
    publish_all(
        &mirror_dir,
        &flex_path,
        &grants_store,
        &capability_tokens_store,
    );
    let mut tick = tokio::time::interval(Duration::from_secs(MIRROR_EXPORT_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick — startup already published.
    tick.tick().await;
    info!(
        mirror_dir = %mirror_dir.display(),
        flex_path = %flex_path.display(),
        grants_store = %grants_store.display(),
        capability_tokens_store = %capability_tokens_store.display(),
        interval_secs = MIRROR_EXPORT_INTERVAL_SECS,
        "M060: mirror-export loop running (active-profile + grants + capability-tokens, read-only)"
    );
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("M060: shutdown signalled; exiting mirror-export loop");
                return;
            }
            _ = tick.tick() => publish_all(
                &mirror_dir, &flex_path, &grants_store, &capability_tokens_store
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_flex_profile::FlexProfile;

    fn flex_with_baseline(baseline: &str) -> FlexProfile {
        FlexProfile::new(baseline)
    }

    #[test]
    fn project_defaults_to_private_when_absent() {
        let snap = project_snapshot(None);
        assert_eq!(snap.active, MirrorProfile::Private);
        assert!(snap.history.is_empty());
        assert_eq!(snap.since, SINCE_UNTRACKED);
        assert_eq!(snap.actor, ACTOR_UNTRACKED);
    }

    #[test]
    fn project_maps_each_baseline() {
        for (token, expected) in [
            ("private", MirrorProfile::Private),
            ("fast", MirrorProfile::Fast),
            ("careful", MirrorProfile::Careful),
            ("autonomous", MirrorProfile::Autonomous),
            ("experimental", MirrorProfile::Experimental),
            ("production", MirrorProfile::Production),
        ] {
            let f = flex_with_baseline(token);
            assert_eq!(project_snapshot(Some(&f)).active, expected);
        }
    }

    #[test]
    fn project_uppercase_baseline_is_normalised() {
        let f = flex_with_baseline("Production");
        assert_eq!(project_snapshot(Some(&f)).active, MirrorProfile::Production);
    }

    #[test]
    fn project_unknown_baseline_falls_back_to_private() {
        let f = flex_with_baseline("some-custom-yaml");
        assert_eq!(project_snapshot(Some(&f)).active, MirrorProfile::Private);
    }

    #[test]
    fn envelope_is_derived_and_nonempty() {
        for p in [
            MirrorProfile::Private,
            MirrorProfile::Fast,
            MirrorProfile::Careful,
            MirrorProfile::Autonomous,
            MirrorProfile::Experimental,
            MirrorProfile::Production,
        ] {
            let env = envelope_for(p);
            assert!(env.contains("authority"), "got: {env}");
            assert!(env.contains("trust"), "got: {env}");
        }
    }

    #[test]
    fn atomic_write_round_trips() {
        let dir = std::env::temp_dir().join(format!("selfdef-mirror-test-{}", std::process::id()));
        let snap = project_snapshot(Some(&flex_with_baseline("autonomous")));
        let path = write_json_atomic(&dir, ACTIVE_PROFILE_FILE, &snap).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let back: ProfileMirrorSnapshot = serde_json::from_str(&body).unwrap();
        assert_eq!(back.active, MirrorProfile::Autonomous);
        back.validate_schema().unwrap();
        // No .tmp left behind.
        assert!(!dir.join(".active-profile.json.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_grants_skips_when_store_absent() {
        let dir =
            std::env::temp_dir().join(format!("selfdef-grants-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("grants.json");
        publish_grants(&dir, &store, OffsetDateTime::now_utc());
        // No resident store → no published mirror (honest offline).
        assert!(!dir.join(GRANTS_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_capability_tokens_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-cap-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("capability-tokens.json");
        publish_capability_tokens(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(CAPABILITY_TOKENS_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_capability_tokens_writes_resident_registry() {
        use selfdef_capability_registry::{
            CapabilityMirrorSnapshot, CapabilityRegistry, CapabilityRequest, TrustRing,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-cap-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("capability-tokens.json");
        let mut reg = CapabilityRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let req = CapabilityRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            allowed_tools: vec!["tests".into(), "builds".into()],
            trust_ring: TrustRing::Ring2,
            authority_level: selfdef_capability_registry::AuthorityLevel::L4Execute,
            sandbox_tier: "A".into(),
            parent_token_id: String::new(),
            ttl_seconds: 3600,
            signature: "sig".into(),
        };
        reg.issue(&req, "tok-1", "t1", now).unwrap();
        reg.activate("tok-1", now).unwrap();
        reg.save(&store).unwrap();

        publish_capability_tokens(&dir, &store, now);
        let published = dir.join(CAPABILITY_TOKENS_FILE);
        assert!(
            published.exists(),
            "capability-tokens mirror must be published"
        );
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: CapabilityMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.tokens.len(), 1);
        assert_eq!(snap.tokens[0].token_id, "tok-1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_grants_writes_resident_registry() {
        use selfdef_grant_registry::{
            GrantKind, GrantRegistry, GrantRequest, GrantsMirrorSnapshot,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-grants-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("grants.json");
        // Provision a resident registry with one active grant.
        let mut reg = GrantRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let req = GrantRequest {
            kind: GrantKind::Filesystem,
            scope: "/workspace/**".into(),
            reason: "author".into(),
            profile: "careful".into(),
            actor: "operator-fp".into(),
            ttl_seconds: 3600,
            signature: "sig".into(),
        };
        reg.issue(&req, "gr-1", "t1", now).unwrap();
        reg.activate("gr-1", now).unwrap();
        reg.save(&store).unwrap();

        publish_grants(&dir, &store, now);
        let published = dir.join(GRANTS_FILE);
        assert!(published.exists(), "grants mirror must be published");
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: GrantsMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.grants.len(), 1);
        assert_eq!(snap.grants[0].grant_id, "gr-1");
        std::fs::remove_dir_all(&dir).ok();
    }
}
