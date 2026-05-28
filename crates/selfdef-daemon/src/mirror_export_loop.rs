//! M060 D-02 (R10063-R10068): daemon-side cross-repo mirror export.
//!
//! When `[deployment].selfdef_mirror_dir` is set, the daemon publishes
//! the MS007 typed-mirror artifacts READ-ONLY into that directory for
//! the sovereign-os cockpit dashboards to render. This first increment
//! publishes the active authority-profile snapshot
//! (`active-profile.json`), projected from the live flex-profile state
//! (MS011 Z-3 / SDD-026) + the MS040 authority envelope.
//!
//! Project boundary: this is IPS state published READ-ONLY. sovereign-os
//! NEVER mutates it — profile switches are `selfdefctl` + MS003 verbs on
//! this (IPS) side only (MS043 R10212). The other four mirror domains
//! (grants/quarantine/capability/sandbox) are NOT published here: their
//! registries are not yet daemon-resident, so their dashboards stay
//! honestly offline rather than report fabricated empty-online state.
//!
//! The pure projection is in [`project_snapshot`] (no I/O, unit-tested
//! in isolation). The loop does file I/O + tokio ticks + cooperates
//! with the daemon shutdown signal, mirroring `hardware_probe_loop`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_flex_profile::FlexProfile;
use selfdef_profile_authority_gate::Profile as GateProfile;
use selfdef_profile_mirror::{Profile as MirrorProfile, ProfileMirrorSnapshot};
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

/// Atomically publish the snapshot to `dir/active-profile.json` via a
/// sibling tempfile + rename (same-dir rename is atomic on POSIX).
fn write_snapshot_atomic(dir: &Path, snapshot: &ProfileMirrorSnapshot) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let target = dir.join(ACTIVE_PROFILE_FILE);
    let tmp = dir.join(".active-profile.json.tmp");
    let body = serde_json::to_string_pretty(snapshot)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &target)?;
    Ok(target)
}

/// One publish pass: read live state, project, atomic-write. Best-effort
/// — a write failure is logged + retried next tick, never fatal.
fn publish_once(mirror_dir: &Path, flex_path: &Path) {
    let flex = read_flex_profile(flex_path);
    let snapshot = project_snapshot(flex.as_ref());
    match write_snapshot_atomic(mirror_dir, &snapshot) {
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

/// M060 D-02 mirror-export loop. Publishes once at startup, then every
/// [`MIRROR_EXPORT_INTERVAL_SECS`], cooperating with the daemon shutdown
/// signal (clean exit on cancel).
pub(crate) async fn run_mirror_export_loop(
    mirror_dir: PathBuf,
    flex_path: PathBuf,
    shutdown: CancellationToken,
) {
    publish_once(&mirror_dir, &flex_path);
    let mut tick = tokio::time::interval(Duration::from_secs(MIRROR_EXPORT_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick — startup already published.
    tick.tick().await;
    info!(
        mirror_dir = %mirror_dir.display(),
        flex_path = %flex_path.display(),
        interval_secs = MIRROR_EXPORT_INTERVAL_SECS,
        "M060 D-02: mirror-export loop running (active-profile, read-only)"
    );
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("M060 D-02: shutdown signalled; exiting mirror-export loop");
                return;
            }
            _ = tick.tick() => publish_once(&mirror_dir, &flex_path),
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
        let path = write_snapshot_atomic(&dir, &snap).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let back: ProfileMirrorSnapshot = serde_json::from_str(&body).unwrap();
        assert_eq!(back.active, MirrorProfile::Autonomous);
        back.validate_schema().unwrap();
        // No .tmp left behind.
        assert!(!dir.join(".active-profile.json.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
