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
//!   resident store exists.
//! - **D-15 sandboxes** (`sandboxes.json`) — the daemon-resident
//!   sandbox-allocation registry (`selfdef-sandbox-registry`, MS036
//!   A/B/C/D × MS032 9-tier indices). Same honesty bar.
//! - **D-17 quarantine** (`quarantine.json`) — the daemon-resident
//!   quarantine registry (`selfdef-quarantine-registry`). Entries are
//!   daemon-populated by MS042 declaration-vs-observed detection;
//!   operator mutations are release/forfeit overrides only. Same
//!   honesty bar.
//! - **D-18 trust-scores** (`trust-scores.json`) — the daemon-resident
//!   per-tool trust-score registry (`selfdef-trust-score-registry`,
//!   composing the engine's `canonical_delta`). Daemon-populated by
//!   scoring events; operator mutations are manual deltas (override).
//!   Same honesty bar.
//! - **D-16 audit** (`audit.json`) — the daemon-resident MS016 audit-
//!   chain registry (`selfdef-audit-registry`, SHA-256 hash chain +
//!   bounded-tail spans + integrity report). Append-only by MS016
//!   R03567 doctrine; operator has no mutation surface.
//! - **D-12 rules** (`rules.json`) — the daemon-resident nftables rule
//!   registry (`selfdef-rules-registry`, MS024 nftables + MS038 network
//!   boundary + MS039 Ring 0..4 trust topology). Daemon-populated by an
//!   nft collector; the operator never appends rules through this
//!   surface (rules are installed via selfdefctl + nft commands at the
//!   IPS layer). Same honesty bar.
//!
//! Project boundary: IPS state
//! published READ-ONLY. sovereign-os NEVER mutates — operator mutations
//! are `selfdefctl` + MS003 verbs on this (IPS) side only (MS043 R10212).
//!
//! The pure projection is in [`project_snapshot`] (no I/O, unit-tested
//! in isolation). The loop does file I/O + tokio ticks + cooperates
//! with the daemon shutdown signal, mirroring `hardware_probe_loop`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use selfdef_audit_registry::AuditRegistry;
use selfdef_capability_registry::CapabilityRegistry;
use selfdef_flex_profile::FlexProfile;
use selfdef_grant_registry::GrantRegistry;
use selfdef_profile_authority_gate::Profile as GateProfile;
use selfdef_profile_mirror::{Profile as MirrorProfile, ProfileMirrorSnapshot};
use selfdef_quarantine_registry::QuarantineRegistry;
use selfdef_rules_registry::RulesRegistry;
use selfdef_sandbox_registry::SandboxRegistry;
use selfdef_trust_score_registry::TrustScoreRegistry;
use selfdef_tui_mirror::canonical_snapshot as canonical_tui_snapshot;
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

/// Published sandboxes artifact filename, wire-stable with the
/// sovereign-os D-15 consumer (`scripts/mirror/selfdef-sandbox-mirror.py`).
const SANDBOXES_FILE: &str = "sandboxes.json";

/// Published quarantine artifact filename, wire-stable with the
/// sovereign-os D-17 consumer (`scripts/mirror/selfdef-quarantine-mirror.py`).
const QUARANTINE_FILE: &str = "quarantine.json";

/// Published trust-scores artifact filename, wire-stable with the
/// sovereign-os D-18 consumer (`scripts/mirror/selfdef-trust-score-mirror.py`).
const TRUST_SCORES_FILE: &str = "trust-scores.json";

/// Published audit artifact filename, wire-stable with the sovereign-os
/// D-16 audit-chain consumer.
const AUDIT_FILE: &str = "audit.json";

/// Published rules artifact filename, wire-stable with the sovereign-os
/// D-12 networking consumer (`scripts/mirror/selfdef-rules-mirror.py`
/// when shipped).
const RULES_FILE: &str = "rules.json";

/// Published TUI-mirror artifact filename — the canonical 4-panel
/// schema per MS043 R10141 + F05081, consumed by the sovereign-os
/// minimal-web mirroring path (R10170 "same 4-panel layout as TUI").
const TUI_FILE: &str = "tui.json";

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

/// Publish the D-15 sandboxes mirror from the daemon-resident sandbox
/// registry. Same honesty bar: only published when the resident store
/// exists. TTL expiry is presentation-only.
fn publish_sandboxes(mirror_dir: &Path, store: &Path, now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let mut registry = match SandboxRegistry::load(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: sandboxes store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    let _ = registry.expire_due(now);
    match write_json_atomic(mirror_dir, SANDBOXES_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            allocations = registry.allocations().len(),
            running = registry.running_count(),
            "mirror export: sandboxes published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: sandboxes write failed; will retry"
        ),
    }
}

/// Publish the D-17 quarantine mirror from the daemon-resident
/// quarantine registry. Same honesty bar: only published when the
/// resident store exists. Unlike grants/capability/sandbox, quarantine
/// entries are daemon-populated by MS042 detection (record_block);
/// operator mutations are release/forfeit overrides only.
fn publish_quarantine(mirror_dir: &Path, store: &Path, now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let registry = match QuarantineRegistry::load(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: quarantine store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    let _ = now; // quarantine has no presentation-time expiry yet
    match write_json_atomic(mirror_dir, QUARANTINE_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            entries = registry.entries().len(),
            quarantined = registry.quarantined_count(),
            "mirror export: quarantine published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: quarantine write failed; will retry"
        ),
    }
}

/// Publish the D-16 audit mirror from the daemon-resident audit-chain
/// registry. Same honesty bar: only published when the resident store
/// exists. Daemon-populated by every IPS decision (append_span).
fn publish_audit(mirror_dir: &Path, store: &Path, _now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let registry = match AuditRegistry::load(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: audit store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    match write_json_atomic(mirror_dir, AUDIT_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            spans = registry.spans().len(),
            total_entries = registry.total_entries(),
            "mirror export: audit published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: audit write failed; will retry"
        ),
    }
}

/// Publish the canonical 4-panel TUI mirror per MS043 R10141 / F05081
/// / R10298 ("a dashboard should not show vanity graphs"). This is a
/// STATIC-SHAPE snapshot — the layout is fixed by doctrine. Always
/// publish (no resident-store gate); the captured_at refreshes each
/// tick so the consumer can detect a live mirror-export loop.
fn publish_tui(mirror_dir: &Path, now: OffsetDateTime) {
    let captured_at = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let snap = canonical_tui_snapshot(env!("CARGO_PKG_VERSION"), &captured_at);
    match write_json_atomic(mirror_dir, TUI_FILE, &snap) {
        Ok(path) => debug!(
            path = %path.display(),
            panels = snap.panels.len(),
            "mirror export: tui published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: tui write failed; will retry"
        ),
    }
}

/// Publish the D-12 rules mirror from the daemon-resident nftables
/// rule registry. Same honesty bar: only published when the resident
/// store exists. Daemon-populated by the nft collector loop; the
/// operator never appends rules through this surface.
fn publish_rules(mirror_dir: &Path, store: &Path, _now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let registry = match RulesRegistry::load_from_path(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: rules store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    match write_json_atomic(mirror_dir, RULES_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            rules = registry.rule_count(),
            "mirror export: rules published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: rules write failed; will retry"
        ),
    }
}

/// Publish the D-18 trust-scores mirror from the daemon-resident
/// trust-score registry. Same honesty bar: only published when the
/// resident store exists. Daemon-populated by scoring events.
fn publish_trust_scores(mirror_dir: &Path, store: &Path, _now: OffsetDateTime) {
    if !store.exists() {
        return;
    }
    let registry = match TrustScoreRegistry::load(store) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                store = %store.display(),
                error = %e,
                "mirror export: trust-scores store unreadable; skipping (dashboard stays last-known)"
            );
            return;
        }
    };
    match write_json_atomic(mirror_dir, TRUST_SCORES_FILE, registry.snapshot()) {
        Ok(path) => debug!(
            path = %path.display(),
            tools = registry.tools().len(),
            "mirror export: trust-scores published"
        ),
        Err(e) => warn!(
            dir = %mirror_dir.display(),
            error = %e,
            "mirror export: trust-scores write failed; will retry"
        ),
    }
}

/// One publish pass across every wired mirror domain. Best-effort —
/// per-domain failures are logged + retried next tick, never fatal.
#[allow(clippy::too_many_arguments)] // one path per mirror domain
fn publish_all(
    mirror_dir: &Path,
    flex_path: &Path,
    grants_store: &Path,
    capability_tokens_store: &Path,
    sandboxes_store: &Path,
    quarantine_store: &Path,
    trust_scores_store: &Path,
    audit_store: &Path,
    rules_store: &Path,
) {
    let now = OffsetDateTime::now_utc();
    publish_profile(mirror_dir, flex_path);
    publish_grants(mirror_dir, grants_store, now);
    publish_capability_tokens(mirror_dir, capability_tokens_store, now);
    publish_sandboxes(mirror_dir, sandboxes_store, now);
    publish_quarantine(mirror_dir, quarantine_store, now);
    publish_trust_scores(mirror_dir, trust_scores_store, now);
    publish_audit(mirror_dir, audit_store, now);
    publish_rules(mirror_dir, rules_store, now);
    publish_tui(mirror_dir, now);
}

/// M060 mirror-export loop (D-02 active-profile + D-13 grants + D-14
/// capability-tokens). Publishes once at startup, then every
/// [`MIRROR_EXPORT_INTERVAL_SECS`], cooperating with the daemon shutdown
/// signal (clean exit on cancel).
#[allow(clippy::too_many_arguments)] // one path per mirror domain
pub(crate) async fn run_mirror_export_loop(
    mirror_dir: PathBuf,
    flex_path: PathBuf,
    grants_store: PathBuf,
    capability_tokens_store: PathBuf,
    sandboxes_store: PathBuf,
    quarantine_store: PathBuf,
    trust_scores_store: PathBuf,
    audit_store: PathBuf,
    rules_store: PathBuf,
    shutdown: CancellationToken,
) {
    publish_all(
        &mirror_dir,
        &flex_path,
        &grants_store,
        &capability_tokens_store,
        &sandboxes_store,
        &quarantine_store,
        &trust_scores_store,
        &audit_store,
        &rules_store,
    );
    // MS007 cli-mirror is async (shells out to selfdefctl) — published
    // alongside the sync mirrors but on the async path. First call
    // primes the cache; subsequent ticks write the cached buffer.
    crate::cli_mirror_publisher::publish_cli(&mirror_dir).await;
    let mut tick = tokio::time::interval(Duration::from_secs(MIRROR_EXPORT_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate first tick — startup already published.
    tick.tick().await;
    info!(
        mirror_dir = %mirror_dir.display(),
        flex_path = %flex_path.display(),
        grants_store = %grants_store.display(),
        capability_tokens_store = %capability_tokens_store.display(),
        sandboxes_store = %sandboxes_store.display(),
        quarantine_store = %quarantine_store.display(),
        trust_scores_store = %trust_scores_store.display(),
        audit_store = %audit_store.display(),
        rules_store = %rules_store.display(),
        interval_secs = MIRROR_EXPORT_INTERVAL_SECS,
        "M060: mirror-export loop running (active-profile + grants + capability-tokens + sandboxes + quarantine + trust-scores + audit + rules + tui + cli, read-only) — 10/10 mirror domains wired (D-02/12/13/14/15/16/17/18 + tui-layout + cli-schema)"
    );
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("M060: shutdown signalled; exiting mirror-export loop");
                return;
            }
            _ = tick.tick() => {
                publish_all(
                    &mirror_dir,
                    &flex_path,
                    &grants_store,
                    &capability_tokens_store,
                    &sandboxes_store,
                    &quarantine_store,
                    &trust_scores_store,
                    &audit_store,
                    &rules_store,
                );
                crate::cli_mirror_publisher::publish_cli(&mirror_dir).await;
            }
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
    fn publish_audit_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-audit-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("audit.json");
        publish_audit(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(AUDIT_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_audit_writes_resident_registry() {
        use selfdef_audit_registry::{
            AuditMirrorSnapshot, AuditRegistry, OcsfCategory, PolicyOutcome, SpanAppend,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-audit-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("audit.json");
        let mut reg = AuditRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let span = SpanAppend {
            trace_id: "t1".into(),
            profile: "careful".into(),
            model: "qwen3-coder-32b".into(),
            provider: "local-cuda".into(),
            hardware: "3090_logic".into(),
            tokens_prompt: 100,
            tokens_completion: 50,
            latency_ms: 1500,
            cost_millicents: 1,
            risk_score: 5,
            memory_refs: vec![],
            tool_refs: vec!["tests".into()],
            policy_result: PolicyOutcome::Allow,
            branch_id: "b1".into(),
            ocsf_category: OcsfCategory::ProcessActivity,
            signature: "sig".into(),
        };
        reg.append_span(&span, now).unwrap();
        reg.save(&store).unwrap();

        publish_audit(&dir, &store, now);
        let published = dir.join(AUDIT_FILE);
        assert!(published.exists());
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: AuditMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.spans.len(), 1);
        assert_eq!(snap.spans[0].trace_id, "t1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_tui_always_writes_canonical_4_panel_snapshot() {
        use selfdef_tui_mirror::{PanelKind, TuiMirrorSnapshot};
        let dir = std::env::temp_dir().join(format!("selfdef-tui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        publish_tui(&dir, now);
        let published = dir.join(TUI_FILE);
        assert!(
            published.exists(),
            "tui mirror must always publish (static shape)"
        );
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: TuiMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        snap.validate_doctrine().unwrap();
        snap.validate_layout().unwrap();
        assert_eq!(snap.panels.len(), 4);
        let kinds: Vec<PanelKind> = snap.panels.iter().map(|p| p.kind).collect();
        assert!(kinds.contains(&PanelKind::Rules));
        assert!(kinds.contains(&PanelKind::Authority));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_rules_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-rules-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("rules.json");
        publish_rules(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(RULES_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_rules_writes_resident_registry() {
        use selfdef_rules_registry::{
            Disposition, RuleEntry, RulesMirrorSnapshot, RulesRegistry, TrustRing,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-rules-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("rules.json");
        let mut reg = RulesRegistry::new();
        reg.replace_rules(vec![RuleEntry {
            handle: 1,
            rule_id: "rule-001".into(),
            ring: TrustRing::SovereignKernel,
            table: "inet".into(),
            chain: "selfdef-ring0".into(),
            match_expr: "ip protocol tcp".into(),
            disposition: Disposition::Accept,
            priority: 100,
            packets: 10,
            bytes: 640,
            installed_at: "2027-01-15T08:00:00Z".into(),
            installed_by: Some("operator-fp".into()),
            signature: "sig".into(),
        }]);
        reg.save_to_path(&store).unwrap();

        publish_rules(&dir, &store, OffsetDateTime::now_utc());
        let published = dir.join(RULES_FILE);
        assert!(published.exists());
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: RulesMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.rules.len(), 1);
        assert_eq!(snap.summaries.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_trust_scores_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-trust-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("trust-scores.json");
        publish_trust_scores(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(TRUST_SCORES_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_trust_scores_writes_resident_registry() {
        use selfdef_trust_score_registry::{
            DeltaReason, TrustScoreMirrorSnapshot, TrustScoreRegistry,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-trust-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("trust-scores.json");
        let mut reg = TrustScoreRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        reg.admit("rg", "operator-fp", 750, now).unwrap();
        reg.record_delta("rg", DeltaReason::SuccessfulExecution, "t1", now)
            .unwrap();
        reg.save(&store).unwrap();

        publish_trust_scores(&dir, &store, now);
        let published = dir.join(TRUST_SCORES_FILE);
        assert!(published.exists());
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: TrustScoreMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.tools.len(), 1);
        assert_eq!(snap.tools[0].tool, "rg");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_quarantine_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-qrn-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("quarantine.json");
        publish_quarantine(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(QUARANTINE_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_quarantine_writes_resident_registry() {
        use selfdef_quarantine_registry::{
            BlockReport, MismatchDetail, MismatchField, MismatchSeverity, QuarantineMirrorSnapshot,
            QuarantineRegistry,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-qrn-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("quarantine.json");
        let mut reg = QuarantineRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let report = BlockReport {
            tool: "rg".into(),
            declarer: "operator-fp".into(),
            capability_token_id: "tok-1".into(),
            mismatches: vec![MismatchDetail {
                field: MismatchField::ReadPaths,
                declared: "/safe".into(),
                observed: "/etc/passwd".into(),
                first_observed_at: "2027-01-15T07:59:00Z".into(),
                severity: MismatchSeverity::Critical,
            }],
        };
        reg.record_block(&report, "q-1", "t1", now).unwrap();
        reg.save(&store).unwrap();

        publish_quarantine(&dir, &store, now);
        let published = dir.join(QUARANTINE_FILE);
        assert!(published.exists());
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: QuarantineMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(snap.entries[0].quarantine_id, "q-1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_sandboxes_skips_when_store_absent() {
        let dir = std::env::temp_dir().join(format!("selfdef-sbx-absent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("sandboxes.json");
        publish_sandboxes(&dir, &store, OffsetDateTime::now_utc());
        assert!(!dir.join(SANDBOXES_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn publish_sandboxes_writes_resident_registry() {
        use selfdef_sandbox_registry::{
            AllocationRequest, IsolationPrimitive, SandboxMirrorSnapshot, SandboxRegistry,
            SandboxTier, ms032_range_for,
        };
        let dir = std::env::temp_dir().join(format!("selfdef-sbx-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("sandboxes.json");
        let mut reg = SandboxRegistry::new();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let (lo, _) = ms032_range_for(SandboxTier::TierA);
        let req = AllocationRequest {
            actor: "operator-fp".into(),
            profile: "careful".into(),
            tier: SandboxTier::TierA,
            ms032_tier: lo,
            isolation: IsolationPrimitive::HostSeccomp,
            tool: "rg".into(),
            capability_token_id: "tok-1".into(),
            ttl_seconds: 3600,
            signature: "sig".into(),
        };
        reg.allocate(&req, "alloc-1", "t1", now).unwrap();
        reg.start("alloc-1", now).unwrap();
        reg.save(&store).unwrap();

        publish_sandboxes(&dir, &store, now);
        let published = dir.join(SANDBOXES_FILE);
        assert!(published.exists(), "sandboxes mirror must be published");
        let body = std::fs::read_to_string(&published).unwrap();
        let snap: SandboxMirrorSnapshot = serde_json::from_str(&body).unwrap();
        snap.validate_schema().unwrap();
        assert_eq!(snap.allocations.len(), 1);
        assert_eq!(snap.allocations[0].allocation_id, "alloc-1");
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
