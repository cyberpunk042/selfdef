//! D-12 rules-mirror *live registry* read surface.
//!
//! - `GET /v1/rules/snapshot` — current daemon-resident snapshot of the
//!   nftables ruleset projected through `selfdef-rules-registry`. Data is
//!   produced by the daemon's `rules_collector_loop` (polls `nft -j list
//!   ruleset` every 30s; persists to `/var/lib/selfdef/rules.json` —
//!   honoring `SELFDEF_RULES_PATH` env override).
//!
//! No mutation endpoints: D-12 is READ-ONLY by doctrine (R10212). Rule
//! installation lives in `selfdefctl + nft` at the IPS layer (operator
//! MS003 only); this HTTP surface only OBSERVES the live projection.
//!
//! Companion to `crates/selfdef-cli/src/rules_registry.rs` (the CLI
//! verbs that wrap the same underlying read path) and
//! `crates/sovereign-os/scripts/mirror/selfdef-rules-mirror.py` (the
//! cross-repo D-12 consumer).

use std::path::PathBuf;

use axum::Json;
use axum::http::StatusCode;
use selfdef_rules_registry::{RulesMirrorSnapshot, RulesRegistry};

fn state_path() -> PathBuf {
    std::env::var("SELFDEF_RULES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(selfdef_rules_registry::DEFAULT_STATE_PATH))
}

/// `GET /v1/rules/snapshot` — full RulesMirrorSnapshot 1.0.0 payload.
///
/// Returns 200 + the snapshot JSON on success. The handler is honest-
/// offline: when the resident store is absent (e.g. daemon hasn't run
/// or the collector loop hasn't completed its first poll), an empty
/// registry is returned with `mirror_status` synthesized from the
/// payload contents on the consumer side.
pub(crate) async fn snapshot() -> Result<Json<RulesMirrorSnapshot>, (StatusCode, String)> {
    let path = state_path();
    let reg = RulesRegistry::load_from_path(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(reg.snapshot().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_rules_registry::{Disposition, RuleEntry, TrustRing};

    fn sample(ring: TrustRing, handle: u64, id: &str) -> RuleEntry {
        RuleEntry {
            handle,
            rule_id: id.into(),
            ring,
            table: "inet".into(),
            chain: format!("ring{}_egress", ring.index()),
            match_expr: "ip protocol tcp".into(),
            disposition: Disposition::Accept,
            priority: 0,
            packets: 5,
            bytes: 320,
            installed_at: "2027-01-15T08:00:00Z".into(),
            installed_by: None,
            signature: String::new(),
        }
    }

    #[tokio::test]
    async fn snapshot_handler_returns_empty_when_store_absent() {
        // Direct snapshot() can't be called without going through state_path;
        // exercise the underlying load to prove the handler's behavior is
        // honest-offline (no panic, returns empty registry).
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");
        let reg = RulesRegistry::load_from_path(&missing).unwrap();
        assert_eq!(reg.rule_count(), 0);
        let snap = reg.snapshot();
        assert_eq!(snap.rules.len(), 0);
        assert_eq!(snap.summaries.len(), 0);
    }

    #[tokio::test]
    async fn snapshot_handler_returns_populated_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let mut reg = RulesRegistry::new();
        reg.replace_rules(vec![
            sample(TrustRing::SovereignKernel, 1, "rule-001"),
            sample(TrustRing::CloudExternal, 2, "rule-002"),
        ]);
        reg.save_to_path(&path).unwrap();

        let loaded = RulesRegistry::load_from_path(&path).unwrap();
        let snap = loaded.snapshot();
        assert_eq!(snap.rules.len(), 2);
        assert_eq!(snap.summaries.len(), 2);
        // Wire-stable schema_version that the sovereign-os consumer pins.
        assert_eq!(snap.schema_version, selfdef_rules_registry::SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn malformed_store_yields_internal_server_error_shape() {
        // The handler maps any RegistryError → 500. Exercise via the
        // underlying load function.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, b"not json").unwrap();
        let err = RulesRegistry::load_from_path(&path).unwrap_err();
        // Map shape matches what the handler does inline (we don't
        // import StatusCode::INTERNAL_SERVER_ERROR in this branch
        // because we're proving the error path triggers, not the
        // axum response code which axum::Json wraps).
        assert!(!err.to_string().is_empty());
    }
}
