//! `selfdef-rules-registry` — daemon-resident registry of live nftables
//! rule state. The producer side of the M060 D-12 networking mirror.
//!
//! This closes the publisher gap: the `selfdef-rules-mirror` crate defines
//! the wire schema (`RulesMirrorSnapshot`, Ring 0..4 typed entries), but
//! nothing held the *set* of live rules or persisted it. This crate is
//! that registry:
//!
//! - holds a [`RulesMirrorSnapshot`] (the same wire type the mirror
//!   publishes — no parallel schema),
//! - persists atomically to `/var/lib/selfdef/rules.json`
//!   ([`DEFAULT_STATE_PATH`]) — the daemon-resident store the export
//!   loop reads,
//! - accepts a snapshot from a producer (the daemon's nft-reader; this
//!   crate does NOT itself shell out to nft, keeping the registry
//!   sovereignty-clean / testable / nft-version-independent),
//! - recomputes per-ring summaries from the rule list.
//!
//! Mutation is read-only-from-the-operator: this registry CONSUMES rules
//! from a daemon-side nft collector. The operator never appends rules
//! through this surface — rules are installed via selfdefctl + nft
//! commands at the IPS layer. Sovereign-os never mutates this — it
//! renders the published mirror READ-ONLY (MS043 R10212).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// Facade re-exports: consumers (daemon, CLI) depend only on this crate
// for the rules types, not on the underlying mirror crate.
pub use selfdef_rules_mirror::{
    Disposition, MirrorError, RingSummary, RuleEntry, RulesMirrorSnapshot,
    SCHEMA_VERSION, TrustRing,
};

/// Default on-disk path for the persisted registry (operator override
/// via daemon config / env). The daemon's mirror-export loop reads this
/// resident store and republishes it to the sovereign-os mirror dir.
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/rules.json";

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Persisted store was present but malformed.
    #[error("malformed rules store at {path}: {source}")]
    Malformed {
        /// Offending path.
        path: String,
        /// Parse error.
        source: serde_json::Error,
    },
    /// I/O failure on load/save.
    #[error("rules store io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// Timestamp formatting failed (should not happen with Rfc3339).
    #[error("timestamp format error: {0}")]
    TimeFormat(#[from] time::error::Format),
    /// Mirror validation failed (schema-version drift, etc.).
    #[error("mirror validation: {0}")]
    Validate(#[from] MirrorError),
}

/// Daemon-resident rules registry.
#[derive(Debug, Clone)]
pub struct RulesRegistry {
    snapshot: RulesMirrorSnapshot,
}

impl Default for RulesRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesRegistry {
    /// New empty registry (no rules), schema-version pinned.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: RulesMirrorSnapshot {
                schema_version: SCHEMA_VERSION.into(),
                captured_at: now_rfc3339(),
                summaries: Vec::new(),
                rules: Vec::new(),
                signature: String::new(),
            },
        }
    }

    /// Replace the live rule set with a fresh capture from the daemon's
    /// nft collector. Recomputes per-ring summaries from the new list.
    /// `captured_at` is set to now (RFC-3339).
    pub fn replace_rules(&mut self, rules: Vec<RuleEntry>) {
        self.snapshot.rules = rules;
        self.snapshot.captured_at = now_rfc3339();
        self.snapshot.summaries = self.snapshot.recompute_summaries();
    }

    /// Stamp a fresh capture-time without changing the rule list.
    /// Used by the export loop when the collector reports unchanged
    /// state (so the consumer knows the mirror is live, just static).
    pub fn touch(&mut self) {
        self.snapshot.captured_at = now_rfc3339();
    }

    /// The current snapshot the daemon export loop should publish.
    /// Read-only borrow; the registry owns the canonical state.
    #[must_use]
    pub fn snapshot(&self) -> &RulesMirrorSnapshot {
        &self.snapshot
    }

    /// Number of rules currently in the registry.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot.rules.len()
    }

    /// Per-ring rule counts (convenience accessor for the CLI's
    /// `selfdefctl rules-mirror summaries` verb).
    #[must_use]
    pub fn summaries(&self) -> &[RingSummary] {
        &self.snapshot.summaries
    }

    /// Load the registry from the on-disk store. Returns an empty
    /// registry if the file is absent (the operator hasn't enabled
    /// the export, or the daemon hasn't started — honest offline).
    ///
    /// # Errors
    /// Returns `RegistryError::Malformed` on parse failure,
    /// `RegistryError::Io` on read failure (other than not-found),
    /// `RegistryError::Validate` on schema-version drift.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        match std::fs::read(path) {
            Ok(bytes) => {
                let snapshot: RulesMirrorSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|e| RegistryError::Malformed {
                        path: path.display().to_string(),
                        source: e,
                    })?;
                snapshot.validate_schema()?;
                Ok(Self { snapshot })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Absent store → empty registry (honest-offline). Per the
                // sovereignty-graceful doctrine.
                Ok(Self::new())
            }
            Err(e) => Err(RegistryError::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    /// Atomically persist the registry to disk (write to a tempfile in
    /// the same directory, then rename — POSIX rename is atomic on the
    /// same filesystem).
    ///
    /// # Errors
    /// Returns `RegistryError::Io` on any I/O failure.
    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), RegistryError> {
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| RegistryError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
        let tmp = parent.join(format!(
            ".rules.json.tmp.{}",
            std::process::id()
        ));
        let bytes = serde_json::to_vec_pretty(&self.snapshot).map_err(|e| {
            // Should not happen — our snapshot is always serializable.
            RegistryError::Malformed {
                path: tmp.display().to_string(),
                source: e,
            }
        })?;
        std::fs::write(&tmp, &bytes).map_err(|e| RegistryError::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| RegistryError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(())
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule(ring: TrustRing, handle: u64, packets: u64) -> RuleEntry {
        RuleEntry {
            handle,
            rule_id: format!("rule-{handle:03}"),
            ring,
            table: "inet".into(),
            chain: format!("selfdef-{}", ring.index()),
            match_expr: "ip protocol tcp".into(),
            disposition: Disposition::Accept,
            priority: 100,
            packets,
            bytes: packets * 64,
            installed_at: "2027-01-15T08:00:00Z".into(),
            installed_by: Some("operator-fp".into()),
            signature: "sig".into(),
        }
    }

    #[test]
    fn new_registry_is_empty() {
        let r = RulesRegistry::new();
        assert_eq!(r.rule_count(), 0);
        assert!(r.summaries().is_empty());
        assert_eq!(r.snapshot().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn replace_rules_recomputes_summaries() {
        let mut r = RulesRegistry::new();
        r.replace_rules(vec![
            sample_rule(TrustRing::SovereignKernel, 1, 100),
            sample_rule(TrustRing::SovereignKernel, 2, 200),
            sample_rule(TrustRing::Sandboxed, 3, 50),
        ]);
        assert_eq!(r.rule_count(), 3);
        let sums = r.summaries();
        assert_eq!(sums.len(), 2);
        let k = sums.iter().find(|s| s.ring == TrustRing::SovereignKernel).unwrap();
        assert_eq!(k.rule_count, 2);
        assert_eq!(k.total_packets, 300);
        assert_eq!(k.total_bytes, 300 * 64);
    }

    #[test]
    fn replace_rules_updates_captured_at() {
        let mut r = RulesRegistry::new();
        let before = r.snapshot().captured_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(2));
        r.replace_rules(vec![sample_rule(TrustRing::CloudExternal, 7, 1)]);
        assert_ne!(r.snapshot().captured_at, before);
    }

    #[test]
    fn touch_updates_captured_at_without_changing_rules() {
        let mut r = RulesRegistry::new();
        r.replace_rules(vec![sample_rule(TrustRing::TrustedLocal, 1, 1)]);
        let rules_before = r.snapshot().rules.clone();
        let ts_before = r.snapshot().captured_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(2));
        r.touch();
        assert_eq!(r.snapshot().rules, rules_before);
        assert_ne!(r.snapshot().captured_at, ts_before);
    }

    #[test]
    fn save_then_load_round_trips() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("rules.json");

        let mut r = RulesRegistry::new();
        r.replace_rules(vec![
            sample_rule(TrustRing::SovereignKernel, 1, 100),
            sample_rule(TrustRing::CloudExternal, 99, 999),
        ]);
        r.save_to_path(&path).unwrap();

        let loaded = RulesRegistry::load_from_path(&path).unwrap();
        assert_eq!(loaded.rule_count(), 2);
        assert_eq!(loaded.snapshot().schema_version, SCHEMA_VERSION);
        assert_eq!(loaded.summaries().len(), 2);
    }

    #[test]
    fn load_absent_path_returns_empty_registry() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("does-not-exist.json");
        let r = RulesRegistry::load_from_path(&path).unwrap();
        assert_eq!(r.rule_count(), 0);
    }

    #[test]
    fn load_malformed_returns_error() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("bad.json");
        std::fs::write(&path, b"not json").unwrap();
        let err = RulesRegistry::load_from_path(&path).unwrap_err();
        assert!(matches!(err, RegistryError::Malformed { .. }));
    }

    #[test]
    fn load_schema_drift_returns_error() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("drift.json");
        let snap = RulesMirrorSnapshot {
            schema_version: "9.0.0".into(),
            captured_at: "2027-01-15T08:00:00Z".into(),
            summaries: vec![],
            rules: vec![],
            signature: String::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();
        let err = RulesRegistry::load_from_path(&path).unwrap_err();
        assert!(matches!(err, RegistryError::Validate(_)));
    }

    #[test]
    fn atomic_save_uses_rename_pattern() {
        // Verify the tempfile naming scheme: .rules.json.tmp.<pid>
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path().join("rules.json");
        let r = RulesRegistry::new();
        r.save_to_path(&path).unwrap();
        assert!(path.is_file());
        // After rename, no .tmp.* leftover.
        let leftovers: Vec<_> = std::fs::read_dir(tmpdir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn summaries_sorted_by_ring_index() {
        let mut r = RulesRegistry::new();
        r.replace_rules(vec![
            sample_rule(TrustRing::CloudExternal, 1, 1),
            sample_rule(TrustRing::SovereignKernel, 2, 2),
            sample_rule(TrustRing::Sandboxed, 3, 3),
        ]);
        let indices: Vec<u8> = r.summaries().iter().map(|s| s.ring.index()).collect();
        let mut sorted = indices.clone();
        sorted.sort();
        assert_eq!(indices, sorted);
    }
}
