//! `selfdef-actor-registry` — MS041 actor registry catalog.
//!
//! Per F04918 + R09654-R09757 + architecture:
//! - Actors are keyed by their MS003 key fingerprint.
//! - The registry is signed via MS003 (R09757-R09759).
//! - The on-disk surface is `/etc/selfdef/actors/registry.json`.
//! - Commits whose `actor` field is not in this registry are REJECTED
//!   per R09656 + F04839.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Canonical on-disk registry path per R09759.
pub const REGISTRY_PATH: &str = "/etc/selfdef/actors/registry.json";

/// Actor kinds — what role this actor plays in the IPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    /// Operator (human; primary signer).
    Operator,
    /// Guardian daemon (Ring 1 signed binary).
    Guardian,
    /// Sovereign-os runtime component.
    SovereignRuntime,
    /// Agent (sandboxed, Ring 3).
    Agent,
    /// External tool (untrusted, Ring 4).
    External,
}

/// One actor entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorEntry {
    /// MS003 minisign public-key fingerprint (hex, uppercase).
    pub fingerprint: String,
    /// Operator-readable name.
    pub name: String,
    /// Role classification.
    pub kind: ActorKind,
    /// ISO-8601 UTC registration timestamp.
    pub registered_at: String,
    /// ISO-8601 UTC revocation timestamp (empty if active).
    pub revoked_at: String,
    /// Free-form notes (mailto / contact / etc.).
    pub notes: String,
}

impl ActorEntry {
    /// True iff the actor is currently active (not revoked).
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_empty()
    }
}

/// Registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActorRegistry {
    /// Wire-stable schema version.
    pub schema_version: String,
    /// Actors keyed by fingerprint (uppercase hex).
    pub actors: BTreeMap<String, ActorEntry>,
    /// MS003 signature over the canonical-JSON encoding (R09757).
    pub signature: String,
}

impl Default for ActorRegistry {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            actors: BTreeMap::new(),
            signature: String::new(),
        }
    }
}

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Schema drift.
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected.
        expected: String,
        /// Observed.
        actual: String,
    },
    /// Actor entry has empty fingerprint.
    #[error("actor entry empty fingerprint not allowed")]
    EmptyFingerprint,
    /// Fingerprint contains non-hex characters.
    #[error("fingerprint contains non-hex characters: {0}")]
    InvalidFingerprint(String),
    /// Fingerprint length not 32 (RFC4648 hex = 16 bytes = 32 chars) or 64 (= 32 bytes).
    #[error("fingerprint length {0} not 32 or 64 hex chars")]
    InvalidFingerprintLength(usize),
    /// Two entries share the same fingerprint.
    #[error("duplicate fingerprint: {0}")]
    DuplicateFingerprint(String),
    /// Registry envelope unsigned (R09757 MS003 signing required).
    #[error("registry envelope unsigned (R09757 MS003 signing required)")]
    RegistryUnsigned,
    /// Actor field references a fingerprint absent from the registry.
    #[error("actor fingerprint not in registry: {0}")]
    ActorNotRegistered(String),
    /// Actor fingerprint is registered but revoked.
    #[error("actor fingerprint revoked: {fingerprint} (revoked at {revoked_at})")]
    ActorRevoked {
        /// Fingerprint.
        fingerprint: String,
        /// Revocation timestamp.
        revoked_at: String,
    },
}

fn validate_fingerprint(fp: &str) -> Result<(), RegistryError> {
    if fp.is_empty() {
        return Err(RegistryError::EmptyFingerprint);
    }
    if fp.len() != 32 && fp.len() != 64 {
        return Err(RegistryError::InvalidFingerprintLength(fp.len()));
    }
    for c in fp.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(RegistryError::InvalidFingerprint(fp.into()));
        }
    }
    // Uppercase normalisation: reject lowercase to keep the registry canonical.
    for c in fp.chars() {
        if c.is_ascii_lowercase() {
            return Err(RegistryError::InvalidFingerprint(fp.into()));
        }
    }
    Ok(())
}

impl ActorRegistry {
    /// Validate canonical invariants.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RegistryError::SchemaMismatch {
                expected: SCHEMA_VERSION.into(),
                actual: self.schema_version.clone(),
            });
        }
        if self.signature.is_empty() {
            return Err(RegistryError::RegistryUnsigned);
        }
        for (key, entry) in &self.actors {
            validate_fingerprint(key)?;
            if entry.fingerprint != *key {
                return Err(RegistryError::DuplicateFingerprint(format!(
                    "map-key {key} != entry-fingerprint {}",
                    entry.fingerprint
                )));
            }
        }
        Ok(())
    }

    /// Resolve an actor fingerprint to its entry per R09656.
    /// Returns `Err(ActorNotRegistered)` if absent.
    /// Returns `Err(ActorRevoked)` if registered but revoked.
    pub fn assert_active_actor(&self, fingerprint: &str) -> Result<&ActorEntry, RegistryError> {
        let entry = self
            .actors
            .get(fingerprint)
            .ok_or_else(|| RegistryError::ActorNotRegistered(fingerprint.into()))?;
        if !entry.is_active() {
            return Err(RegistryError::ActorRevoked {
                fingerprint: fingerprint.into(),
                revoked_at: entry.revoked_at.clone(),
            });
        }
        Ok(entry)
    }

    /// Insert a new actor entry. Refuses duplicates + invalid fingerprints.
    pub fn insert(&mut self, entry: ActorEntry) -> Result<(), RegistryError> {
        validate_fingerprint(&entry.fingerprint)?;
        if self.actors.contains_key(&entry.fingerprint) {
            return Err(RegistryError::DuplicateFingerprint(entry.fingerprint));
        }
        self.actors.insert(entry.fingerprint.clone(), entry);
        Ok(())
    }

    /// Revoke an actor's fingerprint (sets revoked_at).
    pub fn revoke(&mut self, fingerprint: &str, revoked_at: &str) -> Result<(), RegistryError> {
        let entry = self
            .actors
            .get_mut(fingerprint)
            .ok_or_else(|| RegistryError::ActorNotRegistered(fingerprint.into()))?;
        entry.revoked_at = revoked_at.into();
        Ok(())
    }

    /// Count of active (non-revoked) actors.
    pub fn active_count(&self) -> usize {
        self.actors.values().filter(|e| e.is_active()).count()
    }

    /// Count of actors by role.
    pub fn count_by_kind(&self, kind: ActorKind) -> usize {
        self.actors
            .values()
            .filter(|e| e.is_active() && e.kind == kind)
            .count()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    fn mk_entry(fp: &str, kind: ActorKind, revoked: bool) -> ActorEntry {
        ActorEntry {
            fingerprint: fp.into(),
            name: format!("actor-{}", &fp[..8]),
            kind,
            registered_at: "2026-05-19T00:00:00Z".into(),
            revoked_at: if revoked {
                "2026-05-19T03:00:00Z".into()
            } else {
                String::new()
            },
            notes: String::new(),
        }
    }

    fn fp32(prefix: char) -> String {
        // 32-char uppercase hex fingerprint
        let mut s = String::with_capacity(32);
        s.push(prefix.to_ascii_uppercase());
        for _ in 0..31 {
            s.push('A');
        }
        s
    }

    fn ok_registry() -> ActorRegistry {
        let mut r = ActorRegistry::default();
        r.signature = "ms003-sig".into();
        r.insert(mk_entry(&fp32('A'), ActorKind::Operator, false))
            .unwrap();
        r
    }

    // --- Fingerprint validation ---

    #[test]
    fn empty_fingerprint_rejected() {
        let err = validate_fingerprint("").unwrap_err();
        assert!(matches!(err, RegistryError::EmptyFingerprint));
    }

    #[test]
    fn lowercase_fingerprint_rejected() {
        let err = validate_fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidFingerprint(_)));
    }

    #[test]
    fn non_hex_fingerprint_rejected() {
        let err = validate_fingerprint("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidFingerprint(_)));
    }

    #[test]
    fn wrong_length_rejected() {
        let err = validate_fingerprint("AAAAA").unwrap_err();
        assert!(matches!(err, RegistryError::InvalidFingerprintLength(5)));
    }

    #[test]
    fn valid_32_and_64_char_fingerprints_accepted() {
        validate_fingerprint(&fp32('B')).unwrap();
        let fp64: String = std::iter::repeat_n('B', 64).collect();
        validate_fingerprint(&fp64).unwrap();
    }

    // --- Registry validation ---

    #[test]
    fn ok_registry_validates() {
        ok_registry().validate().unwrap();
    }

    #[test]
    fn unsigned_registry_rejected() {
        let mut r = ok_registry();
        r.signature = String::new();
        assert!(matches!(
            r.validate().unwrap_err(),
            RegistryError::RegistryUnsigned
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut r = ok_registry();
        r.schema_version = "9.9.9".into();
        assert!(matches!(
            r.validate().unwrap_err(),
            RegistryError::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn map_key_entry_fingerprint_mismatch_caught() {
        let mut r = ok_registry();
        // inject directly: map key Z..A but entry.fingerprint Y..B
        let mut e = mk_entry(&fp32('B'), ActorKind::Guardian, false);
        let key = fp32('C');
        e.fingerprint = fp32('D');
        r.actors.insert(key, e);
        assert!(matches!(
            r.validate().unwrap_err(),
            RegistryError::DuplicateFingerprint(_)
        ));
    }

    // --- insert / revoke ---

    #[test]
    fn insert_new_actor() {
        let mut r = ok_registry();
        r.insert(mk_entry(&fp32('B'), ActorKind::Guardian, false))
            .unwrap();
        assert_eq!(r.actors.len(), 2);
    }

    #[test]
    fn insert_duplicate_refused() {
        let mut r = ok_registry();
        let dup = mk_entry(&fp32('A'), ActorKind::Operator, false);
        assert!(matches!(
            r.insert(dup).unwrap_err(),
            RegistryError::DuplicateFingerprint(_)
        ));
    }

    #[test]
    fn revoke_marks_revoked_at() {
        let mut r = ok_registry();
        r.revoke(&fp32('A'), "2026-05-19T04:00:00Z").unwrap();
        let entry = r.actors.get(&fp32('A')).unwrap();
        assert!(!entry.is_active());
        assert_eq!(entry.revoked_at, "2026-05-19T04:00:00Z");
    }

    #[test]
    fn revoke_unknown_fingerprint_refused() {
        let mut r = ok_registry();
        let err = r.revoke(&fp32('Z'), "2026-05-19T04:00:00Z").unwrap_err();
        assert!(matches!(err, RegistryError::ActorNotRegistered(_)));
    }

    // --- assert_active_actor ---

    #[test]
    fn assert_active_returns_entry_for_registered_active() {
        let r = ok_registry();
        let entry = r.assert_active_actor(&fp32('A')).unwrap();
        assert!(entry.is_active());
        assert_eq!(entry.kind, ActorKind::Operator);
    }

    #[test]
    fn assert_active_refuses_unknown() {
        let r = ok_registry();
        let err = r.assert_active_actor(&fp32('Z')).unwrap_err();
        assert!(matches!(err, RegistryError::ActorNotRegistered(_)));
    }

    #[test]
    fn assert_active_refuses_revoked() {
        let mut r = ok_registry();
        r.revoke(&fp32('A'), "2026-05-19T04:00:00Z").unwrap();
        match r.assert_active_actor(&fp32('A')).unwrap_err() {
            RegistryError::ActorRevoked {
                fingerprint,
                revoked_at,
            } => {
                assert_eq!(fingerprint, fp32('A'));
                assert_eq!(revoked_at, "2026-05-19T04:00:00Z");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // --- count helpers ---

    #[test]
    fn active_count_and_count_by_kind() {
        let mut r = ok_registry();
        r.insert(mk_entry(&fp32('B'), ActorKind::Guardian, false))
            .unwrap();
        r.insert(mk_entry(&fp32('C'), ActorKind::Agent, false))
            .unwrap();
        r.insert(mk_entry(&fp32('D'), ActorKind::Agent, true))
            .unwrap();
        assert_eq!(r.active_count(), 3); // A, B, C
        assert_eq!(r.count_by_kind(ActorKind::Operator), 1);
        assert_eq!(r.count_by_kind(ActorKind::Guardian), 1);
        assert_eq!(r.count_by_kind(ActorKind::Agent), 1); // D is revoked
        assert_eq!(r.count_by_kind(ActorKind::External), 0);
    }

    // --- constants ---

    #[test]
    fn canonical_path_matches_r09759() {
        assert_eq!(REGISTRY_PATH, "/etc/selfdef/actors/registry.json");
    }

    #[test]
    fn actor_kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ActorKind::SovereignRuntime).unwrap(),
            "\"sovereign-runtime\""
        );
        assert_eq!(
            serde_json::to_string(&ActorKind::Operator).unwrap(),
            "\"operator\""
        );
        assert_eq!(
            serde_json::to_string(&ActorKind::External).unwrap(),
            "\"external\""
        );
    }

    // --- Serde ---

    #[test]
    fn registry_serde_roundtrip() {
        let r = ok_registry();
        let j = serde_json::to_string(&r).unwrap();
        let back: ActorRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}
