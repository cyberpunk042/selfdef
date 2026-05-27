//! `selfdef-credential-rotation-policy` — periodic credential rotation.
//!
//! Each credential id has: `created_ms`, a `max_age_ms`, and a
//! `grace_ms` window. `check(cred_id, now_ms)` returns:
//!   * `Fresh { remaining_ms }` — under max_age.
//!   * `DueForRotation { overdue_ms, grace_remaining_ms }` — past
//!     max_age but within grace.
//!   * `Expired { overdue_ms }` — past max_age + grace.
//!   * `Unknown` — not registered.
//!
//! `rotate(cred_id, now_ms)` records a successful rotation
//! (resets `created_ms`).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// One credential's rotation config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// When created / last rotated.
    pub created_ms: u64,
    /// Maximum age before rotation due.
    pub max_age_ms: u64,
    /// Grace window past max_age before expiry.
    pub grace_ms: u64,
    /// Total rotations recorded.
    pub rotations: u64,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRotationPolicy {
    /// Schema version.
    pub schema_version: String,
    /// cred_id → cred.
    pub credentials: BTreeMap<String, Credential>,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RotationVerdict {
    /// Fresh.
    Fresh {
        /// remaining.
        remaining_ms: u64,
    },
    /// Due (within grace).
    DueForRotation {
        /// how overdue.
        overdue_ms: u64,
        /// grace remaining.
        grace_remaining_ms: u64,
    },
    /// Expired (past grace).
    Expired {
        /// total overdue past max_age.
        overdue_ms: u64,
    },
    /// Unknown.
    Unknown,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty cred id.
    #[error("credential id empty")]
    EmptyId,
    /// Zero max_age.
    #[error("max_age must be > 0")]
    ZeroMaxAge,
    /// Unknown credential.
    #[error("unknown credential: {0}")]
    UnknownCredential(String),
}

impl CredentialRotationPolicy {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            credentials: BTreeMap::new(),
        }
    }

    /// Register a credential.
    pub fn register(
        &mut self,
        cred_id: &str,
        created_ms: u64,
        max_age_ms: u64,
        grace_ms: u64,
    ) -> Result<(), RotationError> {
        if cred_id.is_empty() {
            return Err(RotationError::EmptyId);
        }
        if max_age_ms == 0 {
            return Err(RotationError::ZeroMaxAge);
        }
        self.credentials.insert(
            cred_id.into(),
            Credential {
                created_ms,
                max_age_ms,
                grace_ms,
                rotations: 0,
            },
        );
        Ok(())
    }

    /// Record a rotation.
    pub fn rotate(&mut self, cred_id: &str, now_ms: u64) -> Result<(), RotationError> {
        let c = self
            .credentials
            .get_mut(cred_id)
            .ok_or_else(|| RotationError::UnknownCredential(cred_id.into()))?;
        c.created_ms = now_ms;
        c.rotations = c.rotations.saturating_add(1);
        Ok(())
    }

    /// Check status.
    pub fn check(&self, cred_id: &str, now_ms: u64) -> RotationVerdict {
        let Some(c) = self.credentials.get(cred_id) else {
            return RotationVerdict::Unknown;
        };
        let age = now_ms.saturating_sub(c.created_ms);
        if age < c.max_age_ms {
            return RotationVerdict::Fresh {
                remaining_ms: c.max_age_ms - age,
            };
        }
        let overdue = age - c.max_age_ms;
        if overdue < c.grace_ms {
            RotationVerdict::DueForRotation {
                overdue_ms: overdue,
                grace_remaining_ms: c.grace_ms - overdue,
            }
        } else {
            RotationVerdict::Expired {
                overdue_ms: overdue,
            }
        }
    }

    /// All credentials currently due or expired.
    pub fn needs_attention(&self, now_ms: u64) -> Vec<String> {
        self.credentials
            .iter()
            .filter(|(_, c)| {
                let age = now_ms.saturating_sub(c.created_ms);
                age >= c.max_age_ms
            })
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RotationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RotationError::SchemaMismatch);
        }
        for (id, c) in &self.credentials {
            if id.is_empty() {
                return Err(RotationError::EmptyId);
            }
            if c.max_age_ms == 0 {
                return Err(RotationError::ZeroMaxAge);
            }
        }
        Ok(())
    }
}

impl Default for CredentialRotationPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_when_young() {
        let mut p = CredentialRotationPolicy::new();
        p.register("k", 0, 1000, 100).unwrap();
        assert!(matches!(
            p.check("k", 500),
            RotationVerdict::Fresh { remaining_ms: 500 }
        ));
    }

    #[test]
    fn due_in_grace_window() {
        let mut p = CredentialRotationPolicy::new();
        p.register("k", 0, 1000, 100).unwrap();
        match p.check("k", 1050) {
            RotationVerdict::DueForRotation {
                overdue_ms,
                grace_remaining_ms,
            } => {
                assert_eq!(overdue_ms, 50);
                assert_eq!(grace_remaining_ms, 50);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn expired_past_grace() {
        let mut p = CredentialRotationPolicy::new();
        p.register("k", 0, 1000, 100).unwrap();
        match p.check("k", 2000) {
            RotationVerdict::Expired { overdue_ms } => assert_eq!(overdue_ms, 1000),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_credential() {
        let p = CredentialRotationPolicy::new();
        assert_eq!(p.check("nope", 0), RotationVerdict::Unknown);
    }

    #[test]
    fn rotate_resets_clock() {
        let mut p = CredentialRotationPolicy::new();
        p.register("k", 0, 1000, 100).unwrap();
        p.rotate("k", 2000).unwrap();
        // Right after rotation: fresh.
        assert!(matches!(
            p.check("k", 2500),
            RotationVerdict::Fresh { remaining_ms: 500 }
        ));
        assert_eq!(p.credentials["k"].rotations, 1);
    }

    #[test]
    fn needs_attention_lists_due_and_expired() {
        let mut p = CredentialRotationPolicy::new();
        p.register("a", 0, 1000, 100).unwrap();
        p.register("b", 5000, 1000, 100).unwrap();
        // At now=2000: a is past max_age, b is still fresh.
        let l = p.needs_attention(2000);
        assert!(l.contains(&"a".to_string()));
        assert!(!l.contains(&"b".to_string()));
    }

    #[test]
    fn rotate_unknown_rejected() {
        let mut p = CredentialRotationPolicy::new();
        assert!(matches!(
            p.rotate("nope", 0).unwrap_err(),
            RotationError::UnknownCredential(_)
        ));
    }

    #[test]
    fn zero_max_age_rejected() {
        let mut p = CredentialRotationPolicy::new();
        assert!(matches!(
            p.register("k", 0, 0, 0).unwrap_err(),
            RotationError::ZeroMaxAge
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut p = CredentialRotationPolicy::new();
        assert!(matches!(
            p.register("", 0, 1, 0).unwrap_err(),
            RotationError::EmptyId
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = CredentialRotationPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RotationError::SchemaMismatch
        ));
    }

    #[test]
    fn rotation_serde_roundtrip() {
        let mut p = CredentialRotationPolicy::new();
        p.register("k", 0, 1000, 100).unwrap();
        p.rotate("k", 500).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: CredentialRotationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
