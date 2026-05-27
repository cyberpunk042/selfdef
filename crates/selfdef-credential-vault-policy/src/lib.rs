//! `selfdef-credential-vault-policy` — credential-unseal authority.
//!
//! Each credential carries a class, an `allowed_ops` set, a quota
//! `max_unseal_per_hour`, and an `operator_approval_required` flag.
//! `unseal()` checks: op-class permitted ∧ quota window not full
//! ∧ approval present (if required). A sliding-window list of
//! unseal timestamps enforces the per-hour quota.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Credential class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialClass {
    /// Local API key (low blast radius).
    Local,
    /// Cloud API key (medium blast radius).
    Cloud,
    /// Master credential (high blast radius — vault, root keys).
    Master,
    /// Recovery credential (only for disaster recovery).
    Recovery,
}

/// Operation class that may use a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationClass {
    /// Read-only lookup.
    Read,
    /// Write / mutation.
    Write,
    /// Administrative (rotate, revoke).
    Admin,
    /// Emergency / recovery.
    Recovery,
}

/// One credential entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// Stable id.
    pub id: String,
    /// Class.
    pub class: CredentialClass,
    /// Which op classes may use it.
    pub allowed_ops: Vec<OperationClass>,
    /// Max unseals per hour.
    pub max_unseal_per_hour: u32,
    /// Operator approval required for each unseal?
    pub operator_approval_required: bool,
    /// Sliding window of unix-second timestamps for unseals.
    pub recent_unseals: Vec<u64>,
}

/// Vault envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialVaultPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Credentials.
    pub credentials: Vec<Credential>,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnsealDecision {
    /// Allowed; recorded in recent_unseals.
    Allow,
    /// Op class not in allowed_ops.
    DeniedOpClass,
    /// Per-hour quota exhausted.
    DeniedQuota,
    /// Operator approval missing.
    DeniedApprovalMissing,
    /// Credential not found.
    DeniedUnknown,
}

/// Errors (mostly construction).
#[derive(Debug, Error)]
pub enum VaultError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty id.
    #[error("credential id empty")]
    EmptyId,
    /// Duplicate id.
    #[error("duplicate credential id: {0}")]
    DuplicateId(String),
    /// Allowed ops empty.
    #[error("credential {0} allowed_ops empty")]
    EmptyAllowedOps(String),
    /// Quota zero.
    #[error("credential {0} max_unseal_per_hour zero")]
    QuotaZero(String),
}

impl CredentialVaultPolicy {
    /// New empty.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            credentials: Vec::new(),
        }
    }

    /// Add a credential.
    pub fn add(&mut self, c: Credential) -> Result<(), VaultError> {
        check_credential(&c)?;
        if self.credentials.iter().any(|x| x.id == c.id) {
            return Err(VaultError::DuplicateId(c.id));
        }
        self.credentials.push(c);
        Ok(())
    }

    /// Unseal request gate.
    pub fn unseal(
        &mut self,
        id: &str,
        op: OperationClass,
        approval_present: bool,
        now_unix: u64,
    ) -> UnsealDecision {
        let cred = match self.credentials.iter_mut().find(|c| c.id == id) {
            Some(c) => c,
            None => return UnsealDecision::DeniedUnknown,
        };
        if !cred.allowed_ops.contains(&op) {
            return UnsealDecision::DeniedOpClass;
        }
        // Drop unseals older than 3600s.
        cred.recent_unseals
            .retain(|t| now_unix.saturating_sub(*t) < 3600);
        if (cred.recent_unseals.len() as u32) >= cred.max_unseal_per_hour {
            return UnsealDecision::DeniedQuota;
        }
        if cred.operator_approval_required && !approval_present {
            return UnsealDecision::DeniedApprovalMissing;
        }
        cred.recent_unseals.push(now_unix);
        UnsealDecision::Allow
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(VaultError::SchemaMismatch);
        }
        use std::collections::HashSet;
        let mut seen: HashSet<&str> = HashSet::new();
        for c in &self.credentials {
            check_credential(c)?;
            if !seen.insert(c.id.as_str()) {
                return Err(VaultError::DuplicateId(c.id.clone()));
            }
        }
        Ok(())
    }
}

fn check_credential(c: &Credential) -> Result<(), VaultError> {
    if c.id.is_empty() {
        return Err(VaultError::EmptyId);
    }
    if c.allowed_ops.is_empty() {
        return Err(VaultError::EmptyAllowedOps(c.id.clone()));
    }
    if c.max_unseal_per_hour == 0 {
        return Err(VaultError::QuotaZero(c.id.clone()));
    }
    Ok(())
}

impl Default for CredentialVaultPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(
        id: &str,
        class: CredentialClass,
        ops: Vec<OperationClass>,
        quota: u32,
        approval: bool,
    ) -> Credential {
        Credential {
            id: id.into(),
            class,
            allowed_ops: ops,
            max_unseal_per_hour: quota,
            operator_approval_required: approval,
            recent_unseals: Vec::new(),
        }
    }

    #[test]
    fn unknown_credential_denied() {
        let mut v = CredentialVaultPolicy::new();
        assert_eq!(
            v.unseal("none", OperationClass::Read, true, 0),
            UnsealDecision::DeniedUnknown
        );
    }

    #[test]
    fn allowed_op_unseals() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            10,
            false,
        ))
        .unwrap();
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 0),
            UnsealDecision::Allow
        );
    }

    #[test]
    fn disallowed_op_denied() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            10,
            false,
        ))
        .unwrap();
        assert_eq!(
            v.unseal("a", OperationClass::Write, false, 0),
            UnsealDecision::DeniedOpClass
        );
    }

    #[test]
    fn quota_exhausted_denies() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            2,
            false,
        ))
        .unwrap();
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 0),
            UnsealDecision::Allow
        );
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 0),
            UnsealDecision::Allow
        );
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 0),
            UnsealDecision::DeniedQuota
        );
    }

    #[test]
    fn quota_window_slides() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            1,
            false,
        ))
        .unwrap();
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 0),
            UnsealDecision::Allow
        );
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 100),
            UnsealDecision::DeniedQuota
        );
        assert_eq!(
            v.unseal("a", OperationClass::Read, false, 4000),
            UnsealDecision::Allow
        );
    }

    #[test]
    fn approval_required_blocks_without_approval() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Master,
            vec![OperationClass::Admin],
            5,
            true,
        ))
        .unwrap();
        assert_eq!(
            v.unseal("a", OperationClass::Admin, false, 0),
            UnsealDecision::DeniedApprovalMissing
        );
        assert_eq!(
            v.unseal("a", OperationClass::Admin, true, 0),
            UnsealDecision::Allow
        );
    }

    #[test]
    fn add_duplicate_rejected() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            1,
            false,
        ))
        .unwrap();
        assert!(matches!(
            v.add(cred(
                "a",
                CredentialClass::Cloud,
                vec![OperationClass::Read],
                1,
                false
            ))
            .unwrap_err(),
            VaultError::DuplicateId(_)
        ));
    }

    #[test]
    fn empty_id_rejected() {
        let mut v = CredentialVaultPolicy::new();
        assert!(matches!(
            v.add(cred(
                "",
                CredentialClass::Local,
                vec![OperationClass::Read],
                1,
                false
            ))
            .unwrap_err(),
            VaultError::EmptyId
        ));
    }

    #[test]
    fn empty_allowed_ops_rejected() {
        let mut v = CredentialVaultPolicy::new();
        assert!(matches!(
            v.add(cred("a", CredentialClass::Local, vec![], 1, false))
                .unwrap_err(),
            VaultError::EmptyAllowedOps(_)
        ));
    }

    #[test]
    fn zero_quota_rejected() {
        let mut v = CredentialVaultPolicy::new();
        assert!(matches!(
            v.add(cred(
                "a",
                CredentialClass::Local,
                vec![OperationClass::Read],
                0,
                false
            ))
            .unwrap_err(),
            VaultError::QuotaZero(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = CredentialVaultPolicy::new();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            VaultError::SchemaMismatch
        ));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&CredentialClass::Recovery).unwrap(),
            "\"recovery\""
        );
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&UnsealDecision::DeniedQuota).unwrap(),
            "\"denied-quota\""
        );
    }

    #[test]
    fn vault_serde_roundtrip() {
        let mut v = CredentialVaultPolicy::new();
        v.add(cred(
            "a",
            CredentialClass::Local,
            vec![OperationClass::Read],
            5,
            false,
        ))
        .unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let back: CredentialVaultPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(v, back);
    }
}
