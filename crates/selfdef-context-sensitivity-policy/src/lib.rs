//! `selfdef-context-sensitivity-policy` — flow control by sensitivity.
//!
//! Each `ContextSensitivity` × `ProviderClass` pair has a verdict:
//! - Public: any provider class
//! - Internal: Local / Cloud / Synthetic all OK (operator may further gate via routing-decision-authority)
//! - Confidential: Local / Synthetic always OK; Cloud only with operator_approval=true
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_policy_decision::ContextSensitivity;
use selfdef_routing_decision_authority::ProviderClass;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum SensitivityError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Flow not authorized.
    #[error("flow not authorized: sensitivity={sensitivity:?} class={class:?} reason={reason}")]
    NotAuthorized {
        /// sensitivity.
        sensitivity: ContextSensitivity,
        /// class.
        class: ProviderClass,
        /// reason.
        reason: &'static str,
    },
}

/// IPS-authoritative flow check.
///
/// `operator_approved`: did the operator explicitly approve this flow?
pub fn authorize_flow(
    sensitivity: ContextSensitivity,
    class: ProviderClass,
    operator_approved: bool,
) -> Result<(), SensitivityError> {
    use ContextSensitivity::*;
    use ProviderClass::*;
    match (sensitivity, class) {
        // Public: always ok.
        (Public, _) => Ok(()),
        // Internal: any provider class ok (routing authority gates further).
        (Internal, _) => Ok(()),
        // Confidential: Local/Synthetic ok; Cloud requires explicit operator approval.
        (Confidential, Local) | (Confidential, Synthetic) => Ok(()),
        (Confidential, Cloud) => {
            if operator_approved {
                Ok(())
            } else {
                Err(SensitivityError::NotAuthorized {
                    sensitivity, class,
                    reason: "confidential-to-cloud-requires-operator-approval",
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ContextSensitivity::*;
    use ProviderClass::*;

    #[test]
    fn public_to_any_ok() {
        for class in [Local, Cloud, Synthetic] {
            authorize_flow(Public, class, false).unwrap();
        }
    }

    #[test]
    fn internal_to_any_ok() {
        for class in [Local, Cloud, Synthetic] {
            authorize_flow(Internal, class, false).unwrap();
        }
    }

    #[test]
    fn confidential_to_local_ok() {
        authorize_flow(Confidential, Local, false).unwrap();
    }

    #[test]
    fn confidential_to_synthetic_ok() {
        authorize_flow(Confidential, Synthetic, false).unwrap();
    }

    #[test]
    fn confidential_to_cloud_requires_approval() {
        let err = authorize_flow(Confidential, Cloud, false).unwrap_err();
        match err {
            SensitivityError::NotAuthorized { reason, .. } => {
                assert_eq!(reason, "confidential-to-cloud-requires-operator-approval");
            }
            other => panic!("unexpected: {other:?}"),
        }
        authorize_flow(Confidential, Cloud, true).unwrap();
    }
}
