//! `selfdef-grant-promotion-policy` — IPS gate over grant modifications.
//!
//! Operator can:
//! - extend TTL by `delta` ≤ original TTL (routine)
//! - widen scope (requires double-operator)
//! - shorten TTL / narrow scope (routine demotion)
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Grant change kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    /// Extend TTL.
    ExtendTtl,
    /// Shorten TTL.
    ShortenTtl,
    /// Widen scope.
    WidenScope,
    /// Narrow scope.
    NarrowScope,
}

/// Gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromotionGate {
    /// Routine.
    Routine,
    /// Requires single operator approval.
    SingleOperator,
    /// Requires double operator approval.
    DoubleOperator,
    /// Forbidden outright.
    Forbidden,
}

/// Errors.
#[derive(Debug, Error)]
pub enum PromotionError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Extend exceeds original TTL doubling rule.
    #[error("extend delta {delta} > original_ttl {original} (max 1x)")]
    ExtendTooFar {
        /// delta.
        delta: u32,
        /// original.
        original: u32,
    },
    /// Insufficient operator signatures.
    #[error("change {kind:?} requires {required:?} approvals; got {got}")]
    MissingApproval {
        /// kind.
        kind: ChangeKind,
        /// required.
        required: PromotionGate,
        /// got.
        got: u8,
    },
}

/// Classify the gate.
pub fn gate_for(kind: ChangeKind) -> PromotionGate {
    match kind {
        ChangeKind::ExtendTtl => PromotionGate::SingleOperator,
        ChangeKind::ShortenTtl => PromotionGate::Routine,
        ChangeKind::WidenScope => PromotionGate::DoubleOperator,
        ChangeKind::NarrowScope => PromotionGate::Routine,
    }
}

/// Authorize an ExtendTtl by `delta` against the original TTL.
pub fn authorize_extend(
    delta_seconds: u32,
    original_ttl_seconds: u32,
    operator_signatures: u8,
) -> Result<(), PromotionError> {
    if delta_seconds > original_ttl_seconds {
        return Err(PromotionError::ExtendTooFar {
            delta: delta_seconds,
            original: original_ttl_seconds,
        });
    }
    if operator_signatures < 1 {
        return Err(PromotionError::MissingApproval {
            kind: ChangeKind::ExtendTtl,
            required: PromotionGate::SingleOperator,
            got: operator_signatures,
        });
    }
    Ok(())
}

/// Authorize a WidenScope.
pub fn authorize_widen(operator_signatures: u8) -> Result<(), PromotionError> {
    if operator_signatures < 2 {
        return Err(PromotionError::MissingApproval {
            kind: ChangeKind::WidenScope,
            required: PromotionGate::DoubleOperator,
            got: operator_signatures,
        });
    }
    Ok(())
}

/// Generic authorize for ShortenTtl / NarrowScope (always Ok).
pub fn authorize_demote() -> Result<(), PromotionError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_within_original_ok() {
        authorize_extend(60, 120, 1).unwrap();
    }

    #[test]
    fn extend_at_original_ok() {
        authorize_extend(120, 120, 1).unwrap();
    }

    #[test]
    fn extend_beyond_original_rejected() {
        assert!(matches!(
            authorize_extend(1000, 120, 1).unwrap_err(),
            PromotionError::ExtendTooFar { .. }
        ));
    }

    #[test]
    fn extend_no_signature_rejected() {
        assert!(matches!(
            authorize_extend(60, 120, 0).unwrap_err(),
            PromotionError::MissingApproval { .. }
        ));
    }

    #[test]
    fn widen_requires_two() {
        assert!(matches!(
            authorize_widen(0).unwrap_err(),
            PromotionError::MissingApproval { .. }
        ));
        assert!(matches!(
            authorize_widen(1).unwrap_err(),
            PromotionError::MissingApproval { .. }
        ));
        authorize_widen(2).unwrap();
    }

    #[test]
    fn demote_always_ok() {
        authorize_demote().unwrap();
    }

    #[test]
    fn gate_classification() {
        assert_eq!(
            gate_for(ChangeKind::ExtendTtl),
            PromotionGate::SingleOperator
        );
        assert_eq!(gate_for(ChangeKind::ShortenTtl), PromotionGate::Routine);
        assert_eq!(
            gate_for(ChangeKind::WidenScope),
            PromotionGate::DoubleOperator
        );
        assert_eq!(gate_for(ChangeKind::NarrowScope), PromotionGate::Routine);
    }

    #[test]
    fn change_kind_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&ChangeKind::ExtendTtl).unwrap(),
            "\"extend-ttl\""
        );
        assert_eq!(
            serde_json::to_string(&ChangeKind::WidenScope).unwrap(),
            "\"widen-scope\""
        );
        assert_eq!(
            serde_json::to_string(&ChangeKind::NarrowScope).unwrap(),
            "\"narrow-scope\""
        );
    }
}
