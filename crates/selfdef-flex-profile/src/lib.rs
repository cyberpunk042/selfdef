//! `selfdef-flex-profile` — MS011 Z-3 / SDD-026 flex-profile state.
//!
//! Per SDD-026 Z-3 (verbatim):
//!
//! > Replace "profile" (the static YAML) with "flex-profile" — the
//! > same YAML PLUS operator-runtime mutations the dashboard applies
//! > (e.g. "this profile + Qwen3-Coder-32B attached + LoRA X on top").
//! > Persist to /var/lib/selfdef/flex-profile.json with full revert
//! > history.
//!
//! This crate models the live-delta + revert-history state. It is
//! the foundation for the future dashboard "Profiles" tab + CLI
//! `selfdefctl flex-profile {show, apply, revert}` surface.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version pinned for `flex-profile.json` round-trip.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Default on-disk path for the persisted state (operator override
/// via daemon config / env).
pub const DEFAULT_STATE_PATH: &str = "/var/lib/selfdef/flex-profile.json";

/// One operator-applied delta over the baseline YAML profile.
///
/// Each delta carries 4 mandatory fields so the revert path can
/// undo the exact change (R09603 reason + actor + timestamp +
/// inverse operation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delta {
    /// Monotonic id (1-indexed; new deltas append + increment).
    pub id: u64,
    /// MS003 fingerprint of the applying operator / agent.
    pub actor: String,
    /// Human-readable reason (non-empty per R09657).
    pub reason: String,
    /// Unix millis at apply time.
    pub applied_at_ms: u64,
    /// What the delta does. Operator-readable + serializable so a
    /// later revert can compute the inverse.
    pub operation: DeltaOp,
}

/// The 4 canonical delta operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DeltaOp {
    /// Attach a model (e.g. `Qwen3-Coder-32B`) to the active profile.
    AttachModel {
        /// Model slug.
        slug: String,
    },
    /// Detach a previously-attached model.
    DetachModel {
        /// Model slug.
        slug: String,
    },
    /// Attach a LoRA adapter on top of a model.
    AttachLora {
        /// Base model slug.
        base_model: String,
        /// LoRA slug.
        lora: String,
    },
    /// Detach a LoRA adapter.
    DetachLora {
        /// Base model slug.
        base_model: String,
        /// LoRA slug.
        lora: String,
    },
}

impl DeltaOp {
    /// Compute the operation that would undo this one.
    #[must_use]
    pub fn inverse(&self) -> Self {
        match self {
            Self::AttachModel { slug } => Self::DetachModel { slug: slug.clone() },
            Self::DetachModel { slug } => Self::AttachModel { slug: slug.clone() },
            Self::AttachLora { base_model, lora } => Self::DetachLora {
                base_model: base_model.clone(),
                lora: lora.clone(),
            },
            Self::DetachLora { base_model, lora } => Self::AttachLora {
                base_model: base_model.clone(),
                lora: lora.clone(),
            },
        }
    }
}

/// Persisted flex-profile state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlexProfile {
    /// Schema version.
    pub schema_version: String,
    /// Baseline profile name (the YAML this is a delta-over).
    pub baseline: String,
    /// Applied deltas in oldest-first order. Revert applies the
    /// inverse of the last delta + truncates the vec.
    pub deltas: Vec<Delta>,
    /// Reverted deltas — full revert history per SDD-026 Z-3
    /// "with full revert history" requirement.
    pub history: Vec<RevertRecord>,
}

/// One revert record — operator-actionable provenance of an undo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevertRecord {
    /// The delta that was reverted (copied verbatim).
    pub original: Delta,
    /// MS003 fingerprint of the reverting party.
    pub actor: String,
    /// Unix millis at revert time.
    pub reverted_at_ms: u64,
    /// Operator-readable reason for the revert.
    pub reason: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FlexProfileError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Tried to revert when no delta is on the stack.
    #[error("no delta to revert (history is the only record)")]
    NothingToRevert,
    /// One of the 4 mandatory fields is missing.
    #[error("mandatory field missing: {0}")]
    MandatoryFieldMissing(&'static str),
}

impl FlexProfile {
    /// New empty flex-profile over `baseline`.
    #[must_use]
    pub fn new(baseline: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            baseline: baseline.into(),
            deltas: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Apply a delta. Refuses on missing mandatory fields.
    pub fn apply(&mut self, delta: Delta) -> Result<(), FlexProfileError> {
        if delta.actor.is_empty() {
            return Err(FlexProfileError::MandatoryFieldMissing("actor"));
        }
        if delta.reason.is_empty() {
            return Err(FlexProfileError::MandatoryFieldMissing("reason"));
        }
        self.deltas.push(delta);
        Ok(())
    }

    /// Revert the most-recent delta, recording the revert in history.
    pub fn revert(
        &mut self,
        actor: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<Delta, FlexProfileError> {
        let original = self.deltas.pop().ok_or(FlexProfileError::NothingToRevert)?;
        self.history.push(RevertRecord {
            original: original.clone(),
            actor: actor.to_string(),
            reverted_at_ms: now_ms,
            reason: reason.to_string(),
        });
        Ok(original)
    }

    /// Number of active deltas on the live stack.
    #[must_use]
    pub fn delta_count(&self) -> usize {
        self.deltas.len()
    }

    /// Number of reverted deltas in history.
    #[must_use]
    pub fn revert_count(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty_with_baseline() {
        let p = FlexProfile::new("production");
        assert_eq!(p.baseline, "production");
        assert_eq!(p.delta_count(), 0);
        assert_eq!(p.revert_count(), 0);
        assert_eq!(p.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn apply_pushes_a_delta() {
        let mut p = FlexProfile::new("production");
        let d = Delta {
            id: 1,
            actor: "op-fingerprint".into(),
            reason: "attach Qwen3 for code work".into(),
            applied_at_ms: 1_700_000_000_000,
            operation: DeltaOp::AttachModel {
                slug: "qwen3-coder-32b".into(),
            },
        };
        p.apply(d).unwrap();
        assert_eq!(p.delta_count(), 1);
    }

    #[test]
    fn apply_refuses_empty_actor() {
        let mut p = FlexProfile::new("production");
        let d = Delta {
            id: 1,
            actor: String::new(),
            reason: "attach".into(),
            applied_at_ms: 0,
            operation: DeltaOp::AttachModel { slug: "x".into() },
        };
        assert!(matches!(
            p.apply(d),
            Err(FlexProfileError::MandatoryFieldMissing("actor"))
        ));
    }

    #[test]
    fn apply_refuses_empty_reason() {
        let mut p = FlexProfile::new("production");
        let d = Delta {
            id: 1,
            actor: "op".into(),
            reason: String::new(),
            applied_at_ms: 0,
            operation: DeltaOp::AttachModel { slug: "x".into() },
        };
        assert!(matches!(
            p.apply(d),
            Err(FlexProfileError::MandatoryFieldMissing("reason"))
        ));
    }

    #[test]
    fn revert_moves_delta_to_history() {
        let mut p = FlexProfile::new("production");
        let d = Delta {
            id: 1,
            actor: "op-fingerprint".into(),
            reason: "attach Qwen3".into(),
            applied_at_ms: 1_700_000_000_000,
            operation: DeltaOp::AttachModel {
                slug: "qwen3-coder-32b".into(),
            },
        };
        p.apply(d).unwrap();
        let reverted = p.revert("op2", "rolling back", 1_700_000_001_000).unwrap();
        assert_eq!(reverted.id, 1);
        assert_eq!(p.delta_count(), 0);
        assert_eq!(p.revert_count(), 1);
        assert_eq!(p.history[0].actor, "op2");
        assert_eq!(p.history[0].original.id, 1);
    }

    #[test]
    fn revert_with_no_deltas_errors() {
        let mut p = FlexProfile::new("production");
        assert!(matches!(
            p.revert("op", "x", 0),
            Err(FlexProfileError::NothingToRevert)
        ));
    }

    #[test]
    fn inverse_round_trips_each_op() {
        let a = DeltaOp::AttachModel { slug: "m".into() };
        assert_eq!(a.inverse(), DeltaOp::DetachModel { slug: "m".into() });
        assert_eq!(a.inverse().inverse(), a);

        let l = DeltaOp::AttachLora {
            base_model: "m".into(),
            lora: "l".into(),
        };
        let lop = l.inverse();
        assert!(matches!(lop, DeltaOp::DetachLora { .. }));
        assert_eq!(lop.inverse(), l);
    }

    #[test]
    fn full_round_trip_through_json() {
        let mut p = FlexProfile::new("production");
        p.apply(Delta {
            id: 1,
            actor: "op".into(),
            reason: "test".into(),
            applied_at_ms: 1,
            operation: DeltaOp::AttachModel { slug: "m".into() },
        })
        .unwrap();
        let s = serde_json::to_string(&p).unwrap();
        let p2: FlexProfile = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }
}
