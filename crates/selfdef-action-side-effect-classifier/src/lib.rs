//! `selfdef-action-side-effect-classifier` — action effect classifier.
//!
//! 5 classes:
//! * Pure — no observable effect (reads).
//! * Idempotent — repeatable with the same outcome.
//! * Mutating — non-destructive change.
//! * Destructive — removes data / can't be reversed.
//! * External — calls outside the engine (network, IPC).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Side-effect class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SideEffectClass {
    /// Pure (no effect, just reads).
    Pure,
    /// Idempotent (repeatable, same outcome).
    Idempotent,
    /// Mutating (non-destructive change).
    Mutating,
    /// Destructive (irreversible).
    Destructive,
    /// External (calls outside engine).
    External,
}

/// Action verb (canonical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verb {
    /// Read.
    Read,
    /// List/enumerate.
    List,
    /// Create.
    Create,
    /// Update.
    Update,
    /// Upsert.
    Upsert,
    /// Delete.
    Delete,
    /// Send (message, request).
    Send,
    /// Spawn (subprocess).
    Spawn,
}

/// Input features.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionFeatures {
    /// Verb.
    pub verb: Verb,
    /// Does the action call out of the engine (network / IPC)?
    pub has_external_call: bool,
    /// Is the operation repeatable with same outcome (e.g., set-x=5)?
    pub is_repeatable: bool,
}

/// Result.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Classification {
    /// Class.
    pub class: SideEffectClass,
}

/// Errors.
#[derive(Debug, Error)]
pub enum SideEffectError {
    /// Schema drift (placeholder for serde envelope).
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Stateless classifier.
#[derive(Debug, Clone, Default)]
pub struct ActionSideEffectClassifier;

impl ActionSideEffectClassifier {
    /// Classify.
    pub fn classify(f: ActionFeatures) -> Classification {
        let base = match f.verb {
            Verb::Read | Verb::List => SideEffectClass::Pure,
            Verb::Create | Verb::Update => SideEffectClass::Mutating,
            Verb::Upsert => SideEffectClass::Idempotent,
            Verb::Delete => SideEffectClass::Destructive,
            Verb::Send | Verb::Spawn => SideEffectClass::External,
        };
        // External calls escalate Pure/Idempotent/Mutating to External.
        let class = if f.has_external_call && matches!(base,
            SideEffectClass::Pure | SideEffectClass::Idempotent | SideEffectClass::Mutating
        ) {
            SideEffectClass::External
        } else if f.is_repeatable && matches!(base, SideEffectClass::Mutating) {
            // Operator-asserted repeatable mutation promotes to Idempotent.
            SideEffectClass::Idempotent
        } else {
            base
        };
        Classification { class }
    }
}

/// Envelope (for schema versioning).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionSideEffectClassifierEnv {
    /// Schema version.
    pub schema_version: String,
}

impl ActionSideEffectClassifierEnv {
    /// New.
    pub fn new() -> Self { Self { schema_version: SCHEMA_VERSION.into() } }

    /// Validate.
    pub fn validate(&self) -> Result<(), SideEffectError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SideEffectError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for ActionSideEffectClassifierEnv {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(verb: Verb, external: bool, repeatable: bool) -> ActionFeatures {
        ActionFeatures { verb, has_external_call: external, is_repeatable: repeatable }
    }

    #[test]
    fn read_pure() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Read, false, false));
        assert_eq!(c.class, SideEffectClass::Pure);
    }

    #[test]
    fn list_pure() {
        let c = ActionSideEffectClassifier::classify(f(Verb::List, false, false));
        assert_eq!(c.class, SideEffectClass::Pure);
    }

    #[test]
    fn create_mutating() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Create, false, false));
        assert_eq!(c.class, SideEffectClass::Mutating);
    }

    #[test]
    fn upsert_idempotent() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Upsert, false, false));
        assert_eq!(c.class, SideEffectClass::Idempotent);
    }

    #[test]
    fn delete_destructive() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Delete, false, false));
        assert_eq!(c.class, SideEffectClass::Destructive);
    }

    #[test]
    fn send_external() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Send, false, false));
        assert_eq!(c.class, SideEffectClass::External);
    }

    #[test]
    fn spawn_external() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Spawn, false, false));
        assert_eq!(c.class, SideEffectClass::External);
    }

    #[test]
    fn read_with_external_call_promoted() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Read, true, false));
        assert_eq!(c.class, SideEffectClass::External);
    }

    #[test]
    fn create_repeatable_promoted_to_idempotent() {
        let c = ActionSideEffectClassifier::classify(f(Verb::Create, false, true));
        assert_eq!(c.class, SideEffectClass::Idempotent);
    }

    #[test]
    fn delete_external_call_stays_destructive() {
        // External-call promotion only applies to base Pure/Idempotent/Mutating.
        let c = ActionSideEffectClassifier::classify(f(Verb::Delete, true, false));
        assert_eq!(c.class, SideEffectClass::Destructive);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut e = ActionSideEffectClassifierEnv::new();
        e.schema_version = "9.9.9".into();
        assert!(matches!(e.validate().unwrap_err(), SideEffectError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&SideEffectClass::Destructive).unwrap(), "\"destructive\"");
        assert_eq!(serde_json::to_string(&SideEffectClass::External).unwrap(), "\"external\"");
    }

    #[test]
    fn verb_serde_kebab() {
        assert_eq!(serde_json::to_string(&Verb::Upsert).unwrap(), "\"upsert\"");
    }
}
