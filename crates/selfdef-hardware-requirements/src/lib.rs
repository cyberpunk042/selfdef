//! `selfdef-hardware-requirements` — per-module `[requires_hardware]`
//! gate evaluator. Stage-2 of SDD-057: scaffold + stub.
//!
//! The full `HardwareRequirements` struct + `evaluate` /
//! `evaluate_resolved` impl lives today in `crates/selfdef-cli/src/
//! modules.rs` lines 190-613 (~423 LOC). This crate is the
//! destination; the move + re-export from selfdef-cli lands in
//! SDD-057 step 3.
//!
//! Until the move ships, this crate exposes ONLY the schema-version
//! constant + the placeholder error type so callers can begin
//! adding `selfdef-hardware-requirements = { workspace = true }`
//! without breaking when the real surface lands.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Schema version pinned to the moved `HardwareRequirements`
/// shape. Bumps when the on-disk module.toml `[requires_hardware]`
/// schema changes.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Placeholder error type for the gate evaluator. Will be replaced
/// by the real enum in SDD-057 step 3 (the variants enumerate
/// every unmet predicate).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RequirementError {
    /// Schema version drift.
    SchemaMismatch,
    /// One or more predicates unmet (placeholder; the real variant
    /// will carry a Vec<String> of unmet-predicate descriptions).
    UnmetPlaceholder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_present() {
        assert!(SCHEMA_VERSION.starts_with("1."));
    }

    #[test]
    fn error_round_trips() {
        let e = RequirementError::SchemaMismatch;
        let s = serde_json::to_string(&e).unwrap();
        let e2: RequirementError = serde_json::from_str(&s).unwrap();
        assert_eq!(e, e2);
    }
}
