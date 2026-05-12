//! Crate-level error type.

use thiserror::Error;

use crate::SCHEMA_VERSION;

/// Errors originating from schema operations.
///
/// Module-specific errors (collectors, store, bus, ...) live in their own
/// crates; this type only covers what `selfdef-core` itself can fail at:
/// (de)serialization and schema version mismatches.
#[derive(Debug, Error)]
pub enum Error {
    #[error("event (de)serialization failed: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("unsupported schema version: got {got}, this build supports up to {supported}")]
    UnsupportedSchema { got: u32, supported: u32 },

    #[error("validation failed: {0}")]
    Validation(String),
}

impl Error {
    /// Convenience constructor for the schema-mismatch case.
    #[must_use]
    pub fn unsupported_schema(got: u32) -> Self {
        Self::UnsupportedSchema {
            got,
            supported: SCHEMA_VERSION,
        }
    }

    /// Convenience constructor for validation errors.
    #[must_use]
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }
}
