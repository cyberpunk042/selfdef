//! `selfdef-fence-token` — monotonic fencing token.
//!
//! issue() returns the next strictly-increasing token. accept(t)
//! permits only tokens >= last-accepted, otherwise Stale. The
//! issuer + acceptor sides are independent state machines: a
//! storage backend issues, and a downstream service accepts.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Issuer side — owns the monotonic counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FenceIssuer {
    /// Schema version.
    pub schema_version: String,
    /// Next token to hand out.
    pub next: u64,
}

/// Acceptor side — rejects stale tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FenceAcceptor {
    /// Schema version.
    pub schema_version: String,
    /// Highest token observed and accepted.
    pub last_accepted: u64,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FenceError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Token is older than last_accepted.
    #[error("stale token: {token} < last_accepted {last}")]
    Stale {
        /// Offending token.
        token: u64,
        /// Last accepted.
        last: u64,
    },
    /// Exhausted.
    #[error("token space exhausted")]
    Exhausted,
}

impl FenceIssuer {
    /// New (starts at 1; 0 is reserved as "no token yet").
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into(), next: 1 }
    }

    /// Issue the next token.
    pub fn issue(&mut self) -> Result<u64, FenceError> {
        let t = self.next;
        self.next = self.next.checked_add(1).ok_or(FenceError::Exhausted)?;
        Ok(t)
    }

    /// Peek without issuing.
    pub fn peek(&self) -> u64 { self.next }

    /// Validate.
    pub fn validate(&self) -> Result<(), FenceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FenceError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for FenceIssuer {
    fn default() -> Self { Self::new() }
}

impl FenceAcceptor {
    /// New.
    pub fn new() -> Self {
        Self { schema_version: SCHEMA_VERSION.into(), last_accepted: 0 }
    }

    /// Accept token; advances last_accepted if >= last_accepted.
    /// Rejects strictly-older tokens as Stale. (Equal tokens are
    /// accepted as idempotent retries.)
    pub fn accept(&mut self, token: u64) -> Result<(), FenceError> {
        if token < self.last_accepted {
            return Err(FenceError::Stale { token, last: self.last_accepted });
        }
        self.last_accepted = token;
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FenceError> {
        if self.schema_version != SCHEMA_VERSION { return Err(FenceError::SchemaMismatch); }
        Ok(())
    }
}

impl Default for FenceAcceptor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_is_strictly_monotonic() {
        let mut i = FenceIssuer::new();
        assert_eq!(i.issue().unwrap(), 1);
        assert_eq!(i.issue().unwrap(), 2);
        assert_eq!(i.issue().unwrap(), 3);
    }

    #[test]
    fn accept_advances() {
        let mut a = FenceAcceptor::new();
        a.accept(5).unwrap();
        a.accept(7).unwrap();
        assert_eq!(a.last_accepted, 7);
    }

    #[test]
    fn stale_rejected() {
        let mut a = FenceAcceptor::new();
        a.accept(10).unwrap();
        let e = a.accept(5).unwrap_err();
        assert!(matches!(e, FenceError::Stale { token: 5, last: 10 }));
        assert_eq!(a.last_accepted, 10);
    }

    #[test]
    fn equal_token_is_idempotent() {
        let mut a = FenceAcceptor::new();
        a.accept(7).unwrap();
        a.accept(7).unwrap();
        assert_eq!(a.last_accepted, 7);
    }

    #[test]
    fn exhausted_at_u64_max() {
        let mut i = FenceIssuer::new();
        i.next = u64::MAX - 1;
        assert_eq!(i.issue().unwrap(), u64::MAX - 1);
        // next is now u64::MAX; incrementing overflows.
        assert!(matches!(i.issue().unwrap_err(), FenceError::Exhausted));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut i = FenceIssuer::new();
        i.schema_version = "9.9.9".into();
        assert!(matches!(i.validate().unwrap_err(), FenceError::SchemaMismatch));
    }

    #[test]
    fn issuer_serde_roundtrip() {
        let mut i = FenceIssuer::new();
        i.issue().unwrap();
        i.issue().unwrap();
        let j = serde_json::to_string(&i).unwrap();
        let back: FenceIssuer = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }

    #[test]
    fn acceptor_serde_roundtrip() {
        let mut a = FenceAcceptor::new();
        a.accept(42).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let back: FenceAcceptor = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
