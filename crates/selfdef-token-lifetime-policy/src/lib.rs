//! `selfdef-token-lifetime-policy` — access-token TTL authority.
//!
//! Encodes per-class (max_lifetime, idle_timeout) for access tokens
//! the engine accepts. A token is admissible iff:
//! * `now - issued_at <= max_lifetime`
//! * `now - last_used  <= idle_timeout`
//! * `revoked == false`
//! * `issued_at <= now` (no future-dated tokens).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Token class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenClass {
    /// Short-lived session token (cockpit login).
    Session,
    /// API token for inbound MCP-style calls.
    Api,
    /// Long-lived refresh token.
    Refresh,
    /// One-time grant token (consumed-after-use).
    OneTime,
}

/// Per-class TTL configuration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClassLifetime {
    /// Maximum total lifetime in seconds.
    pub max_lifetime_seconds: u64,
    /// Maximum idle interval in seconds.
    pub idle_timeout_seconds: u64,
}

/// A token state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenState {
    /// Token id (opaque).
    pub id: String,
    /// Class.
    pub class: TokenClass,
    /// Unix time when issued.
    pub issued_at: u64,
    /// Unix time of last use.
    pub last_used: u64,
    /// Has the token been revoked?
    pub revoked: bool,
}

/// Per-token decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifetimeDecision {
    /// Token currently admissible.
    Admissible,
    /// Token expired by max-lifetime.
    ExpiredLifetime,
    /// Token expired by idle.
    ExpiredIdle,
    /// Token explicitly revoked.
    Revoked,
    /// Token issued in the future (clock skew or forgery).
    FutureIssued,
    /// Class missing in policy.
    UnknownClass,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenLifetimePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Session.
    pub session: ClassLifetime,
    /// Api.
    pub api: ClassLifetime,
    /// Refresh.
    pub refresh: ClassLifetime,
    /// One-time.
    pub one_time: ClassLifetime,
}

/// Errors.
#[derive(Debug, Error)]
pub enum TokenLifetimeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// max_lifetime_seconds zero in class.
    #[error("class {0:?} max_lifetime_seconds is zero")]
    MaxLifetimeZero(TokenClass),
    /// idle_timeout_seconds zero in class.
    #[error("class {0:?} idle_timeout_seconds is zero")]
    IdleTimeoutZero(TokenClass),
    /// idle_timeout > max_lifetime.
    #[error("class {0:?}: idle_timeout {1} > max_lifetime {2}")]
    IdleExceedsMax(TokenClass, u64, u64),
}

impl TokenLifetimePolicy {
    /// Canonical defaults:
    /// * Session: 8h max / 30m idle
    /// * Api: 30d max / 24h idle
    /// * Refresh: 90d max / 14d idle
    /// * OneTime: 5m max / 5m idle
    pub fn canonical() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            session: ClassLifetime { max_lifetime_seconds: 8 * 3600, idle_timeout_seconds: 30 * 60 },
            api: ClassLifetime { max_lifetime_seconds: 30 * 86_400, idle_timeout_seconds: 24 * 3600 },
            refresh: ClassLifetime { max_lifetime_seconds: 90 * 86_400, idle_timeout_seconds: 14 * 86_400 },
            one_time: ClassLifetime { max_lifetime_seconds: 5 * 60, idle_timeout_seconds: 5 * 60 },
        }
    }

    /// Get per-class lifetime config.
    pub fn class(&self, c: TokenClass) -> ClassLifetime {
        match c {
            TokenClass::Session => self.session,
            TokenClass::Api => self.api,
            TokenClass::Refresh => self.refresh,
            TokenClass::OneTime => self.one_time,
        }
    }

    /// Decide.
    pub fn decide(&self, token: &TokenState, now: u64) -> LifetimeDecision {
        if token.revoked {
            return LifetimeDecision::Revoked;
        }
        if token.issued_at > now {
            return LifetimeDecision::FutureIssued;
        }
        let cl = self.class(token.class);
        let age = now - token.issued_at;
        if age > cl.max_lifetime_seconds {
            return LifetimeDecision::ExpiredLifetime;
        }
        let idle = now.saturating_sub(token.last_used);
        if idle > cl.idle_timeout_seconds {
            return LifetimeDecision::ExpiredIdle;
        }
        LifetimeDecision::Admissible
    }

    /// Seconds until lifetime expiry (0 if already expired).
    pub fn seconds_to_lifetime_expiry(&self, token: &TokenState, now: u64) -> u64 {
        let cl = self.class(token.class);
        cl.max_lifetime_seconds.saturating_sub(now.saturating_sub(token.issued_at))
    }

    /// Seconds until idle expiry (0 if already expired).
    pub fn seconds_to_idle_expiry(&self, token: &TokenState, now: u64) -> u64 {
        let cl = self.class(token.class);
        cl.idle_timeout_seconds.saturating_sub(now.saturating_sub(token.last_used))
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), TokenLifetimeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TokenLifetimeError::SchemaMismatch);
        }
        for (cls, c) in [
            (TokenClass::Session, self.session),
            (TokenClass::Api, self.api),
            (TokenClass::Refresh, self.refresh),
            (TokenClass::OneTime, self.one_time),
        ] {
            if c.max_lifetime_seconds == 0 {
                return Err(TokenLifetimeError::MaxLifetimeZero(cls));
            }
            if c.idle_timeout_seconds == 0 {
                return Err(TokenLifetimeError::IdleTimeoutZero(cls));
            }
            if c.idle_timeout_seconds > c.max_lifetime_seconds {
                return Err(TokenLifetimeError::IdleExceedsMax(cls, c.idle_timeout_seconds, c.max_lifetime_seconds));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(class: TokenClass, issued_at: u64, last_used: u64) -> TokenState {
        TokenState {
            id: "t".into(),
            class,
            issued_at,
            last_used,
            revoked: false,
        }
    }

    #[test]
    fn canonical_validates() {
        TokenLifetimePolicy::canonical().validate().unwrap();
    }

    #[test]
    fn fresh_session_admissible() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::Session, 100, 100);
        assert_eq!(p.decide(&t, 200), LifetimeDecision::Admissible);
    }

    #[test]
    fn revoked_revoked() {
        let p = TokenLifetimePolicy::canonical();
        let mut t = tok(TokenClass::Api, 0, 0);
        t.revoked = true;
        assert_eq!(p.decide(&t, 100), LifetimeDecision::Revoked);
    }

    #[test]
    fn future_issued_detected() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::Session, 1000, 1000);
        assert_eq!(p.decide(&t, 500), LifetimeDecision::FutureIssued);
    }

    #[test]
    fn expired_lifetime() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::OneTime, 0, 500);
        assert_eq!(p.decide(&t, 1000), LifetimeDecision::ExpiredLifetime);
    }

    #[test]
    fn expired_idle() {
        let p = TokenLifetimePolicy::canonical();
        // OneTime idle = 5min = 300s.
        let t = tok(TokenClass::OneTime, 0, 0);
        assert_eq!(p.decide(&t, 400), LifetimeDecision::ExpiredLifetime); // Both expired but lifetime is first check.
        let t = tok(TokenClass::Session, 0, 0);
        assert_eq!(p.decide(&t, 31 * 60), LifetimeDecision::ExpiredIdle);
    }

    #[test]
    fn idle_resets_on_use() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::Session, 0, 60 * 25);
        assert_eq!(p.decide(&t, 60 * 26), LifetimeDecision::Admissible);
    }

    #[test]
    fn seconds_to_lifetime_expiry() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::Session, 0, 0);
        assert_eq!(p.seconds_to_lifetime_expiry(&t, 3600), 7 * 3600);
    }

    #[test]
    fn seconds_to_idle_expiry() {
        let p = TokenLifetimePolicy::canonical();
        let t = tok(TokenClass::Session, 0, 0);
        assert_eq!(p.seconds_to_idle_expiry(&t, 60), 29 * 60);
    }

    #[test]
    fn validate_rejects_zero_max() {
        let mut p = TokenLifetimePolicy::canonical();
        p.session.max_lifetime_seconds = 0;
        assert!(matches!(p.validate().unwrap_err(), TokenLifetimeError::MaxLifetimeZero(_)));
    }

    #[test]
    fn validate_rejects_zero_idle() {
        let mut p = TokenLifetimePolicy::canonical();
        p.api.idle_timeout_seconds = 0;
        assert!(matches!(p.validate().unwrap_err(), TokenLifetimeError::IdleTimeoutZero(_)));
    }

    #[test]
    fn validate_rejects_idle_gt_max() {
        let mut p = TokenLifetimePolicy::canonical();
        p.session.idle_timeout_seconds = p.session.max_lifetime_seconds + 1;
        assert!(matches!(p.validate().unwrap_err(), TokenLifetimeError::IdleExceedsMax(_, _, _)));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = TokenLifetimePolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), TokenLifetimeError::SchemaMismatch));
    }

    #[test]
    fn class_serde_kebab() {
        assert_eq!(serde_json::to_string(&TokenClass::OneTime).unwrap(), "\"one-time\"");
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(serde_json::to_string(&LifetimeDecision::ExpiredLifetime).unwrap(), "\"expired-lifetime\"");
        assert_eq!(serde_json::to_string(&LifetimeDecision::FutureIssued).unwrap(), "\"future-issued\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = TokenLifetimePolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: TokenLifetimePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
