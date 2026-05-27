//! `selfdef-session-resume-policy` — session resume decisions.
//!
//! Each session has a `last_seen_at_ms` and a disconnect cause. The
//! policy holds:
//!   * `soft_resume_window_ms` — within this window, resume freely.
//!   * `reauth_window_ms` — beyond soft but within reauth, allow
//!     resume only with fresh credentials.
//!   * Beyond reauth → require full new session.
//!
//! `decide(disconnected_at, now, cause)` returns:
//!   * `ResumeFreely`
//!   * `RequireReauth { since_disconnect_ms }`
//!   * `RequireNewSession { since_disconnect_ms }`
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Disconnect cause (affects which window applies).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DisconnectCause {
    /// Operator-initiated logout (most stringent — full new session).
    OperatorLogout,
    /// Network interruption.
    NetworkInterruption,
    /// Server restart (caller-initiated).
    ServerRestart,
    /// Idle timeout.
    IdleTimeout,
    /// Crash / unclean disconnect.
    UncleanShutdown,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionResumePolicy {
    /// Schema version.
    pub schema_version: String,
    /// Soft window.
    pub soft_resume_window_ms: u64,
    /// Reauth window (must be >= soft).
    pub reauth_window_ms: u64,
}

/// Verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResumeVerdict {
    /// Free resume.
    ResumeFreely,
    /// Require fresh credentials.
    RequireReauth {
        /// elapsed since disconnect.
        since_disconnect_ms: u64,
    },
    /// Require entirely new session.
    RequireNewSession {
        /// elapsed since disconnect.
        since_disconnect_ms: u64,
    },
}

/// Errors.
#[derive(Debug, Error)]
pub enum ResumeError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Reauth window must be >= soft.
    #[error("reauth_window_ms ({reauth}) must be >= soft_resume_window_ms ({soft})")]
    BadWindows {
        /// soft.
        soft: u64,
        /// reauth.
        reauth: u64,
    },
}

impl SessionResumePolicy {
    /// New.
    pub fn new(soft_resume_window_ms: u64, reauth_window_ms: u64) -> Result<Self, ResumeError> {
        if reauth_window_ms < soft_resume_window_ms {
            return Err(ResumeError::BadWindows {
                soft: soft_resume_window_ms,
                reauth: reauth_window_ms,
            });
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            soft_resume_window_ms,
            reauth_window_ms,
        })
    }

    /// Decide.
    pub fn decide(
        &self,
        disconnected_at_ms: u64,
        now_ms: u64,
        cause: DisconnectCause,
    ) -> ResumeVerdict {
        let since = now_ms.saturating_sub(disconnected_at_ms);
        if matches!(cause, DisconnectCause::OperatorLogout) {
            // Operator logout always requires a new session.
            return ResumeVerdict::RequireNewSession {
                since_disconnect_ms: since,
            };
        }
        if since <= self.soft_resume_window_ms {
            return ResumeVerdict::ResumeFreely;
        }
        if since <= self.reauth_window_ms {
            return ResumeVerdict::RequireReauth {
                since_disconnect_ms: since,
            };
        }
        ResumeVerdict::RequireNewSession {
            since_disconnect_ms: since,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ResumeError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ResumeError::SchemaMismatch);
        }
        if self.reauth_window_ms < self.soft_resume_window_ms {
            return Err(ResumeError::BadWindows {
                soft: self.soft_resume_window_ms,
                reauth: self.reauth_window_ms,
            });
        }
        Ok(())
    }
}

impl Default for SessionResumePolicy {
    fn default() -> Self {
        Self::new(60_000, 3_600_000).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freely_within_soft_window() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        assert_eq!(
            p.decide(0, 500, DisconnectCause::NetworkInterruption),
            ResumeVerdict::ResumeFreely
        );
    }

    #[test]
    fn reauth_in_intermediate_window() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        match p.decide(0, 5000, DisconnectCause::NetworkInterruption) {
            ResumeVerdict::RequireReauth {
                since_disconnect_ms,
            } => assert_eq!(since_disconnect_ms, 5000),
            _ => panic!(),
        }
    }

    #[test]
    fn new_session_past_reauth() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        assert!(matches!(
            p.decide(0, 20_000, DisconnectCause::NetworkInterruption),
            ResumeVerdict::RequireNewSession { .. }
        ));
    }

    #[test]
    fn operator_logout_always_new() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        // Even 1ms after logout, still require new.
        assert!(matches!(
            p.decide(0, 1, DisconnectCause::OperatorLogout),
            ResumeVerdict::RequireNewSession { .. }
        ));
    }

    #[test]
    fn idle_timeout_uses_normal_windows() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        assert_eq!(
            p.decide(0, 500, DisconnectCause::IdleTimeout),
            ResumeVerdict::ResumeFreely
        );
        assert!(matches!(
            p.decide(0, 5000, DisconnectCause::IdleTimeout),
            ResumeVerdict::RequireReauth { .. }
        ));
    }

    #[test]
    fn boundary_exact() {
        let p = SessionResumePolicy::new(1000, 10_000).unwrap();
        // At exactly soft window.
        assert_eq!(
            p.decide(0, 1000, DisconnectCause::NetworkInterruption),
            ResumeVerdict::ResumeFreely
        );
        // At exactly reauth window.
        assert!(matches!(
            p.decide(0, 10_000, DisconnectCause::NetworkInterruption),
            ResumeVerdict::RequireReauth { .. }
        ));
    }

    #[test]
    fn bad_windows_rejected() {
        assert!(matches!(
            SessionResumePolicy::new(10, 5).unwrap_err(),
            ResumeError::BadWindows { .. }
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = SessionResumePolicy::new(1, 1).unwrap();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            ResumeError::SchemaMismatch
        ));
    }

    #[test]
    fn resume_serde_roundtrip() {
        let p = SessionResumePolicy::new(60_000, 3_600_000).unwrap();
        let j = serde_json::to_string(&p).unwrap();
        let back: SessionResumePolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
