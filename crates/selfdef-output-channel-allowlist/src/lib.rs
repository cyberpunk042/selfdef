//! `selfdef-output-channel-allowlist` — per-channel sensitivity gate.
//!
//! 7 OutputChannels × 4 ContextSensitivity → Allow/Deny.
//! Rule of thumb: high sensitivity flows only to OperatorChat /
//! AuditLog (engine-owned). Webhooks/Email/Notifications are
//! external — only Public goes there by default.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Sensitivity (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sensitivity {
    /// Public.
    Public,
    /// Internal.
    Internal,
    /// Confidential.
    Confidential,
    /// Top-secret.
    TopSecret,
}

/// Output channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputChannel {
    /// Engine stdout / log.
    Stdout,
    /// Audit log (encrypted).
    AuditLog,
    /// Operator chat surface.
    OperatorChat,
    /// External webhook.
    Webhook,
    /// Outbound email.
    EmailOut,
    /// OS notification / system tray.
    Notification,
    /// Filesystem write.
    FileOut,
}

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelDecision {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// Policy (canonical-only; matrix baked-in for now).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputChannelAllowlist {
    /// Schema version.
    pub schema_version: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum AllowlistError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

impl OutputChannelAllowlist {
    /// New.
    pub fn new() -> Self { Self { schema_version: SCHEMA_VERSION.into() } }

    /// Decide.
    pub fn decide(&self, s: Sensitivity, c: OutputChannel) -> ChannelDecision {
        use ChannelDecision::*;
        use OutputChannel::*;
        use Sensitivity::*;
        match (s, c) {
            // TopSecret stays in the engine + audit.
            (TopSecret, AuditLog) => Allow,
            (TopSecret, _) => Deny,
            // Confidential: operator chat + audit only; not external.
            (Confidential, AuditLog | OperatorChat) => Allow,
            (Confidential, _) => Deny,
            // Internal: anything except external broadcast channels.
            (Internal, Webhook | EmailOut | Notification) => Deny,
            (Internal, _) => Allow,
            // Public: anywhere.
            (Public, _) => Allow,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), AllowlistError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(AllowlistError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for OutputChannelAllowlist {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_secret_only_audit() {
        let p = OutputChannelAllowlist::new();
        assert_eq!(p.decide(Sensitivity::TopSecret, OutputChannel::AuditLog), ChannelDecision::Allow);
        assert_eq!(p.decide(Sensitivity::TopSecret, OutputChannel::OperatorChat), ChannelDecision::Deny);
        assert_eq!(p.decide(Sensitivity::TopSecret, OutputChannel::Webhook), ChannelDecision::Deny);
    }

    #[test]
    fn confidential_audit_and_chat() {
        let p = OutputChannelAllowlist::new();
        assert_eq!(p.decide(Sensitivity::Confidential, OutputChannel::AuditLog), ChannelDecision::Allow);
        assert_eq!(p.decide(Sensitivity::Confidential, OutputChannel::OperatorChat), ChannelDecision::Allow);
        assert_eq!(p.decide(Sensitivity::Confidential, OutputChannel::EmailOut), ChannelDecision::Deny);
    }

    #[test]
    fn internal_blocks_external_broadcast() {
        let p = OutputChannelAllowlist::new();
        assert_eq!(p.decide(Sensitivity::Internal, OutputChannel::OperatorChat), ChannelDecision::Allow);
        assert_eq!(p.decide(Sensitivity::Internal, OutputChannel::Stdout), ChannelDecision::Allow);
        assert_eq!(p.decide(Sensitivity::Internal, OutputChannel::Webhook), ChannelDecision::Deny);
        assert_eq!(p.decide(Sensitivity::Internal, OutputChannel::EmailOut), ChannelDecision::Deny);
        assert_eq!(p.decide(Sensitivity::Internal, OutputChannel::Notification), ChannelDecision::Deny);
    }

    #[test]
    fn public_allows_everything() {
        let p = OutputChannelAllowlist::new();
        for c in [OutputChannel::Stdout, OutputChannel::AuditLog, OutputChannel::OperatorChat,
                  OutputChannel::Webhook, OutputChannel::EmailOut, OutputChannel::Notification,
                  OutputChannel::FileOut] {
            assert_eq!(p.decide(Sensitivity::Public, c), ChannelDecision::Allow);
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = OutputChannelAllowlist::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(p.validate().unwrap_err(), AllowlistError::SchemaMismatch));
    }

    #[test]
    fn channel_serde_kebab() {
        assert_eq!(serde_json::to_string(&OutputChannel::EmailOut).unwrap(), "\"email-out\"");
        assert_eq!(serde_json::to_string(&OutputChannel::OperatorChat).unwrap(), "\"operator-chat\"");
        assert_eq!(serde_json::to_string(&OutputChannel::AuditLog).unwrap(), "\"audit-log\"");
    }

    #[test]
    fn sensitivity_serde_kebab() {
        assert_eq!(serde_json::to_string(&Sensitivity::TopSecret).unwrap(), "\"top-secret\"");
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = OutputChannelAllowlist::new();
        let j = serde_json::to_string(&p).unwrap();
        let back: OutputChannelAllowlist = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
