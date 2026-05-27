//! `selfdef-evidence-redaction-policy` — per-channel redactor set.
//!
//! For each `Channel` (from `selfdef-incident-classifier`), declares
//! which `RedactorClass` (from `selfdef-audit-redaction`) apply when
//! evidence flows out. Public channels (Discord/Slack) get all
//! redactors; private channels (Loki/OpenSearch) get a subset.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use selfdef_audit_redaction::{RedactorClass, redact_one};
use selfdef_incident_classifier::Channel;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Per-channel redactor set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRedactors {
    /// Channel.
    pub channel: Channel,
    /// Active redactors for this channel.
    pub redactors: Vec<RedactorClass>,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRedactionPolicy {
    /// Schema version.
    pub schema_version: String,
    /// 11 channels.
    pub per_channel: Vec<ChannelRedactors>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum RedactionPolicyError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 11.
    #[error("per_channel count {0} != 11 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing channel: {0:?}")]
    Missing(Channel),
}

const REQUIRED: [Channel; 11] = [
    Channel::Loki,
    Channel::OpenSearch,
    Channel::Ntfy,
    Channel::Discord,
    Channel::Signal,
    Channel::Slack,
    Channel::Smtp,
    Channel::PagerDuty,
    Channel::Twilio,
    Channel::TheHive,
    Channel::Wall,
];

impl EvidenceRedactionPolicy {
    /// Canonical defaults — public channels get all, private get fewer.
    pub fn canonical() -> Self {
        let all = vec![
            RedactorClass::Email,
            RedactorClass::Ipv4,
            RedactorClass::Ipv6,
            RedactorClass::SshKey,
            RedactorClass::BearerToken,
            RedactorClass::PathHome,
        ];
        let private_set = vec![
            RedactorClass::SshKey,
            RedactorClass::BearerToken,
            RedactorClass::PathHome,
        ];
        let per_channel = vec![
            ChannelRedactors {
                channel: Channel::Loki,
                redactors: private_set.clone(),
            },
            ChannelRedactors {
                channel: Channel::OpenSearch,
                redactors: private_set.clone(),
            },
            ChannelRedactors {
                channel: Channel::Ntfy,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::Discord,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::Signal,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::Slack,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::Smtp,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::PagerDuty,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::Twilio,
                redactors: all.clone(),
            },
            ChannelRedactors {
                channel: Channel::TheHive,
                redactors: private_set.clone(),
            },
            ChannelRedactors {
                channel: Channel::Wall,
                redactors: all,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            per_channel,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), RedactionPolicyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(RedactionPolicyError::SchemaMismatch);
        }
        if self.per_channel.len() != 11 {
            return Err(RedactionPolicyError::CountInvalid(self.per_channel.len()));
        }
        for c in REQUIRED {
            if !self.per_channel.iter().any(|x| x.channel == c) {
                return Err(RedactionPolicyError::Missing(c));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn redactors_for(&self, channel: Channel) -> &[RedactorClass] {
        self.per_channel
            .iter()
            .find(|x| x.channel == channel)
            .map(|x| x.redactors.as_slice())
            .unwrap_or(&[])
    }

    /// Apply the channel's redactor set to a text.
    pub fn apply(&self, channel: Channel, text: &str) -> String {
        let mut s = text.to_string();
        for r in self.redactors_for(channel) {
            s = redact_one(&s, *r);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        EvidenceRedactionPolicy::canonical().validate().unwrap();
    }

    #[test]
    fn eleven_channels_present() {
        let p = EvidenceRedactionPolicy::canonical();
        for c in REQUIRED {
            assert!(!p.redactors_for(c).is_empty(), "missing {c:?}");
        }
    }

    #[test]
    fn discord_redacts_everything() {
        let p = EvidenceRedactionPolicy::canonical();
        let out = p.apply(
            Channel::Discord,
            "alice@ex.com from 10.0.0.1 with apikey=AAAAAAAAAAAAAAAAAAAAAAAA at /home/alice/x",
        );
        assert!(out.contains("[email]"));
        assert!(out.contains("[ipv4]"));
        assert!(out.contains("[bearer]") || out.contains("[~]") || out.contains("[ssh-key]"));
    }

    #[test]
    fn loki_skips_email_and_ipv4() {
        let p = EvidenceRedactionPolicy::canonical();
        let out = p.apply(
            Channel::Loki,
            "alice@ex.com from 10.0.0.1 path /home/alice/x",
        );
        // Loki keeps email + ipv4 visible; redacts path.
        assert!(out.contains("alice@ex.com"));
        assert!(out.contains("10.0.0.1"));
        assert!(out.contains("[~]"));
    }

    #[test]
    fn count_invalid_caught() {
        let mut p = EvidenceRedactionPolicy::canonical();
        p.per_channel.pop();
        assert!(matches!(
            p.validate().unwrap_err(),
            RedactionPolicyError::CountInvalid(10)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = EvidenceRedactionPolicy::canonical();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            RedactionPolicyError::SchemaMismatch
        ));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = EvidenceRedactionPolicy::canonical();
        let j = serde_json::to_string(&p).unwrap();
        let back: EvidenceRedactionPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
