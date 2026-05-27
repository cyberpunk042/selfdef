//! `selfdef-incident-classifier` — 5-level incident taxonomy.
//!
//! Each incident severity declares:
//! - which notifier channels it dispatches to
//! - whether it pages the on-call rotation
//! - whether it locks the cockpit
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// 5 severity levels (rank order: Info < Notice < Warn < Critical < Emergency).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational — e.g. boot complete.
    Info,
    /// Background notice — non-actionable.
    Notice,
    /// Warning — operator should be informed but no immediate action.
    Warn,
    /// Critical — operator must act soon.
    Critical,
    /// Emergency — operator must act immediately; cockpit locked.
    Emergency,
}

/// Notifier channels (matches existing selfdef-integration-* crates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Channel {
    /// Loki log sink.
    Loki,
    /// OpenSearch index.
    OpenSearch,
    /// ntfy push.
    Ntfy,
    /// Discord webhook.
    Discord,
    /// Signal message.
    Signal,
    /// Slack.
    Slack,
    /// SMTP email.
    Smtp,
    /// PagerDuty (on-call rotation).
    PagerDuty,
    /// Twilio SMS.
    Twilio,
    /// TheHive case ticket.
    TheHive,
    /// `wall` to logged-in operators.
    Wall,
}

/// Per-severity dispatch profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchProfile {
    /// Severity.
    pub severity: Severity,
    /// Channels.
    pub channels: Vec<Channel>,
    /// Pages on-call rotation.
    pub pages_on_call: bool,
    /// Locks cockpit to operator-acknowledge.
    pub locks_cockpit: bool,
}

/// Registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentTaxonomy {
    /// Schema version.
    pub schema_version: String,
    /// 5 dispatch profiles.
    pub profiles: Vec<DispatchProfile>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum IncidentError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Count != 5.
    #[error("profile count {0} != 5 canonical")]
    CountInvalid(usize),
    /// Missing.
    #[error("missing severity: {0:?}")]
    Missing(Severity),
    /// Channel set empty.
    #[error("severity {0:?} has no channels")]
    EmptyChannels(Severity),
}

impl IncidentTaxonomy {
    /// Canonical taxonomy.
    pub fn canonical() -> Self {
        use Channel::*;
        let profiles = vec![
            DispatchProfile {
                severity: Severity::Info,
                channels: vec![Loki, OpenSearch],
                pages_on_call: false,
                locks_cockpit: false,
            },
            DispatchProfile {
                severity: Severity::Notice,
                channels: vec![Loki, OpenSearch, Ntfy],
                pages_on_call: false,
                locks_cockpit: false,
            },
            DispatchProfile {
                severity: Severity::Warn,
                channels: vec![Loki, OpenSearch, Ntfy, Discord, Slack],
                pages_on_call: false,
                locks_cockpit: false,
            },
            DispatchProfile {
                severity: Severity::Critical,
                channels: vec![
                    Loki, OpenSearch, Ntfy, Discord, Slack, Smtp, PagerDuty, TheHive,
                ],
                pages_on_call: true,
                locks_cockpit: false,
            },
            DispatchProfile {
                severity: Severity::Emergency,
                channels: vec![
                    Loki, OpenSearch, Ntfy, Discord, Slack, Smtp, PagerDuty, Twilio, Signal,
                    TheHive, Wall,
                ],
                pages_on_call: true,
                locks_cockpit: true,
            },
        ];
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), IncidentError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(IncidentError::SchemaMismatch);
        }
        if self.profiles.len() != 5 {
            return Err(IncidentError::CountInvalid(self.profiles.len()));
        }
        for s in [
            Severity::Info,
            Severity::Notice,
            Severity::Warn,
            Severity::Critical,
            Severity::Emergency,
        ] {
            if !self.profiles.iter().any(|p| p.severity == s) {
                return Err(IncidentError::Missing(s));
            }
        }
        for p in &self.profiles {
            if p.channels.is_empty() {
                return Err(IncidentError::EmptyChannels(p.severity));
            }
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, s: Severity) -> Option<&DispatchProfile> {
        self.profiles.iter().find(|p| p.severity == s)
    }

    /// Channels for severity.
    pub fn channels(&self, s: Severity) -> &[Channel] {
        self.get(s).map(|p| p.channels.as_slice()).unwrap_or(&[])
    }

    /// True if severity pages on-call.
    pub fn pages(&self, s: Severity) -> bool {
        self.get(s).map(|p| p.pages_on_call).unwrap_or(false)
    }

    /// True if severity locks cockpit.
    pub fn locks(&self, s: Severity) -> bool {
        self.get(s).map(|p| p.locks_cockpit).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        IncidentTaxonomy::canonical().validate().unwrap();
    }

    #[test]
    fn five_severities_present() {
        let t = IncidentTaxonomy::canonical();
        for s in [
            Severity::Info,
            Severity::Notice,
            Severity::Warn,
            Severity::Critical,
            Severity::Emergency,
        ] {
            assert!(t.get(s).is_some(), "missing {s:?}");
        }
    }

    #[test]
    fn info_channels_minimal() {
        let t = IncidentTaxonomy::canonical();
        let c = t.channels(Severity::Info);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&Channel::Loki));
        assert!(c.contains(&Channel::OpenSearch));
    }

    #[test]
    fn critical_pages_on_call() {
        let t = IncidentTaxonomy::canonical();
        assert!(t.pages(Severity::Critical));
        assert!(!t.locks(Severity::Critical));
    }

    #[test]
    fn emergency_locks_cockpit_and_pages() {
        let t = IncidentTaxonomy::canonical();
        assert!(t.pages(Severity::Emergency));
        assert!(t.locks(Severity::Emergency));
    }

    #[test]
    fn emergency_includes_wall_and_twilio_and_signal() {
        let t = IncidentTaxonomy::canonical();
        let c = t.channels(Severity::Emergency);
        assert!(c.contains(&Channel::Wall));
        assert!(c.contains(&Channel::Twilio));
        assert!(c.contains(&Channel::Signal));
    }

    #[test]
    fn warn_does_not_page_or_lock() {
        let t = IncidentTaxonomy::canonical();
        assert!(!t.pages(Severity::Warn));
        assert!(!t.locks(Severity::Warn));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Notice);
        assert!(Severity::Notice < Severity::Warn);
        assert!(Severity::Warn < Severity::Critical);
        assert!(Severity::Critical < Severity::Emergency);
    }

    #[test]
    fn schema_drift_rejected() {
        let mut t = IncidentTaxonomy::canonical();
        t.schema_version = "9.9.9".into();
        assert!(matches!(
            t.validate().unwrap_err(),
            IncidentError::SchemaMismatch
        ));
    }

    #[test]
    fn count_invalid_caught() {
        let mut t = IncidentTaxonomy::canonical();
        t.profiles.pop();
        assert!(matches!(
            t.validate().unwrap_err(),
            IncidentError::CountInvalid(4)
        ));
    }

    #[test]
    fn empty_channels_caught() {
        let mut t = IncidentTaxonomy::canonical();
        t.profiles[0].channels.clear();
        assert!(matches!(
            t.validate().unwrap_err(),
            IncidentError::EmptyChannels(Severity::Info)
        ));
    }

    #[test]
    fn severity_serde_kebab() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Emergency).unwrap(),
            "\"emergency\""
        );
    }

    #[test]
    fn channel_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&Channel::PagerDuty).unwrap(),
            "\"pager-duty\""
        );
        assert_eq!(
            serde_json::to_string(&Channel::TheHive).unwrap(),
            "\"the-hive\""
        );
        assert_eq!(
            serde_json::to_string(&Channel::OpenSearch).unwrap(),
            "\"open-search\""
        );
    }

    #[test]
    fn taxonomy_serde_roundtrip() {
        let t = IncidentTaxonomy::canonical();
        let j = serde_json::to_string(&t).unwrap();
        let back: IncidentTaxonomy = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }
}
