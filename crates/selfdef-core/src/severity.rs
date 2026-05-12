//! Event severity grading.
//!
//! Aligned with OCSF `severity_id` integer enumeration. Two representations:
//! - [`SeverityId`] — wire form, serializes as integer.
//! - [`SeverityId::name`] — human-readable label.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF-aligned severity. Serializes as integer on the wire.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum SeverityId {
    Unknown = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
    Fatal = 6,
    Other = 99,
}

impl SeverityId {
    /// Stable string label, matching the OCSF `severity` field convention.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Informational => "Informational",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
            Self::Fatal => "Fatal",
            Self::Other => "Other",
        }
    }

    /// Returns `true` for severities that should trigger immediate operator
    /// notification by default. Tunable per deployment via rule metadata.
    #[must_use]
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::High | Self::Critical | Self::Fatal)
    }
}

impl std::fmt::Display for SeverityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_is_integer() {
        let s = serde_json::to_string(&SeverityId::High).unwrap();
        assert_eq!(s, "4");
    }

    #[test]
    fn ordering_is_intuitive() {
        assert!(SeverityId::Critical > SeverityId::High);
        assert!(SeverityId::High > SeverityId::Medium);
        assert!(SeverityId::Medium > SeverityId::Low);
        assert!(SeverityId::Low > SeverityId::Informational);
    }

    #[test]
    fn actionable_threshold() {
        assert!(SeverityId::Critical.is_actionable());
        assert!(SeverityId::High.is_actionable());
        assert!(!SeverityId::Medium.is_actionable());
        assert!(!SeverityId::Informational.is_actionable());
    }
}
