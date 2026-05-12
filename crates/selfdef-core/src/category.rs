//! OCSF category and class taxonomy.
//!
//! - [`CategoryUid`] is a closed enum of the six OCSF categories (plus
//!   `Unknown` and `Other`).
//! - [`ClassUid`] is a newtype around the integer class id; OCSF defines
//!   ~50 classes today and may add more, so we keep it open with named
//!   constants for the classes selfdef cares about.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF top-level category. Wire form: integer.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum CategoryUid {
    Unknown = 0,
    SystemActivity = 1,
    Findings = 2,
    /// Identity & Access Management.
    Iam = 3,
    NetworkActivity = 4,
    Discovery = 5,
    ApplicationActivity = 6,
    Other = 99,
}

impl CategoryUid {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::SystemActivity => "System Activity",
            Self::Findings => "Findings",
            Self::Iam => "Identity & Access Management",
            Self::NetworkActivity => "Network Activity",
            Self::Discovery => "Discovery",
            Self::ApplicationActivity => "Application Activity",
            Self::Other => "Other",
        }
    }
}

impl std::fmt::Display for CategoryUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ----------------------------------------------------------------- ClassUid

/// OCSF class UID. Newtype wrapper around the integer id.
///
/// Named constants are provided for the classes selfdef emits; other classes
/// can be constructed with [`ClassUid::new`] and will round-trip unchanged.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassUid(pub u32);

impl ClassUid {
    // ---- System Activity (category 1) ----
    pub const FILE_SYSTEM_ACTIVITY: Self = Self(1001);
    pub const KERNEL_EXTENSION: Self = Self(1002);
    pub const KERNEL_ACTIVITY: Self = Self(1003);
    pub const MEMORY_ACTIVITY: Self = Self(1004);
    pub const MODULE_ACTIVITY: Self = Self(1005);
    pub const SCHEDULED_JOB: Self = Self(1006);
    pub const PROCESS_ACTIVITY: Self = Self(1007);

    // ---- Findings (category 2) ----
    pub const SECURITY_FINDING: Self = Self(2001);
    pub const DETECTION_FINDING: Self = Self(2004);
    pub const INCIDENT_FINDING: Self = Self(2005);

    // ---- IAM (category 3) ----
    pub const ACCOUNT_CHANGE: Self = Self(3001);
    pub const AUTHENTICATION: Self = Self(3002);
    pub const AUTHORIZE_SESSION: Self = Self(3003);
    pub const GROUP_MANAGEMENT: Self = Self(3006);

    // ---- Network Activity (category 4) ----
    pub const NETWORK_ACTIVITY: Self = Self(4001);
    pub const HTTP_ACTIVITY: Self = Self(4002);
    pub const DNS_ACTIVITY: Self = Self(4003);
    pub const SSH_ACTIVITY: Self = Self(4007);

    /// Construct from a raw integer. Use only when no named constant fits.
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        Self(uid)
    }

    /// The category this class belongs to, derived from the thousands digit.
    #[must_use]
    pub const fn category(self) -> CategoryUid {
        match self.0 / 1000 {
            1 => CategoryUid::SystemActivity,
            2 => CategoryUid::Findings,
            3 => CategoryUid::Iam,
            4 => CategoryUid::NetworkActivity,
            5 => CategoryUid::Discovery,
            6 => CategoryUid::ApplicationActivity,
            _ => CategoryUid::Other,
        }
    }

    /// Human-readable class name. Returns "Unknown" for unrecognized ids.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            1001 => "File System Activity",
            1002 => "Kernel Extension",
            1003 => "Kernel Activity",
            1004 => "Memory Activity",
            1005 => "Module Activity",
            1006 => "Scheduled Job",
            1007 => "Process Activity",
            2001 => "Security Finding",
            2004 => "Detection Finding",
            2005 => "Incident Finding",
            3001 => "Account Change",
            3002 => "Authentication",
            3003 => "Authorize Session",
            3006 => "Group Management",
            4001 => "Network Activity",
            4002 => "HTTP Activity",
            4003 => "DNS Activity",
            4007 => "SSH Activity",
            _ => "Unknown",
        }
    }

    /// Compute `type_uid = class_uid * 100 + activity_id` per OCSF.
    #[must_use]
    pub const fn type_uid(self, activity_id: u32) -> u64 {
        (self.0 as u64) * 100 + (activity_id as u64)
    }
}

impl std::fmt::Display for ClassUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_serializes_as_int() {
        assert_eq!(serde_json::to_string(&CategoryUid::Iam).unwrap(), "3");
    }

    #[test]
    fn class_uid_round_trip() {
        let c = ClassUid::AUTHENTICATION;
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(s, "3002");
        let back: ClassUid = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn category_derivation() {
        assert_eq!(ClassUid::AUTHENTICATION.category(), CategoryUid::Iam);
        assert_eq!(
            ClassUid::PROCESS_ACTIVITY.category(),
            CategoryUid::SystemActivity
        );
        assert_eq!(
            ClassUid::NETWORK_ACTIVITY.category(),
            CategoryUid::NetworkActivity
        );
    }

    #[test]
    fn type_uid_formula() {
        // OCSF: Authentication / Logon = 3002 * 100 + 1 = 300201
        assert_eq!(ClassUid::AUTHENTICATION.type_uid(1), 300_201);
    }

    #[test]
    fn unknown_class_round_trips() {
        let c = ClassUid::new(9999);
        let s = serde_json::to_string(&c).unwrap();
        let back: ClassUid = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
        assert_eq!(c.name(), "Unknown");
    }
}
