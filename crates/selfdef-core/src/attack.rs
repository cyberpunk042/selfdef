//! MITRE ATT&CK overlay — tactics and technique references.
//!
//! Rules and collectors can attach one or more [`TechniqueRef`] to an event.
//! The correlator and downstream tools use this for ATT&CK coverage matrices
//! and prioritization.

use serde::{Deserialize, Serialize};

/// ATT&CK Enterprise tactic. Wire form: snake_case string.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Reconnaissance => "TA0043",
            Self::ResourceDevelopment => "TA0042",
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }
}

/// Reference to a specific ATT&CK technique.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechniqueRef {
    /// Full technique id, including subtechnique if applicable. e.g. `"T1110.001"`.
    pub id: String,
    /// Human-readable technique name.
    pub name: String,
    /// Tactic this technique falls under.
    pub tactic: Tactic,
}

impl TechniqueRef {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, tactic: Tactic) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            tactic,
        }
    }

    /// Convenience constructors for techniques we reference often.
    #[must_use]
    pub fn brute_force() -> Self {
        Self::new("T1110", "Brute Force", Tactic::CredentialAccess)
    }

    #[must_use]
    pub fn unsecured_credentials_files() -> Self {
        Self::new("T1552.001", "Unsecured Credentials: Credentials In Files", Tactic::CredentialAccess)
    }

    #[must_use]
    pub fn valid_accounts_local() -> Self {
        Self::new("T1078.003", "Valid Accounts: Local Accounts", Tactic::DefenseEvasion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tactic_is_snake_case_string() {
        assert_eq!(
            serde_json::to_string(&Tactic::CredentialAccess).unwrap(),
            "\"credential_access\""
        );
    }

    #[test]
    fn technique_round_trips() {
        let t = TechniqueRef::brute_force();
        let s = serde_json::to_string(&t).unwrap();
        let back: TechniqueRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }
}
