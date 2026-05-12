//! Per-class activity enumerations.
//!
//! OCSF defines activity IDs scoped per class. We provide typed enums for the
//! classes selfdef cares about; integer ids are accepted unconditionally on
//! the wire so unknown collectors/versions still round-trip.

use serde_repr::{Deserialize_repr, Serialize_repr};

// ----------------------------------------- Authentication (3002)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum AuthenticationActivity {
    Unknown = 0,
    Logon = 1,
    Logoff = 2,
    AuthenticationTicket = 3,
    ServiceTicketRequest = 4,
    ServiceTicketRenew = 5,
    Preauth = 6,
    Other = 99,
}

// ----------------------------------------- Process Activity (1007)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum ProcessActivity {
    Unknown = 0,
    Launch = 1,
    Terminate = 2,
    Open = 3,
    Inject = 4,
    SetUserId = 5,
    SetGroupId = 6,
    Other = 99,
}

// ----------------------------------------- File System Activity (1001)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum FileSystemActivity {
    Unknown = 0,
    Create = 1,
    Read = 2,
    Update = 3,
    Delete = 4,
    Rename = 5,
    SetAttributes = 6,
    SetSecurity = 7,
    GetAttributes = 8,
    GetSecurity = 9,
    Encrypt = 10,
    Decrypt = 11,
    Mount = 12,
    Unmount = 13,
    Open = 14,
    Other = 99,
}

// ----------------------------------------- Network Activity (4001)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum NetworkActivity {
    Unknown = 0,
    Open = 1,
    Close = 2,
    Reset = 3,
    Fail = 4,
    Refuse = 5,
    Traffic = 6,
    Other = 99,
}

// ----------------------------------------- SSH Activity (4007)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum SshActivity {
    Unknown = 0,
    Open = 1,
    Close = 2,
    Reset = 3,
    Fail = 4,
    Refuse = 5,
    Traffic = 6,
    Other = 99,
}

// ----------------------------------------- Account Change (3001)

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum AccountChangeActivity {
    Unknown = 0,
    Create = 1,
    Enable = 2,
    PasswordChange = 3,
    PasswordReset = 4,
    Disable = 5,
    Delete = 6,
    AttachPolicy = 7,
    DetachPolicy = 8,
    Lockout = 9,
    Other = 99,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activities_serialize_as_int() {
        assert_eq!(
            serde_json::to_string(&AuthenticationActivity::Logon).unwrap(),
            "1"
        );
        assert_eq!(
            serde_json::to_string(&ProcessActivity::Launch).unwrap(),
            "1"
        );
        assert_eq!(
            serde_json::to_string(&NetworkActivity::Refuse).unwrap(),
            "5"
        );
    }
}
