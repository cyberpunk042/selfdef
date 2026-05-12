//! Actor observables: who or what performed the activity.
//!
//! [`Actor`] groups [`User`], [`Process`], and [`Session`] — all optional.
//! Collectors fill what they know.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Local or remote user identity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// POSIX numeric UID, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Account name (login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// String-form ID for systems where numeric uid doesn't apply (cloud ARNs etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_str: Option<String>,
    /// Domain / realm / cloud account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Primary group, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
}

impl User {
    #[must_use]
    pub fn local(uid: u32, name: impl Into<String>) -> Self {
        Self {
            uid: Some(uid),
            name: Some(name.into()),
            ..Self::default()
        }
    }
}

/// Process. May represent the actor (the doer) or the subject (the affected
/// process), depending on its placement in [`crate::Event`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Full executable path, e.g. `/usr/bin/sshd`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Full command line as observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::envelope::opt_rfc3339",
        default
    )]
    pub created_time_dt: Option<OffsetDateTime>,
    /// User the process runs as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// SHA-256 of the executable image, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_sha256: Option<String>,
}

impl Process {
    #[must_use]
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            ..Self::default()
        }
    }
}

/// Logon session or equivalent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::envelope::opt_rfc3339",
        default
    )]
    pub created_time_dt: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_remote: Option<bool>,
    /// `tty`, `ssh`, `console`, `service`, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The doer of the activity. All members optional so collectors fill only
/// what they observed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<Session>,
    /// Free-form caller hint (e.g. `"systemd"` invoking a unit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoked_by: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_user_round_trips() {
        let u = User::default();
        let s = serde_json::to_string(&u).unwrap();
        // No optional fields → empty object.
        assert_eq!(s, "{}");
        let back: User = serde_json::from_str(&s).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn process_serializes_cleanly() {
        let p = Process {
            pid: 42,
            name: Some("sshd".into()),
            ..Process::default()
        };
        let s = serde_json::to_value(&p).unwrap();
        assert_eq!(s["pid"], 42);
        assert_eq!(s["name"], "sshd");
        assert!(s.get("cmdline").is_none(), "absent fields omitted");
    }
}
