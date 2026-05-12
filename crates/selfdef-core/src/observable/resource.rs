//! Resource observables: files and other on-disk artifacts.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use time::OffsetDateTime;

use super::actor::User;
use super::hash::Hash;

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum FileType {
    Unknown = 0,
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    CharacterDevice = 4,
    BlockDevice = 5,
    Pipe = 6,
    Socket = 7,
    Other = 99,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// Just the basename. e.g. `passwd`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Full path. e.g. `/etc/passwd`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<FileType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// One entry per hash algorithm computed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User>,
    /// POSIX mode, e.g. `0o600`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::envelope::opt_rfc3339",
        default
    )]
    pub created_time_dt: Option<OffsetDateTime>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "crate::envelope::opt_rfc3339",
        default
    )]
    pub modified_time_dt: Option<OffsetDateTime>,
}

impl File {
    #[must_use]
    pub fn at_path(path: impl Into<String>) -> Self {
        Self {
            path: Some(path.into()),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_serializes_minimally() {
        let f = File::at_path("/etc/passwd");
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["path"], "/etc/passwd");
        assert!(v.get("hashes").is_none(), "empty vec omitted");
        assert!(v.get("size").is_none(), "absent fields omitted");
    }
}
