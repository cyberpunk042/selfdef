//! `selfdef-substrate-fd-quota` — per-Profile open-FD cap.
//!
//! Each Profile carries `max_open_fds`. `open()` returns
//! `Granted{handle_id}` or `Exhausted{open, cap}`. `close()` frees by
//! handle id. Distinct from the cpu / gpu / disk / network-egress
//! lanes.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile (mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Private.
    Private,
    /// Fast.
    Fast,
    /// Careful.
    Careful,
    /// Autonomous.
    Autonomous,
    /// Experimental.
    Experimental,
    /// Production.
    Production,
}

/// Per-Profile config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileFd {
    /// Max simultaneously-open file descriptors.
    pub max_open_fds: u32,
}

/// One open handle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handle {
    /// Handle id.
    pub handle_id: u64,
    /// Profile.
    pub profile: Profile,
    /// Optional path / label.
    pub label: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateFdQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile caps.
    pub profiles: BTreeMap<Profile, ProfileFd>,
    /// Currently open handles.
    pub handles: Vec<Handle>,
    /// Next handle id.
    pub next_id: u64,
}

/// Open verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OpenVerdict {
    /// Granted.
    Granted {
        /// id.
        handle_id: u64,
    },
    /// Cap reached.
    Exhausted {
        /// currently open for profile.
        open: u32,
        /// cap.
        cap: u32,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FdError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown handle.
    #[error("unknown handle: {0}")]
    UnknownHandle(u64),
}

impl SubstrateFdQuota {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(Profile::Private, ProfileFd { max_open_fds: 32 });
        profiles.insert(Profile::Fast, ProfileFd { max_open_fds: 128 });
        profiles.insert(Profile::Careful, ProfileFd { max_open_fds: 64 });
        profiles.insert(Profile::Autonomous, ProfileFd { max_open_fds: 256 });
        profiles.insert(Profile::Experimental, ProfileFd { max_open_fds: 512 });
        profiles.insert(Profile::Production, ProfileFd { max_open_fds: 64 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            handles: Vec::new(),
            next_id: 1,
        }
    }

    /// Open one handle.
    pub fn open(&mut self, profile: Profile, label: &str) -> OpenVerdict {
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return OpenVerdict::Unconfigured,
        };
        let open = self.handles.iter().filter(|h| h.profile == profile).count() as u32;
        if open >= cfg.max_open_fds {
            return OpenVerdict::Exhausted {
                open,
                cap: cfg.max_open_fds,
            };
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.handles.push(Handle {
            handle_id: id,
            profile,
            label: label.into(),
        });
        OpenVerdict::Granted { handle_id: id }
    }

    /// Close.
    pub fn close(&mut self, handle_id: u64) -> Result<(), FdError> {
        let pos = self
            .handles
            .iter()
            .position(|h| h.handle_id == handle_id)
            .ok_or(FdError::UnknownHandle(handle_id))?;
        self.handles.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FdError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FdError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateFdQuota::canonical().validate().unwrap();
    }

    #[test]
    fn open_grants() {
        let mut q = SubstrateFdQuota::canonical();
        assert!(matches!(
            q.open(Profile::Fast, "a"),
            OpenVerdict::Granted { .. }
        ));
    }

    #[test]
    fn exhausted_when_full() {
        let mut q = SubstrateFdQuota::canonical();
        q.profiles
            .insert(Profile::Fast, ProfileFd { max_open_fds: 2 });
        q.open(Profile::Fast, "a");
        q.open(Profile::Fast, "b");
        let v = q.open(Profile::Fast, "c");
        match v {
            OpenVerdict::Exhausted { open, cap } => {
                assert_eq!(open, 2);
                assert_eq!(cap, 2);
            }
            _ => panic!("expected exhausted"),
        }
    }

    #[test]
    fn close_frees() {
        let mut q = SubstrateFdQuota::canonical();
        q.profiles
            .insert(Profile::Fast, ProfileFd { max_open_fds: 1 });
        let id = match q.open(Profile::Fast, "a") {
            OpenVerdict::Granted { handle_id } => handle_id,
            _ => unreachable!(),
        };
        assert!(matches!(
            q.open(Profile::Fast, "b"),
            OpenVerdict::Exhausted { .. }
        ));
        q.close(id).unwrap();
        assert!(matches!(
            q.open(Profile::Fast, "b"),
            OpenVerdict::Granted { .. }
        ));
    }

    #[test]
    fn close_unknown_rejected() {
        let mut q = SubstrateFdQuota::canonical();
        assert!(matches!(
            q.close(999).unwrap_err(),
            FdError::UnknownHandle(_)
        ));
    }

    #[test]
    fn unconfigured_returns_unconfigured() {
        let mut q = SubstrateFdQuota::canonical();
        q.profiles.clear();
        assert!(matches!(
            q.open(Profile::Fast, "a"),
            OpenVerdict::Unconfigured
        ));
    }

    #[test]
    fn per_profile_isolation() {
        let mut q = SubstrateFdQuota::canonical();
        q.profiles
            .insert(Profile::Fast, ProfileFd { max_open_fds: 1 });
        q.open(Profile::Fast, "a");
        // Fast is full; other profiles still grant.
        assert!(matches!(
            q.open(Profile::Production, "x"),
            OpenVerdict::Granted { .. }
        ));
        assert!(matches!(
            q.open(Profile::Fast, "b"),
            OpenVerdict::Exhausted { .. }
        ));
    }

    #[test]
    fn handle_ids_unique() {
        let mut q = SubstrateFdQuota::canonical();
        let ids: Vec<u64> = (0..5)
            .map(|i| match q.open(Profile::Fast, &format!("h{i}")) {
                OpenVerdict::Granted { handle_id } => handle_id,
                _ => 0,
            })
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateFdQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), FdError::SchemaMismatch));
    }

    #[test]
    fn fd_serde_roundtrip() {
        let mut q = SubstrateFdQuota::canonical();
        q.open(Profile::Fast, "a");
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateFdQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
