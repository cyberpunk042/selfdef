//! `selfdef-substrate-thread-quota` — per-Profile concurrent-thread cap.
//!
//! Each Profile carries `max_threads`. `spawn(label)` returns
//! `Granted{thread_id}` or `Exhausted{live, cap}`. `finish(id)` frees.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Profile.
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

/// Per-profile config.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileThreads {
    /// Max live threads.
    pub max_threads: u32,
}

/// One live thread.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveThread {
    /// Thread id.
    pub thread_id: u64,
    /// Profile.
    pub profile: Profile,
    /// Label.
    pub label: String,
}

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateThreadQuota {
    /// Schema version.
    pub schema_version: String,
    /// Per-profile configs.
    pub profiles: BTreeMap<Profile, ProfileThreads>,
    /// Live threads.
    pub live: Vec<LiveThread>,
    /// Next id.
    pub next_id: u64,
}

/// Spawn verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SpawnVerdict {
    /// Granted.
    Granted {
        /// id.
        thread_id: u64,
    },
    /// Cap reached.
    Exhausted {
        /// live count.
        live: u32,
        /// cap.
        cap: u32,
    },
    /// Profile unconfigured.
    Unconfigured,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ThreadError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Unknown thread id.
    #[error("unknown thread: {0}")]
    UnknownThread(u64),
}

impl SubstrateThreadQuota {
    /// Canonical defaults.
    pub fn canonical() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(Profile::Private, ProfileThreads { max_threads: 4 });
        profiles.insert(Profile::Fast, ProfileThreads { max_threads: 16 });
        profiles.insert(Profile::Careful, ProfileThreads { max_threads: 8 });
        profiles.insert(Profile::Autonomous, ProfileThreads { max_threads: 32 });
        profiles.insert(Profile::Experimental, ProfileThreads { max_threads: 64 });
        profiles.insert(Profile::Production, ProfileThreads { max_threads: 8 });
        Self {
            schema_version: SCHEMA_VERSION.into(),
            profiles,
            live: Vec::new(),
            next_id: 1,
        }
    }

    /// Spawn.
    pub fn spawn(&mut self, profile: Profile, label: &str) -> SpawnVerdict {
        let cfg = match self.profiles.get(&profile) {
            Some(c) => *c,
            None => return SpawnVerdict::Unconfigured,
        };
        let live = self.live.iter().filter(|t| t.profile == profile).count() as u32;
        if live >= cfg.max_threads {
            return SpawnVerdict::Exhausted { live, cap: cfg.max_threads };
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.live.push(LiveThread { thread_id: id, profile, label: label.into() });
        SpawnVerdict::Granted { thread_id: id }
    }

    /// Finish.
    pub fn finish(&mut self, thread_id: u64) -> Result<(), ThreadError> {
        let pos = self.live.iter().position(|t| t.thread_id == thread_id)
            .ok_or(ThreadError::UnknownThread(thread_id))?;
        self.live.remove(pos);
        Ok(())
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ThreadError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ThreadError::SchemaMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validates() {
        SubstrateThreadQuota::canonical().validate().unwrap();
    }

    #[test]
    fn spawn_grants() {
        let mut q = SubstrateThreadQuota::canonical();
        assert!(matches!(q.spawn(Profile::Fast, "w1"), SpawnVerdict::Granted { .. }));
    }

    #[test]
    fn exhausted_when_full() {
        let mut q = SubstrateThreadQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileThreads { max_threads: 1 });
        q.spawn(Profile::Fast, "a");
        assert!(matches!(q.spawn(Profile::Fast, "b"), SpawnVerdict::Exhausted { .. }));
    }

    #[test]
    fn finish_frees() {
        let mut q = SubstrateThreadQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileThreads { max_threads: 1 });
        let id = match q.spawn(Profile::Fast, "a") {
            SpawnVerdict::Granted { thread_id } => thread_id,
            _ => unreachable!(),
        };
        q.finish(id).unwrap();
        assert!(matches!(q.spawn(Profile::Fast, "b"), SpawnVerdict::Granted { .. }));
    }

    #[test]
    fn finish_unknown_rejected() {
        let mut q = SubstrateThreadQuota::canonical();
        assert!(matches!(q.finish(999).unwrap_err(), ThreadError::UnknownThread(_)));
    }

    #[test]
    fn unconfigured_profile() {
        let mut q = SubstrateThreadQuota::canonical();
        q.profiles.clear();
        assert!(matches!(q.spawn(Profile::Fast, "a"), SpawnVerdict::Unconfigured));
    }

    #[test]
    fn per_profile_isolation() {
        let mut q = SubstrateThreadQuota::canonical();
        q.profiles.insert(Profile::Fast, ProfileThreads { max_threads: 1 });
        q.spawn(Profile::Fast, "a");
        assert!(matches!(q.spawn(Profile::Production, "p"), SpawnVerdict::Granted { .. }));
        assert!(matches!(q.spawn(Profile::Fast, "b"), SpawnVerdict::Exhausted { .. }));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut q = SubstrateThreadQuota::canonical();
        q.schema_version = "9.9.9".into();
        assert!(matches!(q.validate().unwrap_err(), ThreadError::SchemaMismatch));
    }

    #[test]
    fn thread_serde_roundtrip() {
        let mut q = SubstrateThreadQuota::canonical();
        q.spawn(Profile::Fast, "a");
        let j = serde_json::to_string(&q).unwrap();
        let back: SubstrateThreadQuota = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }
}
