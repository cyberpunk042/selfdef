//! `selfdef-substrate-replay-validator` — replay-env compatibility.
//!
//! Compares (recorded, current) ReplayEnv tuples. Returns Identical
//! when all match; Compatible when engine_version differs but
//! rule_bundle_digest and tool_versions match; Incompatible
//! otherwise.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Env snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayEnv {
    /// Engine version semver.
    pub engine_version: String,
    /// Rule bundle FNV-1a hex.
    pub rule_bundle_digest: String,
    /// Tool id → version digest hex.
    pub tool_versions: BTreeMap<String, String>,
}

/// Compatibility decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CompatVerdict {
    /// All match.
    Identical,
    /// engine_version differs but bundle + tools match.
    Compatible {
        /// recorded.
        recorded_engine_version: String,
        /// current.
        current_engine_version: String,
    },
    /// Bundle or tool version differs.
    Incompatible {
        /// list of (kind, recorded, current).
        diffs: Vec<EnvDiff>,
    },
}

/// Single env diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvDiff {
    /// "rule-bundle" / "tool:<id>".
    pub kind: String,
    /// Recorded value.
    pub recorded: String,
    /// Current value.
    pub current: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
}

/// Stateless validator.
#[derive(Debug, Clone, Default)]
pub struct ReplayEnvValidator;

impl ReplayEnvValidator {
    /// Compare.
    pub fn compare(recorded: &ReplayEnv, current: &ReplayEnv) -> CompatVerdict {
        let mut diffs: Vec<EnvDiff> = Vec::new();
        if recorded.rule_bundle_digest != current.rule_bundle_digest {
            diffs.push(EnvDiff {
                kind: "rule-bundle".into(),
                recorded: recorded.rule_bundle_digest.clone(),
                current: current.rule_bundle_digest.clone(),
            });
        }
        // Find tool diffs (added, removed, changed).
        for (id, rec_ver) in &recorded.tool_versions {
            match current.tool_versions.get(id) {
                Some(cur_ver) if cur_ver != rec_ver => {
                    diffs.push(EnvDiff {
                        kind: format!("tool:{id}"),
                        recorded: rec_ver.clone(),
                        current: cur_ver.clone(),
                    });
                }
                None => {
                    diffs.push(EnvDiff {
                        kind: format!("tool-removed:{id}"),
                        recorded: rec_ver.clone(),
                        current: String::new(),
                    });
                }
                _ => {}
            }
        }
        for (id, cur_ver) in &current.tool_versions {
            if !recorded.tool_versions.contains_key(id) {
                diffs.push(EnvDiff {
                    kind: format!("tool-added:{id}"),
                    recorded: String::new(),
                    current: cur_ver.clone(),
                });
            }
        }
        if !diffs.is_empty() {
            return CompatVerdict::Incompatible { diffs };
        }
        if recorded.engine_version == current.engine_version {
            CompatVerdict::Identical
        } else {
            CompatVerdict::Compatible {
                recorded_engine_version: recorded.engine_version.clone(),
                current_engine_version: current.engine_version.clone(),
            }
        }
    }
}

/// Envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubstrateReplayValidator {
    /// Schema version.
    pub schema_version: String,
}

impl SubstrateReplayValidator {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), ValidatorError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidatorError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for SubstrateReplayValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(engine: &str, bundle: &str, tools: &[(&str, &str)]) -> ReplayEnv {
        ReplayEnv {
            engine_version: engine.into(),
            rule_bundle_digest: bundle.into(),
            tool_versions: tools
                .iter()
                .map(|(id, v)| ((*id).into(), (*v).into()))
                .collect(),
        }
    }

    #[test]
    fn identical_matches() {
        let a = env("1.0.0", "abc", &[("git", "v1"), ("ls", "v2")]);
        let b = env("1.0.0", "abc", &[("git", "v1"), ("ls", "v2")]);
        assert!(matches!(
            ReplayEnvValidator::compare(&a, &b),
            CompatVerdict::Identical
        ));
    }

    #[test]
    fn engine_only_compatible() {
        let a = env("1.0.0", "abc", &[("git", "v1")]);
        let b = env("1.0.1", "abc", &[("git", "v1")]);
        assert!(matches!(
            ReplayEnvValidator::compare(&a, &b),
            CompatVerdict::Compatible { .. }
        ));
    }

    #[test]
    fn bundle_diff_incompatible() {
        let a = env("1.0.0", "abc", &[("git", "v1")]);
        let b = env("1.0.0", "def", &[("git", "v1")]);
        let v = ReplayEnvValidator::compare(&a, &b);
        match v {
            CompatVerdict::Incompatible { diffs } => {
                assert!(diffs.iter().any(|d| d.kind == "rule-bundle"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn tool_version_diff_incompatible() {
        let a = env("1.0.0", "abc", &[("git", "v1")]);
        let b = env("1.0.0", "abc", &[("git", "v2")]);
        let v = ReplayEnvValidator::compare(&a, &b);
        match v {
            CompatVerdict::Incompatible { diffs } => {
                assert!(diffs.iter().any(|d| d.kind == "tool:git"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn tool_removed_reported() {
        let a = env("1.0.0", "abc", &[("git", "v1"), ("ls", "v2")]);
        let b = env("1.0.0", "abc", &[("git", "v1")]);
        let v = ReplayEnvValidator::compare(&a, &b);
        match v {
            CompatVerdict::Incompatible { diffs } => {
                assert!(diffs.iter().any(|d| d.kind == "tool-removed:ls"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn tool_added_reported() {
        let a = env("1.0.0", "abc", &[("git", "v1")]);
        let b = env("1.0.0", "abc", &[("git", "v1"), ("ls", "v2")]);
        let v = ReplayEnvValidator::compare(&a, &b);
        match v {
            CompatVerdict::Incompatible { diffs } => {
                assert!(diffs.iter().any(|d| d.kind == "tool-added:ls"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn schema_drift_rejected() {
        let mut v = SubstrateReplayValidator::new();
        v.schema_version = "9.9.9".into();
        assert!(matches!(
            v.validate().unwrap_err(),
            ValidatorError::SchemaMismatch
        ));
    }

    #[test]
    fn verdict_serde_kebab() {
        let v = CompatVerdict::Identical;
        assert!(
            serde_json::to_string(&v)
                .unwrap()
                .contains("\"kind\":\"identical\"")
        );
    }

    #[test]
    fn env_serde_roundtrip() {
        let a = env("1.0.0", "abc", &[("git", "v1")]);
        let j = serde_json::to_string(&a).unwrap();
        let back: ReplayEnv = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
