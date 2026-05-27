//! `selfdef-fs-watch-policy` — file-system watch authority.
//!
//! Encodes which absolute paths the engine may register a watcher
//! on. Allow-list with simple glob support (`*`/`?`/`**`), explicit
//! deny-list (deny wins), and a `never_watch` set (always denied).
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchDecision {
    /// Watch permitted.
    Allow,
    /// Watch denied.
    Deny,
}

/// Policy envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FsWatchPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Allow globs (absolute, may contain * ? **).
    pub allow: Vec<String>,
    /// Deny globs (override allow).
    pub deny: Vec<String>,
    /// Never-watch hard set (override everything).
    pub never_watch: Vec<String>,
}

/// Errors.
#[derive(Debug, Error)]
pub enum FsWatchError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Relative pattern.
    #[error("pattern {0:?} must be absolute (start with /)")]
    NotAbsolute(String),
    /// Empty pattern.
    #[error("empty pattern in {section}")]
    EmptyPattern {
        /// section.
        section: String,
    },
}

impl FsWatchPolicy {
    /// New empty policy.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            allow: Vec::new(),
            deny: Vec::new(),
            never_watch: Vec::new(),
        }
    }

    /// Canonical: allow common project paths, never-watch operator
    /// secrets dirs (~/.ssh, ~/.gnupg, ~/.aws, /etc/shadow).
    pub fn canonical(home: &str) -> Self {
        let mut p = Self::new();
        p.allow.push(format!("{home}/projects/**"));
        p.allow.push(format!("{home}/code/**"));
        p.allow.push("/var/log/**".into());
        p.never_watch.push(format!("{home}/.ssh/**"));
        p.never_watch.push(format!("{home}/.gnupg/**"));
        p.never_watch.push(format!("{home}/.aws/**"));
        p.never_watch.push("/etc/shadow".into());
        p
    }

    /// Decide a single absolute path.
    pub fn decide(&self, path: &str) -> WatchDecision {
        if !path.starts_with('/') {
            return WatchDecision::Deny;
        }
        if self.never_watch.iter().any(|g| glob_match(g, path)) {
            return WatchDecision::Deny;
        }
        if self.deny.iter().any(|g| glob_match(g, path)) {
            return WatchDecision::Deny;
        }
        if self.allow.iter().any(|g| glob_match(g, path)) {
            return WatchDecision::Allow;
        }
        WatchDecision::Deny
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), FsWatchError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FsWatchError::SchemaMismatch);
        }
        for (sec, list) in [
            ("allow", &self.allow),
            ("deny", &self.deny),
            ("never_watch", &self.never_watch),
        ] {
            for p in list {
                if p.is_empty() {
                    return Err(FsWatchError::EmptyPattern {
                        section: sec.into(),
                    });
                }
                if !p.starts_with('/') {
                    return Err(FsWatchError::NotAbsolute(p.clone()));
                }
            }
        }
        Ok(())
    }
}

/// Match a path against a glob (`*` = any chars except `/`, `?` = one char
/// except `/`, `**` = any chars including `/`).
fn glob_match(pat: &str, path: &str) -> bool {
    let pat_bytes = pat.as_bytes();
    let path_bytes = path.as_bytes();
    match_inner(pat_bytes, 0, path_bytes, 0)
}

fn match_inner(pat: &[u8], mut pi: usize, path: &[u8], mut si: usize) -> bool {
    while pi < pat.len() {
        let c = pat[pi];
        if c == b'*' {
            // double star?
            if pi + 1 < pat.len() && pat[pi + 1] == b'*' {
                pi += 2;
                // Skip a trailing /.
                if pi < pat.len() && pat[pi] == b'/' {
                    pi += 1;
                }
                // Try matching tail at every suffix.
                for end in si..=path.len() {
                    if match_inner(pat, pi, path, end) {
                        return true;
                    }
                }
                return false;
            } else {
                pi += 1;
                // Match any chars except '/'.
                for end in si..=path.len() {
                    if end > si && path[end - 1] == b'/' {
                        break;
                    }
                    if match_inner(pat, pi, path, end) {
                        return true;
                    }
                }
                return false;
            }
        } else if c == b'?' {
            if si >= path.len() || path[si] == b'/' {
                return false;
            }
            si += 1;
            pi += 1;
        } else {
            if si >= path.len() || path[si] != c {
                return false;
            }
            si += 1;
            pi += 1;
        }
    }
    si == path.len()
}

impl Default for FsWatchPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_all() {
        let p = FsWatchPolicy::new();
        assert_eq!(p.decide("/home/user/code/main.rs"), WatchDecision::Deny);
    }

    #[test]
    fn relative_path_denied() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/home/user/**".into());
        assert_eq!(p.decide("home/user/main.rs"), WatchDecision::Deny);
    }

    #[test]
    fn allow_glob_grants_watch() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/home/user/code/**".into());
        assert_eq!(p.decide("/home/user/code/main.rs"), WatchDecision::Allow);
        assert_eq!(p.decide("/home/user/code/sub/x.rs"), WatchDecision::Allow);
    }

    #[test]
    fn deny_overrides_allow() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/home/user/**".into());
        p.deny.push("/home/user/private/**".into());
        assert_eq!(
            p.decide("/home/user/private/secret.txt"),
            WatchDecision::Deny
        );
    }

    #[test]
    fn never_watch_overrides_all() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/**".into());
        p.never_watch.push("/home/user/.ssh/**".into());
        assert_eq!(p.decide("/home/user/.ssh/id_ed25519"), WatchDecision::Deny);
    }

    #[test]
    fn star_does_not_match_slash() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/home/user/code/*.rs".into());
        assert_eq!(p.decide("/home/user/code/main.rs"), WatchDecision::Allow);
        assert_eq!(p.decide("/home/user/code/sub/main.rs"), WatchDecision::Deny);
    }

    #[test]
    fn double_star_matches_slash() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/home/user/**/*.rs".into());
        assert_eq!(
            p.decide("/home/user/code/sub/deep/main.rs"),
            WatchDecision::Allow
        );
    }

    #[test]
    fn question_mark_matches_one_char() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("/a/?.txt".into());
        assert_eq!(p.decide("/a/x.txt"), WatchDecision::Allow);
        assert_eq!(p.decide("/a/xy.txt"), WatchDecision::Deny);
    }

    #[test]
    fn canonical_protects_ssh() {
        let p = FsWatchPolicy::canonical("/home/user");
        assert_eq!(p.decide("/home/user/code/main.rs"), WatchDecision::Allow);
        assert_eq!(p.decide("/home/user/.ssh/config"), WatchDecision::Deny);
        assert_eq!(p.decide("/etc/shadow"), WatchDecision::Deny);
    }

    #[test]
    fn empty_pattern_rejected_on_validate() {
        let mut p = FsWatchPolicy::new();
        p.allow.push(String::new());
        assert!(matches!(
            p.validate().unwrap_err(),
            FsWatchError::EmptyPattern { .. }
        ));
    }

    #[test]
    fn relative_pattern_rejected_on_validate() {
        let mut p = FsWatchPolicy::new();
        p.allow.push("rel/path".into());
        assert!(matches!(
            p.validate().unwrap_err(),
            FsWatchError::NotAbsolute(_)
        ));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut p = FsWatchPolicy::new();
        p.schema_version = "9.9.9".into();
        assert!(matches!(
            p.validate().unwrap_err(),
            FsWatchError::SchemaMismatch
        ));
    }

    #[test]
    fn decision_serde_kebab() {
        assert_eq!(
            serde_json::to_string(&WatchDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&WatchDecision::Deny).unwrap(),
            "\"deny\""
        );
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = FsWatchPolicy::canonical("/home/user");
        let j = serde_json::to_string(&p).unwrap();
        let back: FsWatchPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
