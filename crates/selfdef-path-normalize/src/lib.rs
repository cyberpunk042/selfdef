//! `selfdef-path-normalize` — collapse + resolve path segments.
//!
//! normalize(path) splits on '/', drops empty segs (collapses //)
//! and ".", pops on "..". For absolute paths (starting with /),
//! popping past root errors EscapesRoot. For relative paths,
//! ".." beyond start is kept as ".." segments.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Errors.
#[derive(Debug, Error)]
pub enum PathError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Escapes root.
    #[error(".. escapes absolute root")]
    EscapesRoot,
}

/// Versioned state placeholder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathNormalizeState {
    /// Schema version.
    pub schema_version: String,
}

/// Normalize.
pub fn normalize(path: &str) -> Result<String, PathError> {
    let absolute = path.starts_with('/');
    let mut segs: Vec<&str> = Vec::new();
    for s in path.split('/') {
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            if segs.last().map(|&t| t == "..").unwrap_or(false) || segs.is_empty() {
                if absolute {
                    return Err(PathError::EscapesRoot);
                }
                segs.push("..");
            } else {
                segs.pop();
            }
        } else {
            segs.push(s);
        }
    }
    let joined = segs.join("/");
    if absolute {
        if joined.is_empty() {
            Ok("/".into())
        } else {
            Ok(format!("/{}", joined))
        }
    } else {
        if joined.is_empty() {
            Ok(".".into())
        } else {
            Ok(joined)
        }
    }
}

impl PathNormalizeState {
    /// New.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), PathError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PathError::SchemaMismatch);
        }
        Ok(())
    }
}

impl Default for PathNormalizeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_double_slashes() {
        assert_eq!(normalize("/a//b///c").unwrap(), "/a/b/c");
    }

    #[test]
    fn dot_dropped() {
        assert_eq!(normalize("/a/./b/./c").unwrap(), "/a/b/c");
    }

    #[test]
    fn dotdot_pops() {
        assert_eq!(normalize("/a/b/../c").unwrap(), "/a/c");
    }

    #[test]
    fn dotdot_escape_absolute_rejected() {
        assert!(matches!(
            normalize("/a/../../b").unwrap_err(),
            PathError::EscapesRoot
        ));
    }

    #[test]
    fn relative_keeps_dotdot() {
        assert_eq!(normalize("../../a").unwrap(), "../../a");
    }

    #[test]
    fn empty_relative_dot() {
        assert_eq!(normalize("").unwrap(), ".");
        assert_eq!(normalize(".").unwrap(), ".");
    }

    #[test]
    fn root_only() {
        assert_eq!(normalize("/").unwrap(), "/");
    }

    #[test]
    fn schema_drift_rejected() {
        let mut s = PathNormalizeState::new();
        s.schema_version = "9.9.9".into();
        assert!(matches!(
            s.validate().unwrap_err(),
            PathError::SchemaMismatch
        ));
    }

    #[test]
    fn state_serde_roundtrip() {
        let s = PathNormalizeState::new();
        let j = serde_json::to_string(&s).unwrap();
        let back: PathNormalizeState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
