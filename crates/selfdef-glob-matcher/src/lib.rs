//! `selfdef-glob-matcher` — shell-style glob.
//!
//! Supported metacharacters: `*` matches zero-or-more characters
//! (excluding `/`), `?` matches exactly one character (excluding
//! `/`), `[abc]` matches one of, `[^abc]` matches one not of.
//! `\\x` escapes any next char as literal. `/` separators must
//! line up exactly.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// State.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobMatcher {
    /// Schema version.
    pub schema_version: String,
    /// Pattern.
    pub pattern: String,
}

/// Errors.
#[derive(Debug, Error)]
pub enum GlobError {
    /// Schema drift.
    #[error("schema version mismatch")]
    SchemaMismatch,
    /// Empty.
    #[error("pattern empty")]
    EmptyPattern,
    /// Bad class.
    #[error("unterminated character class")]
    UnterminatedClass,
}

fn match_class(class: &[char], c: char) -> bool {
    let (negate, body) = if class.first() == Some(&'^') {
        (true, &class[1..])
    } else {
        (false, class)
    };
    let mut hit = false;
    let mut i = 0;
    while i < body.len() {
        let ch = body[i];
        if ch == c { hit = true; break; }
        i += 1;
    }
    hit ^ negate
}

fn glob_match(pat: &[char], path: &[char]) -> bool {
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_si = 0usize;
    while si < path.len() {
        if pi < pat.len() {
            match pat[pi] {
                '\\' if pi + 1 < pat.len() => {
                    if pat[pi + 1] == path[si] {
                        pi += 2;
                        si += 1;
                        continue;
                    }
                }
                '*' => {
                    star_pi = Some(pi);
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    if path[si] != '/' {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                '[' => {
                    // Locate closing ']'.
                    if let Some(end_rel) = pat[pi + 1..].iter().position(|&c| c == ']') {
                        let end_abs = pi + 1 + end_rel;
                        let class = &pat[pi + 1..end_abs];
                        if path[si] != '/' && match_class(class, path[si]) {
                            pi = end_abs + 1;
                            si += 1;
                            continue;
                        }
                    } else {
                        return false;
                    }
                }
                c if c == path[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        // Mismatch or pattern exhausted — try expanding the last '*'.
        if let Some(spi) = star_pi {
            if path[star_si] == '/' {
                return false;
            }
            star_si += 1;
            si = star_si;
            pi = spi + 1;
        } else {
            return false;
        }
    }
    // Trailing '*' wildcards in the pattern.
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
}

impl GlobMatcher {
    /// New.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() { return Err(GlobError::EmptyPattern); }
        // Validate balanced character classes.
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            match chars[i] {
                '\\' if i + 1 < chars.len() => i += 2,
                '[' => {
                    let rest = &chars[i + 1..];
                    let Some(end) = rest.iter().position(|&c| c == ']') else {
                        return Err(GlobError::UnterminatedClass);
                    };
                    i = i + 1 + end + 1;
                }
                _ => i += 1,
            }
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION.into(),
            pattern: pattern.into(),
        })
    }

    /// Match path against pattern.
    pub fn is_match(&self, path: &str) -> bool {
        let pat: Vec<char> = self.pattern.chars().collect();
        let s: Vec<char> = path.chars().collect();
        glob_match(&pat, &s)
    }

    /// Validate.
    pub fn validate(&self) -> Result<(), GlobError> {
        if self.schema_version != SCHEMA_VERSION { return Err(GlobError::SchemaMismatch); }
        if self.pattern.is_empty() { return Err(GlobError::EmptyPattern); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_match() {
        let g = GlobMatcher::new("/etc/passwd").unwrap();
        assert!(g.is_match("/etc/passwd"));
        assert!(!g.is_match("/etc/passwd2"));
    }

    #[test]
    fn star_matches_within_segment() {
        let g = GlobMatcher::new("/var/log/*.log").unwrap();
        assert!(g.is_match("/var/log/messages.log"));
        assert!(g.is_match("/var/log/.log"));
        assert!(!g.is_match("/var/log/sub/messages.log"));
    }

    #[test]
    fn question_matches_one_char() {
        let g = GlobMatcher::new("file?.txt").unwrap();
        assert!(g.is_match("file1.txt"));
        assert!(!g.is_match("file10.txt"));
        assert!(!g.is_match("file.txt"));
    }

    #[test]
    fn character_class_positive() {
        let g = GlobMatcher::new("file[abc].txt").unwrap();
        assert!(g.is_match("filea.txt"));
        assert!(g.is_match("fileb.txt"));
        assert!(!g.is_match("filed.txt"));
    }

    #[test]
    fn character_class_negative() {
        let g = GlobMatcher::new("file[^abc].txt").unwrap();
        assert!(!g.is_match("filea.txt"));
        assert!(g.is_match("filed.txt"));
    }

    #[test]
    fn star_does_not_cross_slash() {
        let g = GlobMatcher::new("/a/*/b").unwrap();
        assert!(g.is_match("/a/x/b"));
        assert!(!g.is_match("/a/x/y/b"));
    }

    #[test]
    fn trailing_star() {
        let g = GlobMatcher::new("/tmp/*").unwrap();
        assert!(g.is_match("/tmp/foo"));
        assert!(!g.is_match("/tmp/foo/bar"));
    }

    #[test]
    fn escape_metachar() {
        let g = GlobMatcher::new("\\*literal").unwrap();
        assert!(g.is_match("*literal"));
        assert!(!g.is_match("anything-literal"));
    }

    #[test]
    fn unterminated_class_rejected() {
        assert!(matches!(GlobMatcher::new("[abc").unwrap_err(), GlobError::UnterminatedClass));
    }

    #[test]
    fn empty_pattern_rejected() {
        assert!(matches!(GlobMatcher::new("").unwrap_err(), GlobError::EmptyPattern));
    }

    #[test]
    fn schema_drift_rejected() {
        let mut g = GlobMatcher::new("*").unwrap();
        g.schema_version = "9.9.9".into();
        assert!(matches!(g.validate().unwrap_err(), GlobError::SchemaMismatch));
    }

    #[test]
    fn glob_serde_roundtrip() {
        let g = GlobMatcher::new("/var/log/*.log").unwrap();
        let j = serde_json::to_string(&g).unwrap();
        let back: GlobMatcher = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }
}
